//go:build linux && ebpf_integration

package capture

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// The privilege drop is irreversible and process-wide: syscall.AllThreadsSyscall
// moves every thread to the proxy UID and setuid(0) then fails. Running the real
// drop in the test process would poison the whole test binary, so the positive
// sequence cases (#135-141, #143) re-exec this test binary as an unprivileged
// child that performs the drop and reports its observable state; the parent only
// asserts on that report. The error cases (#142, #144) instead replace fields of
// the unexported privDropSeam so a step can fail or no-op without a real drop.

const privDropChildEnv = "AKSH_PRIVDROP_CHILD"

const (
	// testProxyUID is defined in resolver_integration_test.go (1774); reuse it.
	testProxyGID uint32 = 1774
)

// privDropChildReport is the observable post-drop state the child reports to the
// parent as a single line of JSON on stdout.
type privDropChildReport struct {
	DropErr      string   `json:"drop_err"`
	UID          uint32   `json:"uid"`
	EUID         uint32   `json:"euid"`
	GID          uint32   `json:"gid"`
	Groups       []uint32 `json:"groups"`
	PreCaps      uint64   `json:"pre_caps"`
	PostCaps     uint64   `json:"post_caps"`
	BoundingSet  uint64   `json:"bounding_set"`
	NoNewPrivs   int      `json:"no_new_privs"`
	KeepCaps     int      `json:"keep_caps"`
	SetUID0Errno int      `json:"setuid0_errno"`
}

// TestMain intercepts the re-exec: when the child sentinel is set it performs
// the drop and reports, otherwise it runs the tests normally.
func TestMain(m *testing.M) {
	if scenario := os.Getenv(privDropChildEnv); scenario != "" {
		os.Exit(runPrivDropChild(scenario))
	}
	os.Exit(m.Run())
}

func standardPrivDropCfg() PrivDropConfig {
	return PrivDropConfig{
		ProxyUID:         testProxyUID,
		ProxyGID:         testProxyGID,
		KeepCapabilities: []string{"CAP_BPF"},
		NoNewPrivs:       true,
	}
}

// runPrivDropChild executes the real drop and prints the report. It must run as
// root holding CAP_BPF and the drop-time capabilities (privileged Docker).
func runPrivDropChild(scenario string) int {
	if scenario != "fullseq" {
		fmt.Fprintf(os.Stderr, "unknown child scenario %q\n", scenario)
		return 2
	}

	// Seed a bogus supplementary group so that clearing it is observable.
	_ = unix.Setgroups([]int{12345})

	rep := privDropChildReport{PreCaps: childEffectiveCaps()}

	if err := DropPrivileges(standardPrivDropCfg()); err != nil {
		rep.DropErr = err.Error()
	}

	rep.UID = uint32(unix.Getuid())
	rep.EUID = uint32(unix.Geteuid())
	rep.GID = uint32(unix.Getgid())
	if gs, err := unix.Getgroups(); err == nil {
		for _, g := range gs {
			rep.Groups = append(rep.Groups, uint32(g))
		}
	}
	rep.PostCaps = childEffectiveCaps()
	rep.BoundingSet = childBoundingSet()
	rep.NoNewPrivs = childPrctlRead(unix.PR_GET_NO_NEW_PRIVS)
	rep.KeepCaps = childPrctlRead(unix.PR_GET_KEEPCAPS)
	if _, _, errno := unix.RawSyscall(unix.SYS_SETUID, 0, 0, 0); errno != 0 {
		rep.SetUID0Errno = int(errno)
	}

	out, err := json.Marshal(rep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal report: %v\n", err)
		return 3
	}
	fmt.Println(string(out))
	return 0
}

func childEffectiveCaps() uint64 {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0
	}
	return uint64(data[0].Effective) | uint64(data[1].Effective)<<32
}

func childBoundingSet() uint64 {
	var m uint64
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		present, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if err != nil {
			break
		}
		if present == 1 {
			m |= uint64(1) << uint(c)
		}
	}
	return m
}

func childPrctlRead(option int) int {
	v, err := unix.PrctlRetInt(option, 0, 0, 0, 0)
	if err != nil {
		return -1
	}
	return v
}

// runPrivDropFullSequence re-execs the child and returns its report.
func runPrivDropFullSequence(t *testing.T) privDropChildReport {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), privDropChildEnv+"=fullseq")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("privilege-drop child failed: %v (output: %s)", err, string(out))
	}
	var rep privDropChildReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("decode child report: %v (raw: %s)", err, string(out))
	}
	if rep.DropErr != "" {
		t.Fatalf("child DropPrivileges returned error: %s", rep.DropErr)
	}
	return rep
}

func capBit(c uint) uint64 { return uint64(1) << c }

func assertEPrivdrop(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want E_PRIVDROP")
	}
	var pf *PreflightError
	if !errors.As(err, &pf) {
		t.Fatalf("error = %v (%T), want a *PreflightError carrying E_PRIVDROP", err, err)
	}
	if pf.Code != E_PRIVDROP {
		t.Fatalf("failure code = %s, want E_PRIVDROP", pf.Code)
	}
}

func TestDropPrivileges(t *testing.T) {
	rep := runPrivDropFullSequence(t)

	// #135
	t.Run("DropPrivileges_FullSequence_EndsAtNonRootUID", func(t *testing.T) {
		if rep.UID != testProxyUID || rep.EUID != testProxyUID || rep.GID != testProxyGID {
			t.Fatalf("uid/euid/gid = %d/%d/%d, want %d/%d/%d",
				rep.UID, rep.EUID, rep.GID, testProxyUID, testProxyUID, testProxyGID)
		}
		if rep.UID == 0 || rep.EUID == 0 || rep.GID == 0 {
			t.Fatalf("process still root: uid/euid/gid = %d/%d/%d", rep.UID, rep.EUID, rep.GID)
		}
	})

	// #136
	t.Run("DropPrivileges_PostDrop_OnlyCapBPFRetained", func(t *testing.T) {
		want := capBit(unix.CAP_BPF)
		if rep.PostCaps != want {
			t.Fatalf("effective caps = %#x, want exactly {CAP_BPF} = %#x", rep.PostCaps, want)
		}
		if rep.PostCaps&capBit(unix.CAP_NET_ADMIN) != 0 {
			t.Fatalf("CAP_NET_ADMIN still effective: caps = %#x", rep.PostCaps)
		}
	})

	// #137
	t.Run("DropPrivileges_PostDrop_SetuidZeroFails", func(t *testing.T) {
		if rep.SetUID0Errno != int(unix.EPERM) {
			t.Fatalf("setuid(0) errno = %d, want EPERM (%d)", rep.SetUID0Errno, int(unix.EPERM))
		}
	})

	// #138
	t.Run("DropPrivileges_PostDrop_NoNewPrivsSet", func(t *testing.T) {
		if rep.NoNewPrivs != 1 {
			t.Fatalf("PR_GET_NO_NEW_PRIVS = %d, want 1", rep.NoNewPrivs)
		}
	})

	// #139
	t.Run("DropPrivileges_AfterCapsetStep_KeepCapsCleared", func(t *testing.T) {
		if rep.KeepCaps != 0 {
			t.Fatalf("PR_GET_KEEPCAPS = %d, want 0", rep.KeepCaps)
		}
	})

	// #140
	t.Run("DropPrivileges_BeforeSetgidStep_GroupsCleared", func(t *testing.T) {
		if len(rep.Groups) != 0 {
			t.Fatalf("supplementary groups = %v, want none", rep.Groups)
		}
	})

	// #141
	t.Run("DropPrivileges_BeforeDropStep_PrivilegedWorkCompletes", func(t *testing.T) {
		if rep.PreCaps&capBit(unix.CAP_NET_ADMIN) == 0 {
			t.Fatalf("pre-drop caps lacked CAP_NET_ADMIN: %#x", rep.PreCaps)
		}
		if rep.PostCaps&capBit(unix.CAP_NET_ADMIN) != 0 {
			t.Fatalf("privileged CAP_NET_ADMIN survived the drop: %#x", rep.PostCaps)
		}
	})

	// #143
	t.Run("DropPrivileges_CapBSetDropStep_RemovesBoundingSetCapabilities", func(t *testing.T) {
		want := capBit(unix.CAP_BPF)
		if rep.BoundingSet != want {
			t.Fatalf("bounding set = %#x, want exactly {CAP_BPF} = %#x", rep.BoundingSet, want)
		}
	})

	// #142
	t.Run("DropPrivileges_SequenceFailsPartway_ReturnsEPrivdropAndProcessExits", func(t *testing.T) {
		restore := privDropSeam
		t.Cleanup(func() { privDropSeam = restore })
		s := restore
		// Fail the first step so no real, irreversible syscall runs in-process.
		s.setKeepCaps = func(bool) error { return unix.EPERM }
		privDropSeam = s

		err := DropPrivileges(standardPrivDropCfg())
		assertEPrivdrop(t, err)

		if os.Getuid() != 0 {
			t.Fatalf("parent uid = %d after a forced failure; drop leaked into the test process", os.Getuid())
		}
	})

	// #144
	t.Run("DropPrivileges_VerificationStepCatchesIncompleteDrop_ReturnsEPrivdrop", func(t *testing.T) {
		restore := privDropSeam
		t.Cleanup(func() { privDropSeam = restore })
		s := restore
		// Every mutating step is a no-op, so the test process is untouched, but
		// the verification queries report a process that never left root - the
		// incomplete drop the final step must catch.
		s.setKeepCaps = func(bool) error { return nil }
		s.setGroups = func([]uint32) error { return nil }
		s.setGID = func(uint32) error { return nil }
		s.setUID = func(uint32) error { return nil }
		s.setCaps = func([]string) error { return nil }
		s.dropBoundingCaps = func([]string) error { return nil }
		s.setNoNewPrivs = func() error { return nil }
		s.getUID = func() uint32 { return 0 }
		s.getEUID = func() uint32 { return 0 }
		s.getGID = func() uint32 { return 0 }
		s.getGroups = func() ([]uint32, error) { return nil, nil }
		s.getEffectiveCaps = func() (uint64, error) { return capBit(unix.CAP_BPF), nil }
		s.probeSetUIDZero = func() error { return nil }
		privDropSeam = s

		err := DropPrivileges(standardPrivDropCfg())
		assertEPrivdrop(t, err)
	})
}

// passingVerifySeam builds a seam whose mutating steps are all no-ops (so the
// test process is never really dropped) but whose readback fields report a
// correctly and irreversibly dropped process. Each verification-invariant
// negative test starts from this seam and corrupts exactly one readback so that
// verifyDrop (step 11) must fail closed with E_PRIVDROP.
func passingVerifySeam() privDropSyscalls {
	s := defaultPrivDropSyscalls()
	s.setKeepCaps = func(bool) error { return nil }
	s.setGroups = func([]uint32) error { return nil }
	s.setGID = func(uint32) error { return nil }
	s.setUID = func(uint32) error { return nil }
	s.setCaps = func([]string) error { return nil }
	s.dropBoundingCaps = func([]string) error { return nil }
	s.setNoNewPrivs = func() error { return nil }
	s.getUID = func() uint32 { return testProxyUID }
	s.getEUID = func() uint32 { return testProxyUID }
	s.getGID = func() uint32 { return testProxyGID }
	s.getGroups = func() ([]uint32, error) { return nil, nil }
	s.getEffectiveCaps = func() (uint64, error) { return capBit(unix.CAP_BPF), nil }
	s.getBoundingCaps = func() (uint64, error) { return capBit(unix.CAP_BPF), nil }
	s.getKeepCaps = func() (int, error) { return 0, nil }
	s.getNoNewPrivs = func() (int, error) { return 1, nil }
	s.probeSetUIDZero = func() error { return unix.EPERM }
	return s
}

// TestDropPrivilegesVerifyInvariants locks in the step-11 hardening checks: a
// correctly reported drop passes, but any single broken invariant (bounding set
// not shrunk, NO_NEW_PRIVS unset, KEEPCAPS not cleared, or a setuid(0) probe
// that does not fail with EPERM) makes DropPrivileges fail closed.
func TestDropPrivilegesVerifyInvariants(t *testing.T) {
	// A fully-consistent readback must pass verification (guards against the
	// negative cases passing for the wrong reason).
	t.Run("VerifyStep_ConsistentReadback_Succeeds", func(t *testing.T) {
		restore := privDropSeam
		t.Cleanup(func() { privDropSeam = restore })
		privDropSeam = passingVerifySeam()
		if err := DropPrivileges(standardPrivDropCfg()); err != nil {
			t.Fatalf("DropPrivileges with a consistent readback returned error: %v", err)
		}
	})

	// #145
	t.Run("VerifyStep_BoundingSetNotShrunk_ReturnsEPrivdrop", func(t *testing.T) {
		restore := privDropSeam
		t.Cleanup(func() { privDropSeam = restore })
		s := passingVerifySeam()
		s.getBoundingCaps = func() (uint64, error) {
			return capBit(unix.CAP_BPF) | capBit(unix.CAP_NET_ADMIN), nil
		}
		privDropSeam = s
		assertEPrivdrop(t, DropPrivileges(standardPrivDropCfg()))
	})

	// #146
	t.Run("VerifyStep_NoNewPrivsUnset_ReturnsEPrivdrop", func(t *testing.T) {
		restore := privDropSeam
		t.Cleanup(func() { privDropSeam = restore })
		s := passingVerifySeam()
		s.getNoNewPrivs = func() (int, error) { return 0, nil }
		privDropSeam = s
		assertEPrivdrop(t, DropPrivileges(standardPrivDropCfg()))
	})

	// #147
	t.Run("VerifyStep_KeepCapsNotCleared_ReturnsEPrivdrop", func(t *testing.T) {
		restore := privDropSeam
		t.Cleanup(func() { privDropSeam = restore })
		s := passingVerifySeam()
		s.getKeepCaps = func() (int, error) { return 1, nil }
		privDropSeam = s
		assertEPrivdrop(t, DropPrivileges(standardPrivDropCfg()))
	})

	// #148
	t.Run("VerifyStep_SetuidZeroSucceeds_ReturnsEPrivdrop", func(t *testing.T) {
		restore := privDropSeam
		t.Cleanup(func() { privDropSeam = restore })
		s := passingVerifySeam()
		s.probeSetUIDZero = func() error { return nil }
		privDropSeam = s
		assertEPrivdrop(t, DropPrivileges(standardPrivDropCfg()))
	})

	// #149
	t.Run("VerifyStep_SetuidZeroNonEPERMError_ReturnsEPrivdrop", func(t *testing.T) {
		restore := privDropSeam
		t.Cleanup(func() { privDropSeam = restore })
		s := passingVerifySeam()
		s.probeSetUIDZero = func() error { return unix.EACCES }
		privDropSeam = s
		assertEPrivdrop(t, DropPrivileges(standardPrivDropCfg()))
	})
}
