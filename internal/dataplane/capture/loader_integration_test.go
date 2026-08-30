//go:build linux && ebpf_integration

package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/girishmotwani/aksh/internal/audit"
	bpf "github.com/girishmotwani/aksh/internal/dataplane/bpf"
)

// The loader load/attach/pin sequence composes irreversible, process-wide kernel
// effects. Two of the checks it must satisfy - a CAP_BPF-only reader opening a
// pinned link (#111-#113) and a separate process writing a frozen map (#107) -
// cannot be performed in the parent test process without either dropping its own
// privileges permanently or poisoning shared state, so they re-exec this test
// binary as a child that performs exactly one probe and reports it as JSON.
//
// The interception is done in init() (which runs before the privilege-drop
// TestMain in privdrop_integration_test.go) rather than in a second TestMain,
// so there is exactly one TestMain in the ebpf_integration build.

const loaderChildEnv = "AKSH_LOADER_CHILD"

func init() {
	if scenario := os.Getenv(loaderChildEnv); scenario != "" {
		os.Exit(runLoaderChild(scenario))
	}
}

// loaderChildReport is the single JSON line the probe child prints on stdout.
type loaderChildReport struct {
	Errno int    `json:"errno"`
	Fatal string `json:"fatal,omitempty"`
}

// runLoaderChild performs one probe described by the AKSH_LOADER_* environment
// and prints a loaderChildReport. It never returns to the test runner.
func runLoaderChild(scenario string) int {
	rep := loaderChildReport{}
	emit := func() int {
		out, _ := json.Marshal(rep)
		fmt.Println(string(out))
		return 0
	}

	if os.Getenv("AKSH_LOADER_DROP") == "1" {
		if err := DropPrivileges(PrivDropConfig{
			ProxyUID:         testProxyUID,
			ProxyGID:         testProxyGID,
			KeepCapabilities: []string{"CAP_BPF"},
			NoNewPrivs:       true,
		}); err != nil {
			rep.Fatal = "drop: " + err.Error()
			return emit()
		}
	}

	switch scenario {
	case "objget_link":
		var opts *ebpf.LoadPinOptions
		if os.Getenv("AKSH_LOADER_RDONLY") == "1" {
			opts = &ebpf.LoadPinOptions{Flags: unix.BPF_F_RDONLY}
		}
		lk, err := link.LoadPinnedLink(os.Getenv("AKSH_LOADER_PIN"), opts)
		if err != nil {
			rep.Errno = errnoOf(err)
			return emit()
		}
		_ = lk.Close()
		rep.Errno = 0
	case "mapupdate":
		m, err := ebpf.LoadPinnedMap(os.Getenv("AKSH_LOADER_PIN"), nil)
		if err != nil {
			rep.Fatal = "open pinned map: " + err.Error()
			return emit()
		}
		defer m.Close()
		var zero [ConfigImageSize]byte
		rep.Errno = errnoOf(m.Update(uint32(0), zero[:], ebpf.UpdateAny))
	case "connect":
		cg := os.Getenv("AKSH_LOADER_CGROUP")
		if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"),
			[]byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
			rep.Fatal = "join cgroup: " + err.Error()
			return emit()
		}
		if uidStr := os.Getenv("AKSH_LOADER_UID"); uidStr != "" {
			uid, _ := strconv.Atoi(uidStr)
			if err := syscall.Setuid(uid); err != nil {
				rep.Fatal = "setuid: " + err.Error()
				return emit()
			}
		}
		d := net.Dialer{Timeout: 500 * time.Millisecond}
		conn, err := d.Dial("tcp4", os.Getenv("AKSH_LOADER_DST"))
		if err == nil {
			_ = conn.Close()
		}
		rep.Errno = errnoOf(err)
	default:
		rep.Fatal = "unknown scenario " + scenario
	}
	return emit()
}

func errnoOf(err error) int {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return -1
}

// --- parent-side helpers ---------------------------------------------------

// mountCgroup2 mounts a private cgroup2 hierarchy for one test and returns its
// path; the programs attach here and the connect probe joins it.
func mountCgroup2(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := unix.Mount("none", dir, "cgroup2", 0, ""); err != nil {
		t.Fatalf("mount cgroup2: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, 0) })
	return dir
}

// mountBPFFS mounts a private bpffs for one test and returns its path; it is the
// pin root, so each test gets a clean subtree that gate P15 can own.
func mountBPFFS(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := unix.Mount("bpf", dir, "bpf", 0, "mode=0755"); err != nil {
		t.Fatalf("mount bpffs: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, 0) })
	return dir
}

// requirePinnable skips the calling test when the running kernel rejects
// pinning a bpf_link to bpffs. Link pinning is a kernel capability that some
// kernels (notably the microsoft-standard WSL2 5.15 build this repo's Docker
// runner uses) do not permit, returning EPERM/EOPNOTSUPP at the BPF_OBJ_PIN
// syscall even though map pinning succeeds. The pin-DAC assertions of
// #111-#113 pin a real cgroup link and then BPF_OBJ_GET it as a dropped uid, so
// they can only run where the kernel supports link pinning; this is the
// standard capability gate (mirroring cilium/ebpf's SkipIfNotSupported), not a
// relaxation of the assertion. The design flags the pinning path (pre-merge
// kernel gate M1) as unverified and defaults PinLinks to false for exactly this
// reason.
func requirePinnable(t *testing.T) {
	t.Helper()
	cg := mountCgroup2(t)
	fs := mountBPFFS(t)
	spec, err := bpf.LoadAkshbpf()
	if err != nil {
		t.Fatalf("probe load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("probe new collection: %v", err)
	}
	defer coll.Close()
	lk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cg,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: coll.Programs[bpf.AkshbpfProgAkshConnect4],
	})
	if err != nil {
		t.Fatalf("probe attach: %v", err)
	}
	defer lk.Close()
	if err := lk.Pin(filepath.Join(fs, "probe.link")); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
			t.Skipf("BPF_LINK pinning is unsupported on this kernel; pin-DAC assertion cannot run here: %v", err)
		}
		t.Fatalf("probe link pin: %v", err)
	}
	_ = lk.Unpin()
}

func loaderBaseOptions(t *testing.T, podPath string) *Options {
	t.Helper()
	return &Options{
		PodPath:             podPath,
		HostCgroupMount:     "/host/sys/fs/cgroup",
		Metrics:             audit.NopMetricsRecorder{},
		ProxyUID:            testProxyUID,
		ProxyGID:            testProxyGID,
		AttachCheckInterval: 30 * time.Second,
		BlockNonTCP:         true,
		RunProbe:            true,
	}
}

// saveLoaderSeam restores the package seam and clears any loader state after a
// subtest so seam overrides and retained fds never leak across cases.
func saveLoaderSeam(t *testing.T) {
	t.Helper()
	restore := loaderSeam
	t.Cleanup(func() { loaderSeam = restore })
}

// mustLoad runs LoadAndAttach and registers teardown of every retained kernel
// object, so a subtest can assert on live objects without leaking them.
func mustLoad(t *testing.T, opts *Options) *AttachInfo {
	t.Helper()
	h, err := LoadAndAttach(opts)
	if err != nil {
		t.Fatalf("LoadAndAttach() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	ai := h.AttachInfo()
	return &ai
}

func runLoaderChildProbe(t *testing.T, scenario string, env map[string]string) loaderChildReport {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), loaderChildEnv+"="+scenario)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("loader child exited non-zero: %v, stderr=%s", err, ee.Stderr)
		}
		t.Fatalf("run loader child: %v", err)
	}
	var rep loaderChildReport
	if jerr := json.Unmarshal(lastJSONLine(out), &rep); jerr != nil {
		t.Fatalf("decode child report %q: %v", out, jerr)
	}
	if rep.Fatal != "" {
		t.Fatalf("loader child fatal: %s", rep.Fatal)
	}
	return rep
}

func lastJSONLine(b []byte) []byte {
	lines := bytes.Split(bytes.TrimRight(b, "\r\n"), []byte("\n"))
	return bytes.TrimSpace(lines[len(lines)-1])
}

func firstLinkPin(info *AttachInfo) string {
	for _, p := range info.PinPaths {
		if strings.HasSuffix(p, ".link") {
			return p
		}
	}
	return ""
}

// --- tests -----------------------------------------------------------------

func TestLoadAndAttach(t *testing.T) {
	// #101
	t.Run("LoadAndAttach_ValidPrograms_ReturnsAttachInfo", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		info := mustLoad(t, loaderBaseOptions(t, cg))
		if len(info.ProgIDs) == 0 {
			t.Fatalf("AttachInfo.ProgIDs = %v, want non-empty", info.ProgIDs)
		}
		for _, id := range info.ProgIDs {
			if id == 0 {
				t.Fatalf("AttachInfo.ProgIDs contains a zero id: %v", info.ProgIDs)
			}
		}
		if info.CgroupID == 0 {
			t.Fatalf("AttachInfo.CgroupID = 0, want a real cgroup id")
		}
	})

	// #102
	t.Run("LoadAndAttach_InvalidProgram_ReturnsEProgLoad", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		loaderSeam.loadCollectionSpec = func() (*ebpf.CollectionSpec, error) {
			spec, err := bpf.LoadAkshbpf()
			if err != nil {
				return nil, err
			}
			// An uninitialised stack read the verifier must reject.
			spec.Programs[bpf.AkshbpfProgAkshConnect4].Instructions = asm.Instructions{
				asm.LoadMem(asm.R0, asm.RFP, -8, asm.DWord),
				asm.Return(),
			}
			return spec, nil
		}
		_, err := LoadAndAttach(loaderBaseOptions(t, cg))
		assertFailureCode(t, err, E_PROG_LOAD)
	})

	// #103
	t.Run("LoadAndAttach_ConfigWriteThenReadback_ValuesMatch", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		opts := loaderBaseOptions(t, cg)
		mustLoad(t, opts)
		want, err := buildConfigImage(opts)
		if err != nil {
			t.Fatalf("buildConfigImage: %v", err)
		}
		var got [ConfigImageSize]byte
		if err := loaderFor(opts).configMap.Lookup(uint32(0), &got); err != nil {
			t.Fatalf("config lookup: %v", err)
		}
		if !bytes.Equal(got[:], want) {
			t.Fatalf("config readback %x, want %x", got[:], want)
		}
	})

	// #104
	t.Run("LoadAndAttach_FreezeMap_BPFMapFreezeSucceeds", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		opts := loaderBaseOptions(t, cg)
		// A freeze failure surfaces as E_CONFIG_FREEZE and fails the load, so a
		// nil error is itself the proof BPF_MAP_FREEZE succeeded.
		mustLoad(t, opts)
		if loaderFor(opts).configMap == nil {
			t.Fatalf("config map handle is nil after a successful load")
		}
	})

	// #105
	t.Run("LoadAndAttach_AfterFreeze_UpdateFromSameFDReturnsEPERM", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		opts := loaderBaseOptions(t, cg)
		mustLoad(t, opts)
		var zero [ConfigImageSize]byte
		err := loaderFor(opts).configMap.Update(uint32(0), zero[:], ebpf.UpdateAny)
		if got := errnoOf(err); got != int(unix.EPERM) {
			t.Fatalf("same-fd update errno = %d (%v), want EPERM (%d)", got, err, int(unix.EPERM))
		}
	})

	// #106
	t.Run("LoadAndAttach_AfterFreeze_UpdateFromReopenedPinnedFDReturnsEPERM", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		pinRoot := mountBPFFS(t)
		opts := loaderBaseOptions(t, cg)
		mustLoad(t, opts)

		pinPath := filepath.Join(pinRoot, "aksh_config_reopen")
		if err := loaderFor(opts).configMap.Pin(pinPath); err != nil {
			t.Fatalf("pin config map: %v", err)
		}
		reopened, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			t.Fatalf("reopen pinned map: %v", err)
		}
		defer reopened.Close()
		var zero [ConfigImageSize]byte
		if got := errnoOf(reopened.Update(uint32(0), zero[:], ebpf.UpdateAny)); got != int(unix.EPERM) {
			t.Fatalf("reopened-fd update errno = %d, want EPERM (%d)", got, int(unix.EPERM))
		}
	})

	// #107
	t.Run("LoadAndAttach_AfterFreeze_UpdateFromSeparateProcessReturnsEPERM", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		pinRoot := mountBPFFS(t)
		opts := loaderBaseOptions(t, cg)
		mustLoad(t, opts)

		pinPath := filepath.Join(pinRoot, "aksh_config_sep")
		if err := loaderFor(opts).configMap.Pin(pinPath); err != nil {
			t.Fatalf("pin config map: %v", err)
		}
		rep := runLoaderChildProbe(t, "mapupdate", map[string]string{"AKSH_LOADER_PIN": pinPath})
		if rep.Errno != int(unix.EPERM) {
			t.Fatalf("separate-process update errno = %d, want EPERM (%d)", rep.Errno, int(unix.EPERM))
		}
	})

	// #108
	t.Run("LoadAndAttach_AfterFreeze_AttachedProgramStillReadsMapCorrectly", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		opts := loaderBaseOptions(t, cg)
		mustLoad(t, opts)

		// A process in the cgroup, running as a non-proxy uid, does a TCP
		// connect; connect4 reads the frozen config and redirects, populating
		// cookie_orig_dst. A non-empty map proves the program still reads the
		// frozen config correctly.
		runLoaderChildProbe(t, "connect", map[string]string{
			"AKSH_LOADER_CGROUP": cg,
			"AKSH_LOADER_UID":    "65534",
			"AKSH_LOADER_DST":    "93.184.216.34:443",
		})
		if n := cookieMapLen(t, loaderFor(opts).coll); n == 0 {
			t.Fatalf("cookie_orig_dst is empty; attached connect4 did not read the frozen config")
		}
	})

	// #109
	t.Run("LoadAndAttach_AttachHealthCheckLoop_DetectsDetachedProgramAndLogs", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		var buf syncBuffer
		tick := make(chan time.Time, 1)
		loaderSeam.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		loaderSeam.newHealthTicker = func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} }
		loaderSeam.checkAttachment = func(*loaderState) error {
			return fmt.Errorf("program detached: %w", errAttachLost)
		}
		h, err := LoadAndAttach(loaderBaseOptions(t, cg))
		if err != nil {
			t.Fatalf("LoadAndAttach() error = %v", err)
		}
		t.Cleanup(func() { _ = h.Close() })
		lost := make(chan error, 1)
		h.OnAttachLoss(func(e error) { lost <- e })

		tick <- time.Now()
		select {
		case <-lost:
		case <-time.After(5 * time.Second):
			t.Fatalf("health loop did not react to a detached program")
		}
		if !strings.Contains(buf.String(), "capture.attach_lost") {
			t.Fatalf("log = %q, want it to contain capture.attach_lost", buf.String())
		}
		if !strings.Contains(buf.String(), "level=ERROR") {
			t.Fatalf("log = %q, want capture.attach_lost logged at ERROR", buf.String())
		}
	})

	// #110 — migrated: the health loop no longer calls os.Exit on detach (DD-2
	// anti-pattern removal). It now dispatches the fail-closed attach-loss signal
	// through the owning Handle; this asserts the signal fires and os.Exit does
	// NOT (the integration analogue of #17/#19/#22).
	t.Run("LoadAndAttach_AttachHealthCheckLoop_ExitsProcessOnDetach", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		tick := make(chan time.Time, 1)
		exited := make(chan int, 1)
		loaderSeam.newHealthTicker = func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} }
		loaderSeam.exit = func(code int) { exited <- code }
		loaderSeam.checkAttachment = func(*loaderState) error {
			return fmt.Errorf("program detached: %w", errAttachLost)
		}
		h, err := LoadAndAttach(loaderBaseOptions(t, cg))
		if err != nil {
			t.Fatalf("LoadAndAttach() error = %v", err)
		}
		t.Cleanup(func() { _ = h.Close() })
		lost := make(chan error, 1)
		h.OnAttachLoss(func(e error) { lost <- e })

		tick <- time.Now()
		select {
		case <-lost:
		case <-time.After(5 * time.Second):
			t.Fatalf("attach-loss signal did not fire on detach")
		}
		select {
		case code := <-exited:
			t.Fatalf("health loop called os.Exit(%d); DD-2 anti-pattern was not removed", code)
		case <-time.After(500 * time.Millisecond):
		}
	})

	// #114
	t.Run("LoadAndAttach_PinRootUnsafeOwnership_ReturnsEPinRootUnsafeBeforeAnySyscall", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		pinRoot := mountBPFFS(t)
		// A pre-existing <pinRoot>/aksh owned safely but with a world-open mode
		// is unsafe and must be refused rather than repaired.
		unsafeDir := filepath.Join(pinRoot, "aksh")
		if err := os.Mkdir(unsafeDir, 0o777); err != nil {
			t.Fatalf("mkdir unsafe aksh dir: %v", err)
		}
		opts := loaderBaseOptions(t, cg)
		opts.PinLinks = true
		opts.PinRoot = pinRoot

		_, err := LoadAndAttach(opts)
		if l := loaderFor(opts); l != nil {
			t.Cleanup(l.closeAll)
		}
		assertFailureCode(t, err, E_PIN_ROOT_UNSAFE)

		entries, _ := os.ReadDir(unsafeDir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".link") {
				t.Fatalf("a pin was created under an unsafe pin root: %s", e.Name())
			}
		}
	})

	// #115
	t.Run("LoadAndAttach_MemlockRlimitTooLow_ReturnsEMemlock", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		loaderSeam.newCollection = func(*ebpf.CollectionSpec) (*ebpf.Collection, error) {
			return nil, fmt.Errorf("map create failed (RLIMIT_MEMLOCK too low): %w", unix.EPERM)
		}
		_, err := LoadAndAttach(loaderBaseOptions(t, cg))
		assertFailureCode(t, err, E_MEMLOCK)
	})

	// #116
	t.Run("LoadAndAttach_DoubleInvocation_SecondCallIsRejectedOrIdempotent", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		opts := loaderBaseOptions(t, cg)
		info := mustLoad(t, opts)

		_, err := LoadAndAttach(opts)
		if !errors.Is(err, ErrAlreadyAttached) {
			t.Fatalf("second LoadAndAttach error = %v, want ErrAlreadyAttached", err)
		}
		// The retained program set must not have doubled.
		if got := len(loaderFor(opts).info.ProgIDs); got != len(info.ProgIDs) {
			t.Fatalf("prog count after second call = %d, want %d (no double load)", got, len(info.ProgIDs))
		}
	})

	// #117
	t.Run("LoadAndAttach_KernelBelowFloor_ReturnsEKernelTooOld", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		loaded := false
		loaderSeam.kernelVersion = func() (KernelVersion, error) { return KernelVersion{Major: 5, Minor: 14}, nil }
		loaderSeam.newCollection = func(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
			loaded = true
			return ebpf.NewCollection(spec)
		}
		_, err := LoadAndAttach(loaderBaseOptions(t, cg))
		assertFailureCode(t, err, E_KERNEL_TOO_OLD)
		if loaded {
			t.Fatalf("programs were loaded despite a below-floor kernel")
		}
	})

	// #118
	t.Run("LoadAndAttach_ContextCancelledDuringLoad_UnwindsPartialState", func(t *testing.T) {
		saveLoaderSeam(t)
		cg := mountCgroup2(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		loaderSeam.newCollection = func(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
			coll, err := ebpf.NewCollection(spec)
			// Cancel mid-load, after real kernel objects exist, so the loader
			// must unwind them rather than proceed to attach.
			cancel()
			return coll, err
		}
		opts := loaderBaseOptions(t, cg)
		opts.Context = ctx
		_, err := LoadAndAttach(opts)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if loaderFor(opts) != nil {
			t.Fatalf("loader state was retained after a cancelled load; partial state leaked")
		}
	})
}

func TestLoadAndAttachPinLinks(t *testing.T) {
	// #111
	t.Run("PinLinks_SuccessAfterChownToPostDropUID_BPFObjGetSucceeds", func(t *testing.T) {
		saveLoaderSeam(t)
		requirePinnable(t)
		cg := mountCgroup2(t)
		pinRoot := mountBPFFS(t)
		opts := loaderBaseOptions(t, cg)
		opts.PinLinks = true
		opts.PinRoot = pinRoot
		info := mustLoad(t, opts)

		pin := firstLinkPin(info)
		if pin == "" {
			t.Fatalf("no link pin in AttachInfo.PinPaths = %v", info.PinPaths)
		}
		rep := runLoaderChildProbe(t, "objget_link", map[string]string{
			"AKSH_LOADER_PIN":  pin,
			"AKSH_LOADER_DROP": "1",
		})
		if rep.Errno != 0 {
			t.Fatalf("CAP_BPF-only BPF_OBJ_GET errno = %d, want 0 (success) after chown to %d", rep.Errno, testProxyUID)
		}
	})

	// #112
	t.Run("PinLinks_EACCESWhenRootOwned0600_BPFObjGetFails", func(t *testing.T) {
		saveLoaderSeam(t)
		requirePinnable(t)
		cg := mountCgroup2(t)
		pinRoot := mountBPFFS(t)
		opts := loaderBaseOptions(t, cg)
		mustLoad(t, opts)

		// Pin a link ourselves, root-owned at the default 0600, without any
		// chown to the proxy uid: a CAP_BPF-only reader must be denied by DAC.
		rootPin := filepath.Join(pinRoot, "rootowned.link")
		if err := loaderFor(opts).links[0].link.Pin(rootPin); err != nil {
			t.Fatalf("pin link root-owned: %v", err)
		}
		rep := runLoaderChildProbe(t, "objget_link", map[string]string{
			"AKSH_LOADER_PIN":  rootPin,
			"AKSH_LOADER_DROP": "1",
		})
		if rep.Errno != int(unix.EACCES) {
			t.Fatalf("CAP_BPF-only BPF_OBJ_GET errno = %d, want EACCES (%d) for a root-owned 0600 pin", rep.Errno, int(unix.EACCES))
		}
	})

	// #113
	t.Run("PinLinks_EINVALForBPFFRdonlyFlag_NotAnEscapeHatch", func(t *testing.T) {
		saveLoaderSeam(t)
		requirePinnable(t)
		cg := mountCgroup2(t)
		pinRoot := mountBPFFS(t)
		opts := loaderBaseOptions(t, cg)
		mustLoad(t, opts)

		pin := filepath.Join(pinRoot, "rdonly.link")
		if err := loaderFor(opts).links[0].link.Pin(pin); err != nil {
			t.Fatalf("pin link: %v", err)
		}
		rep := runLoaderChildProbe(t, "objget_link", map[string]string{
			"AKSH_LOADER_PIN":    pin,
			"AKSH_LOADER_RDONLY": "1",
		})
		if rep.Errno != int(unix.EINVAL) {
			t.Fatalf("BPF_OBJ_GET with BPF_F_RDONLY errno = %d, want EINVAL (%d)", rep.Errno, int(unix.EINVAL))
		}
	})
}

// TestLoadAndAttachProgramIDFailure is the FIX C regression: when a program's
// kernel id cannot be established, the load must fail closed with E_ATTACH and
// leave neither an AttachInfo nor any retained kernel state, rather than
// emitting a placeholder zero id into AttachInfo.ProgIDs (#101 contract). It
// forces the failure through the unexported programID seam.
func TestLoadAndAttachProgramIDFailure(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	loaderSeam.programID = func(*ebpf.Program) (uint32, error) {
		return 0, errors.New("forced program id failure")
	}
	opts := loaderBaseOptions(t, cg)

	info, err := LoadAndAttach(opts)
	assertFailureCode(t, err, E_ATTACH)
	if info != nil {
		t.Fatalf("AttachInfo = %v, want nil on a program-id failure", info)
	}
	if l := loaderFor(opts); l != nil {
		l.closeAll()
		t.Fatalf("loader state retained after a program-id failure; partial state leaked")
	}
}

// TestLoadAndAttachConcurrentSingleAttach is the FIX B regression: two callers
// racing LoadAndAttach on the same *Options must resolve to exactly one attach,
// with the loser refused ErrAlreadyAttached and no duplicate/leaked kernel
// objects. Run under -race, it also proves the check-and-reserve is atomic.
func TestLoadAndAttachConcurrentSingleAttach(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	opts := loaderBaseOptions(t, cg)
	t.Cleanup(func() {
		if l := loaderFor(opts); l != nil {
			l.closeAll()
		}
	})

	const callers = 2
	var wg sync.WaitGroup
	infos := make([]*Handle, callers)
	errs := make([]error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			infos[i], errs[i] = LoadAndAttach(opts)
		}(i)
	}
	close(start)
	wg.Wait()

	success, rejected := 0, 0
	for i := 0; i < callers; i++ {
		switch {
		case errs[i] == nil && infos[i] != nil:
			success++
		case errors.Is(errs[i], ErrAlreadyAttached):
			rejected++
		default:
			t.Fatalf("caller %d: unexpected result info=%v err=%v", i, infos[i], errs[i])
		}
	}
	if success != 1 {
		t.Fatalf("successful attaches = %d, want exactly 1", success)
	}
	if rejected != callers-1 {
		t.Fatalf("rejected callers = %d, want %d", rejected, callers-1)
	}
	l := loaderFor(opts)
	if l == nil {
		t.Fatalf("no retained loader state after a successful concurrent attach")
	}
	if got, want := len(l.info.ProgIDs), len(attachSpecs); got != want {
		t.Fatalf("retained ProgIDs = %d, want %d (no double load)", got, want)
	}
}

// assertFailureCode fails unless err is a *PreflightError carrying code.
func assertFailureCode(t *testing.T, err error, code FailureCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	var pf *PreflightError
	if !errors.As(err, &pf) {
		t.Fatalf("error = %v (%T), want a *PreflightError carrying %s", err, err, code)
	}
	if pf.Code != code {
		t.Fatalf("failure code = %s, want %s", pf.Code, code)
	}
}

// cookieMapLen counts entries in cookie_orig_dst.
func cookieMapLen(t *testing.T, coll *ebpf.Collection) int {
	t.Helper()
	m := coll.Maps[bpf.AkshbpfMapCookieOrigDst]
	var key uint64
	var val bpf.AkshbpfOrigDst
	n := 0
	it := m.Iterate()
	for it.Next(&key, &val) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate cookie_orig_dst: %v", err)
	}
	return n
}

// syncBuffer is a minimal concurrency-safe buffer for capturing slog output
// written by the health-check goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
