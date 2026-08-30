package capture_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// recorder collects the gate names the fakes were called from, so that the
// aggregate case can assert the gate ordering (spec case #74).
type recorder struct {
	mu    sync.Mutex
	gates []string
}

func (r *recorder) mark(gate string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gates = append(r.gates, gate)
}

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.gates))
	copy(out, r.gates)
	return out
}

type fakeCgo struct {
	rec     *recorder
	enabled bool
}

func (f *fakeCgo) CgoEnabled() bool { f.rec.mark("P1"); return f.enabled }

type fakeUname struct {
	rec     *recorder
	release string
	err     error
}

func (f *fakeUname) Release() (string, error) { f.rec.mark("P2"); return f.release, f.err }

type fakeStatfs struct {
	rec   *recorder
	gates map[string]string
	magic map[string]uint32
	err   error
}

func (f *fakeStatfs) FSMagic(path string) (uint32, error) {
	f.rec.mark(f.gates[path])
	if f.err != nil {
		return 0, f.err
	}
	return f.magic[path], nil
}

type fakeBPFFS struct {
	rec        *recorder
	mounted    bool
	statErr    error
	mountErr   error
	mountCalls int
}

func (f *fakeBPFFS) IsBPFFSMounted(string) (bool, error) {
	f.rec.mark("P6")
	return f.mounted, f.statErr
}

func (f *fakeBPFFS) MountBPFFS(string) error {
	f.mountCalls++
	if f.mountErr != nil {
		return f.mountErr
	}
	f.mounted = true
	return nil
}

type fakeCaps struct {
	rec     *recorder
	present map[string]bool
	err     error
}

func (f *fakeCaps) HasCapability(name string) (bool, error) {
	f.rec.mark("P7")
	if f.err != nil {
		return false, f.err
	}
	return f.present[name], nil
}

type fakeMemlock struct {
	rec *recorder
	err error
}

func (f *fakeMemlock) RemoveMemlock() error { f.rec.mark("P8"); return f.err }

type fakeResolver struct {
	rec  *recorder
	path string
	err  error
}

func (f *fakeResolver) ResolvePodCgroup(string) (string, error) {
	f.rec.mark("P5")
	return f.path, f.err
}

type fakeLoader struct {
	rec *recorder
	ids []uint32
	err error
}

func (f *fakeLoader) LoadPrograms() ([]uint32, error) { f.rec.mark("P9"); return f.ids, f.err }

type fakeConfigMap struct {
	rec       *recorder
	written   []byte
	readback  []byte
	writeErr  error
	readErr   error
	freezeErr error
}

func (f *fakeConfigMap) WriteConfig(image []byte) error {
	f.rec.mark("P10")
	if f.writeErr != nil {
		return f.writeErr
	}
	f.written = append([]byte(nil), image...)
	return nil
}

func (f *fakeConfigMap) ReadConfig() ([]byte, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if f.readback != nil {
		return f.readback, nil
	}
	return f.written, nil
}

func (f *fakeConfigMap) FreezeConfig() error { return f.freezeErr }

type fakeAttacher struct {
	rec        *recorder
	attached   []uint32
	requeried  []uint32
	attachErr  error
	requeryErr error
}

func (f *fakeAttacher) Attach(string) ([]uint32, error) {
	f.rec.mark("P11")
	return f.attached, f.attachErr
}

func (f *fakeAttacher) AttachedProgIDs(string) ([]uint32, error) {
	if f.requeryErr != nil {
		return nil, f.requeryErr
	}
	if f.requeried != nil {
		return f.requeried, nil
	}
	return f.attached, nil
}

type fakePinStater struct {
	rec  *recorder
	info capture.PinRootInfo
	err  error
}

func (f *fakePinStater) StatPinRoot(string) (capture.PinRootInfo, error) {
	f.rec.mark("P15")
	return f.info, f.err
}

type fakeRedirectProber struct {
	rec *recorder
	err error
}

func (f *fakeRedirectProber) ProbeRedirect() error { f.rec.mark("P12"); return f.err }

type fakePrivDropper struct {
	rec *recorder
	got capture.PrivDropConfig
	err error
}

func (f *fakePrivDropper) DropPrivileges(cfg capture.PrivDropConfig) error {
	f.rec.mark("P13")
	f.got = cfg
	return f.err
}

type fakeUIDProber struct {
	rec *recorder
	err error
}

func (f *fakeUIDProber) ProbeUIDExclusion() error { f.rec.mark("P14"); return f.err }

// seamSet holds every fake so that a case can mutate exactly one of them and
// leave the rest on their success path.
type seamSet struct {
	rec      *recorder
	cgo      *fakeCgo
	uname    *fakeUname
	statfs   *fakeStatfs
	bpffs    *fakeBPFFS
	caps     *fakeCaps
	memlock  *fakeMemlock
	resolver *fakeResolver
	loader   *fakeLoader
	config   *fakeConfigMap
	attacher *fakeAttacher
	pinStat  *fakePinStater
	redirect *fakeRedirectProber
	privdrop *fakePrivDropper
	uidProbe *fakeUIDProber
}

const (
	testLocalMount = "/sys/fs/cgroup"
	testHostMount  = "/host/sys/fs/cgroup"
	testPodPath    = "/host/sys/fs/cgroup/kubepods.slice/kubepods-burstable-pod11111111-2222-3333-4444-555555555555.slice"
)

// newSeams returns a seam set on which every gate passes.
func newSeams() *seamSet {
	rec := &recorder{}
	return &seamSet{
		rec:   rec,
		cgo:   &fakeCgo{rec: rec, enabled: false},
		uname: &fakeUname{rec: rec, release: "5.15.0-1064-azure"},
		statfs: &fakeStatfs{
			rec:   rec,
			gates: map[string]string{testLocalMount: "P3", testHostMount: "P4"},
			magic: map[string]uint32{
				testLocalMount: capture.Cgroup2SuperMagic,
				testHostMount:  capture.Cgroup2SuperMagic,
			},
		},
		bpffs:    &fakeBPFFS{rec: rec, mounted: true},
		caps:     &fakeCaps{rec: rec, present: map[string]bool{"CAP_BPF": true, "CAP_NET_ADMIN": true}},
		memlock:  &fakeMemlock{rec: rec},
		resolver: &fakeResolver{rec: rec, path: testPodPath},
		loader:   &fakeLoader{rec: rec, ids: []uint32{101, 102, 103}},
		config:   &fakeConfigMap{rec: rec},
		attacher: &fakeAttacher{rec: rec, attached: []uint32{101, 102, 103}},
		pinStat:  &fakePinStater{rec: rec, info: capture.PinRootInfo{IsDir: true, UID: 0, GID: 0, Mode: 0o700}},
		redirect: &fakeRedirectProber{rec: rec},
		privdrop: &fakePrivDropper{rec: rec},
		uidProbe: &fakeUIDProber{rec: rec},
	}
}

func (s *seamSet) seams() capture.PreflightSeams {
	return capture.PreflightSeams{
		Cgo:          s.cgo,
		Uname:        s.uname,
		FSMagic:      s.statfs,
		BPFFS:        s.bpffs,
		Capabilities: s.caps,
		Memlock:      s.memlock,
		Cgroup:       s.resolver,
		Loader:       s.loader,
		Config:       s.config,
		Attacher:     s.attacher,
		PinRoot:      s.pinStat,
		Redirect:     s.redirect,
		PrivDrop:     s.privdrop,
		UIDExclusion: s.uidProbe,
	}
}

// preflightOptions returns options that Validate() accepts and that exercise
// every preflight gate.
func preflightOptions() capture.Options {
	opts := capture.DefaultOptions()
	opts.PodPath = testPodPath
	opts.HostCgroupMount = testHostMount
	opts.LocalCgroupMount = testLocalMount
	opts.Metrics = fakeMetrics{}
	opts.PinRoot = "/sys/fs/bpf"
	return opts
}

// TestRunPreflight covers unit test spec section 6 (#45-#74): the seam-only
// preflight gates P1-P15.
func TestRunPreflight(t *testing.T) {
	// Case #45. The spec name says "CgoDisabled" but gate P1 fails when cgo is
	// ENABLED, because syscall.AllThreadsSyscall requires a pure-Go build. The
	// name is kept verbatim; the input is the one the gate actually rejects.
	t.Run("RunPreflight_CgoDisabled_ReturnsECgoEnabled", func(t *testing.T) {
		s := newSeams()
		s.cgo.enabled = true
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_CGO_ENABLED)
	})

	t.Run("RunPreflight_KernelVersionBelowFloor_ReturnsEKernelTooOld", func(t *testing.T) {
		s := newSeams()
		s.uname.release = "5.14.0-284.el9.x86_64"
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_KERNEL_TOO_OLD)
	})

	t.Run("RunPreflight_KernelVersionAtFloor_PassesGate", func(t *testing.T) {
		s := newSeams()
		s.uname.release = "5.15.0"
		opts := preflightOptions()
		if err := capture.RunPreflight(&opts, s.seams()); err != nil {
			t.Fatalf("RunPreflight() error = %v, want nil", err)
		}
	})

	t.Run("RunPreflight_LocalCgroupNotV2_ReturnsENoCgroup2", func(t *testing.T) {
		s := newSeams()
		s.statfs.magic[testLocalMount] = 0x27e0eb // CGROUP_SUPER_MAGIC (v1)
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_NO_CGROUP2)
	})

	t.Run("RunPreflight_HostCgroupNotV2_ReturnsENoCgroup2", func(t *testing.T) {
		s := newSeams()
		s.statfs.magic[testHostMount] = 0x27e0eb
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_NO_CGROUP2)
	})

	t.Run("RunPreflight_CgroupResolutionFails_ReturnsECgroupScope", func(t *testing.T) {
		s := newSeams()
		s.resolver.err = &capture.PreflightError{Code: capture.E_CGROUP_SCOPE, Gate: "V2"}
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_CGROUP_SCOPE)
	})

	t.Run("RunPreflight_CgroupResolutionAmbiguous_ReturnsEAmbiguousCgroup", func(t *testing.T) {
		s := newSeams()
		s.resolver.err = &capture.PreflightError{Code: capture.E_AMBIGUOUS_CGROUP, Gate: "V6"}
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_AMBIGUOUS_CGROUP)
	})

	t.Run("RunPreflight_CgroupNamespaceOpaque_ReturnsECgroupnsOpaque", func(t *testing.T) {
		s := newSeams()
		s.resolver.err = &capture.PreflightError{Code: capture.E_CGROUPNS_OPAQUE, Gate: "V6"}
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_CGROUPNS_OPAQUE)
	})

	t.Run("RunPreflight_CgroupWalkLimitExceeded_ReturnsECgroupWalkLimit", func(t *testing.T) {
		s := newSeams()
		s.resolver.err = &capture.PreflightError{Code: capture.E_CGROUP_WALK_LIMIT, Gate: "V6"}
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_CGROUP_WALK_LIMIT)
	})

	t.Run("RunPreflight_BpffsNotMountedNoAutoMount_ReturnsENoBpffs", func(t *testing.T) {
		s := newSeams()
		s.bpffs.mounted = false
		opts := preflightOptions()
		opts.MountBPFFS = false
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_NO_BPFFS)
		if s.bpffs.mountCalls != 0 {
			t.Fatalf("MountBPFFS called %d times, want 0 when MountBPFFS=false", s.bpffs.mountCalls)
		}
	})

	t.Run("RunPreflight_BpffsNotMountedAutoMountEnabled_MountsAndPasses", func(t *testing.T) {
		s := newSeams()
		s.bpffs.mounted = false
		opts := preflightOptions()
		opts.MountBPFFS = true
		if err := capture.RunPreflight(&opts, s.seams()); err != nil {
			t.Fatalf("RunPreflight() error = %v, want nil", err)
		}
		if s.bpffs.mountCalls != 1 {
			t.Fatalf("MountBPFFS called %d times, want 1", s.bpffs.mountCalls)
		}
	})

	t.Run("RunPreflight_BpffsMountFails_ReturnsENoBpffs", func(t *testing.T) {
		s := newSeams()
		s.bpffs.mounted = false
		s.bpffs.mountErr = errors.New("mount: operation not permitted")
		opts := preflightOptions()
		opts.MountBPFFS = true
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_NO_BPFFS)
	})

	t.Run("RunPreflight_MissingCapBPF_ReturnsEMissingCaps", func(t *testing.T) {
		s := newSeams()
		s.caps.present["CAP_BPF"] = false
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_MISSING_CAPS)
	})

	t.Run("RunPreflight_MissingCapNetAdmin_ReturnsEMissingCaps", func(t *testing.T) {
		s := newSeams()
		s.caps.present["CAP_NET_ADMIN"] = false
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_MISSING_CAPS)
	})

	t.Run("RunPreflight_AllRequiredCapsPresent_PassesGate", func(t *testing.T) {
		s := newSeams()
		opts := preflightOptions()
		if err := capture.RunPreflight(&opts, s.seams()); err != nil {
			t.Fatalf("RunPreflight() error = %v, want nil", err)
		}
	})

	t.Run("RunPreflight_MemlockRaiseFails_ReturnsEMemlock", func(t *testing.T) {
		s := newSeams()
		s.memlock.err = errors.New("setrlimit: operation not permitted")
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_MEMLOCK)
	})

	t.Run("RunPreflight_MemlockRaiseSucceeds_PassesGate", func(t *testing.T) {
		s := newSeams()
		opts := preflightOptions()
		if err := capture.RunPreflight(&opts, s.seams()); err != nil {
			t.Fatalf("RunPreflight() error = %v, want nil", err)
		}
		if got := s.rec.seen(); len(got) == 0 {
			t.Fatal("no gates ran")
		}
	})

	t.Run("RunPreflight_ProgramLoadSeamFails_ReturnsEProgLoad", func(t *testing.T) {
		s := newSeams()
		s.loader.err = errors.New("verifier: R2 invalid mem access")
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_PROG_LOAD)
	})

	t.Run("RunPreflight_ConfigWriteSeamFails_ReturnsEConfigWrite", func(t *testing.T) {
		s := newSeams()
		s.config.writeErr = errors.New("bpf: map update elem: operation not permitted")
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_CONFIG_WRITE)
	})

	t.Run("RunPreflight_ConfigReadbackMismatch_ReturnsEConfigWrite", func(t *testing.T) {
		s := newSeams()
		s.config.readback = make([]byte, capture.ConfigImageSize)
		s.config.readback[0] = 0xff
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_CONFIG_WRITE)
	})

	t.Run("RunPreflight_ConfigFreezeSeamFails_ReturnsEConfigFreeze", func(t *testing.T) {
		s := newSeams()
		s.config.freezeErr = errors.New("bpf: map freeze: operation not permitted")
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_CONFIG_FREEZE)
	})

	t.Run("RunPreflight_AttachSeamFails_ReturnsEAttach", func(t *testing.T) {
		s := newSeams()
		s.attacher.attachErr = errors.New("bpf: link create: operation not permitted")
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_ATTACH)
	})

	t.Run("RunPreflight_AttachIDRequeryMismatch_ReturnsEAttachVerify", func(t *testing.T) {
		s := newSeams()
		s.attacher.requeried = []uint32{101, 102, 999}
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_ATTACH_VERIFY)
	})

	t.Run("RunPreflight_PinRootUnsafeOwnership_ReturnsEPinRootUnsafe", func(t *testing.T) {
		s := newSeams()
		s.pinStat.info = capture.PinRootInfo{IsDir: true, UID: 1000, GID: 1000, Mode: 0o777}
		opts := preflightOptions()
		opts.PinLinks = true
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_PIN_ROOT_UNSAFE)
	})

	t.Run("RunPreflight_PinRootSafeOwnership_PassesGate", func(t *testing.T) {
		s := newSeams()
		opts := preflightOptions()
		opts.PinLinks = true
		if err := capture.RunPreflight(&opts, s.seams()); err != nil {
			t.Fatalf("RunPreflight() error = %v, want nil", err)
		}
		if !containsGate(s.rec.seen(), "P15") {
			t.Fatal("gate P15 did not run with PinLinks=true")
		}
	})

	t.Run("RunPreflight_RedirectSelfProbeSeamFails_ReturnsEProbe", func(t *testing.T) {
		s := newSeams()
		s.redirect.err = errors.New("self-probe: connection reached the original destination")
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_PROBE)
	})

	t.Run("RunPreflight_PrivilegeDropSeamFails_ReturnsEPrivdrop", func(t *testing.T) {
		s := newSeams()
		s.privdrop.err = errors.New("step 7: setresuid: operation not permitted")
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_PRIVDROP)
	})

	t.Run("RunPreflight_PrivilegeDropSeamSucceeds_PassesGate", func(t *testing.T) {
		s := newSeams()
		opts := preflightOptions()
		if err := capture.RunPreflight(&opts, s.seams()); err != nil {
			t.Fatalf("RunPreflight() error = %v, want nil", err)
		}
		if s.privdrop.got.ProxyUID != opts.ProxyUID || s.privdrop.got.ProxyGID != opts.ProxyGID {
			t.Fatalf("PrivDropConfig = %+v, want ProxyUID=%d ProxyGID=%d",
				s.privdrop.got, opts.ProxyUID, opts.ProxyGID)
		}
	})

	t.Run("RunPreflight_UidExclusionProbeSeamFails_ReturnsEProbeUid", func(t *testing.T) {
		s := newSeams()
		s.uidProbe.err = errors.New("uid-exclusion probe: proxy traffic was captured")
		opts := preflightOptions()
		assertFailureCode(t, capture.RunPreflight(&opts, s.seams()), capture.E_PROBE_UID)
	})

	t.Run("RunPreflight_AllGatesPass_ReturnsNilError", func(t *testing.T) {
		s := newSeams()
		opts := preflightOptions()
		opts.PinLinks = true
		opts.RunProbe = true
		if err := capture.RunPreflight(&opts, s.seams()); err != nil {
			t.Fatalf("RunPreflight() error = %v, want nil", err)
		}
		want := []string{"P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10", "P11", "P15", "P12", "P13", "P14"}
		got := collapse(s.rec.seen())
		if len(got) != len(want) {
			t.Fatalf("gate order = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("gate order = %v, want %v", got, want)
			}
		}
	})
}

// TestRunEnvironmentPreflight covers the extracted P1-P8 environment-only gate
// sequence: it must run exactly the environment checks, in order, stop at the
// first failure, and never reach the P9-P15 kernel-object gates (those are done
// in production by LoadAndAttach and the orchestrator, so wiring them here would
// double-load).
func TestRunEnvironmentPreflight(t *testing.T) {
	t.Run("AllEnvironmentGatesPass_ReturnsNilAndRunsOnlyP1toP8", func(t *testing.T) {
		s := newSeams()
		opts := preflightOptions()
		if err := capture.RunEnvironmentPreflight(&opts, s.seams()); err != nil {
			t.Fatalf("RunEnvironmentPreflight() error = %v, want nil", err)
		}
		want := []string{"P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"}
		got := collapse(s.rec.seen())
		if len(got) != len(want) {
			t.Fatalf("gate order = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("gate order = %v, want %v", got, want)
			}
		}
		for _, g := range got {
			switch g {
			case "P9", "P10", "P11", "P12", "P13", "P14", "P15":
				t.Fatalf("environment preflight ran kernel-object gate %s: %v", g, got)
			}
		}
	})

	// Each case forces exactly one environment gate to fail and asserts the
	// stable code plus that no later environment gate ran.
	cases := []struct {
		name    string
		mutate  func(*seamSet, *capture.Options)
		code    capture.FailureCode
		lastRun string
	}{
		{
			name:    "P1_CgoEnabled",
			mutate:  func(s *seamSet, _ *capture.Options) { s.cgo.enabled = true },
			code:    capture.E_CGO_ENABLED,
			lastRun: "P1",
		},
		{
			name:    "P2_KernelTooOld",
			mutate:  func(s *seamSet, _ *capture.Options) { s.uname.release = "5.14.0" },
			code:    capture.E_KERNEL_TOO_OLD,
			lastRun: "P2",
		},
		{
			name:    "P3_LocalCgroupNotV2",
			mutate:  func(s *seamSet, _ *capture.Options) { s.statfs.magic[testLocalMount] = 0x27e0eb },
			code:    capture.E_NO_CGROUP2,
			lastRun: "P3",
		},
		{
			name: "P5_CgroupScope",
			mutate: func(s *seamSet, _ *capture.Options) {
				s.resolver.err = &capture.PreflightError{Code: capture.E_CGROUP_SCOPE, Gate: "V2"}
			},
			code:    capture.E_CGROUP_SCOPE,
			lastRun: "P5",
		},
		{
			name:    "P6_NoBpffs",
			mutate:  func(s *seamSet, o *capture.Options) { s.bpffs.mounted = false; o.MountBPFFS = false },
			code:    capture.E_NO_BPFFS,
			lastRun: "P6",
		},
		{
			name:    "P7_MissingCaps",
			mutate:  func(s *seamSet, _ *capture.Options) { s.caps.present["CAP_BPF"] = false },
			code:    capture.E_MISSING_CAPS,
			lastRun: "P7",
		},
		{
			name:    "P8_Memlock",
			mutate:  func(s *seamSet, _ *capture.Options) { s.memlock.err = errors.New("setrlimit: EPERM") },
			code:    capture.E_MEMLOCK,
			lastRun: "P8",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSeams()
			opts := preflightOptions()
			tc.mutate(s, &opts)
			assertFailureCode(t, capture.RunEnvironmentPreflight(&opts, s.seams()), tc.code)
			got := collapse(s.rec.seen())
			if len(got) == 0 || got[len(got)-1] != tc.lastRun {
				t.Fatalf("gates ran = %v, want to stop at %s", got, tc.lastRun)
			}
		})
	}
}

// collapse removes consecutive duplicates, so that a gate probing several
// values through one seam still contributes a single entry.
func collapse(in []string) []string {
	out := make([]string, 0, len(in))
	for _, g := range in {
		if len(out) > 0 && out[len(out)-1] == g {
			continue
		}
		out = append(out, g)
	}
	return out
}

func containsGate(gates []string, want string) bool {
	for _, g := range gates {
		if g == want {
			return true
		}
	}
	return false
}
