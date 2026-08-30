// Package capture_test exercises the platform-neutral slice of the capture
// package. This file carries no build tag on purpose: every symbol it touches
// is defined on all platforms, and the fixtures under testdata/cgroupfs are
// ordinary directories, so `go vet` test-compiles and `go test` runs it under
// both GOOS=windows and GOOS=linux. The only platform-sensitive operation is
// symlink creation, which unprivileged Windows hosts refuse; those cases call
// t.Skipf rather than failing (see makeDirLink).
package capture_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// Fixture paths under testdata/cgroupfs. The tree mirrors a kubelet systemd
// cgroup layout: <hostMount>/<qos>/<pod>/<container>.
const (
	fixtureHostMount = "testdata/cgroupfs/host"
	fixtureQoSSlice  = fixtureHostMount + "/kubepods.slice"
	fixturePodA      = fixtureQoSSlice + "/kubepods-burstable-pod11111111-2222-3333-4444-555555555555.slice"
	fixturePodB      = fixtureQoSSlice + "/kubepods-burstable-pod22222222-2222-3333-4444-555555555555.slice"
	fixturePodSingle = fixtureQoSSlice + "/kubepods-burstable-pod33333333-2222-3333-4444-555555555555.slice"
	fixturePodNoPID  = fixtureQoSSlice + "/kubepods-burstable-pod44444444-2222-3333-4444-555555555555.slice"
	fixturePodNoProc = fixtureQoSSlice + "/kubepods-burstable-pod55555555-2222-3333-4444-555555555555.slice"
	fixturePodNoCtl  = fixtureQoSSlice + "/kubepods-burstable-pod66666666-2222-3333-4444-555555555555.slice"
	fixturePodBadNam = fixtureQoSSlice + "/not-a-kubelet-name"
	fixtureOutside   = "testdata/cgroupfs/outside/strange-pod.slice"
	fixtureNotADir   = fixtureHostMount + "/notacgroup.txt"

	// fixtureProxyPID is the pid written into the container cgroup.procs files
	// of every fixture pod that is expected to satisfy V6.
	fixtureProxyPID = 4242
)

// fakeFSMagic is a plain-struct FSMagicProber. It reports cgroup2 for every
// path unless an override is registered, so that Windows hosts (which have no
// statfs) can exercise the V1/V2 checks against real directories.
type fakeFSMagic struct {
	def       uint32
	overrides map[string]uint32
	err       error
}

func (f fakeFSMagic) FSMagic(path string) (uint32, error) {
	if f.err != nil {
		return 0, f.err
	}
	if magic, ok := f.overrides[filepath.ToSlash(filepath.Clean(path))]; ok {
		return magic, nil
	}
	if f.def != 0 {
		return f.def, nil
	}
	return capture.Cgroup2SuperMagic, nil
}

// fakeNamespaceProber is a plain-struct CgroupNamespaceProber returning a fixed
// answer for the bounded host-mount search.
type fakeNamespaceProber struct {
	err error
}

func (f fakeNamespaceProber) ConfirmVisible(string) error { return f.err }

// newTestResolverConfig returns a config wired to the testdata fixtures.
func newTestResolverConfig() *capture.PodCgroupResolverConfig {
	return &capture.PodCgroupResolverConfig{
		HostCgroupMount: fixtureHostMount,
		ProxyPID:        fixtureProxyPID,
		FSMagic:         fakeFSMagic{},
	}
}

// newTestResolver constructs a resolver over the fixtures, failing the test if
// construction fails.
func newTestResolver(t *testing.T, cfg *capture.PodCgroupResolverConfig) *capture.PodCgroupResolver {
	t.Helper()
	r, err := capture.NewPodCgroupResolver(cfg)
	if err != nil {
		t.Fatalf("NewPodCgroupResolver() error = %v, want nil", err)
	}
	return r
}

// assertFailureCode asserts that err carries the expected E_* failure code.
func assertFailureCode(t *testing.T, err error, want capture.FailureCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", want)
	}
	var pfErr *capture.PreflightError
	if !errors.As(err, &pfErr) {
		t.Fatalf("error = %v (%T), want a *capture.PreflightError carrying %s", err, err, want)
	}
	if pfErr.Code != want {
		t.Fatalf("failure code = %s, want %s", pfErr.Code, want)
	}
}

// TestNewPodCgroupResolver covers the constructor guard (spec case #44).
func TestNewPodCgroupResolver(t *testing.T) {
	t.Run("NewPodCgroupResolver_NilConfig_ReturnsErrMissingConfig", func(t *testing.T) {
		r, err := capture.NewPodCgroupResolver(nil)
		if !errors.Is(err, capture.ErrMissingConfig) {
			t.Fatalf("NewPodCgroupResolver(nil) error = %v, want ErrMissingConfig", err)
		}
		if r != nil {
			t.Fatalf("NewPodCgroupResolver(nil) resolver = %v, want nil", r)
		}
	})
}

// TestResolvePodCgroupEntryGuards covers spec cases #23 and #24.
func TestResolvePodCgroupEntryGuards(t *testing.T) {
	t.Run("ResolvePodCgroup_NilResolver_ReturnsErrMissingResolver", func(t *testing.T) {
		var r *capture.PodCgroupResolver
		got, err := r.ResolvePodCgroup(fixturePodA)
		if !errors.Is(err, capture.ErrMissingResolver) {
			t.Fatalf("ResolvePodCgroup() error = %v, want ErrMissingResolver", err)
		}
		if got != "" {
			t.Fatalf("ResolvePodCgroup() path = %q, want empty", got)
		}
	})

	t.Run("ResolvePodCgroup_EmptyPodPath_ReturnsErrEmptyPodPath", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		got, err := r.ResolvePodCgroup("")
		if !errors.Is(err, capture.ErrEmptyPodPath) {
			t.Fatalf("ResolvePodCgroup(\"\") error = %v, want ErrEmptyPodPath", err)
		}
		if got != "" {
			t.Fatalf("ResolvePodCgroup(\"\") path = %q, want empty", got)
		}
	})
}

// TestResolvePodCgroupScopeValidations covers the V1-V5 scope assertions
// (spec cases #25-#31).
func TestResolvePodCgroupScopeValidations(t *testing.T) {
	t.Run("ResolvePodCgroup_PodPathNotDirectory_ReturnsECgroupScope", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		_, err := r.ResolvePodCgroup(fixtureNotADir)
		assertFailureCode(t, err, capture.E_CGROUP_SCOPE)
	})

	t.Run("ResolvePodCgroup_PodPathNotCgroup2Magic_ReturnsECgroupScope", func(t *testing.T) {
		cfg := newTestResolverConfig()
		cfg.FSMagic = fakeFSMagic{def: 0x01021994} // TMPFS_MAGIC
		r := newTestResolver(t, cfg)
		_, err := r.ResolvePodCgroup(fixturePodA)
		assertFailureCode(t, err, capture.E_CGROUP_SCOPE)
	})

	t.Run("ResolvePodCgroup_PodPathEqualsHostMount_ReturnsECgroupScope", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		_, err := r.ResolvePodCgroup(fixtureHostMount)
		assertFailureCode(t, err, capture.E_CGROUP_SCOPE)
	})

	t.Run("ResolvePodCgroup_PodPathNotDescendantOfHostMount_ReturnsECgroupScope", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		_, err := r.ResolvePodCgroup(fixtureOutside)
		assertFailureCode(t, err, capture.E_CGROUP_SCOPE)
	})

	t.Run("ResolvePodCgroup_DepthBelowTwo_ReturnsECgroupScope", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		_, err := r.ResolvePodCgroup(fixtureQoSSlice)
		assertFailureCode(t, err, capture.E_CGROUP_SCOPE)
	})

	t.Run("ResolvePodCgroup_MissingCgroupProcsFile_ReturnsECgroupScope", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		_, err := r.ResolvePodCgroup(fixturePodNoProc)
		assertFailureCode(t, err, capture.E_CGROUP_SCOPE)
	})

	t.Run("ResolvePodCgroup_MissingCgroupControllersFile_ReturnsECgroupScope", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		_, err := r.ResolvePodCgroup(fixturePodNoCtl)
		assertFailureCode(t, err, capture.E_CGROUP_SCOPE)
	})
}

// ensure the fixture constants that later units consume stay referenced.
var _ = []string{fixturePodB, fixturePodSingle, fixturePodNoPID, fixturePodBadNam}

// warningSink collects the non-fatal V7/V8 findings a resolver reports.
type warningSink struct {
	mu       sync.Mutex
	messages []string
}

func (w *warningSink) record(msg string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.messages = append(w.messages, msg)
}

func (w *warningSink) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.messages)
}

// TestResolvePodCgroupProxyPresence covers V6 (spec cases #32 and #33).
func TestResolvePodCgroupProxyPresence(t *testing.T) {
	t.Run("ResolvePodCgroup_ProxyPIDAbsentFromDescendantProcs_ReturnsEAmbiguousCgroup", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		_, err := r.ResolvePodCgroup(fixturePodNoPID)
		assertFailureCode(t, err, capture.E_AMBIGUOUS_CGROUP)
	})

	t.Run("ResolvePodCgroup_ProxyPIDPresentInDescendantProcs_Succeeds", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		got, err := r.ResolvePodCgroup(fixturePodA)
		if err != nil {
			t.Fatalf("ResolvePodCgroup(%q) error = %v, want nil", fixturePodA, err)
		}
		want, absErr := filepath.Abs(fixturePodA)
		if absErr != nil {
			t.Fatalf("filepath.Abs error = %v", absErr)
		}
		if got != want {
			t.Fatalf("ResolvePodCgroup(%q) = %q, want %q", fixturePodA, got, want)
		}
	})
}

// TestResolvePodCgroupWarnings covers the non-fatal V7 and V8 assertions
// (spec cases #34-#37).
func TestResolvePodCgroupWarnings(t *testing.T) {
	t.Run("ResolvePodCgroup_SingleChildDuringStartup_SucceedsWithWarning", func(t *testing.T) {
		sink := &warningSink{}
		cfg := newTestResolverConfig()
		cfg.OnWarning = sink.record
		r := newTestResolver(t, cfg)
		if _, err := r.ResolvePodCgroup(fixturePodSingle); err != nil {
			t.Fatalf("ResolvePodCgroup(%q) error = %v, want nil", fixturePodSingle, err)
		}
		if sink.count() == 0 {
			t.Fatalf("warnings = 0, want at least one V7 warning for a single child directory")
		}
	})

	t.Run("ResolvePodCgroup_TwoOrMoreChildDirs_SucceedsNoWarning", func(t *testing.T) {
		sink := &warningSink{}
		cfg := newTestResolverConfig()
		cfg.OnWarning = sink.record
		r := newTestResolver(t, cfg)
		if _, err := r.ResolvePodCgroup(fixturePodA); err != nil {
			t.Fatalf("ResolvePodCgroup(%q) error = %v, want nil", fixturePodA, err)
		}
		if got := sink.count(); got != 0 {
			t.Fatalf("warnings = %d (%v), want 0", got, sink.messages)
		}
	})

	t.Run("ResolvePodCgroup_BasenameMismatchesKubeletPattern_SucceedsWithWarning", func(t *testing.T) {
		sink := &warningSink{}
		cfg := newTestResolverConfig()
		cfg.OnWarning = sink.record
		r := newTestResolver(t, cfg)
		if _, err := r.ResolvePodCgroup(fixturePodBadNam); err != nil {
			t.Fatalf("ResolvePodCgroup(%q) error = %v, want nil", fixturePodBadNam, err)
		}
		if sink.count() == 0 {
			t.Fatalf("warnings = 0, want a V8 warning for a non-kubelet basename")
		}
	})

	t.Run("ResolvePodCgroup_BasenameMatchesKubeletPattern_SucceedsNoWarning", func(t *testing.T) {
		sink := &warningSink{}
		cfg := newTestResolverConfig()
		cfg.OnWarning = sink.record
		r := newTestResolver(t, cfg)
		if _, err := r.ResolvePodCgroup(fixturePodB); err != nil {
			t.Fatalf("ResolvePodCgroup(%q) error = %v, want nil", fixturePodB, err)
		}
		if got := sink.count(); got != 0 {
			t.Fatalf("warnings = %d (%v), want 0", got, sink.messages)
		}
	})
}

// TestResolvePodCgroupEdgeCases covers the namespace, walk-bound, happy-path,
// symlink, concurrency and error-wrapping cases (spec cases #38-#43).
func TestResolvePodCgroupEdgeCases(t *testing.T) {
	t.Run("ResolvePodCgroup_CgroupNamespaceOpaque_ReturnsECgroupnsOpaque", func(t *testing.T) {
		cfg := newTestResolverConfig()
		cfg.Namespace = fakeNamespaceProber{err: &capture.PreflightError{
			Code: capture.E_CGROUPNS_OPAQUE,
			Gate: "P5",
			Err:  errors.New("no host directory matches the namespace-local cgroup inode"),
		}}
		r := newTestResolver(t, cfg)
		_, err := r.ResolvePodCgroup(fixturePodA)
		assertFailureCode(t, err, capture.E_CGROUPNS_OPAQUE)
	})

	t.Run("ResolvePodCgroup_WalkExceedsLimit_ReturnsECgroupWalkLimit", func(t *testing.T) {
		root := t.TempDir()
		podPath := filepath.Join(root, "host", "kubepods.slice", "kubepods-burstable-pod77777777-2222-3333-4444-555555555555.slice")
		writeCgroupDir(t, podPath, "")
		// A pathologically deep subtree: deeper than the documented walk bound,
		// and with no cgroup.procs naming the proxy, so the walk cannot finish
		// before the bound fires.
		deep := podPath
		for i := 0; i < 20; i++ {
			deep = filepath.Join(deep, "level")
			writeCgroupDir(t, deep, "")
		}
		cfg := newTestResolverConfig()
		cfg.HostCgroupMount = filepath.Join(root, "host")
		r := newTestResolver(t, cfg)
		_, err := r.ResolvePodCgroup(podPath)
		assertFailureCode(t, err, capture.E_CGROUP_WALK_LIMIT)
	})

	t.Run("ResolvePodCgroup_AllValidationsPass_ReturnsResolvedPath", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		got, err := r.ResolvePodCgroup(fixturePodA)
		if err != nil {
			t.Fatalf("ResolvePodCgroup(%q) error = %v, want nil", fixturePodA, err)
		}
		want, absErr := filepath.Abs(fixturePodA)
		if absErr != nil {
			t.Fatalf("filepath.Abs error = %v", absErr)
		}
		if got != want {
			t.Fatalf("ResolvePodCgroup(%q) = %q, want %q", fixturePodA, got, want)
		}
	})

	t.Run("ResolvePodCgroup_SymlinkPodPath_ResolvesRealPathBeforeValidation", func(t *testing.T) {
		target, err := filepath.Abs(fixturePodA)
		if err != nil {
			t.Fatalf("filepath.Abs error = %v", err)
		}
		link := filepath.Join(t.TempDir(), "pod-link")
		if err := makeDirLink(t, target, link); err != nil {
			t.Skipf("host does not permit symlink creation: %v", err)
		}
		r := newTestResolver(t, newTestResolverConfig())
		got, err := r.ResolvePodCgroup(link)
		if err != nil {
			t.Fatalf("ResolvePodCgroup(symlink) error = %v, want nil", err)
		}
		want, err := filepath.EvalSymlinks(target)
		if err != nil {
			t.Fatalf("filepath.EvalSymlinks error = %v", err)
		}
		if got != want {
			t.Fatalf("ResolvePodCgroup(symlink) = %q, want the real path %q", got, want)
		}
	})

	// Not a spec case. The review flagged that HostCgroupMount is only
	// abs-cleaned while podPath is fully canonicalised, so a symlinked host
	// mount makes the V3 descendant check compare two different spellings of
	// the same directory. This case reproduces exactly that arrangement. It
	// skips where symlink creation is not permitted (plan risk R8) and runs on
	// Linux.
	t.Run("ResolvePodCgroup_SymlinkedHostMount_ResolvesRealPathBeforeScopeCheck", func(t *testing.T) {
		root := t.TempDir()
		realHost := filepath.Join(root, "real", "host")
		podName := "kubepods-burstable-pod88888888-2222-3333-4444-555555555555.slice"
		podPath := filepath.Join(realHost, "kubepods.slice", podName)
		writeCgroupDir(t, podPath, "")
		writeCgroupDir(t, filepath.Join(podPath, "container-a"), "4242\n")
		writeCgroupDir(t, filepath.Join(podPath, "container-b"), "7\n")

		link := filepath.Join(root, "link-host")
		if err := makeDirLink(t, realHost, link); err != nil {
			t.Skipf("host does not permit symlink creation: %v", err)
		}

		cfg := newTestResolverConfig()
		cfg.HostCgroupMount = link
		r := newTestResolver(t, cfg)

		got, err := r.ResolvePodCgroup(filepath.Join(link, "kubepods.slice", podName))
		if err != nil {
			t.Fatalf("ResolvePodCgroup(under symlinked host mount) error = %v, want nil", err)
		}
		want, err := filepath.EvalSymlinks(podPath)
		if err != nil {
			t.Fatalf("filepath.EvalSymlinks error = %v", err)
		}
		if got != want {
			t.Fatalf("ResolvePodCgroup() = %q, want the real path %q", got, want)
		}
	})

	t.Run("ResolvePodCgroup_ConcurrentCalls_EachReturnIndependentResult", func(t *testing.T) {
		r := newTestResolver(t, newTestResolverConfig())
		paths := []string{fixturePodA, fixturePodB, fixturePodNoPID, fixturePodSingle}
		type result struct {
			path string
			err  error
		}
		results := make([]result, len(paths)*8)
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				got, err := r.ResolvePodCgroup(paths[i%len(paths)])
				results[i] = result{path: got, err: err}
			}(i)
		}
		wg.Wait()
		for i, res := range results {
			in := paths[i%len(paths)]
			if in == fixturePodNoPID {
				assertFailureCode(t, res.err, capture.E_AMBIGUOUS_CGROUP)
				continue
			}
			if res.err != nil {
				t.Fatalf("ResolvePodCgroup(%q) error = %v, want nil", in, res.err)
			}
			want, err := filepath.Abs(in)
			if err != nil {
				t.Fatalf("filepath.Abs error = %v", err)
			}
			if res.path != want {
				t.Fatalf("ResolvePodCgroup(%q) = %q, want %q", in, res.path, want)
			}
		}
	})

	t.Run("ResolvePodCgroup_HostMountUnreadable_ReturnsWrappedStatError", func(t *testing.T) {
		cfg := newTestResolverConfig()
		cfg.HostCgroupMount = filepath.Join(t.TempDir(), "unreadable-host-mount")
		r := newTestResolver(t, cfg)
		_, err := r.ResolvePodCgroup(fixturePodA)
		if err == nil {
			t.Fatalf("ResolvePodCgroup() error = nil, want a wrapped os.Stat failure")
		}
		var pathErr *fs.PathError
		if !errors.As(err, &pathErr) {
			t.Fatalf("ResolvePodCgroup() error = %v (%T), want an error wrapping *fs.PathError", err, err)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("ResolvePodCgroup() error = %v, want it to wrap the underlying os.Stat failure", err)
		}
	})
}

// makeDirLink creates a directory symlink at link pointing at target.
// Unprivileged Windows hosts refuse symlink creation; a directory junction is
// not an alternative, because filepath.EvalSymlinks deliberately does not
// resolve junctions, so the caller skips instead (plan risk R8).
func makeDirLink(t *testing.T, target, link string) error {
	t.Helper()
	return os.Symlink(target, link)
}

// writeCgroupDir creates dir and gives it the two files V5 requires, with procs
// as the content of cgroup.procs.
func writeCgroupDir(t *testing.T, dir, procs string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(procs), 0o644); err != nil {
		t.Fatalf("WriteFile(cgroup.procs) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(cgroup.controllers) error = %v", err)
	}
}
