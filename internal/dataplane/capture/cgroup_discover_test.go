// Package capture_test exercises the cgroup discovery half of design section
// 6.1.2. Like cgroup_test.go this file carries no build tag: the bounded walk
// and the match arithmetic are ordinary Go behind two seams, so every branch -
// including the walk bounds and the ambiguous-match case, which are impractical
// to provoke against a real cgroup tree - runs under both GOOS=windows and
// GOOS=linux.
package capture_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

const (
	// fixtureContainerA is the container cgroup inside fixturePodA. Discovery
	// identifies the *container* cgroup; the pod cgroup is its parent.
	fixtureContainerA = fixturePodA + "/cri-containerd-aaaa.scope"
	// fixtureRelA is what /proc/self/cgroup reads for that container when the
	// process is not in a private cgroup namespace (case A).
	fixtureRelA = "/kubepods.slice/kubepods-burstable-pod11111111-2222-3333-4444-555555555555.slice/cri-containerd-aaaa.scope"
	// fixtureLocalMount stands in for the proxy's own cgroup2 mount. It is
	// never read from disk: FSMagic and InodeOf are both seams.
	fixtureLocalMount = "/sys/fs/cgroup"
	// fixtureSelfIno is the inode the case B search matches on.
	fixtureSelfIno = 987654
	// walkDepthLimit and walkDirsLimit mirror the unexported bounds in
	// cgroup.go. They are duplicated rather than exported because the bounds
	// are an implementation detail; the tests below assert the *behaviour* at
	// the bound, and a drift in either constant makes them fail loudly.
	walkDepthLimit = 12
	walkDirsLimit  = 50000
)

// fakeInodeStater is a plain-struct CgroupInodeStater.
type fakeInodeStater struct {
	ino uint64
	err error
}

func (f fakeInodeStater) InodeOf(string) (uint64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.ino, nil
}

// realTreeDirs lists the real testdata directories, assigning each one a
// synthetic inode from inos (keyed by slash-separated path relative to the walk
// root). Unlisted directories get inode 0, which never matches a target.
type realTreeDirs struct {
	root string
	inos map[string]uint64
	err  error
}

func (d realTreeDirs) ReadCgroupDirs(path string) ([]capture.CgroupDirEntry, error) {
	if d.err != nil {
		return nil, d.err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]capture.CgroupDirEntry, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		rel, relErr := filepath.Rel(d.root, filepath.Join(path, entry.Name()))
		if relErr != nil {
			return nil, relErr
		}
		out = append(out, capture.CgroupDirEntry{
			Name: entry.Name(),
			Ino:  d.inos[filepath.ToSlash(rel)],
		})
	}
	return out, nil
}

// syntheticDirs generates a tree without touching the filesystem: every
// directory has fanout children, forever. It exists to drive the walk past its
// bounds, which no realistic fixture tree can do. Children are named
// "d<depth>_<index>" so that a reader given only a path can tell how deep it is.
type syntheticDirs struct {
	fanout     int
	rootFanout int    // children of the walk root, when it differs from fanout
	matchDepth int    // depth whose first child carries matchIno; 0 disables
	matchIno   uint64 // inode planted at matchDepth
}

// syntheticDepth recovers the depth encoded in a generated directory name. The
// walk root is not generated, so anything unparseable is depth 0.
func syntheticDepth(path string) int {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "d") {
		return 0
	}
	head, _, _ := strings.Cut(strings.TrimPrefix(base, "d"), "_")
	depth, err := strconv.Atoi(head)
	if err != nil {
		return 0
	}
	return depth
}

func (d syntheticDirs) ReadCgroupDirs(path string) ([]capture.CgroupDirEntry, error) {
	depth := syntheticDepth(path)
	n := d.fanout
	if depth == 0 && d.rootFanout > 0 {
		n = d.rootFanout
	}
	out := make([]capture.CgroupDirEntry, 0, n)
	for i := 0; i < n; i++ {
		entry := capture.CgroupDirEntry{Name: fmt.Sprintf("d%d_%d", depth+1, i)}
		if d.matchDepth > 0 && depth+1 == d.matchDepth && i == 0 {
			entry.Ino = d.matchIno
		}
		out = append(out, entry)
	}
	return out, nil
}

// writeProcCgroup writes a /proc/self/cgroup stand-in and returns its path.
func writeProcCgroup(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write proc cgroup fixture: %v", err)
	}
	return path
}

// newDiscoveryConfig returns a config wired for discovery over the fixtures.
func newDiscoveryConfig(procPath string) *capture.PodCgroupResolverConfig {
	cfg := newTestResolverConfig()
	cfg.ProcCgroupPath = procPath
	cfg.LocalCgroupMount = fixtureLocalMount
	cfg.Inode = fakeInodeStater{ino: fixtureSelfIno}
	return cfg
}

// wantPodA is the absolute form of fixturePodA, which is what a successful
// discovery must return.
func wantPodA(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(fixturePodA)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", fixturePodA, err)
	}
	return abs
}

// absHostMount is the absolute walk root, which realTreeDirs keys against.
func absHostMount(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(fixtureHostMount)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", fixtureHostMount, err)
	}
	return abs
}

// TestDiscoverPodCgroupGuards covers the inputs discovery refuses outright.
// Each one is a missing input with no safe default: guessing any of them would
// mean guessing whose traffic to capture.
func TestDiscoverPodCgroupGuards(t *testing.T) {
	t.Run("DiscoverPodCgroup_NilResolver_ReturnsErrMissingResolver", func(t *testing.T) {
		var r *capture.PodCgroupResolver
		if _, err := r.DiscoverPodCgroup(); !errors.Is(err, capture.ErrMissingResolver) {
			t.Fatalf("error = %v, want ErrMissingResolver", err)
		}
	})

	t.Run("DiscoverPodCgroup_NoProcCgroupPath_ReturnsErrMissingProcCgroupPath", func(t *testing.T) {
		cfg := newDiscoveryConfig("")
		r := newTestResolver(t, cfg)
		if _, err := r.DiscoverPodCgroup(); !errors.Is(err, capture.ErrMissingProcCgroupPath) {
			t.Fatalf("error = %v, want ErrMissingProcCgroupPath", err)
		}
	})

	t.Run("DiscoverPodCgroup_NoLocalMount_ReturnsErrMissingLocalMount", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::"+fixtureRelA+"\n"))
		cfg.LocalCgroupMount = ""
		r := newTestResolver(t, cfg)
		if _, err := r.DiscoverPodCgroup(); !errors.Is(err, capture.ErrMissingLocalMount) {
			t.Fatalf("error = %v, want ErrMissingLocalMount", err)
		}
	})

	t.Run("DiscoverPodCgroup_NoHostMount_ReturnsErrMissingHostMount", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::"+fixtureRelA+"\n"))
		cfg.HostCgroupMount = ""
		r := newTestResolver(t, cfg)
		if _, err := r.DiscoverPodCgroup(); !errors.Is(err, capture.ErrMissingHostMount) {
			t.Fatalf("error = %v, want ErrMissingHostMount", err)
		}
	})
}

// TestDiscoverPodCgroupProcParsing covers step 1: reading the cgroup v2 line.
func TestDiscoverPodCgroupProcParsing(t *testing.T) {
	t.Run("DiscoverPodCgroup_UnreadableProcFile_ReturnsNoCgroup2", func(t *testing.T) {
		cfg := newDiscoveryConfig(filepath.Join(t.TempDir(), "absent"))
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_NO_CGROUP2)
	})

	t.Run("DiscoverPodCgroup_V1OnlyHierarchy_ReturnsNoCgroup2", func(t *testing.T) {
		// A pure cgroup v1 node: every line has a non-zero hierarchy id and a
		// controller list. Phase 5A does not support it.
		cfg := newDiscoveryConfig(writeProcCgroup(t,
			"12:devices:/kubepods/burstable/podaaaa\n11:memory:/kubepods/burstable/podaaaa\n"))
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_NO_CGROUP2)
	})

	t.Run("DiscoverPodCgroup_EmptyV2Path_ReturnsNoCgroup2", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::\n"))
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_NO_CGROUP2)
	})

	t.Run("DiscoverPodCgroup_HybridHierarchy_UsesTheV2Line", func(t *testing.T) {
		// A hybrid node carries both. Only the "0::" line describes the unified
		// hierarchy, and it may appear after the v1 lines.
		cfg := newDiscoveryConfig(writeProcCgroup(t,
			"12:devices:/some/v1/path\n0::"+fixtureRelA+"\n"))
		r := newTestResolver(t, cfg)
		got, err := r.DiscoverPodCgroup()
		if err != nil {
			t.Fatalf("DiscoverPodCgroup() error = %v, want nil", err)
		}
		if got != wantPodA(t) {
			t.Fatalf("DiscoverPodCgroup() = %q, want %q", got, wantPodA(t))
		}
	})
}

// TestDiscoverPodCgroupLocalMount covers step 2: the local mount must really be
// cgroup2. On a hybrid v1/v2 host /sys/fs/cgroup is tmpfs, and an inode taken
// from tmpfs would be compared against cgroup2 inodes - a match would then be a
// coincidence rather than an identity.
func TestDiscoverPodCgroupLocalMount(t *testing.T) {
	t.Run("DiscoverPodCgroup_LocalMountNotCgroup2_ReturnsNoCgroup2", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.FSMagic = fakeFSMagic{def: 0x01021994} // tmpfs
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_NO_CGROUP2)
	})

	t.Run("DiscoverPodCgroup_StatfsFails_ReturnsNoCgroup2", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.FSMagic = fakeFSMagic{err: errors.New("statfs refused")}
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_NO_CGROUP2)
	})
}

// TestDiscoverPodCgroupCaseA covers step 3: no cgroup namespace, so
// /proc/self/cgroup already names the container relative to the host root.
func TestDiscoverPodCgroupCaseA(t *testing.T) {
	t.Run("DiscoverPodCgroup_NamedContainerPath_ReturnsPodParent", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::"+fixtureRelA+"\n"))
		r := newTestResolver(t, cfg)
		got, err := r.DiscoverPodCgroup()
		if err != nil {
			t.Fatalf("DiscoverPodCgroup() error = %v, want nil", err)
		}
		if got != wantPodA(t) {
			t.Fatalf("DiscoverPodCgroup() = %q, want %q", got, wantPodA(t))
		}
	})

	t.Run("DiscoverPodCgroup_CaseANeedsNoInodeSeams", func(t *testing.T) {
		// Case A must not depend on the case B seams; a nil Inode/Dirs pair is
		// the production wiring on any host without a cgroup namespace.
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::"+fixtureRelA+"\n"))
		cfg.Inode = nil
		cfg.Dirs = nil
		r := newTestResolver(t, cfg)
		if _, err := r.DiscoverPodCgroup(); err != nil {
			t.Fatalf("DiscoverPodCgroup() error = %v, want nil", err)
		}
	})

	t.Run("DiscoverPodCgroup_TraversalInProcPath_FailsScopeCheck", func(t *testing.T) {
		// A "../" in the v2 line would escape the host mount. V3 requires a
		// strict descendant, so the escape is refused rather than followed.
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/../outside/strange-pod.slice/cri-containerd-llll.scope\n"))
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_CGROUP_SCOPE)
	})
}

// TestDiscoverPodCgroupCaseB covers step 4: a private cgroup namespace, where
// /proc/self/cgroup reads exactly "0::/" and the cgroup can only be identified
// by inode. This is the kubelet default from Kubernetes 1.22 on cgroup v2, so
// it is the case that matters on AKS.
func TestDiscoverPodCgroupCaseB(t *testing.T) {
	root := absHostMount(t)

	t.Run("DiscoverPodCgroup_SingleInodeMatch_ReturnsPodParent", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Dirs = realTreeDirs{
			root: root,
			inos: map[string]uint64{
				"kubepods.slice/kubepods-burstable-pod11111111-2222-3333-4444-555555555555.slice/cri-containerd-aaaa.scope": fixtureSelfIno,
			},
		}
		r := newTestResolver(t, cfg)
		got, err := r.DiscoverPodCgroup()
		if err != nil {
			t.Fatalf("DiscoverPodCgroup() error = %v, want nil", err)
		}
		if got != wantPodA(t) {
			t.Fatalf("DiscoverPodCgroup() = %q, want %q", got, wantPodA(t))
		}
	})

	t.Run("DiscoverPodCgroup_NoInodeMatch_ReturnsCgroupNSOpaque", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Dirs = realTreeDirs{root: root, inos: map[string]uint64{}}
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_CGROUPNS_OPAQUE)
	})

	t.Run("DiscoverPodCgroup_TwoInodeMatches_ReturnsAmbiguous", func(t *testing.T) {
		// Two directories cannot share an inode on a live cgroup2 filesystem,
		// so this says the host mount is not what we were told it is. Picking
		// one would be picking whose traffic to capture at random.
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Dirs = realTreeDirs{
			root: root,
			inos: map[string]uint64{
				"kubepods.slice/kubepods-burstable-pod11111111-2222-3333-4444-555555555555.slice/cri-containerd-aaaa.scope": fixtureSelfIno,
				"kubepods.slice/kubepods-burstable-pod22222222-2222-3333-4444-555555555555.slice/cri-containerd-cccc.scope": fixtureSelfIno,
			},
		}
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_AMBIGUOUS_CGROUP)
	})

	t.Run("DiscoverPodCgroup_InodeStatFails_ReturnsCgroupNSOpaque", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Inode = fakeInodeStater{err: errors.New("stat refused")}
		cfg.Dirs = realTreeDirs{root: root, inos: map[string]uint64{}}
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_CGROUPNS_OPAQUE)
	})

	t.Run("DiscoverPodCgroup_UnreadableWalkRoot_ReturnsCgroupNSOpaque", func(t *testing.T) {
		// Nothing was searched, so "no match" would be a false statement.
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Dirs = realTreeDirs{root: root, err: errors.New("permission denied")}
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_CGROUPNS_OPAQUE)
	})

	t.Run("DiscoverPodCgroup_MissingInodeSeam_ReturnsErrMissingConfig", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Inode = nil
		cfg.Dirs = realTreeDirs{root: root}
		r := newTestResolver(t, cfg)
		if _, err := r.DiscoverPodCgroup(); !errors.Is(err, capture.ErrMissingConfig) {
			t.Fatalf("error = %v, want ErrMissingConfig", err)
		}
	})

	t.Run("DiscoverPodCgroup_MissingDirsSeam_ReturnsErrMissingConfig", func(t *testing.T) {
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Dirs = nil
		r := newTestResolver(t, cfg)
		if _, err := r.DiscoverPodCgroup(); !errors.Is(err, capture.ErrMissingConfig) {
			t.Fatalf("error = %v, want ErrMissingConfig", err)
		}
	})
}

// TestDiscoverPodCgroupWalkBounds covers step 4b: the walk is bounded on both
// depth and total directories, and breaching either bound is fail-closed.
func TestDiscoverPodCgroupWalkBounds(t *testing.T) {
	t.Run("DiscoverPodCgroup_ExceedsDepthBound_ReturnsWalkLimit", func(t *testing.T) {
		// A single chain, so the directory bound is nowhere near reached: only
		// the depth bound can stop this walk.
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Dirs = syntheticDirs{fanout: 1}
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_CGROUP_WALK_LIMIT)
	})

	t.Run("DiscoverPodCgroup_ExceedsDirectoryBound_ReturnsWalkLimit", func(t *testing.T) {
		// A wide root, so the depth bound is nowhere near reached: only the
		// directory bound can stop this walk.
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Dirs = syntheticDirs{fanout: 0, rootFanout: walkDirsLimit + 1}
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_CGROUP_WALK_LIMIT)
	})

	t.Run("DiscoverPodCgroup_WalkLimitDiscardsPartialMatch", func(t *testing.T) {
		// A match exists shallowly, but the walk cannot finish. Returning the
		// match would assert "exactly one" without having looked everywhere, so
		// the limit wins. This is the fail-closed property of the bound.
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Dirs = syntheticDirs{fanout: 1, matchDepth: 2, matchIno: fixtureSelfIno}
		r := newTestResolver(t, cfg)
		_, err := r.DiscoverPodCgroup()
		assertFailureCode(t, err, capture.E_CGROUP_WALK_LIMIT)
	})

	t.Run("DiscoverPodCgroup_AtDepthBound_DoesNotTripTheLimit", func(t *testing.T) {
		// The fixture tree is three levels deep, well inside the bound, and a
		// clean completion proves the bound is not off by one at the shallow
		// end. walkDepthLimit is referenced so that lowering it below the
		// fixture depth breaks this test rather than passing silently.
		if walkDepthLimit < 3 {
			t.Fatalf("walkDepthLimit = %d, too small for the fixture tree", walkDepthLimit)
		}
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::/\n"))
		cfg.Dirs = realTreeDirs{
			root: absHostMount(t),
			inos: map[string]uint64{
				"kubepods.slice/kubepods-burstable-pod11111111-2222-3333-4444-555555555555.slice/cri-containerd-aaaa.scope": fixtureSelfIno,
			},
		}
		r := newTestResolver(t, cfg)
		if _, err := r.DiscoverPodCgroup(); err != nil {
			t.Fatalf("DiscoverPodCgroup() error = %v, want nil", err)
		}
	})
}

// TestDiscoverPodCgroupStillValidates asserts that discovery does not bypass
// the V1-V8 assertions: narrowing the search is not the same as deciding the
// answer is safe.
func TestDiscoverPodCgroupStillValidates(t *testing.T) {
	t.Run("DiscoverPodCgroup_ProxyNotInPodTree_FailsV6", func(t *testing.T) {
		// fixturePodNoPID contains no cgroup.procs naming the proxy pid, so V6
		// rejects it even though discovery named it.
		rel := "/kubepods.slice/kubepods-burstable-pod44444444-2222-3333-4444-555555555555.slice/cri-containerd-ffff.scope"
		cfg := newDiscoveryConfig(writeProcCgroup(t, "0::"+rel+"\n"))
		r := newTestResolver(t, cfg)
		if _, err := r.DiscoverPodCgroup(); err == nil {
			t.Fatal("DiscoverPodCgroup() error = nil, want a V6 failure")
		}
	})
}
