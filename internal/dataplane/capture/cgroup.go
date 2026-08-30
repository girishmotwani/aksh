package capture

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Filesystem magic values used by the cgroup and pin-root validations.
const (
	// Cgroup2SuperMagic is CGROUP2_SUPER_MAGIC.
	Cgroup2SuperMagic uint32 = 0x63677270
	// BPFFSMagic is BPF_FS_MAGIC.
	BPFFSMagic uint32 = 0xCAFE4A11
)

// minPodCgroupDepth is the V4 bound: the pod cgroup is always at least
// <qos>/<pod> below the host mount, so depth 1 means a QoS-class cgroup was
// resolved and attaching there would capture every pod in that class.
const minPodCgroupDepth = 2

// Walk bounds for the descendant search that answers V6. Both are constants
// rather than options: they are correctness guards, and an operator who can
// raise them can turn the guard off (design section 6.1.2).
const (
	maxWalkDepth = 12
	maxWalkDirs  = 50000
)

// errWalkLimit is the internal signal that a walk bound was breached.
var errWalkLimit = errors.New("capture: cgroup walk bound exceeded")

// Kubelet pod-cgroup basename patterns for the non-fatal V8 assertion:
// the cgroupfs driver names pods pod<uid>, the systemd driver <prefix>pod<uid>.slice.
var (
	kubeletCgroupfsPattern = regexp.MustCompile(`(?i)^pod[0-9a-f-]{36}$`)
	kubeletSystemdPattern  = regexp.MustCompile(`(?i)^.*pod[0-9a-f_-]{36}\.slice$`)
)

// PodCgroupResolverConfig configures a PodCgroupResolver. Every field that
// reaches the operating system does so through a seam so that the resolver is
// testable on any platform.
type PodCgroupResolverConfig struct {
	// HostCgroupMount is the read-only bind of the host cgroup2 root.
	HostCgroupMount string
	// LocalCgroupMount is the proxy's own cgroup2 mount.
	LocalCgroupMount string
	// ProcCgroupPath is the path of the process cgroup file, /proc/self/cgroup.
	ProcCgroupPath string
	// ProxyPID is the pid whose presence in a descendant cgroup.procs proves
	// the resolved cgroup actually contains this process (V6).
	ProxyPID int
	// FSMagic reports the filesystem magic of a path (V1).
	FSMagic FSMagicProber
	// Namespace answers the bounded host-mount search of design section 6.1.2
	// case B. It is optional; a nil prober skips the namespace check.
	Namespace CgroupNamespaceProber
	// Inode reports the inode of a directory for the case B search. It is
	// required by DiscoverPodCgroup and unused by ResolvePodCgroup.
	Inode CgroupInodeStater
	// Dirs lists subdirectories with their inodes for the case B search. It is
	// required by DiscoverPodCgroup and unused by ResolvePodCgroup.
	Dirs CgroupDirReader
	// Procs reads a cgroup.procs file. It is optional; a nil reader makes the
	// resolver read the file directly.
	Procs ProcTableReader
	// OnWarning receives the non-fatal V7 and V8 findings. It is optional.
	OnWarning func(string)
}

// PodCgroupResolver resolves and validates the pod cgroup the capture programs
// attach to. It holds no mutable state, so concurrent calls are independent.
type PodCgroupResolver struct {
	cfg PodCgroupResolverConfig
}

// NewPodCgroupResolver constructs a resolver from cfg. A nil cfg is rejected
// rather than defaulted, because every field of it is security-relevant.
func NewPodCgroupResolver(cfg *PodCgroupResolverConfig) (*PodCgroupResolver, error) {
	if cfg == nil {
		return nil, ErrMissingConfig
	}
	return &PodCgroupResolver{cfg: *cfg}, nil
}

// ResolvePodCgroup validates podPath against the V1-V8 assertions of design
// section 6.1.3 and returns the resolved pod cgroup path. Fatal failures carry
// a *PreflightError with the E_* code the design assigns; V7 and V8 report
// through OnWarning instead of failing.
func (r *PodCgroupResolver) ResolvePodCgroup(podPath string) (string, error) {
	if r == nil {
		return "", ErrMissingResolver
	}
	if podPath == "" {
		return "", ErrEmptyPodPath
	}
	if r.cfg.HostCgroupMount == "" {
		return "", ErrMissingHostMount
	}
	if r.cfg.FSMagic == nil {
		return "", fmt.Errorf("capture: FSMagic prober: %w", ErrMissingConfig)
	}

	hostMount, err := absClean(r.cfg.HostCgroupMount)
	if err != nil {
		return "", fmt.Errorf("capture: host cgroup mount %q: %w", r.cfg.HostCgroupMount, err)
	}
	if _, err := os.Stat(hostMount); err != nil {
		return "", fmt.Errorf("capture: host cgroup mount %q: %w", r.cfg.HostCgroupMount, err)
	}
	// The host mount is canonicalised with the same strategy as podPath below.
	// V2 and V3 compare the two paths textually, so both sides must be the
	// real path: otherwise a symlinked host mount makes an in-scope pod cgroup
	// look out of scope, and - the security-relevant direction - a containment
	// check performed on an uncanonicalised prefix can be satisfied by a path
	// that does not actually live under the mount. Canonicalisation must fail
	// closed: silently falling back to the uncanonicalised path on error would
	// reopen exactly the containment bypass this check exists to close.
	hostMount, err = canonicalizeHostMount(hostMount)
	if err != nil {
		return "", err
	}

	resolved, err := absClean(podPath)
	if err != nil {
		return "", scopeError("V1", err)
	}
	// Symlinks are resolved before any assertion runs, so that a symlinked pod
	// path cannot bypass the descendant and depth checks.
	if real, err := filepath.EvalSymlinks(resolved); err == nil {
		resolved = filepath.Clean(real)
	}

	// The bounded host-mount search of design section 6.1.2 case B answers
	// whether this process's cgroup namespace can name the pod cgroup at all.
	if r.cfg.Namespace != nil {
		if err := r.cfg.Namespace.ConfirmVisible(resolved); err != nil {
			return "", err
		}
	}

	if err := r.validateScope(resolved, hostMount); err != nil {
		return "", err
	}
	if err := r.validateProxyPresence(resolved); err != nil {
		return "", err
	}
	r.validateShape(resolved)
	return resolved, nil
}

// validateProxyPresence runs V6: the proxy's own pid must appear in some
// descendant's cgroup.procs, which is what proves the resolved cgroup actually
// contains this process. The descendant walk is bounded on both axes; breaching
// either bound is fail-closed with E_CGROUP_WALK_LIMIT rather than a stall.
func (r *PodCgroupResolver) validateProxyPresence(podPath string) error {
	var (
		found   bool
		visited int
	)
	walkErr := filepath.WalkDir(podPath, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() || path == podPath {
			return nil
		}
		visited++
		if visited > maxWalkDirs {
			return errWalkLimit
		}
		rel, relErr := filepath.Rel(podPath, path)
		if relErr != nil {
			return relErr
		}
		if depth := len(strings.Split(filepath.ToSlash(rel), "/")); depth > maxWalkDepth {
			return errWalkLimit
		}
		pids, procsErr := r.procsIn(path)
		if procsErr != nil {
			return nil
		}
		for _, pid := range pids {
			if pid == r.cfg.ProxyPID {
				found = true
				return fs.SkipAll
			}
		}
		return nil
	})
	switch {
	case errors.Is(walkErr, errWalkLimit):
		return newPreflightError("V6", E_CGROUP_WALK_LIMIT, walkErr)
	case walkErr != nil:
		return scopeError("V6", walkErr)
	case !found:
		return newPreflightError("V6", E_AMBIGUOUS_CGROUP,
			fmt.Errorf("proxy pid %d does not appear in any cgroup.procs below %q", r.cfg.ProxyPID, podPath))
	}
	return nil
}

// validateShape runs the two non-fatal assertions V7 (child-directory count)
// and V8 (kubelet basename pattern). Neither may be load-bearing: the first is
// legitimately violated during pod startup, the second depends on a kubelet
// implementation detail.
func (r *PodCgroupResolver) validateShape(podPath string) {
	entries, err := os.ReadDir(podPath)
	if err != nil {
		r.warn("V7: cannot read %q to count container cgroups: %v", podPath, err)
	} else {
		children := 0
		for _, entry := range entries {
			if entry.IsDir() {
				children++
			}
		}
		if children < 2 {
			r.warn("V7: %q has %d child cgroup(s); expected at least two once every container has started", podPath, children)
		}
	}

	base := filepath.Base(podPath)
	if !kubeletCgroupfsPattern.MatchString(base) && !kubeletSystemdPattern.MatchString(base) {
		r.warn("V8: %q does not match a kubelet pod-cgroup naming pattern", base)
	}
}

// procsIn returns the pids listed in the cgroup.procs file of dir.
func (r *PodCgroupResolver) procsIn(dir string) ([]int, error) {
	if r.cfg.Procs != nil {
		return r.cfg.Procs.ProcsIn(dir)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, line := range strings.Fields(string(raw)) {
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// validateScope runs the fatal scope assertions V1-V5.
func (r *PodCgroupResolver) validateScope(podPath, hostMount string) error {
	// V1: the pod path is a directory on a cgroup2 filesystem.
	info, err := os.Stat(podPath)
	if err != nil {
		return scopeError("V1", err)
	}
	if !info.IsDir() {
		return scopeError("V1", fmt.Errorf("%q is not a directory", podPath))
	}
	magic, err := r.cfg.FSMagic.FSMagic(podPath)
	if err != nil {
		return scopeError("V1", err)
	}
	if magic != Cgroup2SuperMagic {
		return scopeError("V1", fmt.Errorf("%q reports filesystem magic %#08x, want CGROUP2_SUPER_MAGIC %#08x", podPath, magic, Cgroup2SuperMagic))
	}

	// V2: the pod path is not the host mount itself - attaching there captures
	// the whole node. This is the proof-of-concept defect.
	if podPath == hostMount {
		return scopeError("V2", fmt.Errorf("%q is the host cgroup mount itself", podPath))
	}

	// V3: the pod path is a strict descendant of the host mount.
	rel, err := filepath.Rel(hostMount, podPath)
	if err != nil {
		return scopeError("V3", err)
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return scopeError("V3", fmt.Errorf("%q is not a descendant of %q", podPath, hostMount))
	}

	// V4: the pod cgroup sits at least <qos>/<pod> below the host mount.
	if depth := len(strings.Split(rel, "/")); depth < minPodCgroupDepth {
		return scopeError("V4", fmt.Errorf("%q is %d level(s) below %q, want at least %d", podPath, depth, hostMount, minPodCgroupDepth))
	}

	// V5: the directory is a real cgroup, not a stray directory.
	for _, name := range []string{"cgroup.procs", "cgroup.controllers"} {
		if _, err := os.Stat(filepath.Join(podPath, name)); err != nil {
			return scopeError("V5", fmt.Errorf("%q lacks %s: %w", podPath, name, err))
		}
	}
	return nil
}

// warn reports a non-fatal validation finding when a sink is configured.
func (r *PodCgroupResolver) warn(format string, args ...any) {
	if r.cfg.OnWarning == nil {
		return
	}
	r.cfg.OnWarning(fmt.Sprintf(format, args...))
}

// scopeError wraps a fatal scope-validation failure with E_CGROUP_SCOPE.
func scopeError(gate string, err error) error {
	return newPreflightError(gate, E_CGROUP_SCOPE, err)
}

// absClean returns the cleaned absolute form of path.
func absClean(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// canonicalizeHostMount resolves hostMount to its real, symlink-free form.
// It fails closed: a filepath.EvalSymlinks error is returned as a hard
// failure instead of silently retaining the uncanonicalised path. The V2/V3
// containment checks compare hostMount and the resolved pod path textually,
// so running that comparison against an uncanonicalised prefix is exactly
// the containment bypass canonicalisation exists to close.
func canonicalizeHostMount(hostMount string) (string, error) {
	real, err := filepath.EvalSymlinks(hostMount)
	if err != nil {
		return "", fmt.Errorf("capture: cannot canonicalise host cgroup mount %q: %w", hostMount, err)
	}
	return filepath.Clean(real), nil
}
