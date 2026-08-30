package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
)

// Sentinels for the pure pod-cgroup candidate derivation. They are closed
// errors so callers and tests classify a failure without string matching.
var (
	// errHostMountRequired is returned when the host cgroup mount is empty.
	errHostMountRequired = errors.New("aksh-proxy: cgroup: host cgroup mount is required")
	// errHostMountNotAbsolute is returned when the host cgroup mount is not an
	// absolute path. A relative mount would produce a relative pod candidate,
	// so reject it fail closed rather than silently deriving a bad path.
	errHostMountNotAbsolute = errors.New("aksh-proxy: cgroup: host cgroup mount is not absolute")
	// errProcCgroupPathRequired is returned when the proc cgroup path is empty.
	errProcCgroupPathRequired = errors.New("aksh-proxy: cgroup: proc cgroup path is required")
	// errNoV2Hierarchy is returned when the proc cgroup file has no cgroup v2
	// (0::) hierarchy line.
	errNoV2Hierarchy = errors.New("aksh-proxy: cgroup: no cgroup v2 (0::) hierarchy line")
	// errV2PathEmpty is returned when the cgroup v2 hierarchy line carries an
	// empty path (0:: with nothing after it).
	errV2PathEmpty = errors.New("aksh-proxy: cgroup: cgroup v2 hierarchy path is empty")
	// errV2PathNotAbsolute is returned when the cgroup v2 hierarchy path is not
	// absolute, which signals a malformed or tampered proc cgroup file.
	errV2PathNotAbsolute = errors.New("aksh-proxy: cgroup: cgroup v2 hierarchy path is not absolute")
	// errV2PathHasNoPodParent is returned when the cgroup v2 hierarchy path has
	// no pod parent segment (e.g. "/" or a single top-level component), so the
	// pod candidate would collapse onto the cgroup2 root rather than a pod.
	errV2PathHasNoPodParent = errors.New("aksh-proxy: cgroup: cgroup v2 hierarchy path has no pod parent segment")
)

// derivePodCgroupCandidate reads the cgroup v2 hierarchy line from the proc
// cgroup file and returns the POD-level candidate path under hostMount. The
// cgroup v2 line format is "0::<path>": three colon-separated fields, the
// hierarchy id 0, empty controllers, and an absolute path. The pod cgroup is
// the parent of the container cgroup, so the candidate is the dirname of that
// path, joined under hostMount and cleaned. A candidate that escapes hostMount
// via ../ is rejected fail closed.
func derivePodCgroupCandidate(hostMount, procCgroupPath string) (string, error) {
	hostMount = strings.TrimSpace(hostMount)
	if hostMount == "" {
		return "", errHostMountRequired
	}
	// The host cgroup mount is a filesystem path that is always absolute on the
	// Linux hosts aksh runs on. Reject a relative mount defensively so a bad
	// config cannot yield a relative candidate.
	if !path.IsAbs(hostMount) {
		return "", fmt.Errorf("%w: %q", errHostMountNotAbsolute, hostMount)
	}
	procCgroupPath = strings.TrimSpace(procCgroupPath)
	if procCgroupPath == "" {
		return "", errProcCgroupPathRequired
	}

	raw, err := os.ReadFile(procCgroupPath)
	if err != nil {
		return "", fmt.Errorf("aksh-proxy: cgroup: read %q: %w", procCgroupPath, err)
	}

	v2Path, found := "", false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			v2Path = parts[2]
			found = true
			break
		}
	}
	if !found {
		return "", errNoV2Hierarchy
	}
	v2Path = strings.TrimSpace(v2Path)
	if v2Path == "" {
		return "", errV2PathEmpty
	}
	// The cgroup v2 hierarchy path is always absolute ("0::/..."), and it is
	// Linux kernel data that always uses forward-slash semantics regardless of
	// the host OS. Parse it with the path package (not path/filepath) so the
	// syntax is OS-independent. A relative value indicates a malformed or
	// tampered proc cgroup file; reject it before path.Dir so a relative path
	// cannot collapse the candidate onto hostMount or an unintended location.
	if !path.IsAbs(v2Path) {
		return "", fmt.Errorf("%w: %q is not absolute", errV2PathNotAbsolute, v2Path)
	}

	podRel := path.Dir(v2Path)
	// A v2 path with no pod parent segment (e.g. "/" or a single top-level
	// component like "/kubepods") collapses the candidate onto the host mount
	// root, which is the cgroup2 root rather than a pod cgroup. Reject it fail
	// closed instead of returning the host root.
	if podRel == "/" || podRel == "." {
		return "", fmt.Errorf("%w: %q", errV2PathHasNoPodParent, v2Path)
	}
	cleanHost := path.Clean(hostMount)
	// Containment is structural, not a runtime check: v2Path is absolute (guarded
	// above) and path.Dir returns it cleaned, so podRel carries no ".." component.
	// path.Join(cleanHost, <absolute-cleaned>) therefore always yields a path
	// under cleanHost and cannot escape it. The authoritative containment,
	// symlink-canonicalisation and descendant checks are performed later by
	// capture.PodCgroupResolver.ResolvePodCgroup against the real host mount;
	// this function only produces the candidate.
	candidate := path.Join(cleanHost, podRel)
	return candidate, nil
}
