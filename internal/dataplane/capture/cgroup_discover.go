package capture

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// unifiedCgroupFields is the number of colon-separated fields in a line of
// /proc/self/cgroup. The path is the third and may itself contain colons, so
// the line is split with a limit rather than fully.
const unifiedCgroupFields = 3

// discoveryGate names the gate that consumes the result. Discovery has no gate
// of its own: it produces the path that gate P5 then validates, so a discovery
// failure is reported as a P5 failure and stops startup at the same place.
const discoveryGate = "P5"

// DiscoverPodCgroup resolves the pod cgroup path using only /proc/self/cgroup
// and the filesystem, implementing steps 1-7 of design section 6.1.2, and then
// validates the result through ResolvePodCgroup so that every V1-V8 assertion
// still has the final say.
//
// Nothing here consults the Kubernetes API, the Downward API, or an environment
// variable naming the path. Each of those would be a value the pod's own
// manifest could set, and the attach point decides whose traffic is captured:
// it must be derived from the kernel's view of this process, not asserted by
// its configuration.
//
// The hard case is a private cgroup namespace, which is the kubelet default
// from Kubernetes 1.22 on cgroup v2. Inside it /proc/self/cgroup reads exactly
// "0::/" because the pod cgroup sits above the namespace root and cannot be
// named from within. Case B below recovers the name by inode instead.
func (r *PodCgroupResolver) DiscoverPodCgroup() (string, error) {
	if r == nil {
		return "", ErrMissingResolver
	}
	if r.cfg.ProcCgroupPath == "" {
		return "", ErrMissingProcCgroupPath
	}
	if r.cfg.HostCgroupMount == "" {
		return "", ErrMissingHostMount
	}
	if r.cfg.LocalCgroupMount == "" {
		return "", ErrMissingLocalMount
	}
	if r.cfg.FSMagic == nil {
		return "", fmt.Errorf("capture: FSMagic prober: %w", ErrMissingConfig)
	}

	// Step 1: the cgroup v2 line of /proc/self/cgroup.
	rel, err := r.unifiedRelPath()
	if err != nil {
		return "", err
	}

	// Step 2: the local mount really is cgroup2. Without this a hybrid v1/v2
	// host, where /sys/fs/cgroup is tmpfs, would yield an inode from the wrong
	// filesystem and the case B match would be meaningless.
	if err := r.confirmLocalCgroup2(); err != nil {
		return "", err
	}

	hostMount, err := absClean(r.cfg.HostCgroupMount)
	if err != nil {
		return "", fmt.Errorf("capture: host cgroup mount %q: %w", r.cfg.HostCgroupMount, err)
	}

	var candidate string
	if rel != "/" {
		// Step 3, case A: no cgroup namespace, or a partially namespaced view.
		// The line already names the container cgroup relative to the host
		// root. A rel containing ".." would escape the host mount here; that is
		// caught by V3, which requires a strict descendant, so the failure is
		// closed rather than silent.
		candidate = filepath.Clean(filepath.Join(hostMount, rel))
	} else {
		// Step 4, case B: private cgroup namespace.
		candidate, err = r.discoverByInode(hostMount)
		if err != nil {
			return "", err
		}
	}

	// Step 5: the candidate is the *container* cgroup. Its parent is the pod
	// cgroup under both kubelet drivers - systemd
	// (/kubepods.slice/kubepods-burstable-podUID.slice/cri-containerd-HASH.scope)
	// and cgroupfs (/kubepods/burstable/podUID/HASH).
	podPath := filepath.Dir(candidate)

	// Steps 6-7: V1-V8. Discovery narrows the search; it does not get to
	// decide the answer is safe.
	return r.ResolvePodCgroup(podPath)
}

// unifiedRelPath returns the path field of the cgroup v2 line of
// /proc/self/cgroup. The v2 line is the one whose hierarchy id is 0 and whose
// controller list is empty. A file with no such line describes a cgroup v1
// node, which 5A does not support.
func (r *PodCgroupResolver) unifiedRelPath() (string, error) {
	data, err := os.ReadFile(r.cfg.ProcCgroupPath)
	if err != nil {
		return "", newPreflightError(discoveryGate, E_NO_CGROUP2,
			fmt.Errorf("read %q: %w", r.cfg.ProcCgroupPath, err))
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, ":", unifiedCgroupFields)
		if len(fields) != unifiedCgroupFields {
			continue
		}
		if fields[0] != "0" || fields[1] != "" {
			continue
		}
		rel := fields[2]
		if rel == "" {
			return "", newPreflightError(discoveryGate, E_NO_CGROUP2,
				fmt.Errorf("cgroup v2 line of %q has an empty path", r.cfg.ProcCgroupPath))
		}
		return rel, nil
	}
	return "", newPreflightError(discoveryGate, E_NO_CGROUP2,
		fmt.Errorf("%q has no cgroup v2 line; the node is not on a unified hierarchy", r.cfg.ProcCgroupPath))
}

// confirmLocalCgroup2 is step 2: the proxy's own cgroup mount must be cgroup2.
func (r *PodCgroupResolver) confirmLocalCgroup2() error {
	magic, err := r.cfg.FSMagic.FSMagic(r.cfg.LocalCgroupMount)
	if err != nil {
		return newPreflightError(discoveryGate, E_NO_CGROUP2,
			fmt.Errorf("statfs %q: %w", r.cfg.LocalCgroupMount, err))
	}
	if magic != Cgroup2SuperMagic {
		return newPreflightError(discoveryGate, E_NO_CGROUP2,
			fmt.Errorf("%q has filesystem magic %#x, want cgroup2 %#x",
				r.cfg.LocalCgroupMount, magic, Cgroup2SuperMagic))
	}
	return nil
}

// discoverByInode is step 4: identify our own cgroup on the host mount by
// inode, because in a private cgroup namespace we cannot name it.
func (r *PodCgroupResolver) discoverByInode(hostMount string) (string, error) {
	if r.cfg.Inode == nil {
		return "", fmt.Errorf("capture: Inode stater: %w", ErrMissingConfig)
	}
	if r.cfg.Dirs == nil {
		return "", fmt.Errorf("capture: Dirs reader: %w", ErrMissingConfig)
	}

	// Step 4a. cgroup2 is a single filesystem, so the directory behind the
	// namespace-local mount has the same inode when reached through the host
	// mount.
	selfIno, err := r.cfg.Inode.InodeOf(r.cfg.LocalCgroupMount)
	if err != nil {
		return "", newPreflightError(discoveryGate, E_CGROUPNS_OPAQUE,
			fmt.Errorf("inode of local cgroup mount %q: %w", r.cfg.LocalCgroupMount, err))
	}

	// Step 4b.
	matches, walkErr := r.walkForInode(hostMount, selfIno)

	// Step 4c.
	switch {
	case errors.Is(walkErr, errWalkLimit):
		return "", newPreflightError(discoveryGate, E_CGROUP_WALK_LIMIT, walkErr)
	case walkErr != nil:
		return "", newPreflightError(discoveryGate, E_CGROUPNS_OPAQUE, walkErr)
	case len(matches) == 0:
		return "", newPreflightError(discoveryGate, E_CGROUPNS_OPAQUE,
			fmt.Errorf("no directory below %q has inode %d; the cgroup namespace is opaque",
				hostMount, selfIno))
	case len(matches) > 1:
		return "", newPreflightError(discoveryGate, E_AMBIGUOUS_CGROUP,
			fmt.Errorf("%d directories below %q share inode %d: %s",
				len(matches), hostMount, selfIno, strings.Join(matches, ", ")))
	}
	return matches[0], nil
}

// walkItem is one pending directory in the depth-first search.
type walkItem struct {
	path  string
	depth int
}

// walkForInode collects every directory below hostMount whose inode is target,
// bounded on both depth and total directories visited.
//
// Breaching either bound returns errWalkLimit and no matches. Returning what
// was found so far would be worse than returning nothing: a partial walk cannot
// distinguish "there is exactly one match" from "the second match is in the
// part I did not visit", and nothing downstream can recover that distinction.
// One match means attach here; two means we do not know whose cgroup this is.
func (r *PodCgroupResolver) walkForInode(hostMount string, target uint64) ([]string, error) {
	var (
		matches []string
		visited int
	)
	stack := []walkItem{{path: hostMount, depth: 0}}

	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := r.cfg.Dirs.ReadCgroupDirs(cur.path)
		if err != nil {
			// The root is load-bearing: if it cannot be read, nothing has been
			// searched and reporting "no match" would be a lie. Deeper
			// directories are not: the cgroup tree is live and a subtree can
			// disappear mid-walk as a container exits, which is not an error.
			if cur.depth == 0 {
				return nil, err
			}
			continue
		}

		for _, entry := range entries {
			visited++
			if visited > maxWalkDirs {
				return nil, errWalkLimit
			}
			depth := cur.depth + 1
			if depth > maxWalkDepth {
				return nil, errWalkLimit
			}

			child := filepath.Join(cur.path, entry.Name)
			if entry.Ino == target {
				matches = append(matches, child)
				// A second match is already fatal, so there is nothing to learn
				// from continuing.
				if len(matches) > 1 {
					return matches, nil
				}
			}
			stack = append(stack, walkItem{path: child, depth: depth})
		}
	}
	return matches, nil
}
