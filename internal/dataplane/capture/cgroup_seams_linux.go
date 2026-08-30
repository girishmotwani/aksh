//go:build linux

package capture

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// This file supplies the two operating-system primitives that case B of design
// section 6.1.2 needs. Both are deliberately trivial: the bounded walk and the
// match arithmetic live in cgroup_discover.go as ordinary Go so they can be
// tested exhaustively on any platform, including the walk-bound and
// ambiguous-match paths that are impractical to provoke against a real
// cgroup tree.

// statInodeProber answers step 4a with stat(2).
type statInodeProber struct{}

// InodeOf returns the inode number of path.
func (statInodeProber) InodeOf(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("capture: stat %q: %w", path, err)
	}
	return uint64(st.Ino), nil
}

// osCgroupDirReader lists immediate subdirectories with their inodes.
type osCgroupDirReader struct{}

// NewCgroupInodeStater returns the production Linux inode stater used by the
// Case-B (namespaced cgroup) discovery in DiscoverPodCgroup.
func NewCgroupInodeStater() CgroupInodeStater { return statInodeProber{} }

// NewCgroupDirReader returns the production Linux cgroup directory reader used
// by the bounded host-mount walk in DiscoverPodCgroup (Case B).
func NewCgroupDirReader() CgroupDirReader { return osCgroupDirReader{} }

// ReadCgroupDirs returns the immediate subdirectories of path.
//
// Symlinks are skipped rather than followed. A real cgroup2 tree contains none,
// so skipping costs nothing, and following one is exactly how a walk would
// escape the host mount and match a directory that is not a cgroup at all.
// lstat is used for the same reason.
func (osCgroupDirReader) ReadCgroupDirs(path string) ([]CgroupDirEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("capture: read cgroup directory %q: %w", path, err)
	}
	out := make([]CgroupDirEntry, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(path, entry.Name()), &st); err != nil {
			// The cgroup tree is live: a container exiting removes its cgroup
			// between the readdir and the lstat. That is not a failure of the
			// search, and treating it as one would make startup flaky on a busy
			// node. An entry we cannot stat simply cannot be our match.
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		out = append(out, CgroupDirEntry{Name: entry.Name(), Ino: uint64(st.Ino)})
	}
	return out, nil
}
