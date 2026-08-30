//go:build linux

package capture

import "golang.org/x/sys/unix"

// linuxFSMagicProber is the production FSMagicProber. It reports the statfs
// f_type of a path so the pod-cgroup resolver's V1 assertion can confirm the
// resolved path lives on a cgroup2 filesystem.
type linuxFSMagicProber struct{}

// FSMagic returns the filesystem magic (statfs f_type) of path.
func (linuxFSMagicProber) FSMagic(path string) (uint32, error) {
	var sfs unix.Statfs_t
	if err := unix.Statfs(path, &sfs); err != nil {
		return 0, err
	}
	return uint32(sfs.Type), nil
}

// NewFSMagicProber returns the production statfs-based FSMagicProber that the
// proxy startup wires into capture.PodCgroupResolver.
func NewFSMagicProber() FSMagicProber { return linuxFSMagicProber{} }
