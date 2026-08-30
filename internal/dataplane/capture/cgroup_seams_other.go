//go:build !linux

package capture

// Non-Linux stubs for the two Case-B cgroup seams. The inode walk that
// DiscoverPodCgroup performs is Linux-only; these exist so cross-platform
// builds of the proxy wiring (which constructs the resolver unconditionally)
// compile. Every call reports ErrUnsupportedPlatform.

// unsupportedCgroupInodeStater is the non-Linux stub CgroupInodeStater.
type unsupportedCgroupInodeStater struct{}

// InodeOf always fails off Linux.
func (unsupportedCgroupInodeStater) InodeOf(string) (uint64, error) {
	return 0, ErrUnsupportedPlatform
}

// NewCgroupInodeStater returns the non-Linux stub CgroupInodeStater.
func NewCgroupInodeStater() CgroupInodeStater { return unsupportedCgroupInodeStater{} }

// unsupportedCgroupDirReader is the non-Linux stub CgroupDirReader.
type unsupportedCgroupDirReader struct{}

// ReadCgroupDirs always fails off Linux.
func (unsupportedCgroupDirReader) ReadCgroupDirs(string) ([]CgroupDirEntry, error) {
	return nil, ErrUnsupportedPlatform
}

// NewCgroupDirReader returns the non-Linux stub CgroupDirReader.
func NewCgroupDirReader() CgroupDirReader { return unsupportedCgroupDirReader{} }
