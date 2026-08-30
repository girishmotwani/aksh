//go:build !linux

package capture

// unsupportedFSMagicProber is the non-Linux stub: statfs-based cgroup probing
// exists only on Linux, so every call reports ErrUnsupportedPlatform. It exists
// so cross-platform builds of the proxy wiring compile.
type unsupportedFSMagicProber struct{}

// FSMagic always fails off Linux.
func (unsupportedFSMagicProber) FSMagic(string) (uint32, error) { return 0, ErrUnsupportedPlatform }

// NewFSMagicProber returns the non-Linux stub FSMagicProber.
func NewFSMagicProber() FSMagicProber { return unsupportedFSMagicProber{} }
