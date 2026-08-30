//go:build !linux

package capture

// DropPrivileges is the non-Linux stub of the 11-step privilege-drop sequence
// (design section 6.6.2). The sequence depends on Linux capabilities and on
// syscall.AllThreadsSyscall, so the stub refuses rather than dropping partially
// and leaving the process in an unintended identity. cfg is named for
// readability and is never read.
func DropPrivileges(cfg PrivDropConfig) error {
	_ = cfg
	return ErrUnsupportedPlatform
}
