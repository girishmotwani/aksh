//go:build !linux

package capture

// LoadAndAttach is the non-Linux stub of the eBPF load-and-attach entry point.
// The real implementation needs cgroup2, bpffs and the bpf(2) syscall, none of
// which exist here, so the stub refuses immediately rather than failing
// half-way through a privileged sequence. opts is named but unused, and a nil
// opts is safe: the stub never dereferences it.
func LoadAndAttach(opts *Options) (*Handle, error) {
	_ = opts
	return nil, ErrUnsupportedPlatform
}
