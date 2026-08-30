//go:build !linux

package capture

import "github.com/cilium/ebpf"

// Handle is the non-Linux stub of the eBPF owner object. The real Handle needs
// cgroup2, bpffs and the bpf(2) syscall, none of which exist here, so the stub
// carries no kernel state and every method degrades safely. It exists only so
// the return type of LoadAndAttach and the capture public surface cross-compile
// cleanly under CGO_ENABLED=0.
type Handle struct{}

// PairMap always returns nil: there is no live map off-Linux.
func (h *Handle) PairMap() *ebpf.Map { return nil }

// AttachInfo returns the zero snapshot: nothing is ever attached off-Linux.
func (h *Handle) AttachInfo() AttachInfo { return AttachInfo{} }

// Close reports the platform is unsupported; there is nothing to tear down.
func (h *Handle) Close() error { return ErrUnsupportedPlatform }

// OnAttachLoss is a no-op: no health loop runs off-Linux, so loss never fires.
func (h *Handle) OnAttachLoss(fn func(error)) { _ = fn }

// AttachLoss returns nil: there is no loss channel off-Linux.
func (h *Handle) AttachLoss() <-chan error { return nil }

// AttachLost always reports false: no attach is ever established off-Linux, so
// the loss latch can never fire (parity stub for the S5 preflight predicate).
func (h *Handle) AttachLost() bool { return false }
