// Package capture implements the Phase 5A transparent-capture layer: pod-cgroup
// resolution, the ordered startup preflight, the Go mirrors of the kernel-facing
// BPF structures, and the byte-order helpers that are the only permitted
// conversion site between network and host order.
//
// Everything in this package that is not guarded by a build tag is
// platform-neutral: it compiles and its tests execute on any GOOS. The
// kernel-executing parts (program load/attach/pin/freeze, the BPF destination
// resolver and the privilege-drop sequence) live in Linux-tagged files; on every
// other platform the stubs in the "!linux" files return ErrUnsupportedPlatform.
//
// Design: docs/design/S1a-dataplane-capture.md.
package capture
