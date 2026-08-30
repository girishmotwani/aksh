//go:build !linux

package capture

import (
	"net"
	"net/netip"

	"github.com/girishmotwani/aksh/internal/dataplane"
)

// BPFDestinationResolver reads original destinations out of the BPF maps. On
// non-Linux platforms it exists only so that dependent code compiles; it is
// never constructed.
type BPFDestinationResolver struct{}

// Compile-time proof that the non-Linux stub also satisfies the frozen
// dataplane.DestinationResolver interface, so cmd/aksh-proxy run() can assign a
// *BPFDestinationResolver to a dataplane.DestinationResolver under
// CGO_ENABLED=0 cross-compilation (the Linux file carries the same assertion).
var _ dataplane.DestinationResolver = (*BPFDestinationResolver)(nil)

// NewBPFDestinationResolver is the non-Linux stub constructor.
//
// The unit test specification types the first parameter as *ebpf.Map. It is
// declared as `any` so that the platform-neutral slice of this package adds no
// module dependency; the Linux implementation asserts the concrete type. Both
// parameters are named for readability and neither is read: the stub never
// dereferences destMap, so a nil is safe.
func NewBPFDestinationResolver(destMap any, opts Options) (*BPFDestinationResolver, error) {
	_, _ = destMap, opts
	return nil, ErrUnsupportedPlatform
}

// Resolve is the non-Linux stub: the resolver is never constructed off-Linux, so
// this only exists to satisfy dataplane.DestinationResolver at compile time.
func (*BPFDestinationResolver) Resolve(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, ErrUnsupportedPlatform
}
