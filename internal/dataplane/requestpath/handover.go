package requestpath

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/girishmotwani/aksh/internal/policy"
)

// Handover mirrors the 5A connection fields consumed by the request path.
type Handover struct {
	TLSConn        net.Conn
	Downstream     net.Conn
	SourceIP       netip.Addr
	PeerAddr       netip.AddrPort
	OriginalDst    netip.AddrPort
	SNI            string
	ConnID         string
	AcceptedAt     time.Time
	IsTLS          bool
	OriginUID      uint32
	Transport      policy.Transport
	NegotiatedALPN string

	// decided is the connection's shared aksh_decisions_total latch, owned by
	// the listener's ConnContext. It is a pointer on purpose: Handover is
	// passed by value, so an inline atomic would give every copy its own
	// latch and defeat the whole mechanism.
	decided *atomic.Bool
}

// MarkDecided claims the right to record this connection's one and only
// aksh_decisions_total sample, returning true to exactly one caller across
// every layer that shares the latch (see listener.ConnContext.MarkDecided for
// the full contract and the issues #89/#83 background).
//
// A zero-valued Handover has no latch. That happens only in unit tests that
// construct one directly, so a nil latch returns true - each site records, as
// it did before the latch existed - rather than silently suppressing metrics.
func (h Handover) MarkDecided() bool {
	if h.decided == nil {
		return true
	}
	return h.decided.CompareAndSwap(false, true)
}
