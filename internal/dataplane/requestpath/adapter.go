package requestpath

import (
	"context"
	"net/netip"

	"github.com/girishmotwani/aksh/internal/dataplane/listener"
)

// Handle adapts the concrete 5A handover into the request-path handover shape.
func (h *Handler) Handle(ctx context.Context, cc *listener.ConnContext) error {
	return h.Serve(ctx, handoverFromConnContext(cc))
}

func handoverFromConnContext(cc *listener.ConnContext) Handover {
	if cc == nil {
		return Handover{}
	}
	return Handover{
		TLSConn:        cc.Downstream,
		Downstream:     cc.Downstream,
		SourceIP:       peerAddrSourceIP(cc.PeerAddr),
		PeerAddr:       cc.PeerAddr,
		OriginalDst:    cc.OriginalDst,
		SNI:            cc.CandidateSNI,
		ConnID:         cc.ConnID,
		AcceptedAt:     cc.AcceptedAt,
		IsTLS:          cc.Protocol == listener.ProtocolTLS,
		OriginUID:      cc.OriginUID,
		Transport:      cc.Transport,
		NegotiatedALPN: cc.NegotiatedALPN,
		decided:        cc.DecisionLatch(),
	}
}

func peerAddrSourceIP(addr netip.AddrPort) netip.Addr {
	if !addr.IsValid() {
		return netip.Addr{}
	}
	return addr.Addr()
}

var _ listener.ConnHandler = (*Handler)(nil)
