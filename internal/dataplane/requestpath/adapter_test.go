package requestpath

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/policy"
)

func TestAdapterCopiesConnContext(t *testing.T) {
	downstream, peer := net.Pipe()
	defer downstream.Close()
	defer peer.Close()

	acceptedAt := time.Unix(1700000100, 0)
	cc := &listener.ConnContext{
		ConnID:         "conn-42",
		Downstream:     downstream,
		PeerAddr:       netip.MustParseAddrPort("127.0.0.1:54321"),
		OriginalDst:    netip.MustParseAddrPort("10.0.0.7:443"),
		OriginUID:      1774,
		Protocol:       listener.ProtocolTLS,
		Transport:      policy.TransportTLS,
		CandidateSNI:   "api.example.com",
		NegotiatedALPN: "http/1.1",
		AcceptedAt:     acceptedAt,
	}

	ho := handoverFromConnContext(cc)
	if ho.TLSConn != downstream {
		t.Fatal("TLSConn was not copied from Downstream")
	}
	if ho.Downstream != downstream {
		t.Fatal("Downstream was not preserved")
	}
	if ho.PeerAddr != cc.PeerAddr {
		t.Fatalf("PeerAddr = %v, want %v", ho.PeerAddr, cc.PeerAddr)
	}
	if ho.SourceIP != cc.PeerAddr.Addr() {
		t.Fatalf("SourceIP = %v, want %v", ho.SourceIP, cc.PeerAddr.Addr())
	}
	if ho.OriginalDst != cc.OriginalDst {
		t.Fatalf("OriginalDst = %v, want %v", ho.OriginalDst, cc.OriginalDst)
	}
	if ho.SNI != cc.CandidateSNI {
		t.Fatalf("SNI = %q, want %q", ho.SNI, cc.CandidateSNI)
	}
	if ho.ConnID != cc.ConnID {
		t.Fatalf("ConnID = %q, want %q", ho.ConnID, cc.ConnID)
	}
	if !ho.AcceptedAt.Equal(acceptedAt) {
		t.Fatalf("AcceptedAt = %v, want %v", ho.AcceptedAt, acceptedAt)
	}
	if !ho.IsTLS {
		t.Fatal("IsTLS = false, want true")
	}
	if ho.OriginUID != cc.OriginUID {
		t.Fatalf("OriginUID = %d, want %d", ho.OriginUID, cc.OriginUID)
	}
	if ho.Transport != cc.Transport {
		t.Fatalf("Transport = %q, want %q", ho.Transport, cc.Transport)
	}
	if ho.NegotiatedALPN != cc.NegotiatedALPN {
		t.Fatalf("NegotiatedALPN = %q, want %q", ho.NegotiatedALPN, cc.NegotiatedALPN)
	}
}
