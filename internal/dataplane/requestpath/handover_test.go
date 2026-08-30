package requestpath_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
)

func TestHandover_FieldAssignment_PreservesSection7Fields(t *testing.T) {
	tlsConn, peerA := net.Pipe()
	defer tlsConn.Close()
	defer peerA.Close()

	downstream, peerB := net.Pipe()
	defer downstream.Close()
	defer peerB.Close()

	acceptedAt := time.Unix(1700000000, 0)
	ho := requestpath.Handover{
		TLSConn:     tlsConn,
		Downstream:  downstream,
		SourceIP:    netip.MustParseAddr("127.0.0.1"),
		OriginalDst: netip.MustParseAddrPort("10.0.0.7:443"),
		SNI:         "api.example.com",
		ConnID:      "conn-1",
		AcceptedAt:  acceptedAt,
		IsTLS:       true,
	}

	if ho.TLSConn != tlsConn {
		t.Fatal("TLSConn was not preserved")
	}
	if ho.Downstream != downstream {
		t.Fatal("Downstream was not preserved")
	}
	if got := ho.SourceIP.String(); got != "127.0.0.1" {
		t.Fatalf("SourceIP = %q, want %q", got, "127.0.0.1")
	}
	if got := ho.OriginalDst.String(); got != "10.0.0.7:443" {
		t.Fatalf("OriginalDst = %q, want %q", got, "10.0.0.7:443")
	}
	if ho.SNI != "api.example.com" {
		t.Fatalf("SNI = %q, want %q", ho.SNI, "api.example.com")
	}
	if ho.ConnID != "conn-1" {
		t.Fatalf("ConnID = %q, want %q", ho.ConnID, "conn-1")
	}
	if !ho.AcceptedAt.Equal(acceptedAt) {
		t.Fatalf("AcceptedAt = %v, want %v", ho.AcceptedAt, acceptedAt)
	}
	if !ho.IsTLS {
		t.Fatal("IsTLS = false, want true")
	}
}
