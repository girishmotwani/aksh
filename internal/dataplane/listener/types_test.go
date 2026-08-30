package listener_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/policy"
)

// TestProtocol covers unittest spec section 15 (tests 205-212): the Protocol
// closed enum produced by the discriminator.
func TestProtocol(t *testing.T) {
	t.Run("Protocol_String_UnknownReturnsUnknownLiteral", func(t *testing.T) {
		if got := listener.ProtocolUnknown.String(); got != "unknown" {
			t.Fatalf("ProtocolUnknown.String() = %q, want %q", got, "unknown")
		}
	})

	t.Run("Protocol_String_TLSReturnsTLSLiteral", func(t *testing.T) {
		if got := listener.ProtocolTLS.String(); got != "tls" {
			t.Fatalf("ProtocolTLS.String() = %q, want %q", got, "tls")
		}
	})

	t.Run("Protocol_String_HTTP1ReturnsHTTP1Literal", func(t *testing.T) {
		if got := listener.ProtocolHTTP1.String(); got != "http/1.1" {
			t.Fatalf("ProtocolHTTP1.String() = %q, want %q", got, "http/1.1")
		}
	})

	t.Run("Protocol_String_H2CPrefaceReturnsH2CLiteral", func(t *testing.T) {
		if got := listener.ProtocolH2CPreface.String(); got != "h2c" {
			t.Fatalf("ProtocolH2CPreface.String() = %q, want %q", got, "h2c")
		}
	})

	t.Run("Protocol_Transport_TLSReturnsPolicyTransportAndTrue", func(t *testing.T) {
		got, ok := listener.ProtocolTLS.Transport()
		if !ok {
			t.Fatalf("ProtocolTLS.Transport() ok = false, want true")
		}
		if got != policy.TransportTLS {
			t.Fatalf("ProtocolTLS.Transport() = %q, want %q", got, policy.TransportTLS)
		}
	})

	t.Run("Protocol_Transport_UnknownReturnsFalse", func(t *testing.T) {
		if _, ok := listener.ProtocolUnknown.Transport(); ok {
			t.Fatalf("ProtocolUnknown.Transport() ok = true, want false")
		}
	})

	t.Run("Protocol_Transport_H2CPrefaceReturnsFalse", func(t *testing.T) {
		if _, ok := listener.ProtocolH2CPreface.Transport(); ok {
			t.Fatalf("ProtocolH2CPreface.Transport() ok = true, want false")
		}
	})

	t.Run("Protocol_ZeroValue_EqualsProtocolUnknown", func(t *testing.T) {
		var p listener.Protocol
		if p != listener.ProtocolUnknown {
			t.Fatalf("zero-value Protocol = %v, want ProtocolUnknown", p)
		}
	})
}

// allNineRejectClasses is T1-T9 in the design's documented numbering order.
var allNineRejectClasses = []struct {
	class listener.RejectClass
	code  string
	text  string
}{
	{listener.RejectNoOriginalDst, "T1", "no_original_dst"},
	{listener.RejectLoopGuard, "T2", "loop_guard"},
	{listener.RejectNoSNI, "T3", "no_sni"},
	{listener.RejectHandshake, "T4", "handshake"},
	{listener.RejectUnsupportedProtocol, "T5", "unsupported_protocol"},
	{listener.RejectIdentityMismatch, "T6", "identity_mismatch"},
	{listener.RejectResourceLimit, "T7", "resource_limit"},
	{listener.RejectPlaintextUnresolvable, "T8", "plaintext_unresolvable"},
	{listener.RejectPlaintextRegistryUnavail, "T9", "plaintext_registry_unavailable"},
}

// TestRejectClass covers unittest spec section 16 (tests 213-222): the T1-T9
// rejection taxonomy enum shared across the listener, tlsterm and upstream packages.
func TestRejectClass(t *testing.T) {
	t.Run("RejectClass_String_NoOriginalDstReturnsT1Literal", func(t *testing.T) {
		if got := listener.RejectNoOriginalDst.String(); got != "no_original_dst" {
			t.Fatalf("RejectNoOriginalDst.String() = %q, want %q", got, "no_original_dst")
		}
	})

	t.Run("RejectClass_String_LoopGuardReturnsT2Literal", func(t *testing.T) {
		if got := listener.RejectLoopGuard.String(); got != "loop_guard" {
			t.Fatalf("RejectLoopGuard.String() = %q, want %q", got, "loop_guard")
		}
	})

	t.Run("RejectClass_Code_NoOriginalDstReturnsT1Code", func(t *testing.T) {
		if got := listener.RejectNoOriginalDst.Code(); got != "T1" {
			t.Fatalf("RejectNoOriginalDst.Code() = %q, want %q", got, "T1")
		}
	})

	t.Run("RejectClass_Code_ResourceLimitReturnsT7Code", func(t *testing.T) {
		if got := listener.RejectResourceLimit.Code(); got != "T7" {
			t.Fatalf("RejectResourceLimit.Code() = %q, want %q", got, "T7")
		}
	})

	t.Run("RejectClass_ZeroValue_EqualsRejectNone", func(t *testing.T) {
		var r listener.RejectClass
		if r != listener.RejectNone {
			t.Fatalf("zero-value RejectClass = %v, want RejectNone", r)
		}
		if code := r.Code(); code != "" {
			t.Fatalf("RejectNone.Code() = %q, want empty string (no T-class)", code)
		}
	})

	t.Run("RejectClass_String_AllNineClassesReturnDistinctNonEmptyLiterals", func(t *testing.T) {
		seen := make(map[string]listener.RejectClass, len(allNineRejectClasses))
		for _, tc := range allNineRejectClasses {
			got := tc.class.String()
			if got == "" {
				t.Errorf("%s.String() is empty", tc.code)
				continue
			}
			if got != tc.text {
				t.Errorf("%s.String() = %q, want %q", tc.code, got, tc.text)
			}
			if prev, dup := seen[got]; dup {
				t.Errorf("%s.String() = %q collides with RejectClass(%d)", tc.code, got, int(prev))
			}
			seen[got] = tc.class
		}
		if len(seen) != 9 {
			t.Fatalf("distinct String() literals = %d, want 9", len(seen))
		}
	})

	t.Run("RejectClass_Code_AllNineClassesReturnDistinctTCodes", func(t *testing.T) {
		seen := make(map[string]listener.RejectClass, len(allNineRejectClasses))
		for _, tc := range allNineRejectClasses {
			got := tc.class.Code()
			if got != tc.code {
				t.Errorf("RejectClass(%d).Code() = %q, want %q", int(tc.class), got, tc.code)
			}
			if prev, dup := seen[got]; dup {
				t.Errorf("Code() %q collides between RejectClass(%d) and RejectClass(%d)", got, int(prev), int(tc.class))
			}
			seen[got] = tc.class
		}
		if len(seen) != 9 {
			t.Fatalf("distinct Code() values = %d, want 9", len(seen))
		}
	})

	t.Run("RejectClass_String_IdentityMismatchDocumentedButUnreachableIn5A", func(t *testing.T) {
		if got := listener.RejectIdentityMismatch.String(); got != "identity_mismatch" {
			t.Fatalf("RejectIdentityMismatch.String() = %q, want %q", got, "identity_mismatch")
		}
		if got := listener.RejectIdentityMismatch.Code(); got != "T6" {
			t.Fatalf("RejectIdentityMismatch.Code() = %q, want %q", got, "T6")
		}
	})

	t.Run("RejectClass_String_PlaintextUnresolvableDocumentedButUnreachableIn5A", func(t *testing.T) {
		if got := listener.RejectPlaintextUnresolvable.String(); got != "plaintext_unresolvable" {
			t.Fatalf("RejectPlaintextUnresolvable.String() = %q, want %q", got, "plaintext_unresolvable")
		}
		if got := listener.RejectPlaintextUnresolvable.Code(); got != "T8" {
			t.Fatalf("RejectPlaintextUnresolvable.Code() = %q, want %q", got, "T8")
		}
	})

	t.Run("RejectClass_String_PlaintextRegistryUnavailableAppliesToEveryPlaintextConnIn5A", func(t *testing.T) {
		if got := listener.RejectPlaintextRegistryUnavail.String(); got != "plaintext_registry_unavailable" {
			t.Fatalf("RejectPlaintextRegistryUnavail.String() = %q, want %q", got, "plaintext_registry_unavailable")
		}
		if got := listener.RejectPlaintextRegistryUnavail.Code(); got != "T9" {
			t.Fatalf("RejectPlaintextRegistryUnavail.Code() = %q, want %q", got, "T9")
		}
		// Every plaintext framing in 5A carries policy.TransportPlaintext, which is
		// exactly the set of connections design section 10.3 routes to T9.
		transport, ok := listener.ProtocolHTTP1.Transport()
		if !ok || transport != policy.TransportPlaintext {
			t.Fatalf("ProtocolHTTP1.Transport() = (%q, %v), want (%q, true)", transport, ok, policy.TransportPlaintext)
		}
	})
}

// TestConnContext covers unittest spec section 17 (tests 223-226): the
// per-connection state 5A owns and hands to 5B.
func TestConnContext(t *testing.T) {
	t.Run("ConnContext_PopulatedByAcceptLoop_AllFieldsSet", func(t *testing.T) {
		downstream, peer := net.Pipe()
		defer downstream.Close()
		defer peer.Close()

		cc := listener.ConnContext{
			ConnID:         "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
			Downstream:     downstream,
			PeerAddr:       netip.MustParseAddrPort("127.0.0.1:15001"),
			OriginalDst:    netip.MustParseAddrPort("10.0.0.7:443"),
			OriginUID:      1000,
			Protocol:       listener.ProtocolTLS,
			Transport:      policy.TransportTLS,
			CandidateSNI:   "api.example.com",
			NegotiatedALPN: "h2",
			AcceptedAt:     time.Now(),
		}

		if cc.ConnID == "" {
			t.Errorf("ConnID is empty")
		}
		if cc.Downstream == nil {
			t.Errorf("Downstream is nil")
		}
		if !cc.PeerAddr.IsValid() {
			t.Errorf("PeerAddr = %v, want a valid AddrPort", cc.PeerAddr)
		}
		if !cc.OriginalDst.IsValid() {
			t.Errorf("OriginalDst = %v, want a valid AddrPort", cc.OriginalDst)
		}
		if cc.OriginUID == 0 {
			t.Errorf("OriginUID is zero")
		}
		if cc.Protocol == listener.ProtocolUnknown {
			t.Errorf("Protocol = ProtocolUnknown, want a classified protocol")
		}
		if cc.CandidateSNI == "" {
			t.Errorf("CandidateSNI is empty")
		}
		if cc.AcceptedAt.IsZero() {
			t.Errorf("AcceptedAt is the zero time")
		}
	})

	t.Run("ConnContext_ZeroValue_ProtocolFieldIsProtocolUnknown", func(t *testing.T) {
		var cc listener.ConnContext
		if cc.Protocol != listener.ProtocolUnknown {
			t.Fatalf("zero-value ConnContext.Protocol = %v, want ProtocolUnknown", cc.Protocol)
		}
		if _, ok := cc.Protocol.Transport(); ok {
			t.Fatalf("zero-value ConnContext.Protocol.Transport() ok = true, want false")
		}
	})

	t.Run("ConnContext_AcceptedAtMonotonic_LaterConnGetsLaterTimestamp", func(t *testing.T) {
		earlier := listener.ConnContext{AcceptedAt: time.Now()}
		later := listener.ConnContext{AcceptedAt: time.Now()}
		if later.AcceptedAt.Before(earlier.AcceptedAt) {
			t.Fatalf("later.AcceptedAt (%v) is before earlier.AcceptedAt (%v)", later.AcceptedAt, earlier.AcceptedAt)
		}
	})

	t.Run("ConnContext_NegotiatedALPNEmptyBeforeHandshake_PopulatedAfter", func(t *testing.T) {
		cc := listener.ConnContext{
			ConnID:       "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
			CandidateSNI: "api.example.com",
			Protocol:     listener.ProtocolTLS,
		}
		if cc.NegotiatedALPN != "" {
			t.Fatalf("NegotiatedALPN = %q immediately after accept, want empty", cc.NegotiatedALPN)
		}
		cc.NegotiatedALPN = "h2"
		if cc.NegotiatedALPN != "h2" {
			t.Fatalf("NegotiatedALPN = %q after handshake, want %q", cc.NegotiatedALPN, "h2")
		}
	})
}
