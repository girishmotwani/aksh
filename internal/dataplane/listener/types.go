// Package listener owns the loopback control-plane accept loop and the shared
// connection vocabulary (Protocol, RejectClass, ConnContext) used across the
// Phase 5A data-plane packages.
// See docs/design/S1a-dataplane-capture.md sections 7.2, 10.1 and 14.
package listener

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/policy"
)

// Protocol is the closed enum produced by the discriminator. It is not a parallel
// of policy.Transport: it distinguishes wire framings, two of which map onto the
// single policy.Transport value TransportPlaintext. Transport() performs that
// mapping so that no call site invents its own.
type Protocol int

const (
	ProtocolUnknown Protocol = iota // zero value rejects (INV-4)
	ProtocolTLS
	ProtocolHTTP1
	ProtocolH2CPreface
)

// String returns the bounded metric/log literal for the protocol.
func (p Protocol) String() string {
	switch p {
	case ProtocolTLS:
		return "tls"
	case ProtocolHTTP1:
		return "http/1.1"
	case ProtocolH2CPreface:
		return "h2c"
	default:
		return "unknown"
	}
}

// Transport maps a wire framing onto the policy transport it is evaluated under.
// It reports false for ProtocolUnknown and ProtocolH2CPreface, both of which are
// rejected rather than forwarded, so no caller can treat an unknown framing as
// plaintext.
func (p Protocol) Transport() (policy.Transport, bool) {
	switch p {
	case ProtocolTLS:
		return policy.TransportTLS, true
	case ProtocolHTTP1:
		return policy.TransportPlaintext, true
	default:
		return "", false
	}
}

// transportKindOf maps a wire framing onto the audit transport label.
// Only a verified TLS ClientHello (ProtocolTLS) is labelled tls; every other
// framing -- plaintext HTTP/1, h2c prefaces, and unclassifiable bytes -- is
// plaintext, so a rejection can never misreport a non-TLS connection as tls.
func transportKindOf(p Protocol) audit.TransportKind {
	if p == ProtocolTLS {
		return audit.TransportTLS
	}
	return audit.TransportPlaintext
}

// RejectClass is the closed enum for the S1 section 8 transport rejections,
// numbered T1-T9 (design section 14). Its zero value is RejectNone, so an unset
// rejection field never falsely maps to a T-class.
type RejectClass int

const (
	RejectNone RejectClass = iota
	RejectNoOriginalDst
	RejectLoopGuard
	RejectNoSNI
	RejectHandshake
	RejectUnsupportedProtocol
	RejectIdentityMismatch // T6 - decided by S4 stage 1, never raised in 5A
	RejectResourceLimit
	RejectPlaintextUnresolvable    // T8 - not reachable in 5A
	RejectPlaintextRegistryUnavail // T9 - every plaintext connection in 5A
)

// String returns the aksh_transport_reject_total{class="..."} metric label.
func (r RejectClass) String() string {
	switch r {
	case RejectNoOriginalDst:
		return "no_original_dst"
	case RejectLoopGuard:
		return "loop_guard"
	case RejectNoSNI:
		return "no_sni"
	case RejectHandshake:
		return "handshake"
	case RejectUnsupportedProtocol:
		return "unsupported_protocol"
	case RejectIdentityMismatch:
		return "identity_mismatch"
	case RejectResourceLimit:
		return "resource_limit"
	case RejectPlaintextUnresolvable:
		return "plaintext_unresolvable"
	case RejectPlaintextRegistryUnavail:
		return "plaintext_registry_unavailable"
	default:
		return "none"
	}
}

// Code returns the taxonomy code "T1".."T9", or the empty string for RejectNone
// and any out-of-range value, since neither denotes a rejection.
func (r RejectClass) Code() string {
	if r < RejectNoOriginalDst || r > RejectPlaintextRegistryUnavail {
		return ""
	}
	return [...]string{"T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9"}[r-RejectNoOriginalDst]
}

// ConnContext is the per-connection state 5A owns. It is created at accept, is
// confined to the connection's own goroutine, and is what 5A hands to 5B.
type ConnContext struct {
	ConnID         string         // 128-bit random hex; correlates log lines, not a RequestID
	Downstream     net.Conn       // the peeked-and-restored connection
	PeerAddr       netip.AddrPort // the agent socket's local tuple
	OriginalDst    netip.AddrPort // kernel-attested, from BPFDestinationResolver
	OriginUID      uint32         // from orig_dst.uid
	Protocol       Protocol
	Transport      policy.Transport
	CandidateSNI   string // canonical A-label; empty for plaintext
	NegotiatedALPN string
	AcceptedAt     time.Time

	// decided latches the connection's single aksh_decisions_total sample.
	// See MarkDecided.
	decided atomic.Bool
}

// MarkDecided claims the right to record this connection's one and only
// aksh_decisions_total sample, returning true to exactly one caller.
//
// The metric is defined as "every terminal connection outcome"
// (docs/design/S9b-production-wiring.md) and spec row 174 requires "exactly
// one RecordDecision call reflecting its eventual disposition". Enforcing
// that is not local to any single layer: a connection's terminal disposition
// can be reached in the TLS terminator (handshake refused), the request path
// (policy verdict, request rejection), the relay (transport fault), or the
// progress watchdog — which runs on its own goroutine, hence the atomic.
// Each of those sites knows its own reason but cannot know whether another
// already fired, so before this latch existed every layer recorded
// independently and the listener added a coarse rollup on top. That
// over-counted allows threefold and double-counted every rejection
// (issues #89 and #83).
//
// The contract is: the first site to reach a terminal disposition wins and
// records; every later site skips. The listener's post-Handle rollup calls
// this last, so it degrades to a fallback that fires only for connections no
// layer classified.
func (c *ConnContext) MarkDecided() bool {
	if c == nil {
		return false
	}
	return c.decided.CompareAndSwap(false, true)
}

// Decided reports whether this connection's decision sample has been claimed.
func (c *ConnContext) Decided() bool {
	if c == nil {
		return false
	}
	return c.decided.Load()
}

// DecisionLatch exposes the underlying latch so layers that receive a *copy*
// of the connection state rather than this pointer - requestpath.Handover is
// a value struct - can share the one latch instead of each owning a private
// copy that would defeat it. Returns nil for a nil receiver.
func (c *ConnContext) DecisionLatch() *atomic.Bool {
	if c == nil {
		return nil
	}
	return &c.decided
}
