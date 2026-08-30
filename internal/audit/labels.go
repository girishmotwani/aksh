package audit

// This file defines the closed-enum vocabulary backing the cardinality-safe
// metric labels of S6 §4.1. Every type here is a closed set: an agent-controlled
// free string can never be assigned to one, which is the security property §4.1
// protects (an unbounded label set is a memory-exhaustion vector).
//
// Note: TransportReject cannot reuse the existing listener.RejectClass int
// enum, because internal/dataplane/listener imports internal/audit (for the
// recorder interfaces), so audit importing listener would create an import
// cycle. RejectClass is therefore defined locally here with the identical
// taxonomy strings.

// StageName is the closed enum for the aksh_decision_duration_seconds{stage}
// label (F1). Its zero value is StageUnknown so an unset stage never leaks.
type StageName int

const (
	StageUnknown StageName = iota
	StageSanitise
	StageIdentity
	StageMatch
	StageAcquire
	StageInject
	StageAcceptDispatch
	StageTLSConfigBuild
	StageLeafMint
	StageUpstreamDial
	StageResolve
)

// String returns the bounded stage label value.
func (s StageName) String() string {
	switch s {
	case StageSanitise:
		return "sanitise"
	case StageIdentity:
		return "identity"
	case StageMatch:
		return "match"
	case StageAcquire:
		return "acquire"
	case StageInject:
		return "inject"
	case StageAcceptDispatch:
		return "accept_to_dispatch"
	case StageTLSConfigBuild:
		return "tls_config_build"
	case StageLeafMint:
		return "leaf_mint"
	case StageUpstreamDial:
		return "upstream_dial"
	case StageResolve:
		return "resolve"
	default:
		return "unknown"
	}
}

// BoundName is the closed enum for the aksh_transport_reject_total{bound} label
// (F5). Its zero value is BoundNone.
type BoundName int

const (
	BoundNone BoundName = iota
	BoundMaxInflightRequests
	BoundPipelining
	BoundMaxHeaderBytes
	BoundRequestHeaderReadTimeout
	BoundHandover
	BoundMaxResponseBody
	BoundHandshakeRate
)

// String returns the bounded bound label value.
func (b BoundName) String() string {
	switch b {
	case BoundNone:
		return "none"
	case BoundMaxInflightRequests:
		return "max_inflight_requests"
	case BoundPipelining:
		return "pipelining"
	case BoundMaxHeaderBytes:
		return "max_header_bytes"
	case BoundRequestHeaderReadTimeout:
		return "request_header_read_timeout"
	case BoundHandover:
		return "handover"
	case BoundMaxResponseBody:
		return "max_response_body"
	case BoundHandshakeRate:
		return "handshake_rate"
	default:
		return "unknown"
	}
}

// TransportKind is the closed enum {tls, plaintext} backing the transport label
// (F16), replacing the free-string policy.Transport. Its zero value is
// TransportTLS.
type TransportKind int

const (
	TransportTLS TransportKind = iota
	TransportPlaintext
)

// String returns the bounded transport label value.
func (t TransportKind) String() string {
	switch t {
	case TransportPlaintext:
		return "plaintext"
	default:
		return "tls"
	}
}

// AuditRecordKind is the closed enum for the aksh_audit_records_total{kind}
// label. Its zero value is AuditRecordDecision.
type AuditRecordKind int

const (
	AuditRecordDecision AuditRecordKind = iota
	AuditRecordCompletion
)

// String returns the bounded kind label value.
func (k AuditRecordKind) String() string {
	switch k {
	case AuditRecordCompletion:
		return "completion"
	default:
		return "decision"
	}
}

// RejectClass is the closed enum for the aksh_transport_reject_total{class}
// label (F6). It mirrors the listener.RejectClass taxonomy strings; the
// duplication avoids an audit<-listener import cycle. Zero value RejectClassNone.
type RejectClass int

const (
	RejectClassNone RejectClass = iota
	RejectClassNoOriginalDst
	RejectClassLoopGuard
	RejectClassNoSNI
	RejectClassHandshake
	RejectClassUnsupportedProtocol
	RejectClassIdentityMismatch
	RejectClassResourceLimit
	RejectClassPlaintextUnresolvable
	RejectClassPlaintextRegistryUnavail
)

// String returns the bounded class label value.
func (r RejectClass) String() string {
	switch r {
	case RejectClassNone:
		return "none"
	case RejectClassNoOriginalDst:
		return "no_original_dst"
	case RejectClassLoopGuard:
		return "loop_guard"
	case RejectClassNoSNI:
		return "no_sni"
	case RejectClassHandshake:
		return "handshake"
	case RejectClassUnsupportedProtocol:
		return "unsupported_protocol"
	case RejectClassIdentityMismatch:
		return "identity_mismatch"
	case RejectClassResourceLimit:
		return "resource_limit"
	case RejectClassPlaintextUnresolvable:
		return "plaintext_unresolvable"
	case RejectClassPlaintextRegistryUnavail:
		return "plaintext_registry_unavailable"
	default:
		return "unknown"
	}
}

// RejectClassFromString maps a legacy taxonomy string to the closed RejectClass
// enum, falling back to RejectClassNone for an unrecognised value so an
// agent-influenced string can never leak as a new label series.
func RejectClassFromString(s string) RejectClass {
	switch s {
	case "no_original_dst":
		return RejectClassNoOriginalDst
	case "loop_guard":
		return RejectClassLoopGuard
	case "no_sni":
		return RejectClassNoSNI
	case "handshake":
		return RejectClassHandshake
	case "unsupported_protocol":
		return RejectClassUnsupportedProtocol
	case "identity_mismatch":
		return RejectClassIdentityMismatch
	case "resource_limit":
		return RejectClassResourceLimit
	case "plaintext_unresolvable":
		return RejectClassPlaintextUnresolvable
	case "plaintext_registry_unavailable":
		return RejectClassPlaintextRegistryUnavail
	default:
		return RejectClassNone
	}
}

// BoundNameFromString maps a legacy bound string to the closed BoundName enum,
// falling back to BoundNone for an unrecognised value.
func BoundNameFromString(s string) BoundName {
	switch s {
	case "max_inflight_requests":
		return BoundMaxInflightRequests
	case "pipelining":
		return BoundPipelining
	case "max_header_bytes":
		return BoundMaxHeaderBytes
	case "request_header_read_timeout":
		return BoundRequestHeaderReadTimeout
	case "handover":
		return BoundHandover
	case "max_response_body":
		return BoundMaxResponseBody
	case "handshake_rate":
		return BoundHandshakeRate
	default:
		return BoundNone
	}
}
