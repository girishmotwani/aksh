package pipeline

// DenyReason is closed so audit and metric values stay bounded and cannot
// expose operator- or agent-controlled text. Reasons are never surfaced to
// the agent (ADR-S0-13).
type DenyReason int

const (
	ReasonNone DenyReason = iota
	ReasonNoMatch
	ReasonNoSnapshot
	ReasonSnapshotStale
	ReasonTokenUnavailable
	ReasonAuditUnavailable
	ReasonIdentityMismatch
	ReasonUnsupportedProtocol
	ReasonNoSNI
	ReasonMatcherFault
	ReasonInternal
	ReasonMalformedTarget
	ReasonResourceLimit
	ReasonPodLocalDestination

	// Dataplane reasons (S6 Slice 7): closed-enum values for the refusal
	// reasons the dataplane previously emitted as ad-hoc strings through the
	// legacy DataplaneMetrics adapter. Appended after the existing values so
	// no pre-existing enum ordinal changes.
	ReasonDraining
	ReasonHandlerPanic
	ReasonDialFailed
	ReasonWriteFailed
	ReasonResponseFailed
	ReasonProgressDeadline
	ReasonRegistryAddFailed
	ReasonHandshakeFailed
	ReasonLoopGuard
	ReasonMissingClientHello
	ReasonNoOriginalDst

	DenyReasonUnspecified            = ReasonNone
	DenyReasonNoMatch                = ReasonNoMatch
	DenyReasonPolicyCacheEmpty       = ReasonNoSnapshot
	DenyReasonPolicyCacheStale       = ReasonSnapshotStale
	DenyReasonTokenAcquisitionFailed = ReasonTokenUnavailable
	DenyReasonAuditFailed            = ReasonAuditUnavailable
	DenyReasonIdentityMismatch       = ReasonIdentityMismatch
	DenyReasonUnsupportedProtocol    = ReasonUnsupportedProtocol
	DenyReasonNoSNI                  = ReasonNoSNI
)

func (r DenyReason) String() string {
	switch r {
	case ReasonNone:
		return "unspecified"
	case ReasonNoMatch:
		return "policy_no_match"
	case ReasonNoSnapshot:
		return "policy_cache_empty"
	case ReasonSnapshotStale:
		return "policy_cache_stale"
	case ReasonTokenUnavailable:
		return "token_acquisition_failed"
	case ReasonAuditUnavailable:
		return "audit_failed"
	case ReasonIdentityMismatch:
		return "identity_mismatch"
	case ReasonUnsupportedProtocol:
		return "unsupported_protocol"
	case ReasonNoSNI:
		return "no_sni"
	case ReasonMatcherFault:
		return "matcher_fault"
	case ReasonInternal:
		return "internal"
	case ReasonMalformedTarget:
		return "malformed_target"
	case ReasonResourceLimit:
		return "resource_limit"
	case ReasonPodLocalDestination:
		return "destination_pod_local"
	case ReasonDraining:
		return "draining"
	case ReasonHandlerPanic:
		return "handler_panic"
	case ReasonDialFailed:
		return "dial_failed"
	case ReasonWriteFailed:
		return "write_failed"
	case ReasonResponseFailed:
		return "response_failed"
	case ReasonProgressDeadline:
		return "progress_deadline"
	case ReasonRegistryAddFailed:
		return "registry_add_failed"
	case ReasonHandshakeFailed:
		return "handshake_failed"
	case ReasonLoopGuard:
		return "loop_guard"
	case ReasonMissingClientHello:
		return "missing_client_hello"
	case ReasonNoOriginalDst:
		return "no_original_dst"
	default:
		return "unknown"
	}
}
