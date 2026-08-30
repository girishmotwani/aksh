package audit

// This file extends the closed-enum label vocabulary of labels.go with the
// Slice-2 metric families (token, upstream, injector) of S6 §4. Every type here
// is a closed set: an agent-controlled free string can never be assigned to one,
// which is the cardinality-as-security property §4.1 protects.

// ProviderID is the closed enum for the `provider` label (F2) on the token
// metric family. Its bounded set mirrors the identity providers Aksh supports
// (Entra in MVP). Zero value ProviderUnknown so an unset provider never leaks.
type ProviderID int

const (
	ProviderUnknown ProviderID = iota
	ProviderEntra
)

// String returns the bounded provider label value.
func (p ProviderID) String() string {
	switch p {
	case ProviderEntra:
		return "entra"
	default:
		return "unknown"
	}
}

// Result is the closed enum for the `result` label (F3) on
// aksh_token_acquisitions_total. The acquisition's error taxonomy is carried
// separately by AcquireErrorClass; Result records only the coarse outcome.
// Zero value ResultUnknown.
type Result int

const (
	ResultUnknown Result = iota
	ResultSuccess
	ResultFailure
)

// String returns the bounded result label value.
func (r Result) String() string {
	switch r {
	case ResultSuccess:
		return "success"
	case ResultFailure:
		return "failure"
	default:
		return "unknown"
	}
}

// AcquireErrorClass is the closed enum for the `class` label on
// aksh_token_acquisitions_total. It mirrors internal/token.AcquireErrorClass's
// taxonomy strings; the duplication keeps audit from importing token purely for
// a label enum and follows the Slice-1 I2 mirror pattern. Zero value
// AcquireErrorNone (a successful acquisition has no error class).
type AcquireErrorClass int

const (
	AcquireErrorNone AcquireErrorClass = iota
	AcquireErrorTransient
	AcquireErrorPermanent
	AcquireErrorLocal
)

// String returns the bounded class label value.
func (c AcquireErrorClass) String() string {
	switch c {
	case AcquireErrorTransient:
		return "transient"
	case AcquireErrorPermanent:
		return "permanent"
	case AcquireErrorLocal:
		return "local"
	default:
		return "none"
	}
}

// AcquireErrorClassFromString maps a token-package taxonomy string to the closed
// AcquireErrorClass enum, falling back to AcquireErrorNone for an unrecognised
// value so an agent-influenced string can never leak as a new label series.
func AcquireErrorClassFromString(s string) AcquireErrorClass {
	switch s {
	case "transient":
		return AcquireErrorTransient
	case "permanent":
		return AcquireErrorPermanent
	case "local":
		return AcquireErrorLocal
	default:
		return AcquireErrorNone
	}
}

// CredentialID is the bounded derived `credential` label (F4) on
// breaker_state / cache_evictions_total / refresh_failures_total. It is the S3
// §2.3 credential hash, structurally capped by S3 §8's 256-entry cache. It is a
// NAMED type (not the predeclared string) so the whole-surface #69 reflection
// assertion — every metric label parameter is a named, non-`string` type —
// holds while still permitting the bounded operator/derived hash value.
type CredentialID string

// String returns the credential hash label value.
func (c CredentialID) String() string { return string(c) }

// UpstreamResult is the closed enum for the `result` label on
// aksh_upstream_requests_total (#57). It is deliberately distinct from the token
// Result enum: the upstream outcome vocabulary is independent of acquisition.
// Zero value UpstreamResultUnknown.
type UpstreamResult int

const (
	UpstreamResultUnknown UpstreamResult = iota
	UpstreamResultSuccess
	UpstreamResultFailure
)

// String returns the bounded upstream result label value.
func (r UpstreamResult) String() string {
	switch r {
	case UpstreamResultSuccess:
		return "success"
	case UpstreamResultFailure:
		return "failure"
	default:
		return "unknown"
	}
}

// WebhookName is the closed enum for the `webhook` label on the injector
// admission metrics (S6 §4, S5 §1: exactly two webhooks). Zero value
// WebhookUnknown.
type WebhookName int

const (
	WebhookUnknown WebhookName = iota
	WebhookMutate
	WebhookValidate
)

// String returns the bounded webhook label value.
func (w WebhookName) String() string {
	switch w {
	case WebhookMutate:
		return "mutate"
	case WebhookValidate:
		return "validate"
	default:
		return "unknown"
	}
}

// AdmissionResult is the closed enum for the `result` label on
// aksh_admission_requests_total (#65). Zero value AdmissionResultUnknown.
type AdmissionResult int

const (
	AdmissionResultUnknown AdmissionResult = iota
	AdmissionResultAllowed
	AdmissionResultDenied
	AdmissionResultError
)

// String returns the bounded admission result label value.
func (r AdmissionResult) String() string {
	switch r {
	case AdmissionResultAllowed:
		return "allowed"
	case AdmissionResultDenied:
		return "denied"
	case AdmissionResultError:
		return "errored"
	default:
		return "unknown"
	}
}

// AdmissionRule is the closed enum for the `rule` label on
// aksh_admission_rejections_total (#67) — the INV-10 admissibility check that
// fired (S5 §4). The set is bounded to the validating webhook's checks. Zero
// value AdmissionRuleUnknown.
type AdmissionRule int

const (
	AdmissionRuleUnknown AdmissionRule = iota
	AdmissionRuleRunAsUser
	AdmissionRuleContainerOrder
	AdmissionRuleCanonicalShape
	AdmissionRuleCapabilities
	AdmissionRuleProcessNamespace
	AdmissionRuleHostNetwork
	AdmissionRuleServiceAccountToken
	AdmissionRuleCredentialMounts
	AdmissionRuleHostUsers
	AdmissionRuleIstioSidecar
	AdmissionRuleCATrustReadOnly
)

// String returns the bounded rule label value.
func (r AdmissionRule) String() string {
	switch r {
	case AdmissionRuleRunAsUser:
		return "run_as_user"
	case AdmissionRuleContainerOrder:
		return "container_order"
	case AdmissionRuleCanonicalShape:
		return "canonical_shape"
	case AdmissionRuleCapabilities:
		return "capabilities"
	case AdmissionRuleProcessNamespace:
		return "process_namespace"
	case AdmissionRuleHostNetwork:
		return "host_network"
	case AdmissionRuleServiceAccountToken:
		return "service_account_token"
	case AdmissionRuleCredentialMounts:
		return "credential_mounts"
	case AdmissionRuleHostUsers:
		return "host_users"
	case AdmissionRuleIstioSidecar:
		return "istio_sidecar"
	case AdmissionRuleCATrustReadOnly:
		return "ca_trust_read_only"
	default:
		return "unknown"
	}
}

// BreakerState is the closed enum for the value of the aksh_token_breaker_state
// gauge (#53). It is the gauge's numeric value (not a label): closed=0, open=1,
// half_open=2, mirroring internal/token's breaker states. Zero value
// BreakerClosed.
type BreakerState int

const (
	BreakerClosed BreakerState = iota
	BreakerOpen
	BreakerHalfOpen
)

// String returns the breaker state name (for diagnostics; the gauge stores the
// numeric value).
func (s BreakerState) String() string {
	switch s {
	case BreakerOpen:
		return "open"
	case BreakerHalfOpen:
		return "half_open"
	default:
		return "closed"
	}
}
