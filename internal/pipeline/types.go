package pipeline

import (
	"net/http"
	"time"

	"github.com/girishmotwani/aksh/internal/policy"
	"github.com/girishmotwani/aksh/internal/token"
)

// FaultClass classifies errors without leaking request data or
// secrets into error messages (ADR-S0-13).
type FaultClass int

const (
	FaultClassNone      FaultClass = iota // no fault
	FaultClassTransient                   // retriable infrastructure error
	FaultClassPermanent                   // non-retriable error
	FaultClassLocal                       // Aksh configuration problem
)

func (f FaultClass) String() string {
	switch f {
	case FaultClassNone:
		return "none"
	case FaultClassTransient:
		return "transient"
	case FaultClassPermanent:
		return "permanent"
	case FaultClassLocal:
		return "local"
	default:
		return "unknown"
	}
}

// IdentityInput is S1's untrusted handoff to the pipeline: the
// candidate SNI, authority host/port, and the kernel-attested
// destination port. Carried separately from validated Facts so
// nothing can trust what no stage has checked.
type IdentityInput struct {
	SNI             string // TLS ServerName (agent-chosen)
	AuthorityHost   string // HTTP Host / :authority hostname
	AuthorityPort   uint16 // HTTP Host / :authority port (0 if absent)
	DestinationPort uint16 // kernel-attested port from a BPF map written by the capture programs
}

// RequestContext is the mutable per-request state threaded through
// the pipeline stages. Stages accumulate state here; AuditEvent is
// built from a snapshot of this, never passed directly to a sink.
type RequestContext struct {
	Request     *http.Request
	Identity    IdentityInput
	Transport   policy.Transport
	Facts       policy.RequestFacts
	MatchResult policy.MatchResult
	TokenResult token.TokenResult
	Decision    Decision
	StartTime   time.Time
	RequestID   string
	// Timings is per-request and remains owned by the pipeline goroutine; it
	// must not be shared with sinks through this mutable context.
	Timings map[string]time.Duration
}

// ResponseContext is the minimal immutable view given to response
// and completion hooks — identity and provenance, never the request
// or the token (S3 §6.1).
type ResponseContext struct {
	RequestID     string
	Identity      string // validated identity
	CredentialID  string // credential identity for audit
	PolicyVersion string
	Disposition   Disposition
}

// AuditTimings carries the per-stage durations that feed the S4 §7
// latency budget. Each stage is emitted as microseconds in the audit
// record (§2 timings block). The zero value means the stage was not
// measured for this request.
type AuditTimings struct {
	// Total is measured from RequestContext.StartTime to audit-build time.
	// Because audit deliberately runs BEFORE the post-audit inject/forward
	// stages (S4), this is time-to-audit — an honest lower bound on request
	// latency, not the full request duration.
	Total time.Duration // policy-to-audit elapsed time
	Match time.Duration // policy match stage
	// Acquire is the credential acquisition stage duration.
	Acquire time.Duration
	// Audit is the audit-write duration. It is structurally unavailable in the
	// request record that carries it: the write duration can only be known once
	// the record has already been built and handed to the sink, so a record can
	// never contain the time taken to write itself. It is therefore left zero
	// on the decision record rather than fabricated; the completion record (if
	// any) is the place that can honestly report write latency.
	Audit time.Duration // audit write stage (zero on the record it describes)
}

// AuditEvent is the immutable snapshot that stage 6 hands to
// AuditSink. Built from RequestContext rather than being the context,
// so a sink can never reach the injected credential.
// Deliberately has NO Token field — S4 §2.
type AuditEvent struct {
	Timestamp     time.Time
	RequestID     string
	Identity      string
	Method        string
	Path          string
	Port          uint16
	Disposition   Disposition
	DenyReason    DenyReason
	Fault         bool
	FaultClass    FaultClass
	PolicyVersion string
	RuleName      string
	CredentialID  string
	CacheHit      bool
	Ambiguous     bool

	// --- S6 Slice-3 (F8) additive fields for the aksh.dev/audit/v1 record ---

	// Pod attribution (S5 Downward API) — replicas share a ServiceAccount
	// identity, so the pod triple is what distinguishes them (ADR-S0-06).
	PodNamespace string
	PodName      string
	PodUID       string

	// AgentServiceAccount is the FR9 identity from the Downward API.
	AgentServiceAccount string

	// Transport is the validated transport assurance (tls | plaintext).
	// Reuses the closed policy.Transport enum; the two transports carry
	// different assurance (S1 §6.1) and the audit trail must tell them apart.
	Transport policy.Transport
	// ServiceUID / ServiceGeneration are the resolved plaintext-transport
	// identifiers; they are meaningful only for plaintext transport.
	ServiceUID        string
	ServiceGeneration int64

	// EvaluatorVersion is the S2 §6 evaluator build version — the policy
	// hash attests inputs, not behaviour, so this is always recorded.
	EvaluatorVersion string

	// Credential provenance (S3 §9) — never the token. Present only when
	// the matched rule names a credential.
	CredentialProvider  string
	CredentialResource  string
	CredentialScopes    []string
	CredentialExpiresAt time.Time

	// Timings are the per-stage microsecond durations (§2 timings block).
	Timings AuditTimings

	// --- completion-record fields (§2.2); written by the Slice-4 write path ---

	CompletionStatus   int
	CompletionBytes    int64
	CompletionDuration time.Duration
}

// Stage is one ordered step of the request-phase enforcement
// pipeline (S4). The v1 extension seam for hooks.
type Stage interface {
	Execute(rc *RequestContext) Decision
	Name() string
}

// ResponseStage is one ordered step of the response-phase pipeline.
// Reserved at MVP with a pass-through default; FR14's response
// redaction and FR11's provenance capture attach here.
type ResponseStage interface {
	Execute(rc *ResponseContext) error
	Name() string
}
