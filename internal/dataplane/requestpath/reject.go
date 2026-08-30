package requestpath

import "github.com/girishmotwani/aksh/internal/pipeline"

// RejectClass is the request-path rejection taxonomy.
type RejectClass string

const (
	ClassT1 RejectClass = "no_original_dst"
	ClassT2 RejectClass = "loop_guard"
	ClassT3 RejectClass = "no_sni"
	ClassT4 RejectClass = "handshake"
	ClassT5 RejectClass = "unsupported_protocol"
	ClassT6 RejectClass = "identity_mismatch"
	ClassT7 RejectClass = "resource_limit"
	ClassT8 RejectClass = "plaintext_unresolvable"
	ClassT9 RejectClass = "plaintext_registry_unavailable"
)

// WireBehaviour describes what the agent observes for a rejection.
type WireBehaviour int

const (
	WireCloseBare WireBehaviour = iota
	WireWrite400Close
	WireWrite431Close
)

// Rejection is the complete description of one refusal.
type Rejection struct {
	Class     RejectClass
	Reason    pipeline.DenyReason
	Bound     string
	Wire      WireBehaviour
	Status    int
	Fault     bool
	RequestID string
	ConnID    string
	Port      uint16
	Method    string
	Path      string
}
