package pipeline

import "fmt"

// Disposition is the four-valued outcome of the enforcement pipeline.
// The zero value is DispositionInvalid, ensuring that a forgotten
// assignment cannot fail open (S0 INV-4).
type Disposition int

const (
	DispositionInvalid Disposition = iota // zero value — denies
	DispositionAllow
	DispositionDeny
	DispositionPending // reserved for FR13 approval hooks
)

func (d Disposition) String() string {
	switch d {
	case DispositionInvalid:
		return "invalid"
	case DispositionAllow:
		return "allow"
	case DispositionDeny:
		return "deny"
	case DispositionPending:
		return "pending"
	default:
		return fmt.Sprintf("disposition(%d)", int(d))
	}
}

// Decision is the pipeline's verdict for a single request.
type Decision struct {
	disposition Disposition
	Reason      DenyReason
	// Fault separates ordinary policy denials from failures that require
	// operator attention while preserving the same fail-closed disposition.
	Fault bool
	// Cause remains internal for classification and diagnostics; audit records
	// use closed enums so arbitrary error text cannot leak request data.
	Cause error
}

// Allow creates an allow decision.
func Allow() Decision {
	return Decision{disposition: DispositionAllow}
}

// Deny creates a deny decision with the given reason and cause.
func Deny(reason DenyReason, cause error) Decision {
	return Decision{
		disposition: DispositionDeny,
		Reason:      reason,
		Cause:       cause,
	}
}

// DenyFault creates a deny decision caused by infrastructure failure.
func DenyFault(reason DenyReason, cause error) Decision {
	return Decision{
		disposition: DispositionDeny,
		Reason:      reason,
		Fault:       true,
		Cause:       cause,
	}
}

// Pending creates a pending decision (FR13 approval hooks, not used in MVP).
func Pending() Decision {
	return Decision{disposition: DispositionPending}
}

// Disposition returns the decision's disposition.
func (d Decision) Disposition() Disposition {
	return d.disposition
}

// IsAllow returns true only for an explicit allow.
func (d Decision) IsAllow() bool {
	return d.disposition == DispositionAllow
}
