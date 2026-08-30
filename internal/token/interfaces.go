package token

import "context"

// AcquireErrorClass classifies token acquisition failures.
// The three classes have genuinely different handling — transient
// errors may be retried, permanent errors should not, and local
// errors indicate Aksh's own configuration problems.
type AcquireErrorClass int

const (
	AcquireErrorTransient AcquireErrorClass = iota + 1
	AcquireErrorPermanent
	AcquireErrorLocal
)

func (c AcquireErrorClass) String() string {
	switch c {
	case AcquireErrorTransient:
		return "transient"
	case AcquireErrorPermanent:
		return "permanent"
	case AcquireErrorLocal:
		return "local"
	default:
		return "unknown"
	}
}

// AcquireError is a classified acquisition failure.
type AcquireError struct {
	Class   AcquireErrorClass
	Message string
	Cause   error
}

// Error renders only the classification and Message — never the raw
// Cause. Cause may wrap transport-level errors from the IdP HTTP layer
// that can carry request or secret material (INV-5), so it must never
// be rendered verbatim in a log or audit sink. Cause remains reachable
// programmatically via Unwrap() for errors.Is/errors.As, but callers
// must not call Cause.Error() and log the result; Message itself must
// only ever be set to validated, non-secret metadata.
func (e *AcquireError) Error() string {
	return e.Class.String() + ": " + e.Message
}

func (e *AcquireError) Unwrap() error {
	return e.Cause
}

// ResolvedCredential is the canonical resolved form of a credential
// selector — shared by S1's pool key, S3's cache, and S6's audit.
type ResolvedCredential struct {
	Identity   string // hex SHA-256 credential identity
	Provider   string
	Resource   string
	WireScopes []string
}

// TokenResult is a token plus resolution metadata and a cache-hit flag
// that S6 must record.
type TokenResult struct {
	Token    Token
	Resolved ResolvedCredential
	CacheHit bool
}

// TokenProvider resolves a CredentialSelector into a token by calling
// the identity provider (Entra in MVP). The seam that makes FR10
// (multi-IdP) additive.
type TokenProvider interface {
	Acquire(ctx context.Context, selector CredentialSelector) (TokenResult, error)
}

// TokenCache caches tokens to avoid calling Entra on every request.
type TokenCache interface {
	Get(credID string) (Token, bool)
	Put(credID string, token Token)
}
