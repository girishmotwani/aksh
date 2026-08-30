// Package policy defines the S2 policy engine interfaces:
// the policy store, immutable snapshots, matching, and the canonical
// request representation.
package policy

import (
	"context"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
)

// RequestFacts is the canonical, validated view of a request.
// Built by the identity stage (S4) after INV-8 host validation;
// consumed by S2 matching and remaining pipeline stages.
//
// All fields are pre-validated — the matcher trusts them:
//   - Identity is the validated hostname (SNI or Host header, never raw)
//   - Path is already canonicalized via CanonicalizePath
//   - Transport determines whether AllowPlaintext rules apply
type RequestFacts struct {
	Identity  string    // validated hostname (SNI after INV-8 checks)
	Method    string    // HTTP method
	Path      string    // canonical request path
	Port      uint16    // destination port
	Transport Transport // tls or plaintext
}

// MatchResult is the output of policy evaluation.
// A zero-value MatchResult has Matched=false, which the pipeline
// interprets as "no rule matched → deny" (fail-closed per INV-4).
type MatchResult struct {
	Matched    bool                         // true if at least one rule matched
	PolicyRef  string                       // "namespace/policy/rule" — the winning rule's ref
	Version    string                       // snapshot version at time of match (for audit)
	Credential *v1alpha1.CredentialSelector // nil = no credential injection needed
	Ambiguous  bool                         // true if runner-up has different credential (security concern)
}

// PolicySnapshot is an immutable, point-in-time compiled rule set.
// Created by Compile() and stored by the PolicyStore, it is safe
// for concurrent reads without locking. The snapshot is replaced
// atomically when CRD changes are detected.
type PolicySnapshot interface {
	Version() string       // content-derived SHA-256 digest
	Rules() []CompiledRule // defensive copy — safe to mutate
}

// PolicyStore provides the current snapshot and its age.
type PolicyStore interface {
	Current() (snap PolicySnapshot, age time.Duration, ok bool)
}

// Matcher evaluates a request against a snapshot.
type Matcher interface {
	Match(ctx context.Context, snap PolicySnapshot, req RequestFacts) (MatchResult, error)
}
