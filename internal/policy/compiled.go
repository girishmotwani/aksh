package policy

import v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"

// Transport is a closed enum for the request's transport layer.
// The proxy determines this from whether the client sent a TLS
// ClientHello (→ TransportTLS) or raw HTTP (→ TransportPlaintext).
// This feeds the AllowPlaintext check: a rule without AllowPlaintext
// automatically rejects plaintext requests regardless of host/path match.
type Transport string

const (
	TransportTLS       Transport = "tls"
	TransportPlaintext Transport = "plaintext"
)

// EvaluatorVersion is the S2 §6 evaluator build version recorded in every audit
// record's policy block. It exists because the policy hash (PolicySnapshot
// .Version) attests the rule INPUTS, not the evaluator's BEHAVIOUR: two sidecars
// on different Aksh builds could hash identical rules yet enforce them
// differently, which would make the replica-equivalence claim (S2 §6, ADR-S0-06)
// unfalsifiable. Recording the evaluator build alongside the policy hash is what
// lets an incident distinguish "same rules, different code". It is a
// per-process build constant, not a per-request value; the design specifies that
// it is mandated but not its exact string, so a stable in-repo identifier is
// used until a build-stamped value replaces it.
const EvaluatorVersion = "aksh-eval-v1"

// CompiledPath is a single path matcher in canonical form.
// The Value is already canonicalized at compile time (see CanonicalizePath),
// so at match time no further normalisation is needed — just compare strings.
type CompiledPath struct {
	Exact bool   // true = PathTypeExact, false = segment-aware prefix
	Value string // canonical form, always starts with "/"
}

// RuleRank is the static part of the §5.2 ordering key.
// "Static" means it is computed once at compile time and doesn't
// depend on the specific request being matched. The request-dependent
// part (path specificity) lives in MatchRank.
//
// Ordering priority (most → least significant):
//  1. HostExact (exact host > wildcard host)
//  2. MethodCount (explicit methods > absent; fewer > more)
//  3. ConstraintRank (reserved for future narrowing dimensions)
//  4. TieBreak (lexicographic "ns/policy/rule" for determinism)
type RuleRank struct {
	HostExact      bool   // true if the rule matches a literal host (not wildcard)
	MethodCount    int    // 0 = any method (least specific); >0 = number of explicit methods
	ConstraintRank int    // always 0 in MVP — reserved for future use
	TieBreak       string // "namespace/policy/rule" — ensures deterministic winner
}

// MatchRank is the full ordering key for one candidate against one request.
// It combines the compile-time static rank with the request-time path
// specificity. The ordering per S2 §5.2 interleaves host, path, method:
//  1. HostExact (from Static)
//  2. PathExact (exact path > prefix path)
//  3. PathLen (longer prefix > shorter prefix)
//  4. MethodCount (from Static)
//  5. ConstraintRank (from Static)
//  6. TieBreak (from Static)
type MatchRank struct {
	Static    RuleRank
	PathExact bool // true if an Exact path entry matched
	PathLen   int  // length of the longest matching path entry
}

// CompiledRule is one rule in canonical, pre-sorted form.
// Created by Compile() from an EgressRule, it holds all data needed
// for matching without referencing the original CRD object. This
// decouples the matcher from informer-shared memory and ensures
// all string comparisons use lower-cased/canonicalized values.
type CompiledRule struct {
	Ref            string                       // "namespace/policy/rule" — unique rule identifier for audit
	Host           string                       // lower-cased; if Wildcard, starts with "*."
	Wildcard       bool                         // true → single-label wildcard match (*.example.com)
	Methods        []string                     // nil/empty = match any method
	Paths          []CompiledPath               // nil/empty = match any path
	AllowPlaintext bool                         // true → allow HTTP (not just HTTPS)
	Credential     *v1alpha1.CredentialSelector // nil → forward without injecting a token
	Rank           RuleRank                     // pre-computed static ordering key
}
