package policy

import (
	"context"
	"sort"
	"strings"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
)

// matcher implements the Matcher interface.
type matcher struct{}

// NewMatcher returns a new Matcher instance.
func NewMatcher() Matcher {
	return &matcher{}
}

func (m *matcher) Match(ctx context.Context, snap PolicySnapshot, req RequestFacts) (MatchResult, error) {
	// Use internal read-only accessor if available to avoid per-request
	// deep copy of up to 2048 rules. The compiledSnapshot exposes
	// internalRules() for this purpose — external snapshots (e.g. in tests)
	// fall back to Rules() which returns a defensive copy.
	var rules []CompiledRule
	if ro, ok := snap.(interface{ internalRules() []CompiledRule }); ok {
		rules = ro.internalRules()
	} else {
		rules = snap.Rules()
	}
	if len(rules) == 0 {
		return MatchResult{}, nil
	}

	type candidate struct {
		rule CompiledRule
		rank MatchRank
	}

	var candidates []candidate

	for _, r := range rules {
		// Host matching.
		if !matchHost(r, req.Identity) {
			continue
		}

		// Plaintext eligibility.
		if req.Transport == TransportPlaintext && !r.AllowPlaintext {
			continue
		}

		// Method matching.
		if len(r.Methods) > 0 && !containsMethod(r.Methods, req.Method) {
			continue
		}

		// Path matching.
		pathExact, pathLen, pathMatched := matchPaths(r.Paths, req.Path)
		if len(r.Paths) > 0 && !pathMatched {
			continue
		}

		candidates = append(candidates, candidate{
			rule: r,
			rank: MatchRank{
				Static:    r.Rank,
				PathExact: pathExact,
				PathLen:   pathLen,
			},
		})
	}

	if len(candidates) == 0 {
		return MatchResult{}, nil
	}

	// Sort candidates by full MatchRank.
	sort.SliceStable(candidates, func(i, j int) bool {
		return compareMatchRank(candidates[i].rank, candidates[j].rank) < 0
	})

	winner := candidates[0]

	// Determine ambiguity: a match is ambiguous when the runner-up
	// carries a DIFFERENT credential than the winner. This matters
	// because ambiguity means a different rule ordering could inject
	// a different token — a security-relevant outcome. Same-credential
	// ties are NOT ambiguous (the outcome is identical regardless).
	// The Ambiguous flag is forwarded to the audit event.
	ambiguous := false
	if len(candidates) > 1 {
		// Check if any candidate carries a different credential than the winner.
		hasDifferentCred := false
		for i := 1; i < len(candidates); i++ {
			if !credentialEqual(winner.rule.Credential, candidates[i].rule.Credential) {
				hasDifferentCred = true
				break
			}
		}
		if hasDifferentCred {
			ambiguous = true
		} else if isTieBreakOnly(candidates[0].rank, candidates[1].rank) {
			// Tie resolved between same-credential rules is NOT ambiguous.
			// Only flag if credentials differ (handled above).
		}
	}

	return MatchResult{
		Matched:    true,
		PolicyRef:  winner.rule.Ref,
		Version:    snap.Version(),
		Credential: winner.rule.Credential,
		Ambiguous:  ambiguous,
	}, nil
}

// matchHost checks if a rule's host pattern matches the request identity.
// Wildcard rules (*.example.com) match exactly one subdomain label:
//   - *.example.com matches sub.example.com ✓
//   - *.example.com does NOT match example.com ✗ (no label before suffix)
//   - *.example.com does NOT match sub.sub.example.com ✗ (two labels)
func matchHost(r CompiledRule, identity string) bool {
	identity = strings.ToLower(identity)
	if r.Wildcard {
		// *.example.com matches sub.example.com but not example.com or sub.sub.example.com
		suffix := r.Host[1:] // ".example.com"
		if !strings.HasSuffix(identity, suffix) {
			return false
		}
		// Check single label: the part before suffix must not contain a dot.
		prefix := identity[:len(identity)-len(suffix)]
		return len(prefix) > 0 && !strings.Contains(prefix, ".")
	}
	return identity == r.Host
}

func containsMethod(methods []string, method string) bool {
	for _, m := range methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// matchPaths returns the most specific matching path entry.
// Returns (isExact, matchLen, matched).
func matchPaths(paths []CompiledPath, reqPath string) (bool, int, bool) {
	if len(paths) == 0 {
		return false, 0, true // no paths = match any
	}
	bestExact := false
	bestLen := -1
	matched := false

	for _, p := range paths {
		if p.Exact {
			if reqPath == p.Value {
				bestExact = true
				if len(p.Value) > bestLen {
					bestLen = len(p.Value)
				}
				matched = true
			}
		} else {
			if matchPrefix(p.Value, reqPath) {
				if len(p.Value) > bestLen && !bestExact {
					bestLen = len(p.Value)
				}
				matched = true
			}
		}
	}
	return bestExact, bestLen, matched
}

// matchPrefix implements segment-aware prefix matching per S2 §5.1.
// Unlike strings.HasPrefix alone, this prevents partial-segment matches:
//   - /api matches /api ✓ and /api/v1 ✓ but NOT /apix ✗
//   - /api/ matches /api/v1 ✓ (trailing slash = HasPrefix is sufficient)
//
// The next character after the prefix must be '/' to ensure a segment boundary.
func matchPrefix(prefix, path string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	// Exact length match.
	if len(path) == len(prefix) {
		return true
	}
	// Prefix ends with / (e.g., "/api/" or "/") — HasPrefix is sufficient.
	if prefix[len(prefix)-1] == '/' {
		return true
	}
	// Otherwise next char must be /.
	return path[len(prefix)] == '/'
}

// compareMatchRank implements the full §5.2 ordering. Returns <0 if a is
// more specific than b. The ordering interleaves static and dynamic dimensions:
//  1. Host (exact > wildcard)           — from Static
//  2. Path (exact > prefix; longer > shorter) — from request match
//  3. Method (explicit > absent; fewer > more) — from Static
//  4. Constraint rank                   — from Static (reserved)
//  5. Tie-break (lexicographic)         — from Static
func compareMatchRank(a, b MatchRank) int {
	// Static rank first (host, method, constraint, tie-break).
	// But we interleave path between host and method per §5.2.
	if a.Static.HostExact != b.Static.HostExact {
		if a.Static.HostExact {
			return -1
		}
		return 1
	}
	// Path specificity: exact beats prefix; longer beats shorter.
	if a.PathExact != b.PathExact {
		if a.PathExact {
			return -1
		}
		return 1
	}
	if a.PathLen != b.PathLen {
		return b.PathLen - a.PathLen // longer is more specific
	}
	// Method specificity.
	if a.Static.MethodCount != b.Static.MethodCount {
		if a.Static.MethodCount == 0 {
			return 1
		}
		if b.Static.MethodCount == 0 {
			return -1
		}
		return a.Static.MethodCount - b.Static.MethodCount
	}
	// Constraint rank (always 0 in MVP, reserved for future).
	if a.Static.ConstraintRank != b.Static.ConstraintRank {
		return a.Static.ConstraintRank - b.Static.ConstraintRank
	}
	// Tie-break.
	return strings.Compare(a.Static.TieBreak, b.Static.TieBreak)
}

func isTieBreakOnly(a, b MatchRank) bool {
	return a.Static.HostExact == b.Static.HostExact &&
		a.PathExact == b.PathExact &&
		a.PathLen == b.PathLen &&
		a.Static.MethodCount == b.Static.MethodCount &&
		a.Static.ConstraintRank == b.Static.ConstraintRank
}

// credentialEqual compares two CredentialSelectors by value.
// Scopes are sorted before comparison because their order in the CRD
// is not semantically significant (OAuth scopes are a set, not a list).
func credentialEqual(a, b *v1alpha1.CredentialSelector) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Provider != b.Provider || a.Resource != b.Resource {
		return false
	}
	if len(a.Scopes) != len(b.Scopes) {
		return false
	}
	// Compare sorted.
	as := make([]string, len(a.Scopes))
	bs := make([]string, len(b.Scopes))
	copy(as, a.Scopes)
	copy(bs, b.Scopes)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
