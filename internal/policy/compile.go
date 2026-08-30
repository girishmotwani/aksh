package policy

import (
	"crypto/sha256"
	"encoding/binary"

	"fmt"
	"sort"
	"strings"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
)

const maxTotalRules = 2048

// compiledSnapshot is the immutable PolicySnapshot implementation.
// Once created by Compile(), it never changes. This allows the matcher
// to read it concurrently without locks. A new snapshot replaces the
// old one atomically when the PolicyStore detects CRD changes.
type compiledSnapshot struct {
	version string         // content-derived SHA-256 hex digest
	rules   []CompiledRule // sorted by RuleRank (most specific first)
}

func (s *compiledSnapshot) Version() string { return s.version }

// internalRules returns the internal slice for read-only matching.
// Callers MUST NOT mutate the returned slice or its elements.
func (s *compiledSnapshot) internalRules() []CompiledRule { return s.rules }

// Rules returns a defensive deep copy for external callers.
func (s *compiledSnapshot) Rules() []CompiledRule {
	cp := make([]CompiledRule, len(s.rules))
	for i, r := range s.rules {
		cp[i] = r
		if r.Methods != nil {
			cp[i].Methods = make([]string, len(r.Methods))
			copy(cp[i].Methods, r.Methods)
		}
		if r.Paths != nil {
			cp[i].Paths = make([]CompiledPath, len(r.Paths))
			copy(cp[i].Paths, r.Paths)
		}
		if r.Credential != nil {
			cred := *r.Credential
			if r.Credential.Scopes != nil {
				cred.Scopes = make([]string, len(r.Credential.Scopes))
				copy(cred.Scopes, r.Credential.Scopes)
			}
			cp[i].Credential = &cred
		}
	}
	return cp
}

// Compile builds an immutable PolicySnapshot from a set of AkshPolicy resources.
//
// This is the only entry point for creating a snapshot. It:
//  1. Validates each rule (rejects unsupported effects like "Deny")
//  2. Canonicalizes all paths via CanonicalizePath (S2 §5.1.1)
//  3. Deep-copies credential/method slices to avoid aliasing
//     informer-shared memory (which Kubernetes may mutate)
//  4. Pre-computes a RuleRank for each rule
//  5. Sorts rules by specificity for deterministic matching
//  6. Generates a content-derived SHA-256 version for audit trails
//
// The maxTotalRules limit (2048) prevents pathological O(n²) matching.
func Compile(policies []v1alpha1.AkshPolicy) (PolicySnapshot, error) {
	var rules []CompiledRule

	for i := range policies {
		p := &policies[i]
		ns := p.GetNamespace()
		pName := p.GetName()
		for j := range p.Spec.Egress.Rules {
			r := &p.Spec.Egress.Rules[j]
			ref := fmt.Sprintf("%s/%s/%s", ns, pName, r.Name)

			// MVP rejects any effect that is not "Allow" or empty (S2 §4).
			if r.Effect != "" && !strings.EqualFold(r.Effect, "Allow") {
				return nil, fmt.Errorf("rule %s: unsupported effect %q (MVP supports only Allow)", ref, r.Effect)
			}

			host := strings.ToLower(r.To.Host)
			wildcard := strings.HasPrefix(host, "*.")

			var methods []string
			var paths []CompiledPath
			if r.Match != nil {
				if r.Match.Methods != nil {
					methods = make([]string, len(r.Match.Methods))
					copy(methods, r.Match.Methods)
				}
				for _, pm := range r.Match.Paths {
					canon, err := CanonicalizePath(pm.Value)
					if err != nil {
						return nil, fmt.Errorf("rule %s: invalid path %q: %w", ref, pm.Value, err)
					}
					paths = append(paths, CompiledPath{
						Exact: pm.Type == v1alpha1.PathTypeExact,
						Value: canon,
					})
				}
			}

			methodCount := 0
			if len(methods) > 0 {
				methodCount = len(methods)
			}

			// Deep-copy credential so the snapshot doesn't alias
			// caller-owned (potentially informer-shared) memory.
			var cred *v1alpha1.CredentialSelector
			if r.Credential != nil {
				c := *r.Credential
				if r.Credential.Scopes != nil {
					c.Scopes = make([]string, len(r.Credential.Scopes))
					copy(c.Scopes, r.Credential.Scopes)
				}
				cred = &c
			}

			rules = append(rules, CompiledRule{
				Ref:            ref,
				Host:           host,
				Wildcard:       wildcard,
				Methods:        methods,
				Paths:          paths,
				AllowPlaintext: r.AllowPlaintext,
				Credential:     cred,
				Rank: RuleRank{
					HostExact:      !wildcard,
					MethodCount:    methodCount,
					ConstraintRank: 0,
					TieBreak:       ref,
				},
			})
		}
	}

	if len(rules) > maxTotalRules {
		return nil, fmt.Errorf("total rules %d exceeds maximum %d", len(rules), maxTotalRules)
	}

	// Sort by RuleRank for deterministic ordering.
	sort.Slice(rules, func(i, j int) bool {
		return compareRuleRank(rules[i].Rank, rules[j].Rank) < 0
	})

	return &compiledSnapshot{
		version: computeVersion(rules),
		rules:   rules,
	}, nil
}

// compareRuleRank returns <0 if a is more specific than b.
func compareRuleRank(a, b RuleRank) int {
	// Exact host beats wildcard.
	if a.HostExact != b.HostExact {
		if a.HostExact {
			return -1
		}
		return 1
	}
	// Explicit methods beat absent; fewer beats more.
	if a.MethodCount != b.MethodCount {
		if a.MethodCount == 0 {
			return 1 // absent is least specific
		}
		if b.MethodCount == 0 {
			return -1
		}
		return a.MethodCount - b.MethodCount
	}
	// Constraint rank (always 0 in MVP).
	if a.ConstraintRank != b.ConstraintRank {
		return a.ConstraintRank - b.ConstraintRank
	}
	// Lexicographic tie-break.
	return strings.Compare(a.TieBreak, b.TieBreak)
}

// computeVersion produces a content-derived SHA-256 hex digest of the rule set.
// This ensures the version string changes if and only if any rule field changes.
//
// Each string field is length-prefixed (4-byte big-endian uint32) to prevent
// ambiguous boundaries — without length prefixes, ("ab","c") and ("a","bc")
// would hash identically. Methods and scopes are sorted before hashing
// for determinism (Go map iteration order and informer delivery order are
// both non-deterministic).
func computeVersion(rules []CompiledRule) string {
	h := sha256.New()
	for _, r := range rules {
		writeLen(h, r.Ref)
		writeLen(h, r.Host)
		if r.Wildcard {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
		if r.AllowPlaintext {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
		// Methods sorted for determinism.
		sorted := make([]string, len(r.Methods))
		copy(sorted, r.Methods)
		sort.Strings(sorted)
		for _, m := range sorted {
			writeLen(h, m)
		}
		for _, p := range r.Paths {
			if p.Exact {
				h.Write([]byte{1})
			} else {
				h.Write([]byte{0})
			}
			writeLen(h, p.Value)
		}
		if r.Credential != nil {
			writeLen(h, r.Credential.Provider)
			writeLen(h, r.Credential.Resource)
			scopes := make([]string, len(r.Credential.Scopes))
			copy(scopes, r.Credential.Scopes)
			sort.Strings(scopes)
			for _, s := range scopes {
				writeLen(h, s)
			}
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// writeLen writes a length-prefixed string to a hash writer.
// The 4-byte big-endian length prefix prevents boundary ambiguity
// (see computeVersion comment).
func writeLen(h interface{ Write([]byte) (int, error) }, s string) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(len(s)))
	h.Write(buf[:])
	h.Write([]byte(s))
}
