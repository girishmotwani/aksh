package policy_test

import (
	"context"
	"testing"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/policy"
)

// TestPrecedence_OrderIndependentUnderShuffledInput proves INV-7: the winning
// rule is a pure function of the rule set and the request, never of the order
// in which the rules were presented to the compiler. The design (S7 §5.1)
// requires this be shown "twice with shuffled input"; here it is shown across
// every permutation of the input, which subsumes any single shuffle.
//
// The rule set below has a single unambiguous winner (the exact host + exact
// path + explicit method rule "target"), so a correct matcher must select it
// regardless of input order. A matcher that leaked input order — e.g. by
// resolving ties with the first-seen rule rather than the documented
// lexicographic tie-break — would fail on at least one permutation.
func TestPrecedence_OrderIndependentUnderShuffledInput(t *testing.T) {
	base := []v1alpha1.AkshPolicy{
		makePolicy("ns", "p-wild", "wild", "*.example.com", true, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "wild-res"}, false),
		makePolicy("ns", "p-host", "host", "api.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "host-res"}, false),
		makePolicy("ns", "p-prefix", "prefix", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypePrefix, Value: "/api"}},
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "prefix-res"}, false),
		makePolicy("ns", "p-target", "target", "api.example.com", false,
			[]string{"GET"},
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypeExact, Value: "/api/v1"}},
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "target-res"}, false),
	}
	facts := policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/api/v1", Transport: policy.TransportTLS,
	}
	m := newMatcher(t)

	var perms [][]v1alpha1.AkshPolicy
	permute(append([]v1alpha1.AkshPolicy(nil), base...), 0, &perms)
	if len(perms) != 24 { // 4! — guards against a broken permutation generator
		t.Fatalf("expected 24 permutations of 4 rules, got %d", len(perms))
	}

	var firstRef string
	var firstAmbiguous bool

	for i, order := range perms {
		snap := mustCompile(t, order)
		res, err := m.Match(context.Background(), snap, facts)
		if err != nil {
			t.Fatalf("perm %d: %v", i, err)
		}
		if !res.Matched {
			t.Fatalf("perm %d: expected a match", i)
		}
		// Specificity correctness: the exact-host + exact-path + explicit-method
		// rule must win in every ordering.
		if res.Credential == nil || res.Credential.Resource != "target-res" {
			t.Fatalf("perm %d: winner depends on input order; got %+v, want target-res", i, res.Credential)
		}
		// Order-independence: every derived field of the decision — the winner,
		// its policy ref, and the credential-shadowing ambiguity flag — must be
		// invariant under input permutation. (Ambiguous is legitimately true
		// here because the runner-up rules carry different credentials; INV-7
		// requires that this verdict not vary with rule order.)
		if i == 0 {
			// This rule set has runner-up rules carrying DIFFERENT credentials
			// than the winner, so credential-shadowing ambiguity MUST be flagged.
			// Pinning the expected value (not just cross-permutation consistency)
			// means a regression that dropped the ambiguity signal is caught here.
			if !res.Ambiguous {
				t.Fatalf("perm 0: expected Ambiguous=true (runner-ups carry different credentials)")
			}
			if res.PolicyRef == "" {
				t.Fatalf("perm 0: empty PolicyRef for a matched decision")
			}
			firstRef = res.PolicyRef
			firstAmbiguous = res.Ambiguous
			continue
		}
		if res.PolicyRef != firstRef {
			t.Fatalf("perm %d: PolicyRef depends on input order; got %q, want %q", i, res.PolicyRef, firstRef)
		}
		if res.Ambiguous != firstAmbiguous {
			t.Fatalf("perm %d: Ambiguous flag depends on input order; got %v, want %v", i, res.Ambiguous, firstAmbiguous)
		}
	}
}

// permute appends every permutation of s to out (Heap-agnostic simple swap
// recursion). It mutates s in place, so callers pass a copy.
func permute(s []v1alpha1.AkshPolicy, k int, out *[][]v1alpha1.AkshPolicy) {
	if k == len(s) {
		cp := make([]v1alpha1.AkshPolicy, len(s))
		copy(cp, s)
		*out = append(*out, cp)
		return
	}
	for i := k; i < len(s); i++ {
		s[k], s[i] = s[i], s[k]
		permute(s, k+1, out)
		s[k], s[i] = s[i], s[k]
	}
}
