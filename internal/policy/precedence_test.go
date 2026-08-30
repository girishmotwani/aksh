package policy_test

import (
	"context"
	"testing"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/policy"
)

func TestPrecedence_ExactHostBeatsWildcard(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "wildcard-rule", "*.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "wildcard-res"}, false),
		makePolicy("ns", "p2", "exact-rule", "sub.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "exact-res"}, false),
	})
	m := newMatcher(t)
	res, err := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "sub.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matched {
		t.Fatal("expected match")
	}
	if res.Credential == nil || res.Credential.Resource != "exact-res" {
		t.Errorf("exact host should win; got credential %+v", res.Credential)
	}
}

func TestPrecedence_ExactPathBeatsPrefixPath(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "prefix-rule", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypePrefix, Value: "/api"}},
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "prefix-res"}, false),
		makePolicy("ns", "p2", "exact-rule", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypeExact, Value: "/api/v1"}},
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "exact-res"}, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/api/v1", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Fatal("expected match")
	}
	if res.Credential == nil || res.Credential.Resource != "exact-res" {
		t.Errorf("exact path should win; got credential %+v", res.Credential)
	}
}

func TestPrecedence_LongerPrefixBeatsShorter(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "short-rule", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypePrefix, Value: "/api"}},
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "short-res"}, false),
		makePolicy("ns", "p2", "long-rule", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypePrefix, Value: "/api/v1"}},
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "long-res"}, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/api/v1/users", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Fatal("expected match")
	}
	if res.Credential == nil || res.Credential.Resource != "long-res" {
		t.Errorf("longer prefix should win; got credential %+v", res.Credential)
	}
}

func TestPrecedence_ExplicitMethodsBeatsAbsent(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "any-method", "api.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "any-res"}, false),
		makePolicy("ns", "p2", "get-only", "api.example.com", false,
			[]string{"GET"}, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "get-res"}, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Fatal("expected match")
	}
	if res.Credential == nil || res.Credential.Resource != "get-res" {
		t.Errorf("explicit methods should beat absent; got credential %+v", res.Credential)
	}
}

func TestPrecedence_FewerMethodsBeatsMore(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "many-methods", "api.example.com", false,
			[]string{"GET", "POST", "PUT"}, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "many-res"}, false),
		makePolicy("ns", "p2", "few-methods", "api.example.com", false,
			[]string{"GET"}, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "few-res"}, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Fatal("expected match")
	}
	if res.Credential == nil || res.Credential.Resource != "few-res" {
		t.Errorf("fewer methods should win; got credential %+v", res.Credential)
	}
}

func TestPrecedence_TieBreakLexicographic(t *testing.T) {
	// Both rules identical in specificity; tie-break by namespace/policy/rule.
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p2", "rule-a", "api.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "p2-res"}, false),
		makePolicy("ns", "p1", "rule-a", "api.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "p1-res"}, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Fatal("expected match")
	}
	// "ns/p1/rule-a" < "ns/p2/rule-a" lexicographically, so p1 wins.
	if res.Credential == nil || res.Credential.Resource != "p1-res" {
		t.Errorf("lexicographic tie-break should pick p1; got credential %+v", res.Credential)
	}
}

func TestPrecedence_AmbiguityFlaggedOnTieBreak(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "rule-a", "api.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "res-a"}, false),
		makePolicy("ns", "p2", "rule-a", "api.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "res-b"}, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if !res.Ambiguous {
		t.Error("tie-break resolved match should be flagged Ambiguous")
	}
}

func TestPrecedence_CredentialShadowing_Ambiguous(t *testing.T) {
	// Exact host beats wildcard (ordering is clear), but different credentials → ambiguous flag.
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "wildcard-rule", "*.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypeExact, Value: "/admin"}},
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "admin-cred"}, false),
		makePolicy("ns", "p2", "exact-rule", "sub.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "readonly-cred"}, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "sub.example.com", Method: "GET", Path: "/admin", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Fatal("expected match")
	}
	if !res.Ambiguous {
		t.Error("different credentials across candidates should flag Ambiguous (credential shadowing)")
	}
}

func TestPrecedence_SameCredential_NotAmbiguous(t *testing.T) {
	cred := &v1alpha1.CredentialSelector{Provider: "entra", Resource: "same-res", Scopes: []string{".default"}}
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "rule-a", "api.example.com", false, nil, nil, cred, false),
		makePolicy("ns", "p2", "rule-b", "api.example.com", false, nil, nil, cred, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if res.Ambiguous {
		t.Error("same credential across candidates should NOT be flagged Ambiguous")
	}
}

func TestPrecedence_ORdPaths_MostSpecificEntry(t *testing.T) {
	// Rule has both a prefix and an exact path; the exact match should determine specificity.
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "multi-path", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{
				{Type: v1alpha1.PathTypePrefix, Value: "/api"},
				{Type: v1alpha1.PathTypeExact, Value: "/api/v1"},
			},
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "multi-res"}, false),
		makePolicy("ns", "p2", "prefix-only", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypePrefix, Value: "/api/v1"}},
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "prefix-res"}, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/api/v1", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Fatal("expected match")
	}
	// p1's exact /api/v1 should beat p2's prefix /api/v1.
	if res.Credential == nil || res.Credential.Resource != "multi-res" {
		t.Errorf("OR'd exact path should give the rule higher specificity; got %+v", res.Credential)
	}
}

func TestPrecedence_MethodSpecificity_AfterHostAndPath(t *testing.T) {
	// Both rules: same host, same path specificity (both absent). Method is the differentiator.
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "rule-any", "api.example.com", false, nil, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "any-res"}, false),
		makePolicy("ns", "p2", "rule-get", "api.example.com", false,
			[]string{"GET"}, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "get-res"}, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if res.Credential == nil || res.Credential.Resource != "get-res" {
		t.Errorf("method specificity should decide after host/path tie; got %+v", res.Credential)
	}
}

func TestPrecedence_Deterministic(t *testing.T) {
	policies := []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "rule-a", "api.example.com", false, []string{"GET"}, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "res-a"}, false),
		makePolicy("ns", "p2", "rule-b", "api.example.com", false, []string{"GET"}, nil,
			&v1alpha1.CredentialSelector{Provider: "entra", Resource: "res-b"}, false),
	}
	facts := policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	}
	m := newMatcher(t)

	var firstRef string
	for i := 0; i < 50; i++ {
		snap := mustCompile(t, policies)
		res, _ := m.Match(context.Background(), snap, facts)
		if i == 0 {
			firstRef = res.PolicyRef
		} else if res.PolicyRef != firstRef {
			t.Fatalf("non-deterministic: iteration %d got %q, first was %q", i, res.PolicyRef, firstRef)
		}
	}
}
