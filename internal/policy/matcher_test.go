package policy_test

import (
	"context"
	"testing"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/policy"
)

// helper builds a compiled snapshot from policies.
func mustCompile(t *testing.T, policies []v1alpha1.AkshPolicy) policy.PolicySnapshot {
	t.Helper()
	snap, err := policy.Compile(policies)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	return snap
}

func newMatcher(t *testing.T) policy.Matcher {
	t.Helper()
	return policy.NewMatcher()
}

// --- Host matching ---

func TestMatch_ExactHost(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, err := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matched {
		t.Error("expected match for exact host")
	}
}

func TestMatch_ExactHost_CaseInsensitive(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "API.Example.COM", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, err := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matched {
		t.Error("expected case-insensitive host match")
	}
}

func TestMatch_ExactHost_NoMatch(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, err := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "other.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched {
		t.Error("expected no match for different host")
	}
}

func TestMatch_WildcardHost(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "*.example.com", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, err := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "sub.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matched {
		t.Error("expected wildcard match for sub.example.com")
	}
}

func TestMatch_WildcardHost_NotBare(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "*.example.com", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, err := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched {
		t.Error("wildcard should NOT match bare domain")
	}
}

func TestMatch_WildcardHost_SingleLabelOnly(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "*.example.com", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, err := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "sub.sub.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched {
		t.Error("wildcard should NOT match multi-label sub.sub.example.com")
	}
}

// --- Path matching ---

func TestMatch_ExactPath(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypeExact, Value: "/healthz"}}, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/healthz", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Error("expected exact path match")
	}
}

func TestMatch_ExactPath_NoExtraSegments(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypeExact, Value: "/healthz"}}, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/healthz/extra", Transport: policy.TransportTLS,
	})
	if res.Matched {
		t.Error("exact path should NOT match with extra segments")
	}
}

func TestMatch_PrefixPath_MatchesSubpath(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypePrefix, Value: "/api"}}, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/api/v1", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Error("prefix /api should match /api/v1")
	}
}

func TestMatch_PrefixPath_SegmentAware(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypePrefix, Value: "/api"}}, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/apix", Transport: policy.TransportTLS,
	})
	if res.Matched {
		t.Error("prefix /api must NOT match /apix (segment-aware)")
	}
}

func TestMatch_PrefixPath_ExactSelf(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypePrefix, Value: "/api"}}, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/api", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Error("prefix /api should match /api exactly")
	}
}

// --- Method matching ---

func TestMatch_ExplicitMethods_Listed(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false,
			[]string{"GET", "POST"}, nil, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Error("GET should match [GET, POST]")
	}
}

func TestMatch_ExplicitMethods_Unlisted(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false,
			[]string{"GET", "POST"}, nil, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "DELETE", Path: "/", Transport: policy.TransportTLS,
	})
	if res.Matched {
		t.Error("DELETE should NOT match [GET, POST]")
	}
}

func TestMatch_AbsentMethods_MatchAny(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "PATCH", Path: "/", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Error("absent methods should match any method")
	}
}

// --- AllowPlaintext eligibility ---

func TestMatch_PlaintextBlocked_ByDefault(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportPlaintext,
	})
	if res.Matched {
		t.Error("plaintext should NOT match when allowPlaintext is false")
	}
}

func TestMatch_PlaintextAllowed(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, true),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportPlaintext,
	})
	if !res.Matched {
		t.Error("plaintext should match when allowPlaintext is true")
	}
}

func TestMatch_TLS_IgnoresPlaintextFlag(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if !res.Matched {
		t.Error("TLS request should match regardless of allowPlaintext setting")
	}
}

// --- Default deny ---

func TestMatch_EmptySnapshot_DefaultDeny(t *testing.T) {
	snap := mustCompile(t, nil)
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if res.Matched {
		t.Error("empty snapshot must deny (default-deny)")
	}
}

func TestMatch_NoMatchingRule_DefaultDeny(t *testing.T) {
	snap := mustCompile(t, []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "other.example.com", false, nil, nil, nil, false),
	})
	m := newMatcher(t)
	res, _ := m.Match(context.Background(), snap, policy.RequestFacts{
		Identity: "api.example.com", Method: "GET", Path: "/", Transport: policy.TransportTLS,
	})
	if res.Matched {
		t.Error("no matching rule should deny")
	}
}

// --- helpers ---

// makePolicy builds an AkshPolicy for testing.
func makePolicy(
	ns, policyName, ruleName, host string,
	wildcard bool,
	methods []string,
	paths []v1alpha1.PathMatcher,
	credential *v1alpha1.CredentialSelector,
	allowPlaintext bool,
) v1alpha1.AkshPolicy {
	rule := v1alpha1.EgressRule{
		Name:           ruleName,
		To:             v1alpha1.HostMatch{Host: host},
		AllowPlaintext: allowPlaintext,
	}
	if methods != nil || paths != nil {
		rule.Match = &v1alpha1.RuleMatch{
			Methods: methods,
			Paths:   paths,
		}
	}
	if credential != nil {
		rule.Credential = credential
	}
	p := v1alpha1.AkshPolicy{
		Spec: v1alpha1.AkshPolicySpec{
			Egress: v1alpha1.EgressSpec{
				Rules: []v1alpha1.EgressRule{rule},
			},
		},
	}
	p.SetNamespace(ns)
	p.SetName(policyName)
	return p
}
