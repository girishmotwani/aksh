package policy_test

import (
	"testing"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/policy"
)

func TestCompile_SinglePolicy(t *testing.T) {
	snap, err := policy.Compile([]v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Version() == "" {
		t.Error("snapshot version must be non-empty")
	}
	if len(snap.Rules()) == 0 {
		t.Error("snapshot should have at least one rule")
	}
}

func TestCompile_MultiplePolicies_Union(t *testing.T) {
	snap, err := policy.Compile([]v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "a.example.com", false, nil, nil, nil, false),
		makePolicy("ns", "p2", "r1", "b.example.com", false, nil, nil, nil, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Rules()) != 2 {
		t.Errorf("expected 2 rules from union, got %d", len(snap.Rules()))
	}
}

func TestCompile_VersionContentDerived_SameInput(t *testing.T) {
	policies := []v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, false),
	}
	snap1, _ := policy.Compile(policies)
	snap2, _ := policy.Compile(policies)
	if snap1.Version() != snap2.Version() {
		t.Errorf("same input should yield same version: %q vs %q", snap1.Version(), snap2.Version())
	}
}

func TestCompile_VersionContentDerived_DifferentInput(t *testing.T) {
	snap1, _ := policy.Compile([]v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "a.example.com", false, nil, nil, nil, false),
	})
	snap2, _ := policy.Compile([]v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "b.example.com", false, nil, nil, nil, false),
	})
	if snap1.Version() == snap2.Version() {
		t.Error("different input should yield different version")
	}
}

func TestCompile_RulesSortedByRank(t *testing.T) {
	snap, err := policy.Compile([]v1alpha1.AkshPolicy{
		makePolicy("ns", "p2", "r1", "api.example.com", false, nil, nil, nil, false),
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := snap.Rules()
	if len(rules) < 2 {
		t.Fatal("expected at least 2 rules")
	}
	// p1 should come before p2 lexicographically.
	if rules[0].Ref > rules[1].Ref {
		t.Errorf("rules not sorted: %q should precede %q", rules[1].Ref, rules[0].Ref)
	}
}

func TestCompile_HostsCanonicalised(t *testing.T) {
	snap, _ := policy.Compile([]v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "API.EXAMPLE.COM", false, nil, nil, nil, false),
	})
	rules := snap.Rules()
	if len(rules) != 1 {
		t.Fatal("expected 1 rule")
	}
	if rules[0].Host != "api.example.com" {
		t.Errorf("host should be lowercased: got %q", rules[0].Host)
	}
}

func TestCompile_PathsCanonicalised(t *testing.T) {
	snap, _ := policy.Compile([]v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil,
			[]v1alpha1.PathMatcher{{Type: v1alpha1.PathTypePrefix, Value: "/a//b"}}, nil, false),
	})
	rules := snap.Rules()
	if len(rules) != 1 || len(rules[0].Paths) != 1 {
		t.Fatal("expected 1 rule with 1 path")
	}
	if rules[0].Paths[0].Value != "/a/b" {
		t.Errorf("path should be canonicalised: got %q", rules[0].Paths[0].Value)
	}
}

func TestCompile_ExceedMaxRules_Error(t *testing.T) {
	// Build a policy with 256 rules (the per-policy max), then 9 such policies = 2304 > 2048.
	var policies []v1alpha1.AkshPolicy
	for i := 0; i < 9; i++ {
		p := v1alpha1.AkshPolicy{
			Spec: v1alpha1.AkshPolicySpec{
				Egress: v1alpha1.EgressSpec{},
			},
		}
		p.SetNamespace("ns")
		p.SetName("p" + string(rune('a'+i)))
		for j := 0; j < 256; j++ {
			p.Spec.Egress.Rules = append(p.Spec.Egress.Rules, v1alpha1.EgressRule{
				Name: "r" + itoa(j),
				To:   v1alpha1.HostMatch{Host: "h" + itoa(j) + ".example.com"},
			})
		}
		policies = append(policies, p)
	}
	_, err := policy.Compile(policies)
	if err == nil {
		t.Error("expected error when exceeding 2048 total rules")
	}
}

func TestCompile_SnapshotImmutable_RulesCopy(t *testing.T) {
	snap, _ := policy.Compile([]v1alpha1.AkshPolicy{
		makePolicy("ns", "p1", "r1", "api.example.com", false, nil, nil, nil, false),
	})
	rules1 := snap.Rules()
	rules2 := snap.Rules()
	if len(rules1) == 0 {
		t.Fatal("expected rules")
	}
	// Mutating one copy should not affect the other.
	rules1[0].Host = "mutated.example.com"
	if rules2[0].Host == "mutated.example.com" {
		t.Error("Rules() must return a defensive copy; mutation leaked")
	}
}

func TestCompile_EmptyPolicies_ValidSnapshot(t *testing.T) {
	snap, err := policy.Compile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Version() == "" {
		t.Error("empty snapshot should still have a version")
	}
	if len(snap.Rules()) != 0 {
		t.Error("empty snapshot should have zero rules")
	}
}

func TestCompile_EffectDeny_Rejected(t *testing.T) {
	p := v1alpha1.AkshPolicy{
		Spec: v1alpha1.AkshPolicySpec{
			Egress: v1alpha1.EgressSpec{
				Rules: []v1alpha1.EgressRule{{
					Name:   "block",
					To:     v1alpha1.HostMatch{Host: "evil.com"},
					Effect: "Deny",
				}},
			},
		},
	}
	p.SetNamespace("ns")
	p.SetName("p1")
	_, err := policy.Compile([]v1alpha1.AkshPolicy{p})
	if err == nil {
		t.Fatal("expected error for effect: Deny")
	}
}

func TestCompile_EffectAllow_Accepted(t *testing.T) {
	p := v1alpha1.AkshPolicy{
		Spec: v1alpha1.AkshPolicySpec{
			Egress: v1alpha1.EgressSpec{
				Rules: []v1alpha1.EgressRule{{
					Name:   "allow-explicit",
					To:     v1alpha1.HostMatch{Host: "good.com"},
					Effect: "Allow",
				}},
			},
		},
	}
	p.SetNamespace("ns")
	p.SetName("p1")
	_, err := policy.Compile([]v1alpha1.AkshPolicy{p})
	if err != nil {
		t.Fatalf("effect Allow should be accepted: %v", err)
	}
}

// itoa is a trivial int-to-string for test naming without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
