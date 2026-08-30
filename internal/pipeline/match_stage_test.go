package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/policy"
)

type testSnapshot struct {
	version string
}

func (s testSnapshot) Version() string              { return s.version }
func (s testSnapshot) Rules() []policy.CompiledRule { return nil }

type testStore struct {
	snap policy.PolicySnapshot
	age  time.Duration
	ok   bool
}

func (s testStore) Current() (policy.PolicySnapshot, time.Duration, bool) {
	return s.snap, s.age, s.ok
}

type testMatcher struct {
	result policy.MatchResult
	err    error
}

func (m testMatcher) Match(context.Context, policy.PolicySnapshot, policy.RequestFacts) (policy.MatchResult, error) {
	return m.result, m.err
}

func TestMatchStage_RuleMatchesStoresResult(t *testing.T) {
	expected := policy.MatchResult{
		Matched:   true,
		PolicyRef: "default/policy/rule",
		Version:   "v1",
		Credential: &v1alpha1.CredentialSelector{
			Provider: "entra",
		},
	}
	rc := &RequestContext{Facts: policy.RequestFacts{Identity: "api.example.com"}}
	stage := &MatchStage{
		Store:        testStore{snap: testSnapshot{version: "v1"}, ok: true},
		Matcher:      testMatcher{result: expected},
		MaxStaleness: time.Minute,
	}

	decision := stage.Execute(rc)

	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	if rc.MatchResult.PolicyRef != expected.PolicyRef || rc.MatchResult.Version != expected.Version {
		t.Fatalf("stored MatchResult = %+v, want %+v", rc.MatchResult, expected)
	}
	if rc.MatchResult.Credential == nil || rc.MatchResult.Credential.Provider != "entra" {
		t.Fatalf("stored Credential = %+v, want provider entra", rc.MatchResult.Credential)
	}
}

func TestMatchStage_NoMatchDenies(t *testing.T) {
	stage := &MatchStage{
		Store:        testStore{snap: testSnapshot{version: "v1"}, ok: true},
		Matcher:      testMatcher{result: policy.MatchResult{}},
		MaxStaleness: time.Minute,
	}

	decision := stage.Execute(&RequestContext{})

	if decision.Reason != ReasonNoMatch || decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() = %+v, want deny no-match", decision)
	}
}

func TestMatchStage_MatcherErrorDeniesFault(t *testing.T) {
	stage := &MatchStage{
		Store:        testStore{snap: testSnapshot{version: "v1"}, ok: true},
		Matcher:      testMatcher{err: errors.New("boom")},
		MaxStaleness: time.Minute,
	}

	decision := stage.Execute(&RequestContext{})

	if decision.Reason != ReasonMatcherFault || !decision.Fault {
		t.Fatalf("Execute() = %+v, want matcher fault", decision)
	}
}

func TestMatchStage_NoSnapshotDeniesFault(t *testing.T) {
	stage := &MatchStage{
		Store:        testStore{},
		Matcher:      testMatcher{},
		MaxStaleness: time.Minute,
	}

	decision := stage.Execute(&RequestContext{})

	if decision.Reason != ReasonNoSnapshot || !decision.Fault {
		t.Fatalf("Execute() = %+v, want no snapshot fault", decision)
	}
}

func TestMatchStage_StaleSnapshotDeniesFault(t *testing.T) {
	stage := &MatchStage{
		Store:        testStore{snap: testSnapshot{version: "v1"}, age: time.Minute, ok: true},
		Matcher:      testMatcher{},
		MaxStaleness: time.Minute,
	}

	decision := stage.Execute(&RequestContext{})

	if decision.Reason != ReasonSnapshotStale || !decision.Fault {
		t.Fatalf("Execute() = %+v, want stale snapshot fault", decision)
	}
}

func TestMatchStage_NegativeAge_DeniesStale(t *testing.T) {
	// A negative age can only arise from a clock anomaly (non-monotonic
	// publication time plus a wall-clock rollback). The one-sided
	// `age >= maxStaleness` check would treat it as fresh (fail-OPEN), so the
	// stage must fail closed and deny the snapshot as stale.
	stage := &MatchStage{
		Store:        testStore{snap: testSnapshot{version: "v1"}, age: -time.Second, ok: true},
		Matcher:      testMatcher{result: policy.MatchResult{Matched: true, PolicyRef: "r"}},
		MaxStaleness: time.Minute,
	}

	decision := stage.Execute(&RequestContext{})

	if decision.Reason != ReasonSnapshotStale || !decision.Fault {
		t.Fatalf("Execute() = %+v, want stale snapshot fault on negative age", decision)
	}
}

func TestMatchStage_ZeroMaxStaleness_DefaultsFiveMinutes(t *testing.T) {
	// Age under 5 min should allow.
	stage := &MatchStage{
		Store:   testStore{snap: testSnapshot{version: "v1"}, age: 4 * time.Minute, ok: true},
		Matcher: testMatcher{result: policy.MatchResult{Matched: true, PolicyRef: "r"}},
	}
	d := stage.Execute(&RequestContext{})
	if !d.IsAllow() {
		t.Fatalf("4min age with zero MaxStaleness should allow, got %v", d)
	}

	// Age at 5 min should deny.
	stage2 := &MatchStage{
		Store:   testStore{snap: testSnapshot{version: "v1"}, age: 5 * time.Minute, ok: true},
		Matcher: testMatcher{},
	}
	d2 := stage2.Execute(&RequestContext{})
	if d2.Reason != ReasonSnapshotStale {
		t.Fatalf("5min age with zero MaxStaleness should deny stale, got %v", d2)
	}
}
