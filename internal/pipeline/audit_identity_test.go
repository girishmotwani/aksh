package pipeline

import (
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/policy"
)

// TestBuildAuditEvent_StampsPodIdentityAndServiceAccount proves the producing
// side (issue #62): the pod triple and service account resolved once at
// construction via WithAuditIdentity must appear on every built event, because
// replicas share a ServiceAccount and the pod triple is the only attribution
// that distinguishes them (ADR-S0-06).
func TestBuildAuditEvent_StampsPodIdentityAndServiceAccount(t *testing.T) {
	id := AuditIdentity{
		PodNamespace:   "aksh-e2e",
		PodName:        "aksh-e2e-abc123",
		PodUID:         "11111111-2222-3333-4444-555555555555",
		ServiceAccount: "aksh-proxy",
	}
	p := NewPipeline([]Stage{}, &testAuditSink{}, WithAuditIdentity(id))

	rc := &RequestContext{RequestID: "req-1", Timings: map[string]time.Duration{}}
	ev := p.buildAuditEvent(rc, Allow())

	if ev.PodNamespace != id.PodNamespace {
		t.Errorf("PodNamespace = %q, want %q", ev.PodNamespace, id.PodNamespace)
	}
	if ev.PodName != id.PodName {
		t.Errorf("PodName = %q, want %q", ev.PodName, id.PodName)
	}
	if ev.PodUID != id.PodUID {
		t.Errorf("PodUID = %q, want %q", ev.PodUID, id.PodUID)
	}
	if ev.AgentServiceAccount != id.ServiceAccount {
		t.Errorf("AgentServiceAccount = %q, want %q", ev.AgentServiceAccount, id.ServiceAccount)
	}
}

// TestBuildAuditEvent_AlwaysRecordsEvaluatorVersion proves the S2 §6 evaluator
// build version is stamped unconditionally (the policy hash attests inputs, not
// behaviour), independent of any per-request state.
func TestBuildAuditEvent_AlwaysRecordsEvaluatorVersion(t *testing.T) {
	p := NewPipeline([]Stage{}, &testAuditSink{})

	rc := &RequestContext{RequestID: "req-1", Timings: map[string]time.Duration{}}
	ev := p.buildAuditEvent(rc, Allow())

	if ev.EvaluatorVersion != policy.EvaluatorVersion {
		t.Errorf("EvaluatorVersion = %q, want %q", ev.EvaluatorVersion, policy.EvaluatorVersion)
	}
	if ev.EvaluatorVersion == "" {
		t.Error("EvaluatorVersion must never be empty")
	}
}

// TestBuildAuditEvent_MapsTimings proves rc.Timings and rc.StartTime are mapped
// into AuditTimings: Match from the "match" key, Acquire from "acquire", and
// Total from time-since-StartTime (time-to-audit, since audit runs before the
// post-audit stages). Audit is structurally unavailable in the record that
// carries it and is documented to stay zero.
func TestBuildAuditEvent_MapsTimings(t *testing.T) {
	start := time.Now().Add(-5 * time.Millisecond)
	rc := &RequestContext{
		RequestID: "req-1",
		StartTime: start,
		Timings: map[string]time.Duration{
			"match":   2 * time.Millisecond,
			"acquire": 3 * time.Millisecond,
			"audit":   9 * time.Millisecond, // written after build; must not appear here
		},
	}
	p := NewPipeline([]Stage{}, &testAuditSink{})

	ev := p.buildAuditEvent(rc, Allow())

	if ev.Timings.Match != 2*time.Millisecond {
		t.Errorf("Timings.Match = %v, want %v", ev.Timings.Match, 2*time.Millisecond)
	}
	if ev.Timings.Acquire != 3*time.Millisecond {
		t.Errorf("Timings.Acquire = %v, want %v", ev.Timings.Acquire, 3*time.Millisecond)
	}
	if ev.Timings.Total < 5*time.Millisecond {
		t.Errorf("Timings.Total = %v, want >= 5ms (time since StartTime)", ev.Timings.Total)
	}
	if ev.Timings.Audit != 0 {
		t.Errorf("Timings.Audit = %v, want 0 (a record cannot contain the time taken to write itself)", ev.Timings.Audit)
	}
}

// TestBuildAuditEvent_MissingTimingKeysAreZero proves absent stage keys map to
// the zero duration rather than panicking on the nil-safe map read.
func TestBuildAuditEvent_MissingTimingKeysAreZero(t *testing.T) {
	rc := &RequestContext{RequestID: "req-1", StartTime: time.Now(), Timings: map[string]time.Duration{}}
	p := NewPipeline([]Stage{}, &testAuditSink{})

	ev := p.buildAuditEvent(rc, Allow())

	if ev.Timings.Match != 0 {
		t.Errorf("Timings.Match = %v, want 0", ev.Timings.Match)
	}
	if ev.Timings.Acquire != 0 {
		t.Errorf("Timings.Acquire = %v, want 0", ev.Timings.Acquire)
	}
}

// TestNewPipeline_TwoArgFormUnchanged proves the additive PipelineOption did not
// break the existing two-argument construction: it still compiles, leaves the
// audit identity zero-valued, and behaves identically.
func TestNewPipeline_TwoArgFormUnchanged(t *testing.T) {
	p := NewPipeline([]Stage{}, &testAuditSink{})

	rc := &RequestContext{RequestID: "req-1", Timings: map[string]time.Duration{}}
	ev := p.buildAuditEvent(rc, Allow())

	if ev.PodNamespace != "" || ev.PodName != "" || ev.PodUID != "" || ev.AgentServiceAccount != "" {
		t.Errorf("two-arg NewPipeline must leave identity empty, got %+v", ev)
	}
}
