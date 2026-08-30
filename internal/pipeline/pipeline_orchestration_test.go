package pipeline

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/policy"
)

type auditRecord struct {
	ctx context.Context
	ev  AuditEvent
}

type testAuditSink struct {
	records []auditRecord
	err     error
	order   *[]string
}

func (s *testAuditSink) Record(ctx context.Context, ev AuditEvent) error {
	if s.order != nil {
		*s.order = append(*s.order, "audit")
	}
	s.records = append(s.records, auditRecord{ctx: ctx, ev: ev})
	return s.err
}

type testStageFunc struct {
	name string
	fn   func(*RequestContext) Decision
}

func (s testStageFunc) Name() string { return s.name }
func (s testStageFunc) Execute(rc *RequestContext) Decision {
	return s.fn(rc)
}

func newPipelineRequestContext(t *testing.T) *RequestContext {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	return &RequestContext{
		Request:   req,
		RequestID: "req-1",
		Facts: policy.RequestFacts{
			Identity:  "api.example.com",
			Method:    http.MethodGet,
			Path:      "/path",
			Port:      443,
			Transport: policy.TransportTLS,
		},
	}
}

func TestPipeline_RunsAllStagesInOrderOnAllow(t *testing.T) {
	var order []string
	sink := &testAuditSink{order: &order}
	p := NewPipeline([]Stage{
		testStageFunc{name: "sanitise", fn: func(*RequestContext) Decision { order = append(order, "sanitise"); return Allow() }},
		testStageFunc{name: "identity", fn: func(*RequestContext) Decision { order = append(order, "identity"); return Allow() }},
		testStageFunc{name: "inject", fn: func(*RequestContext) Decision { order = append(order, "inject"); return Allow() }},
		testStageFunc{name: "complete", fn: func(*RequestContext) Decision { order = append(order, "complete"); return Allow() }},
	}, sink)

	decision := p.Execute(context.Background(), newPipelineRequestContext(t))

	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	want := []string{"sanitise", "identity", "audit", "inject", "complete"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("execution order = %v, want %v", order, want)
	}
}

func TestPipeline_DenyShortCircuitsToAuditAndSkipsPostAuditStages(t *testing.T) {
	var order []string
	sink := &testAuditSink{order: &order}
	p := NewPipeline([]Stage{
		testStageFunc{name: "sanitise", fn: func(*RequestContext) Decision { order = append(order, "sanitise"); return Allow() }},
		testStageFunc{name: "match", fn: func(*RequestContext) Decision { order = append(order, "match"); return Deny(ReasonNoMatch, nil) }},
		testStageFunc{name: "inject", fn: func(*RequestContext) Decision { order = append(order, "inject"); return Allow() }},
	}, sink)

	decision := p.Execute(context.Background(), newPipelineRequestContext(t))

	if decision.Reason != ReasonNoMatch {
		t.Fatalf("Execute() reason = %v, want %v", decision.Reason, ReasonNoMatch)
	}
	want := []string{"sanitise", "match", "audit"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("execution order = %v, want %v", order, want)
	}
}

func TestPipeline_AuditAlwaysRunsEvenOnDeny(t *testing.T) {
	sink := &testAuditSink{}
	p := NewPipeline([]Stage{
		testStageFunc{name: "identity", fn: func(*RequestContext) Decision { return Deny(ReasonIdentityMismatch, nil) }},
		testStageFunc{name: "inject", fn: func(*RequestContext) Decision { return Allow() }},
	}, sink)

	decision := p.Execute(context.Background(), newPipelineRequestContext(t))

	if decision.Disposition() != DispositionDeny {
		t.Fatalf("Execute() disposition = %v, want deny", decision.Disposition())
	}
	if len(sink.records) != 1 {
		t.Fatalf("audit calls = %d, want 1", len(sink.records))
	}
	if sink.records[0].ev.DenyReason != ReasonIdentityMismatch {
		t.Fatalf("audit deny reason = %v, want %v", sink.records[0].ev.DenyReason, ReasonIdentityMismatch)
	}
}

func TestPipeline_ZeroValueDecisionIsDenied(t *testing.T) {
	sink := &testAuditSink{}
	p := NewPipeline([]Stage{
		testStageFunc{name: "identity", fn: func(*RequestContext) Decision { return Decision{} }},
		testStageFunc{name: "inject", fn: func(*RequestContext) Decision { return Allow() }},
	}, sink)

	decision := p.Execute(context.Background(), newPipelineRequestContext(t))

	if decision.Disposition() != DispositionDeny || decision.Reason != ReasonInternal || !decision.Fault {
		t.Fatalf("Execute() = %+v, want internal deny fault", decision)
	}
	if len(sink.records) != 1 || sink.records[0].ev.Disposition != DispositionDeny {
		t.Fatalf("audit records = %+v, want one deny record", sink.records)
	}
}

func TestPipeline_PanicBeforeAuditRecoveredAsDenyFault(t *testing.T) {
	sink := &testAuditSink{}
	p := NewPipeline([]Stage{
		testStageFunc{name: "identity", fn: func(*RequestContext) Decision { panic("boom") }},
		testStageFunc{name: "inject", fn: func(*RequestContext) Decision { return Allow() }},
	}, sink)

	decision := p.Execute(context.Background(), newPipelineRequestContext(t))

	if decision.Disposition() != DispositionDeny || decision.Reason != ReasonInternal || !decision.Fault {
		t.Fatalf("Execute() = %+v, want internal deny fault", decision)
	}
	if len(sink.records) != 1 {
		t.Fatalf("audit calls = %d, want 1", len(sink.records))
	}
}

func TestPipeline_PendingIsRewrittenToDeny(t *testing.T) {
	sink := &testAuditSink{}
	p := NewPipeline([]Stage{
		testStageFunc{name: "identity", fn: func(*RequestContext) Decision { return Pending() }},
		testStageFunc{name: "inject", fn: func(*RequestContext) Decision { return Allow() }},
	}, sink)

	decision := p.Execute(context.Background(), newPipelineRequestContext(t))

	if decision.Disposition() != DispositionDeny || decision.Reason != ReasonInternal || !decision.Fault {
		t.Fatalf("Execute() = %+v, want internal deny fault", decision)
	}
	if len(sink.records) != 1 || sink.records[0].ev.Disposition != DispositionDeny {
		t.Fatalf("audit records = %+v, want one deny record", sink.records)
	}
}

func TestPipeline_RecordsPerStageTimings(t *testing.T) {
	sink := &testAuditSink{}
	rc := newPipelineRequestContext(t)
	p := NewPipeline([]Stage{
		testStageFunc{name: "identity", fn: func(*RequestContext) Decision { time.Sleep(time.Millisecond); return Allow() }},
		testStageFunc{name: "inject", fn: func(*RequestContext) Decision { time.Sleep(time.Millisecond); return Allow() }},
	}, sink)

	decision := p.Execute(context.Background(), rc)

	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	for _, key := range []string{"identity", "inject", "audit"} {
		duration, ok := rc.Timings[key]
		if !ok {
			t.Fatalf("Timings missing key %q", key)
		}
		if duration < 0 {
			t.Fatalf("Timings[%q] = %v, want non-negative", key, duration)
		}
	}
}

func TestPipeline_AuditFailureReturnsDeny(t *testing.T) {
	sink := &testAuditSink{err: errors.New("audit down")}
	p := NewPipeline([]Stage{
		testStageFunc{name: "identity", fn: func(*RequestContext) Decision { return Allow() }},
		testStageFunc{name: "inject", fn: func(*RequestContext) Decision { return Allow() }},
	}, sink)

	decision := p.Execute(context.Background(), newPipelineRequestContext(t))

	if decision.Disposition() != DispositionDeny || decision.Reason != ReasonAuditUnavailable || !decision.Fault {
		t.Fatalf("Execute() = %+v, want audit unavailable deny fault", decision)
	}
}
