package audit_test

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

type rejectionSink struct {
	mu      sync.Mutex
	events  []pipeline.AuditEvent
	ctxs    []context.Context
	started chan struct{}
	release chan struct{}
}

func (s *rejectionSink) Record(ctx context.Context, event pipeline.AuditEvent) error {
	if s.started != nil {
		select {
		case s.started <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		<-s.release
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctxs = append(s.ctxs, ctx)
	s.events = append(s.events, event)
	return nil
}

func (s *rejectionSink) RecordCompletion(ctx context.Context, event pipeline.AuditEvent) error {
	return s.Record(ctx, event)
}

func (s *rejectionSink) snapshot() ([]context.Context, []pipeline.AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctxs := append([]context.Context(nil), s.ctxs...)
	events := append([]pipeline.AuditEvent(nil), s.events...)
	return ctxs, events
}

type transportRejectCall struct {
	class audit.RejectClass
	bound audit.BoundName
}

// rejectionMetrics is a typed MetricsRecorder test double that captures
// TransportReject calls; all other methods are no-ops.
type rejectionMetrics struct {
	mu               sync.Mutex
	transportRejects []transportRejectCall
}

func (m *rejectionMetrics) TransportReject(class audit.RejectClass, bound audit.BoundName) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transportRejects = append(m.transportRejects, transportRejectCall{class, bound})
}

func (m *rejectionMetrics) rejects() []transportRejectCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]transportRejectCall(nil), m.transportRejects...)
}

func (m *rejectionMetrics) Decisions(pipeline.Disposition, pipeline.DenyReason, audit.TransportKind, bool) {
}
func (m *rejectionMetrics) StageDuration(audit.StageName, time.Duration) {}
func (m *rejectionMetrics) LeafCacheHit()                                {}
func (m *rejectionMetrics) LeafCacheMiss()                               {}
func (m *rejectionMetrics) AuditRecord(audit.AuditRecordKind)            {}
func (m *rejectionMetrics) AuditWriteDuration(time.Duration)             {}
func (m *rejectionMetrics) AuditUnavailable(bool)                        {}
func (m *rejectionMetrics) SnapshotAge(time.Duration)                    {}
func (m *rejectionMetrics) SnapshotVersion(string)                       {}
func (m *rejectionMetrics) PolicyCompileFailure()                        {}
func (m *rejectionMetrics) PolicyStaleDeny()                             {}
func (m *rejectionMetrics) PolicyListForbidden()                         {}
func (m *rejectionMetrics) CAExpiry(time.Duration)                       {}
func (m *rejectionMetrics) TokenAcquisition(audit.ProviderID, audit.Result, audit.AcquireErrorClass) {
}
func (m *rejectionMetrics) TokenAcquisitionDuration(audit.ProviderID, time.Duration) {}
func (m *rejectionMetrics) TokenCacheHit(audit.ProviderID)                           {}
func (m *rejectionMetrics) TokenCacheMiss(audit.ProviderID)                          {}
func (m *rejectionMetrics) TokenCacheEviction(audit.ProviderID, audit.CredentialID)  {}
func (m *rejectionMetrics) TokenRefreshFailure(audit.ProviderID, audit.CredentialID) {}
func (m *rejectionMetrics) TokenBreakerState(audit.ProviderID, audit.CredentialID, audit.BreakerState) {
}
func (m *rejectionMetrics) UpstreamRequest(audit.UpstreamResult)                      {}
func (m *rejectionMetrics) AdmissionRequest(audit.WebhookName, audit.AdmissionResult) {}
func (m *rejectionMetrics) AdmissionDuration(audit.WebhookName, time.Duration)        {}
func (m *rejectionMetrics) AdmissionRejection(audit.AdmissionRule)                    {}
func (m *rejectionMetrics) InjectorCertExpiry(time.Duration)                          {}
func (m *rejectionMetrics) AdmissionPatchBytes(int)                                   {}
func (m *rejectionMetrics) CABundlePatch(audit.WebhookConfigName, audit.PatchResult)  {}
func (m *rejectionMetrics) WebhookTLSError()                                          {}
func (m *rejectionMetrics) ProxyCgroupResolutionError()                               {}

// #115
func TestRecord_TypedMetricsRecorder_CallsTransportRejectWithEnums(t *testing.T) {
	metrics := &rejectionMetrics{}
	recorder := audit.NewRejectionRecorder(nil, metrics, 1, 10*time.Millisecond, nil)

	recorder.Record(audit.Rejection{
		Class:  "resource_limit",
		Reason: pipeline.ReasonResourceLimit,
		Bound:  "max_inflight_requests",
	})

	calls := metrics.rejects()
	if len(calls) != 1 {
		t.Fatalf("TransportReject call count = %d, want 1", len(calls))
	}
	if calls[0].class != audit.RejectClassResourceLimit {
		t.Fatalf("class = %v, want RejectClassResourceLimit", calls[0].class)
	}
	if calls[0].bound != audit.BoundMaxInflightRequests {
		t.Fatalf("bound = %v, want BoundMaxInflightRequests", calls[0].bound)
	}
}

func TestNewRejectionRecorder_NilSink_ReturnsUsableRecorderOrError(t *testing.T) {
	recorder := audit.NewRejectionRecorder(nil, &rejectionMetrics{}, 1, 10*time.Millisecond, nil)
	if recorder == nil {
		t.Fatal("NewRejectionRecorder() = nil, want non-nil")
	}
	recorder.Record(audit.Rejection{})
}

func TestRecord_ValidRejection_EmitsToSink(t *testing.T) {
	sink := &rejectionSink{}
	recorder := audit.NewRejectionRecorder(sink, &rejectionMetrics{}, 1, time.Second, nil)

	recorder.Record(audit.Rejection{
		Class:     "resource_limit",
		Reason:    pipeline.ReasonResourceLimit,
		Bound:     "max_inflight_requests",
		RequestID: "req-1",
		ConnID:    "conn-1",
		Port:      443,
		Method:    "GET",
		Path:      "/v1/models",
	})

	deadline := time.After(5 * time.Second)
	for {
		_, events := sink.snapshot()
		if len(events) == 1 {
			event := events[0]
			if event.RequestID != "req-1" {
				t.Fatalf("RequestID = %q, want %q", event.RequestID, "req-1")
			}
			if event.Method != "GET" {
				t.Fatalf("Method = %q, want %q", event.Method, "GET")
			}
			if event.Path != "/v1/models" {
				t.Fatalf("Path = %q, want %q", event.Path, "/v1/models")
			}
			if event.Port != 443 {
				t.Fatalf("Port = %d, want 443", event.Port)
			}
			if event.Disposition != pipeline.DispositionDeny {
				t.Fatalf("Disposition = %v, want %v", event.Disposition, pipeline.DispositionDeny)
			}
			if event.DenyReason != pipeline.ReasonResourceLimit {
				t.Fatalf("DenyReason = %v, want %v", event.DenyReason, pipeline.ReasonResourceLimit)
			}
			if event.CredentialID != "none" {
				t.Fatalf("CredentialID = %q, want %q", event.CredentialID, "none")
			}
			return
		}

		select {
		case <-deadline:
			t.Fatal("timed out waiting for rejection audit event")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestRecord_CallerContextCancelledBeforeSinkCompletes_StillReachesSink(t *testing.T) {
	sink := &rejectionSink{}
	recorder := audit.NewRejectionRecorder(sink, &rejectionMetrics{}, 1, time.Second, nil)

	ctx, cancel := context.WithCancel(context.Background())
	recorder.Record(audit.Rejection{Class: "unsupported_protocol", Reason: pipeline.ReasonUnsupportedProtocol})
	cancel()
	if err := ctx.Err(); err == nil {
		t.Fatal("ctx.Err() = nil, want canceled context")
	}

	deadline := time.After(5 * time.Second)
	for {
		_, events := sink.snapshot()
		if len(events) == 1 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for detached rejection audit")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestRecord_NeverBlocksCallerOnSlowSink_ReturnsPromptly(t *testing.T) {
	sink := &rejectionSink{release: make(chan struct{})}
	recorder := audit.NewRejectionRecorder(sink, &rejectionMetrics{}, 1, time.Second, nil)

	start := time.Now()
	recorder.Record(audit.Rejection{Class: "unsupported_protocol", Reason: pipeline.ReasonUnsupportedProtocol})
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Record() took %v, want <= 100ms", elapsed)
	}

	close(sink.release)
}

func TestRecord_ConcurrencyBoundExceeded_ShedsExcessAndIncrementsDropped(t *testing.T) {
	sink := &rejectionSink{started: make(chan struct{}, 1), release: make(chan struct{})}
	var emergencyCalls atomic.Uint64
	recorder := audit.NewRejectionRecorder(sink, &rejectionMetrics{}, 1, time.Second, func(string, ...any) {
		emergencyCalls.Add(1)
	})

	recorder.Record(audit.Rejection{Class: "resource_limit", Reason: pipeline.ReasonResourceLimit, Bound: "max_inflight_requests"})
	<-sink.started

	recorder.Record(audit.Rejection{Class: "resource_limit", Reason: pipeline.ReasonResourceLimit, Bound: "max_inflight_requests"})

	if got := recorder.Dropped(); got != 1 {
		t.Fatalf("Dropped() = %d, want 1", got)
	}
	if got := emergencyCalls.Load(); got != 1 {
		t.Fatalf("emergency call count = %d, want 1", got)
	}

	close(sink.release)
}

func TestRecord_SinkStallsBeyondTimeout_RecordAbandonedNotBlockedForever(t *testing.T) {
	sink := &rejectionSink{release: make(chan struct{})}
	recorder := audit.NewRejectionRecorder(sink, &rejectionMetrics{}, 1, 20*time.Millisecond, nil)

	recorder.Record(audit.Rejection{Class: "unsupported_protocol", Reason: pipeline.ReasonUnsupportedProtocol})
	time.Sleep(100 * time.Millisecond)

	close(sink.release)
	recorder.Record(audit.Rejection{Class: "unsupported_protocol", Reason: pipeline.ReasonUnsupportedProtocol})

	deadline := time.After(5 * time.Second)
	for {
		_, events := sink.snapshot()
		if len(events) >= 1 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for post-timeout rejection audit")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestDropped_InitialState_ReturnsZero(t *testing.T) {
	recorder := audit.NewRejectionRecorder(&rejectionSink{}, &rejectionMetrics{}, 1, time.Second, nil)
	if got := recorder.Dropped(); got != 0 {
		t.Fatalf("Dropped() = %d, want 0", got)
	}
}

func TestDropped_AfterShedRecords_ReturnsAccurateCumulativeCount(t *testing.T) {
	sink := &rejectionSink{started: make(chan struct{}, 1), release: make(chan struct{})}
	recorder := audit.NewRejectionRecorder(sink, &rejectionMetrics{}, 1, time.Second, nil)

	recorder.Record(audit.Rejection{Class: "resource_limit", Reason: pipeline.ReasonResourceLimit, Bound: "max_inflight_requests"})
	<-sink.started
	recorder.Record(audit.Rejection{Class: "resource_limit", Reason: pipeline.ReasonResourceLimit, Bound: "max_inflight_requests"})
	recorder.Record(audit.Rejection{Class: "resource_limit", Reason: pipeline.ReasonResourceLimit, Bound: "max_inflight_requests"})

	if got := recorder.Dropped(); got != 2 {
		t.Fatalf("Dropped() = %d, want 2", got)
	}

	close(sink.release)
}

// #116 — shedding reconcile under the typed recorder, wiring the emergency
// callback through EmergencyChannel.Signalf: a shed record drops, Dropped
// increments, and the emergency channel fires all three §3.1 signals.
func TestRecord_SlotsExhausted_DropsAndEmergencySignals(t *testing.T) {
	sink := &rejectionSink{started: make(chan struct{}, 1), release: make(chan struct{})}
	var stderr bytes.Buffer
	ecMetrics := newEmergencyMetrics()
	readiness := &recordingReadiness{}
	ec := audit.NewEmergencyChannel(&stderr, ecMetrics, readiness)

	recorder := audit.NewRejectionRecorder(sink, newEmergencyMetrics(), 1, time.Second, ec.Signalf)

	// Occupy the single slot, then submit an excess record that must shed.
	recorder.Record(audit.Rejection{Class: "resource_limit", Reason: pipeline.ReasonResourceLimit, Bound: "max_inflight_requests"})
	<-sink.started
	recorder.Record(audit.Rejection{Class: "resource_limit", Reason: pipeline.ReasonResourceLimit, Bound: "max_inflight_requests"})

	if got := recorder.Dropped(); got != 1 {
		t.Fatalf("Dropped() = %d, want 1", got)
	}
	if stderr.Len() == 0 {
		t.Fatal("emergency stderr line not written on shed")
	}
	if last, ok := ecMetrics.lastUnavailable(); !ok || last != true {
		t.Fatalf("AuditUnavailable = %v, want last=true on shed", ecMetrics.unavailableCalls())
	}
	if last, ok := readiness.last(); !ok || last != false {
		t.Fatalf("readiness = %v, want last=false on shed", readiness.snapshot())
	}

	close(sink.release)
}

// #117
func TestRecord_RejectionAlwaysDeny_NeverAllow(t *testing.T) {
	sink := &rejectionSink{}
	recorder := audit.NewRejectionRecorder(sink, &rejectionMetrics{}, 1, time.Second, nil)

	recorder.Record(audit.Rejection{
		Class:     "unsupported_protocol",
		Reason:    pipeline.ReasonUnsupportedProtocol,
		RequestID: "req-deny",
	})

	deadline := time.After(5 * time.Second)
	for {
		_, events := sink.snapshot()
		if len(events) == 1 {
			ev := events[0]
			if ev.Disposition != pipeline.DispositionDeny {
				t.Fatalf("Disposition = %v, want DispositionDeny — a rejection never appears as an allow", ev.Disposition)
			}
			if ev.CredentialID != "none" {
				t.Fatalf("CredentialID = %q, want \"none\"", ev.CredentialID)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for rejection audit event")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

// #118
func TestDropped_CountsShedRecords_Monotonic(t *testing.T) {
	sink := &rejectionSink{started: make(chan struct{}, 1), release: make(chan struct{})}
	recorder := audit.NewRejectionRecorder(sink, &rejectionMetrics{}, 1, time.Second, nil)

	if got := recorder.Dropped(); got != 0 {
		t.Fatalf("initial Dropped() = %d, want 0", got)
	}

	// Occupy the slot, then shed several records and confirm Dropped only rises.
	recorder.Record(audit.Rejection{Class: "resource_limit", Reason: pipeline.ReasonResourceLimit, Bound: "max_inflight_requests"})
	<-sink.started

	prev := recorder.Dropped()
	for i := 0; i < 3; i++ {
		recorder.Record(audit.Rejection{Class: "resource_limit", Reason: pipeline.ReasonResourceLimit, Bound: "max_inflight_requests"})
		got := recorder.Dropped()
		if got < prev {
			t.Fatalf("Dropped() = %d, went below previous %d — must be monotonic", got, prev)
		}
		prev = got
	}
	if prev != 3 {
		t.Fatalf("Dropped() = %d, want 3 after three sheds", prev)
	}

	close(sink.release)
}
