package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

func sampleCompletion(requestID string) pipeline.AuditEvent {
	ev := sampleEvent(requestID)
	ev.CompletionStatus = 200
	ev.CompletionBytes = 4096
	ev.CompletionDuration = 1500 * time.Microsecond
	return ev
}

// #19
func TestRecordCompletion_BestEffort_DoesNotBlockOnFlush(t *testing.T) {
	w := &bsWriter{gate: make(chan struct{})}
	s := newTestSink(t, w, 16, 10*time.Second, nil)
	defer func() {
		close(w.gate)
		s.Close()
	}()

	done := make(chan error, 1)
	go func() { done <- s.RecordCompletion(context.Background(), sampleCompletion("req-19")) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RecordCompletion() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("RecordCompletion blocked on the flush; must be best-effort/non-blocking")
	}
}

// #20
func TestRecordCompletion_WriteFailure_DoesNotDeny(t *testing.T) {
	w := &bsWriter{err: context.DeadlineExceeded}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	if err := s.RecordCompletion(context.Background(), sampleCompletion("req-20")); err != nil {
		t.Fatalf("RecordCompletion() error = %v, want nil (completion failure is never a denial)", err)
	}
	// Give the writer time to attempt (and fail) the write; still no denial.
	time.Sleep(20 * time.Millisecond)
}

// #21
func TestRecordCompletion_CarriesRequestIdStatusBytesDuration(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	if err := s.RecordCompletion(context.Background(), sampleCompletion("req-21")); err != nil {
		t.Fatalf("RecordCompletion() error = %v", err)
	}
	s.Flush()
	out := string(w.bytesWritten())
	for _, want := range []string{`"requestId":"req-21"`, `"status":200`, `"bytes":4096`, `"duration_us":1500`} {
		if !strings.Contains(out, want) {
			t.Fatalf("completion record missing %s: %q", want, out)
		}
	}
}

// #22
func TestRecordCompletion_LostRecord_LosesDetailNotEvidence(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	// The decision record is durably written and its caller has returned.
	if err := s.Record(context.Background(), sampleEvent("decision-22")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	decisionBytes := string(w.bytesWritten())
	if !strings.Contains(decisionBytes, "decision-22") {
		t.Fatal("decision evidence not durable")
	}

	// A subsequent completion write fails; it must not retroactively deny.
	w.setErr(context.DeadlineExceeded)
	if err := s.RecordCompletion(context.Background(), sampleCompletion("completion-22")); err != nil {
		t.Fatalf("RecordCompletion() error = %v, want nil despite lost detail", err)
	}
	time.Sleep(20 * time.Millisecond)

	// The already-returned decision is unaffected: its evidence remains.
	if !strings.Contains(string(w.bytesWritten()), "decision-22") {
		t.Fatal("losing completion detail must not lose decision evidence")
	}
}
