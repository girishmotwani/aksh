package audit

import (
	"context"
	"strings"
	"testing"
	"time"
)

// #23
func TestClose_FlushesPendingRecords_BeforeReturn(t *testing.T) {
	w := &bsWriter{}
	// Long interval so the record stays buffered until Close drives the flush.
	s := newTestSink(t, w, 16, 10*time.Second, nil)

	if err := s.RecordCompletion(context.Background(), sampleCompletion("pending-23")); err != nil {
		t.Fatalf("RecordCompletion() error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !strings.Contains(string(w.bytesWritten()), "pending-23") {
		t.Fatalf("Close did not flush pending record before returning: %q", w.bytesWritten())
	}
}

// #24
func TestClose_CalledTwice_Idempotent(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)

	if err := s.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

// #25
func TestFlush_TimerElapsed_WritesBatchOnce(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 10*time.Millisecond, nil)
	defer s.Close()

	if err := s.RecordCompletion(context.Background(), sampleCompletion("req-25")); err != nil {
		t.Fatalf("RecordCompletion() error = %v", err)
	}
	// Span several intervals; the accumulated batch flushes exactly once and
	// subsequent empty ticks are no-ops.
	time.Sleep(80 * time.Millisecond)
	if got := w.writeCount(); got != 1 {
		t.Fatalf("write count = %d, want exactly 1 per elapse", got)
	}
}
