package audit

import (
	"testing"
	"time"
)

// #1
func TestNewBufferedSink_NilWriter_ReturnsError(t *testing.T) {
	s, err := NewBufferedSink(nil, 16, 5*time.Millisecond, &bsClock{}, NewAuditRecordEncoder(), &bsMetrics{})
	if err == nil {
		t.Fatal("NewBufferedSink(nil writer) error = nil, want non-nil")
	}
	if s != nil {
		t.Fatalf("NewBufferedSink(nil writer) sink = %v, want nil", s)
	}
}

// #2
func TestNewBufferedSink_ZeroBufferSize_AppliesDefaultBound(t *testing.T) {
	w := &bsWriter{}
	s, err := NewBufferedSink(w, 0, 5*time.Millisecond, &bsClock{}, NewAuditRecordEncoder(), &bsMetrics{})
	if err != nil {
		t.Fatalf("NewBufferedSink() error = %v", err)
	}
	defer s.Close()
	if s.bufSize <= 0 {
		t.Fatalf("bufSize = %d, want clamped to a positive bounded default", s.bufSize)
	}
	if s.bufSize != defaultBufferSize {
		t.Fatalf("bufSize = %d, want default %d", s.bufSize, defaultBufferSize)
	}
}

// #3
func TestNewBufferedSink_ZeroFlushInterval_AppliesDefault(t *testing.T) {
	w := &bsWriter{}
	s, err := NewBufferedSink(w, 16, 0, &bsClock{}, NewAuditRecordEncoder(), &bsMetrics{})
	if err != nil {
		t.Fatalf("NewBufferedSink() error = %v", err)
	}
	defer s.Close()
	if s.interval <= 0 {
		t.Fatalf("interval = %v, want clamped to a positive default", s.interval)
	}
	if s.interval != defaultFlushInterval {
		t.Fatalf("interval = %v, want default %v", s.interval, defaultFlushInterval)
	}
}

// #4
func TestNewBufferedSink_NilClock_DefaultsToTimeNow(t *testing.T) {
	w := &bsWriter{}
	s, err := NewBufferedSink(w, 16, 5*time.Millisecond, nil, NewAuditRecordEncoder(), &bsMetrics{})
	if err != nil {
		t.Fatalf("NewBufferedSink() error = %v", err)
	}
	defer s.Close()
	if s.clock == nil {
		t.Fatal("clock = nil, want a default time.Now-backed clock")
	}
	got := s.clock.Now()
	if delta := time.Since(got); delta < 0 || delta > time.Minute {
		t.Fatalf("clock.Now() = %v, want ~time.Now()", got)
	}
}
