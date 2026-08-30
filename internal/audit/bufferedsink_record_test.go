package audit

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

func newTestSink(t *testing.T, w *bsWriter, bufSize int, flush time.Duration, m *bsMetrics) *BufferedSink {
	t.Helper()
	if m == nil {
		m = &bsMetrics{}
	}
	s, err := NewBufferedSink(w, bufSize, flush, &bsClock{}, NewAuditRecordEncoder(), m)
	if err != nil {
		t.Fatalf("NewBufferedSink() error = %v", err)
	}
	return s
}

// #5
func TestRecord_CompletedFlush_ReturnsNilAfterDurableWrite(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	if err := s.Record(context.Background(), sampleEvent("req-5")); err != nil {
		t.Fatalf("Record() error = %v, want nil", err)
	}
	if !strings.Contains(string(w.bytesWritten()), "req-5") {
		t.Fatalf("writer did not observe the durable record: %q", w.bytesWritten())
	}
}

// #6
func TestRecord_ReturnedNil_MeansRecordLeftAddressSpace(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	if err := s.Record(context.Background(), sampleEvent("req-6")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	out := string(w.bytesWritten())
	if !strings.Contains(out, "req-6") || !strings.HasSuffix(out, "\n") {
		t.Fatalf("full record not observed on writer: %q", out)
	}
	// Durable == completed write(2); the pipe writer offers no Sync, so no
	// fsync is attempted (ADR-S6-01).
	if _, ok := interface{}(w).(interface{ Sync() error }); ok {
		t.Fatal("test writer unexpectedly exposes Sync; cannot prove no-fsync")
	}
}

// #7
func TestRecord_ConcurrentRequests_ShareSingleFlush(t *testing.T) {
	const n = 8
	w := &bsWriter{}
	// Long interval so the timer never fires; the full-batch trigger (bufSize
	// == n) coalesces all concurrent records into a single flush/syscall.
	s := newTestSink(t, w, n, 10*time.Second, nil)
	defer s.Close()

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Record(context.Background(), sampleEvent("req-7"))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Record[%d] error = %v", i, err)
		}
	}
	if got := w.writeCount(); got != 1 {
		t.Fatalf("write count = %d, want 1 (single coalesced flush)", got)
	}
}

// #8
func TestRecord_ShortFlushInterval_FlushesWithoutFullBuffer(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 64, 5*time.Millisecond, nil)
	defer s.Close()

	if err := s.Record(context.Background(), sampleEvent("req-8")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if w.writeCount() < 1 {
		t.Fatal("record was not flushed on interval without a full buffer")
	}
}

// #9
func TestRecord_BufferFull_BlocksBrieflyThenTerminalFailure(t *testing.T) {
	w := &bsWriter{gate: make(chan struct{})}
	s := newTestSink(t, w, 1, 10*time.Second, nil)
	defer func() {
		close(w.gate)
		s.Close()
	}()

	// One record is flushed and blocks in write; a second occupies the queue.
	go s.Record(context.Background(), sampleEvent("req-9a"))
	go s.Record(context.Background(), sampleEvent("req-9b"))
	time.Sleep(100 * time.Millisecond)

	err := s.Record(context.Background(), sampleEvent("req-9c"))
	if !errors.Is(err, ErrAuditBufferFull) {
		t.Fatalf("Record() error = %v, want ErrAuditBufferFull", err)
	}
}

// #10
func TestRecord_BufferFull_DoesNotGrowMemory(t *testing.T) {
	w := &bsWriter{gate: make(chan struct{})}
	s := newTestSink(t, w, 2, 10*time.Second, nil)
	defer func() {
		close(w.gate)
		s.Close()
	}()

	// Fire far more callers than the bounded buffer can hold. Records that
	// admit block on durability (bounded by their deadline); the excess is
	// denied with a terminal audit failure rather than growing the queue.
	const n = 64
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			results <- s.Record(ctx, sampleEvent("flood"))
		}()
	}

	denied := 0
	for i := 0; i < n; i++ {
		if errors.Is(<-results, ErrAuditBufferFull) {
			denied++
		}
		if cap(s.queue) != 2 {
			t.Fatalf("queue cap = %d, want bounded at 2", cap(s.queue))
		}
	}
	if denied == 0 {
		t.Fatal("expected sustained overload to be denied, not queued unbounded")
	}
}

// #11
func TestRecord_ContextAlreadyCancelled_ReturnsError(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Record(ctx, sampleEvent("req-11")); err == nil {
		t.Fatal("Record(cancelled ctx) error = nil, want non-nil")
	}
	time.Sleep(20 * time.Millisecond)
	if w.writeCount() != 0 {
		t.Fatalf("write count = %d, want 0 (nothing written on cancelled ctx)", w.writeCount())
	}
}

// #12
func TestRecord_ContextDeadlineExceededDuringWrite_TerminalFailure(t *testing.T) {
	w := &bsWriter{gate: make(chan struct{})}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer func() {
		close(w.gate)
		s.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := s.Record(ctx, sampleEvent("req-12"))
	if err == nil {
		t.Fatal("Record() error = nil, want terminal failure on deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Record() error = %v, want context.DeadlineExceeded", err)
	}
}

// #13
func TestRecord_WriteSyscallError_ReturnsTerminalFailure(t *testing.T) {
	sentinel := errors.New("stdout blocked")
	w := &bsWriter{err: sentinel}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	err := s.Record(context.Background(), sampleEvent("req-13"))
	if !errors.Is(err, sentinel) {
		t.Fatalf("Record() error = %v, want wrapped write(2) error", err)
	}
}

// #14
func TestRecord_EmptyRequestID_StillRecordsDegraded(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	if err := s.Record(context.Background(), sampleEvent("")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	out := string(w.bytesWritten())
	if !strings.Contains(out, `"requestId":""`) {
		t.Fatalf("degraded record missing empty requestId field: %q", out)
	}
}

// #15
func TestRecord_DecisionKind_BlocksUntilDurableBeforeCredential(t *testing.T) {
	w := &bsWriter{gate: make(chan struct{})}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()

	result := make(chan error, 1)
	go func() { result <- s.Record(context.Background(), sampleEvent("req-15")) }()

	// The write is gated; the decision caller must still be blocked (durable
	// before returning, INV-6).
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-result:
		t.Fatalf("Record returned before durable write: err=%v", err)
	default:
	}

	w.gate <- struct{}{}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Record() error = %v after durable write", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Record did not return after the write completed")
	}
	if !strings.Contains(string(w.bytesWritten()), "req-15") {
		t.Fatal("record not durable after Record returned")
	}
}

// #16
func TestRecord_SuccessAfterFailure_ClearsUnavailableState(t *testing.T) {
	m := &bsMetrics{}
	w := &bsWriter{err: errors.New("stdout blocked")}
	s := newTestSink(t, w, 16, 5*time.Millisecond, m)
	defer s.Close()

	if err := s.Record(context.Background(), sampleEvent("fail")); err == nil {
		t.Fatal("expected terminal failure on write error")
	}
	w.setErr(nil)
	if err := s.Record(context.Background(), sampleEvent("ok")); err != nil {
		t.Fatalf("Record() after recovery error = %v", err)
	}

	calls := m.unavailableCalls()
	if len(calls) < 2 || calls[0] != true || calls[len(calls)-1] != false {
		t.Fatalf("AuditUnavailable calls = %v, want [true ... false] recovery transition", calls)
	}
}

// #17
func TestRecord_EventHasNoTokenField_StructurallyRedacted(t *testing.T) {
	rt := reflect.TypeOf(pipeline.AuditEvent{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		if strings.Contains(name, "token") || strings.Contains(name, "secret") {
			t.Fatalf("AuditEvent has a credential-bearing field %q (INV-5 violation)", rt.Field(i).Name)
		}
	}

	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	defer s.Close()
	if err := s.Record(context.Background(), sampleEvent("req-17")); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	out := string(w.bytesWritten())
	for _, sentinel := range []string{"eyJhbGciOi", "SECRET-TOKEN-123", "Bearer "} {
		if strings.Contains(out, sentinel) {
			t.Fatalf("emitted record leaked a token sentinel %q: %q", sentinel, out)
		}
	}
}

// #18
func TestRecord_AfterClose_ReturnsError(t *testing.T) {
	w := &bsWriter{}
	s := newTestSink(t, w, 16, 5*time.Millisecond, nil)
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := s.Record(context.Background(), sampleEvent("req-18")); !errors.Is(err, ErrSinkClosed) {
		t.Fatalf("Record after Close error = %v, want ErrSinkClosed", err)
	}
}
