package listener

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// countingHandler is a ConnHandler double that counts how many times Handle
// is invoked, used to prove a rejected connection never reaches the handler.
type countingHandler struct {
	mu sync.Mutex
	n  int
}

func (h *countingHandler) Handle(ctx context.Context, cc *ConnContext) error {
	h.mu.Lock()
	h.n++
	h.mu.Unlock()
	return nil
}

func (h *countingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func validRateOptions() Options {
	o := DefaultOptions()
	o.Handler = recordingHandler{}
	o.Metrics = &recordingMetrics{}
	return o
}

func (m *recordingMetrics) countDecision(want string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := 0
	for _, d := range m.decisions {
		if d == want {
			c++
		}
	}
	return c
}

// ---- Options validation (#18-21, #37, #38) ----

func TestListenerDefaultOptions_HandshakeRate_Is50Burst100(t *testing.T) {
	o := DefaultOptions()
	if o.HandshakeRatePerSecond != 50 {
		t.Fatalf("HandshakeRatePerSecond = %d, want 50", o.HandshakeRatePerSecond)
	}
	if o.HandshakeRateBurst != 100 {
		t.Fatalf("HandshakeRateBurst = %d, want 100", o.HandshakeRateBurst)
	}
}

func TestListenerValidate_HandshakeRateZero_ReturnsError(t *testing.T) {
	o := validRateOptions()
	o.HandshakeRatePerSecond = 0
	if err := o.Validate(); err == nil {
		t.Fatal("Validate() error = nil for HandshakeRatePerSecond=0, want non-nil")
	}
}

func TestListenerValidate_HandshakeBurstNegative_ReturnsError(t *testing.T) {
	o := validRateOptions()
	o.HandshakeRateBurst = -1
	if err := o.Validate(); err == nil {
		t.Fatal("Validate() error = nil for HandshakeRateBurst=-1, want non-nil")
	}
}

func TestListenerValidate_CustomPositiveRateAndBurst_ReturnsNil(t *testing.T) {
	o := validRateOptions()
	o.HandshakeRatePerSecond = 200
	o.HandshakeRateBurst = 500
	if err := o.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestListenerValidate_HandshakeRateNegative_ReturnsError(t *testing.T) {
	o := validRateOptions()
	o.HandshakeRatePerSecond = -5
	if err := o.Validate(); err == nil {
		t.Fatal("Validate() error = nil for HandshakeRatePerSecond=-5, want non-nil")
	}
}

func TestListenerValidate_HandshakeBurstZero_ReturnsError(t *testing.T) {
	o := validRateOptions()
	o.HandshakeRateBurst = 0
	if err := o.Validate(); err == nil {
		t.Fatal("Validate() error = nil for HandshakeRateBurst=0, want non-nil")
	}
}

// ---- Handshake limiter at accept path (#22-26, #33) ----

func newRateListener(handler ConnHandler, metrics *recordingMetrics, limiter *rate.Limiter, semCap int) *Listener {
	return &Listener{
		handler:          handler,
		metrics:          metrics,
		log:              discardLogger(),
		sem:              make(chan struct{}, semCap),
		handshakeLimiter: limiter,
	}
}

func TestHandshakeLimiter_BurstWithinLimit_AllConnectionsAccepted(t *testing.T) {
	const burst = 5
	handler := &countingHandler{}
	metrics := &recordingMetrics{}
	// rate 1/s so no refill can add tokens during this test's brief window.
	l := newRateListener(handler, metrics, rate.NewLimiter(rate.Limit(1), burst), burst)

	for i := 0; i < burst; i++ {
		l.dispatch(context.Background(), closableConn{}, time.Now())
	}
	l.wg.Wait()

	if handler.count() != burst {
		t.Fatalf("handler invocations = %d, want %d", handler.count(), burst)
	}
	if got := metrics.countDecision("deny/resource_limit"); got != 0 {
		t.Fatalf("handshake_rate rejections = %d, want 0 within burst", got)
	}
}

func TestHandshakeLimiter_BurstExhausted_NextConnectionClosedBeforeHandler(t *testing.T) {
	handler := &countingHandler{}
	metrics := &recordingMetrics{}
	limiter := rate.NewLimiter(rate.Limit(1), 1)
	if !limiter.Allow() {
		t.Fatal("precondition: first token should be available")
	}
	l := newRateListener(handler, metrics, limiter, 4)

	l.dispatch(context.Background(), closableConn{}, time.Now())

	if handler.count() != 0 {
		t.Fatalf("handler invocations = %d, want 0 (rejected before handler)", handler.count())
	}
}

func TestHandshakeLimiter_RejectionRecordsMetric(t *testing.T) {
	handler := &countingHandler{}
	metrics := &recordingMetrics{}
	limiter := rate.NewLimiter(rate.Limit(1), 1)
	limiter.Allow() // exhaust the single burst token
	l := newRateListener(handler, metrics, limiter, 4)

	l.dispatch(context.Background(), closableConn{}, time.Now())

	if got := metrics.countDecision("deny/resource_limit"); got != 1 {
		t.Fatalf("RecordDecision(rejected, resource_limit:handshake_rate) count = %d, want 1", got)
	}
}

func TestHandshakeLimiter_UsesNonBlockingAllow_DoesNotBlockAcceptLoop(t *testing.T) {
	handler := &countingHandler{}
	metrics := &recordingMetrics{}
	limiter := rate.NewLimiter(rate.Limit(1), 1)
	limiter.Allow() // saturate; a blocking Wait would stall ~1s for the next token
	l := newRateListener(handler, metrics, limiter, 4)

	start := time.Now()
	l.dispatch(context.Background(), closableConn{}, time.Now())
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("dispatch under saturated limiter took %v, want prompt return (non-blocking Allow)", elapsed)
	}
}

func TestHandshakeLimiter_TokensRefillOverTime_AcceptsAfterWait(t *testing.T) {
	// Drive the limiter with an injected clock rather than a real sleep to
	// avoid wall-clock flakiness: rate 10/s => one token every 100ms.
	limiter := rate.NewLimiter(rate.Limit(10), 1)
	t0 := time.Now()
	if !limiter.AllowN(t0, 1) {
		t.Fatal("first token should be immediately available")
	}
	if limiter.AllowN(t0, 1) {
		t.Fatal("second token should be unavailable at the same instant (burst=1)")
	}
	if !limiter.AllowN(t0.Add(100*time.Millisecond), 1) {
		t.Fatal("a token should be available exactly at the 100ms refill boundary")
	}
}

func TestHandshakeLimiter_ConcurrentDispatch_NoRace(t *testing.T) {
	const goroutines = 64
	handler := &countingHandler{}
	metrics := &recordingMetrics{}
	// Mixed accept/reject: burst below goroutine count so both paths run.
	l := newRateListener(handler, metrics, rate.NewLimiter(rate.Limit(1000), 16), goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			l.dispatch(context.Background(), closableConn{}, time.Now())
		}()
	}
	wg.Wait()
	l.wg.Wait()
}
