//go:build linux

package capture

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
)

// Group A platform-neutral Handle tests (UT spec §3). These construct a Handle
// (or a partially built one) directly and drive signalAttachLoss through the
// seam, so none of them require a live kernel.

// #2
func TestLoadAndAttach_NilOptions_ReturnsErrMissingOptions(t *testing.T) {
	h, err := LoadAndAttach(nil)
	if !errors.Is(err, ErrMissingOptions) {
		t.Fatalf("LoadAndAttach(nil) error = %v, want ErrMissingOptions", err)
	}
	if h != nil {
		t.Fatalf("LoadAndAttach(nil) handle = %v, want nil", h)
	}
}

// #3
func TestLoadAndAttach_InvalidOptions_ReturnsValidationError(t *testing.T) {
	opts := DefaultOptions()
	opts.PodPath = "/sys/fs/cgroup/pod"
	opts.Metrics = audit.NopMetricsRecorder{}
	opts.ProxyUID = 0 // fails Options.Validate

	h, err := LoadAndAttach(&opts)
	if err == nil {
		t.Fatalf("LoadAndAttach() error = nil, want a validation error")
	}
	if !errors.Is(err, ErrInvalidProxyUID) {
		t.Fatalf("LoadAndAttach() error = %v, want ErrInvalidProxyUID", err)
	}
	if h != nil {
		t.Fatalf("LoadAndAttach() handle = %v, want nil", h)
	}
}

// #4
func TestLoadAndAttach_EmptyPodPath_ReturnsErrMissingPodPath(t *testing.T) {
	opts := DefaultOptions()
	opts.PodPath = ""
	opts.Metrics = audit.NopMetricsRecorder{}

	h, err := LoadAndAttach(&opts)
	if !errors.Is(err, ErrMissingPodPath) {
		t.Fatalf("LoadAndAttach() error = %v, want ErrMissingPodPath", err)
	}
	if h != nil {
		t.Fatalf("LoadAndAttach() handle = %v, want nil", h)
	}
}

// AttachLost (S5 predicate) — linux latch behaviour: false before loss, true
// after signalAttachLoss fires.
func TestAttachLost_BeforeAndAfterLoss_ReflectsLatch(t *testing.T) {
	h := &Handle{lossCh: make(chan error, 1)}
	if h.AttachLost() {
		t.Fatalf("AttachLost() before loss = true, want false")
	}
	h.signalAttachLoss(errAttachLost)
	if !h.AttachLost() {
		t.Fatalf("AttachLost() after loss = false, want true")
	}
}

// #14
func TestClose_CalledTwice_IsIdempotent(t *testing.T) {
	var teardowns int32
	st := &loaderState{opts: &Options{}, cancel: func() { atomic.AddInt32(&teardowns, 1) }}
	h := &Handle{st: st, lossCh: make(chan error, 1)}

	if err := h.Close(); err != nil {
		t.Fatalf("first Close() error = %v, want nil", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil", err)
	}
	if got := atomic.LoadInt32(&teardowns); got != 1 {
		t.Fatalf("teardown ran %d times, want exactly 1", got)
	}
}

// #15
func TestClose_OnPartiallyBuiltHandle_DoesNotPanic(t *testing.T) {
	h := &Handle{} // st, lossCh and pairMap all zero-valued
	if err := h.Close(); err != nil {
		t.Fatalf("Close() on partial handle error = %v, want nil", err)
	}
	if pm := h.PairMap(); pm != nil {
		t.Fatalf("PairMap() on partial handle = %v, want nil", pm)
	}
	if ai := h.AttachInfo(); ai.CgroupID != 0 || len(ai.ProgIDs) != 0 || len(ai.PinPaths) != 0 {
		t.Fatalf("AttachInfo() on partial handle = %+v, want zero value", ai)
	}
}

// #18
func TestOnAttachLoss_RegisterAfterLoss_DeliversImmediately(t *testing.T) {
	h := &Handle{st: &loaderState{opts: &Options{}}, lossCh: make(chan error, 1)}
	h.signalAttachLoss(errAttachLost)

	got := make(chan error, 1)
	h.OnAttachLoss(func(e error) { got <- e })

	select {
	case e := <-got:
		if !errors.Is(e, errAttachLost) {
			t.Fatalf("callback error = %v, want errAttachLost", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("callback registered after loss was not delivered immediately")
	}
}

// #20
func TestOnAttachLoss_NilCallbackOrNeverRegistered_LossDoesNotPanic(t *testing.T) {
	t.Run("nil callback", func(t *testing.T) {
		h := &Handle{lossCh: make(chan error, 1)}
		h.OnAttachLoss(nil)
		h.signalAttachLoss(errAttachLost) // must not panic
	})
	t.Run("never registered", func(t *testing.T) {
		h := &Handle{lossCh: make(chan error, 1)}
		h.signalAttachLoss(errAttachLost) // must not panic
	})
}

// #21
func TestOnAttachLoss_Callback_NonBlockingContractOnlyCancelsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &Handle{lossCh: make(chan error, 1)}
	h.OnAttachLoss(func(error) { cancel() })
	h.signalAttachLoss(errAttachLost)

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("non-blocking callback did not cancel the context")
	}
}

// #23
func TestAttachLoss_Buffered1_SendDoesNotBlockWithoutReceiver(t *testing.T) {
	h := &Handle{lossCh: make(chan error, 1)}
	done := make(chan struct{})
	go func() {
		h.signalAttachLoss(errAttachLost) // no receiver draining lossCh
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("signalAttachLoss blocked on a buffered(1) channel without a receiver")
	}
	select {
	case e := <-h.AttachLoss():
		if !errors.Is(e, errAttachLost) {
			t.Fatalf("AttachLoss() delivered %v, want errAttachLost", e)
		}
	default:
		t.Fatalf("AttachLoss() had no buffered value")
	}
}

// #24
func TestClose_ConcurrentWithOnAttachLoss_ResolvesViaSyncOnce(t *testing.T) {
	var teardowns int32
	st := &loaderState{opts: &Options{}, cancel: func() { atomic.AddInt32(&teardowns, 1) }}
	h := &Handle{st: st, lossCh: make(chan error, 1)}
	// Drain pattern: the attach-loss callback triggers Close.
	h.OnAttachLoss(func(error) { _ = h.Close() })

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); h.signalAttachLoss(errAttachLost) }()
	go func() { defer wg.Done(); _ = h.Close() }()
	wg.Wait()

	if got := atomic.LoadInt32(&teardowns); got != 1 {
		t.Fatalf("teardown ran %d times, want exactly 1", got)
	}
}

// #25
func TestClose_ConcurrentCalls_ExactlyOneTeardown(t *testing.T) {
	var teardowns int32
	st := &loaderState{opts: &Options{}, cancel: func() { atomic.AddInt32(&teardowns, 1) }}
	h := &Handle{st: st, lossCh: make(chan error, 1)}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = h.Close() }()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&teardowns); got != 1 {
		t.Fatalf("teardown ran %d times, want exactly 1", got)
	}
}
