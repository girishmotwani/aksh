package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/runtime"
)

// recorder is a goroutine-safe ordered event log for the lifecycle tests.
type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(e string) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	copy(out, r.events)
	return out
}

func (r *recorder) index(e string) int {
	for i, ev := range r.snapshot() {
		if ev == e {
			return i
		}
	}
	return -1
}

// fakeRunner is an orchestratorRunner double used to observe the eager
// LoadAndAttach-before-runtime.New ordering (#102). Run returns runErr (or
// blocks until ctx cancellation when block is set).
type fakeRunner struct {
	runErr error
	block  bool
}

func (f *fakeRunner) Run(ctx context.Context) error {
	if f.block {
		<-ctx.Done()
		return nil
	}
	return f.runErr
}
func (f *fakeRunner) Ready() runtime.ProbeStatus { return runtime.ProbeStatus{} }
func (f *fakeRunner) Live() runtime.ProbeStatus  { return runtime.ProbeStatus{} }

// orderedListener records Bind/Shutdown ordering and blocks in Serve until ctx
// cancellation so the drain path is exercised deterministically.
type orderedListener struct {
	rec *recorder
	mu  sync.Mutex
	b   int
	s   int
}

func (l *orderedListener) Bind() error {
	l.mu.Lock()
	l.b++
	l.mu.Unlock()
	l.rec.add("bind")
	return nil
}
func (l *orderedListener) Serve(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func (l *orderedListener) Shutdown(context.Context) error {
	l.mu.Lock()
	l.s++
	l.mu.Unlock()
	l.rec.add("listener-shutdown")
	return nil
}
func (l *orderedListener) binds() int     { l.mu.Lock(); defer l.mu.Unlock(); return l.b }
func (l *orderedListener) shutdowns() int { l.mu.Lock(); defer l.mu.Unlock(); return l.s }

func orderedFactory(l *orderedListener) runtime.ListenerFactory {
	return func(config.Config, listener.ConnHandler, *slog.Logger) (runtime.Listener, error) {
		return l, nil
	}
}

// orderedControlPlane records Start/Shutdown ordering.
type orderedControlPlane struct {
	rec *recorder
}

func (c *orderedControlPlane) Start(context.Context) error {
	c.rec.add("cp-start")
	return nil
}
func (c *orderedControlPlane) Shutdown(context.Context) error {
	c.rec.add("cp-shutdown")
	return nil
}

// runValidConfig is the lifecycle-test config: it passes Config.Validate and the
// orchestrator gates run with benign defaults.
func runValidConfig() config.Config { return validConfig() }

// #102
func TestRun_EagerLoadAndAttach_HappensBeforeRuntimeNew(t *testing.T) {
	rec := &recorder{}
	fh := &fakeHandle{attachInfo: healthyAttach()}
	fl := &fakeListener{}

	code := run(context.Background(), deps{
		loadConfig: func() (config.Config, error) { return runValidConfig(), nil },
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			rec.add("load")
			return fh, nil
		},
		factory: fakeFactory(fl),
		newOrchestrator: func(o runtime.Options) (orchestratorRunner, error) {
			rec.add("runtime-new")
			return &fakeRunner{}, nil
		},
	})
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	li, ni := rec.index("load"), rec.index("runtime-new")
	if li < 0 || ni < 0 || li >= ni {
		t.Fatalf("eager LoadAndAttach order = %v, want load before runtime-new", rec.snapshot())
	}
}

// #103
func TestRun_LoadAndAttachFailure_AbortsBeforeAnyBindFailClosed(t *testing.T) {
	rec := &recorder{}
	fl := &fakeListener{}

	code := run(context.Background(), deps{
		loadConfig: func() (config.Config, error) { return runValidConfig(), nil },
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			return nil, errors.New("kernel load failed")
		},
		factory: fakeFactory(fl),
		newOrchestrator: func(o runtime.Options) (orchestratorRunner, error) {
			rec.add("runtime-new")
			return &fakeRunner{}, nil
		},
		newControlPlane: func(config.ControlPlaneConfig, prometheus.Gatherer, runtime.ProbeSource) (controlPlane, error) {
			rec.add("control-plane")
			return &orderedControlPlane{rec: rec}, nil
		},
	})
	if code == 0 {
		t.Fatalf("run() = 0, want non-zero on eager load/attach failure")
	}
	if fl.binds() != 0 {
		t.Fatalf("listener bound %d times, want 0 (aborted before any bind)", fl.binds())
	}
	if rec.index("runtime-new") != -1 || rec.index("control-plane") != -1 {
		t.Fatalf("wiring proceeded past the eager load failure: %v", rec.snapshot())
	}
}

// #104
func TestRun_HandleClose_DeferredAndInvokedExactlyOnceOnNormalDrain(t *testing.T) {
	fh := &fakeHandle{attachInfo: healthyAttach()}
	code := runNormalDrain(t, fh, &fakeListener{})
	if code != 0 {
		t.Fatalf("run() = %d, want 0 on clean drain", code)
	}
	if got := fh.teardowns(); got != 1 {
		t.Fatalf("Handle teardown ran %d times, want exactly 1", got)
	}
}

// #105
func TestRun_HandleClose_IdempotentAcrossDrainAndDefer(t *testing.T) {
	fh := &fakeHandle{attachInfo: healthyAttach()}
	runNormalDrain(t, fh, &fakeListener{})
	if got := fh.closes(); got < 2 {
		t.Fatalf("Handle Close() calls = %d, want >= 2 (orchestrator drain + deferred close)", got)
	}
	if got := fh.teardowns(); got != 1 {
		t.Fatalf("Handle teardown ran %d times despite overlapping Close(), want exactly 1", got)
	}
}

// #106
func TestOrchestratorDrain_NormalShutdown_CallsHandleClose(t *testing.T) {
	fh := &fakeHandle{attachInfo: healthyAttach()}
	runNormalDrain(t, fh, &fakeListener{})
	if fh.teardowns() < 1 {
		t.Fatalf("orchestrator drain did not invoke Handle.Close()")
	}
}

// #107
func TestAttachLossDuringServe_CallbackFires_TriggersFailClosedCancelAndDrain(t *testing.T) {
	fh := &fakeHandle{attachInfo: healthyAttach()}
	fl := &fakeListener{}
	done := make(chan int, 1)
	// A background parent ctx that is never cancelled: only the attach-loss
	// callback can cancel the serve ctx and initiate drain.
	go func() {
		done <- run(context.Background(), lifecycleDeps(fh, fakeFactory(fl), nil))
	}()

	waitFor(t, func() bool { return fl.binds() > 0 }, "listener never bound")
	fh.fireLoss(errors.New("program detached"))

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("run() = %d, want 0 (attach-loss triggers a clean fail-closed drain)", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("attach-loss did not cancel serve ctx / initiate drain")
	}
	if fl.shutdowns() != 1 {
		t.Fatalf("listener Shutdown calls = %d, want 1 on attach-loss drain", fl.shutdowns())
	}
}

// #108
func TestAttachLossDuringServe_DrainPath_InvokesHandleClose(t *testing.T) {
	fh := &fakeHandle{attachInfo: healthyAttach()}
	fl := &fakeListener{}
	done := make(chan int, 1)
	go func() {
		done <- run(context.Background(), lifecycleDeps(fh, fakeFactory(fl), nil))
	}()
	waitFor(t, func() bool { return fl.binds() > 0 }, "listener never bound")
	fh.fireLoss(errors.New("program detached"))
	waitExit(t, done)
	if fh.teardowns() < 1 {
		t.Fatalf("attach-loss drain did not invoke Handle.Close()")
	}
}

// #109
func TestShutdown_OrderReverseOfStartup_ControlPlaneLast(t *testing.T) {
	rec := &recorder{}
	fh := &fakeHandle{attachInfo: healthyAttach(), onTeardown: func() { rec.add("handle-close") }}
	ol := &orderedListener{rec: rec}
	cp := &orderedControlPlane{rec: rec}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, lifecycleDeps(fh, orderedFactory(ol), func(config.ControlPlaneConfig, prometheus.Gatherer, runtime.ProbeSource) (controlPlane, error) {
			return cp, nil
		}))
	}()
	waitFor(t, func() bool { return ol.binds() > 0 }, "listener never bound")
	cancel()
	waitExit(t, done)

	li := rec.index("listener-shutdown")
	hi := rec.index("handle-close")
	ci := rec.index("cp-shutdown")
	if li < 0 || hi < 0 || ci < 0 || !(li < hi && hi < ci) {
		t.Fatalf("shutdown order = %v, want listener-shutdown -> handle-close -> cp-shutdown (control-plane last)", rec.snapshot())
	}
}

// lifecycleDeps builds a hermetic deps for the real-orchestrator lifecycle tests
// with the given fake handle, factory, and optional control-plane constructor.
func lifecycleDeps(fh *fakeHandle, factory runtime.ListenerFactory, cpFn func(config.ControlPlaneConfig, prometheus.Gatherer, runtime.ProbeSource) (controlPlane, error)) deps {
	d := deps{
		loadConfig: func() (config.Config, error) { return runValidConfig(), nil },
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			return fh, nil
		},
		factory: factory,
	}
	if cpFn != nil {
		d.newControlPlane = cpFn
	}
	return d
}

// runNormalDrain runs the real orchestrator with the given fake handle/listener,
// waits for the bind, delivers a SIGTERM (ctx cancel), and returns the exit code.
func runNormalDrain(t *testing.T, fh *fakeHandle, fl *fakeListener) int {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- run(ctx, lifecycleDeps(fh, fakeFactory(fl), nil)) }()
	waitFor(t, func() bool { return fl.binds() > 0 }, "listener never bound")
	cancel()
	select {
	case code := <-done:
		return code
	case <-time.After(2 * time.Second):
		t.Fatalf("run() did not return after SIGTERM")
		return -1
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for !cond() {
		select {
		case <-deadline:
			t.Fatal(msg)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// waitExit blocks for run()'s exit code with a bounded timeout so a regression
// that fails to drain surfaces as a test failure rather than hanging the suite.
func waitExit(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not return within the drain deadline")
		return -1
	}
}
