package runtime

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/prometheus/client_golang/prometheus"
)

func factoryTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// spyResolver is a real (non-noop) DestinationResolver that records whether the
// listener invoked it. It returns an error so dispatch fail-closes without ever
// reaching the handler; the recorded call count is what proves the factory
// threaded THIS resolver (not noopResolver{}) into listener.New.
type spyResolver struct{ calls atomic.Int32 }

func (s *spyResolver) Resolve(net.Conn) (netip.AddrPort, error) {
	s.calls.Add(1)
	return netip.AddrPort{}, errSpyResolve
}

var errSpyResolve = &spyResolveError{}

type spyResolveError struct{}

func (*spyResolveError) Error() string { return "spy: no original destination" }

// spyRecorder embeds noopTypedMetrics for the full audit.MetricsRecorder
// surface and overrides StageDuration to record that the listener recorded a
// resolve stage through THIS recorder (not noopTypedMetrics{}).
type spyRecorder struct {
	noopTypedMetrics
	resolveStages atomic.Int32
}

func (s *spyRecorder) StageDuration(name audit.StageName, _ time.Duration) {
	if name == audit.StageResolve {
		s.resolveStages.Add(1)
	}
}

// connHandlerFunc adapts a func to listener.ConnHandler. It is never invoked in
// these tests because the spy resolver always fail-closes before dispatch hands
// the connection to the handler.
type connHandlerFunc func(ctx context.Context, cc *listener.ConnContext) error

func (f connHandlerFunc) Handle(ctx context.Context, cc *listener.ConnContext) error {
	return f(ctx, cc)
}

// #66
func TestMakeProductionListenerFactory_PassesRealResolverAndRecorder_NotNoops(t *testing.T) {
	res := &spyResolver{}
	rec := &spyRecorder{}
	f := MakeProductionListenerFactory(res, rec)

	cfg := config.Config{Listener: config.ListenerConfig{Address: "127.0.0.1:0"}}
	h := connHandlerFunc(func(context.Context, *listener.ConnContext) error {
		t.Error("handler must not be reached when resolver fail-closes")
		return nil
	})
	ln, err := f(cfg, h, factoryTestLogger())
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}
	if err := ln.Bind(); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		_ = ln.Serve(ctx)
		close(serveDone)
	}()
	t.Cleanup(func() {
		cancel()
		<-serveDone
		shutdownCtx, sc := context.WithTimeout(context.Background(), 2*time.Second)
		defer sc()
		_ = ln.Shutdown(shutdownCtx)
	})

	addr := ln.(*listener.Listener).Addr()
	if !addr.IsValid() {
		t.Fatal("listener Addr() invalid after Bind")
	}
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if res.calls.Load() >= 1 && rec.resolveStages.Load() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := res.calls.Load(); got < 1 {
		t.Fatalf("spy resolver Resolve calls = %d, want >=1 (real resolver not threaded into listener.New)", got)
	}
	if got := rec.resolveStages.Load(); got < 1 {
		t.Fatalf("spy recorder StageResolve records = %d, want >=1 (real recorder not threaded into listener.New)", got)
	}
}

// #67
func TestMakeProductionListenerFactory_ParsesListenerAddress_Success(t *testing.T) {
	f := MakeProductionListenerFactory(&spyResolver{}, &spyRecorder{})
	cfg := config.Config{Listener: config.ListenerConfig{Address: "127.0.0.1:0"}}
	ln, err := f(cfg, connHandlerFunc(func(context.Context, *listener.ConnContext) error { return nil }), factoryTestLogger())
	if err != nil {
		t.Fatalf("factory() error = %v, want nil for valid loopback address", err)
	}
	lst, ok := ln.(*listener.Listener)
	if !ok {
		t.Fatalf("factory returned %T, want *listener.Listener", ln)
	}
	if err := lst.Bind(); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, sc := context.WithTimeout(context.Background(), 2*time.Second)
		defer sc()
		_ = lst.Shutdown(shutdownCtx)
	})
	if !lst.Addr().Addr().IsLoopback() {
		t.Fatalf("bound address %v is not loopback", lst.Addr())
	}
}

// #68
func TestMakeProductionListenerFactory_InvalidListenerAddress_ReturnsError(t *testing.T) {
	f := MakeProductionListenerFactory(&spyResolver{}, &spyRecorder{})
	for _, addr := range []string{"", "not-an-address", "10.0.0.5:443", "127.0.0.1"} {
		cfg := config.Config{Listener: config.ListenerConfig{Address: addr}}
		ln, err := f(cfg, connHandlerFunc(func(context.Context, *listener.ConnContext) error { return nil }), factoryTestLogger())
		if err == nil {
			t.Fatalf("factory(%q) error = nil, want error (must fail fast, never bind a bad address)", addr)
		}
		if ln != nil {
			t.Fatalf("factory(%q) listener = %v, want nil on error", addr, ln)
		}
	}
}

// #69
func TestDataMetrics_Injection_IsSamePromMetricsRecorderInstance(t *testing.T) {
	prom, err := audit.NewPromMetricsRecorder(prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder() error = %v", err)
	}
	o, err := New(Options{DataMetrics: prom})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if o.dataMetrics != prom {
		t.Fatalf("orchestrator dataMetrics = %p, want the exact injected instance %p", o.dataMetrics, prom)
	}
}

// #70
func TestDataMetrics_Injection_ReplacesDefaultNoop(t *testing.T) {
	def, err := New(Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, ok := def.dataMetrics.(noopTypedMetrics); !ok {
		t.Fatalf("default dataMetrics = %T, want noopTypedMetrics", def.dataMetrics)
	}

	prom, err := audit.NewPromMetricsRecorder(prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder() error = %v", err)
	}
	injected, err := New(Options{DataMetrics: prom})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, ok := injected.dataMetrics.(noopTypedMetrics); ok {
		t.Fatal("injected dataMetrics is still noopTypedMetrics; injection did not replace the default")
	}
	if _, ok := injected.dataMetrics.(*audit.PromMetricsRecorder); !ok {
		t.Fatalf("injected dataMetrics = %T, want *audit.PromMetricsRecorder", injected.dataMetrics)
	}
}
