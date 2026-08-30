package runtime

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
)

// scrapeMetrics runs a /metrics GET against a control-plane Handler served via
// httptest and returns the exposition body.
func scrapeMetrics(t *testing.T, cp *ControlPlaneServer) string {
	t.Helper()
	srv := httptest.NewServer(cp.Handler())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}
	return string(body)
}

// #71
func TestSharedRegistry_DispatchWrittenCounters_AppearInMetricsGather(t *testing.T) {
	reg := prometheus.NewRegistry()
	recorder, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder: %v", err)
	}
	// Simulate a dispatch reject writing through the recorder.
	recorder.TransportReject(audit.RejectClassNoOriginalDst, audit.BoundNone)
	recorder.StageDuration(audit.StageResolve, 3*time.Millisecond)

	cp, err := NewControlPlaneServer("10.0.0.1", Port15020, reg, &fakeProbeSource{ready: true, live: true})
	if err != nil {
		t.Fatalf("NewControlPlaneServer: %v", err)
	}
	body := scrapeMetrics(t, cp)
	if !strings.Contains(body, "aksh_transport_reject_total") {
		t.Fatalf("/metrics missing dispatch-written transport reject counter:\n%s", body)
	}
	if !strings.Contains(body, `class="no_original_dst"`) {
		t.Fatalf("/metrics missing reject class written by dispatch:\n%s", body)
	}
}

// #72
func TestSharedRegistry_SameInstance_RegistererEqualsGatherer(t *testing.T) {
	// The identity property: a counter written through a recorder built over reg
	// is scraped from a control-plane built over the SAME reg, and is ABSENT
	// from a control-plane built over a different registry.
	reg := prometheus.NewRegistry()
	recorder, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder: %v", err)
	}
	recorder.TransportReject(audit.RejectClassNoOriginalDst, audit.BoundNone)

	cpSame, err := NewControlPlaneServer("10.0.0.1", Port15020, reg, &fakeProbeSource{ready: true})
	if err != nil {
		t.Fatalf("NewControlPlaneServer(same reg): %v", err)
	}
	if got := scrapeMetrics(t, cpSame); !strings.Contains(got, `aksh_transport_reject_total{bound="none",class="no_original_dst"} 1`) {
		t.Fatalf("shared-registry scrape did not observe the writer's counter:\n%s", got)
	}

	other := prometheus.NewRegistry()
	if _, err := audit.NewPromMetricsRecorder(other); err != nil {
		t.Fatalf("NewPromMetricsRecorder(other): %v", err)
	}
	cpOther, err := NewControlPlaneServer("10.0.0.1", Port15020, other, &fakeProbeSource{ready: true})
	if err != nil {
		t.Fatalf("NewControlPlaneServer(other reg): %v", err)
	}
	if got := scrapeMetrics(t, cpOther); strings.Contains(got, `aksh_transport_reject_total{bound="none",class="no_original_dst"} 1`) {
		t.Fatalf("a different registry must not observe the writer's counter (identity broken):\n%s", got)
	}
}

// #73
func TestSharedRegistry_MetricsEndpoint_ExposesResolveRejectCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	recorder, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder: %v", err)
	}
	recorder.TransportReject(audit.RejectClassNoOriginalDst, audit.BoundNone)
	recorder.StageDuration(audit.StageResolve, 5*time.Millisecond)

	cp, err := NewControlPlaneServer("10.0.0.1", Port15020, reg, &fakeProbeSource{ready: true})
	if err != nil {
		t.Fatalf("NewControlPlaneServer: %v", err)
	}
	body := scrapeMetrics(t, cp)
	if !strings.Contains(body, `aksh_transport_reject_total{bound="none",class="no_original_dst"} 1`) {
		t.Fatalf("/metrics missing aksh_transport_reject_total{class=no_original_dst,bound=none}:\n%s", body)
	}
	if !strings.Contains(body, `aksh_decision_duration_seconds_count{stage="resolve"} 1`) {
		t.Fatalf("/metrics missing aksh_decision_duration_seconds{stage=resolve}:\n%s", body)
	}
}

// cpOrderListener records Bind ordering into a shared recorder for the
// start-before-bind test.
type cpOrderListener struct {
	rec *cpRecorder
	mu  sync.Mutex
	b   int
}

func (l *cpOrderListener) Bind() error {
	l.mu.Lock()
	l.b++
	l.mu.Unlock()
	l.rec.add("bind")
	return nil
}
func (l *cpOrderListener) Serve(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func (l *cpOrderListener) Shutdown(context.Context) error  { return nil }
func (l *cpOrderListener) binds() int                      { l.mu.Lock(); defer l.mu.Unlock(); return l.b }

type cpRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *cpRecorder) add(e string) { r.mu.Lock(); r.events = append(r.events, e); r.mu.Unlock() }
func (r *cpRecorder) index(e string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, ev := range r.events {
		if ev == e {
			return i
		}
	}
	return -1
}

// #77
func TestControlPlaneServer_Startup_StartsBeforeDataPlaneBind(t *testing.T) {
	rec := &cpRecorder{}
	ol := &cpOrderListener{rec: rec}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	o, err := New(Options{
		Config: validRuntimeConfig(),
		ListenerFactory: func(config.Config, listener.ConnHandler, *slog.Logger) (Listener, error) {
			return ol, nil
		},
		ControlPlaneStart: func(context.Context) error { rec.add("cp-start"); return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = o.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for ol.binds() == 0 {
		select {
		case <-deadline:
			t.Fatal("listener never bound")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	si, bi := rec.index("cp-start"), rec.index("bind")
	if si < 0 || bi < 0 || si >= bi {
		t.Fatalf("control-plane start order = %v, want cp-start before bind", rec.events)
	}
}

// #78
func TestControlPlaneServer_StartFailure_AbortsFailClosedNoDataPlaneBind(t *testing.T) {
	fl := &fakeListener{}
	o, err := New(Options{
		Config:            validRuntimeConfig(),
		ListenerFactory:   fakeFactory(fl),
		ControlPlaneStart: func(context.Context) error { return errors.New("control-plane bind failed") },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := o.Run(context.Background()); err == nil {
		t.Fatal("Run() = nil, want a fail-closed control-plane start error")
	}
	if got := fl.binds(); got != 0 {
		t.Fatalf("data-plane Bind calls = %d, want 0 on control-plane start failure", got)
	}
}

// SI-S5-1 regression: a failure AFTER the control plane has started (listener
// factory error, or Bind error) must still tear the control plane down in
// reverse order (#109) rather than leaking the running HTTP server. Two review
// models independently flagged the missing teardown on these paths.
func TestControlPlaneServer_ListenerFactoryFailure_ShutsDownControlPlane(t *testing.T) {
	rec := &cpRecorder{}
	o, err := New(Options{
		Config: validRuntimeConfig(),
		ListenerFactory: func(config.Config, listener.ConnHandler, *slog.Logger) (Listener, error) {
			return nil, errors.New("factory boom")
		},
		ControlPlaneStart:    func(context.Context) error { rec.add("cp-start"); return nil },
		ControlPlaneShutdown: func(context.Context) error { rec.add("cp-shutdown"); return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := o.Run(context.Background()); err == nil {
		t.Fatal("Run() = nil, want a listener factory failure")
	}
	if rec.index("cp-start") < 0 {
		t.Fatal("precondition: control-plane was never started")
	}
	if rec.index("cp-shutdown") < 0 {
		t.Fatal("control-plane started but not shut down on listener-factory failure (leak)")
	}
}

func TestControlPlaneServer_BindFailure_ShutsDownControlPlane(t *testing.T) {
	rec := &cpRecorder{}
	o, err := New(Options{
		Config: validRuntimeConfig(),
		ListenerFactory: func(config.Config, listener.ConnHandler, *slog.Logger) (Listener, error) {
			return &bindErrListener{err: errors.New("bind boom")}, nil
		},
		ControlPlaneStart:    func(context.Context) error { rec.add("cp-start"); return nil },
		ControlPlaneShutdown: func(context.Context) error { rec.add("cp-shutdown"); return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := o.Run(context.Background()); err == nil {
		t.Fatal("Run() = nil, want a data-plane bind failure")
	}
	if rec.index("cp-shutdown") < 0 {
		t.Fatal("control-plane started but not shut down on data-plane bind failure (leak)")
	}
}

// bindErrListener is a minimal Listener whose Bind always fails, used to drive
// the post-control-plane-start bind-failure teardown path.
type bindErrListener struct{ err error }

func (l *bindErrListener) Bind() error                     { return l.err }
func (l *bindErrListener) Serve(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func (l *bindErrListener) Shutdown(context.Context) error  { return nil }

// #79
func TestControlPlaneServer_PortDefault_UsesPort15020(t *testing.T) {
	cp, err := NewControlPlaneServerFromConfig(
		config.ControlPlaneConfig{Address: "10.0.0.1"}, prometheus.NewRegistry(), &fakeProbeSource{})
	if err != nil {
		t.Fatalf("NewControlPlaneServerFromConfig: %v", err)
	}
	if got := cp.Addr(); got != "10.0.0.1:15020" {
		t.Fatalf("Addr() = %q, want 10.0.0.1:15020 (Port15020 default)", got)
	}
}

// #80
func TestAddressReconciliation_EmptyHost_ResolvesToPodIP(t *testing.T) {
	t.Setenv(PodIPEnv, "10.1.2.3")
	cp, err := NewControlPlaneServerFromConfig(
		config.ControlPlaneConfig{Address: ""}, prometheus.NewRegistry(), &fakeProbeSource{})
	if err != nil {
		t.Fatalf("NewControlPlaneServerFromConfig: %v", err)
	}
	if got := cp.Addr(); got != "10.1.2.3:15020" {
		t.Fatalf("Addr() = %q, want 10.1.2.3:15020 (POD_IP downward API)", got)
	}
}

// #81
func TestAddressReconciliation_LoopbackHost_RejectedAtWireTime(t *testing.T) {
	_, err := NewControlPlaneServerFromConfig(
		config.ControlPlaneConfig{Address: "127.0.0.1"}, prometheus.NewRegistry(), &fakeProbeSource{})
	if !errors.Is(err, ErrLoopbackBindAddress) {
		t.Fatalf("NewControlPlaneServerFromConfig(loopback) error = %v, want ErrLoopbackBindAddress", err)
	}
}

// #82
func TestAddressReconciliation_PortOverride_UsesConfiguredPort(t *testing.T) {
	cp, err := NewControlPlaneServerFromConfig(
		config.ControlPlaneConfig{Address: "10.0.0.1", Port: 9443}, prometheus.NewRegistry(), &fakeProbeSource{})
	if err != nil {
		t.Fatalf("NewControlPlaneServerFromConfig: %v", err)
	}
	if got := cp.Addr(); got != "10.0.0.1:9443" {
		t.Fatalf("Addr() = %q, want 10.0.0.1:9443 (configured port override)", got)
	}
}
