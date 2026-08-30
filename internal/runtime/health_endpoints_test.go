package runtime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/prometheus/client_golang/prometheus"
)

// fakeProbeSource is a controllable ProbeSource test double.
type fakeProbeSource struct {
	ready  bool
	live   bool
	reason string
}

func (f *fakeProbeSource) Ready() ProbeStatus {
	return ProbeStatus{Ready: f.ready, Live: f.live, Reason: f.reason}
}

func (f *fakeProbeSource) Live() ProbeStatus {
	return ProbeStatus{Ready: f.ready, Live: f.live, Reason: f.reason}
}

func newTestRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()
	return prometheus.NewRegistry()
}

// newPopulatedRegistry returns a registry carrying the real S6 collectors with
// a decision recorded, so /metrics exposition is non-trivial.
func newPopulatedRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	if _, err := audit.NewPromMetricsRecorder(reg); err != nil {
		t.Fatalf("NewPromMetricsRecorder: %v", err)
	}
	return reg
}

// --- 7.1 Constructor / binding ---

func TestNewControlPlaneServer_BindsPodIP15020_NotLoopback(t *testing.T) {
	reg := newTestRegistry(t)
	probes := &fakeProbeSource{ready: true, live: true, reason: "serving"}

	s, err := NewControlPlaneServer("10.0.0.5", Port15020, reg, probes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if Port15020 != 15020 {
		t.Fatalf("Port15020 = %d, want 15020", Port15020)
	}
	if got, want := s.Addr(), "10.0.0.5:15020"; got != want {
		t.Fatalf("Addr() = %q, want %q", got, want)
	}
}

func TestNewControlPlaneServer_NilProbeSource_ReturnsError(t *testing.T) {
	reg := newTestRegistry(t)
	if _, err := NewControlPlaneServer("10.0.0.5", Port15020, reg, nil); err == nil {
		t.Fatal("expected error for nil ProbeSource, got nil")
	}
}

func TestNewControlPlaneServer_EmptyBindAddress_ReturnsError(t *testing.T) {
	reg := newTestRegistry(t)
	probes := &fakeProbeSource{ready: true, live: true}
	if _, err := NewControlPlaneServer("", Port15020, reg, probes); err == nil {
		t.Fatal("expected error for empty bind address, got nil")
	}
}

func TestServer_LoopbackBindAddress_RejectedByConfig(t *testing.T) {
	reg := newTestRegistry(t)
	probes := &fakeProbeSource{ready: true, live: true}
	for _, addr := range []string{"127.0.0.1", "::1", "localhost", "LocalHost", "127.0.0.2"} {
		if _, err := NewControlPlaneServer(addr, Port15020, reg, probes); err == nil {
			t.Fatalf("expected error for loopback bind %q, got nil", addr)
		}
	}
}

// newTestServer builds a server on a non-loopback pod IP with the given
// registry and probes, for handler-level testing via httptest.NewRecorder.
func newTestServer(t *testing.T, reg prometheus.Gatherer, probes ProbeSource) *ControlPlaneServer {
	t.Helper()
	s, err := NewControlPlaneServer("10.0.0.5", Port15020, reg, probes)
	if err != nil {
		t.Fatalf("NewControlPlaneServer: %v", err)
	}
	return s
}

// --- 7.2 /metrics ---

func TestMetrics_GET_ReturnsExpositionFormat(t *testing.T) {
	reg := newPopulatedRegistry(t)
	s := newTestServer(t, reg, &fakeProbeSource{ready: true, live: true})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "aksh_") {
		t.Fatalf("body does not contain exposition metrics:\n%s", rr.Body.String())
	}
}

func TestMetrics_NonGET_RejectedMethodNotAllowed(t *testing.T) {
	reg := newPopulatedRegistry(t)
	s := newTestServer(t, reg, &fakeProbeSource{ready: true, live: true})

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/metrics", nil)
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /metrics status = %d, want 405", method, rr.Code)
		}
	}
}

func TestMetrics_Response_ContainsNoSecrets(t *testing.T) {
	reg := newPopulatedRegistry(t)
	s := newTestServer(t, reg, &fakeProbeSource{ready: true, live: true})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	s.Handler().ServeHTTP(rr, req)

	assertNoSecrets(t, rr.Body.String())
}

// --- 7.3 /healthz ---

func TestHealthz_LiveProcess_Returns200(t *testing.T) {
	s := newTestServer(t, newTestRegistry(t), &fakeProbeSource{ready: true, live: true, reason: "serving"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestHealthz_NotLive_Returns503(t *testing.T) {
	s := newTestServer(t, newTestRegistry(t), &fakeProbeSource{ready: false, live: false, reason: "serve failed"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

// assertNoSecrets fails if the body contains any known secret marker. The
// control ports are read-only and expose only closed enums (INV-5).
func assertNoSecrets(t *testing.T, body string) {
	t.Helper()
	for _, marker := range []string{"Bearer ", "authorization", "password", "eyJ", "secret", "private_key", "BEGIN "} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
			t.Fatalf("response leaked secret marker %q:\n%s", marker, body)
		}
	}
}

// doGet drives a GET request through the server mux via an httptest recorder.
func doGet(t *testing.T, s *ControlPlaneServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	s.Handler().ServeHTTP(rr, req)
	return rr
}

// --- 7.4 /readyz ---

func TestReadyz_Ready_Returns200(t *testing.T) {
	s := newTestServer(t, newTestRegistry(t), &fakeProbeSource{ready: true, live: true, reason: "serving"})
	if rr := doGet(t, s, "/readyz"); rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestReadyz_AuditUnavailable_Returns503(t *testing.T) {
	base := &fakeProbeSource{ready: true, live: true, reason: "serving"}
	agg := NewProbeAggregator(base)
	ec := audit.NewEmergencyChannel(io.Discard, nil, agg)
	s := newTestServer(t, newTestRegistry(t), agg)

	if rr := doGet(t, s, "/readyz"); rr.Code != http.StatusOK {
		t.Fatalf("pre-signal status = %d, want 200", rr.Code)
	}

	ec.Signal("audit write failed")

	rr := doGet(t, s, "/readyz")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-signal status = %d, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "audit_unavailable") {
		t.Fatalf("body does not reflect audit_unavailable reason: %q", rr.Body.String())
	}
}

func TestReadyz_RecoveredAudit_Returns200Again(t *testing.T) {
	base := &fakeProbeSource{ready: true, live: true, reason: "serving"}
	agg := NewProbeAggregator(base)
	ec := audit.NewEmergencyChannel(io.Discard, nil, agg)
	s := newTestServer(t, newTestRegistry(t), agg)

	ec.Signal("audit write failed")
	if rr := doGet(t, s, "/readyz"); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("after signal status = %d, want 503", rr.Code)
	}

	ec.Recover()
	if rr := doGet(t, s, "/readyz"); rr.Code != http.StatusOK {
		t.Fatalf("after recover status = %d, want 200 (readiness must not latch)", rr.Code)
	}
}

func TestReadyz_DegradedState_ReflectsReason(t *testing.T) {
	for _, reason := range []string{"starting", "shutting down"} {
		s := newTestServer(t, newTestRegistry(t), &fakeProbeSource{ready: false, live: true, reason: reason})
		rr := doGet(t, s, "/readyz")
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("reason %q: status = %d, want 503", reason, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), reason) {
			t.Fatalf("body %q does not reflect degraded reason %q", rr.Body.String(), reason)
		}
	}

	// audit_unavailable path via the emergency channel.
	agg := NewProbeAggregator(&fakeProbeSource{ready: true, live: true, reason: "serving"})
	ec := audit.NewEmergencyChannel(io.Discard, nil, agg)
	ec.Signal("audit write failed")
	s := newTestServer(t, newTestRegistry(t), agg)
	rr := doGet(t, s, "/readyz")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit_unavailable: status = %d, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "audit_unavailable") {
		t.Fatalf("body %q does not reflect audit_unavailable reason", rr.Body.String())
	}
}

func TestReadyz_Response_ExposesNoSecrets(t *testing.T) {
	agg := NewProbeAggregator(&fakeProbeSource{ready: true, live: true, reason: "serving"})
	ec := audit.NewEmergencyChannel(io.Discard, nil, agg)
	ec.Signal("audit write failed")
	s := newTestServer(t, newTestRegistry(t), agg)

	assertNoSecrets(t, doGet(t, s, "/readyz").Body.String())
	assertNoSecrets(t, doGet(t, s, "/healthz").Body.String())
}

// --- 7.5 Binding rationale (ADR-S6-04) ---

func TestServer_LoopbackBindAddress_RejectedAtStartup(t *testing.T) {
	probes := &fakeProbeSource{ready: true, live: true}
	for _, addr := range []string{"127.0.0.1", "::1", "localhost"} {
		// Construct the struct directly to bypass the constructor's rejection
		// and prove Start independently refuses to serve on loopback.
		s := &ControlPlaneServer{bindAddr: addr, port: Port15020, gatherer: newTestRegistry(t), probes: probes}
		if err := s.Start(context.Background()); err == nil {
			_ = s.Shutdown(context.Background())
			t.Fatalf("Start with loopback bind %q: expected error, got nil", addr)
		}
	}
}

// --- 7.6 Lifecycle ---

func TestShutdown_GracefullyStopsServer(t *testing.T) {
	s := newLifecycleServer(t)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestShutdown_CalledTwice_Idempotent(t *testing.T) {
	s := newLifecycleServer(t)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown must be a no-op, got: %v", err)
	}
}

// TestStart_CalledTwice_RejectsSecondStart proves a second Start does not orphan
// the first listener/server: it returns ErrAlreadyStarted so Shutdown still
// governs the single running server.
func TestStart_CalledTwice_RejectsSecondStart(t *testing.T) {
	s := newLifecycleServer(t)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer func() { _ = s.Shutdown(context.Background()) }()
	if err := s.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start: got %v, want ErrAlreadyStarted", err)
	}
}

// TestShutdown_BeforeStart_TerminalPreventsServing proves shutdown intent is
// terminal: a Shutdown before Start latches, and a subsequent Start honors it
// by not serving (no listener/server is created), closing the lost-shutdown
// race window.
func TestShutdown_BeforeStart_TerminalPreventsServing(t *testing.T) {
	s := newLifecycleServer(t)
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown before Start: %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start after Shutdown: got %v, want nil (honored)", err)
	}
	if s.srv != nil {
		t.Fatal("Start served despite prior Shutdown: s.srv must remain nil")
	}
}

// TestShutdown_ConcurrentCallers_NoDeadlockOrRace drives many concurrent
// Shutdown callers against a live server: exactly one performs the stop while
// the others wait on shutdownCh, and all return the same nil result without
// deadlock (the lock is not held across the blocking http.Server.Shutdown).
func TestShutdown_ConcurrentCallers_NoDeadlockOrRace(t *testing.T) {
	s := newLifecycleServer(t)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	const callers = 16
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			errs[i] = s.Shutdown(ctx)
		}(i)
	}
	// Watchdog: fail fast on a deadlock regression instead of hanging the suite.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent Shutdown callers did not all return within 30s (possible deadlock)")
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Shutdown caller %d: %v", i, err)
		}
	}
}

// newLifecycleServer builds a server bound to a non-loopback wildcard address on
// an ephemeral port, so Start actually binds a socket without violating the
// ADR-S6-04 loopback refusal.
func newLifecycleServer(t *testing.T) *ControlPlaneServer {
	t.Helper()
	s, err := NewControlPlaneServer("0.0.0.0", 0, newTestRegistry(t), &fakeProbeSource{ready: true, live: true, reason: "serving"})
	if err != nil {
		t.Fatalf("NewControlPlaneServer: %v", err)
	}
	return s
}

// --- E2E-3: httptest round-trip ---

func TestControlPlaneServer_E2E_MetricsAndReadinessFlip(t *testing.T) {
	base := &fakeProbeSource{ready: true, live: true, reason: "serving"}
	agg := NewProbeAggregator(base)
	ec := audit.NewEmergencyChannel(io.Discard, nil, agg)
	s := newTestServer(t, newPopulatedRegistry(t), agg)

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// /metrics returns exposition from the real registry.
	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "aksh_") {
		t.Fatalf("/metrics status=%d body=%q", resp.StatusCode, string(body))
	}

	// /readyz flips 200 -> 503 on emergency signal.
	if code := getStatus(t, ts.URL+"/readyz"); code != http.StatusOK {
		t.Fatalf("pre-signal /readyz = %d, want 200", code)
	}
	ec.Signal("audit write failed")
	if code := getStatus(t, ts.URL+"/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("post-signal /readyz = %d, want 503", code)
	}
	// 503 -> 200 on recovery (not latched).
	ec.Recover()
	if code := getStatus(t, ts.URL+"/readyz"); code != http.StatusOK {
		t.Fatalf("post-recover /readyz = %d, want 200", code)
	}
}

func getStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
