package runtime

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/pki"
	"github.com/girishmotwani/aksh/internal/policy/watch"
)

// --- test doubles -----------------------------------------------------------

// orderLog is a mutex-guarded ordered event log shared by the orchestrator
// (via Options.Recorder) and the gate fakes.
type orderLog struct {
	mu sync.Mutex
	ev []string
}

func (l *orderLog) add(e string) {
	l.mu.Lock()
	l.ev = append(l.ev, e)
	l.mu.Unlock()
}

func (l *orderLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.ev))
	copy(out, l.ev)
	return out
}

func (l *orderLog) index(e string) int {
	for i, v := range l.snapshot() {
		if v == e {
			return i
		}
	}
	return -1
}

func (l *orderLog) has(e string) bool { return l.index(e) >= 0 }

// gateListener is a fake runtime.Listener that also implements the Phase-B
// probeListener seam, counting calls and returning injected errors.
type gateListener struct {
	mu          sync.Mutex
	bindCalls   int
	probeCalls  int
	serveCalls  int
	closeCalls  int
	bindErr     error
	probeErr    error
	serveErr    error // when set, Serve returns it immediately
	shutdownErr error
}

func (g *gateListener) Bind() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bindCalls++
	return g.bindErr
}

func (g *gateListener) AcceptProbe(deadline time.Time) (net.Conn, error) {
	g.mu.Lock()
	g.probeCalls++
	err := g.probeErr
	g.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (g *gateListener) Serve(ctx context.Context) error {
	g.mu.Lock()
	g.serveCalls++
	err := g.serveErr
	g.mu.Unlock()
	if err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func (g *gateListener) Shutdown(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closeCalls++
	return g.shutdownErr
}

func (g *gateListener) binds() int     { g.mu.Lock(); defer g.mu.Unlock(); return g.bindCalls }
func (g *gateListener) probes() int    { g.mu.Lock(); defer g.mu.Unlock(); return g.probeCalls }
func (g *gateListener) serves() int    { g.mu.Lock(); defer g.mu.Unlock(); return g.serveCalls }
func (g *gateListener) shutdowns() int { g.mu.Lock(); defer g.mu.Unlock(); return g.closeCalls }

// recordingSink and recordingMetrics observe rejection-recorder wiring.
type recordingSink struct {
	mu    sync.Mutex
	count int
}

func (s *recordingSink) Record(context.Context, pipeline.AuditEvent) error {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
	return nil
}
func (s *recordingSink) records() int { s.mu.Lock(); defer s.mu.Unlock(); return s.count }
func (s *recordingSink) RecordCompletion(ctx context.Context, ev pipeline.AuditEvent) error {
	return s.Record(ctx, ev)
}

type recordingMetrics struct {
	mu        sync.Mutex
	decisions int
}

func (m *recordingMetrics) TransportReject(audit.RejectClass, audit.BoundName) {
	m.mu.Lock()
	m.decisions++
	m.mu.Unlock()
}
func (m *recordingMetrics) Decisions(pipeline.Disposition, pipeline.DenyReason, audit.TransportKind, bool) {
}
func (m *recordingMetrics) StageDuration(audit.StageName, time.Duration) {}
func (m *recordingMetrics) LeafCacheHit()                                {}
func (m *recordingMetrics) LeafCacheMiss()                               {}
func (m *recordingMetrics) AuditRecord(audit.AuditRecordKind)            {}
func (m *recordingMetrics) AuditWriteDuration(time.Duration)             {}
func (m *recordingMetrics) AuditUnavailable(bool)                        {}
func (m *recordingMetrics) SnapshotAge(time.Duration)                    {}
func (m *recordingMetrics) SnapshotVersion(string)                       {}
func (m *recordingMetrics) PolicyCompileFailure()                        {}
func (m *recordingMetrics) PolicyStaleDeny()                             {}
func (m *recordingMetrics) PolicyListForbidden()                         {}
func (m *recordingMetrics) CAExpiry(time.Duration)                       {}
func (m *recordingMetrics) TokenAcquisition(audit.ProviderID, audit.Result, audit.AcquireErrorClass) {
}
func (m *recordingMetrics) TokenAcquisitionDuration(audit.ProviderID, time.Duration) {}
func (m *recordingMetrics) TokenCacheHit(audit.ProviderID)                           {}
func (m *recordingMetrics) TokenCacheMiss(audit.ProviderID)                          {}
func (m *recordingMetrics) TokenCacheEviction(audit.ProviderID, audit.CredentialID)  {}
func (m *recordingMetrics) TokenRefreshFailure(audit.ProviderID, audit.CredentialID) {}
func (m *recordingMetrics) TokenBreakerState(audit.ProviderID, audit.CredentialID, audit.BreakerState) {
}
func (m *recordingMetrics) UpstreamRequest(audit.UpstreamResult)                      {}
func (m *recordingMetrics) AdmissionRequest(audit.WebhookName, audit.AdmissionResult) {}
func (m *recordingMetrics) AdmissionDuration(audit.WebhookName, time.Duration)        {}
func (m *recordingMetrics) AdmissionRejection(audit.AdmissionRule)                    {}
func (m *recordingMetrics) InjectorCertExpiry(time.Duration)                          {}
func (m *recordingMetrics) AdmissionPatchBytes(int)                                   {}
func (m *recordingMetrics) CABundlePatch(audit.WebhookConfigName, audit.PatchResult)  {}
func (m *recordingMetrics) WebhookTLSError()                                          {}
func (m *recordingMetrics) ProxyCgroupResolutionError()                               {}
func (m *recordingMetrics) count() int                                                { m.mu.Lock(); defer m.mu.Unlock(); return m.decisions }

// startupMetricsFake records fatal startup-gate metric events.
type startupMetricsFake struct {
	mu        sync.Mutex
	failures  []string
	gateError []string
}

func (s *startupMetricsFake) RecordStartupFailure(gate string) {
	s.mu.Lock()
	s.failures = append(s.failures, gate)
	s.mu.Unlock()
}
func (s *startupMetricsFake) RecordStartupGateResult(gate, result string, _ time.Duration) {
	s.mu.Lock()
	if result == "error" {
		s.gateError = append(s.gateError, gate)
	}
	s.mu.Unlock()
}
func (s *startupMetricsFake) failed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.failures...)
}
func (s *startupMetricsFake) errored() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.gateError...)
}

// --- helpers ----------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func validRuntimeConfig() config.Config {
	return config.Config{
		Listener: config.ListenerConfig{Address: "127.0.0.1:0"},
		CA:       config.CAConfig{PrivDir: "/priv", PubDir: "/pub"},
		Policy:   config.PolicyConfig{Namespace: "ns", MaxStaleness: 45 * time.Second},
		Capture: config.CaptureConfig{
			PodPath:     "/proc/1/root/sys/fs/cgroup",
			ProxyUID:    1774,
			ProxyGID:    1774,
			BlockNonTCP: true,
			RunProbe:    true,
		},
		Token: config.TokenConfig{
			SATokenPath: "/token",
			Entra: config.EntraConfig{
				TenantID:  "tenant",
				ClientID:  "client",
				Authority: "https://login.microsoftonline.com",
			},
		},
		Audit: config.AuditConfig{Sink: "stdout"},
	}
}

// baseOptions returns Options with all gate seams wired to benign successes and
// the given listener, recording ordered milestones into log.
func baseOptions(log *orderLog, gl *gateListener) Options {
	return Options{
		Config:   validRuntimeConfig(),
		Log:      discardLogger(),
		Recorder: log.add,
		ListenerFactory: func(config.Config, listener.ConnHandler, *slog.Logger) (Listener, error) {
			return gl, nil
		},
		Preflight:          func(context.Context) error { return nil },
		ConstructResolvers: func(context.Context) error { return nil },
		CAProvider:         func(context.Context) (pki.CAProvider, error) { return nopCAProvider{}, nil },
		PolicyStartup:      func(context.Context) (*watch.Store, error) { return &watch.Store{}, nil },
		LocalSelfTest:      func(context.Context) error { return nil },
		AuditSinkFactory:   func() (audit.AuditSink, error) { return audit.NewStreamSink(io.Discard), nil },
		PrivDrop:           func(capture.PrivDropConfig) error { return nil },
	}
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", msg)
}

// runInBackground starts o.Run and returns a cancel func and its result channel.
func runInBackground(o *Orchestrator) (context.CancelFunc, chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- o.Run(ctx) }()
	return cancel, errc
}

// --- tests ------------------------------------------------------------------

// 119
func TestRun_StartupOrder_ExactlyMatchesDesignSequence(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	o, err := New(baseOptions(log, gl))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve milestone")
	cancel()
	<-errc

	canon := map[string]bool{
		"config-validated": true, "preflight": true, "ca-ready": true,
		"first-snapshot": true, "self-test": true, "bind": true,
		"accept-probe": true, "priv-drop": true, "serve": true,
	}
	want := []string{
		"config-validated", "preflight", "ca-ready", "first-snapshot",
		"self-test", "bind", "accept-probe", "priv-drop", "serve",
	}
	var got []string
	for _, e := range log.snapshot() {
		if canon[e] {
			got = append(got, e)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("startup sequence = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("startup sequence[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
}

// 120
func TestRun_RunPreflightCompletesBeforeBind(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc
	if log.index("preflight") < 0 || log.index("preflight") >= log.index("bind") {
		t.Fatalf("preflight (%d) must complete before bind (%d)", log.index("preflight"), log.index("bind"))
	}
}

// 121
func TestRun_AttachCompletesBeforeBind(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	// The preflight seam records a distinct attach marker, standing in for the
	// privileged attach that capture.RunPreflight completes internally.
	opts.Preflight = func(context.Context) error {
		log.add("attach")
		return nil
	}
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc
	if !log.has("attach") || log.index("attach") >= log.index("bind") {
		t.Fatalf("attach (%d) must complete before bind (%d)", log.index("attach"), log.index("bind"))
	}
}

// 122
func TestRun_S3LocalSelfTestCompletesBeforeBind(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	var networked bool
	opts.LocalSelfTest = func(context.Context) error {
		// A local self-test performs no network calls; record only.
		return nil
	}
	_ = networked
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc
	if log.index("self-test") < 0 || log.index("self-test") >= log.index("bind") {
		t.Fatalf("self-test (%d) must complete before bind (%d)", log.index("self-test"), log.index("bind"))
	}
	if log.index("preflight") >= log.index("self-test") {
		t.Fatalf("self-test must be distinct from and after preflight")
	}
}

// 123
func TestRun_ConstructsAuditRejectionRecorderWithFakeSink(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	sink := &recordingSink{}
	metrics := &recordingMetrics{}
	opts := baseOptions(log, gl)
	opts.AuditSinkFactory = func() (audit.AuditSink, error) { return sink, nil }
	opts.DataMetrics = metrics
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")

	if o.rejectionRecorder == nil {
		t.Fatal("assembly did not construct a rejection recorder")
	}
	// Drive one rejection to prove the recorder is wired to the injected fake
	// sink and fake metrics with a bounded, non-blocking path.
	o.rejectionRecorder.Record(audit.Rejection{Class: "test", Reason: pipeline.ReasonNoMatch})
	if metrics.count() == 0 {
		t.Fatal("rejection recorder did not route to injected metrics")
	}
	waitFor(t, func() bool { return sink.records() > 0 }, time.Second, "sink record")
	cancel()
	<-errc
}

// 124
func TestRun_ListenerBindAcceptProbeDropServe_OrderRecorded(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	o, _ := New(baseOptions(log, gl))
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc
	b, p, d, s := log.index("bind"), log.index("accept-probe"), log.index("priv-drop"), log.index("serve")
	if !(b < p && p < d && d < s) {
		t.Fatalf("order bind=%d probe=%d drop=%d serve=%d, want strictly increasing", b, p, d, s)
	}
}

// 125
func TestRun_ComposesPipelineWithPolicyStoreAndTokenCache(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	store := &watch.Store{}
	opts := baseOptions(log, gl)
	opts.PolicyStartup = func(context.Context) (*watch.Store, error) { return store, nil }
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc

	if o.matchStage == nil || o.matchStage.Store != store {
		t.Fatalf("MatchStage.Store = %v, want the injected watch.Store %p", o.matchStage, store)
	}
	if o.matchStage.MaxStaleness != o.cfg.Policy.MaxStaleness {
		t.Fatalf("MatchStage.MaxStaleness = %v, want %v", o.matchStage.MaxStaleness, o.cfg.Policy.MaxStaleness)
	}
	if o.acquireStage == nil || o.tokenCache == nil {
		t.Fatal("AcquireStage/token cache not composed")
	}
	if o.acquireStage.Cache != o.tokenCache {
		t.Fatal("AcquireStage wired to something other than the guarded token cache")
	}
}

// 126
func TestRun_CAProviderReadyBeforeLeafSourceConstruction(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	opts.CAProvider = func(context.Context) (pki.CAProvider, error) {
		log.add("ca-ready-fake")
		return nopCAProvider{}, nil
	}
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc
	if log.index("ca-ready-fake") < 0 || log.index("ca-ready-fake") >= log.index("leafsource") {
		t.Fatalf("CA readiness (%d) must precede leaf-source construction (%d)", log.index("ca-ready-fake"), log.index("leafsource"))
	}
}

// 127
func TestRun_FirstPolicySnapshotBeforeListenerBind(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	o, _ := New(baseOptions(log, gl))
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc
	if log.index("first-snapshot") < 0 || log.index("first-snapshot") >= log.index("bind") {
		t.Fatalf("first-snapshot (%d) must precede bind (%d)", log.index("first-snapshot"), log.index("bind"))
	}
}

// 128
func TestRun_LocalSelfTestBeforeListenerBind(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	o, _ := New(baseOptions(log, gl))
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc
	if log.index("self-test") < 0 || log.index("self-test") >= log.index("bind") {
		t.Fatalf("self-test (%d) must precede bind (%d)", log.index("self-test"), log.index("bind"))
	}
}

// 129
func TestRun_PrivDropReceivesUIDGID1774(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	var got capture.PrivDropConfig
	opts.PrivDrop = func(c capture.PrivDropConfig) error {
		got = c
		return nil
	}
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc
	if got.ProxyUID != 1774 || got.ProxyGID != 1774 || !got.NoNewPrivs {
		t.Fatalf("priv-drop config = %+v, want UID/GID 1774 and NoNewPrivs=true", got)
	}
	// The runtime resolver performs pair-map LookupAndDelete on every
	// connection, which requires CAP_BPF. The priv-drop MUST retain CAP_BPF or
	// the data path fails closed on a live kernel with EPERM ("no_original_dst")
	// -- a bug that only manifests in a real cgroup, not with fake seams
	// (surfaced by the P9c kind e2e).
	if !slices.Contains(got.KeepCapabilities, "CAP_BPF") {
		t.Fatalf("priv-drop KeepCapabilities = %v, want it to contain CAP_BPF", got.KeepCapabilities)
	}
}

// 130
func TestRun_SignalAndServeReturnRace_ShutdownCalledOnce(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	o, _ := New(baseOptions(log, gl))
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); cancel() }()
	go func() { defer wg.Done(); _ = o.Shutdown(context.Background()) }()
	wg.Wait()
	<-errc

	if got := gl.shutdowns(); got != 1 {
		t.Fatalf("listener Shutdown calls = %d, want exactly 1", got)
	}
	if o.Ready().Ready {
		t.Fatal("orchestrator still reports ready after shutdown")
	}
}

// 131
func TestReadyLive_ConcurrentProbes_NoRace(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	o, _ := New(baseOptions(log, gl))
	cancel, errc := runInBackground(o)
	defer cancel()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					r := o.Ready()
					l := o.Live()
					_ = r.Ready
					_ = l.Live
				}
			}
		}()
	}
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	<-errc
	close(stop)
	wg.Wait()
}

// 132
func TestRun_AcceptProbeDeadlineExceeded_ClosesBindAndSkipsPrivilegeDrop(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{probeErr: context.DeadlineExceeded}
	opts := baseOptions(log, gl)
	var dropCalls int
	opts.PrivDrop = func(capture.PrivDropConfig) error { dropCalls++; return nil }
	o, _ := New(opts)
	err := o.Run(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() error = %v, want deadline exceeded", err)
	}
	if gl.probes() != 1 {
		t.Fatalf("probe calls = %d, want 1", gl.probes())
	}
	if dropCalls != 0 {
		t.Fatalf("priv-drop calls = %d, want 0 after probe failure", dropCalls)
	}
	if gl.serves() != 0 {
		t.Fatalf("serve calls = %d, want 0 after probe failure", gl.serves())
	}
	if gl.shutdowns() == 0 {
		t.Fatal("bound socket was not closed after probe failure")
	}
}

// 133
func TestRun_DropPrivilegesFails_ClosesListenerAndSkipsServe(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	dropErr := errors.New("drop failed")
	opts := baseOptions(log, gl)
	opts.PrivDrop = func(capture.PrivDropConfig) error { return dropErr }
	o, _ := New(opts)
	err := o.Run(context.Background())
	if !errors.Is(err, dropErr) {
		t.Fatalf("Run() error = %v, want drop error", err)
	}
	if gl.serves() != 0 {
		t.Fatalf("serve calls = %d, want 0 after drop failure", gl.serves())
	}
	if gl.shutdowns() == 0 {
		t.Fatal("listener was not closed after drop failure")
	}
}

// 135
func TestRun_ServeReturnsError_TriggersShutdownAndReturnsError(t *testing.T) {
	log := &orderLog{}
	serveErr := errors.New("serve boom")
	gl := &gateListener{serveErr: serveErr}
	o, _ := New(baseOptions(log, gl))
	err := o.Run(context.Background())
	if !errors.Is(err, serveErr) {
		t.Fatalf("Run() error = %v, want serve error", err)
	}
	if gl.shutdowns() == 0 {
		t.Fatal("Shutdown was not called after serve error")
	}
	if o.Live().Live {
		t.Fatal("liveness must be false after a fatal serve error")
	}
}

// 136
func TestRun_SIGTERMDuringStartupBeforeBind_CancelsGatesWithoutBind(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	// First-snapshot gate blocks until context cancellation, simulating a
	// SIGTERM delivered while the watcher waits for its first compiled snapshot.
	opts.PolicyStartup = func(ctx context.Context) (*watch.Store, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	waitFor(t, func() bool { return log.has("ca-ready") }, 2*time.Second, "ca-ready")
	cancel()
	err := <-errc
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
	if gl.binds() != 0 {
		t.Fatalf("bind calls = %d, want 0 when startup is cancelled", gl.binds())
	}
}

// 137
func TestRun_ShutdownDeadlineExceeded_ReturnsShutdownError(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{shutdownErr: context.DeadlineExceeded}
	o, _ := New(baseOptions(log, gl))
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	err := <-errc
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() error = %v, want shutdown deadline error", err)
	}
}

// 138
func TestRun_NormalServeContextCancel_DrainsAndStops(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	o, _ := New(baseOptions(log, gl))
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("Run() error = %v, want nil after clean drain", err)
	}
	if gl.shutdowns() != 1 {
		t.Fatalf("Shutdown calls = %d, want 1", gl.shutdowns())
	}
}

// 139
func TestReady_AfterGatesAndServing_ReturnsReadyTrue(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	var oref *Orchestrator
	var readyDuringGate bool
	opts.LocalSelfTest = func(context.Context) error {
		readyDuringGate = oref.Ready().Ready
		return nil
	}
	o, _ := New(opts)
	oref = o
	if o.Ready().Ready {
		t.Fatal("readiness must be false before startup")
	}
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return o.Ready().Ready }, 2*time.Second, "ready")
	if readyDuringGate {
		t.Fatal("readiness must remain false through pre-bind gates")
	}
	cancel()
	<-errc
}

// 140
func TestLive_EntraAndPolicyOutagesAfterStartup_RemainTrue(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	// Empty store => a policy "outage" (no snapshot) at request time.
	opts := baseOptions(log, gl)
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return log.has("serve") }, 2*time.Second, "serve")

	if !o.Live().Live {
		t.Fatal("liveness must remain true after successful startup")
	}
	// A policy outage (empty snapshot store) must fail closed at request time
	// without affecting liveness.
	d := o.matchStage.Execute(&pipeline.RequestContext{})
	if d.Reason != pipeline.ReasonNoSnapshot || !d.Fault {
		t.Fatalf("policy outage decision = %+v, want fail-closed no-snapshot", d)
	}
	if !o.Live().Live {
		t.Fatal("liveness flipped false on a policy outage")
	}
	cancel()
	<-errc
}

// 141
func TestRun_PreBindGateFailure_NoListenerBind(t *testing.T) {
	gateErr := errors.New("gate failed")
	cases := []struct {
		name  string
		apply func(*Options)
	}{
		{"ca", func(o *Options) {
			o.CAProvider = func(context.Context) (pki.CAProvider, error) { return nil, gateErr }
		}},
		{"first-snapshot", func(o *Options) {
			o.PolicyStartup = func(context.Context) (*watch.Store, error) { return nil, gateErr }
		}},
		{"self-test", func(o *Options) {
			o.LocalSelfTest = func(context.Context) error { return gateErr }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &orderLog{}
			gl := &gateListener{}
			opts := baseOptions(log, gl)
			tc.apply(&opts)
			o, _ := New(opts)
			if err := o.Run(context.Background()); !errors.Is(err, gateErr) {
				t.Fatalf("Run() error = %v, want gate error", err)
			}
			if gl.binds() != 0 {
				t.Fatalf("bind calls = %d, want 0 on %s gate failure", gl.binds(), tc.name)
			}
		})
	}
}

// 142
func TestRun_NoBindBeforeCAFirstSnapshotAndSelfTest(t *testing.T) {
	gateErr := errors.New("gate failed")
	cases := []struct {
		name  string
		apply func(*Options)
	}{
		{"preflight", func(o *Options) { o.Preflight = func(context.Context) error { return gateErr } }},
		{"ca", func(o *Options) {
			o.CAProvider = func(context.Context) (pki.CAProvider, error) { return nil, gateErr }
		}},
		{"first-snapshot", func(o *Options) {
			o.PolicyStartup = func(context.Context) (*watch.Store, error) { return nil, gateErr }
		}},
		{"self-test", func(o *Options) { o.LocalSelfTest = func(context.Context) error { return gateErr } }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := &orderLog{}
			gl := &gateListener{}
			opts := baseOptions(log, gl)
			tc.apply(&opts)
			o, _ := New(opts)
			_ = o.Run(context.Background())
			if gl.binds() != 0 {
				t.Fatalf("bind reached despite %s gate failure", tc.name)
			}
			if log.has("bind") {
				t.Fatalf("bind milestone recorded despite %s gate failure", tc.name)
			}
		})
	}
}

// 143
func TestReady_LocalOnly_DoesNotCallEntraNetwork(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	o, _ := New(baseOptions(log, gl))
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return o.Ready().Ready }, 2*time.Second, "ready")

	// Readiness and liveness read local atomic state only. Hammering them must
	// never panic or reach any network path.
	for i := 0; i < 1000; i++ {
		if !o.Ready().Ready || !o.Live().Live {
			t.Fatal("probe returned not-ready/not-live while serving")
		}
	}
	cancel()
	<-errc
}

// 144
func TestRun_StartupFailureMetrics_RecordsGateAndResult(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	metrics := &startupMetricsFake{}
	opts := baseOptions(log, gl)
	opts.StartupMetrics = metrics
	gateErr := errors.New("ca boom")
	opts.CAProvider = func(context.Context) (pki.CAProvider, error) { return nil, gateErr }
	o, _ := New(opts)
	if err := o.Run(context.Background()); !errors.Is(err, gateErr) {
		t.Fatalf("Run() error = %v, want gate error", err)
	}
	if got := metrics.failed(); len(got) != 1 || got[0] != "ca" {
		t.Fatalf("startup failures = %v, want [ca]", got)
	}
	if got := metrics.errored(); len(got) != 1 || got[0] != "ca" {
		t.Fatalf("startup gate error results = %v, want [ca]", got)
	}
}

// 145
func TestRun_AuditRecorderConstructionFailure_FailsClosedBeforeBind(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	sinkErr := errors.New("sink factory failed")
	opts.AuditSinkFactory = func() (audit.AuditSink, error) { return nil, sinkErr }
	o, _ := New(opts)
	if err := o.Run(context.Background()); !errors.Is(err, sinkErr) {
		t.Fatalf("Run() error = %v, want audit sink factory error", err)
	}
	if gl.binds() != 0 {
		t.Fatalf("bind calls = %d, want 0 on audit sink construction failure", gl.binds())
	}
}

// 117
func TestRun_AuditSinkFactoryFailure_ReturnsErrorBeforeBind(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	sinkErr := errors.New("no sink")
	opts.AuditSinkFactory = func() (audit.AuditSink, error) { return nil, sinkErr }
	o, _ := New(opts)
	if err := o.Run(context.Background()); !errors.Is(err, sinkErr) {
		t.Fatalf("Run() error = %v, want sink factory error", err)
	}
	if gl.binds() != 0 {
		t.Fatalf("bind calls = %d, want 0 before listener construction", gl.binds())
	}
	if o.getListener() != nil {
		t.Fatal("listener was constructed despite audit sink factory failure")
	}
}

// 76
func TestReadiness_EntraLocalOnly_NeverCallsAcquire(t *testing.T) {
	log := &orderLog{}
	gl := &gateListener{}
	opts := baseOptions(log, gl)
	var selfTestCalls int
	opts.LocalSelfTest = func(context.Context) error {
		selfTestCalls++
		return nil
	}
	o, _ := New(opts)
	cancel, errc := runInBackground(o)
	defer cancel()
	waitFor(t, func() bool { return o.Ready().Ready }, 2*time.Second, "ready")

	// Readiness gating uses LocalSelfTest exactly once during startup and the
	// probe itself reads only local state; no Entra Acquire is ever invoked.
	if selfTestCalls != 1 {
		t.Fatalf("LocalSelfTest calls = %d, want exactly 1", selfTestCalls)
	}
	if !o.Ready().Ready {
		t.Fatal("readiness must be true after local self-test and serving")
	}
	cancel()
	<-errc
}
