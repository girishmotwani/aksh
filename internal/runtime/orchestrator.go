// Package runtime hosts the aksh-proxy Orchestrator: the daemon lifecycle spine
// that runs the full fail-closed startup gate sequence, composes the data-plane
// handler chain, binds the loopback listener, serves accepted connections, and
// shuts down cleanly on signal.
//
// The fixed startup order (design §"Startup Flow") is:
//
//	config.Validate -> capture.RunPreflight+attach -> construct resolvers ->
//	CA ready -> first policy snapshot -> entra.LocalSelfTest -> compose
//	(audit recorder, token cache, pipeline, TLS terminator, upstream, request
//	path) -> listener.Bind -> AcceptProbe (Phase-B) -> DropPrivileges 1774 ->
//	Serve -> Shutdown on SIGTERM.
//
// Every gate is an injectable seam on Options; a nil seam defaults to a benign
// success so the skeleton lifecycle keeps working, and production main.go wires
// the real fail-closed implementations. Bind never happens before CA, first
// snapshot, and local self-test all succeed; Serve never happens unless
// privilege drop to UID/GID 1774 succeeds.
package runtime

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/dataplane/tlsterm"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/pki"
	"github.com/girishmotwani/aksh/internal/policy/watch"
	"github.com/girishmotwani/aksh/internal/token"
)

const (
	// shutdownTimeout bounds how long Run waits for in-flight handlers to drain
	// after context cancellation before returning.
	shutdownTimeout = 30 * time.Second
	// acceptProbeTimeout is the Phase-B redirect-probe deadline budget.
	acceptProbeTimeout = 5 * time.Second
	// proxyUID / proxyGID are the reserved unprivileged identity the proxy runs
	// under after the privilege drop (design invariant).
	proxyUID uint32 = 1774
	proxyGID uint32 = 1774
)

// ProbeStatus is the readiness/liveness result surfaced to health probes.
type ProbeStatus struct {
	Ready  bool
	Live   bool
	Reason string
}

// Listener is the minimal bind/serve/shutdown surface the Orchestrator drives.
// The production *listener.Listener satisfies it; tests inject fakes.
type Listener interface {
	Bind() error
	Serve(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// probeListener is the optional Phase-B probe surface. The real
// *listener.Listener implements it; a listener that does not (a minimal
// skeleton fake) simply skips the probe.
type probeListener interface {
	AcceptProbe(deadline time.Time) (net.Conn, error)
}

// ListenerFactory constructs a Listener for the given config and handler. It is
// an injectable seam so tests can substitute a fake listener.
type ListenerFactory func(cfg config.Config, h listener.ConnHandler, log *slog.Logger) (Listener, error)

// StartupMetricsRecorder records fatal startup-gate outcomes with bounded gate
// and result labels only. The concrete Prometheus backend arrives separately;
// no unbounded or sensitive label ever crosses this seam.
type StartupMetricsRecorder interface {
	// RecordStartupFailure records one aksh_runtime_startup_fail_total event.
	RecordStartupFailure(gate string)
	// RecordStartupGateResult records aksh_runtime_startup_gate_seconds for the
	// gate with the given bounded result ("error").
	RecordStartupGateResult(gate, result string, d time.Duration)
}

// CaptureHandleCloser is the minimal capture-teardown surface the orchestrator
// drives on drain (reverse-order, before the control plane stops). The eBPF
// *capture.Handle satisfies it; run() may inject a fake for the lifecycle tests
// so no kernel is required. Kept as an interface (not a concrete *capture.Handle)
// so the drain seam is neutrally testable (S5, #106/#108/#109).
type CaptureHandleCloser interface {
	Close() error
}

// Options configures a new Orchestrator. Every gate seam is optional; a nil
// seam defaults to a benign success (or a functional no-op object) so the
// skeleton lifecycle keeps working and production main.go supplies the real
// fail-closed implementations.
type Options struct {
	Config config.Config
	Log    *slog.Logger
	// ListenerFactory constructs the data-plane listener. When nil, the
	// production loopback listener factory is used.
	ListenerFactory ListenerFactory
	// Recorder observes ordered startup milestones for tests. Nil discards.
	Recorder func(event string)
	// Preflight runs capture.RunPreflight plus attach before bind.
	Preflight func(context.Context) error
	// ConstructResolvers builds the cgroup and destination resolvers.
	ConstructResolvers func(context.Context) error
	// CAProvider loads or generates the pod CA and reports it ready.
	CAProvider func(context.Context) (pki.CAProvider, error)
	// PolicyStartup starts the policy watcher and waits for the first snapshot.
	PolicyStartup func(context.Context) (*watch.Store, error)
	// LocalSelfTest runs entra.LocalSelfTest (no network).
	LocalSelfTest func(context.Context) error
	// AuditSinkFactory constructs the audit sink; a failure fails startup.
	AuditSinkFactory func() (audit.AuditSink, error)
	// DataMetrics is the typed metrics recorder feeding the S6 audit path
	// (rejection recorder) and the dataplane call sites, which now consume the
	// typed recorder directly. Nil defaults to a typed no-op.
	DataMetrics audit.MetricsRecorder
	// PrivDrop drops privileges to UID/GID 1774. Nil defaults to a no-op.
	PrivDrop func(capture.PrivDropConfig) error
	// StartupMetrics records fatal gate outcomes. Nil defaults to a no-op.
	StartupMetrics StartupMetricsRecorder
	// CaptureHandle is the eBPF capture Handle whose Close() releases the
	// attach on drain. Nil-safe: when nil (all skeleton/orchestrator tests)
	// the teardown seam is skipped. S5 wires the attach-loss fail-closed
	// trigger and the eager LoadAndAttach that produces this Handle.
	CaptureHandle CaptureHandleCloser
	// ControlPlaneStart starts the control-plane HTTP server BEFORE the
	// data-plane listener binds (design step 8 before step 9). A nil seam is a
	// benign no-op (skeleton/orchestrator tests). A non-nil failure aborts Run
	// fail-closed with no data-plane Bind (#77/#78). run() supplies
	// (*ControlPlaneServer).Start.
	ControlPlaneStart func(context.Context) error
	// ControlPlaneShutdown stops the control-plane server LAST on drain, after
	// the data-plane listener drains and the capture Handle closes
	// (reverse-order teardown, #109). run() supplies
	// (*ControlPlaneServer).Shutdown.
	ControlPlaneShutdown func(context.Context) error
	// RootCAs is the upstream TLS trust pool built in Go by main.go from the pod
	// CA public material and the mounted upstream CA. Nil means the direct
	// dialer falls back to the host system roots.
	RootCAs *x509.CertPool
}

// Orchestrator owns the daemon lifecycle spine.
type Orchestrator struct {
	cfg     config.Config
	log     *slog.Logger
	factory ListenerFactory
	rec     func(string)

	preflight      func(context.Context) error
	resolvers      func(context.Context) error
	caProvider     func(context.Context) (pki.CAProvider, error)
	policyStartup  func(context.Context) (*watch.Store, error)
	selfTest       func(context.Context) error
	auditSink      func() (audit.AuditSink, error)
	dataMetrics    audit.MetricsRecorder
	privDrop       func(capture.PrivDropConfig) error
	startupMetrics StartupMetricsRecorder
	captureHandle  CaptureHandleCloser

	controlPlaneStart    func(context.Context) error
	controlPlaneShutdown func(context.Context) error

	rootCAs *x509.CertPool

	ready  atomic.Bool
	live   atomic.Bool
	reason atomic.Value // string

	mu           sync.Mutex
	ln           Listener
	shutdownOnce sync.Once
	shutdownErr  error

	// Composed artifacts, retained for white-box test observability.
	store             *watch.Store
	matchStage        *pipeline.MatchStage
	acquireStage      *pipeline.AcquireStage
	pipeline          *pipeline.Pipeline
	tokenCache        *token.CachingTokenCache
	leafSource        *tlsterm.CachedLeafSource
	rejectionRecorder *audit.RejectionRecorder
}

// New constructs an Orchestrator, defaulting a nil logger to slog.Default, a
// nil ListenerFactory to the production loopback factory, and every nil gate
// seam to a benign success or functional no-op.
func New(opts Options) (*Orchestrator, error) {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.ListenerFactory == nil {
		opts.ListenerFactory = ProductionListenerFactory
	}
	if opts.Recorder == nil {
		opts.Recorder = func(string) {}
	}
	if opts.Preflight == nil {
		opts.Preflight = func(context.Context) error { return nil }
	}
	if opts.ConstructResolvers == nil {
		opts.ConstructResolvers = func(context.Context) error { return nil }
	}
	if opts.CAProvider == nil {
		opts.CAProvider = func(context.Context) (pki.CAProvider, error) { return nopCAProvider{}, nil }
	}
	if opts.PolicyStartup == nil {
		opts.PolicyStartup = func(context.Context) (*watch.Store, error) { return &watch.Store{}, nil }
	}
	if opts.LocalSelfTest == nil {
		opts.LocalSelfTest = func(context.Context) error { return nil }
	}
	if opts.AuditSinkFactory == nil {
		opts.AuditSinkFactory = defaultAuditSinkFactory
	}
	if opts.DataMetrics == nil {
		opts.DataMetrics = noopTypedMetrics{}
	}
	if opts.PrivDrop == nil {
		opts.PrivDrop = func(capture.PrivDropConfig) error { return nil }
	}
	if opts.StartupMetrics == nil {
		opts.StartupMetrics = noopStartupMetrics{}
	}
	if opts.ControlPlaneStart == nil {
		opts.ControlPlaneStart = func(context.Context) error { return nil }
	}
	if opts.ControlPlaneShutdown == nil {
		opts.ControlPlaneShutdown = func(context.Context) error { return nil }
	}

	o := &Orchestrator{
		cfg:            opts.Config,
		log:            opts.Log,
		factory:        opts.ListenerFactory,
		rec:            opts.Recorder,
		preflight:      opts.Preflight,
		resolvers:      opts.ConstructResolvers,
		caProvider:     opts.CAProvider,
		policyStartup:  opts.PolicyStartup,
		selfTest:       opts.LocalSelfTest,
		auditSink:      opts.AuditSinkFactory,
		dataMetrics:    opts.DataMetrics,
		privDrop:       opts.PrivDrop,
		startupMetrics: opts.StartupMetrics,
		captureHandle:  opts.CaptureHandle,

		controlPlaneStart:    opts.ControlPlaneStart,
		controlPlaneShutdown: opts.ControlPlaneShutdown,

		rootCAs: opts.RootCAs,
	}
	o.live.Store(true)
	o.reason.Store("starting")
	return o, nil
}

// Run drives the full fail-closed startup gate sequence in fixed order, then
// serves until ctx is cancelled (SIGTERM) or Serve returns, then drains. Any
// pre-bind gate failure returns the error with zero listener Bind calls.
func (o *Orchestrator) Run(ctx context.Context) error {
	if err := o.cfg.Validate(); err != nil {
		return o.fail("config", err)
	}
	o.rec("config-validated")

	if err := o.runGate(ctx, "preflight", o.preflight); err != nil {
		return err
	}
	if err := o.runGate(ctx, "resolvers", o.resolvers); err != nil {
		return err
	}

	ca, err := o.caProvider(ctx)
	if err != nil {
		return o.fail("ca", err)
	}
	o.rec("ca-ready")

	store, err := o.policyStartup(ctx)
	if err != nil {
		return o.fail("first-snapshot", err)
	}
	o.store = store
	o.rec("first-snapshot")

	if err := o.runGate(ctx, "self-test", o.selfTest); err != nil {
		return err
	}

	sink, err := o.auditSink()
	if err != nil {
		return o.fail("audit-recorder", err)
	}
	o.rec("audit-recorder")

	handler, err := o.assemble(ca, store, sink)
	if err != nil {
		return o.fail("compose", err)
	}
	o.rec("compose")

	// A SIGTERM delivered while the pre-bind gates ran must abort before any
	// socket is opened, so re-check cancellation immediately before Bind.
	if err := ctx.Err(); err != nil {
		return o.fail("bind", err)
	}

	// Control-plane start-before-serve (design step 8 before step 9): the
	// control-plane HTTP server must be listening BEFORE the data-plane binds,
	// so a bind/start failure aborts fail-closed with no data-plane socket ever
	// opened (#77/#78). It is torn down last on drain (#109).
	if err := o.controlPlaneStart(ctx); err != nil {
		return o.fail("control-plane", err)
	}
	o.rec("control-plane")

	ln, err := o.factory(o.cfg, handler, o.log)
	if err != nil {
		// The control plane already started (above); a listener-factory failure
		// must tear it down in reverse order rather than leak the running HTTP
		// server (#109). drain() is a no-op for the not-yet-set listener.
		o.failNoReturn("listener", err)
		o.drain()
		return err
	}
	o.setListener(ln)

	if err := ln.Bind(); err != nil {
		// Bind failed after the control plane started: reverse-order drain
		// releases the (partially) bound listener and stops the control plane
		// (#109) instead of leaving it running.
		o.failNoReturn("bind", err)
		o.drain()
		return err
	}
	o.rec("bind")

	if err := o.acceptProbe(ln); err != nil {
		return err
	}

	if err := o.privDrop(capture.PrivDropConfig{
		ProxyUID: proxyUID,
		ProxyGID: proxyGID,
		// Retain CAP_BPF across the drop: the runtime destination resolver
		// performs a pair-map LookupAndDelete on every accepted connection,
		// which the kernel gates on CAP_BPF. Without this the data path fails
		// closed with EPERM ("no_original_dst") on a live kernel -- matching the
		// design's own preflight P13 (capture/preflight.go), and surfaced by the
		// P9c kind e2e where a fake privDrop seam had hidden it.
		KeepCapabilities: []string{"CAP_BPF"},
		NoNewPrivs:       true,
	}); err != nil {
		o.failNoReturn("priv-drop", err)
		o.drain()
		return err
	}
	o.rec("priv-drop")

	o.setReady(true, "serving")
	o.rec("serve")
	return o.serve(ctx, ln)
}

// acceptProbe runs the Phase-B redirect probe when the listener supports it. A
// deadline-exceeded (or any probe) failure closes the bound socket and returns
// the error, so privilege drop and Serve are never reached.
func (o *Orchestrator) acceptProbe(ln Listener) error {
	pl, ok := ln.(probeListener)
	if !ok {
		return nil
	}
	conn, err := pl.AcceptProbe(time.Now().Add(acceptProbeTimeout))
	if err != nil {
		o.failNoReturn("accept-probe", err)
		o.drain()
		return err
	}
	if conn != nil {
		_ = conn.Close()
	}
	o.rec("accept-probe")
	return nil
}

// serve launches Serve and drains on ctx cancellation, a serve error, or a
// serve return. It mirrors the skeleton drain semantics over the full pipeline.
func (o *Orchestrator) serve(ctx context.Context, ln Listener) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- ln.Serve(ctx) }()

	select {
	case <-ctx.Done():
		o.log.Info("aksh-proxy: shutdown signal received, draining")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		shutdownErr := o.Shutdown(shutdownCtx)
		select {
		case sErr := <-serveErr:
			if sErr != nil && !errors.Is(sErr, context.Canceled) && !errors.Is(sErr, context.DeadlineExceeded) {
				o.log.Warn("aksh-proxy: serve returned error during shutdown", "error", sErr)
			}
		case <-shutdownCtx.Done():
			o.log.Warn("aksh-proxy: serve did not return before shutdown deadline")
		}
		return shutdownErr
	case sErr := <-serveErr:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if sErr != nil && ctx.Err() == nil {
			o.failNoReturn("serve", sErr)
			_ = o.Shutdown(shutdownCtx)
			return sErr
		}
		return o.Shutdown(shutdownCtx)
	}
}

// runGate executes a pass/fail startup gate seam, recording the milestone on
// success and the fatal metrics on failure.
func (o *Orchestrator) runGate(ctx context.Context, name string, fn func(context.Context) error) error {
	if err := fn(ctx); err != nil {
		return o.fail(name, err)
	}
	o.rec(name)
	return nil
}

// Shutdown stops the listener and drains in-flight handlers. It is idempotent:
// even under a concurrent SIGTERM and Serve-return race the underlying listener
// Shutdown is invoked at most once.
func (o *Orchestrator) Shutdown(ctx context.Context) error {
	o.setReady(false, "shutting down")
	o.shutdownOnce.Do(func() {
		if ln := o.getListener(); ln != nil {
			o.shutdownErr = ln.Shutdown(ctx)
		}
		// Reverse-order teardown seam: after the data-plane listener drains,
		// release the eBPF capture attach. Nil-safe so every existing
		// orchestrator test (which injects no CaptureHandle) is unchanged. The
		// attach-loss fail-closed trigger + Run integration is S5 (#102-#109).
		if o.captureHandle != nil {
			_ = o.captureHandle.Close()
		}
		// Control-plane stops LAST (reverse of startup step 8): the data-plane
		// listener drained first, then capture tore down, so /metrics and
		// /readyz stay scrapeable for as long as possible (#109).
		if o.controlPlaneShutdown != nil {
			_ = o.controlPlaneShutdown(ctx)
		}
	})
	return o.shutdownErr
}

// drain runs a bounded Shutdown on a fresh deadline, used on pre-serve failure
// paths (probe or privilege-drop failure) to release the bound socket.
func (o *Orchestrator) drain() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	_ = o.Shutdown(shutdownCtx)
}

// Ready reports readiness: true only after CA, first snapshot, local self-test,
// bind, probe, privilege drop, and serving readiness. It reads local atomic
// state only and never calls the Entra network.
func (o *Orchestrator) Ready() ProbeStatus { return o.status() }

// Live reports liveness: true from construction until a fatal startup or serve
// failure. Entra and policy outages after startup do not clear it, and a
// cleanly draining process stays live.
func (o *Orchestrator) Live() ProbeStatus { return o.status() }

func (o *Orchestrator) status() ProbeStatus {
	reason, _ := o.reason.Load().(string)
	return ProbeStatus{Ready: o.ready.Load(), Live: o.live.Load(), Reason: reason}
}

func (o *Orchestrator) setReady(ready bool, reason string) {
	o.ready.Store(ready)
	o.reason.Store(reason)
}

// fail marks the process not-ready and not-live, records the failure metrics,
// and returns err for propagation to main.
func (o *Orchestrator) fail(gate string, err error) error {
	o.failNoReturn(gate, err)
	return err
}

// failNoReturn is fail without the error return, for paths that must also drain
// before propagating. It records both fatal startup metrics.
func (o *Orchestrator) failNoReturn(gate string, err error) {
	o.ready.Store(false)
	o.live.Store(false)
	o.reason.Store(gate + " failed")
	o.startupMetrics.RecordStartupFailure(gate)
	o.startupMetrics.RecordStartupGateResult(gate, "error", 0)
	o.log.Error("aksh-proxy: startup gate failed", "gate", gate, "error", err)
}

func (o *Orchestrator) setListener(ln Listener) {
	o.mu.Lock()
	o.ln = ln
	o.mu.Unlock()
}

func (o *Orchestrator) getListener() Listener {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.ln
}
