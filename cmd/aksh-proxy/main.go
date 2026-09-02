// Command aksh-proxy is the S8 proxy-runtime daemon entrypoint. It loads and
// validates configuration, runs the P1-P8 capture environment preflight, then
// performs the eager eBPF LoadAndAttach, builds the shared metrics
// registry/recorder, the BPF destination resolver, and the control-plane
// server, then drives the runtime.Orchestrator lifecycle: the full fail-closed
// startup gate sequence (validate-only capture preflight, CA ready, first
// policy snapshot, local self-test), data-plane assembly, control-plane
// start-before-bind, bind of the loopback listener, Phase-B accept probe,
// privilege drop to UID/GID 1774, serve, and reverse-order drain on SIGTERM.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
	"github.com/girishmotwani/aksh/internal/pki"
	"github.com/girishmotwani/aksh/internal/policy/watch"
	"github.com/girishmotwani/aksh/internal/runtime"
	"github.com/girishmotwani/aksh/internal/token/entra"
)

// deps holds the injectable seams for run so tests can substitute fakes for the
// production wiring. Every production seam has a benign default so the skeleton
// lifecycle tests (config-validation, SIGTERM drain) stay hermetic without a
// kernel or a live cluster; production mainRun injects the real fail-closed
// implementations.
type deps struct {
	loadConfig func() (config.Config, error)
	log        *slog.Logger

	// deriveCgroupCandidate derives the pod cgroup candidate path (design step:
	// cgroup-in-Go before validate). The benign default returns ("", nil) so
	// lifecycle tests stay hermetic.
	deriveCgroupCandidate func(hostMount, procCgroupPath string) (string, error)
	// newPodCgroupResolver constructs the resolver from cfg capture fields. The
	// benign default returns a passthrough that echoes the already-set
	// cfg.Capture.PodPath.
	newPodCgroupResolver func(cfg config.Config) (podCgroupResolver, error)
	// upstreamTrustPool is the Go-built upstream TLS trust pool threaded into
	// runtime.Options.RootCAs so the direct dialer trusts the pod CA and the
	// mounted upstream CA. Nil (lifecycle tests) falls back to system roots.
	upstreamTrustPool *x509.CertPool

	// loadAndAttach performs the eager eBPF LoadAndAttach (design step 5). The
	// benign default returns a no-op Handle so lifecycle tests need no kernel.
	loadAndAttach func(ctx context.Context, opts *capture.Options) (captureHandle, error)
	// envPreflight runs the P1-P8 environment-validation gates
	// (capture.RunEnvironmentPreflight) BEFORE the eager LoadAndAttach, so a bad
	// environment - a mis-scoped pod cgroup, a missing capability, a cgo build -
	// is rejected fail-closed before any kernel object is created. The benign
	// default succeeds so lifecycle tests need no kernel; production injects the
	// real fail-closed gates.
	envPreflight func(ctx context.Context, opts *capture.Options) error
	// newResolver builds the BPF destination resolver from Handle.PairMap()
	// (design step 6). Only used when factory is nil. Default = platform
	// capture.NewBPFDestinationResolver.
	newResolver func(pairMap any, opts capture.Options) (dataplane.DestinationResolver, error)
	// factory, when set, is used verbatim (skeleton/lifecycle tests). When nil
	// run() builds the production factory from the resolver + recorder.
	factory runtime.ListenerFactory
	// newOrchestrator constructs the orchestrator (design step 7). Default =
	// runtime.New. Tests override it to observe eager-load-before-New (#102).
	newOrchestrator func(runtime.Options) (orchestratorRunner, error)
	// newControlPlane constructs the control-plane server with the shared
	// registry and the orchestrator as ProbeSource (design step 8, address
	// reconciliation). Default = benign no-op (no socket). Production =
	// runtime.NewControlPlaneServerFromConfig.
	newControlPlane func(cp config.ControlPlaneConfig, reg prometheus.Gatherer, probes runtime.ProbeSource) (controlPlane, error)

	// newPreflight builds the validate-only preflight gate from the Handle.
	// Default = benign nil. Production = productionPreflight.
	newPreflight func(h captureHandle) func(context.Context) error
	// newPolicyStartup builds the policy first-snapshot gate. Default = benign
	// empty store. Production = productionPolicyStartup.
	newPolicyStartup func(cfg config.Config, log *slog.Logger, failClosed func(error), metrics watch.Metrics) func(context.Context) (*watch.Store, error)

	caProvider    func(context.Context) (pki.CAProvider, error)
	localSelfTest func(context.Context) error
	auditSink     func() (audit.AuditSink, error)
	privDrop      func(capture.PrivDropConfig) error

	// metrics records the pod-cgroup resolution failure counter. run() builds
	// the shared serving recorder before cgroup resolution and adopts it here
	// when metrics is nil; tests inject a fake recorder in its place.
	metrics audit.MetricsRecorder
}

// run is the testable entrypoint. It returns a process exit code: 0 on a clean
// drain, non-zero on config load/validation, eager load/attach, control-plane
// wiring, or lifecycle failure. The canonical order (design "Startup Sequence")
// is authoritative: load config -> shared registry+recorder -> derive+resolve
// pod cgroup (sets Capture.PodPath) -> validate config -> capture options ->
// eager LoadAndAttach (before runtime.New) -> resolver -> factory ->
// orchestrator -> control-plane (start-before-bind) -> Run.
func run(ctx context.Context, d deps) int {
	d = withDefaults(d)
	log := d.log

	// (a) Load config. Validation is deferred until after the pod cgroup path is
	// derived below, because Capture.PodPath is not injected but resolved in Go.
	cfg, err := d.loadConfig()
	if err != nil {
		log.Error("aksh-proxy: config load failed", "error", err)
		return 1
	}

	// (b) One registry, (c) one recorder - the shared identity that guarantees
	// counters written by dispatch are the counters scraped at /metrics. It is
	// built BEFORE cgroup resolution so aksh_proxy_cgroup_resolution_errors_total
	// increments on the real recorder (not a no-op) even on the fail-closed
	// cgroup path. Tests inject d.metrics to observe the counter; production
	// leaves it nil and adopts this recorder.
	reg := prometheus.NewRegistry()
	recorder, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		log.Error("aksh-proxy: metrics recorder init failed", "error", err)
		return 1
	}
	if d.metrics == nil {
		d.metrics = recorder
	}

	// Resolve the pod cgroup path in Go BEFORE config validation, then set
	// cfg.Capture.PodPath so Validate/LoadAndAttach operate on the resolved
	// path. A failure at any step aborts fail-closed before Validate, the eager
	// LoadAndAttach, and any socket bind.
	res, err := d.newPodCgroupResolver(cfg)
	if err != nil {
		d.metrics.ProxyCgroupResolutionError()
		log.Error("aksh-proxy: capture pod cgroup resolution failed", "step", "resolver_init", "error", err)
		return 1
	}
	candidate, derr := d.deriveCgroupCandidate(cfg.Capture.HostCgroupMount, cfg.Capture.ProcCgroupPath)
	var resolved string
	switch {
	case derr == nil:
		// Case A: /proc/self/cgroup already names the container cgroup, so the
		// pod candidate is its parent. Validate it against the real host mount.
		resolved, err = res.ResolvePodCgroup(candidate)
		if err != nil {
			d.metrics.ProxyCgroupResolutionError()
			log.Error("aksh-proxy: capture pod cgroup resolution failed", "step", "resolve", "error", err)
			return 1
		}
	case errors.Is(derr, errV2PathHasNoPodParent):
		// Case B: a private cgroup namespace (the kubelet default on cgroup v2,
		// e.g. AKS) makes /proc/self/cgroup read "0::/", so the pod cgroup sits
		// above the namespace root and cannot be named from within. Recover it
		// by inode instead (design section 6.1.2 case B). DiscoverPodCgroup runs
		// the bounded host-mount walk and the same V1-V8 validation, so the
		// attach point is still derived from the kernel's view, never asserted
		// by the pod's own configuration.
		log.Info("aksh-proxy: pod cgroup is namespaced (0::/); recovering it by inode discovery", "deriveError", derr)
		resolved, err = res.DiscoverPodCgroup()
		if err != nil {
			d.metrics.ProxyCgroupResolutionError()
			log.Error("aksh-proxy: capture pod cgroup resolution failed", "step", "discover", "error", err)
			return 1
		}
	default:
		// Any other derivation failure (unreadable proc file, no v2 line, path
		// escape) is a genuine fail-closed condition.
		d.metrics.ProxyCgroupResolutionError()
		log.Error("aksh-proxy: capture pod cgroup resolution failed", "step", "derive", "error", derr)
		return 1
	}
	if resolved != "" {
		log.Info("aksh-proxy: capture pod cgroup resolved", "podPath", resolved, "previous", cfg.Capture.PodPath)
		cfg.Capture.PodPath = resolved
	} else {
		// An empty resolver result is not silently accepted: it is surfaced so a
		// stale or manually supplied Capture.PodPath does not slip through
		// unnoticed. cfg.Validate below still fails closed if PodPath is unset.
		log.Warn("aksh-proxy: pod cgroup resolver returned an empty path; retaining configured PodPath", "podPath", cfg.Capture.PodPath)
	}

	if err := cfg.Validate(); err != nil {
		log.Error("aksh-proxy: config validation failed", "error", err)
		return 1
	}

	// (b) One registry, (c) one recorder - constructed above, before the pod
	// cgroup resolution seam, so the resolution-error counter is real in
	// production. (d) Map config -> capture.Options with the recorder as the
	// mandatory metrics sink.
	captureOpts := config.CaptureOptionsFromConfig(ctx, cfg, recorder)

	// Every bypass prefix is a destination aksh will not observe or enforce
	// on. Log it at WARN, once, with the prefixes named: an operator debugging
	// "why was this request never audited" should find the answer in the
	// startup log rather than by reading the pod spec.
	if len(captureOpts.BypassCIDRs) > 0 {
		prefixes := make([]string, 0, len(captureOpts.BypassCIDRs))
		for _, p := range captureOpts.BypassCIDRs {
			prefixes = append(prefixes, p.String())
		}
		log.Warn("aksh-proxy: capture bypass configured; traffic to these prefixes is NOT captured, policed or audited",
			"bypass_cidrs", strings.Join(prefixes, ","))
	}

	// (d.1) Environment preflight (gates P1-P8) BEFORE the eager LoadAndAttach.
	// This is the fail-closed environment gate the eager attach lacks: it
	// validates the pod-cgroup scope (V1-V8), the kernel floor, cgroup2, bpffs,
	// capabilities and cgo BEFORE any kernel object exists, so a bad
	// AKSH_CAPTURE_POD_PATH cannot be attached to. A *PreflightError is preserved
	// so its E_* code reaches the operator; any failure aborts non-zero without
	// attaching.
	if err := d.envPreflight(ctx, &captureOpts); err != nil {
		log.Error("aksh-proxy: capture environment preflight failed; refusing to start", "error", err)
		return 1
	}

	// (e) Eager LoadAndAttach BEFORE runtime.New (#102). A load/attach failure
	// aborts fail-closed before ANY bind (#103). Close is deferred immediately
	// so every subsequent failure path releases the attach (SI-S4-1, #103-#105);
	// it is idempotent via the Handle's sync.Once.
	handle, err := d.loadAndAttach(ctx, &captureOpts)
	if err != nil {
		log.Error("aksh-proxy: capture load/attach failed; refusing to start", "error", err)
		return 1
	}
	defer func() { _ = handle.Close() }()

	// serveCtx is cancelled by the attach-loss fail-closed trigger and by a
	// policy watcher fatal error so the orchestrator drains cleanly.
	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()

	// (j) attach-loss during serve -> fail-closed cancel of serve ctx + drain
	// (#107/#108). Replaces the removed loader_linux.go os.Exit(1).
	handle.OnAttachLoss(func(e error) {
		log.Error("aksh-proxy: eBPF attach lost during serve; failing closed", "error", e)
		cancelServe()
	})

	// (f) Resolver from Handle.PairMap() and the production factory. A pre-built
	// factory (skeleton/lifecycle tests) is used verbatim.
	factory := d.factory
	if factory == nil {
		resolver, rerr := d.newResolver(handle.PairMap(), captureOpts)
		if rerr != nil {
			log.Error("aksh-proxy: destination resolver init failed", "error", rerr)
			return 1
		}
		factory = runtime.MakeProductionListenerFactory(resolver, recorder)
	}

	// failClosed is the policy-watcher fatal-error hook: log + cancel serve so
	// the daemon drains rather than serving without a live policy watcher.
	failClosed := func(e error) {
		log.Error("aksh-proxy: policy watcher failed closed; draining", "error", e)
		cancelServe()
	}

	// cp is referenced by the orchestrator control-plane seams via closure; it
	// is assigned after runtime.New (the control-plane needs the orchestrator as
	// its ProbeSource) but before orch.Run, so a wiring failure aborts before
	// any bind.
	var cp controlPlane

	// (h) runtime.New with the production factory, the validate-only preflight,
	// the real policy startup, the shared recorder as DataMetrics, the capture
	// Handle for reverse-order drain, and the control-plane start/shutdown
	// seams.
	orch, err := d.newOrchestrator(runtime.Options{
		Config:           cfg,
		Log:              log,
		ListenerFactory:  factory,
		Preflight:        d.newPreflight(handle),
		CAProvider:       d.caProvider,
		PolicyStartup:    d.newPolicyStartup(cfg, log, failClosed, d.metrics),
		LocalSelfTest:    d.localSelfTest,
		AuditSinkFactory: d.auditSink,
		PrivDrop:         d.privDrop,
		DataMetrics:      recorder,
		CaptureHandle:    handle,
		ControlPlaneStart: func(c context.Context) error {
			if cp == nil {
				return nil
			}
			return cp.Start(c)
		},
		ControlPlaneShutdown: func(c context.Context) error {
			if cp == nil {
				return nil
			}
			return cp.Shutdown(c)
		},
		RootCAs: d.upstreamTrustPool,
	})
	if err != nil {
		log.Error("aksh-proxy: orchestrator init failed", "error", err)
		return 1
	}

	// (g) Control-plane construction with wire-time address reconciliation +
	// loopback rejection (the sole loopback owner). A failure here aborts
	// fail-closed BEFORE orch.Run, so no data-plane socket is ever bound.
	cp, err = d.newControlPlane(cfg.ControlPlane, reg, orch)
	if err != nil {
		log.Error("aksh-proxy: control-plane wiring failed; refusing to start", "error", err)
		return 1
	}

	// (i) orch.Run starts the control-plane BEFORE the data-plane bind and
	// drains in reverse order (listener -> Handle.Close -> control-plane) on
	// serveCtx cancellation.
	if err := orch.Run(serveCtx); err != nil {
		log.Error("aksh-proxy: runtime failed", "error", err)
		return 1
	}
	return 0
}

// withDefaults fills every nil deps seam with its benign default so run() has a
// total, hermetic wiring for the skeleton lifecycle tests.
func withDefaults(d deps) deps {
	if d.log == nil {
		d.log = slog.Default()
	}
	if d.deriveCgroupCandidate == nil {
		d.deriveCgroupCandidate = func(string, string) (string, error) { return "", nil }
	}
	if d.newPodCgroupResolver == nil {
		d.newPodCgroupResolver = func(cfg config.Config) (podCgroupResolver, error) {
			return passthroughResolver{path: cfg.Capture.PodPath}, nil
		}
	}
	if d.loadAndAttach == nil {
		d.loadAndAttach = func(context.Context, *capture.Options) (captureHandle, error) {
			return noopCaptureHandle{}, nil
		}
	}
	if d.envPreflight == nil {
		d.envPreflight = func(context.Context, *capture.Options) error { return nil }
	}
	if d.newResolver == nil {
		d.newResolver = func(pairMap any, opts capture.Options) (dataplane.DestinationResolver, error) {
			return capture.NewBPFDestinationResolver(pairMap, opts)
		}
	}
	if d.newOrchestrator == nil {
		d.newOrchestrator = func(o runtime.Options) (orchestratorRunner, error) {
			return runtime.New(o)
		}
	}
	if d.newControlPlane == nil {
		d.newControlPlane = func(config.ControlPlaneConfig, prometheus.Gatherer, runtime.ProbeSource) (controlPlane, error) {
			return noopControlPlane{}, nil
		}
	}
	if d.newPreflight == nil {
		d.newPreflight = func(captureHandle) func(context.Context) error {
			return func(context.Context) error { return nil }
		}
	}
	if d.newPolicyStartup == nil {
		d.newPolicyStartup = func(config.Config, *slog.Logger, func(error), watch.Metrics) func(context.Context) (*watch.Store, error) {
			return func(context.Context) (*watch.Store, error) { return &watch.Store{}, nil }
		}
	}
	// d.metrics is intentionally NOT defaulted here: run() builds the shared
	// PromMetricsRecorder immediately after config load (before cgroup
	// resolution) and adopts it when d.metrics is nil, so the cgroup-resolution
	// error counter is real in production. Tests that exercise the cgroup seam
	// inject d.metrics directly.
	return d
}

func main() {
	os.Exit(mainRun())
}

// mainRun wires production dependencies and drives run, ensuring the signal
// context's stop() runs (via defer) before the process exits. Calling os.Exit
// directly in main would skip that deferred cleanup, so the exit code is
// returned here and os.Exit is confined to main.
func mainRun() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	log := slog.Default()
	cfg, err := config.Load()
	if err != nil {
		log.Error("aksh-proxy: config load failed", "error", err)
		return 1
	}

	// Build the upstream TLS trust pool in Go (replacing the shell SSL_CERT_FILE
	// concatenation): system roots plus the pod CA public material and the
	// mounted upstream CA. A malformed cert fails startup closed.
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		log.Warn("aksh-proxy: system cert pool unavailable; starting upstream trust pool empty", "error", err)
		systemPool = nil
	}
	trustPool, err := buildUpstreamTrustPool(systemPool, cfg.CA.PubDir, upstreamCADir)
	if err != nil {
		log.Error("aksh-proxy: upstream trust pool construction failed; refusing to start", "error", err)
		return 1
	}
	log.Info("aksh-proxy: upstream trust pool constructed", "caPubDir", cfg.CA.PubDir, "upstreamCADir", upstreamCADir)

	return run(ctx, deps{
		loadConfig:            func() (config.Config, error) { return cfg, nil },
		log:                   log,
		deriveCgroupCandidate: derivePodCgroupCandidate,
		newPodCgroupResolver:  newProdPodCgroupResolver,
		upstreamTrustPool:     trustPool,
		loadAndAttach: func(_ context.Context, opts *capture.Options) (captureHandle, error) {
			h, err := capture.LoadAndAttach(opts)
			if err != nil {
				return nil, err
			}
			return h, nil
		},
		envPreflight: func(_ context.Context, opts *capture.Options) error {
			seams, err := capture.NewProductionPreflightSeams(opts)
			if err != nil {
				return err
			}
			return capture.RunEnvironmentPreflight(opts, seams)
		},
		newOrchestrator: func(o runtime.Options) (orchestratorRunner, error) { return runtime.New(o) },
		newControlPlane: func(c config.ControlPlaneConfig, reg prometheus.Gatherer, probes runtime.ProbeSource) (controlPlane, error) {
			return runtime.NewControlPlaneServerFromConfig(c, reg, probes)
		},
		newPreflight:     productionPreflight,
		newPolicyStartup: productionPolicyStartup,
		caProvider: func(c context.Context) (pki.CAProvider, error) {
			return pki.NewPodCAProvider(c, pki.PodCAOptions{PrivDir: cfg.CA.PrivDir, PubDir: cfg.CA.PubDir})
		},
		localSelfTest: func(context.Context) error {
			return entra.LocalSelfTest(entra.Options{
				TenantID:    cfg.Token.Entra.TenantID,
				ClientID:    cfg.Token.Entra.ClientID,
				Authority:   cfg.Token.Entra.Authority,
				SATokenPath: cfg.Token.SATokenPath,
			})
		},
		auditSink: func() (audit.AuditSink, error) { return audit.NewStreamSink(os.Stdout), nil },
		privDrop:  capture.DropPrivileges,
	})
}

// newProdPodCgroupResolver is the production podCgroupResolver constructor. It
// threads the capture config's cgroup mount fields, the proxy pid, and the
// production statfs FSMagic prober into a *capture.PodCgroupResolver so run()
// resolves and validates the pod cgroup before config validation. The optional
// Namespace prober is left nil (a nil prober skips the cgroup-namespace
// visibility check, which does not apply to the hostPath cgroup2 mount the
// sidecar uses); Procs is nil so the resolver reads cgroup.procs directly.
func newProdPodCgroupResolver(cfg config.Config) (podCgroupResolver, error) {
	return capture.NewPodCgroupResolver(&capture.PodCgroupResolverConfig{
		HostCgroupMount:  cfg.Capture.HostCgroupMount,
		LocalCgroupMount: cfg.Capture.LocalCgroupMount,
		ProcCgroupPath:   cfg.Capture.ProcCgroupPath,
		ProxyPID:         os.Getpid(),
		FSMagic:          capture.NewFSMagicProber(),
		// Inode + Dirs seams enable the Case-B inode discovery DiscoverPodCgroup
		// runs when the pod cgroup is namespaced ("0::/"); ResolvePodCgroup does
		// not use them, so Case A is unaffected.
		Inode: capture.NewCgroupInodeStater(),
		Dirs:  capture.NewCgroupDirReader(),
	})
}
