# S9b — aksh-proxy Production Wiring Design Document

---

## Metadata `[Required]`

| Field | Value |
|-------|-------|
| **Author** | GitHub Copilot CLI (Architect) |
| **Date** | 2026-08-23 |
| **Status** | Implemented — reconciled to the as-built code on 2026-08-24 (branch `impl/phase-9b-capture-wiring`, all 5 slices + SI-S3-1 follow-up). See [Reconciliation Notes](#reconciliation-notes-implemented-state-optional). |
| **Interface** | `cmd/aksh-proxy/main.go`; `internal/dataplane/capture` (`Handle`); `internal/config`; `internal/runtime` (`factory.go`, `orchestrator.go`, `control_plane_server.go`); `internal/dataplane/listener`; `internal/policy/watch` |
| **Implementation** | `internal/dataplane/capture/{loader_linux.go,loader_other.go,handle_linux.go,handle_other.go}`; `internal/config/config.go`; `internal/runtime/{factory.go,orchestrator.go}`; `internal/dataplane/listener/listener.go`; `internal/policy/watch/{restconfig.go}`; `cmd/aksh-proxy/main.go` |
| **Mock** | Test fakes in the corresponding `_test.go` files; `-tags ebpf_integration` privileged tests |
| **Dependencies** | [S8](./S8-proxy-runtime.md); [S1a](./S1a-dataplane-capture.md); [S6](./S6-observability.md); [S2](./S2-policy-crd.md) |

### Revision History `[Optional]`

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2026-08-23 | GitHub Copilot CLI | Initial integration/wiring design covering the 5 disconnected-component gaps + config expansion (Artifact Iteration 0). |
| 0.2 | 2026-08-24 | GitHub Copilot CLI | Post-review corrections (iter0→iter2): control-plane-before-serve startup ordering; canonical `runtime.Port15020` (removed invented `:15090`); **eager `LoadAndAttach` ownership in `main.go`'s `run()`** with a validate-only `productionPreflight` seam (resolved the ordering contradiction); new closed-enum constants `pipeline.ReasonNoOriginalDst` / `audit.StageResolve`; fail-closed policy-watcher `Run` handling (failClosed trigger); removed the unused `reg *audit.PromMetricsRecorder` parameter from `productionPolicyStartup` (watcher exposes no public metrics hook). |
| 0.3 | 2026-08-24 | GitHub Copilot CLI (Reconciliation) | **Artifact reconciliation** to the as-built code (all 5 slices + SI-S3-1 config-surfacing follow-up on `impl/phase-9b-capture-wiring`). Back-annotated the implementation-time seams: the `deps` struct + `captureHandle`/`orchestratorRunner`/`controlPlane` interfaces (`cmd/aksh-proxy/seams.go`), the policy function-var seams + `policyWatcher` interface, the new `Handle.AttachLost()` predicate, the orchestrator `CaptureHandleCloser` widening and `ControlPlaneStart`/`ControlPlaneShutdown` seams (with SI-S5-1 reverse-order drain), `NewControlPlaneServerFromConfig` as the sole address-reconciliation owner (`PodIPEnv` const), `MakeProductionListenerFactory` export, exported `CaptureOptionsFromConfig`/`EffectivePort`/`EffectiveFirstSnapshotTimeout`/`EffectiveMaxStaleness`, and the SI-S3-1 YAML/env surfacing (MinKernel deliberately non-surfaced; POD_IP owned by S5). Docs-only; see [Reconciliation Notes](#reconciliation-notes-implemented-state-optional). |

### Reconciliation Notes (Implemented State) `[Optional]`

> **[Reconciliation — 2026-08-24, branch `impl/phase-9b-capture-wiring`]** This subsection records the seam/signature decisions that were finalized *at implementation time*. The design body below is preserved as authored; these notes are the authoritative "what the code actually does now" delta. Each item is additive per the artifact-reconciliation procedure. Related discoveries are tracked in the Findings doc (SI-S3-*, SI-S4-*, SI-S5-*).

- **`run()` is now `run(ctx context.Context, d deps) int`** (`cmd/aksh-proxy/main.go`). The design showed inline `main.go` wiring; the implementation extracted a `deps` struct of injectable seams (`loadConfig`, `log`, `loadAndAttach`, `newResolver`, `factory`, `newOrchestrator`, `newControlPlane`, `newPreflight`, `newPolicyStartup`, `caProvider`, `localSelfTest`, `auditSink`, `privDrop`). Production wiring lives in `mainRun() int`, which populates `deps` with the real constructors and calls `run`. The canonical composition order is unchanged from §Architecture: load+validate config → shared `prometheus.NewRegistry()` → `audit.NewPromMetricsRecorder(reg)` → `config.CaptureOptionsFromConfig(ctx,cfg,recorder)` → eager `loadAndAttach` (**before** `runtime.New`) with `defer handle.Close()` and `OnAttachLoss` fail-closed serve-cancel → resolver → `runtime.MakeProductionListenerFactory` → `runtime.New` → `NewControlPlaneServerFromConfig` → `orch.Run`.
- **Interface seams (`cmd/aksh-proxy/seams.go`).** The daemon composes against small interfaces, not concrete types: `captureHandle` (`PairMap() *ebpf.Map`, `AttachInfo() capture.AttachInfo`, `Close() error`, `OnAttachLoss(func(error))`, `AttachLoss() <-chan error`, `AttachLost() bool`), `orchestratorRunner` (`Run`, `Ready`, `Live`), and `controlPlane` (`Start`, `Shutdown`). Benign defaults `noopCaptureHandle`/`noopControlPlane` back the nil-seam pattern.
- **New `Handle.AttachLost() bool` predicate** (`internal/dataplane/capture/handle_linux.go`, non-Linux stub returns `false` in `handle_other.go`) — added to the `capture.Handle` surface and the `captureHandle` interface; consumed by `productionPreflight` (UT #100).
- **Policy startup seams (`cmd/aksh-proxy/policy_startup.go`).** The fail-closed branches are reified as package-level function-vars `inClusterConfig`, `newDynamicClient`, `newAkshPolicyClient`, `newWatcher` plus a `policyWatcher` interface (`Run`, `WaitFirstSnapshot`). `productionPolicyStartup(cfg, log, failClosed)` returns `func(context.Context) (*watch.Store, error)`. `watch.InClusterRESTConfig()` wraps `ErrInClusterConfig` and is itself overridable via the package-level `inClusterConfig` var in `internal/policy/watch/restconfig.go`.
- **Preflight (`cmd/aksh-proxy/preflight.go`).** `productionPreflight(h captureHandle) func(context.Context) error` is validate-only (never re-attaches); sentinels `ErrPreflightNoHandle` / `ErrPreflightInvalidAttach` / `ErrPreflightAttachLost`; helpers `validAttachInfo` and typed-nil-safe `isNilCaptureHandle`.
- **Control-plane construction (`internal/runtime/control_plane_server.go`).** `NewControlPlaneServerFromConfig(cp config.ControlPlaneConfig, reg prometheus.Gatherer, probes ProbeSource) (*ControlPlaneServer, error)` is the **sole** owner of wire-time address reconciliation: empty host → `os.Getenv(PodIPEnv)` (new `PodIPEnv = "POD_IP"` const), port default `Port15020`, loopback still rejected. The design's manual `main.go` reconciliation into `NewControlPlaneServer(podIP, port, …)` was superseded by this constructor.
- **Orchestrator seams (`internal/runtime/orchestrator.go`).** The Handle field is widened from `*capture.Handle` to the `CaptureHandleCloser interface { Close() error }`; new `Options.ControlPlaneStart func(context.Context) error` and `Options.ControlPlaneShutdown func(context.Context) error` seams start the control-plane **before** the data-plane bind and shut it down **last**. Per SI-S5-1, the listener-factory-failure and Bind-failure paths now `drain()` in reverse order (control-plane torn down last on those aborts too).
- **`MakeProductionListenerFactory` is exported** (`internal/runtime/factory.go`; was `makeProductionListenerFactory`) so `mainRun()` can wire it into `deps.factory`.
- **Non-Linux resolver stub (`internal/dataplane/capture/resolver_other.go`).** `(*BPFDestinationResolver).Resolve` stub + `var _ dataplane.DestinationResolver = (*BPFDestinationResolver)(nil)` assertion added for the `GOOS=windows` cross-compile.
- **Config exports + surfacing (`internal/config/config.go`).** `CaptureOptionsFromConfig(ctx context.Context, cfg Config, m audit.MetricsRecorder) capture.Options`, `EffectivePort`, `EffectiveFirstSnapshotTimeout`, `EffectiveMaxStaleness` are now **exported** (were unexported; SI-S3-3). **SI-S3-1 surfacing:** `yamlConfig`/`applyYAML`/`applyEnv`/`trimFields` surface `capture:` (all fields **except `MinKernel`**, the deliberately non-surfaced kernel-floor security control), `controlPlane:` (`address`/`port`), `policy.resync`/`policy.firstSnapshotTimeout`, plus `AKSH_CAPTURE_*` / `AKSH_CONTROLPLANE_*` / `AKSH_POLICY_*` env vars. `Validate` now also rejects negative `Policy.Resync` / `Policy.FirstSnapshotTimeout` / `ControlPlane.Port`. `ControlPlane.Address` is empty by default — S5's `NewControlPlaneServerFromConfig` owns the `POD_IP` resolution.

### Glossary `[Optional]`

| Term | Definition |
|------|------------|
| Handle | `*capture.Handle` — the owner object returned by `LoadAndAttach`, holding the collection, config map, links, pins, and health loop (Gap 1, Option A). |
| Pair map | `pair_orig_dst` BPF map; the resolver reads the kernel-attested pre-redirect destination from it. |
| First snapshot | First successfully compiled `policy.PolicySnapshot` selecting this pod; startup blocks on it (deny-all until then). |
| Attach-loss | The health loop's verdict that a program is no longer attached; replaces `os.Exit(1)` with a fail-closed shutdown signal. |
| Fail-closed | Any wiring failure refuses to serve (start, or drop the connection) rather than bypassing capture/policy. |
| TD S6-1 / TD S6-2 | S8 Findings tech-debt items: the two fail-closed `production*` placeholders this design replaces. |

### Quick-Start Reading Guide `[Optional]`

- Wiring-only change: no new enforcement logic. Read [Overview](#overview-required), then [Architecture](#architecture-required) for the startup/shutdown sequence, then the [Component Design](#core-data-types-required) subsections 1–6.
- Exact signatures live in [API Reference](#api-reference-required).
- Fail-closed rules and Do's/Don'ts are in [Best Practices](#best-practices-required) and [Error Handling Strategy](#error-handling-strategy-optional).

---

## Overview `[Required]`

### Executive Summary

Five production components already exist, are unit-tested, and are green — but they are not connected to each other. As a result `aksh-proxy` cannot boot on Linux: `main.go` wires two fail-closed placeholders (`productionPreflight`, `productionPolicyStartup`) that deliberately refuse to start (TD S6-1 / TD S6-2), the listener never calls the destination resolver, production metrics are a no-op, the control-plane `/metrics` server is never started, and nothing owns eBPF teardown on `SIGTERM`.

S9b is an **integration/wiring** design. It composes the existing pieces and adds the minimum new surface required to make the daemon a functioning, observable, cleanly-terminating binary on Linux, so the next phase (P9c) can validate end-to-end on a kind cluster. The only genuinely new abstraction is `capture.Handle` (Option A): evolving `LoadAndAttach` to return an owner object that exposes the live pair map to the resolver and replaces the health loop's `os.Exit(1)` with a caller-driven, fail-closed attach-loss signal.

### Design Principles

- **Fail-closed everywhere.** Any wiring failure (preflight, policy, resolve, metrics, control-plane bind, attach-loss) refuses to serve rather than serving with capture or policy bypassed. This preserves S8/S1a invariants INV-3/INV-8.
- **Reuse over rebuild.** Consume existing `resolver_linux.go`, `prom.go`, `control_plane_server.go`, and `policy/watch/*` as-is. Gap 2 is *assembly glue only* — every building block is already built and tested.
- **Kernel-attested destination.** OriginalDst comes only from the BPF pair map via `DestinationResolver.Resolve`. There is no `getsockopt(SO_ORIGINAL_DST)` path.
- **Idempotent, deterministic teardown.** `Handle.Close()` is safe to call more than once and unwinds every kernel object.
- **No dependence on pinning.** `PinLinks` defaults to `false` (TD-1/M1, TD-6). The resolver receives the *live* map directly from the Handle, not a pinned path.

### Scope `[Optional — include for larger components]`

**In scope (the 5 gaps + config):**

1. `capture.Handle` (Option A): `LoadAndAttach` returns `*Handle` owning collection/maps/links/health loop; `PairMap()`, `Close()`, `AttachInfo()`, attach-loss callback. Migrate the ~15 existing capture integration tests that reference the old `*AttachInfo` return type.
2. Real `productionPolicyStartup`: in-cluster `rest.Config` → dynamic client → `NewDynamicAkshPolicyClient` → `NewWatcher` → `Run` goroutine → `WaitFirstSnapshot` → `*watch.Store`.
3. Listener resolve wiring: `Resolve(conn)` → `cc.OriginalDst`; fail-closed reject on error (`RejectNoOriginalDst`/T1) + rejection metric.
4. Metrics + control-plane: one `PromMetricsRecorder` + `prometheus.Registry`, injected as orchestrator `DataMetrics` **and** into `ProductionListenerFactory`; start `ControlPlaneServer` on a configured address.
5. Lifecycle teardown: proxy holds the Handle; orchestrator drain calls `Handle.Close()`; attach-loss → fail-closed shutdown.
6. Config expansion: `config.Capture` + `config.ControlPlane` structs, extend `config.Policy`; validation + defaults from `capture.DefaultOptions()`; single `captureOptionsFromConfig` mapping.

**Out of scope (Non-Goals):**

- The P9c e2e-on-kind validation harness itself.
- Any change to the eBPF C programs (`aksh_capture.c`) or `go generate`.
- Production-kernel pin validation (TD-6) and merge gate M1 (TD-1) — `PinLinks` stays `false`.
- The SCTP / connected-UDP recompile debt (S1a Findings TD-15 / imp #15).
- IPv6 capture (denied in 5A), and any new enforcement/policy semantics.

### File Locations

| Concern | File |
|---------|------|
| Handle (Option A) | `internal/dataplane/capture/loader_linux.go` (refactor) + new `handle_linux.go` / `handle_other.go` stub |
| Non-Linux stubs | `internal/dataplane/capture/loader_other.go` (return type change to `*Handle`) |
| Config expansion | `internal/config/config.go` |
| Resolve wiring | `internal/dataplane/listener/listener.go` (dispatch ~line 472) |
| Metrics + factory | `internal/runtime/factory.go` |
| Orchestrator wiring | `internal/runtime/orchestrator.go` |
| Control-plane start | `internal/runtime/control_plane_server.go` (consumed as-is) |
| Policy assembly + rest.Config | `cmd/aksh-proxy/main.go` + new `internal/policy/watch/restconfig.go` |
| Binary assembly | `cmd/aksh-proxy/main.go` |

---

## Problem Statement `[Optional]`

### Current Situation

`cmd/aksh-proxy/main.go` wires two placeholders that fail closed by design:

- `productionPreflight(context.Context) error` returns `errors.New("...capture preflight/attach seams not wired (TD S6-1); refusing to start...")` (main.go, `productionPreflight`).
- `productionPolicyStartup(context.Context) (*watch.Store, error)` returns `errors.New("...policy watcher client not wired (TD S6-2); refusing to start...")` (main.go, `productionPolicyStartup`).

The orchestrator invokes these via `runGate(ctx, "preflight", o.preflight)` and `o.policyStartup(ctx)` (orchestrator.go, `Run`). Either error aborts startup before `Bind`. Even if they succeeded:

- `internal/runtime/factory.go` `ProductionListenerFactory` passes `noopResolver{}` and `noopTypedMetrics{}` to `listener.New` (factory.go).
- `internal/dataplane/listener/listener.go` builds `cc := &ConnContext{Downstream: conn, AcceptedAt: acceptedAt}` and calls `l.handler.Handle(ctx, cc)` **without ever setting `cc.OriginalDst`** (listener.go dispatch, ~line 472). The comment on the stored `resolver` field says it is "stored but not yet read" (listener.go ~line 47).
- `internal/runtime/orchestrator.go` defaults `DataMetrics` to `noopTypedMetrics{}` (orchestrator.go, `New`).
- The `ControlPlaneServer` (`/metrics`, `/healthz`, `/readyz`) is never started by `main.go`.
- Nothing owns eBPF detach/unpin on `SIGTERM`; the map lives only inside the internal `loaderState`, retained by the health-loop goroutine (loader_linux.go), and `runHealthLoop` calls `seam.exit(1)` (`os.Exit`) on attach-loss.

### Example: Before and After

**Before** — the daemon cannot boot; capture, resolution, metrics, and teardown are all disconnected:

```text
main.go → productionPreflight → error "not wired (TD S6-1)" → refuse to start
```

**After** — a single fail-closed startup assembles all five subsystems and the control-plane:

```text
config.Load → captureOptionsFromConfig → capture.LoadAndAttach → *Handle
   → NewBPFDestinationResolver(Handle.PairMap(), opts)
   → PromMetricsRecorder injected into orchestrator + factory
   → ControlPlaneServer.Start (pod IP) → /metrics scrapeable by kind   [before data-plane bind]
   → orchestrator.Run → listener binds + resolves OriginalDst → Serve
   → SIGTERM → orchestrator drain → Handle.Close → ControlPlaneServer.Shutdown (idempotent detach/unpin)
```

---

## Architecture `[Required]`

### Dependency Graph

```text
cmd/aksh-proxy/main.go
  ├─ config.Load ─────────────► config.Config{Capture, ControlPlane, Policy, ...}
  ├─ captureOptionsFromConfig ─► capture.Options
  ├─ capture.LoadAndAttach ────► *capture.Handle ── PairMap() ─┐
  ├─ audit.NewPromMetricsRecorder(reg) ─► *PromMetricsRecorder │
  ├─ watch rest.Config → dynamic → NewDynamicAkshPolicyClient ─┼─► NewWatcher → Run → WaitFirstSnapshot → *watch.Store
  ├─ runtime.NewControlPlaneServer(podIP, port, reg, probes) ──┘
  └─ runtime.New(Options{Preflight, PolicyStartup, DataMetrics, ListenerFactory, ...})
        └─ orchestrator.Run
              ├─ factory(cfg, handler, log) ─► listener.New(opts, BPFResolver, handler, PromMetrics, log)
              └─ drain ─► Handle.Close()
```

The proxy binary owns the `Handle`, the `PromMetricsRecorder`+registry, and the `ControlPlaneServer`. The orchestrator owns lifecycle ordering and drain. Everything else is existing code consumed unchanged.

### High-Level Flow — Startup Sequence

The fixed order extends the S8 startup spine; new S9b steps are marked **[S9b]**.

```text
 1. config.Load + Config.Validate            (config.go, incl. new Capture/ControlPlane) [S9b]
 2. captureOptionsFromConfig(cfg) → Options  (single mapping fn)                          [S9b]
 3. audit.NewPromMetricsRecorder(registry)   (one recorder, one registry)                [S9b]
 4. opts.Metrics = PromMetricsRecorder        (capture.Options.Metrics is mandatory)      [S9b]
 5. capture.LoadAndAttach(opts) → *Handle     (EAGER in main run(); stored in run scope)  [S9b]
      OnAttachLoss = orchestrator fail-closed shutdown trigger                            [S9b]
      A load/attach failure here ABORTS startup fail-closed (non-zero) BEFORE any bind    [S9b]
      Handle.Close() is deferred in run() for drain teardown                              [S9b]
 6. NewBPFDestinationResolver(Handle.PairMap(), opts) → resolver                          [S9b]
 7. runtime.New(Options{Preflight, PolicyStartup(real), DataMetrics=Prom,                 [S9b]
      ListenerFactory=factory bound to {resolver, Prom}})
 8. ControlPlaneServer.Start(podIP:port)      (/metrics, /healthz, /readyz)               [S9b]
      MUST be listening BEFORE any data-plane bind/accept (step 9). A control-plane
      bind/start failure ABORTS startup fail-closed — no data-plane listener is
      bound and no traffic is ever accepted. Readiness semantics: /readyz reports
      NotReady until the first policy snapshot + attach are confirmed, but the
      server itself must be listening first so probes are answerable during the
      deny-all window.
 9. orchestrator.Run:                                                                     [S9b order]
      config.Validate → preflight (validate-only: confirms attach already healthy) → resolvers
      → CA ready → policyStartup(real) → first snapshot (deny-all until now)
      → self-test → audit sink → assemble handler chain
      → factory → listener.Bind → AcceptProbe → privDrop(1774) → Serve
```

> **Control-plane-before-dataplane (see Findings F1).** The `ControlPlaneServer`
> is constructed and `Start`ed (step 8) **after** `runtime.New` (it needs the
> orchestrator as its `ProbeSource`) but **before** `orchestrator.Run` binds/accepts
> the data-plane listener (step 9). This is a fail-closed ordering requirement: if
> the control-plane bind/start fails, startup aborts and no data-plane traffic is
> ever accepted. The server listens first (answering `/readyz`=NotReady) so that
> kubelet probes are serviceable throughout the policy first-snapshot deny-all window.

> **Ordering note (see Findings F1).** `capture.LoadAndAttach` runs **eagerly in
> `cmd/aksh-proxy/main.go`'s `run()`** *before* resolver/factory/`runtime.New`
> construction, because the resolver (step 6) needs `Handle.PairMap()` and the
> factory (step 7) needs the resolver. `run()` builds `capture.Options` from
> config, calls `LoadAndAttach(opts)`, and stores the returned `*capture.Handle`
> in run scope; a load/attach failure here **aborts startup fail-closed (returns
> non-zero) before anything binds**. `Handle.Close()` is deferred in `run()` for
> drain teardown, invoked exactly once. `productionPreflight` (the orchestrator
> `Preflight` seam) is a **validate-only** check: it confirms the already-established
> attach state is healthy (e.g. `handle != nil`, `handle.AttachInfo()` valid,
> attach not already lost) and returns an error if not. It does **not** perform
> `LoadAndAttach`. The *fail-closed* contract is preserved on two fronts: the eager
> load aborts before any construction, and the preflight seam still aborts before
> `Bind` if the established attach is unhealthy.

### High-Level Flow — Shutdown Sequence

```text
SIGTERM (signal.NotifyContext) ─► ctx cancel
  orchestrator.serve: ctx.Done → o.Shutdown(shutdownCtx)   (listener drain, ≤30s)
  main defer / drain hook: Handle.Close()                  (detach + unpin + close coll; idempotent) [S9b]
  ControlPlaneServer.Shutdown(ctx)                          (graceful HTTP stop)                       [S9b]

Attach-loss during serve (health loop):
  Handle.OnAttachLoss(err) ─► orchestrator fail-closed trigger ─► cancel serve ctx ─► drain + Handle.Close [S9b]
  (replaces loader_linux.go runHealthLoop os.Exit(1))
```

> **Shutdown order mirrors startup (reverse).** The control-plane was started
> *before* the data-plane bind (startup step 8), so it is torn down *last* — the
> data-plane listener drains first, then `Handle.Close()` tears down capture, then
> the control-plane HTTP server stops. This keeps `/metrics` and `/readyz`
> scrapeable for as long as possible during drain.

---

## Core Data Types `[Required]`

### `capture.Handle` (Gap 1, Option A)

`Handle` is the owner object returned by `LoadAndAttach`. It holds everything the current internal `loaderState` holds, and exposes exactly the surface the wiring needs. It is declared **without** a build tag for the type shell so Linux and non-Linux agree on the return type; the Linux behaviour lives in `handle_linux.go`, the stub in `handle_other.go`.

```go
// Handle owns the kernel objects and health loop of a successful LoadAndAttach.
// It is the single point of ownership for eBPF teardown (SIGTERM drain) and the
// live pair_orig_dst map (destination resolution). Close is idempotent.
type Handle struct {
    st        *loaderState             // Linux-only internal; nil on the non-Linux stub
    onLoss    atomic.Pointer[func(error)] // attach-loss callback, set via OnAttachLoss (type-safe, Go 1.19+)
    lossCh    chan error               // buffered(1); alternative to the callback
    closeOnce sync.Once
    closeErr  error
}
```

Fields mirror today's `loaderState` (opts, coll, configMap, links, pinPaths, info, cancel) which the Handle now wraps rather than leaving orphaned in the package-level `loadedSet`.

### `config.Capture`, `config.ControlPlane`, extended `config.Policy` (Gap 6)

See [Configuration](#configuration-optional) for full field tables. Summary shape:

```go
type Config struct {
    Listener     ListenerConfig
    CA           CAConfig
    Policy       PolicyConfig      // extended
    Token        TokenConfig
    Audit        AuditConfig
    Capture      CaptureConfig     // new
    ControlPlane ControlPlaneConfig // new
}
```

### Reject taxonomy (Gap 3)

Reused unchanged from `internal/dataplane/listener/types.go` and `internal/audit/labels.go`:

- `listener.RejectNoOriginalDst` → `String()="no_original_dst"`, `Code()="T1"` (types.go).
- `audit.RejectClassNoOriginalDst` → the typed metric label for `TransportReject` (labels.go).

---

## API Reference `[Required]`

### Gap 1 — `capture.Handle` and `LoadAndAttach` (exact signatures)

```go
// LoadAndAttach evolves to return *Handle instead of *AttachInfo. Same load/
// attach/pin/freeze/verify/health composition; the Handle now owns the result.
func LoadAndAttach(opts *Options) (*Handle, error)          // linux (loader_linux.go)
func LoadAndAttach(opts *Options) (*Handle, error)          // non-linux stub: return nil, ErrUnsupportedPlatform (loader_other.go)

// PairMap returns the live pair_orig_dst *ebpf.Map for the resolver. It returns
// nil after Close. The map is NOT pinned (PinLinks defaults false); the live
// handle is authoritative (TD-1/TD-6 — no dependence on pinning).
func (h *Handle) PairMap() *ebpf.Map

// AttachInfo returns the kernel program ids, cgroup id, and pin paths (empty
// when PinLinks is false). Same struct as today (types.go AttachInfo).
func (h *Handle) AttachInfo() AttachInfo

// Close detaches every link, unpins (when pinned), cancels the health loop, and
// closes the collection. It is idempotent and safe on a partially built Handle.
// It is the SIGTERM-drain teardown entry point (Gap 5).
func (h *Handle) Close() error

// OnAttachLoss registers a fail-closed callback invoked once by the health loop
// on a proof of detachment (or 3 inconclusive checks), REPLACING the current
// os.Exit(1) in runHealthLoop (loader_linux.go). fn must be non-blocking; it
// runs on the health goroutine. Registering after loss delivers immediately.
func (h *Handle) OnAttachLoss(fn func(error))

// AttachLoss is the channel alternative to OnAttachLoss: a buffered(1) channel
// that receives the loss error exactly once. Callers use one mechanism or the
// other; the design wires OnAttachLoss.
func (h *Handle) AttachLoss() <-chan error
```

> The `errAttachLost` verdict and the health-loop structure are unchanged; only the terminal action changes from `seam.exit(1)` to "invoke `onLoss` / send on `lossCh`". `os.Exit` is removed from the capture package's serve path (Findings Improvement #2 — anti-pattern removal).

> **[Reconciled 2026-08-24]** As built, `Handle` also exposes `func (h *Handle) AttachLost() bool` (non-Linux stub returns `false`), a validate-only predicate consumed by `productionPreflight`. The daemon composes against the `captureHandle` interface (`cmd/aksh-proxy/seams.go`), not the concrete `*capture.Handle`. See [Reconciliation Notes](#reconciliation-notes-implemented-state-optional).

### Gap 2 — real policy startup + in-cluster rest.Config

```go
// productionPolicyStartup replaces the TD S6-2 placeholder. Assembly glue only.
// log is the daemon logger; failClosed is the orchestrator's fail-closed trigger
// (it cancels the serve context) so a watcher Run failure cannot leave the daemon
// serving with a silently-dead watch loop. No metrics recorder is threaded here:
// watch.Options exposes no public metrics hook (its staleDenyCounter seam is
// unexported and defaults to a no-op in NewWatcher), so a PromMetricsRecorder
// parameter would be unused — see Findings F7.
func productionPolicyStartup(cfg config.Config, log *slog.Logger, failClosed func(error)) func(context.Context) (*watch.Store, error)

// New helper (internal/policy/watch/restconfig.go): the in-cluster rest.Config.
// Wraps k8s.io/client-go/rest.InClusterConfig with a bounded, closed error.
func InClusterRESTConfig() (*rest.Config, error)
```

Assembly body (deny-all until first snapshot):

```go
func productionPolicyStartup(cfg config.Config, log *slog.Logger, failClosed func(error)) func(context.Context) (*watch.Store, error) {
    return func(ctx context.Context) (*watch.Store, error) {
        rc, err := watch.InClusterRESTConfig()                       // in-cluster kubeconfig
        if err != nil { return nil, err }                            // fail-closed
        dc, err := dynamic.NewForConfig(rc)                          // client-go dynamic
        if err != nil { return nil, err }
        client, err := watch.NewDynamicAkshPolicyClient(dc, cfg.Policy.Namespace)
        if err != nil { return nil, err }
        store := &watch.Store{}                                      // deny-all before first Swap
        w, err := watch.NewWatcher(watch.Options{
            Namespace:    cfg.Policy.Namespace,
            MaxStaleness: cfg.Policy.MaxStaleness,
            ResyncPeriod: cfg.Policy.Resync,                         // reserved; 0 today (TD S4-1)
        }, client, store)
        if err != nil { return nil, err }
        go func() {
            // Fail-closed everywhere: a non-nil, non-context-cancelled Run
            // error is logged at ERROR and fed to the orchestrator's
            // fail-closed shutdown trigger (cancel serve ctx) rather than
            // silently discarded. context.Canceled on drain is benign.
            if rerr := w.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
                log.Error("aksh-proxy: policy watcher Run exited", "error", rerr)
                failClosed(rerr) // orchestrator fail-closed trigger
            }
        }()                                                        // watch loop
        waitCtx, cancel := context.WithTimeout(ctx, cfg.Policy.FirstSnapshotTimeout)
        defer cancel()
        if err := w.WaitFirstSnapshot(waitCtx); err != nil {        // fail-closed on timeout
            return nil, err
        }
        return store, nil
    }
}
```

Existing signatures consumed unchanged (verified):

- `watch.NewDynamicAkshPolicyClient(dc dynamic.Interface, namespace string) (AkshPolicyClient, error)` (client.go).
- `watch.NewWatcher(opts Options, client AkshPolicyClient, store *Store) (*Watcher, error)` (watcher.go).
- `(*Watcher).Run(ctx context.Context) error`; `(*Watcher).WaitFirstSnapshot(ctx context.Context) error` (watcher.go).
- `watch.Options{Namespace, PodLabels, MaxStaleness, ResyncPeriod}` (watcher.go).

> **[Reconciled 2026-08-24]** As built, each construction step in `productionPolicyStartup` is driven through a package-level function-var seam (`inClusterConfig`, `newDynamicClient`, `newAkshPolicyClient`, `newWatcher`) and the watcher is consumed via a local `policyWatcher interface { Run; WaitFirstSnapshot }`, making every fail-closed branch reachable under `CGO_ENABLED=0`. `InClusterRESTConfig()` wraps `ErrInClusterConfig` and is itself overridable via the `inClusterConfig` var in `internal/policy/watch/restconfig.go`. See [Reconciliation Notes](#reconciliation-notes-implemented-state-optional).

### Gap 3 — listener resolve wiring (dispatch)

No signature change; the dispatch goroutine (listener.go, ~line 472) gains a resolve step before `Handle`:

```go
cc := &ConnContext{Downstream: conn, AcceptedAt: acceptedAt}

// [S9b] accept_dispatch keeps its existing meaning: accept → dispatch handoff.
// Recorded BEFORE the new resolve step so its semantics are unchanged (the
// resolve latency is recorded separately under StageResolve below).
if l.metrics != nil {
    l.metrics.StageDuration(audit.StageAcceptDispatch, time.Since(acceptedAt))
}

// [S9b] Recover the kernel-attested pre-redirect destination. There is no
// getsockopt(SO_ORIGINAL_DST) path; the resolver reads the BPF pair map.
resolveStart := time.Now()
dst, rerr := l.resolver.Resolve(conn)
if l.metrics != nil {
    l.metrics.StageDuration(audit.StageResolve, time.Since(resolveStart)) // NEW stage; see F5
}
if rerr != nil {
    if l.metrics != nil {
        // Transport labelling invariant (listener.go dispatch): this listener is
        // the TLS-terminating front door, so accept-time rejections on a raw
        // net.Conn (before any ConnContext/Protocol exists) use audit.TransportTLS
        // — the same convention already used by the resource-limit rejections in
        // this function. There is no "bound" for a missing original destination,
        // so the bound label is audit.BoundNone.
        l.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonNoOriginalDst, audit.TransportTLS, false)
        l.metrics.TransportReject(audit.RejectClassNoOriginalDst, audit.BoundNone)
    }
    l.log.Warn("listener: no original destination; rejecting (T1)", "error", rerr.Error())
    return // conn.Close runs via the consolidated defer — fail-closed
}
cc.OriginalDst = dst

err := l.handler.Handle(ctx, cc)
```

Consumed unchanged: `dataplane.DestinationResolver.Resolve(conn net.Conn) (netip.AddrPort, error)` (interfaces.go); `BPFDestinationResolver` (resolver_linux.go). The resolver already wraps every benign miss/stale/malformed as `ErrNoOriginalDestination` (T1) and records the alerting T2 loop-guard itself.

> **Symbol status (see Findings F5).** Every symbol in the snippet references an
> existing API or is explicitly marked NEW with its owning file:
> - `audit.RejectClassNoOriginalDst` — **exists** (`internal/audit/labels.go`), keep.
> - `audit.BoundNone` — **exists** (`internal/audit/labels.go`), zero-value `"none"`;
>   used because a missing original destination is not a resource *bound*. The
>   previously-drafted `audit.BoundOriginalDst` does **not** exist and is **not**
>   added — the `TransportReject(class, bound)` signature is satisfied by `BoundNone`.
> - `pipeline.ReasonNoOriginalDst` — **NEW**; added after `ReasonMissingClientHello`
>   in `internal/pipeline/deny_reason.go` (closed enum, appended so no ordinal shifts;
>   never a free string), with `String() = "no_original_dst"`.
> - `audit.StageResolve` — **NEW**; added after `StageUpstreamDial` in
>   `internal/audit/labels.go` (closed `StageName` enum) with
>   `String() = "resolve"`, so resolve latency is recorded separately and
>   `accept_dispatch` keeps its existing accept→dispatch semantics.
> - `audit.TransportTLS` — **exists**; correct per the listener's documented
>   transport-labelling invariant for accept-time rejects (not a pre-classification bug).

### Gap 4 — metrics + control-plane wiring

```go
// main.go — one recorder, one registry, shared by both consumers.
reg := prometheus.NewRegistry()
prom, err := audit.NewPromMetricsRecorder(reg)              // (reg prometheus.Registerer) (*PromMetricsRecorder, error)

// (a) orchestrator DataMetrics
runtime.New(runtime.Options{ ..., DataMetrics: prom, ListenerFactory: factory })

// (b) listener factory — real resolver + real metrics (replaces both noops)
func makeProductionListenerFactory(resolver dataplane.DestinationResolver, m audit.MetricsRecorder) runtime.ListenerFactory {
    return func(cfg config.Config, h listener.ConnHandler, log *slog.Logger) (runtime.Listener, error) {
        addr, err := netip.ParseAddrPort(cfg.Listener.Address)
        if err != nil { return nil, err }
        opts := listener.DefaultOptions(); opts.ListenAddr = addr
        return listener.New(opts, resolver, h, m, log)     // was noopResolver{}, noopTypedMetrics{}
    }
}

// (c) control-plane server — /metrics scrapeable by kind. reg is the SAME gatherer.
// Started BEFORE the data-plane binds/accepts (startup step 8); a start failure
// aborts fail-closed. port defaults to runtime.Port15020 (15020); podIP resolves
// the empty configured host via the downward-API POD_IP.
port := runtime.Port15020
if cfg.ControlPlane.Port != 0 { port = cfg.ControlPlane.Port }
cps, err := runtime.NewControlPlaneServer(podIP, port, reg, probes) // (bindAddr string, port int, prometheus.Gatherer, ProbeSource)
if err != nil { return 1 }                                          // fail-closed: never bind data-plane
if err := cps.Start(ctx); err != nil { return 1 }                  // fail-closed abort before Serve
```

Consumed unchanged: `audit.NewPromMetricsRecorder(reg prometheus.Registerer) (*PromMetricsRecorder, error)` and `(*PromMetricsRecorder).Gather()` (prom.go); `runtime.NewControlPlaneServer(bindAddr string, port int, reg prometheus.Gatherer, probes ProbeSource) (*ControlPlaneServer, error)`, `(*ControlPlaneServer).Start/Shutdown` (control_plane_server.go). The orchestrator satisfies `ProbeSource` via `Ready()`/`Live()`; `ProbeAggregator` folds in emergency-channel readiness.

> **Address reconciliation (Findings F3).** `ControlPlaneServer` binds the pod IP and **refuses loopback / empty host** (`validateBindAddr`, ADR-S6-04), and its canonical port constant is `runtime.Port15020` (`= 15020`, `internal/runtime/control_plane_server.go`). This design reuses `Port15020` as the default; `config.ControlPlane` carries only the **bind host** (`Address`, default empty ⇒ resolved to the pod IP from the downward-API `POD_IP` env), while the port defaults to `runtime.Port15020` and is optionally overridable via `config.ControlPlane.Port`. The wire step passes `(host, port)` to `NewControlPlaneServer`; an empty host is resolved to the pod IP before the call so the loopback-forbidden invariant still holds. There is no `15090` — that value was invented and is removed in favour of the existing canonical `Port15020`.

> **[Reconciled 2026-08-24]** As built, address reconciliation moved *inside* a new constructor `runtime.NewControlPlaneServerFromConfig(cp config.ControlPlaneConfig, reg prometheus.Gatherer, probes ProbeSource) (*ControlPlaneServer, error)`, the **sole** owner of the empty-host→`POD_IP` (new `runtime.PodIPEnv` const), port-default `Port15020`, and loopback-rejection logic. `main.go` no longer performs this reconciliation manually; `mainRun()` calls `NewControlPlaneServerFromConfig` via the `deps.newControlPlane` seam. The listener factory is wired through the **exported** `runtime.MakeProductionListenerFactory(resolver, m)` (was unexported). See [Reconciliation Notes](#reconciliation-notes-implemented-state-optional).

### Gap 6 — config surface

```go
// captureOptionsFromConfig is the single mapping config → capture.Options.
// Metrics is injected separately (the PromMetricsRecorder) because Options.Metrics
// is mandatory and not expressible in YAML.
func captureOptionsFromConfig(cfg config.Config, m audit.MetricsRecorder) capture.Options
```

> **[Reconciled 2026-08-24]** As built this mapping is **exported** and takes an explicit context: `config.CaptureOptionsFromConfig(ctx context.Context, cfg Config, m audit.MetricsRecorder) capture.Options` (package `config`, not `cmd/aksh-proxy`). Companion effective-value helpers `EffectivePort`, `EffectiveFirstSnapshotTimeout`, `EffectiveMaxStaleness` are likewise exported (SI-S3-3). The loader now surfaces `capture:` (every field **except `MinKernel`**), `controlPlane:` (`address`/`port`), and `policy.resync`/`policy.firstSnapshotTimeout` in YAML plus `AKSH_CAPTURE_*`/`AKSH_CONTROLPLANE_*`/`AKSH_POLICY_*` env vars (SI-S3-1). See [Reconciliation Notes](#reconciliation-notes-implemented-state-optional).

### Parameter Validation

- `config.Config.Validate` gains capture + control-plane checks (see [Configuration](#configuration-optional)). Numeric fields left zero mean "use `capture.DefaultOptions()`"; only fields with no safe default (e.g. `Capture.PodPath`) are hard-required.
- `capture.Options.Validate()` (options.go) runs again inside `LoadAndAttach`; the config layer defaults to values that pass it (e.g. `AttachCheckInterval` in `[10s,60s]`, `ProxyUID != 0`).
- `ControlPlane.Address` is a bind **host** (not `host:port`); an empty host is allowed at config time and resolved to the pod IP at wire time (never bound as loopback). The port comes from `ControlPlane.Port` (default `runtime.Port15020`).

### Exception Behavior

All wiring failures return an error that aborts startup (fail-closed). No wiring path returns a partial or default-substituted success. See [Error Handling Strategy](#error-handling-strategy-optional).

---

## Design Decisions `[Required]`

| # | Decision | Rationale | Alternative rejected |
|---|----------|-----------|----------------------|
| DD-1 | Option A: `LoadAndAttach` returns `*Handle` (owner object) | The resolver needs the live pair map and the daemon needs a teardown owner; a Handle gives both without pinning | Return `*AttachInfo` + a separate map getter (leaks two owners); rely on pinned map (blocked by TD-6) |
| DD-2 | Attach-loss via `OnAttachLoss func(error)` callback | Lets the orchestrator decide (fail-closed drain), removes `os.Exit(1)` from a library | Keep `os.Exit(1)` (untestable, skips deferred cleanup) |
| DD-3 | `Handle.PairMap()` returns the live map, never a pin path | `PinLinks` defaults false (TD-1/M1, TD-6); pins may be rejected on 5.15 | Depend on `BPF_OBJ_GET` from a pinned path |
| DD-4 | Gap 2 is glue only; no watcher rebuild | `client.go`/`watcher.go`/`run.go`/`store.go` exist and are tested | Re-implement the informer (duplicate, risky) |
| DD-5 | One `PromMetricsRecorder` + one `prometheus.Registry`, shared as recorder and gatherer | `/metrics` must expose exactly the counters the dataplane writes | Two registries (metrics written but not scraped) |
| DD-6 | `config.ControlPlane.Address` carries only the bind **host**; port defaults to existing `runtime.Port15020` (overridable via `config.ControlPlane.Port`), host resolved to pod IP at wire time | Reuses the canonical `Port15020` (15020) — the real control-plane port constant is **not** superseded by an invented value; honours ADR-S6-04 (no loopback) | Invent a new `:15090` default (duplicate/contradicts `Port15020`) |
| DD-7 | `LoadAndAttach` runs **eagerly in `main.go`'s `run()`** before resolver/factory/`runtime.New`; the returned `*Handle` is stored in run scope and `Close()` is deferred there. `productionPreflight` is a **validate-only** seam that confirms the established attach is healthy | Resolver + factory both depend on the Handle, so the attach must complete before composition; a load/attach failure aborts fail-closed before any bind. Keeping preflight validate-only avoids surfacing the Handle back out of the orchestrator | Perform `LoadAndAttach` inside the preflight seam (runs too late — after runtime composition already needed the pair map; impossible to implement deterministically) |

---

## Key Operation Flows `[Required]`

### Resolve-on-accept Flow (Gap 3)

```text
accept(conn) → sem admit → trackHandler → goroutine:
  cc = ConnContext{Downstream, AcceptedAt}
  StageDuration(StageAcceptDispatch, since accept)  # unchanged accept→dispatch semantics
  dst, err = resolver.Resolve(conn)            # BPF pair map LookupAndDelete
  StageDuration(StageResolve, resolve time)    # NEW stage; resolve latency recorded separately
  if err:                                       # miss/stale/malformed = T1; loop-guard = T2 (metric inside resolver)
     Decisions(Deny, ReasonNoOriginalDst, TransportTLS, false)   # NEW reason; TransportTLS per invariant
     TransportReject(RejectClassNoOriginalDst, BoundNone)        # existing symbols; no "bound"
     return  → conn.Close (fail-closed)
  cc.OriginalDst = dst
  handler.Handle(ctx, cc) → passthrough/requestpath dial cc.OriginalDst
```

### Attach-loss Flow (Gap 1 + Gap 5)

```text
health loop tick → checkAttachment → proof of loss (or 3 inconclusive)
  log ERROR capture.attach_lost
  h.onLoss(err)                                 # was seam.exit(1)
     → orchestrator fail-closed trigger: cancel serve ctx
     → serve() ctx.Done → Shutdown(drain)
     → Handle.Close() (idempotent)
```

### Clean SIGTERM Flow (Gap 5)

```text
SIGTERM → ctx cancel
  orchestrator.serve ctx.Done → Shutdown (listener drain ≤30s)
  Handle.Close()          # detach + unpin + close collection (idempotent)
  ControlPlaneServer.Shutdown(ctx)
  run() returns 0
```

---

## Error Handling Strategy `[Optional]`

### Error Classification

| Failure | Where | Outcome | Class |
|---------|-------|---------|-------|
| Capture load/attach failure | `LoadAndAttach` (eager, `main.go` `run()`) | Return `*PreflightError` (E_* code); abort before any construction/Bind | Fatal startup, fail-closed |
| Unhealthy established attach | `productionPreflight` (validate-only seam) | Return error; abort before Bind | Fatal startup, fail-closed |
| In-cluster config / dynamic client / client build | `productionPolicyStartup` | Return error; `o.fail("first-snapshot", err)` | Fatal startup, fail-closed |
| First snapshot timeout | `WaitFirstSnapshot(waitCtx)` | Return ctx error; deny-all preserved (never served) | Fatal startup, fail-closed |
| Resolve failure (per-connection) | listener dispatch | Reject + close conn; record T1 metric | Per-connection, fail-closed |
| Loop guard (proxy UID) | resolver internal | Reject; resolver records T2 (alerting) | Per-connection, fail-closed |
| Metrics recorder nil registry | `NewPromMetricsRecorder` | `ErrNilRegistry`; abort startup | Fatal startup |
| Control-plane bind (loopback/empty) | `NewControlPlaneServer` / `Start` | `ErrLoopbackBindAddress` / `ErrEmptyBindAddress`; abort | Fatal startup |
| Attach-loss during serve | health loop → `OnAttachLoss` | Fail-closed drain + `Handle.Close()` | Runtime fault, fail-closed |
| Non-Linux build | every stub | `ErrUnsupportedPlatform` | Compile/run guard |

### Reject Taxonomy (Gap 3)

The listener maps a resolve failure to exactly one taxonomy row (types.go / labels.go):

| Code | `RejectClass` | Metric label | Meaning |
|------|---------------|--------------|---------|
| T1 | `RejectNoOriginalDst` / `audit.RejectClassNoOriginalDst` | `no_original_dst` | No usable pair-map record (miss/stale/malformed/non-TCP/non-IPv4/pod-local) — quiet, recorded |
| T2 | `RejectLoopGuard` / `audit.RejectClassLoopGuard` | `loop_guard` | Record written for the proxy UID — recorded by the resolver, alerting |

Every benign resolve failure wraps `capture.ErrNoOriginalDestination`; the listener does not distinguish sub-causes for the metric — all are T1. The loop guard (`ErrLoopGuard`, T2) is recorded inside the resolver before it returns.

### Retry Strategy

None. Resolution is single-shot (`LookupAndDelete` consumes the entry, INV-3). Startup gates do not retry — a failure is terminal and fail-closed. The policy watcher's internal reconnect/relist is unchanged and out of this design's surface.

---

## Thread-Safety Model `[Required]`

- **`Handle`**: `Close` is guarded by `sync.Once` (idempotent). `PairMap()` returns the retained `*ebpf.Map`; cilium/ebpf map ops are individual `bpf()` syscalls and `LookupAndDelete` is atomic in-kernel, so concurrent `Resolve` callers never double-consume (resolver_linux.go doc). `OnAttachLoss` stores the callback via `atomic.Pointer[func(error)]` (type-safe, no `interface{}` boxing); the health goroutine loads it once.
- **Health loop**: unchanged single goroutine (loader_linux.go `runHealthLoop`), now signalling via `onLoss`/`lossCh` instead of `os.Exit`. The callback must be non-blocking; the orchestrator's trigger only cancels a context (non-blocking).
- **Listener dispatch**: `cc` is confined to its connection goroutine (types.go). The resolver is stateless and safe for concurrent use.
- **`PromMetricsRecorder`**: Prometheus collectors are safe for concurrent use; one instance serves all writers and the `/metrics` gatherer.
- **`ControlPlaneServer`**: already internally synchronized (mutex + once for Start/Shutdown TOCTOU).

---

## Observability `[Required]`

### Logged Operations

| Event | Level | Fields (bounded) |
|-------|-------|------------------|
| `capture.attach_lost` | ERROR | `error` (existing; now precedes fail-closed drain, not `os.Exit`) |
| `listener: no original destination` | WARN | `error` (T1 reject) |
| `aksh-proxy: config loaded` | INFO | `sources` (existing) |
| `aksh-proxy: shutdown signal received, draining` | INFO | — (existing) |
| Startup gate failure | ERROR | `gate`, `error` (existing `failNoReturn`) |

### Performance / Error Metrics

All via the single `PromMetricsRecorder` (prom.go), exposed on `/metrics`:

| Metric | Trigger |
|--------|---------|
| `aksh_transport_reject_total{class="no_original_dst",bound="none"}` | listener resolve failure (T1) |
| `aksh_transport_reject_total{class="loop_guard"}` | resolver loop guard (T2) |
| `aksh_decisions_total{disposition,reason,fault,transport}` | every terminal connection outcome |
| `aksh_decision_duration_seconds{stage="accept_dispatch"}` | accept→dispatch timing (unchanged; excludes resolve) |
| `aksh_decision_duration_seconds{stage="resolve"}` | NEW — BPF pair-map resolve latency (`StageResolve`) |
| existing S6 policy/CA/token/audit metrics | unchanged, now actually scrapeable |

`/healthz` = liveness (`Live()`), `/readyz` = readiness (`Ready()` + emergency-channel via `ProbeAggregator`).

---

## Configuration `[Optional]`

### `CaptureConfig` (new)

Defaults come from `capture.DefaultOptions()` (options.go). YAML keys under `capture:`; env `AKSH_CAPTURE_*`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `PodPath` | string | — (**required**) | resolved pod cgroup; no safe default |
| `HostCgroupMount` | string | `/host/sys/fs/cgroup` | mandatory; defaulted |
| `LocalCgroupMount` | string | `/sys/fs/cgroup` | |
| `ProcCgroupPath` | string | `/proc/self/cgroup` | |
| `ProxyUID` | uint32 | `1774` | must be non-zero |
| `ProxyGID` | uint32 | `1774` | |
| `DNSServer` | string (host:port) | unset (disabled) | IPv4 + non-zero port if set |
| `CaptureIPv6` | bool | `false` | true rejected (5A) |
| `MountBPFFS` | bool | `false` | |
| `BlockNonTCP` | bool | `true` | false needs `AllowUnsafeStartup` |
| `RunProbe` | bool | `true` | false needs `AllowUnsafeStartup` |
| `AllowUnsafeStartup` | bool | `false` | test-only |
| `AttachCheckInterval` | duration | `30s` | `[10s,60s]`, no escape hatch |
| `PinLinks` | bool | **`false`** | TD-1/M1 — stays false |
| `PinRoot` | string | `/sys/fs/bpf` | required only when `PinLinks` |
| `MapEntries` | uint32 | `16384` | `[1024,65536]` |
| `DestMaxAge` | duration | `15s` | `[1s,120s]` |
| `MinKernel` | KernelVersion | `5.15` | floor — **not YAML/env-surfaced** (SI-S3-1: deliberately non-configurable security floor) |

### `ControlPlaneConfig` (new)

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `Address` | string (host) | `""` (empty) | bind **host** only; empty ⇒ pod IP (`POD_IP`) at wire time; never loopback (ADR-S6-04) |
| `Port` | int | `runtime.Port15020` (`15020`) | optional override of the canonical control-plane port; `0` ⇒ use `Port15020` |

### `PolicyConfig` (extended)

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `Namespace` | string | — (**required**) | existing |
| `MaxStaleness` | duration | `45s` | existing |
| `Resync` | duration | `0` | new; reserved (TD S4-1) |
| `FirstSnapshotTimeout` | duration | `30s` | new; bounds `WaitFirstSnapshot` |

### `captureOptionsFromConfig` mapping

| `capture.Options` field | Source |
|-------------------------|--------|
| `PodPath, HostCgroupMount, LocalCgroupMount, ProcCgroupPath` | `cfg.Capture.*` |
| `ProxyUID, ProxyGID` | `cfg.Capture.*` (default 1774) |
| `ListenerAddr` | `cfg.Listener.Address` (parsed; IPv4 loopback) |
| `DNSServer` | `cfg.Capture.DNSServer` (parsed) |
| `CaptureIPv6, MountBPFFS, BlockNonTCP, RunProbe, AllowUnsafeStartup, PinLinks` | `cfg.Capture.*` |
| `AttachCheckInterval, PinRoot, MapEntries, DestMaxAge, MinKernel` | `cfg.Capture.*` (defaulted) |
| `Metrics` | injected `PromMetricsRecorder` (not YAML) |
| `Context` | the daemon context |

---

## Module / Service Lifecycle `[Optional]`

| Phase | Owner | Action |
|-------|-------|--------|
| Load | main | `config.Load`, `captureOptionsFromConfig`, `NewPromMetricsRecorder` |
| Attach | main | `LoadAndAttach` → `*Handle`; register `OnAttachLoss` |
| Compose | main | resolver from `Handle.PairMap()`; factory bound to {resolver, prom}; `runtime.New` |
| Start | main → orchestrator | `ControlPlaneServer.Start` (listen first, fail-closed) → orchestrator gates → Bind → AcceptProbe → privDrop → Serve |
| Run | orchestrator | serve; health loop monitors attach |
| Drain | orchestrator + main | Shutdown (listener) → `Handle.Close()` → `ControlPlaneServer.Shutdown` |

---

## Testing Strategy `[Optional]`

### Testing Levels

**Unit (`CGO_ENABLED=0`, cross-platform, no privilege):**

- `captureOptionsFromConfig` maps every field; defaults from `DefaultOptions()`; invalid values rejected by `Config.Validate` and `Options.Validate`.
- `config.Config.Validate` accepts/rejects `Capture`/`ControlPlane`/`Policy` extensions (required `PodPath`/`Namespace`; `PinLinks=false` default; `ControlPlane.Address` host validation and `ControlPlane.Port` default `Port15020`; loopback host rejected/resolved).
- Listener dispatch: with a fake resolver returning `ErrNoOriginalDestination`, the connection is closed and `TransportReject(RejectClassNoOriginalDst, BoundNone)` + `Decisions(Deny, ReasonNoOriginalDst, TransportTLS, false)` are recorded, and `StageDuration(StageResolve, ...)` is observed; with a success, `cc.OriginalDst` is set and the handler is called.
- Metrics injection: factory passes the real resolver + recorder (not the noops); orchestrator `DataMetrics` is the same instance; `/metrics` gather returns the counters the dispatch wrote (via `httptest` on `ControlPlaneServer.Handler()`).
- Policy assembly: `productionPolicyStartup` with a fake `AkshPolicyClient` reaches a populated `*watch.Store`; a `WaitFirstSnapshot` timeout returns an error and never a store (deny-all).
- Handle lifecycle (platform-neutral parts): `Close` idempotent; `OnAttachLoss` invoked once; non-Linux `LoadAndAttach` returns `ErrUnsupportedPlatform`.
- Control-plane address reconciliation: empty host resolves to pod IP; loopback rejected.

**Privileged integration (`-tags ebpf_integration`, `-count=1`, kernel 5.15, `--privileged --ulimit memlock=-1`, `golang:1.26`):**

- `LoadAndAttach` returns a `*Handle` whose `PairMap()` is a live, non-nil `*ebpf.Map`; `AttachInfo()` carries non-zero prog ids and cgroup id.
- Resolver over the live map: seed a `pair_orig_dst` entry, `Resolve` returns it and consumes it (second lookup misses).
- `Handle.Close()` detaches all links and closes the collection; calling it twice is safe; after `Close`, `PairMap()` is nil.
- Attach-loss: forcing a detached link drives `OnAttachLoss` (not `os.Exit`).
- Migration: the ~15 existing capture `*_integration_test.go` that reference the old `*AttachInfo` return type are updated to the `*Handle` return (moved in the same slice as the Handle introduction — atomicity).

### Test Infrastructure

- TDD sequential (RED before GREEN); binding test-name contract lives in the UT spec (generated downstream).
- Reuse the S1a privileged Docker harness and the `loaderSeam`/`privDropSeam` injection pattern for health-loop and load fault injection.

---

## Best Practices `[Required]`

**Do**

- Construct exactly one `PromMetricsRecorder` + one `prometheus.Registry`; share the recorder as writer and the registry as gatherer.
- Pass `Handle.PairMap()` (the live map) to the resolver — never a pin path.
- Register `OnAttachLoss` before `Serve` so a mid-serve loss triggers a fail-closed drain.
- Resolve `ControlPlane.Address`'s empty host to the pod IP (downward API) before binding.
- Call `Handle.Close()` exactly once from the drain path; rely on its idempotency for the double-call race with attach-loss.

**Don't**

- Don't serve when any wiring step fails — refuse to start (or drop the connection).
- Don't call `l.handler.Handle` with a zero `cc.OriginalDst`; a resolve failure must reject (T1).
- Don't depend on pinning (`PinLinks` stays `false`; TD-1/TD-6).
- Don't reintroduce `os.Exit` in the capture package's serve path.
- Don't bind the control-plane to loopback or an empty host (ADR-S6-04).
- Don't build a second registry or a `noopTypedMetrics` in production paths.

---

## Limitations `[Required]`

- IPv6 capture is not implemented (5A); `CaptureIPv6=true` is rejected.
- Pin-path resolution is unvalidated on 5.15 (TD-6); the design deliberately avoids it by exposing the live map.
- The policy watcher's `ResyncPeriod` is reserved and not yet wired (TD S4-1); freshness relies on relist-on-event.
- `ControlPlane.Address` default (empty host) resolves to the pod IP + `Port15020`; a bare loopback value is refused by design.
- The SCTP / connected-UDP eBPF fixes remain unrecompiled (TD-15) and are out of scope.

---

## Risks and Mitigations `[Optional]`

| Risk | Mitigation |
|------|-----------|
| `LoadAndAttach` return-type change ripples to ~15 integration tests | Migrate them in the same slice as the Handle introduction (atomicity) — Findings F4 |
| Attach-loss callback deadlock | Callback must be non-blocking (only cancels a context); documented contract |
| Control-plane loopback/empty-host bind rejected at runtime | Resolve to pod IP at wire time; unit-test the reconciliation |
| Double `Handle.Close` (drain + attach-loss race) | `sync.Once` idempotency |
| Metrics written but not scraped | Single shared registry as both `Registerer` and `Gatherer` |

---

## Success Criteria / Definition of Done `[Optional]`

### Functional Criteria

- `aksh-proxy` boots on Linux: capture attaches, resolver reads OriginalDst, handler chain forwards, `/metrics` is scrapeable by kind, `SIGTERM` drains and `Handle.Close()` detaches cleanly.
- A missing OriginalDst rejects the connection (T1) and increments `aksh_transport_reject_total{class="no_original_dst"}`.
- First-snapshot timeout refuses to start (deny-all preserved).

### Non-Functional Criteria

- `CGO_ENABLED=0`, Go 1.26; `GOOS=linux` builds and cross-compiles clean; non-linux stubs return `ErrUnsupportedPlatform`.
- Fail-closed on every wiring failure; no `os.Exit` in the capture serve path.
- Existing green unit suites (capture/listener/policy) unaffected (seams/mocks).

### Definition of Done

- All 5 gaps + config expansion implemented with the signatures above; ~15 capture integration tests migrated; unit + privileged integration tests green; Findings TDs carried over.

---

## File Deliverables `[Optional]`

### New Files

| File | Purpose |
|------|---------|
| `internal/dataplane/capture/handle_linux.go` | `Handle` methods (`PairMap`, `Close`, `AttachInfo`, `OnAttachLoss`, `AttachLoss`) |
| `internal/dataplane/capture/handle_other.go` | non-Linux `Handle` stub (`ErrUnsupportedPlatform`) |
| `internal/policy/watch/restconfig.go` | `InClusterRESTConfig()` |

### Modified Files

| File | Change |
|------|--------|
| `internal/dataplane/capture/loader_linux.go` | `LoadAndAttach` returns `*Handle`; health loop signals `onLoss` instead of `os.Exit` |
| `internal/dataplane/capture/loader_other.go` | stub returns `(*Handle, error)` |
| `internal/config/config.go` | `Capture`, `ControlPlane` (host + `Port` default `Port15020`) structs; `Policy` extension; validation; defaults; `captureOptionsFromConfig` |
| `internal/pipeline/deny_reason.go` | **NEW** `ReasonNoOriginalDst` appended after `ReasonMissingClientHello` (closed enum; `String()="no_original_dst"`) — Finding #3 |
| `internal/audit/labels.go` | **NEW** `StageResolve` appended after `StageUpstreamDial` (closed `StageName` enum; `String()="resolve"`) — Finding #8. (No new `Bound` label: the reject uses existing `BoundNone`.) |
| `internal/dataplane/listener/listener.go` | dispatch resolve → `cc.OriginalDst`; T1 reject (`RejectClassNoOriginalDst`, `BoundNone`, `ReasonNoOriginalDst`); `StageResolve` timing |
| `internal/runtime/factory.go` | real resolver + real metrics (replace both noops) |
| `internal/runtime/orchestrator.go` | hold Handle / attach-loss trigger; drain calls `Handle.Close`; wire `DataMetrics` |
| `cmd/aksh-proxy/main.go` | assemble Options; construct recorder; real preflight/policy/resolver/metrics/control-plane; control-plane `Start` before data-plane bind; SIGTERM teardown |
| `internal/dataplane/capture/*_integration_test.go` (~15 files) | migrate `*AttachInfo` → `*Handle` return type in the same slice as the Handle introduction (atomicity) — Finding #3/F4 |

> **[Reconciled 2026-08-24]** As-built deltas to this list: `cmd/aksh-proxy/main.go` now factors wiring through a `deps` struct + `mainRun()`, with **new** files `cmd/aksh-proxy/seams.go` (interface seams), `cmd/aksh-proxy/policy_startup.go` (`productionPolicyStartup` + function-var seams), and `cmd/aksh-proxy/preflight.go` (`productionPreflight` + sentinels). `internal/runtime/control_plane_server.go` gains `NewControlPlaneServerFromConfig` + `PodIPEnv`; `internal/runtime/factory.go` exports `MakeProductionListenerFactory`; `internal/runtime/orchestrator.go` gains `CaptureHandleCloser` + `ControlPlaneStart`/`ControlPlaneShutdown` (SI-S5-1 reverse-order drain); `internal/dataplane/capture/{handle_linux.go,handle_other.go}` gain `AttachLost()`; `internal/dataplane/capture/resolver_other.go` adds the non-Linux `Resolve` stub; `internal/config/config.go` exports `CaptureOptionsFromConfig`/`Effective*` and surfaces the new YAML/env keys (SI-S3-1). See [Reconciliation Notes](#reconciliation-notes-implemented-state-optional).

### Test Files

- New unit tests for config mapping, resolve wiring, metrics injection, Handle lifecycle, policy assembly; migrated capture integration tests; control-plane reconciliation test.
- **[Reconciled 2026-08-24]** As built: `cmd/aksh-proxy/{policy_startup,preflight,run,main,fakes}_test.go`, `internal/runtime/control_plane_wiring_test.go` (incl. the two SI-S5-1 reverse-order teardown regression tests), `internal/policy/watch/restconfig_test.go`, and `internal/config/loader_capture_test.go` (SI-S3-1 YAML/env surfacing regression tests). The exported `config.CaptureOptionsFromConfig` and `Config.Validate` capture rows are covered in `internal/config/config_test.go`.

---

## Technical Decisions / Open Items

| ID | Item | Status |
|----|------|--------|
| TD-S9b-1 | Preflight seam vs. main-side load ordering (DD-7): the Handle is built **eagerly in `main.go`'s `run()`** before `runtime.New` and stored in run scope; the orchestrator `Preflight` seam is **validate-only** (confirms the established attach is healthy) and does not perform `LoadAndAttach` | Resolved (DD-7); eager-load-in-main chosen (preflight-side load is impossible — runtime composition needs the pair map first) |
| TD-S9b-2 | `config.ControlPlane` host + reuse of existing `runtime.Port15020` (no invented `15090`) + loopback-forbidden bind | Resolved (DD-6/F3); `Port15020` default, pod-IP resolution at wire time |
| TD-S9b-3 | Closed-enum constants: `audit.RejectClassNoOriginalDst` **exists**; `audit.BoundNone` **exists** (used; no `BoundOriginalDst`); NEW `pipeline.ReasonNoOriginalDst` (deny_reason.go) + NEW `audit.StageResolve` (labels.go) must be added | **Resolved (2026-08-24)** — both constants added and verified (UT #110–#113; `deny_reason_test.go`, `labels_test.go`) |
| TD-S9b-4 | Slicing boundaries (>300 prod LOC) | Deferred to `design-slicing workflow` |
| Carried | TD S6-1 (preflight not wired) — resolved by Gap 1/5 | This design |
| Carried | TD S6-2 (policy client not wired) — resolved by Gap 2 | This design |
| Carried | TD-1/M1 (pin vs. kubelet cgroup) — `PinLinks` stays false | Out of scope |
| Carried | TD-6 (pin unvalidated on 5.15) — no dependence on pinning | Out of scope |
| Carried | TD-15 (SCTP/UDP recompile) | Out of scope |

---

## References `[Required]`

- [S8 — aksh-proxy Runtime Assembly](./S8-proxy-runtime.md) — Orchestrator seams, `assemble()` order; Findings TD S6-1 (preflight), TD S6-2 (policy client), S6-3 (nil-seam defaults).
- [S1a — Data-plane Capture](./S1a-dataplane-capture.md) — loader/attach/health loop, resolver §8, reject taxonomy §14; Findings TD-1 (M1), TD-6 (pin on 5.15), imp #15 (SCTP/UDP).
- [S6 — Observability](./S6-observability.md) — `PromMetricsRecorder`, control-plane `/metrics`/`/healthz`/`/readyz`, ADR-S6-04 (pod-IP bind).
- [S2 — Policy CRD](./S2-policy-crd.md) — AkshPolicy GVR, namespaced watch.
- Code: `cmd/aksh-proxy/main.go`; `internal/dataplane/capture/{loader_linux.go,options.go,resolver_linux.go,types.go,errors.go}`; `internal/dataplane/interfaces.go`; `internal/dataplane/listener/{listener.go,types.go}`; `internal/runtime/{factory.go,orchestrator.go,assembly.go,control_plane_server.go}`; `internal/audit/{prom.go,labels.go}`; `internal/policy/watch/{client.go,watcher.go,run.go,store.go}`; `internal/config/config.go`.

---

## Appendix `[Optional]`

### Interface Summary `[Optional]`

```go
// Gap 1
func LoadAndAttach(opts *Options) (*Handle, error)
func (h *Handle) PairMap() *ebpf.Map
func (h *Handle) AttachInfo() AttachInfo
func (h *Handle) Close() error
func (h *Handle) OnAttachLoss(fn func(error))
func (h *Handle) AttachLoss() <-chan error

// Gap 2
func InClusterRESTConfig() (*rest.Config, error)
func productionPolicyStartup(cfg config.Config, log *slog.Logger, failClosed func(error)) func(context.Context) (*watch.Store, error)

// Gap 3 (existing, consumed)
type DestinationResolver interface{ Resolve(conn net.Conn) (netip.AddrPort, error) }
// NEW closed-enum constants (owning files): pipeline.ReasonNoOriginalDst (deny_reason.go),
// audit.StageResolve (labels.go). audit.RejectClassNoOriginalDst and audit.BoundNone already exist.

// Gap 4 (existing, consumed)
func NewPromMetricsRecorder(reg prometheus.Registerer) (*PromMetricsRecorder, error)
func NewControlPlaneServer(bindAddr string, port int, reg prometheus.Gatherer, probes ProbeSource) (*ControlPlaneServer, error)
const Port15020 = 15020 // canonical control-plane port (reused; not superseded)

// Gap 6
func captureOptionsFromConfig(cfg config.Config, m audit.MetricsRecorder) capture.Options
```
