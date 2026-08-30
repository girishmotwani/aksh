# S8 — aksh-proxy Runtime Assembly Design Document

---

## Metadata `[Required]`

| Field | Value |
|-------|-------|
| **Author** | GitHub Copilot CLI |
| **Date** | 2026-08-20 |
| **Status** | Implemented (reconciled to code — Phase 6 slices 1–6) |
| **Interface** | `cmd/aksh-proxy/main.go`; `internal/config`; `internal/pki/interfaces.go`; `internal/token/entra`; `internal/policy/watch` |
| **Implementation** | `internal/runtime` (`orchestrator.go`, `assembly.go`, `factory.go`, `token_acquirer.go`, `tls_conn_handler.go`); `cmd/aksh-proxy/main.go`; composed `internal/{config,pki,token,token/entra,policy/watch,pipeline,dataplane/*,audit}` |
| **Mock** | Test fakes in the corresponding `_test.go` files |
| **Dependencies** | [S0](./S0-architecture.md); [S1a](./S1a-dataplane-capture.md); [S1b](./S1b-request-path.md); [S1c](./S1c-transport.md); [S2](./S2-policy-crd.md); [S3](./S3-token-broker.md); [S5](./S5-injection-pki.md) |

### Revision History `[Optional]`

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2026-08-20 | GitHub Copilot CLI | Initial design |
| 1.0 | 2026-08-22 | GitHub Copilot CLI | Artifact reconciliation to the implemented Phase 6 code (slices 1–6): `Orchestrator`/`Options` seam struct, `assemble()` compose order, two-sided fail-closed staleness, `watch.Store` cell shape. Annotated the not-yet-built `capture.PreflightSeams` builder (TD S6-1) and client-go `watch.AkshPolicyClient` construction (TD S6-2) as `[Planned -- not yet implemented]`; no forward-looking content deleted. |

### Glossary `[Optional]`

| Term | Definition |
|------|------------|
| Phase A | Startup work before binding the data-plane listener. |
| Phase B | Post-bind `AcceptProbe` redirect gate before serving. |
| First snapshot | First successfully compiled `policy.PolicySnapshot` selecting this pod. |
| Local self-test | WIF config and projected-token-file checks with no Entra call. |
| credID | `token.CredID(rc)` = `hash(identity | provider | resource)` from `token.ResolvedCredential`; generic across token consumers. |

---

## Overview `[Required]`

### Executive Summary

Phase 6 builds the cluster-native `aksh-proxy` sidecar daemon for `github.com/girishmotwani/aksh` (Go 1.26). It assembles the existing capture, listener, TLS termination, request path, upstream, pipeline, policy, token, PKI, and audit libraries into one fail-closed process.

The daemon startup order is fixed: config load → `capture.RunPreflight` and attach → CA ready → first policy snapshot → S3 local self-test → `listener.Bind` → Phase-B `AcceptProbe` → privilege drop to UID/GID 1774 → `Serve` → SIGTERM drain through `listener.Shutdown`. The data-plane port **MUST NOT bind** until CA, first snapshot, and local self-test all succeed.

### Design Principles

| # | Principle | Description |
|---|-----------|-------------|
| 1 | Fail closed | Missing or stale policy, CA mismatch, token acquisition failure, audit failure, or startup-gate failure denies or prevents bind. |
| 2 | Self-contained sidecar | ADR-S0-06 remains binding: no central token broker or policy service. |
| 3 | No flags | Config sources are defaults → ConfigMap file → `AKSH_*` env only. |
| 4 | Local readiness | Readiness never calls Entra. |
| 5 | Exact reuse | Existing constructors are used with their actual signatures; only documented new/reconciled APIs change. |

### Scope `[Optional — include for larger components]`

**In Scope**

| Component | Responsibility |
|-----------|----------------|
| `cmd/aksh-proxy` | Entrypoint, lifecycle, signals, probes. |
| `internal/config` | Config schema, precedence, validation. |
| `internal/pki` | Concrete per-pod CA provider and reconciled interface. |
| `internal/token/entra` | Entra WIF acquirer implementing `token.TokenAcquirer`. |
| `internal/policy/watch` | `client-go` watch, compile, atomic store, staleness. |

**Out of Scope**

| Item | Reason / Covered By |
|------|---------------------|
| Full Kubernetes manifests vs reference RBAC | Deferrable OQ-5. <!-- TODO --> |
| Non-Entra providers | FR10/v1 seam only. |
| In-place CA rotation | S5 says rotation = pod restart. |

### File Locations

| Artifact | Path |
|----------|------|
| Entrypoint | `cmd/aksh-proxy/main.go` |
| Config | `internal/config` |
| CA provider | `internal/pki` |
| Entra acquirer | `internal/token/entra` |
| Policy watch | `internal/policy/watch` |

---

## Problem Statement `[Optional]`

Phases 0–5 produced libraries, but no daemon assembles them into a protected pod process. Without Phase 6, redirected traffic has no complete runtime enforcing CA readiness, policy freshness, WIF token custody, audit, and graceful shutdown.

---

## Architecture `[Required]`

### Class Diagram

```text
┌──────────────────────────┐
│ cmd/aksh-proxy main      │
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│ Runtime Orchestrator     │
│ Run / Ready / Live       │
└─┬───────┬───────┬────────┘
  │       │       │
  ▼       ▼       ▼
config  pki.PodCAProvider  policy/watch.Store ──implements──▶ policy.PolicyStore
  │       │       │
  │       ▼       ▼
  │   tlsterm.NewCachedLeafSource      pipeline.MatchStage
  │       │
  ▼       ▼
listener.New ◀── requestpath.NewHandler ◀── pipeline.NewPipeline ◀── token.NewTokenCache ◀── entra.Acquirer
  │
  ├─ Bind
  ├─ AcceptProbe
  ├─ Serve
  └─ Shutdown
```

### Dependency Graph

```text
cmd/aksh-proxy
  ├─ internal/config
  ├─ internal/dataplane/capture       RunPreflight, resolvers, privilege drop seams
  ├─ internal/pki                     CAProvider + PodCAProvider
  ├─ internal/policy/watch            client-go, policy.Compile, PolicyStore
  ├─ internal/token/entra             TokenAcquirer, CRD-facing Resolve
  ├─ internal/token                   NewTokenCache, Resolve, CredID, Breaker, NegativeCache
  ├─ internal/pipeline                NewPipeline and stages
  ├─ internal/dataplane/tlsterm       NewCachedLeafSource, NewTerminator
  ├─ internal/dataplane/upstream      NewDirectDialer, SelfDialRegistry
  ├─ internal/dataplane/requestpath   NewHandler
  ├─ internal/dataplane/listener      New, Bind, AcceptProbe, Serve, Shutdown
  └─ internal/audit                   sinks, metrics, NewRejectionRecorder
```

### High-Level Flow

:::mermaid
flowchart TD
    A[Load config: defaults ConfigMap AKSH env] --> B[capture.RunPreflight + attach]
    B --> C[Construct capture resolvers]
    C --> D[Load/generate CA; write public PEM]
    D --> E[Start policy watcher]
    E --> F[Wait first policy.Compile snapshot]
    F --> G[S3 local self-test; no Entra call]
    G --> H[listener.Bind 127.0.0.1:15001]
    H --> I[Phase-B listener.AcceptProbe]
    I --> J[Drop privileges UID/GID 1774]
    J --> K[listener.Serve]
    K --> L[SIGTERM listener.Shutdown]
:::

---

## Core Data Types `[Required]`

### Config

```go
package config

import "time"

type Config struct {
    Listener ListenerConfig
    CA       CAConfig
    Policy   PolicyConfig
    Token    TokenConfig
    Audit    AuditConfig
}

type ListenerConfig struct { Address string }
type CAConfig struct { PrivDir, PubDir string }
type PolicyConfig struct { Namespace string; MaxStaleness time.Duration }
type TokenConfig struct { SATokenPath string; Entra EntraConfig }
type EntraConfig struct { TenantID, ClientID, Authority string }
type AuditConfig struct { Sink string }
```

| Field | Type | Purpose |
|-------|------|---------|
| `Listener.Address` | `string` | Data-plane bind, default `127.0.0.1:15001`. |
| `CA.PrivDir` | `string` | Key+cert emptyDir mounted only into `aksh-proxy`. |
| `CA.PubDir` | `string` | Public CA emptyDir shared read-only to the agent. |
| `Policy.Namespace` | `string` | Own namespace from downward API. |
| `Policy.MaxStaleness` | `time.Duration` | Deny-all threshold, default `45s`. |
| `Token.SATokenPath` | `string` | Projected SA token file read on every exchange. |
| `Token.Entra` | `EntraConfig` | Explicit WIF provider config; no ambient chain. |
| `Audit.Sink` | `string` | Rejection/decision sink; cannot be disabled. |

### Policy Watch Store

```go
package watch

import (
    "sync/atomic"
    "time"

    "github.com/girishmotwani/aksh/internal/policy"
)

type cell struct {
    snapshot policy.PolicySnapshot
    updated  time.Time // publication time, carrying a monotonic reading
}

type Store struct {
    current atomic.Value // holds *cell; nil until the first Swap
    now     func() time.Time // unexported test seam; nil means production time.Now
}

// Current returns the latest snapshot and its raw (unclamped) age. Under a clock
// anomaly the age may be negative; security consumers MUST treat age < 0 as stale
// (or call Fresh, which already does).
func (s *Store) Current() (policy.PolicySnapshot, time.Duration, bool)
// Fresh is the fail-closed request-time gate: it returns the snapshot only when
// 0 <= age < maxStaleness. A negative age (clock anomaly) and age >= maxStaleness
// are both denied (two-sided fail-closed).
func (s *Store) Fresh(maxStaleness time.Duration) (policy.PolicySnapshot, bool)
func (s *Store) Swap(snapshot policy.PolicySnapshot, now time.Time)
```

### ProbeStatus

```go
type ProbeStatus struct {
    Ready  bool
    Live   bool
    Reason string
}
```

---

## API Reference `[Required]`

### Existing APIs Used Exactly

```go
func capture.RunPreflight(opts *capture.Options, seams capture.PreflightSeams) error // [Planned -- not yet implemented] production capture.PreflightSeams builder (loader/attacher/cgroup-resolver/redirect-prober) is not yet wired (TD S6-1); main.go injects a fail-closed placeholder that refuses to start.
func capture.NewPodCgroupResolver(cfg *capture.PodCgroupResolverConfig) (*capture.PodCgroupResolver, error)
func capture.NewBPFDestinationResolver(destMap any, opts capture.Options) (*capture.BPFDestinationResolver, error)

func tlsterm.NewCachedLeafSource(ca pki.CAProvider, opts tlsterm.LeafOptions) (*tlsterm.CachedLeafSource, error)
func tlsterm.NewTerminator(source dataplane.LeafSource, opts tlsterm.LeafOptions, metrics audit.MetricsRecorder) (*tlsterm.Terminator, error)

func listener.New(opts listener.Options, resolver dataplane.DestinationResolver, h listener.ConnHandler, m audit.MetricsRecorder, log *slog.Logger) (*listener.Listener, error)
func (l *listener.Listener) Bind() error
func (l *listener.Listener) AcceptProbe(deadline time.Time) (net.Conn, error)
func (l *listener.Listener) Serve(ctx context.Context) error
func (l *listener.Listener) Shutdown(ctx context.Context) error

func listener.NewSelfDialRegistry() *listener.SelfDialRegistry
func upstream.NewDirectDialer(opts upstream.UpstreamOptions, reg *listener.SelfDialRegistry, m audit.MetricsRecorder) (*upstream.DirectDialer, error)
func requestpath.NewHandler(p *pipeline.Pipeline, dialer dataplane.UpstreamDialer, sink audit.AuditSink, metrics audit.MetricsRecorder, opts requestpath.Options) (*requestpath.Handler, error)
func pipeline.NewPipeline(stages []pipeline.Stage, sink pipeline.AuditSink) *pipeline.Pipeline

func policy.Compile(policies []v1alpha1.AkshPolicy) (policy.PolicySnapshot, error)
func policy.NewMatcher() policy.Matcher
func token.NewTokenCache(provider token.TokenAcquirer, opts token.CacheOptions) *token.CachingTokenCache
func token.NewBreaker(threshold, probeIntervalSec int) *token.Breaker
func (b *token.Breaker) IsOpen() bool
func (b *token.Breaker) AllowRequest() bool
func (b *token.Breaker) RecordFailure(class token.AcquireErrorClass)
func (b *token.Breaker) RecordSuccess()
func token.NewNegativeCache(maxEntries int, ttl time.Duration) *token.NegativeCache
func (nc *token.NegativeCache) Get(id string) *token.AcquireError
func (nc *token.NegativeCache) Put(id string, err *token.AcquireError)
func token.Resolve(sel token.CredentialSelector) (token.ResolvedCredential, error)
func token.CredID(rc token.ResolvedCredential) string
func audit.NewRejectionRecorder(sink audit.AuditSink, metrics audit.MetricsRecorder, maxConcurrent int, timeout time.Duration, emerg func(format string, args ...any)) *audit.RejectionRecorder
```

### Reconciled `pki.CAProvider` Interface

Phase 6 adopts S5 §6.1.1 and replaces the current `CA() (*x509.Certificate, crypto.Signer, error)` / `Generation() int64`. `internal/dataplane/tlsterm` and tests must be updated to call `Signer()` and use `uint64` generation keys.

```go
package pki

import (
    "crypto"
    "crypto/x509"
)

type CAProvider interface {
    Signer() (*x509.Certificate, crypto.Signer)
    Generation() uint64
    PublicPEM() []byte
}
```

Caller invariant: Callers MUST NOT invoke `Signer()` before the Orchestrator passes the CA startup gate (startup step 5). The gate guarantees a non-nil cert+signer for the pod lifetime; therefore `Signer()` has no error return and an uninitialized/unusable CA is a fatal invariant violation (fatal/panic), not a recoverable per-leaf error. `tlsterm.CachedLeafSource` must be constructed only after the CA gate succeeds, so `mint()` can never reach an uninitialized CA.

After this reconcile, `tlsterm.CachedLeafSource.mint()` calls `caCert, caSigner := s.ca.Signer()` and proceeds to `x509.CreateCertificate`; there is no CA lookup error to wrap or propagate from the mint path.

### New Config Loader API

```go
package config

func Load() (Config, error)
func LoadFrom(path string, getenv func(string) string) (Config, error)
func (c Config) Validate() error
```

### New CA Provider API

```go
package pki

import "context"

type PodCAOptions struct { PrivDir, PubDir string }
func NewPodCAProvider(ctx context.Context, opts PodCAOptions) (*PodCAProvider, error)
```

### New TLS Connection Handler Adapter API

`requestpath.Handler` already satisfies `listener.ConnHandler` via `Handle(ctx, *listener.ConnContext) error` in `internal/dataplane/requestpath/adapter.go`. The runtime adapter exists only to insert downstream TLS termination before the request path.

```go
package runtime

import (
    "context"
    "crypto/tls"

    "github.com/girishmotwani/aksh/internal/dataplane/listener"
    // tlsterm is used by configForClient and NewTLSTerminatingConnHandler, which
    // are omitted from this excerpt; no type declared below references it.
    "github.com/girishmotwani/aksh/internal/dataplane/tlsterm"
)

// tlsTerminator is the narrow downstream-TLS contract the handler consumes.
type tlsTerminator interface {
    GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error)
    PostHandshakeAssert(state tls.ConnectionState, candidateSNI string) error
    RecordHandshakeFailure(candidateSNI string)
}

type tlsTerminatingConnHandler struct {
    Terminator tlsTerminator
    Next       listener.ConnHandler
}

func NewTLSTerminatingConnHandler(next listener.ConnHandler, term *tlsterm.Terminator) (*tlsTerminatingConnHandler, error)

func (h tlsTerminatingConnHandler) Handle(ctx context.Context, cc *listener.ConnContext) error
```

**Why the field is a seam, not the concrete terminator.** `Terminator` is the unexported `tlsTerminator` interface rather than `*tlsterm.Terminator` so that a test double can induce a `PostHandshakeAssert` failure through a mechanism that exists in the production type graph. The only alternative was to pre-seed `ConnContext.CandidateSNI` with a value that disagrees with the negotiated `ServerName` — a state production code is contractually required to overwrite, and manufacturing it is what masked issue #32. The seam is unexported, so it adds no public API; the concrete `*tlsterm.Terminator` satisfies it unchanged, and `NewTLSTerminatingConnHandler` still takes the concrete `*tlsterm.Terminator`.

**Why the nil guard is reflective.** `assembly.go` builds the handler with a struct literal (`tlsTerminatingConnHandler{Terminator: term, Next: handler}`), deliberately bypassing `NewTLSTerminatingConnHandler` and its nil check, so no constructor-side guard can be relied on. Introducing an interface field also creates a failure mode a plain `h.Terminator == nil` test cannot see: an interface holding a nil value of an implementing type is non-nil. `Handle` therefore calls the `terminatorIsNil` helper, which switches on the dynamic kind reported by `reflect.ValueOf` and returns `IsNil()` for `Pointer`, `Map`, `Slice`, `Func`, `Chan` and `UnsafePointer` — every kind whose nil value can carry the three seam methods and then panic or misbehave on first use. Narrowing the switch to `reflect.Pointer` alone is not sufficient: a nil map type implementing the seam then reaches `RecordHandshakeFailure` and reproduces `panic: assignment to entry in nil map`. `reflect.Interface` is absent because `reflect.ValueOf` reports the dynamic kind and never returns `Interface`. Rejection is fail-closed and loud (`errNilTerminator`).

`Handle` performs the downstream TLS handshake through `Terminator` (`GetConfigForClient` via the capture closure below, `HandshakeContext`, `PostHandshakeAssert`), records handshake failures through the terminator, populates the `listener.ConnContext` TLS fields, then delegates to `Next.Handle(ctx, cc)`. Passing the bare `requestpath.Handler` to `listener.New` bypasses TLS termination and is invalid for Phase 6.

#### Where `CandidateSNI` is recorded

`Handle` does **not** pass `Terminator.GetConfigForClient` directly to `tls.Server`. It installs a per-connection closure produced by the `configForClient(cc)` factory, which first delegates to `Terminator.GetConfigForClient(hello)` and, **only when certificate selection succeeds**, records `tlsterm.CanonicaliseServerName(hello.ServerName)` onto `cc.CandidateSNI`. This is the capture point mandated by step 4 ("record id on the ConnContext") of the ClientHello sequence in `S1a-dataplane-capture.md`, and it is what makes the INV-8 confused-deputy check non-tautological — `tlsterm.Terminator.PostHandshakeAssert` compares the recorded candidate against the negotiated `ServerName`, and `pipeline.IdentityStage` denies with `ReasonIdentityMismatch` when the SNI and the HTTP authority host disagree. With the field permanently empty, `PostHandshakeAssert` rejected every TLS connection and `IdentityStage` silently fell back to the agent-controlled authority host (issue #32).

- The recorded value is the **canonical** form produced by `tlsterm.CanonicaliseServerName` — lowercased, single trailing root-zone dot stripped, IP literals and wildcards rejected, each label LDH-validated — never the raw ClientHello bytes. It is byte-identical to the identity the leaf was minted for, because both derivations use the same rule set.
- On every **reject path** — no SNI, single-label SNI, non-LDH (e.g. raw unicode U-label) SNI, or leaf-source/certificate-selection failure — the closure returns before the recording statement, so `cc.CandidateSNI` stays empty and the handshake fails closed. A plaintext or identity-less connection therefore never acquires an identity.
- If canonicalisation of an already-accepted hello fails (currently unreachable, since the terminator canonicalised the same input successfully one statement earlier), the closure returns a wrapped `runtime: capture canonicalisation` error and the handshake is rejected.
- The closure is created **per connection** and captures only that connection's `cc`, so concurrent handshakes cannot cross-contaminate identities; there is no shared mutable state. The field is written on the goroutine that calls `HandshakeContext`, which is the same goroutine that later reads it, so no lock is required.
- `cc.CandidateSNI` is **overwritten unconditionally** on the success path. A caller-supplied value is never trusted and never survives; a conditional "record only when empty" write would let a forged identity reach `PostHandshakeAssert` and reinstate exactly the confused-deputy bypass INV-8 exists to close.

**Forbidden alternative.** Assigning `cc.CandidateSNI = state.ServerName` after `HandshakeContext` returns — i.e. deriving the candidate from the same `tls.ConnectionState` that `PostHandshakeAssert` then checks it against — must never be done. It would make the assertion compare a value with itself, rendering INV-8 tautologically true and voiding the confused-deputy protection entirely, while appearing to fix the symptom (a green handshake). Verified on this branch: `state.ServerName` appears nowhere in `internal/runtime` (`Select-String -Path internal\runtime\*.go -Pattern 'state\.ServerName'` returns no matches). The capture must come from `hello.ServerName` inside the ClientHello callback, before the handshake completes.

`Downstream`, `Protocol`, `Transport` and `NegotiatedALPN` are populated later — in `Handle`, in the block immediately following the successful `PostHandshakeAssert` call — strictly after the SNI capture. Citations in this section are anchored to symbol names with no line ranges: bare ranges for this file went stale twice inside a single branch (see Findings improvements 33 and 36).

### New Entra WIF API

```go
package entra

import (
    "context"
    "net/http"
    "time"

    v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
    "github.com/girishmotwani/aksh/internal/token"
)

type Options struct {
    TenantID    string
    ClientID    string
    Authority   string
    SATokenPath string
    HTTPClient  *http.Client
    Timeout     time.Duration
}

type Acquirer struct { /* private fields */ }
func NewAcquirer(opts Options) (*Acquirer, error)
func (a *Acquirer) Acquire(ctx context.Context, rc token.ResolvedCredential) (token.Token, error)
func Resolve(sel *v1alpha1.CredentialSelector) (token.ResolvedCredential, error)
func LocalSelfTest(opts Options) error
```

`Acquirer.Acquire` implements existing `token.TokenAcquirer`, the cache-facing interface that accepts a `token.ResolvedCredential` and returns a `token.Token`. It does **not** implement `token.TokenProvider`, which is the higher-level resolve-plus-acquire interface taking `token.CredentialSelector`.

`entra.Resolve(sel *v1alpha1.CredentialSelector)` is a CRD-facing helper: it converts `v1alpha1.CredentialSelector` into the value type `token.CredentialSelector`, adds Entra-specific validation (provider must be empty or `"entra"`), and delegates to existing `token.Resolve(sel token.CredentialSelector)`. It must not duplicate or conflict with `token.Resolve`. `token.CredID(rc)` is approved OQ-4: `hash(identity | provider | resource)` and lives in `internal/token` beside `ResolvedCredential` because audit correlation and upstream pool keying are not Entra-specific.

### New Policy Watch API

```go
package watch

import (
    "context"
    "time"

    v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
    "github.com/girishmotwani/aksh/internal/policy"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    kwatch "k8s.io/apimachinery/pkg/watch"
)

type Options struct {
    Namespace    string
    PodLabels    map[string]string
    MaxStaleness time.Duration
    ResyncPeriod time.Duration
}

type AkshPolicyClient interface {
    List(ctx context.Context, opts metav1.ListOptions) (*v1alpha1.AkshPolicyList, error)
    Watch(ctx context.Context, opts metav1.ListOptions) (kwatch.Interface, error)
}
// [Planned -- not yet implemented] The production construction of a namespaced
// client-go AkshPolicyClient (in-cluster kubeconfig + informer) feeding
// watch.NewWatcher/WaitFirstSnapshot is not yet built (TD S6-2). The Store,
// Watcher, and AkshPolicyClient seam exist and are unit-tested; main.go injects
// a fail-closed PolicyStartup placeholder that refuses to start until the real
// client is wired.

type Watcher struct { /* private fields */ }
func NewWatcher(opts Options, client AkshPolicyClient, store *Store) (*Watcher, error)
func (w *Watcher) Run(ctx context.Context) error
func (w *Watcher) WaitFirstSnapshot(ctx context.Context) error
func (s *Store) Current() (policy.PolicySnapshot, time.Duration, bool)
func (s *Store) Fresh(maxStaleness time.Duration) (policy.PolicySnapshot, bool)
```

### Parameter Validation

| Method | Parameter | Required | Validation |
|--------|-----------|----------|------------|
| `Config.Validate` | `listener.address` | Yes | IPv4 loopback `host:port`; reject non-loopback host. Port `0` is accepted for OS-assigned test binds such as `127.0.0.1:0`. |
| `Config.Validate` | `policy.maxStaleness` | Yes | `> 0`; default `45s`; no disable value. |
| `Config.Validate` | `tenantID`, `clientID` | Yes | Non-empty; no fallback. |
| `NewPodCAProvider` | `PrivDir`, `PubDir` | Yes | Non-empty directories; mismatch fatal. |
| `NewAcquirer` | `Authority` | Yes | HTTPS URL. |
| `NewWatcher` | `Namespace` | Yes | Non-empty own namespace only. |

### Exception Behavior `[Optional — include when methods throw domain exceptions]`

| Method | Condition | Behavior |
|--------|-----------|----------|
| `Config.Validate` | Config would weaken TLS verify, audit, or fail-closed | Return error; no such keys are accepted. |
| `NewPodCAProvider` | Existing key/cert or public copy mismatch | Fatal startup error; do not regenerate. |
| `Acquirer.Acquire` | 429/5xx/timeout | `*token.AcquireError{Class: token.AcquireErrorTransient}`. |
| `Acquirer.Acquire` | invalid scope/client/federation | `*token.AcquireError{Class: token.AcquireErrorPermanent}`. |
| `Store.Fresh` | No snapshot, age `< 0` (clock anomaly), or age `>= maxStaleness` | Return false; caller denies all (two-sided fail-closed). |

---

## Design Decisions `[Required]`

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | One S8 runtime design doc with per-adapter sections. | Approved OQ-6; avoids assembly-order drift. |
| 2 | Adopt S5 `CAProvider` signature. | Approved OQ-1; startup validates CA so leaf minting need not return CA lookup error. |
| 3 | Use approved config schema, no flags. | S0 §9 and OQ-2. |
| 4 | `policy.maxStaleness` default is `45s`. | Approved OQ-3. |
| 5 | `token.CredID(rc) = hash(identity | provider | resource)`. | Approved OQ-4; provider-neutral pool/audit key owned by `internal/token`. |
| 6 | Add `client-go`; watch only own namespace. | S2/S5: direct namespaced watch and read-only RBAC. |
| 7 | Readiness is local-only. | S3: prevents Entra outage restart storms. |
| 8 | Attach before bind; drop before serve. | Prevents capture gaps and serving with elevated privileges. |

---

## Key Operation Flows `[Required]`

### Startup Flow

```text
1. main creates root context and signal handler.
2. config.Load applies defaults → ConfigMap file → AKSH_* env; Validate rejects invariant-weakening config.
3. capture.RunPreflight(&captureOpts, seams); privileged load/attach completes before bind.
4. Construct cgroup and destination resolvers.
5. pki.NewPodCAProvider loads/generates CA, persists private key+cert, writes PublicPEM.
6. Start policy watcher; wait for first successful policy.Compile snapshot selecting this pod.
7. entra.LocalSelfTest validates config and projected JWT file only.
8. Compose token cache, pipeline, upstream dialer, request handler, TLS leaf source/terminator, listener.
9. listener.Bind opens 127.0.0.1:15001.
10. Phase-B redirect probe is accepted by listener.AcceptProbe(deadline).
11. Drop privileges to UID/GID 1774.
12. listener.Serve(ctx).
13. SIGTERM calls listener.Shutdown(shutdownCtx).
```

> **[Planned -- not yet implemented] for two steps.** Every gate is an injectable seam on `runtime.Options`; a nil seam defaults to a benign success so the skeleton lifecycle keeps working, and production `cmd/aksh-proxy/main.go` wires the real fail-closed implementations. Steps 3 (`capture.RunPreflight` + attach) and 6 (policy watcher first snapshot) depend on production infrastructure that no prior slice built — the real `capture.PreflightSeams` builder (TD S6-1) and the namespaced client-go `watch.AkshPolicyClient` construction (TD S6-2). Until those are wired, `main.go` injects fail-closed placeholders (`productionPreflight`/`productionPolicyStartup`) that refuse to start rather than serving with capture unattached or without a compiled policy snapshot. All other steps are implemented and injected as real seams (`pki.NewPodCAProvider`, `entra.LocalSelfTest`, `capture.DropPrivileges`, `audit.NewStreamSink`).

### Startup Sequence Diagram

:::mermaid
sequenceDiagram
    participant M as main
    participant C as config
    participant Cap as capture
    participant CA as pki
    participant W as policy/watch
    participant T as entra
    participant L as listener
    M->>C: Load + Validate
    M->>Cap: RunPreflight + attach
    M->>CA: NewPodCAProvider
    CA-->>M: PublicPEM written
    M->>W: Run + WaitFirstSnapshot
    W-->>M: snapshot version
    M->>T: LocalSelfTest (no network)
    T-->>M: local OK
    M->>L: New + Bind
    M->>L: AcceptProbe
    M->>Cap: DropPrivileges UID/GID 1774
    M->>L: Serve
:::

### Policy Watch Flow

```text
relist namespace AkshPolicy objects → filter by pod labels → policy.Compile → atomic Swap
watch events/bookmarks → compile new complete set → swap on success
compile failure → retain previous snapshot; staleness timer continues
watch break/410 → bounded backoff + full relist
request-time: no snapshot = deny all; age < 45s = serve; age >= 45s = deny all
```

### Token Acquire Flow

```text
entra.Acquirer.Acquire(ctx, rc):
  reject rc.Provider != entra
  read SATokenPath fresh from disk
  POST client_credentials with client_assertion over verified HTTPS
  map provider/network errors to token.AcquireError classes
  return token.NewToken(accessToken, expiresAt)

Runtime acquisition pipeline passed to token.NewTokenCache(guardedAcquirer, opts):
  breaker := token.NewBreaker(5, 30)                  // 5 transient failures → open; 30s probe
  negative := token.NewNegativeCache(256, 30*time.Second)
  Acquire(ctx, rc):
    credID := token.CredID(rc)
    if cached := negative.Get(credID); cached != nil: return error(cached)
    if !breaker.AllowRequest(): return transient token.AcquireError
    tok, err := entra.Acquirer.Acquire(ctx, rc)
    if err != nil:
      classify/unwrap to *token.AcquireError
      negative.Put(credID, acquireErr)
      breaker.RecordFailure(acquireErr.Class)
      return err
    breaker.RecordSuccess()
    return tok, nil
  cache := token.NewTokenCache(guardedAcquirer, token.CacheOptions{MaxEntries: 256})

`guardedAcquirer` is a Phase 6 runtime adapter implementing `token.TokenAcquirer` with fields `Base token.TokenAcquirer`, `Breaker *token.Breaker`, and `Negative *token.NegativeCache`; it uses only the real token APIs listed above. `token.Breaker` is a gate, not a decorator: the acquisition pipeline calls `AllowRequest()` before an exchange, then `RecordFailure(class)` or `RecordSuccess()` after the exchange. `token.NegativeCache` is also composed explicitly: the pipeline checks `Get(credID)` before the exchange and calls `Put(credID, err)` on a fresh classified failure. `CachingTokenCache` owns only cache hits, refresh-ahead, and single-flight.
```

### CA Provider Flow

```text
if priv key+cert exist: load, verify match, verify pub copy; mismatch fatal
else: generate ECDSA P-256 CA, atomically write key+cert to privDir, write public PEM to pubDir
Signer returns cert+signer; Generation is uint64 and stable for pod lifetime; PublicPEM is copy-safe
```

---

## Error Handling Strategy `[Optional]`

| Error Category | Retryable | Example | Behavior |
|---------------|-----------|---------|----------|
| Config | No | Missing Entra client ID | Startup fails before bind. |
| CA fatal | No | Key/cert mismatch | Startup fails before bind. |
| Policy unavailable | No | No first snapshot | Not ready; no bind. |
| Policy stale | No | Snapshot age `>= 45s` | Deny all; liveness remains true. |
| Token transient | Yes | Entra 429/5xx | Pipeline calls `token.Breaker.AllowRequest()` before Entra and `RecordFailure(token.AcquireErrorTransient)` after transient failures; request denies when the breaker is open or an exchange fails. |
| Token permanent | No | invalid_scope | Pipeline checks `token.NegativeCache.Get(credID)` before Entra and `Put(credID, err)` after fresh classified failures; request denies. |
| Audit unavailable | No | Sink unavailable | Pipeline fails closed before credential leaves. |

Policy watch reconnects with bounded exponential backoff and full relist after uncertain state. The Entra acquirer itself does not implement retries. `CachingTokenCache` owns token reuse and single-flight.
The separate `token.Breaker` and `token.NegativeCache` own acquisition gating around the acquirer through explicit method calls; there is no decorator model.

---

## Persistence / State Model `[Optional]`

| Condition | Action |
|-----------|--------|
| Private CA absent | Generate CA, atomically persist key+cert to `ca.privDir`, write public PEM to `ca.pubDir`. |
| Sidecar-only restart | Load existing CA; do not rotate. |
| Private/public mismatch | Fatal startup error. |
| Pod recreation | `emptyDir` is gone; generate a new pod CA. |

---

## Thread-Safety Model `[Required]`

| Component / Data | Mechanism | Scope | Notes |
|------------------|-----------|-------|-------|
| `watch.Store.snapshot` | `atomic.Value` | Process | Publishes immutable `policy.PolicySnapshot`. |
| `watch.Store.updated` | `atomic.Int64` | Process | Lock-free freshness age. |
| `token.CachingTokenCache` | existing `sync.Mutex`, maps, `list.List` | Cache | Single-flight and refresh guards already implemented. |
| `token.Breaker` | existing `sync.Mutex` | Breaker | Existing half-open probe guard. |
| `token.NegativeCache` | existing `sync.Mutex` | Failure cache | Existing LRU failure cache. |
| `tlsterm.CachedLeafSource` | existing `sync.Mutex` + in-flight map | Leaf source | Change generation key from `int64` to `uint64`. |
| `listener.Listener` | existing atomics, mutexes, semaphores, wait group | Listener | Existing strictly-forward states and drain race protection. |
| Runtime probe state | `atomic.Bool` / `atomic.Value` | Process | Probe state moves only after gates. |

```go
func (s *Store) Current() (policy.PolicySnapshot, time.Duration, bool) {
    v := s.current.Load()
    if v == nil { return nil, 0, false }
    c, ok := v.(*cell)
    if !ok || c == nil || c.snapshot == nil { return nil, 0, false }
    return c.snapshot, s.clock().Sub(c.updated), true // age may be negative under a clock anomaly
}
```

`Store.Fresh(maxStaleness)` is the preferred request-time call; it combines `Current` plus the staleness check atomically and returns `false` for deny-all when age is `< 0` (clock anomaly) or `>= maxStaleness` (two-sided fail-closed). The request-path `pipeline.MatchStage` performs the equivalent two-sided check (`age < 0 || age >= maxStaleness`) on the snapshot it reads from the store, so a rolled-back/corrupted publication time can never be treated as fresh. `Store.Swap` publishes the snapshot and its publication time together as a single immutable `*cell` behind the `atomic.Value`, so concurrent readers never observe a torn (new snapshot, old timestamp) pair; snapshot and age are always read from the same cell. The `updated` time carries a monotonic reading, so the staleness gate is immune to wall-clock jumps.

Snapshots must remain immutable; watch code must never expose informer-owned mutable state to request-time matching.

---

## Observability `[Required]`

### Logged Operations

| Operation | Level | Message | Dimensions |
|-----------|-------|---------|------------|
| Config loaded | Info | `aksh-proxy: config loaded` | bounded source summary |
| Preflight failed | Error | `aksh-proxy: capture preflight failed` | capture error code |
| CA ready | Info | `aksh-proxy: CA ready` | generation, public path |
| CA mismatch | Error | `aksh-proxy: CA persistence mismatch` | file role only |
| First snapshot | Info | `aksh-proxy: first policy snapshot ready` | version, rule count |
| Snapshot stale | Warn | `aksh-proxy: policy snapshot stale` | age, maxStaleness |
| Local self-test failed | Error | `aksh-proxy: local token self-test failed` | bounded reason |
| Listener bound | Info | `aksh-proxy: listener bound` | address |
| Privilege dropped | Info | `aksh-proxy: privileges dropped` | uid, gid |
| Shutdown | Info | `aksh-proxy: shutdown drain` | duration, result |

### Performance Metrics

| Metric Name | Type | When Emitted | Dimensions |
|-------------|------|--------------|------------|
| `aksh_runtime_startup_gate_seconds` | Histogram | Each startup gate | `gate`, `result` |
| `aksh_policy_snapshot_age_seconds` | Gauge | Periodic/readiness | `namespace` |
| `aksh_policy_compile_seconds` | Histogram | Each compile | `result` |
| `aksh_token_acquire_seconds` | Histogram | Each Entra exchange | `provider`, `class` |
| `aksh_ca_ready` | Gauge | CA provider state | none |
| `aksh_probe_ready` | Gauge | Exec readiness | bounded `reason` |

### Error Metrics

| Metric Name | Trigger |
|-------------|---------|
| `aksh_runtime_startup_fail_total` | Fatal startup gate fails. |
| `aksh_policy_watch_reconnect_total` | Watch reconnect. |
| `aksh_policy_stale_deny_total` | Staleness fail-closed. |
| `aksh_token_acquire_fail_total` | Entra acquire failure by class. |
| `aksh_ca_mismatch_total` | Fatal persisted CA mismatch. |

No log or metric includes token strings, SA assertions, CA private key bytes, or unbounded operator text as labels.

---

## Configuration `[Optional]`

| YAML key | Env override | Default | Purpose |
|---|---|---|---|
| `listener.address` | `AKSH_LISTENER_ADDRESS` | `127.0.0.1:15001` | data-plane bind |
| `ca.privDir` | `AKSH_CA_PRIV_DIR` | `/var/run/aksh/ca-priv` | key+cert emptyDir |
| `ca.pubDir` | `AKSH_CA_PUB_DIR` | `/var/run/aksh/ca-pub` | public cert emptyDir |
| `policy.namespace` | `AKSH_POLICY_NAMESPACE` | downward API | watch namespace |
| `policy.maxStaleness` | `AKSH_POLICY_MAX_STALENESS` | `45s` | deny-all threshold |
| `token.saTokenPath` | `AKSH_SA_TOKEN_PATH` | `/var/run/secrets/aksh/token` | projected SA token |
| `token.entra.tenantID` | `AKSH_ENTRA_TENANT_ID` | none | Entra tenant |
| `token.entra.clientID` | `AKSH_ENTRA_CLIENT_ID` | none | federated app |
| `token.entra.authority` | `AKSH_ENTRA_AUTHORITY` | `https://login.microsoftonline.com` | STS host |
| `audit.sink` | `AKSH_AUDIT_SINK` | `stdout` | rejection sink |

Validation rejects non-loopback listener hosts, empty identity settings, invalid durations, non-HTTPS authority, and any unknown attempt to disable TLS verification, audit, default-deny, or staleness fail-closed. The loopback-only constraint applies to the host; port `0` remains valid for tests that need an OS-assigned endpoint on `127.0.0.1:0`. Secrets never come from the ConfigMap.

---

## Module / Service Lifecycle `[Optional]`

```text
[NotStarted] → [PreBindGates] → [Bound] → [DroppedPrivileges] → [Serving] → [Draining] → [Stopped]
                   │ fatal
                   ▼
              [FailedNoBind]
```

| Phase | Trigger | Behavior |
|-------|---------|----------|
| Load | Process start | Load/validate config. |
| Capture | After config | Preflight, load/attach, resolvers. |
| CA | After capture | Load/generate and publish CA. |
| Policy | After CA | Watch and wait first snapshot. |
| Self-test | After policy | Local WIF checks. |
| Bind | Gates pass | Open loopback listener. |
| Phase B | Bound | Accept redirect probe. |
| Drop | Probe success | Drop to UID/GID 1774. |
| Serve | Drop success | Process requests. |
| Drain | SIGTERM | Stop accepts and wait handlers. |

---

## Sequence Diagrams `[Optional]`

```text
listener.Serve
  └─ tlsTerminatingConnHandler.Handle
       └─ requestpath.Handler.Handle
            └─ pipeline.Execute
                 ├─ SanitiseStage
                 ├─ IdentityStage
                 ├─ MatchStage(Store.Fresh + Matcher.Match)
                 ├─ AcquireStage(CachingTokenCache.Get → gated acquirer: NegativeCache.Get + Breaker.AllowRequest + entra.Acquirer.Acquire + Record*)
                 ├─ audit boundary
                 └─ InjectStage
            └─ upstream.DirectDialer.DialUpstream(ctx, originalDst, identity, credID)
```

---

## Usage Examples `[Required]`

### Entrypoint

```go
cfg, err := config.Load()
if err != nil { os.Exit(1) }
runner, err := runtime.New(runtime.Options{Config: cfg, Log: slog.Default()})
if err != nil { os.Exit(1) }
if err := runner.Run(context.Background()); err != nil { os.Exit(1) }
```

### Token Cache Composition

```go
acquirer, err := entra.NewAcquirer(entra.Options{
    TenantID: cfg.Token.Entra.TenantID, ClientID: cfg.Token.Entra.ClientID,
    Authority: cfg.Token.Entra.Authority, SATokenPath: cfg.Token.SATokenPath,
    Timeout: 10 * time.Second,
})
if err != nil { return err }
breaker := token.NewBreaker(5, 30)
negative := token.NewNegativeCache(256, 30*time.Second)
guardedAcquirer := runtimeTokenAcquirer{Base: acquirer, Breaker: breaker, Negative: negative}
// runtimeTokenAcquirer implements token.TokenAcquirer by checking
// Negative.Get(token.CredID(rc)), then Breaker.AllowRequest(), then calling
// Base.Acquire(ctx, rc), and finally Negative.Put / Breaker.RecordFailure or
// Breaker.RecordSuccess. CachingTokenCache owns only cache hits,
// refresh-ahead, and single-flight.
cache := token.NewTokenCache(guardedAcquirer, token.CacheOptions{MaxEntries: 256})
p := pipeline.NewPipeline([]pipeline.Stage{
    &pipeline.SanitiseStage{}, &pipeline.IdentityStage{},
    &pipeline.MatchStage{Store: policyStore, Matcher: policy.NewMatcher(), MaxStaleness: cfg.Policy.MaxStaleness},
    &pipeline.AcquireStage{Cache: cache}, &pipeline.InjectStage{},
}, auditSink)
```

### Listener Two-Phase Startup

```go
leaf, err := tlsterm.NewCachedLeafSource(caProvider, leafOptions)
if err != nil { return err }
term, err := tlsterm.NewTerminator(leaf, leafOptions, metrics)
if err != nil { return err }
reg := listener.NewSelfDialRegistry()
dialer, err := upstream.NewDirectDialer(upstreamOptions, reg, metrics)
if err != nil { return err }
handler, err := requestpath.NewHandler(p, dialer, auditSink, metrics, requestOptions)
if err != nil { return err }
// listener.New accepts a listener.ConnHandler. The Phase 6 assembly handler
// must perform downstream TLS through a per-connection GetConfigForClient
// wrapper (configForClient(cc)) that delegates to term.GetConfigForClient and,
// on certificate-selection success, records the canonical ClientHello SNI onto
// cc.CandidateSNI (issue #32) -- passing term.GetConfigForClient directly
// leaves CandidateSNI empty, which makes PostHandshakeAssert reject every TLS
// connection and disables the INV-8 SNI-vs-Host check. It must then call
// term.PostHandshakeAssert after HandshakeContext, populate the ConnContext TLS
// fields, then delegate to handler.Handle. The current listener options do
// not accept *tlsterm.Terminator directly.
tlsHandler := tlsTerminatingConnHandler{Terminator: term, Next: handler}
l, err := listener.New(listenerOptions, destinationResolver, tlsHandler, metrics, log)
if err != nil { return err }
if err := l.Bind(); err != nil { return err }
probeConn, err := l.AcceptProbe(time.Now().Add(5 * time.Second))
if err != nil { return err }
_ = probeConn.Close()
if err := privilegeDropper.DropPrivileges(capture.PrivDropConfig{ProxyUID: 1774, ProxyGID: 1774, NoNewPrivs: true}); err != nil { return err }
return l.Serve(ctx)
```

### Unit Test Shape

```go
func TestStore_NoSnapshot_DeniesFresh(t *testing.T) {
    store := &watch.Store{}
    if _, ok := store.Fresh(45 * time.Second); ok {
        t.Fatal("Fresh() ok = true, want false without snapshot")
    }
}
```

---

## Testing Strategy `[Optional]`

| Theme | Required assertions |
|-------|---------------------|
| Startup order | `Bind` not called before CA + first snapshot + local self-test; `Serve` not before UID/GID 1774 drop. |
| CA lifecycle order | `tlsterm.CachedLeafSource` is constructed only after the CA startup gate succeeds; fake lifecycle asserts `mint()` is unreachable before CA ready. |
| Config | Env overrides file; no flags; missing tenant/client fails; no disable keys. |
| CA | Generate once, reload, mismatch fatal, public PEM written. |
| Token | SA token file read every exchange; no Entra call in readiness; errors classified. |
| Policy | First snapshot gate; no snapshot deny-all; stale `>=45s` deny-all; watch reconnect. |
| Shutdown | SIGTERM calls `listener.Shutdown` and drains. |

---

## Implementation Notes `[Required]`

1. `internal/pki/interfaces.go` currently has `CA() (*x509.Certificate, crypto.Signer, error)` and `Generation() int64`; Phase 6 replaces it with the reconciled interface above.
2. `internal/dataplane/tlsterm/leafsource.go` currently calls `s.ca.CA()` and uses `generation int64`; update to `caCert, caSigner := s.ca.Signer()` and `uint64` cache keys.
3. `internal/pipeline/acquire_stage.go` currently converts CRD credentials to `token.CredentialSelector`; `internal/token/entra.Resolve(*v1alpha1.CredentialSelector)` is a CRD-facing helper that validates Entra and delegates to existing `token.Resolve` without duplicating it. `token.CredID` remains in `internal/token`, not `internal/token/entra`.
4. Add `k8s.io/client-go v0.36.3` for `internal/policy/watch`, matching the existing `k8s.io/api v0.36.3` and `k8s.io/apimachinery v0.36.3` pins. RBAC is read-only `akshpolicies` in the own namespace. All `client-go` transitive dependencies must be CGO-free because the binary builds with `CGO_ENABLED=0`.
5. `CGO_ENABLED=0` is mandatory for build/runtime; reserved proxy UID/GID is 1774.
6. Exec readiness is true only after CA written, first snapshot, local self-test, and serving readiness; liveness stays true during Entra outages.

```go
// Options carries the injectable startup-gate seams. A nil seam defaults to a
// benign success / functional no-op so the skeleton lifecycle keeps working;
// production cmd/aksh-proxy/main.go injects the real fail-closed implementations.
type Options struct {
    Config             config.Config
    Log                *slog.Logger
    ListenerFactory    ListenerFactory                                 // nil => ProductionListenerFactory
    Recorder           func(event string)                              // ordered-milestone recorder for tests
    Preflight          func(context.Context) error                    // capture.RunPreflight + attach (TD S6-1 placeholder in prod)
    ConstructResolvers func(context.Context) error                    // cgroup + destination resolvers
    CAProvider         func(context.Context) (pki.CAProvider, error)  // load/generate pod CA
    PolicyStartup      func(context.Context) (*watch.Store, error)    // start watcher + first snapshot (TD S6-2 placeholder in prod)
    LocalSelfTest      func(context.Context) error                    // entra.LocalSelfTest (no network)
    AuditSinkFactory   func() (audit.AuditSink, error)
    DataMetrics        audit.MetricsRecorder                          // nil => no-op
    PrivDrop           func(capture.PrivDropConfig) error             // nil => no-op; prod injects capture.DropPrivileges
    StartupMetrics     StartupMetricsRecorder                         // nil => no-op
}

// Orchestrator owns the daemon lifecycle spine. It stores the config, logger,
// listener factory, milestone recorder, and every gate seam from Options, plus
// atomic ready/live/reason probe state, the guarded listener + shutdown-once
// state, and the composed artifacts retained for white-box test observability.
// Methods: New, Run, Shutdown, Ready, Live (returning ProbeStatus), plus the
// internal acceptProbe (Phase-B) and assemble (compose) helpers.
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

    ready  atomic.Bool
    live   atomic.Bool
    reason atomic.Value // string

    mu           sync.Mutex
    ln           Listener // interface seam; production *listener.Listener satisfies it
    shutdownOnce sync.Once
    shutdownErr  error

    // Composed artifacts, retained for white-box test observability.
    store             *watch.Store
    matchStage        *pipeline.MatchStage
    acquireStage      *pipeline.AcquireStage
    tokenCache        *token.CachingTokenCache
    leafSource        *tlsterm.CachedLeafSource
    rejectionRecorder *audit.RejectionRecorder
}
```

---

## Integration with Other Components `[Optional]`

| Component | Runtime Obligation |
|-----------|--------------------|
| S0 | Preserve config precedence, no flags, no central service, UID/GID 1774. |
| S1a | Use capture preflight/attach before bind; privilege drop before serve. |
| S1b/S1c | Use exact listener, handler, pipeline, upstream constructors. |
| S2 | Watch own namespace; compile snapshots; deny no snapshot/stale snapshot. |
| S3 | Read SA token every exchange; readiness local-only; use the token cache plus separately composed `Breaker` and `NegativeCache`. |
| S5 | Persist/reload CA; write public PEM; implement exec readiness/liveness semantics. |

---

## Component Reference `[Optional]`

| Component | Responsibility | Location |
|-----------|----------------|----------|
| `Orchestrator` | Lifecycle and probes | `internal/runtime` |
| `Config` | Runtime config | `internal/config` |
| `PodCAProvider` | Concrete CA provider | `internal/pki` |
| `entra.Acquirer` | Entra WIF exchange | `internal/token/entra` |
| `watch.Watcher` | Kubernetes watch | `internal/policy/watch` |
| `watch.Store` | Atomic `PolicyStore`; request-time callers prefer `Fresh(maxStaleness)` for atomic current+staleness deny-all checks. | `internal/policy/watch` |
| `capture.DropPrivileges` | Post-`AcceptProbe`, pre-`Serve` privilege-drop step to UID/GID 1774. | `internal/dataplane/capture` |
| `tlsTerminatingConnHandler` | Runtime adapter that performs TLS termination before delegating to `requestpath.Handler`, and is the sole writer of `listener.ConnContext.CandidateSNI` in production (via `configForClient`). | `internal/runtime/tls_conn_handler.go` |

---

## Best Practices `[Required]`

1. Never call `listener.Bind` before CA ready, first snapshot, and local self-test.
2. Never call `listener.Serve` unless privilege drop to UID/GID 1774 succeeded.
3. Never add flags or invariant-disable config keys.
4. Never call Entra from readiness or liveness.
5. Read the projected SA token file on every exchange.
6. Treat no snapshot and snapshot age `>=45s` as deny-all.
7. Do not log tokens, SA assertions, private keys, or PEM bytes.
8. Keep watch reconnects, token work, and audit recording bounded.
9. Update `tlsterm` and tests in the same PR as the CAProvider reconcile.

---

## Limitations `[Required]`

1. **No in-place CA rotation.** Rotation is pod restart.
2. **Entra only.** Other providers are future implementations of the same seam.
3. **Manifest boundary unresolved.** Full manifests vs binary plus reference RBAC remains deferrable. <!-- TODO -->
4. **Direct watches have scale limits.** ADR-S0-07 accepts this for MVP.
5. **Readiness does not prove Entra availability.** Request-time token misses may still deny.
6. **Production is Linux.** Non-Linux stubs compile but return unsupported errors.

---

## Risks and Mitigations `[Optional]`

| # | Risk | Impact | Mitigation |
|---|------|--------|------------|
| 1 | CAProvider reconcile breaks callers | High | Update `pki`, `tlsterm`, and tests together. |
| 2 | Wrong startup order opens a gap | High | Fake-based lifecycle order tests. |
| 3 | Policy compile failures serve forever | High | Start staleness lease on compile failure; deny at 45s. |
| 4 | Readiness calls Entra | High | Test with failing HTTP client; local-only contract. |
| 5 | `client-go` complexity | Medium | Isolate behind `AkshPolicyClient`. |

---

## Future Considerations `[Optional]`

- Full Kubernetes manifests and install packaging. <!-- TODO -->
- Multi-provider token packages.
- Cross-downstream upstream pooling using `credID` plus S1c's full pool key.

---

## Success Criteria / Definition of Done `[Optional]`

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | No bind before CA + snapshot + self-test | Runtime unit test. |
| 2 | CA persists/reloads; mismatch fatal | PKI unit test. |
| 3 | Policy deny-all on no snapshot or age `>=45s` | Store/watch unit test. |
| 4 | SA token file read every exchange | Entra unit test. |
| 5 | Readiness local-only | Test forbids HTTP use. |
| 6 | Confirm `CGO_ENABLED=0 go build ./cmd/aksh-proxy` succeeds with client-go v0.36.3 (no CGO transitive deps). | Build validation during implementation. |

---

## File Deliverables `[Optional]`

| File | Change |
|------|--------|
| `cmd/aksh-proxy/main.go` | New entrypoint. |
| `internal/config/config.go` | New loader/schema. |
| `internal/pki/pod_ca_provider.go` | New CA provider. |
| `internal/token/entra/acquirer.go` | New WIF acquirer. |
| `internal/policy/watch/{store,watcher}.go` | New watch/store. |
| `internal/runtime/tls_conn_handler.go` | New `tlsTerminatingConnHandler` adapter that wraps a `tlsterm.Terminator` (consumed through the unexported `tlsTerminator` seam) around `requestpath.Handler`, and records the canonical ClientHello SNI onto `ConnContext.CandidateSNI` via `configForClient`. |
| `internal/runtime/token_acquirer.go` | New guarded acquirer adapter composing `token.NewBreaker(5, 30)` and `token.NewNegativeCache` around `entra.Acquirer`. |
| `internal/pki/interfaces.go` | Reconcile `CAProvider`. |
| `internal/dataplane/tlsterm/leafsource.go` | Consume reconciled `CAProvider`. |
| `go.mod` / `go.sum` | Add `k8s.io/client-go v0.36.3` and keep transitive dependencies CGO-free. |

---

## References `[Required]`

| Document | Relationship |
|----------|--------------|
| [S0 Architecture](./S0-architecture.md) | Config precedence, no flags, no central service, UID/GID 1774. |
| [S1 Data Plane](./S1-data-plane.md) | Data-plane context and request flow. |
| [S1a Data-plane Capture](./S1a-dataplane-capture.md) | Capture preflight, resolvers, privilege drop, `cmd/aksh-proxy` expectation. |
| [S1b Request Path](./S1b-request-path.md) | HTTP request path and pipeline handoff. |
| [S1c Transport](./S1c-transport.md) | Direct dialer, transport bounds, listener limiter. |
| [S2 Policy CRD](./S2-policy-crd.md) | `AkshPolicy`, `policy.Compile`, `PolicyStore`, staleness. |
| [S3 Token Broker](./S3-token-broker.md) | WIF, token cache, breaker, negative cache, local self-test. |
| [S5 Injection PKI](./S5-injection-pki.md) | Per-pod CA lifecycle, CAProvider signature, probes. |
| Unified Design Template | Structural standard. |
| [PKI interface source](../../internal/pki/interfaces.go) | Current interface reconciled by Phase 6. |
| [TLS leaf source source](../../internal/dataplane/tlsterm/leafsource.go) | CAProvider consumer. |
| [TLS terminator source](../../internal/dataplane/tlsterm/terminator.go) | Exact `NewTerminator`. |
| [Listener source](../../internal/dataplane/listener/listener.go) | Exact listener lifecycle. |
| [Upstream source](../../internal/dataplane/upstream/direct.go) | Exact direct dialer. |
| [Request handler source](../../internal/dataplane/requestpath/handler.go) | Exact `NewHandler`. |
| [Capture source](../../internal/dataplane/capture/preflight.go) | Exact `RunPreflight`. |
| [Pipeline source](../../internal/pipeline/runner.go) | Exact `NewPipeline`. |
| [Policy interfaces source](../../internal/policy/interfaces.go) | Exact policy contracts. |
| [Policy compile source](../../internal/policy/compile.go) | Exact `Compile`. |
| [Token interfaces source](../../internal/token/interfaces.go) | Existing token types. |
| [Token cache source](../../internal/token/cache.go) | Exact `TokenAcquirer` and cache. |
| [Audit rejection source](../../internal/audit/rejection.go) | Exact rejection recorder. |
| [API types source](../../api/v1alpha1/types.go) | CRD Go types. |

---

## Appendix `[Optional]`

### API Quick Reference `[Optional]`

```go
cfg, err := config.Load()
ca, err := pki.NewPodCAProvider(ctx, pki.PodCAOptions{PrivDir: cfg.CA.PrivDir, PubDir: cfg.CA.PubDir})
leaf, err := tlsterm.NewCachedLeafSource(ca, leafOptions)
term, err := tlsterm.NewTerminator(leaf, leafOptions, metrics)
breaker := token.NewBreaker(5, 30)
negative := token.NewNegativeCache(256, 30*time.Second)
guardedAcquirer := runtimeTokenAcquirer{Base: entraAcquirer, Breaker: breaker, Negative: negative}
cache := token.NewTokenCache(guardedAcquirer, token.CacheOptions{MaxEntries: 256})
p := pipeline.NewPipeline(stages, auditSink)
handler, err := requestpath.NewHandler(p, dialer, auditSink, metrics, requestOptions)
tlsHandler := tlsTerminatingConnHandler{Terminator: term, Next: handler}
l, err := listener.New(listenerOptions, resolver, tlsHandler, metrics, log)
err = l.Bind()
conn, err := l.AcceptProbe(deadline)
err = l.Serve(ctx)
err = l.Shutdown(ctx)
```
