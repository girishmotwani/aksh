# S1c: Transport Layer (Phase 5C)

> Status: Draft
> Phase: 5C
> Date: 2026-08-20
> Authority: `S1a-dataplane-capture.md` section 23.3 is the governing 5C handoff; `S1-data-plane.md` sections 5.3 and 5.4 remain authoritative background.

## 1. Metadata

| Field | Value |
| ----- | ----- |
| Document id | S1c |
| Title | Transport Layer (Phase 5C) |
| Status | Draft |
| Phase | 5C |
| Author | GitHub Copilot |
| Date | 2026-08-20 |
| Governing contract | `S1a-dataplane-capture.md` section 23.3 |
| Frozen seam | `internal/dataplane/interfaces.go`: `DialUpstream(ctx context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error)` |
| Implemented scope | Response-body cap, downstream TLS handshake-rate limiter, durable upstream concurrency bound documentation |
| Deferred design | Cross-downstream-connection upstream pooling |

### 1.1 Glossary

| Term | Meaning |
| ---- | ------- |
| Response-body cap | Streaming byte counter around `http.Response.Body`; it counts cumulative bytes and does not buffer. |
| Handshake-rate limiter | Token-bucket limiter at the listener accept path, using `golang.org/x/time/rate`. |
| Upstream concurrency bound | Existing `DirectDialer` semaphore sized by `UpstreamOptions.MaxConcurrentDials`. |
| Pool key | S1 section 5.3 key: `(validated identity, recovered destination, resolved credential identity or no-auth sentinel, trust-config generation, negotiated protocol policy)`. |
| Clean connection | Drained to a protocol boundary and eligible for reuse. |
| Dirty connection | Closed mid-stream, after an error, or after a cap breach; never reusable. |

---

## 2. Supersession, amendment and authority map

| Source | 5C treatment |
| ------ | ------------ |
| `S1a-dataplane-capture.md` section 23.3 | Governs this phase. `dataplane.UpstreamDialer` remains the seam; 5C adds no dialing call-site changes. |
| `S1a-dataplane-capture.md` section 13.1 `Max response body size` and OQ-S1a-04 | Closed here with a 128 MiB default streaming response cap. |
| `S1a-dataplane-capture.md` section 13.1 `TLS handshake rate` and OQ-S1a-06 | Implemented as a listener accept-path limiter with configurable starting values 50/s sustained, burst 100. |
| `S1a-dataplane-capture.md` section 13.1 `Concurrent upstream dials` | Amended: because pooling is deferred, the existing 512-slot `DirectDialer` semaphore remains the standing upstream bound. |
| `S1-data-plane.md` section 5.3 | Authoritative for the planned pool design, but not implemented in 5C. |
| `S1-data-plane.md` section 5.4 | Timeout budget unchanged by 5C. Effective request-path values: downstream TLS handshake 10s, request header 10s, upstream connect 15s (the current `defaultUpstreamDialTimeout` in `internal/dataplane/requestpath/options.go`; the S1 design budget was 5s, but 5C does not alter the 5B choice), upstream TLS handshake 10s, upstream response header 30s, idle 90s, per-stream progress deadline 60s, no total-request cap. |

---

## 3. Scope

### 3.1 In scope

1. **Response-body-size cap (closes OQ-S1a-04).** Add a byte-counting `io.ReadCloser` around the streamed response body in `internal/dataplane/requestpath/relay.go`.
2. **Downstream TLS handshake-rate limiter (closes OQ-S1a-06 for implementation).** Add a new accept-path limiter in `internal/dataplane/listener/listener.go`.
3. **Upstream concurrency bound.** Keep the existing `DirectDialer` semaphore (`UpstreamOptions.MaxConcurrentDials`, default 512 by composition) as the durable upstream-connection bound.
4. **Deferred pooling design.** Fully specify the future pool, but mark it `[Planned — deferred pending evidence of benefit]`.

### 3.2 Out of scope

1. Changing `dataplane.UpstreamDialer` or `DialUpstream` call sites.
2. Buffering response bodies.
3. Implementing cross-downstream-connection pooling in 5C.
4. Changing S1 section 5.4 timeouts.
5. Adding first-class Prometheus labels before S6 widens `audit.MetricsRecorder`.

---

## 4. Overview

5C is the transport layer behind the frozen `dataplane.UpstreamDialer` seam. It is intentionally small: response bytes are counted where response bodies exist, downstream TLS handshakes are rate-limited where accepted connections enter the process, and upstream concurrency stays bounded by the existing semaphore.

The current request relay already reuses one upstream connection across keep-alive requests on the same downstream connection through `connState.upstream.reusableFor(rc, cs.ho, credID)`, which reuses only a connection still marked `reusable` (a flag the error and close paths clear so a dirty connection is never reused), keyed on the validated identity, the destination port and `credID`. This is a deliberate **subset** of the full S1 section 5.3 pool key (which additionally partitions on trust-config generation and negotiated protocol policy); the subset is sufficient here because same-downstream-connection reuse cannot cross a trust-config or protocol boundary, whereas the deferred cross-connection pool in section 20 must use the full key. The user explicitly deferred reuse across different downstream connections until there is evidence of benefit.

### 4.1 Design principles

| # | Principle | Description |
| - | --------- | ----------- |
| 1 | Count where observable | The dialer returns raw `net.Conn`; only the relay sees `http.Response.Body`. |
| 2 | Stream, never buffer | The response cap wraps reads and never materializes the body. |
| 3 | Reject before expensive work | The handshake limiter runs before downstream TLS handshake work is dispatched. |
| 4 | Preserve frozen seams | `DialUpstream(ctx context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error)` is unchanged. |
| 5 | Measure before pooling | Pooling adds correctness risk and waits for evidence. |

---

## 5. Architecture

```
Accepted TCP conn
      │
      ▼
listener.Listener.dispatch
      │  5C: handshakeLimiter.Allow()
      │  breach: close + RecordDecision("rejected", "resource_limit:handshake_rate", "")
      ▼
ConnHandler / TLS termination / request path
      │
      ▼
requestpath.Handler.relay
      │
      ├─ ensureUpstream(ctx, cs, rc, credID)
      │       └─ dataplane.UpstreamDialer.DialUpstream(...)
      │              └─ upstream.DirectDialer sem chan struct{} (MaxConcurrentDials)
      │
      ├─ resp, err := http.ReadResponse(upstream.br, req)
      ├─ 5C: resp.Body = byte-counting wrapper
      └─ resp.Write(downstream)
             └─ streams response; wrapper aborts after MaxResponseBodyBytes
```

Dependency view:

```
requestpath.Handler ──depends on──▶ dataplane.UpstreamDialer
       │                                      ▲
       │                                      │ implements
       │                              upstream.DirectDialer
       │
       └──uses──▶ audit.MetricsRecorder

listener.Listener ──uses──▶ rate.Limiter (golang.org/x/time/rate)
       └──uses──▶ audit.MetricsRecorder
```

---

## 6. Core Data Types

### 6.1 Existing frozen interface

```go
type UpstreamDialer interface {
	DialUpstream(ctx context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error)
}
```

No 5C behavior changes this interface.

### 6.2 Existing upstream options

```go
type UpstreamOptions struct {
	DialTimeout        time.Duration
	HandshakeTimeout   time.Duration
	MaxConcurrentDials int
	ProxyUID           uint32
	ListenerPort       uint16
	RootCAs            *x509.CertPool
	NextProtos         []string
}
```

`DirectDialer` already constructs `sem: make(chan struct{}, opts.MaxConcurrentDials)`. The returned `*upstreamConn` releases the semaphore and calls `SelfDialRegistry.Remove` idempotently on `Close()`.

### 6.3 5C request-path option addition

```go
type Options struct {
	MaxHeaderBytes          int
	MaxInflightRequests     int
	CopyBufferBytes         int
	HeaderReadTimeout       time.Duration
	IdleTimeout             time.Duration
	ProgressDeadline        time.Duration
	UpstreamDialTimeout     time.Duration
	UpstreamResponseTimeout time.Duration
	MaxResponseBodyBytes    int64 // 5C addition
	MaxRejectionAudits      int
	RejectionAuditTimeout   time.Duration
}
```

Default: `128 * 1024 * 1024`. Validation: `MaxResponseBodyBytes > 0`.

### 6.4 5C listener option additions

```go
type Options struct {
	Name                   string
	ListenAddr             netip.AddrPort
	Handler                ConnHandler          // overwritten by the positional arg in New()
	Metrics                audit.MetricsRecorder // overwritten by the positional arg in New()
	MaxConnections         int
	PeekTimeout            time.Duration
	HandshakeRatePerSecond int // 5C addition
	HandshakeRateBurst     int // 5C addition
	BlockNonTCP            bool
	AllowUnsafeStartup     bool
}
```

Defaults: `HandshakeRatePerSecond: 50`, `HandshakeRateBurst: 100`. Validation: both `> 0`.

### 6.5 Response-body counter

```go
type responseBodyLimitReader struct {
	body     io.ReadCloser
	limit    int64
	seen     int64
	exceeded bool
}
```

It implements `Read` and `Close`, returns a sentinel such as `ErrResponseBodyTooLarge` after the cap, and never allocates proportional to response size.

---

## 7. API Reference

Existing constructor signatures remain unchanged:

```go
func NewDirectDialer(opts UpstreamOptions, reg *listener.SelfDialRegistry, m audit.MetricsRecorder) (*DirectDialer, error)
```

```go
func NewHandler(
	p *pipeline.Pipeline,
	dialer dataplane.UpstreamDialer,
	sink audit.AuditSink,
	metrics audit.MetricsRecorder,
	opts Options,
) (*Handler, error)
```

```go
func New(opts Options, resolver dataplane.DestinationResolver, h ConnHandler, m audit.MetricsRecorder, log *slog.Logger) (*Listener, error)
```

`audit.MetricsRecorder` currently is:

```go
type MetricsRecorder interface {
	RecordDecision(disposition, reason, identity string)
	RecordLatency(stage string, duration time.Duration)
	RecordTokenCacheHit(credID string, hit bool)
}
```

Because there is no bound parameter, 5C uses the existing rejection encoding pattern: `reason="resource_limit:<bound>"`.

---

## 8. Design Decisions

| # | Decision | Rationale |
| - | -------- | --------- |
| ADR-S1c-01 | Enforce the response cap in `requestpath/relay.go`, not in the dialer. | The dialer returns `net.Conn` and never sees HTTP bodies; `relay.go` has `resp.Body`. |
| ADR-S1c-02 | Default `MaxResponseBodyBytes` is 128 MiB. | 128 MiB is the smallest power-of-two that stays comfortably above realistic legitimate text/JSON/LLM streaming responses (typically KB to low-MB, ~two orders of magnitude below the cap), which is the conservative choice for a security backstop: pick the smallest bound that never binds on legitimate traffic. At 512 downstream conns it permits 64 GiB relayed before forced closure — half of the 128 GiB the originally-considered 256 MiB cap would have permitted. The T7 tuning signal is `bound="max_response_body"`. |
| ADR-S1c-03 | The cap is cumulative streamed bytes, not buffered size. | S1 section 6 forbids buffering; the wrapper counts reads. |
| ADR-S1c-04 | Use 50/s sustained, burst 100 for handshake rate as configurable starting values. | Burst 100 covers a real startup fan-out of 100 parallel tool calls with full handshakes because resumption is disabled. The T7 tuning signal is `bound="handshake_rate"`. |
| ADR-S1c-05 | Keep the existing 512 upstream semaphore. | Pooling is deferred; removing the semaphore would remove the only implemented upstream bound. |
| ADR-S1c-06 | Defer cross-downstream pooling. | Current same-downstream keep-alive reuse exists; cross-downstream value is unmeasured and adds key-cardinality and dirty-reuse risks. |

---

## 9. Resource bounds

### 9.1 Response-body-size cap (closes OQ-S1a-04)

Default: **128 MiB** (`134217728` bytes).

| Derivation element | Value | Rationale |
| ------------------ | ----- | --------- |
| Floor | Realistic legitimate responses | Typical agent tool-call responses are KB to low-MB, including large LLM/SSE streams; 128 MiB sits ~two orders of magnitude above them. A backstop against an unbounded hostile stream, not a content policy. |
| Ceiling | 128 GiB relayed at scale | At 512 downstream conns a 256 MiB cap would permit 128 GiB relayed before closure — too high for a sidecar bound. Streaming means this is bytes-relayed (egress amplification), not resident memory. |
| Default | 128 MiB | Smallest power-of-two comfortably above legitimate large streams: the smallest bound that never binds on legitimate traffic, and at 512 conns permits only 64 GiB relayed — half the 128 GiB of the rejected 256 MiB ceiling. |
| Tuning signal | T7 `bound="max_response_body"` | Sustained legitimate breaches mean raise the cap with evidence; no breaches plus egress pressure may justify lowering it. |

S1 section 5.4 deliberately has no total-request cap because legitimate streams can be long-lived. The byte cap bounds cumulative size; the existing 60s progress deadline bounds no-progress stalls. Together they bound size and stalled duration without imposing a wall-clock total-request cap.

### 9.2 Downstream TLS handshake rate (closes OQ-S1a-06 for implementation)

| Item | Value |
| ---- | ----- |
| Sustained rate | 50 handshakes/second |
| Burst | 100 handshakes |
| Package | `golang.org/x/time/rate` |
| Enforcement point | `internal/dataplane/listener/listener.go`, `dispatch`, before handler handoff |
| Breach metric | `RecordDecision("rejected", "resource_limit:handshake_rate", "")` |

The values are unmeasured starting values. They protect the accept path against connection-churn floods, which incidentally bounds TLS handshake CPU; the connection cap is the primary CPU protection. The burst must admit the documented legitimate case: 100 parallel tool calls at startup, with every connection doing a full handshake because resumption is disabled.

### 9.3 Upstream concurrency

`internal/dataplane/upstream/direct.go` already enforces fail-fast concurrency with `sem chan struct{}`. 5C keeps this as the durable upstream-connection bound. No code change to the semaphore is required beyond documentation and preservation tests.

---

## 10. Key Operation Flows

### 10.1 Response relay cap flow

```
Handler.relay
  1. ensureUpstream(...)
  2. writeUpstreamRequest(...)
  3. resp, err := http.ReadResponse(upstream.br, req)
  4. resp.Body = newResponseBodyLimitReader(resp.Body, h.opts.MaxResponseBodyBytes)
  5. defer resp.Body.Close()  // closes the wrapper, which closes the original body
  6. stripHopByHop(resp.Header)
  7. err := resp.Write(downstream)
       ├─ success: preserve existing keep-alive behavior
       ├─ ErrResponseBodyTooLarge: metric resource_limit:max_response_body; close upstream/downstream; no reuse
       └─ other error: existing non-reusable close path
```

Exact insertion point: in `internal/dataplane/requestpath/relay.go`, the wrapper is assigned to `resp.Body` immediately after `http.ReadResponse` returns and **before** the existing `defer resp.Body.Close()`, so the deferred close targets the wrapper (which in turn closes the original body) rather than the pre-wrap value.

### 10.2 Handshake limiter flow

```
Serve accepts conn
  └─ dispatch(ctx, conn, acceptedAt)
       ├─ !handshakeLimiter.Allow()
       │    ├─ conn.Close()
       │    └─ RecordDecision("rejected", "resource_limit:handshake_rate", "")
       ├─ acquire existing MaxConnections semaphore
       └─ start handler goroutine
```

### 10.3 Upstream semaphore flow

```
DirectDialer.DialUpstream
  1. validate addr/serverName
  2. reject self-dial
  3. try acquire d.sem
       ├─ full: RecordDecision("rejected", "resource_limit", ""); ErrUpstreamConcurrency
       └─ acquired: dial + TLS handshake
  4. return *upstreamConn
  5. Close(): close socket, registry.Remove, release sem exactly once
```

---

## 11. Rejection taxonomy

| Bound | Class | Current metrics encoding | Wire behavior |
| ----- | ----- | ------------------------ | ------------- |
| `max_response_body` | T7 `resource_limit` | `RecordDecision("rejected", "resource_limit:max_response_body", "")` | Abort response and close upstream/downstream. The original allow audit remains an allow; this is a transport completion failure encoded through current metrics. |
| `handshake_rate` | T7 `resource_limit` | `RecordDecision("rejected", "resource_limit:handshake_rate", "")` | Close accepted connection before TLS handshake. |
| `upstream_concurrency` | T7 `resource_limit` | Existing code records `RecordDecision("rejected", "resource_limit", "")`; S6 should expose `bound="upstream_concurrency"`. | Dial fails fast. |

---

## 12. Security analysis

| Threat | Control |
| ------ | ------- |
| Infinite hostile response stream | 128 MiB default response-body cap aborts cumulative bytes. |
| Slow silent upstream | Existing 60s progress deadline closes when no bytes move. |
| Connection-churn flood | 50/s burst-100 handshake limiter at accept dispatch. |
| Legitimate startup fan-out | Burst 100 admits 100 parallel full handshakes. |
| Pool-key memory exhaustion | Pooling deferred; planned manager must bound key cardinality. |
| Dirty connection reuse | Pooling deferred; planned design requires a private poison/discard contract. |
| Self-dial guard leak under pooling | Pooling deferred; planned design deregisters only on final close. |

---

## 13. Thread-Safety Model

| Component / data | Mechanism | Scope | Notes |
| ---------------- | --------- | ----- | ----- |
| Response-body counter | Per-response object | One relay goroutine | No shared mutable state. |
| `Handler.opts` | Immutable copy after validation | Handler lifetime | Additive option only. |
| Progress tracking | Existing `atomic.Int64` | One request | Response writes still pass through `progressConn`. |
| Handshake limiter | `*rate.Limiter` | Listener lifetime | Safe for concurrent use. |
| Listener connection semaphore | Buffered channel | Listener lifetime | Existing MaxConnections bound. |
| Upstream dial semaphore | Buffered channel | DirectDialer lifetime | Existing `MaxConcurrentDials` bound. |
| `upstreamConn.Close` | `atomic.CompareAndSwapInt32` | One upstream conn | Existing idempotent release and registry removal. |
| Planned pool LRU | Mutex-protected map/list | Pool manager lifetime | Planned only; protects key map, LRU order, and eviction close. |

---

## 14. Observability

| Event | Current call | Intended metric labels |
| ----- | ------------ | ---------------------- |
| Response cap exceeded | `RecordDecision("rejected", "resource_limit:max_response_body", "")` | `class="resource_limit", bound="max_response_body"` |
| Handshake rate exceeded | `RecordDecision("rejected", "resource_limit:handshake_rate", "")` | `class="resource_limit", bound="handshake_rate"` |
| Upstream concurrency exceeded | Existing `RecordDecision("rejected", "resource_limit", "")` | `class="resource_limit", bound="upstream_concurrency"` after S6 |

No response body content is logged. A future S6 completion metric should distinguish post-allow transport completion failures from policy denials.

---

## 15. Configuration

| Setting | Type | Default | Validation | File |
| ------- | ---- | ------- | ---------- | ---- |
| `MaxResponseBodyBytes` | `int64` | `128 * 1024 * 1024` | `> 0` | `internal/dataplane/requestpath/options.go` |
| `HandshakeRatePerSecond` | `int` | `50` | `> 0` | `internal/dataplane/listener/options.go` |
| `HandshakeRateBurst` | `int` | `100` | `> 0` | `internal/dataplane/listener/options.go` |
| `MaxConcurrentDials` | `int` | `512` | Existing `> 0` | `internal/dataplane/upstream/upstream_options.go` |

`golang.org/x/time/rate` is required for the listener limiter. If it is not already in `go.mod` at implementation time, add it with module-aware tooling.

---

## 16. Usage Examples

```go
opts := requestpath.DefaultOptions()
opts.MaxResponseBodyBytes = 128 * 1024 * 1024

handler, err := requestpath.NewHandler(p, dialer, sink, metrics, opts)
if err != nil {
	return err
}
```

```go
opts := listener.DefaultOptions()
// Handler and Metrics are supplied as positional arguments to
// listener.New below; newListener overwrites opts.Handler/opts.Metrics
// with them, so setting the fields here would be ignored.
opts.HandshakeRatePerSecond = 50
opts.HandshakeRateBurst = 100

ln, err := listener.New(opts, resolver, handler, metrics, log)
if err != nil {
	return err
}
```

```go
opts := upstream.UpstreamOptions{
	// DialTimeout is the raw upstream TCP dial budget in the upstream
	// layer; it is distinct from requestpath.Options.UpstreamDialTimeout
	// (the 15s request-path context deadline in section 2's budget).
	DialTimeout:        5 * time.Second,
	HandshakeTimeout:   10 * time.Second,
	MaxConcurrentDials: 512,
	ProxyUID:           proxyUID,
	ListenerPort:       listenerPort,
	RootCAs:            roots,
	NextProtos:         []string{"http/1.1"},
}

dialer, err := upstream.NewDirectDialer(opts, registry, metrics)
if err != nil {
	return err
}
```

---

## 17. Testing strategy

| Area | Required coverage |
| ---- | ----------------- |
| Response option | Default 128 MiB; zero/negative invalid; custom positive valid. |
| Response cap success | Under limit and exactly at limit stream successfully without proportional buffering. |
| Response cap breach | Over-limit stream records `resource_limit:max_response_body`, closes upstream/downstream, and does not reuse upstream. |
| Progress interaction | Existing progress deadline still handles no-progress streams. |
| Listener options | Defaults 50/100; invalid rate/burst rejected. |
| Handshake limiter | Burst 100 passes; exhausted limiter closes before handler invocation and records `resource_limit:handshake_rate`. |
| Upstream semaphore | Saturation still returns `ErrUpstreamConcurrency`; `Close()` releases once. |
| Frozen seam | `DialUpstream` signature and compile-time assertion remain unchanged. |

---

## 18. Implementation Notes

### 18.1 Response cap

Add `MaxResponseBodyBytes` in `requestpath.Options`. Wrap at the response side only:

```go
resp, err := http.ReadResponse(upstream.br, req)
if err != nil {
	// existing failure path
}

limited := newResponseBodyLimitReader(resp.Body, h.opts.MaxResponseBodyBytes)
resp.Body = limited
defer resp.Body.Close() // wrapper assigned before the defer so the wrapper's Close runs
stripHopByHop(resp.Header)
if err := resp.Write(downstream); err != nil {
	if errors.Is(err, ErrResponseBodyTooLarge) || limited.Exceeded() {
		h.metrics.RecordDecision("rejected", "resource_limit:max_response_body", "")
	}
	upstream.close()
	cs.upstream = nil
	return false
}
```

Do not alter request-body `io.Copy` paths; they are the request direction.

### 18.2 Handshake limiter

Add a `handshakeLimiter *rate.Limiter` field to `Listener`, construct it in `newListener`, and check it at the start of `dispatch`:

```go
// Allow() is non-blocking: an over-rate connection is rejected and closed
// immediately rather than queued. Wait() would hold the accept goroutine
// and a socket open under a churn flood, which is the exact exhaustion the
// limiter exists to prevent.
if !l.handshakeLimiter.Allow() {
	conn.Close()
	if l.metrics != nil {
		l.metrics.RecordDecision("rejected", "resource_limit:handshake_rate", "")
	}
	return
}
```

### 18.3 Upstream semaphore

No behavior change is required in `internal/dataplane/upstream/direct.go`. Comments and tests may clarify that `sem chan struct{}` is now the durable 5C upstream bound while pooling is deferred.

---

## 19. Best Practices

1. Enforce response-size only around `resp.Body`.
2. Never buffer to count a response.
3. Treat the body cap as a resource backstop, not content filtering.
4. Preserve the frozen `DialUpstream` signature.
5. Emit bound-specific T7 metrics for every bound breach.
6. Reject handshake-rate breaches before handler work.
7. Keep upstream semaphore behavior fail-fast; do not queue unbounded dials.
8. Do not build pooling until section 20's evidence exists.
9. If pooling is later built, never reuse dirty connections.
10. If pooling is later built, bound key cardinality as well as connection count.

---

## 20. [Planned — deferred pending evidence of benefit] Cross-downstream-connection pooling

### 20.1 Deferred boundary

This section is design-only and is not implemented in 5C. The implemented 5C scope ends at the response cap, handshake limiter, and retained upstream semaphore.

### 20.2 Why deferred

The relay already reuses one upstream connection per downstream keep-alive connection. Cross-downstream reuse should be built only if measurements show meaningful latency, CPU, connection-churn, or upstream-load benefit after partitioning by the full S1 section 5.3 key.

### 20.3 Bounded LRU manager keyed by S1 section 5.3 pool key

The planned key is exactly:

```
(validated identity, recovered destination, resolved credential identity | no-auth sentinel,
 trust-config generation, negotiated protocol policy)
```

The manager must be bounded by key cardinality and connection count. Bounding only connections is insufficient because the agent chooses identity and therefore chooses keys; unbounded keys are a memory-exhaustion vector.

| Requirement | Planned behavior |
| ----------- | ---------------- |
| Key bound | Maximum live keys; LRU eviction closes all transports for the evicted key. |
| Per-key bound | Maximum idle and active connections per key. |
| Total bound | Maximum active plus idle pooled connections. |
| Eviction | Close transports on eviction and remove metadata. |
| Immutability | Trust-config generation or protocol-policy changes produce a new key. |
| No shared `http.Transport` | A global transport is forbidden because its internal pool key can bypass S1 partitioning. |

### 20.4 Clean/dirty connection contract

The pool would still return `net.Conn`, but the returned value would also implement a private additive method used by existing non-reusable/error close paths:

```go
type dirtyMarker interface {
	poison()
}

func poisonIfSupported(conn net.Conn) {
	if marker, ok := conn.(dirtyMarker); ok {
		marker.poison()
	}
}
```

Rules:

1. Cleanly drained response: `Close()` may return the connection to the pool.
2. Response cap breach, progress timeout, upstream write failure, response parse failure, or any existing non-reusable/error close path: call `poison()` before `Close()`.
3. Dirty `Close()` performs final socket close, not return-to-pool.
4. This is additive to existing relay close paths and does not change `DialUpstream`.
5. Non-pooled `DirectDialer` need not implement the private method.

### 20.5 `SelfDialRegistry` pool semantics

Current `DirectDialer` behavior is correct because every close is final: register on dial, deregister on close.

Under pooling:

1. Register when a real socket is dialed.
2. Do **not** deregister on return-to-pool.
3. Deregister only on final close: eviction, dirty discard, idle expiry final close, trust-generation retirement, or shutdown.
4. A pooled idle socket remains live and must remain visible to the self-dial guard.

---

## 21. Limitations

1. **No cross-downstream pooling in 5C.** Potential reuse benefit remains unclaimed until measured.
2. **No total wall-clock request cap.** This is intentional per S1 section 5.4.
3. **Metrics are encoded through a narrow interface.** Bound is carried in `reason` until S6.
4. **Response cap is content-agnostic.** It only counts bytes.
5. **Upstream concurrency metric is not yet bound-specific in code.** S6 should expose `bound="upstream_concurrency"`.

---

## 22. Risks and mitigations

| # | Risk | Impact | Mitigation |
| - | ---- | ------ | ---------- |
| 1 | 128 MiB rejects legitimate future workloads | Medium | Configurable; tune from `max_response_body` T7 metric. |
| 2 | 50/s is too low | Medium | Burst 100 covers startup fan-out; tune from `handshake_rate` T7 metric. |
| 3 | 50/s is too high for churn | Medium | Values are starting points; lower only with measurement. |
| 4 | Future pool reuses dirty connection | High | Require private poison/discard contract. |
| 5 | Future pool key map is unbounded | High | Require LRU key-cardinality bound. |

---

## 23. Future/handoffs

| Handoff | Detail |
| ------- | ------ |
| S6 observability | Add first-class transport rejection metrics, e.g. `RecordTransportReject(class, bound string)`. |
| Future pooling phase | Implement section 20 only after evidence of benefit. |
| Performance validation | Measure response-size distribution, handshake fan-out, and cross-downstream reuse opportunity. |
| HTTP/2 phase | If HTTP/2 later shares transports, adapt clean/dirty semantics per stream without poisoning unrelated streams (tracked as OQ-S1c-04). |

---

## 24. File deliverables

| File | Change |
| ---- | ------ |
| `internal/dataplane/requestpath/options.go` | Add `MaxResponseBodyBytes`, default, validation. |
| `internal/dataplane/requestpath/relay.go` | Wrap response body before `resp.Write(downstream)`. |
| `internal/dataplane/listener/options.go` | Add handshake limiter options/defaults/validation. |
| `internal/dataplane/listener/listener.go` | Add `rate.Limiter` field and accept-path check. |
| `internal/dataplane/upstream/direct.go` | No behavior change; document semaphore as durable bound if needed. |
| `internal/dataplane/upstream/upstream_options.go` | No behavior change; document `MaxConcurrentDials` framing if needed. |
| `go.mod` / `go.sum` | Add `golang.org/x/time/rate` if absent at implementation time. |

---

## 25. References

| Document / file | Relationship |
| --------------- | ------------ |
| `docs/design/S1a-dataplane-capture.md` | Bounds, 5C handoff, OQ-S1a-04, OQ-S1a-06. |
| `docs/design/S1-data-plane.md` | Pool key, timeout budget, response-body cap principle. |
| `docs/design/S1b-request-path.md` | Sibling section structure and relay context. |
| `internal/dataplane/interfaces.go` | Frozen `UpstreamDialer`. |
| `internal/dataplane/requestpath/relay.go` | Response-cap insertion point. |
| `internal/dataplane/requestpath/handler.go` | Handler/options context. |
| `internal/dataplane/listener/listener.go` | Accept loop and dispatch. |
| `internal/dataplane/listener/types.go` | `RejectResourceLimit` maps to T7 / `resource_limit`. |
| `internal/dataplane/listener/options.go` | Listener options to extend. |
| `internal/dataplane/upstream/direct.go` | Existing semaphore and `SelfDialRegistry` close semantics. |
| `internal/dataplane/upstream/upstream_options.go` | Existing `UpstreamOptions`. |
| `internal/audit/interfaces.go` | Exact `MetricsRecorder` signature. |
| `internal/audit/rejection.go` | Existing `resource_limit:<bound>` encoding pattern. |

---

## 26. Open questions

| # | Question | Status |
| - | -------- | ------ |
| OQ-S1c-01 | What measured response-size distribution should replace the 128 MiB starting default? | Deferrable; tune from `max_response_body` T7 metric. <!-- TODO --> |
| OQ-S1c-02 | Are 50/s and burst 100 correct for real startup and steady-state fan-out? | Deferrable; tune from `handshake_rate` T7 metric. <!-- TODO --> |
| OQ-S1c-03 | Does cross-downstream pooling produce enough reuse after full S1 pool-key partitioning? | Deferred pending evidence of benefit. <!-- TODO --> |
| OQ-S1c-04 | When HTTP/2 shares upstream transports, how should clean/dirty state be tracked per stream without poisoning unrelated streams? | Deferrable; revisit with the deferred pooling phase (section 20). <!-- TODO --> |
