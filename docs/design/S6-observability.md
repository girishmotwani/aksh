# S6 — Audit, Metrics & Logging

> **Status:** Reviewed · **Depends on:** S0–S5 · **Depended on by:** S7 (evidence and conformance)
>

What every decision leaves behind, and what an operator sees.

---

## Scope

**Decides:** the audit record schema and its versioning; redaction; the sink, its buffering
and the precise meaning of "durably recorded"; the emergency channel INV-6 requires; the
Prometheus metric set and its cardinality budget; the separation of audit from application
logs; the health and readiness endpoints; and retention/export posture.

**Does not decide:** when audit happens (S4 §1.0 — it is stage ⑥, before the credential), or
what a decision means (S2, S3, S4).

## Requirements covered

**FR9** (structured audit logs) in full, and the audit half of **FR8**. Implements **INV-5**
(no secret material in any output) and **INV-6** (every decision recorded; the allow record
precedes the credential). Owns the **operability** and **compliance** NFRs.

---

## Design

### 1. Two streams, deliberately separate

| | Audit stream | Application log |
| --- | --- | --- |
| Content | One record per decision | Diagnostics about Aksh itself |
| Destination | `stdout`, JSON, one object per line | `stderr` |
| Schema | Fixed and versioned (§2) | Free-form |
| Guarantee | Durable before the credential leaves (INV-6) | Best-effort |
| Failure | Denies the request (INV-4) | Never affects a request |

Separating them is not tidiness. Audit is **evidence**: it has a schema contract, a durability
requirement, and a compliance consumer. Application logs are for debugging and may be verbose,
sampled or dropped. Interleaving them on one stream would force the weaker guarantee onto both,
and would make a log-volume spike capable of denying requests.

`stdout` and `stderr` are the sinks because in Kubernetes the node's logging agent is the
export mechanism, and reimplementing shipping inside a sidecar would duplicate infrastructure
that already exists and is already monitored.

### 2. The audit record

One JSON object per line, built from S4's immutable `AuditEvent`.

```json
{
  "schema": "aksh.dev/audit/v1",
  "ts": "2026-07-31T20:14:03.412Z",
  "requestId": "01J...",
  "pod": {"namespace": "agents", "name": "research-agent-7d9f-x2k4", "uid": "..."},
  "agent": {"serviceAccount": "research-agent"},
  "decision": {"disposition": "deny", "reason": "policy_no_match", "fault": false},
  "request": {"identity": "graph.microsoft.com", "method": "GET", "path": "/v1.0/me", "port": 443, "transport": "tls"},
  "policy": {"ref": "agents/graph-readonly/graph-read", "version": "sha256:9f2c...", "evaluatorVersion": "v0.1.0", "ambiguous": false},
  "credential": {"identity": "none"},
  "timings": {"total_us": 1840, "match_us": 210, "acquire_us": 40, "audit_us": 830}
}
```

#### 2.1 Fields

| Field | Source | Notes |
| ----- | ------ | ----- |
| `schema` | S6 | **Versioned from day one.** Consumers parse this; changing fields without a version is how a SIEM silently starts dropping records. |
| `ts` | S6 | RFC 3339, UTC, millisecond precision |
| `requestId` | S4 | A ULID minted at pipeline entry, carried on `RequestContext` and `AuditEvent`. Correlates the decision record, the completion record, and application logs. (Added to S4's `AuditEvent` in the same change — it had no producer before.) |
| `pod` | S5 Downward API | `namespace`, `name`, `uid`. **Required by ADR-S0-06**: identity is per ServiceAccount, so replicas share it and only the pod distinguishes them. `metadata.uid` was added to S5's projection in the same change — it was referenced here before it was projected. |
| `agent.serviceAccount` | Downward API | The identity FR9 calls for |
| `decision` | S4 | `disposition`, `reason` (closed enum), `fault` |
| `decision.faultClass` | S4 | Present only when `fault` — a closed `FaultClass`, **never** error text, which can quote request data |
| `request` | S4 ① | The canonical validated identity, never raw agent input. Includes **`transport`** (`tls` \| `plaintext`) and, for plaintext, the resolved `serviceUID`/`serviceGeneration` — the two transports carry different assurance (S1 §6.1), and an audit trail that could not tell them apart would overstate what it witnessed |
| `policy` | S2 | `ref`, `version`, `evaluatorVersion`, `ambiguous`. Present even on stale and evaluator-fault outcomes, using the last known version — "which policy was in force" is the first question an incident asks. `evaluatorVersion` is mandated by S2 §6: the policy hash attests inputs, not behaviour, so without it two sidecars on different builds could report identical versions while enforcing differently. |
| `credential` | S3 §9 | `identity`, `provider`, `resource`, `scopes`, `cacheHit`, `expiresAt`. `identity` is `"none"` when the rule names no credential; the rest are omitted then. **Never the token.** |
| `timings` | S4 | Per-stage microseconds, feeding the S4 §7 budget |

#### 2.2 Two record kinds

`decision` records are written at S4 stage ⑥, **before** any credential leaves (INV-6).
`completion` records are appended at stage ⑨ and carry `requestId`, status, bytes and duration.

As implemented, `audit.AuditSink` has two distinct paths: `Record(ctx context.Context, event pipeline.AuditEvent) error` for blocking decision records, and `RecordCompletion(ctx context.Context, event pipeline.AuditEvent) error` for completion records. `BufferedSink.RecordCompletion` encodes the `completion` kind and is best-effort/non-blocking: a full queue or later write failure drops only completion detail, never the already-recorded decision evidence.

The split exists because they have different guarantees. The decision record is blocking and
durable; the completion record is best-effort, because by then the credential has already gone
and losing the completion record loses detail rather than evidence. A post-allow failure
(S1 §8, S4 §4) appears as a completion record marking failure — **never** as a denial, which
would make the trail describe something that did not happen.

#### 2.3 Redaction

INV-5 is enforced structurally, not by review:

- The record is built from `AuditEvent`, which by construction has no field capable of holding
  a token (S4 §2). There is no path from a `Token` to this JSON.
- `FaultClass` is a closed enum, so no error string is ever serialised. Error text is the
  most likely accidental carrier of request data or a wrapped secret.
- `scopes` and `resource` are policy-authored, not agent-authored, so they are safe to log —
  but they are **not** used as metric labels (§4).
- S7 asserts this end-to-end by driving a known token value through the proxy and grepping all
  output — both streams, both the access token and the projected SA token (S3 §6).

### 3. Durability, buffering, and what "recorded" means

INV-4 makes an unrecordable decision a denial, and S4 makes the write blocking with a 1 ms P95
budget. Those two together are only achievable with a precise definition.

> **"Durably recorded" means a completed, blocking `write(2)` of the record to the audit
> stream — the record has left Aksh's address space and is held by the container runtime.**

An earlier draft said "`fsync`-ed to the node's log file". **That is not achievable and the
claim is withdrawn.** A container's `stdout` is one end of a FIFO; the container runtime reads
it in a *separate process* and writes the node's log file. `fsync()` on a pipe returns `EINVAL`,
and there is no acknowledgement channel back from the runtime — a container cannot observe, let
alone wait for, its bytes reaching disk. Specifying an operation the process cannot perform
would have sent an implementer looking for an API that does not exist.

What remains is exactly the bar S0's INV-4 already blesses for this row: *"committed to a
bounded, local, crash-visible buffer"*. A completed `write(2)` means the record is out of Aksh
and in the runtime, so an Aksh crash cannot lose it; a *node* loss can. The alternatives are
worse in both directions: requiring remote acknowledgement would let a SIEM hiccup deny every
credentialed request in the cluster, which S0 explicitly warns against, while accepting an
unflushed in-process buffer would lose precisely the records that matter.

The residual exposure is **non-adversarial node loss** — a crash, a spot eviction, a routine
upgrade — which can drop records the runtime had not yet flushed. That is a reliability gap in
an evidence system, and it is *not* covered by S0 §6's exclusion of node *compromise*; the two
are different claims and conflating them would overstate the guarantee. Deployments needing
more must use the owned-file option in OQ-S6-02, which Aksh genuinely can `fsync`.

**Buffering.** Records are batched with a bounded buffer and a short flush interval, so
concurrent requests share a flush rather than each paying a syscall. A request's stage ⑥
returns only once *its* record is in a completed flush. The buffer is **bounded**; when full,
new decisions block briefly and then fail as terminal audit failures rather than growing
memory without limit.

**Backpressure is a denial, not a queue.** An unbounded queue would convert an audit outage
into a memory exhaustion, and would silently break INV-6 by letting requests proceed with
records still in flight.

#### 3.1 The emergency channel

INV-6's bounded exception: when audit has terminally failed, the resulting denial cannot itself
be audited. It is instead signalled on an **independent** path:

1. a line on `stderr` (the application stream, which does not depend on the audit sink);
2. the `aksh_audit_unavailable` gauge set to 1;
3. **readiness fails**, so the pod is removed from service and the condition is visible in
   `kubectl get pods` rather than only in a metric someone has to be watching.

Readiness failing is the important one: a sidecar that is denying everything should not look
healthy.

As implemented, `audit.EmergencyChannel` binds these signals through `NewEmergencyChannel(stderr io.Writer, m MetricsRecorder, readiness ReadinessSink)`. `Signal(cause string)` emits the fixed stderr line and then, under one lock, sets `aksh_audit_unavailable` via `MetricsRecorder.AuditUnavailable(true)`, clears orchestrator readiness via `ReadinessSink.SetReady(false)`, and increments `TransitionCount()` on real ready/not-ready transitions. `Recover()` performs the inverse gauge/readiness update under the same lock.

**Recovery is automatic, not latched.** When a subsequent write succeeds, the gauge returns to
0 and readiness recovers — matching how INV-4's other degraded states (policy staleness, token
breakers) behave. A latch requiring a restart would turn a transient node-log-pressure blip into
an operator-intervention incident, and would discard a healthy in-memory policy snapshot and
token cache for no benefit. Readiness may therefore flap under sustained pressure, which is
honest signalling rather than a defect; S6 exposes the transition count so flapping is itself
alertable.

**One caveat on "independent":** signals (2) and (3) genuinely are — they do not touch the log
path. Signal (1) shares the container-runtime path with the audit stream, so under the very
condition most likely to trigger this state (node log pressure) `stderr` may be impaired too.
Two of three channels remain sound, which is why the emergency signal is specified as
best-effort rather than guaranteed.

### 4. Metrics

Prometheus, on a dedicated port (§5). Names follow the `aksh_` prefix and the standard
`_total`/`_seconds` conventions.

| Metric | Type | Labels |
| ------ | ---- | ------ |
| `aksh_decisions_total` | counter | `disposition`, `reason`, `fault`, `transport` |
| `aksh_decision_duration_seconds` | histogram | `stage` |
| `aksh_policy_snapshot_age_seconds` | gauge | — |
| `aksh_policy_snapshot_version_info` | gauge (info) | `version` |
| `aksh_policy_compile_failures_total` | counter | — |
| `aksh_token_acquisitions_total` | counter | `provider`, `result`, `class` |
| `aksh_token_acquisition_duration_seconds` | histogram | `provider` |
| `aksh_token_cache_hits_total` / `_misses_total` | counter | `provider` |
| `aksh_token_cache_evictions_total` | counter | `provider`, `credential` |
| `aksh_token_refresh_failures_total` | counter | `provider`, `credential` |
| `aksh_token_breaker_state` | gauge | `provider`, `credential` |
| `aksh_transport_reject_total` | counter | `class`, `bound` |
| `aksh_leaf_cache_hits_total` / `_misses_total` | counter | — |
| `aksh_upstream_requests_total` | counter | `result` |
| `aksh_audit_records_total` | counter | `kind` |
| `aksh_audit_write_duration_seconds` | histogram | — |
| `aksh_audit_unavailable` | gauge | — |
| `aksh_ca_expiry_seconds` | gauge | — |

`aksh-injector` exposes its own surface — S5 §7.2 assigns its alerting here, and an injector
outage presents as a cluster-wide *deployment freeze* rather than an obvious alarm, so it is
easy to miss without a dedicated signal:

| Metric | Type | Labels |
| ------ | ---- | ------ |
| `aksh_admission_requests_total` | counter | `webhook` (mutate\|validate), `result` |
| `aksh_admission_duration_seconds` | histogram | `webhook` |
| `aksh_admission_rejections_total` | counter | `rule` (the INV-10 check that fired) |
| `aksh_injector_cert_expiry_seconds` | gauge | — |

#### 4.1 Cardinality budget

The hostile agent chooses hostnames, paths and methods. **None of them may become a label.**

That is the whole budget in one sentence, and it is a security property rather than a cost
control: an agent that can create unbounded label combinations can exhaust the sidecar's
memory and then the monitoring system's, from inside a container that is supposed to be
contained. So:

- **Never labels:** `identity`/host, `path`, `method`, `resource`, `scopes`, `requestId`,
  `pod` (the scrape target already carries pod identity).
- **Allowed labels** are all closed enums or operator-controlled: `disposition`, `reason`,
  `fault`, `class`, `bound`, `stage`, `provider`, `result`, `kind`, `transport`.
- **Two derived labels** are permitted, both structurally bounded:
  - `credential` (on `breaker_state`, `cache_evictions_total`, `refresh_failures_total`) is the
    bounded hash of S3 §2.3, capped by S3 §8's 256-entry cache and breaker-state bounds. S3 §9
    mandates these per-credential signals — eviction rate is its thrashing detector and refresh
    failure is its silent-degradation detector — so narrowing them to `provider` alone would
    have broken that contract.
  - `version` (on `policy_snapshot_version_info`) is a policy content hash. It is **not**
    structurally bounded: nothing evicts old series. It is safe only because it changes at
    *operator* CRD-edit rate, never at agent request rate — so it is not an
    agent-reachable vector, which is the property §4.1 actually protects. In a
    high-churn GitOps environment the series count still grows over a long-lived TSDB, and
    that is a monitoring-retention concern to size for rather than an Aksh bug.

Per-destination visibility is the audit stream's job, not the metrics'. That is the correct
split: metrics are for aggregate health, audit is for "what did this agent do".

**Implemented closed-enum label vocabulary.** The `audit.MetricsRecorder` contract accepts named bounded types for its dimensional labels, not free-form strings — with one deliberate, self-documented exception: `SnapshotVersion(version string)` (`interfaces.go`) sets `aksh_policy_snapshot_version_info{version}` from a free-string `version`, whose cardinality is bounded operationally by the slow-changing policy snapshot version rather than by a closed Go type:

| Type | Implemented label values / contract |
| ---- | ----------------------------------- |
| `StageName` | `unknown`, `sanitise`, `identity`, `match`, `acquire`, `inject`, `accept_to_dispatch`, `tls_config_build`, `leaf_mint`, `upstream_dial` for `aksh_decision_duration_seconds{stage}`. |
| `ProviderID` | `unknown`, `entra` for token-provider labels. |
| `Result` | `unknown`, `success`, `failure` for token acquisition results; upstream requests use the separate `UpstreamResult` enum with the same values. |
| `CredentialID` | named string type for the S3 §2.3 bounded credential hash; cardinality is capped by the 256-entry credential cache/breaker state. |
| `BoundName` | `none`, `max_inflight_requests`, `pipelining`, `max_header_bytes`, `request_header_read_timeout`, `handover`, `max_response_body`, `handshake_rate`. |
| `RejectClass` | audit-local closed enum mirroring the listener taxonomy: `none`, `no_original_dst`, `loop_guard`, `no_sni`, `handshake`, `unsupported_protocol`, `identity_mismatch`, `resource_limit`, `plaintext_unresolvable`, `plaintext_registry_unavailable`. |
| `TransportKind` | `tls`, `plaintext` for `aksh_decisions_total{transport}`; this replaces the free-string `policy.Transport` at the metric boundary. The zero value is `tls` (`TransportTLS`), an asymmetry chosen so the TLS-only ingress listener — whose dispatch sites run only after TLS termination — is correct by default; non-TLS classifiers (`discriminator`, `passthrough`) MUST set the label explicitly via `transportKindOf(Protocol)`, which maps only `ProtocolTLS`→`tls` and everything else (plaintext HTTP/1, h2c, unknown bytes)→`plaintext`. Callers on a genuinely non-TLS path must never rely on the default. |

`Decisions(d pipeline.Disposition, r pipeline.DenyReason, transport TransportKind, fault bool)` maps `fault` internally to the closed string label set `{"true","false"}`. Injector metrics are implemented on the shared `audit.MetricsRecorder` surface (`AdmissionRequest`, `AdmissionDuration`, `AdmissionRejection`, `InjectorCertExpiry`); a future binary-specific interface split would be additive, not a change to the metric contract.

#### 4.2 Alert rate limiting — closing OQ-S4-04

A total IdP or audit outage produces one `fault` per request, which at agent request rates
buries the signal in its own volume.

Faults are therefore counted, not alerted per occurrence. Alerts are defined on **rates and
gauges** — `aksh_audit_unavailable == 1`, `rate(aksh_decisions_total{fault="true"}[5m])` above
a threshold, `aksh_policy_snapshot_age_seconds` approaching `maxStaleness`, `breaker_state`
open. The audit stream keeps the per-request detail for afterwards. No rate limiting is needed
in Aksh itself, because a counter is already an aggregate.

### 5. Endpoints, and keeping the agent out of them — closing OQ-S0-09 / OQ-S1-03

`aksh-proxy` exposes `/metrics`, `/healthz` and `/readyz` on port **15020**, separate from the
data plane. As implemented, `runtime.ControlPlaneServer` is constructed with `NewControlPlaneServer(bindAddr string, port int, reg prometheus.Gatherer, probes ProbeSource)` and uses the named `Port15020 = 15020` constant for the canonical control-plane port. It serves only `GET /metrics`, `GET /healthz`, and `GET /readyz`; non-GET requests are rejected, response bodies use fixed/closed strings, and no secret material is exposed. The server requires a non-empty, non-loopback bind address (pod IP); loopback (`127.0.0.1`, `::1`, `localhost`) is refused at construction and revalidated at `Start`.

`ProbeAggregator` wraps the orchestrator `ProbeSource` and implements `audit.ReadinessSink`, folding the emergency-channel state into readiness: audit unavailable forces `/readyz` to 503 with reason `audit_unavailable`, and recovery restores the base readiness. `Shutdown(ctx)` is terminal and idempotent; once shutdown is requested, concurrent or later `Start` calls cannot begin serving.

The agent shares the pod's network namespace and S1's rules deliberately exclude loopback, so
**binding to `127.0.0.1` does not protect these endpoints** — it makes them *more* reachable
from the agent, not less. This is a real finding rather than a hypothetical: the naive
"bind to localhost for safety" instinct is exactly backwards inside a shared namespace.

The mitigation is layered, because no single layer is sufficient:

1. The endpoints are **read-only** and expose no secrets (INV-5), so the exposure is
   reconnaissance and denial-of-service, not disclosure.
2. Aksh's iptables program (S1 §1) rejects pod-local traffic to port 15020 that does not
   originate from Aksh's own UID. **Two rules are required, not one, and the naive version does
   not work** — worth spelling out, because it fails silently:

   ```
   # nat/AKSH_OUTPUT — BEFORE the catch-all redirect, and scoped to POD-LOCAL
   # destinations only. An unscoped --dport 15020 exclusion would also exempt a
   # legitimate remote API that happens to listen on 15020, punching a hole in
   # interception to protect a metrics port.
   -A AKSH_OUTPUT -p tcp -d ${POD_IP} --dport 15020 -j RETURN

   # filter/AKSH_EGRESS_GUARD — the actual rejection. It must live here: REJECT is
   # not valid in the nat table at all ("the 'nat' table is not intended for filtering").
   -A AKSH_EGRESS_GUARD -p tcp -d ${POD_IP} --dport 15020 \
      -m owner ! --uid-owner ${AKSH_UID} -j REJECT
   ```

   Both rules are installed for IPv4 and IPv6 (`${POD_IP}` meaning each of the pod's assigned
   addresses), and S1 §1 carries them as part of its canonical rule set rather than as an
   S6 addendum, so there is one place where the ordering is visible.

   The ordering trap is the important part: `nat/OUTPUT` is traversed **before**
   `filter/OUTPUT`, and S1's redirect deliberately carries no `--dport` filter, so without the
   `nat` exclusion the port is already rewritten by the time the filter chain sees the packet.
   The rule would look installed and do nothing — precisely the failure class S1 §1.5 calls the
   most dangerous in this design. `aksh-init`'s pre-flight probe (S1 §1.3) therefore covers this
   rule too: it asserts that a connection to `:15020` from a non-Aksh UID is refused.
3. The kubelet scrapes and probes from **outside** the pod, so it is unaffected by an
   `OUTPUT`-chain rule that only constrains pod-local originators.

What remains, honestly: an agent learns the sidecar exists — which it can infer anyway from
the fact its traffic is being intercepted.

### 6. Retention and export

Aksh does not ship, retain or rotate. Records go to `stdout`; the cluster's logging agent
collects them; retention and SIEM export are the platform's, configured once for all workloads.

This is the right boundary: a sidecar that shipped its own logs would need egress credentials
and a network path — both of which are exactly what this product exists to control, and both of
which would have to be exempted from its own interception. That circularity is reason enough.

The compliance obligation S6 does carry is making records **exportable**: a stable versioned
schema (§2), a bounded field set, and no free-form text that a parser could choke on.

---

## Interfaces

```go
// AuditSink durably records one event. Its error is the fail-closed trigger (INV-4), so
// an implementation must return an error rather than dropping a record — silent loss
// would break INV-6 invisibly, which is the worst possible failure for an evidence
// system.
//
// It receives S4's immutable AuditEvent, never the mutable RequestContext, which after
// injection holds the plaintext credential.
//
// ctx is S4's detached, deadline-bounded context (S4 §4.1): implementations MUST honour
// its deadline rather than blocking indefinitely, since a hung sink would pin a request
// slot and S1 sets no total-request timeout.
type AuditSink interface {
    Record(ctx context.Context, ev pipeline.AuditEvent) error
    RecordCompletion(ctx context.Context, ev pipeline.AuditEvent) error
}

// MetricsRecorder accepts only CLOSED-ENUM label values. This must be enforced by the
// type system rather than by convention: §4.1's cardinality rule is a security property,
// and this project has already been burned once by a redaction guarantee that depended on
// reviewer attention (S3 §6).
//
// A map[string]string Labels type would NOT enforce it — Labels{"path": rc.Facts.Path}
// would compile. So labels are per-metric structs whose fields are the closed enum types
// the other documents already define. An agent-controlled string is not merely discouraged
// as a label value; there is no field it can be assigned to.
type MetricsRecorder interface {
    Decisions(d pipeline.Disposition, r pipeline.DenyReason, transport TransportKind, fault bool)
    StageDuration(stage StageName, d time.Duration)
    TransportReject(class RejectClass, bound BoundName)
    LeafCacheHit()
    LeafCacheMiss()
    AuditRecord(kind AuditRecordKind)
    AuditWriteDuration(d time.Duration)
    AuditUnavailable(unavailable bool)
    SnapshotAge(d time.Duration)
    SnapshotVersion(version string)
    PolicyCompileFailure()
    CAExpiry(d time.Duration)
    TokenAcquisition(provider ProviderID, result Result, class AcquireErrorClass)
    TokenAcquisitionDuration(provider ProviderID, d time.Duration)
    TokenCacheHit(provider ProviderID)
    TokenCacheMiss(provider ProviderID)
    TokenCacheEviction(provider ProviderID, credential CredentialID)
    TokenRefreshFailure(provider ProviderID, credential CredentialID)
    TokenBreakerState(provider ProviderID, credential CredentialID, state BreakerState)
    UpstreamRequest(result UpstreamResult)
    AdmissionRequest(webhook WebhookName, result AdmissionResult)
    AdmissionDuration(webhook WebhookName, d time.Duration)
    AdmissionRejection(rule AdmissionRule)
    InjectorCertExpiry(d time.Duration)
}
```

---

## Failure modes

| Failure | Behaviour |
| ------- | --------- |
| Audit buffer full | Brief block, then terminal audit failure → deny + emergency signal (§3.1) |
| `stdout` blocked (node log pressure) | Same |
| Audit write exceeds S4's 2 s deadline | Terminal audit failure |
| Node logging agent down | **No effect on requests** — records are written to the node's file regardless; collection lag is the platform's problem |
| Metrics endpoint scraped by the agent | Rejected by the owner-match rule (§5) |
| A metric label would be unbounded | Prevented by construction: `MetricsRecorder` accepts only closed-enum values (§4.1) |

---

## Decisions (ADRs)

### ADR-S6-01 — Durability is a completed write to the runtime, not an `fsync`
*Context.* INV-4 denies when a decision cannot be recorded; someone must define "recorded".
*Options.* Remote collector acknowledgement; `fsync` to disk; a completed blocking `write(2)`.
*Decision.* A completed blocking `write(2)` to the audit stream.
*Consequences.* An Aksh crash cannot lose a record a credential depended on, and a SIEM outage
cannot deny requests cluster-wide. The `fsync` option was **investigated and found unavailable**
on this channel — `stdout` is a pipe read by a separate process, and `fsync` on a pipe fails —
so the earlier draft specified an impossible operation. The honest residual is that
non-adversarial node loss can drop unflushed records; deployments that cannot accept that need
the owned-file variant (OQ-S6-02), where `fsync` is genuinely available. This is also what makes
S4's 1 ms budget plausible: a pipe write is microseconds, where a disk sync or a network round
trip would not be.

### ADR-S6-02 — Audit to stdout; Aksh never ships logs
*Context.* Compliance wants records in a SIEM.
*Decision.* Write to `stdout` and let the platform collect.
*Consequences.* A sidecar that shipped its own logs would need egress credentials and a network
path, both of which are what this product exists to control, and both of which would have to be
exempted from its own interception. Avoiding that circularity is worth more than the
convenience. The cost is a dependency on the cluster having a logging pipeline — which, for a
cluster running an audited security control, is a fair assumption.

### ADR-S6-03 — No agent-controlled value is ever a metric label
*Context.* Per-destination metrics would be genuinely useful.
*Decision.* Hostnames, paths, methods and scopes are audit fields only.
*Consequences.* Removes an agent-reachable unbounded-cardinality vector that would exhaust
first the sidecar and then the monitoring system. Costs real convenience — "which host is
failing" needs the audit stream rather than a PromQL query. The correct split: metrics for
aggregate health, audit for attribution.

### ADR-S6-04 — Control ports are protected by an owner-match rule, not by binding to loopback
*Context.* `/metrics` and the probes must be reachable by the kubelet but not by the agent.
*Decision.* Bind on the pod IP and add an iptables rule rejecting pod-local traffic to 15020
that is not from Aksh's UID.
*Consequences.* Closes OQ-S0-09/OQ-S1-03. Binding to loopback — the reflexive answer — is
actively *worse* here: containers share the namespace, and S1 deliberately excludes loopback
from interception, so a loopback bind is fully reachable by the agent. Costs one rule and a
dependency on the same owner-match already load-bearing for egress.

---

## v1 forward-compatibility

| v1 need | Seam | Why additive |
| ------- | ---- | ------------ |
| **Distributed tracing** | `requestId` already correlates records | Spans become an additional exporter; the audit schema is untouched. |
| **FR11/FR14 richer records** | `schema` version + additive optional fields | Consumers key on `schema`; adding fields under a new version is the documented path. |
| **Ingress** | `decision.direction`, defaulting to `egress` | An additive field with a safe default. |
| **Approval outcomes (FR13)** | `disposition: "pending"` | The enum already carries it (S4 §2); no schema break. |

---

## Open questions

| ID | Question | Closed by |
| -- | -------- | --------- |
| **OQ-S6-01** | **Inherited from OQ-S4-03.** With durability now defined as a completed pipe write (§3, ADR-S6-01) rather than an `fsync`, is 1 ms P95 comfortably achievable under concurrent load — and what happens when the container runtime's reader falls behind and the pipe fills, which is the realistic backpressure path? Needs measurement on a real node, not a laptop. | S7, by benchmark |
| **OQ-S6-02** | Should the audit stream be a file Aksh owns on a mounted volume, rather than `stdout`? Two independent reasons now point that way: a library writing to `stdout` directly could interleave with the audit stream, and — more substantially — an owned file is the only way to offer a real `fsync` durability tier for deployments that cannot accept the non-adversarial node-loss window of §3. The costs are a volume, rotation, and a collection path that no longer comes free from the platform. | S7 |
| **OQ-S6-03** | What is the record's size budget? A pathological path (S2 bounds it at 1024 bytes) plus scopes could produce large records at high rates, and the audit stream is on the request path. Needs a bound and a truncation rule that never truncates a security-relevant field. | S7 |
| **OQ-S6-04** | ~~Does `pod.uid` belong in every record?~~ — **closed in §2.1: yes.** ADR-S0-06 requires pod-level attribution because identity is per ServiceAccount and replicas share it, and relying on collector enrichment would make the evidence guarantee depend on a component outside Aksh. `metadata.uid` was added to S5's Downward API projection, which had been referenced before it was projected. | *closed in S6* |
