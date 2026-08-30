# S4 — Enforcement Pipeline

> **Status:** Reviewed · **Depends on:** S0, S1, S2, S3 · **Depended on by:** S6 (audit emission point), S7 (conformance)

The order in which enforcement happens, what each step is allowed to assume, and exactly what
occurs when any of them fails.

---

## Scope

**Decides:** the ordered request lifecycle and each stage's contract; the `Decision` type; the
hook mechanism that v1 features attach to; the authoritative fail-closed matrix; header
hygiene and its ordering relative to injection; retry posture; the concurrency model; and the
per-stage latency budget.

**Does not decide:** how bytes are moved (S1), what policy says (S2), how a token is obtained
(S3), or the audit record's schema (S6). S4 decides *when* those happen and what their failures
mean.

## Requirements covered

**FR5** (inject only after policy allows) — S4 is where FR5 actually happens. The
authoritative statement of **FR8** (fail closed). Implements **INV-6** (audit precedes the
credential), **INV-9** (credential headers stripped), and the ordering half of **INV-8**.
Owns S4's share of the **performance** and **resource-safety** NFRs.

---

## Design

### 1. The pipeline

One request — or one HTTP/2 stream (INV-8 rule 7) — passes through an ordered list of stages.
The order is not arbitrary; each position is justified, and several are load-bearing for a
specific invariant.

```
  ⓪  Sanitise     strip agent-supplied credential and proxy headers   [INV-9]
  ①  Identity     compare authority against SNI; build RequestFacts   [INV-8 6c/6d]
  ②  Match        evaluate policy → MatchResult                       [S2]
  ③  BodyGate     reserved; pass-through in MVP                       [FR12 seam]
  ④  Hooks        reserved; empty in MVP                              [FR11/FR13 seam]
  ⑤  Acquire      resolve credential → TokenResult                    [S3]
  ⑥  Audit        durably record the decision — THE POINT OF NO RETURN [INV-6, S6]
  ─────────────── the credential has not existed in the request until here ───────────────
  ⑦  Inject       write Authorization; hand to transport              [S1 §6.1]
  ⑧  Relay        stream the response through ResponseStages
  ⑨  Complete     append the completion record
```

#### 1.0 The pipeline is one-way

Stage ⑥ is a **point of no return**, and the lifecycle is defined around it. There is no path
that revisits it, and no failure after it can retroactively become a denial:

```
        ⓪ ① ② ③ ④ ⑤            ⑥                ⑦ ⑧ ⑨
  ───────────────────────►  AUDIT (once)  ─────────────────►
        │  any non-Allow          │                 │
        └────── jump to ⑥ ────────┘                 │
                                  │  audit failed:  │  any failure here is a
                                  │  emergency      │  COMPLETION FAILURE
                                  │  signal only    │  (⑨ still runs)
                                  ▼                 ▼
```

- **Before ⑥:** a non-`Allow` decision jumps straight to ⑥, which records it. Stages ⑦–⑨ do not
  run. ⑥ executes **exactly once** per request.
- **At ⑥:** if the audit write itself fails terminally, there is nothing to record it with.
  INV-6's bounded exception applies — an emergency signal on an independent channel (S6), no
  audit record, request denied. Attempting to audit the audit failure is the recursion INV-6
  already ruled out.
- **After ⑥:** the `Allow` is committed. An injection error, an upstream dial or TLS failure, a
  `ResponseStage` error, or a panic is a **completion failure**, never a denial. Stage ⑨ appends
  a completion record describing it, and the original allow record stands unaltered. Rewriting
  it would make the audit trail describe something that did not happen — and the credential may
  genuinely have been sent.

Stage ⑨ therefore runs on every post-⑥ path, success or failure. If ⑨ itself fails, that is
logged and metered but does not retroactively invalidate ⑥'s record.

#### 1.1 Audit is not short-circuitable

A non-`Allow` decision short-circuits the pipeline — **except that stage ⑥ Audit always runs.**

This exception is essential and easy to lose. Most denials happen at ① or ③: a bad identity,
no matching rule, a stale snapshot. Those are exactly the events an operator most needs to see.
Under a naive reading of the short-circuit rule, a denial at ③ would skip ⑦ and produce no
record at all, violating INV-6's first obligation ("both allow **and** deny decisions produce
an audit record") and FR9.

So the flow is: a stage returning non-`Allow` stops the *request* stages, control jumps
directly to **⑥ Audit** with the current `Decision`, and **⑦ Inject, ⑧ Relay and ⑨ Complete run
only when that decision is `Allow`.** Audit is the pipeline's exit path, not a step within it.
A denied request is never injected and never forwarded.

This also explains the §4 matrix row for terminal audit failure, which only makes sense if ⑥
is attempted for every outcome, and §7's budgeting of audit as a fixed per-request cost with no
allow/deny carve-out.

#### 1.2 Why this order

**⓪ is unconditional and precedes every decision.** Sanitisation was originally stage ②, after
the identity check — which meant a T6 denial at ① jumped to audit with the agent's forged
`Authorization` still sitting in the request, where audit or a future hook could observe it.
Moving it to ⓪ makes "no stage ever sees an agent-supplied credential" true without exception,
which is what INV-9's word *unconditionally* requires.

⓪ only **removes**. Setting `Host`/`:authority` to the validated identity cannot happen here —
that identity does not exist until ① has validated it — so it is a separate step at the end of
① (§3).

**① performs the authority check, not S1.** S1 captures the SNI (it must, to mint the leaf)
and hands S4 the *candidate* identity plus the request's `Host`/`:authority` — but the
**comparison** happens here. S1 §8 itself classifies an authority/SNI mismatch (T6) as an
*authorisation* outcome rather than a transport rejection, and INV-6 requires authorisation
outcomes to be audited. If S1 rejected it before handoff, there would be no `Decision`, no
stage ⑥, and therefore no record of an agent attempting exactly the confused-deputy attack
INV-8 exists to stop — which is precisely the event worth alerting on. Doing the comparison in
① makes it an ordinary audited denial.

**⓪ before everything.** Sanitisation is first so that no later stage — including a v1 hook
someone adds in two years — can ever observe or act on an agent-supplied `Authorization`.
Sanitising late would leave a window in which a hook might read a forged credential and treat
it as meaningful. INV-9 is unconditional, so its enforcement is unconditional too.

**② before ⑤.** Policy decides *whether*, then names *which* credential. Acquiring first would
mean fetching tokens for requests that are about to be denied — wasteful, and it would let an
agent drive IdP load with requests it has no right to make. FR5 is precisely this ordering.

**③ and ④ between ② and ⑤.** Both v1 seams sit after the request is understood and matched, and
**before** any credential exists. That placement is what lets a v1 body-inspection or approval
stage deny fail-closed: at that point nothing has been acquired and nothing has been sent. S1
established that a `ReverseProxy.Rewrite`-based body hook would be too late; ③ is the position
that fixes it.

**⑥ before ⑦.** INV-6. The allow record is durably committed *before* the credential is
written into the request. A crash between the two must leave evidence of an authorisation that
may have been used — never a used credential with no evidence.

**⑦ last, and adjacent to the transport.** S1 §6.1's materialisation boundary: once the token
is a header string no type protects it, so nothing may run between ⑧ and the round-trip. This
is why `Inject` is a distinct stage rather than part of `Relay` — the gap between them is
intentionally empty and its emptiness is a testable property.

### 2. `Decision` and the stage contract

```go
// Disposition is three-valued FROM THE MVP even though Pending is never returned until
// FR13 ships. S0 requires this: retrofitting a third value onto a boolean would be a
// breaking change to every stage, and approval hooks are a committed v1 feature.
type Disposition int

const (
    // Invalid is the ZERO VALUE, and is treated as Deny everywhere Disposition is
    // examined. This ordering is deliberate and is the single most important line in
    // this file: if Allow were the zero value, a forgotten assignment, a zero-valued
    // struct from a recovery handler, or a stage that returns early would fail OPEN.
    // Making the zero value un-allowable is what turns ADR-S4-01's "the safe behaviour
    // is the only behaviour" from an aspiration into a property of the type.
    Invalid Disposition = iota
    Allow
    Deny
    Pending // reserved for FR13; MVP stages must never return it
)

// Decision is the outcome of the pipeline. It is NOT the whole audit input: S6's sink
// receives the entire RequestContext, because S2 mandates policyVersion, the rule ref and
// Ambiguous be recorded, and S3 mandates credentialIdentity, provider, resource, scopes,
// cacheHit and tokenExpiresAt — none of which live here.
type Decision struct {
    Disposition Disposition
    // Reason is the internal, specific cause. It is recorded in audit and NEVER
    // surfaced to the agent — ADR-S0-13 makes all HTTP-level denials uniform, and a
    // per-reason response would let a hostile agent enumerate policy and infrastructure
    // state by observing the difference.
    Reason DenyReason
    // Fault distinguishes "policy says no" from "we could not decide". Both deny, but
    // only the second is an operational alert: a wall of ordinary denials is normal,
    // a wall of faults means something is broken.
    Fault bool
    // Cause carries the underlying error for Fault decisions. It exists because
    // ADR-S4-01 removes the error return, and without somewhere to put the cause that
    // removal would destroy diagnosability rather than merely relocating it. Recorded
    // in audit; NEVER surfaced to the agent (ADR-S0-13), and never formatted anywhere a
    // token could reach (S3 §6).
    Cause error
}

// Stage is one step. Returning a non-Allow Decision short-circuits the pipeline — with
// ONE exception: stage ⑥ Audit is never skipped (§1.1). Note there is no error return:
// a stage that cannot do its job returns Deny with Fault set, so that "failed" and
// "denied" cannot diverge in behaviour — which is exactly what fail-closed means.
type Stage interface {
    Name() string
    Run(ctx context.Context, rc *RequestContext) Decision
}

// RequestContext is the per-request state stages read and extend. Per-request, not
// per-connection: INV-8 rule 7 requires identity and authorisation to be re-established
// for every request and every HTTP/2 stream.
type RequestContext struct {
    // In is what S1 hands over: UNTRUSTED, agent-chosen values that stage ① must
    // validate. Naming it separately is deliberate — a single pre-validated "identity"
    // field would invite later stages to trust something no one checked.
    In       IdentityInput
    // Facts is nil until ① has validated In and constructed it. Stages ② onward may
    // assume it is canonical; nothing before ① may read it.
    Facts    *RequestFacts       // S2
    Dst      netip.AddrPort      // recovered destination, kernel-attested
    Match    *MatchResult        // set by ②
    Token    *TokenResult        // set by ⑤; nil when the rule names no credential
    Req      *http.Request       // outbound request under construction
    RequestID string                  // minted at pipeline entry; see AuditEvent
    Started  time.Time
    Timings  map[string]time.Duration // per-stage, for the §7 budget
    Decision Decision                 // current outcome; stage ⑥ audits this plus the above
}

// IdentityInput is S1's handoff (S1 §4 step 6c). Every field is agent-controlled except
// DstPort, which the kernel attests.
type IdentityInput struct {
    CandidateSNI  string // canonical A-label form of the TLS SNI
    AuthorityHost string // from Host (h1) or :authority (h2)
    AuthorityPort uint16 // 0 when absent
    DstPort       uint16 // from the recovered destination — NOT agent-controlled
}

// AuditSink (S6) is invoked by stage ⑥ with an immutable event:
//
//     Record(ctx context.Context, ev AuditEvent) error
//     Complete(ctx context.Context, ev CompletionEvent) error   // stage ⑨, best-effort
//
// NOT the mutable *RequestContext, and not Decision alone. Both alternatives were
// considered and both are wrong: Decision cannot carry the fields S2 and S3 mandate,
// while RequestContext is mutable and — after stage ⑦ — contains a request holding the
// plaintext credential, so handing it to a sink would put a token one reflective
// serialisation away from the audit log (INV-5, S3 §6.1).
//
// AuditEvent is built at stage ⑥ from a snapshot of the context, and is immutable.
type AuditEvent struct {
    // Outcome
    Disposition Disposition
    Reason      DenyReason
    Fault       bool
    CauseClass  FaultClass // a CLOSED enum, never the error's text — arbitrary error
                           // strings can quote request data or wrapped secrets
    // Correlation. RequestID is minted by S4 at pipeline entry (a ULID), and threads the
    // decision record, the completion record, and application logs together.
    RequestID string
    // Identity (S1/S4 ①)
    Identity string
    Method   string
    Path     string
    Port     uint16 // the recovered destination's port — from IdentityInput.DstPort
    // Transport is a closed enum (tls | plaintext). The two carry materially different
    // assurance — plaintext has no upstream authentication (S1 §6.1) — so an audit trail
    // that could not distinguish them would overstate what it witnessed.
    Transport      Transport
    ServiceUID     string // plaintext only: the Service the ClusterIP resolved to
    ServiceGeneration int64
    // Policy (S2) — present even on stale/fault outcomes, using the last known snapshot
    // version, because "which policy was in force" is exactly what an incident needs
    PolicyRef     string
    PolicyVersion string
    // EvaluatorVersion is mandated by S2 §6: PolicyVersion attests the policy INPUTS, not
    // the behaviour, so two sidecars on different Aksh builds could hash identically and
    // still enforce differently. Without this the replica-equivalence claim is unfalsifiable.
    EvaluatorVersion string
    Ambiguous        bool
    // Credential (S3) — the RESOLVED metadata is populated even when acquisition FAILED,
    // since "which credential could not be obtained" is the actionable part
    CredentialIdentity string
    Provider           string
    Resource           string
    Scopes             []string
    CacheHit           bool
    TokenExpiresAt     *time.Time // nil when there is no token
    // Timing
    Timings map[string]time.Duration
}
```

The absence of an `error` return on `Stage` is deliberate (ADR-S4-01). With one, every call
site would have to remember that an error means deny — and one that forgot would fail *open*.
Folding faults into `Decision` makes the safe behaviour the only behaviour, at the cost of
carrying `Fault` for observability.

### 3. Header hygiene (stage ⓪, plus authority synthesis in ①)

Executed in this order, on the outbound request. Steps 1–3 are stage ⓪ (removal only, unconditional); step 4 is the tail of stage ① (it needs the validated identity):

1. Remove `Authorization` and `Proxy-Authorization` from the **headers**, and install a
   **trailer filter** for the same names.

   The filter matters because trailers do not exist yet at stage ②: they arrive only after the
   request body reaches EOF, which is long after ⓪ and — for a streaming body — after stage ⑦
   has already handed the request to the transport. A one-shot map deletion at ② would
   therefore silently miss an `Authorization` trailer, which is precisely the INV-9 bypass this
   rule exists to prevent.

   So the mechanism is a wrapper installed at ② around the request's body/trailer reader, whose
   effect fires when the trailer actually arrives. This is **compatible with ADR-S4-02's empty
   gap**: the empty-gap rule forbids anything running between injection and the round trip that
   *observes or logs the outbound request*. The trailer filter is not such a thing — it is part
   of the request's own body plumbing, installed before injection, and it only ever removes
   headers. S7 asserts both properties separately: that the gap contains no observer, and that
   a late `Authorization` trailer never reaches the upstream.
2. Remove hop-by-hop headers, and any header named in `Connection` — an agent must not be able
   to nominate a header as connection-scoped to change how it is handled.
3. Remove forgeable proxy-identity headers: `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, `Via`,
   `X-Forwarded-Client-Cert`, `X-Envoy-*`, `X-Aksh-*`.
4. Set `Host`/`:authority` to the validated identity, so what the upstream sees is what policy
   matched.

Removal is by **canonical form**, and duplicates are removed exhaustively rather than by
deleting the first occurrence — the classic way a stripped header survives.

### 3.1 `DenyReason`

A **closed** enumeration, one value per row of §4. Closed rather than free-form for the same
reason S2 and S3 bound their label sets: it becomes an audit field and a metric label, and an
operator-influenced free-text reason is a cardinality hazard.

```go
type DenyReason string

const (
    ReasonIdentityMismatch   DenyReason = "identity_mismatch"    // ①
    ReasonNoSnapshot         DenyReason = "policy_no_snapshot"   // ②
    ReasonSnapshotStale      DenyReason = "policy_stale"         // ②
    ReasonNoMatch            DenyReason = "policy_no_match"      // ②  (the common case)
    ReasonMatcherFault       DenyReason = "policy_evaluator"     // ②
    ReasonTokenUnavailable   DenyReason = "token_unavailable"    // ⑤
    ReasonAuditUnavailable   DenyReason = "audit_unavailable"    // ⑥
    // NOTE: there are deliberately NO upstream reasons here. Upstream dial and TLS
    // verification failures occur AFTER stage ⑥ has committed the allow record, so they
    // are CompletionOutcomes (§8), not denials. Listing them as DenyReasons would have
    // produced two contradictory records for one request.
    ReasonPodLocalDestination DenyReason = "destination_pod_local" // ①
    ReasonMalformedTarget     DenyReason = "malformed_target"      // ①
    ReasonPlaintextUnresolvable       DenyReason = "plaintext_unresolvable"        // ①
    ReasonPlaintextRegistryUnavailable DenyReason = "plaintext_registry_unavailable" // ①
    ReasonInternal            DenyReason = "internal"              // panic, Invalid, Pending
)

// FaultClass is the closed classification recorded instead of an error string. Error
// text can quote request data or wrapped secrets, so it is never serialised into audit.
type FaultClass string

// CompletionOutcome classifies what happened AFTER the allow was committed. Separate
// from DenyReason on purpose: these are not denials, and conflating them would let a
// post-allow failure rewrite an audit record that has already been used.
type CompletionOutcome string

const (
    CompletedOK               CompletionOutcome = "ok"
    CompletedUpstreamUnreachable CompletionOutcome = "upstream_unreachable"
    CompletedUpstreamUntrusted   CompletionOutcome = "upstream_untrusted"
    CompletedTruncated        CompletionOutcome = "truncated"       // body cap / progress deadline
    CompletedResponseStageFailed CompletionOutcome = "response_stage_failed"
    CompletedInternal         CompletionOutcome = "internal"        // post-⑥ panic
)

// CompletionEvent is what stage ⑨ hands AuditSink. Separate from AuditEvent because its
// guarantee is different: best-effort, since the credential has already gone and losing
// this record loses detail rather than evidence (S6 §2.2).
type CompletionEvent struct {
    RequestID string
    Outcome   CompletionOutcome
    Status    int
    Bytes     int64
    Duration  time.Duration
}

```

`ReasonNoMatch` will dominate in normal operation; the others are all either faults or attacks,
which is what makes the split useful for alerting.

### 4. The fail-closed matrix

This table is authoritative. S0's INV-4 defines the principle; this is its complete
enumeration, and no other document may contradict it.

| Condition | Stage | Disposition | Fault | Notes |
| --------- | ----- | ----------- | ----- | ----- |
| Identity/authority mismatch | ① | Deny | no | S1 class T6, but decided **here** so it is audited (§1.2) |
| No policy snapshot ever built | ③ | Deny | **yes** | INV-4 |
| Destination is pod-local (agent dialled its own IP) | ① | Deny | no | S1 §2.2 case A; `ReasonPodLocalDestination` |
| Plaintext, but the destination is not an exact ClusterIP or its Service is ExternalName/headless/without a ready in-cluster endpoint | ① | Deny | no | S1 class T8; `ReasonPlaintextUnresolvable` |
| Plaintext, but the Service index is unavailable or stale | ① | Deny | **yes** | S1 class T9; `ReasonPlaintextRegistryUnavailable` |
| Plaintext request matches a rule with `allowPlaintext: false` | ② | Deny | no | Ordinary denial — **never** forward without the credential (S2 §3.2); `ReasonNoMatch` |
| Request target fails path canonicalisation | ① | Deny | no | S2 §5.1.1 — hostile input, **not** an evaluator fault; `ReasonMalformedTarget` |
| Snapshot age **≥** `maxStaleness` | ② | Deny | **yes** | S2 §7 uses `>=`; this row must match exactly |
| Snapshot age **<** `maxStaleness` | ② | *continue* | — | serving a cache is a successful lookup |
| No rule matches | ② | Deny | no | default-deny; the common case |
| Matcher returns an error | ② | Deny | **yes** | evaluator fault ≠ policy denial (S2) |
| Rule matches, names no credential | ⑤ | *continue* | — | legitimate; `Token` stays nil |
| Token acquisition fails | ⑤ | Deny | **yes** | FR8; per-credential (S3) |
| Audit sink cannot durably record, or exceeds its deadline | ⑥ | Deny | **yes** | INV-6's bounded exception: emergency signal, **no** audit record (§4.1) |
| Injection, upstream dial, or upstream TLS verification fails | ⑦/⑧ | **completion failure** (`CompletionOutcome`, not `DenyReason`) | no | post-⑥; the allow was already committed and may have been used (§1.0) |
| Response bound or progress deadline hit | ⑧ | **completion failure** | no | S1 §8 |
| A `ResponseStage` fails or panics | ⑧ | **completion failure** | no | allow record stands; stream aborted (§8) |
| A stage panics **before** ⑥ | ⓪–⑤ | Deny | **yes** | recovered at the pipeline boundary; `Invalid` is the zero value so even a dropped assignment denies |
| A stage panics **after** ⑥ | ⑦–⑨ | **completion failure** | no | cannot become a denial — §1.0 |

Pre-decision transport rejections (S1's classes T1–T5 and T7) are **outside** this matrix: they
occur before an HTTP request exists, so there is no `Decision` to make and no audit record to
write. S1 §8 owns them, and S6 counts them as transport metrics rather than decisions. T6 is
the sole exception and appears above, because it is an authorisation outcome.

**Normalisation before ⑥.** Two dispositions must never reach the audit record as themselves:
`Invalid` (the zero value, meaning a stage forgot to decide) and `Pending` (illegal in the MVP).
Both are rewritten to `Deny` / `ReasonInternal` / `Fault=true` at the entry to ⑥. Without this
they would audit as a denial with an empty reason and `Fault=false` — indistinguishable from a
routine policy miss, which is the opposite of what a forgotten assignment deserves.

Every `Deny` row produces the **same** response to the agent (ADR-S0-13). `Reason` and `Fault`
go only to audit and metrics.

The panic row matters more than it looks. In Go an unrecovered panic in a request goroutine
kills the process, and a recovered one whose handler forgets to decide falls through to a
zero-valued `Decision`. Had `Allow` been the zero value of `Disposition`, that fall-through
would have been an **allow** — a fail-open path reachable by any bug anywhere in the pipeline.
This is why §2 makes `Invalid` the zero value and treats it as deny: the recovery handler
should still construct an explicit `Deny`, but the type no longer depends on it remembering.

#### 4.1 Audit runs on a detached, independently bounded context

Stage ⑥ must **not** use the request's `context.Context`.

An agent controls when it disconnects, and a cancelled request context propagates: if ⑥
inherited it, an agent could cancel mid-acquisition and have the subsequent audit write fail
with `context.Canceled` — manufacturing **unaudited denials on demand**, which defeats the
purpose of a control whose output is evidence.

So ⑥ uses a context detached from the request's cancellation, carrying its own deadline
(default **250 ms** — well above §7's 5 ms P99 to absorb buffer contention, and far below
anything that would pin a request slot; the earlier draft said 2 s, which was 400× the budget
and effectively no bound at all). The deadline is not optional in the other direction
either: S1 deliberately sets no total-request timeout, so a hung audit sink with no deadline
would pin a request slot indefinitely, and an agent could exhaust the connection limit by
provoking sink stalls. Exceeding the deadline is a **terminal audit failure** — emergency
signal, deny — not an indefinite wait. `AuditSink` implementations are required to honour it.

### 5. Retry posture

**Nothing in stages ⓪–⑦ is retried.** Not policy evaluation, not token acquisition, not the
audit write. S3 retries internally, in the background, with its own backoff and breaker; a
retry at pipeline level would multiply that and hand a hostile agent an amplifier — one request
becoming several IdP calls.

**Request forwarding is not retried either**, even on a connection error, because the MVP
cannot know whether a request was idempotent or whether the upstream already processed it.
Retrying a `POST` that actually succeeded is worse than failing it.

The single exception is at the transport layer: S1's connection pool may re-dial a connection
that was closed *before any bytes were written*, which is invisible to the pipeline and cannot
duplicate an effect.

### 6. Concurrency

One goroutine per request or HTTP/2 stream. `RequestContext` is owned exclusively by that
goroutine and never shared — which is what makes the stage contract simple enough to reason
about, and avoids a class of races that would be very hard to find.

Shared state is confined to components that are explicitly concurrent by contract: the policy
snapshot (immutable, atomically swapped — S2 §6), the token cache (single-flighted — S3 §4),
the leaf cache (S1 §3.1), and the audit sink (S6).

Because the agent controls concurrency, S1's connection and stream limits are the pipeline's
admission control; S4 adds no separate queue, which would only move the bound.

### 7. Latency budget

The performance NFR needs a number per stage, not an aggregate, or a regression cannot be
attributed.

S0's NFR matrix requires **P95 and P99**, so both are given; a P95-only budget hides exactly the
tail that a hostile agent can provoke.

| Stage | P95 | P99 | Notes |
| ----- | --- | --- | ----- |
| ⓪ Sanitise | < 20 µs | < 50 µs | map operations |
| ① Identity | < 50 µs | < 150 µs | canonicalisation and comparison |
| ② Match | **< 500 µs** | **< 2 ms** | in-memory against a pre-sorted snapshot; tail is large policy sets |
| ③ BodyGate | 0 | 0 | pass-through in MVP |
| ④ Hooks | 0 | 0 | empty in MVP |
| ⑤ Acquire | **< 100 µs** (cache hit) | **< 300 µs** | a miss is an IdP round trip, budgeted separately |
| ⑥ Audit | **< 1 ms** | **< 5 ms** | the dominant in-process cost — a durable write on the request path (INV-6); the tail is buffer contention |
| ⑦ Inject | < 20 µs | < 50 µs | |
| **Pipeline total, cache-warm** | **< 2 ms** | **< 8 ms** | excludes TLS and the upstream round trip, which S1 owns |

Two costs are excluded deliberately and are **measured and reported as their own distributions**
rather than folded in: a **token cache miss** (an IdP round trip, tens to hundreds of ms) and a
**leaf cache miss** (152 µs measured, S1). Folding them in would make the budget meaningless,
and hiding them would conceal the two effects most likely to degrade under load. S7 asserts all
four distributions separately.

`RequestContext.Timings` carries per-stage measurements so S6 can expose them and S7 can assert
them.

### 8. Response phase

After ⑦, the response streams back through an ordered list of `ResponseStage`s. The list is
**empty in the MVP** and the response is relayed unmodified.

```go
// ResponseStage is reserved so that FR14's response redaction and FR11's provenance
// capture attach without redesigning the relay. Naming it in the MVP is what makes the
// v1 claim true — S1 established that a request-only relay contract would have to be
// rebuilt.
type ResponseStage interface {
    Name() string
    // Response bodies stream. A stage that must inspect one wraps the reader; it does
    // not buffer, or streaming responses (LLM token streams) break.
    //
    // The error return here is NOT inconsistent with ADR-S4-01's removal of it from
    // Stage — the two are in genuinely different situations. A request Stage can still
    // deny, so an error must be forced into a Decision. A ResponseStage runs after the
    // request was authorised, audited and forwarded, and usually after response headers
    // have already reached the agent. "Deny" is no longer an available action: you
    // cannot un-send a response.
    Run(ctx context.Context, rc ResponseContext, resp *http.Response) error
}

// ResponseContext is a minimal, immutable view — deliberately NOT *RequestContext.
// By stage ⑦ the RequestContext holds an outbound request carrying the plaintext
// Authorization header and a live TokenResult; handing that to a response hook would
// put the credential one reflective log call away from disclosure, breaching S3 §6.1's
// materialisation boundary and INV-5. Response and completion hooks get identity and
// provenance, never the request or the token.
type ResponseContext struct {
    Identity           string
    Method             string
    Path               string
    PolicyRef          string
    PolicyVersion      string
    CredentialIdentity string // the identity/hash, never the token
    Started            time.Time
}
```

**A `ResponseStage` error or panic is a completion failure, not a denial** — the same class as
S1 §8's post-allow truncation row. Concretely: the response stream is aborted (connection close
on HTTP/1.1, `RST_STREAM(CANCEL)` on HTTP/2), a completion record is appended at ⑨ marking the
outcome as failed, and the original allow record from ⑦ stands unchanged. It must **not** be
recorded as a denial: the request genuinely was authorised, and rewriting history would make
the audit trail describe something that did not happen.

If a stage fails *before* any response byte has reached the agent, the same handling applies —
the MVP does not attempt to convert a late failure into a synthetic error response, because
doing so would require buffering the response head, which §8 forbids.

ASM-1 applies here and is worth restating at the point where it bites: the MVP relays responses
without inspection, so a permitted upstream can reflect the injected token back to the agent.
That is inherent to bearer tokens, and the policy allow-list is the mitigation.

---

## Interfaces

**Defined here:** `Stage`, `ResponseStage`, `RequestContext`, `ResponseContext`,
`IdentityInput`, `Decision`, `Disposition`, `DenyReason`, `FaultClass`, `AuditEvent`.

**Consumed:** `DestinationResolver`, `UpstreamDialer` (S1); `PolicyStore`, `PolicySnapshot`,
`Matcher`, `MatchResult`, `RequestFacts` (S2); `TokenCache`, `TokenResult`, `Token`,
`AcquireError`, `credentialIdentity` (S3); `AuditSink`, `MetricsRecorder` (S6).

All *defined* contracts above are registered in S0's inventory in the same change, per S0's
governance rule.

---

## Failure modes

Covered exhaustively by §4. Two pipeline-level properties are stated separately because they
are not per-request:

| Failure | Behaviour |
| ------- | --------- |
| A stage panics | Recovered at the pipeline boundary; `Deny` with `Fault`; alert. Never fails open (§4). |
| A stage exceeds its budget | Not a failure — budgets are observability targets, not enforced deadlines. Enforcement lives in S1's timeouts, which bound the whole request. Making budgets hard deadlines would convert a latency regression into an outage. |

---

## Decisions (ADRs)

### ADR-S4-01 — `Stage` returns a `Decision`, never an error
*Context.* Stages fail. The idiomatic Go signature would be `(Decision, error)`.
*Decision.* No error return. A stage that cannot do its job returns `Deny` with `Fault` set.
*Consequences.* The safe behaviour is the only behaviour: there is no call site that can
mishandle an error and fail open, because there is no error to mishandle. Observability is
preserved by `Fault`, which separates "denied" from "broken" for alerting. The cost is
non-idiomatic Go and slightly awkward wrapping of underlying errors, which are attached to the
audit record rather than returned.

### ADR-S4-02 — Sanitise first, inject last, with nothing between injection and transport
*Context.* Header hygiene and credential injection could sit anywhere in the pipeline.
*Decision.* Sanitisation is stage ⓪; injection is stage ⑦, immediately before the round trip.
*Consequences.* No stage — including v1 hooks not yet written — can observe an agent-supplied
credential or run after a real one exists. The empty gap between ⑦ and the transport is a
testable property, which is how S1 §6.1's materialisation boundary is actually enforced rather
than merely asserted. Costs: a v1 stage that legitimately needs to see the outbound request
*with* its credential (a signing stage, say) cannot be a `Stage` and would need a distinct,
explicitly-audited extension point.

### ADR-S4-03 — Audit is a blocking stage on the request path
*Context.* INV-6 requires the allow record to precede the credential.
*Options.* Asynchronous audit with best-effort delivery; synchronous durable write.
*Decision.* Synchronous, as stage ⑥.
*Consequences.* Audit latency is request latency — the 1 ms line in §7 is the single largest
in-process cost, and S6's buffering design is what keeps it that low. In exchange, the evidence
guarantee is real: there is no window in which a credential is used without a record. An
asynchronous sink would have made INV-6 unprovable, which for a control whose output is
evidence is self-defeating.

### ADR-S4-04 — No pipeline-level retries
*Context.* Transient failures are common.
*Decision.* Stages ①–⑧ never retry, and forwarding is not retried.
*Consequences.* A hostile agent cannot amplify one request into several IdP or upstream calls.
Retry belongs where it can be bounded globally — S3's background refresh — rather than
per-request where it multiplies with concurrency. The cost is that a transient upstream blip
surfaces to the agent rather than being papered over; that is the correct trade for a component
that cannot know which requests are idempotent.

---

## v1 forward-compatibility

| v1 need | Seam | Why additive |
| ------- | ---- | ------------ |
| **FR12** body inspection | Stage ③ `BodyGate` | Already positioned after matching and **before** acquisition, so a body-based denial is fail-closed with no credential acquired and nothing sent. Turning it on activates a stage; it does not reorder the pipeline. |
| **FR13** approval hooks | Stage ④ + `Pending` | `Disposition` is three-valued from the MVP. What is still missing is the substrate to suspend and resume — OQ-S0-07, restated as OQ-S4-02. |
| **FR11** data-flow policy | Stage ④ + `ResponseStage` | Enforcement on the request side, provenance capture on the response side. Both seams exist; the cross-request store does not (OQ-S4-02). |
| **FR14** response redaction | `ResponseStage` | Reserved and empty in MVP. |
| **Ingress** | A second pipeline instance | Stages are ordered lists, not a hardcoded sequence, so ingress instantiates a different list. `RequestContext` is direction-agnostic. |

---

## Open questions

| ID | Question | Closed by |
| -- | -------- | --------- |
| **OQ-S4-01** | ~~Should `Disposition`'s zero value be un-allowable?~~ — **fixed in §2, not deferred**: `Invalid` is the zero value and is treated as deny. It needed no new information, and every day it stayed open was a day a dropped assignment failed open. What remains is the S7 obligation to *prove* it: a test asserting a zero-valued `Decision` denies, and one asserting a panicking stage denies. | S7 (test only) |
| **OQ-S4-02** | **OQ-S0-07 remains OPEN.** An earlier version of this row claimed to close it, arguing that a cross-request store is captured in a stage's closure and so never appears in a signature. That argument is true and *insufficient*, and the review was right to reject it: a store supplies **storage**, whereas suspend-and-resume needs a **protocol**. `Pending` currently follows the generic non-`Allow` path — audit, terminate, no resume — and nothing in the MVP provides continuation identity, preservation of the request body across suspension, expiry and cancellation of a pending decision, replay protection, binding of the resumed decision to the policy version that suspended it, or any answer for the case where the original connection is gone by the time approval arrives. That last one is not an edge case; it is the normal case for human approval. §1.0's one-way lifecycle makes the gap sharper still: there is no defined way to re-enter the pipeline at all. So the honest position is that FR13 needs a suspension protocol designed *before* it can be called additive, and S0's ADR-S0-09 rule applies — this is a design defect to resolve, not a cost to defer. It does not block the MVP, which never returns `Pending`. | S7 to record as a v1 prerequisite; the protocol itself is a v1 design task |
| **OQ-S4-03** | Is 1 ms a realistic P95 for a durable audit write on the request path? If S6 cannot achieve it, either the budget or ADR-S4-03's synchronous choice has to move — and that is an INV-6 conversation, not a tuning one. | S6, S7 |
| **OQ-S4-04** | ~~Rate-limit `Fault` alerting?~~ — **closed by S6 §4.2: no rate limiting needed in Aksh.** Faults are counted, not alerted per occurrence; alerts are defined on rates and gauges, and a counter is already an aggregate. The per-request detail stays in the audit stream. | *closed in S6* |
