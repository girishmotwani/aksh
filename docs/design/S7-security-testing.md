# S7 — Security Hardening, Anti-Bypass & Test Strategy

> **Status:** Reviewed · **Depends on:** S0–S6 · **Depended on by:** implementation

Every way this design can be defeated, what stops each one, and how we prove it.

---

## Scope

**Decides:** the consolidated bypass catalogue and each entry's disposition; the MVP stance on
NetworkPolicy and CNI; supply-chain posture; the test strategy across every level; the
FR-to-design-to-test traceability matrix; and the definition of done for MVP implementation.

**Does not decide:** anything about how Aksh works — S1–S6 own that. S7 is where their claims
become falsifiable.

## Requirements covered

Verification of **FR1–FR9**, honest accounting of **DEV-01/02/03**, the MVP stance on **FR15**,
and the closure criteria for every NFR in S0's ownership matrix.

---

## Design

### 1. The bypass catalogue

Every vector identified across S0–S6, in one place, with its disposition. "Closed" means a
mechanism prevents it and a test proves it. "Accepted" means we know and have decided; those
rows are the honest part of this document and must not be quietly upgraded to "closed".

#### 1.1 Interception — getting out without passing through Aksh

| # | Vector | Disposition | Mechanism |
| - | ------ | ----------- | --------- |
| B1 | Egress on a non-443 port | **Closed** | S1 §1.1 redirects all TCP ports; no `--dport` filter |
| B2 | Egress over IPv6 in a dual-stack pod | **Closed** | ADR-S1-03 programs `ip6tables` equivalently; `aksh-init` fails if it cannot |
| B3 | Connecting to the pod's **own routable IP** | **Closed** | S1 §1.1's destination-scoped loopback exclusion. Found by review: a bare `-o lo -j RETURN` matched it, because Linux routes self-addressed packets via `lo` |
| B4 | QUIC / HTTP-3 / arbitrary UDP | **Closed** (by blocking) | S1 §1.2 `REJECT`s non-TCP. HTTP/3 is unavailable to the agent — a real functional limitation (§3) |
| B5 | Claiming Aksh's reserved UID | **Closed** | INV-10 + ADR-S5-02: explicit UID required, 1774 rejected, range-bounded against `uint32` aliasing |
| B6 | Adding back `SETUID` alongside `drop: [ALL]` | **Closed** | S5 §4 requires an **empty** `capabilities.add`; `drop: [ALL]` alone does not forbid adding |
| B7 | `NET_ADMIN`/`NET_RAW` to delete rules or open raw sockets | **Closed** | S5 §4: only `aksh-init` may add them |
| B8 | `hostNetwork` — pod rules would not apply | **Closed** | Rejected at admission |
| B9 | Attaching an ephemeral container via `kubectl debug` | **Closed** | S5 §1: the validating webhook covers `pods/ephemeralcontainers` UPDATE |
| B10 | Declining injection via a pod annotation | **Closed** | S5 §1: there is no pod-level opt-out; exemption is a namespace label only an operator can set |
| B11 | A hostile init container running before `aksh-init` | **Closed** | S5 §4: Aksh's containers must be the first two init containers |
| B12 | User namespaces (`hostUsers: false`) changing UID semantics | **Rejected pending analysis** | S5 §4 rejects such pods. OQ-S5-06 — a hardening feature we are blocking, and should not be indefinitely |
| B13 | Istio present, exclusions cross-whitelisting | **Rejected** | S5 §4 refuses injection into a pod already carrying an Istio sidecar |
| B50 | `aksh-init` writes rules through the wrong iptables backend, so they exist but do nothing | **Closed** | S1 §1.5 pod-namespace backend detection + §1.3's pre-flight probe, which fails the pod. OQ-S5-07 asks only *how* detection works, not whether the backstop exists |
| B51 | Rules flushed and reinstalled, leaving a conntrack window in which a new connection is recorded without NAT | **Closed** | S1 §1.3: atomic generation-swap; live re-application is unsupported by contract |
| B52 | Aksh's own egress recursing into its listener because the UID exclusion is broken | **Closed** | S1 §2.2 case B: packet-mark detection plus the §1.3 probe. Comparing destinations cannot detect it |
| B53 | **Plaintext in-cluster hop is unauthenticated** — anything answering on an allowed ClusterIP is trusted to be that Service | **ACCEPTED, scoped** | ADR-S1-05, narrowed by B55/B56. Plaintext in a cluster is not introduced by Aksh, **but injecting a brokered bearer token over it is** — that exposure is ours, which is why it is opt-in (`allowPlaintext`) rather than default, marked `transport: plaintext` in audit, and restricted to selector-backed Services with ready in-cluster endpoints |
| B54 | **OTLP exporter egresses plaintext gRPC** (`insecure: true`, h2c on 4317) and leaves the pod | **OPEN — gates DoD** | Found during kagent source analysis. Mechanics, corrected in review: TCP/4317 is caught by the **NAT redirect**, not the filter guard, and S1 §4's protocol discriminator classifies the HTTP/2 preface as **T5 (h2c unsupported)** — so today OTLP telemetry simply breaks. It *is* identifiable (preface plus `:authority`), so supporting it is deliberate h2c handling, not a new identity concept. Decide before implementation: support h2c, or require OTLP over TLS |
| B14 | **DNS tunnelling** | **ACCEPTED** | DEV-01. **UDP *and TCP*/53** to the cluster resolver are not intercepted. A query carries data out even with no response. Unmitigated in MVP; FR15 in v1 |

#### 1.2 Identity — making Aksh send a credential somewhere it should not

| # | Vector | Disposition | Mechanism |
| - | ------ | ----------- | --------- |
| B15 | SNI says an allowed host, connection goes elsewhere | **Closed** | INV-8 rule 4 + S1 §5.2: upstream verified against the validated identity, so it fails TLS |
| B16 | `Host`/`:authority` differs from SNI | **Closed** | S4 stage ① rejects, and **audits** — it is an authorisation outcome |
| B17 | HTTP/2: allowed SNI, then streams with other authorities | **Closed** | INV-8 rule 7: identity re-established per stream |
| B18 | Bare IP with no SNI | **Closed** | INV-8 rule 1 denies for TLS. **Note this is no longer a blanket rule:** in-cluster plaintext resolves its identity from the Service registry instead (S1 §6.1), so the closure is "no *TLS* connection without SNI, and no plaintext outside the registry rules" |
| B55 | **Selectorless Service with manual `EndpointSlice`s pointing at an external IP** — making an "in-cluster" ClusterIP a route out of the cluster | **Closed** | S1 §6.1 rule 3: the Service must be selector-backed with a ready **Pod** endpoint in this cluster. Found in review of the plaintext design; without it a brokered credential could have left the cluster in plaintext while the design claimed external plaintext was refused |
| B56 | Service deleted and recreated on the same ClusterIP, or mutated to point elsewhere, inherited by a cached decision or pooled connection | **Closed** | S1 §6.1 binds Service UID and generation into the decision, the audit record and the §5.3 pool key |
| B19 | `CONNECT` or WebSocket upgrade to obtain a tunnel | **Closed** | ADR-S1-04 rejects; Aksh never degrades to an opaque tunnel |
| B20 | Path traversal / encoded separators to slip a prefix rule | **Closed** | S2 §5.1.1: segment-aware prefixes, encoded separators not decoded, dot-segments rejected |
| B21 | Request smuggling (CL/TE) | **Closed** | S1 §6: `httputil.ReverseProxy` reserialises; asserted, not assumed |
| B22 | Smuggling a credential in a **trailer** | **Closed** | S4 §3: a trailer filter installed at ⓪ whose effect fires on arrival — a one-shot header deletion would have missed it |
| B23 | Forging `X-Forwarded-*` / `Via` to influence an upstream | **Closed** | S4 §3 strips proxy-identity headers |
| B24 | Supplying an `Authorization` header to smuggle a chosen credential | **Closed** | INV-9, stage ⓪, unconditional |

#### 1.3 Credentials — obtaining the token itself

| # | Vector | Disposition | Mechanism |
| - | ------ | ----------- | --------- |
| B25 | Reading the projected SA token | **Closed** | S5 §2/§4: projected into `aksh-proxy` only; `automountServiceAccountToken: false` |
| B26 | Minting the federation token directly | **OPEN — blocks DoD** | S3 §1: the agent's SA must not hold `create` on `serviceaccounts/token` for the Entra audience, but admission cannot see RBAC (OQ-S5-02). This defeats INV-1 entirely if it happens, so it cannot remain merely "organisational": the install must ship a check, and §7 gates on it |
| B27 | Reading proxy memory (`ptrace`, shared PID namespace) | **Closed** | INV-10: `shareProcessNamespace`/`hostPID` false, `SYS_PTRACE` droppable-only |
| B28 | Token appearing in a log | **Closed for `fmt`/JSON; bounded elsewhere** | S3 §6: `fmt.Formatter` on both types — the unexported-field version provably leaked. Two residues remain by construction and are covered by rules rather than types: a `Token` held in an *unexported field of another* struct (§6 rule 3), and the post-injection request where the token is a plain header string (§6.1's ordering rule). S7 tests both |
| B29 | Token in a heap or core dump | **Closed** | S3 §6: no pprof endpoint, `RLIMIT_CORE` 0 |
| B30 | Reading the CA private key | **Closed** | INV-2 as refined: `aksh-ca-priv` mounted into `aksh-proxy` alone |
| B31 | **A permitted upstream reflecting the token back** | **ACCEPTED** | ASM-1. Inherent to bearer tokens. The allow-list *is* the mitigation; FR14 reduces accidental leakage in v1, never the deliberate case |
| B32 | Using a token after its policy is revoked | **ACCEPTED** | S3 §7: bearer tokens cannot be recalled. Bounded by lifetime (OQ-S3-02) |

#### 1.4 Policy and control plane

| # | Vector | Disposition | Mechanism |
| - | ------ | ----------- | --------- |
| B33 | A v1 narrowing field pruned into a wider policy on an MVP cluster | **Designed, not yet closed** | S2 §4/§4.1 specify the mechanism (`maxItems: 0` + CEL allow-list; a bare `enum: []` provably does not work), but S2 ships an *illustrative* resource rather than the normative schema (OQ-S2-07). Closure requires the literal schema, verified against a non-strict client on 1.29 |
| B34 | Non-determinism producing different decisions on different replicas | **Closed** | INV-7 + S2 §5.2's total order and content-hashed `policyVersion` |
| B35 | Credential shadowing — an unrelated policy changes which token a request gets | **ACCEPTED, surfaced** | S2 §5.2.2: flagged `Ambiguous` in audit whenever candidates carry different credentials |
| B36 | A namespace co-tenant writing a policy that selects another team's agent | **ACCEPTED** | ASM-S2-1: one namespace is one trust domain |
| B37 | A workload author self-selecting into a grant by **setting a label** | **ACCEPTED** | ASM-S2-1: label-write equals policy-write here. OQ-S2-06/OQ-S5-08 |
| B38 | Exhausting sidecars by creating many policies in a namespace | **Partially closed** | S2 §9 + S5 §7.1's `ResourceQuota` is the only bound that works, since a watch cannot filter CRDs by selector — but it is operator-applied and a static install cannot reach namespaces created later (OQ-S5-10). Closed only once protection cannot be enabled without it |

#### 1.5 Availability and side channels

| # | Vector | Disposition | Mechanism |
| - | ------ | ----------- | --------- |
| B39 | Connection/stream exhaustion | **Designed, not yet closed** | S1 §7 names the bounds but their values derive from the sidecar's resource limits, which are unset (OQ-S1-01/OQ-S5-04). A bound without a number is not testable |
| B40 | CPU exhaustion via certificate minting | **Closed** | ADR-S1-01: 198 ms → 152 µs, shared key + bounded cache |
| B41 | Memory exhaustion via SNI-keyed cache growth | **Closed** | S1 §3.1: bounded LRU — the agent chooses the keys |
| B42 | Metric cardinality explosion | **Closed** | ADR-S6-03 + typed `MetricsRecorder`: no agent-controlled value can be a label |
| B43 | Slowloris / stalled streams holding slots | **Closed** | S1 §5.4 per-stream progress deadline; idle timeouts alone do not bound an active stream |
| B44 | Amplifying one request into many IdP calls | **Closed** | ADR-S4-04 no pipeline retries; S3 single-flight, breaker, per-provider rate limit |
| B45 | Cancelling mid-request to suppress the audit record | **Closed** | S4 §4.1: audit runs on a detached, deadline-bounded context |
| B46 | Reaching `/metrics` and probes from the agent | **Closed** | S6 §5: owner-match on 15020. Binding to loopback would have been *worse* |
| B47 | Enumerating policy from response differences | **Closed** | ADR-S0-13: uniform HTTP denials, reasons only in audit |
| B48 | **Timing side channel** (token acquisition is slower than a policy miss) | **ACCEPTED** | ADR-S0-13: constant-time responses would impose a latency floor on every request |
| B49 | Transport-level rejections are distinguishable (T1–T5, T7) | **ACCEPTED** | Coarse oracle; an agent learns only that its bytes were not valid TLS |

### 2. NetworkPolicy and CNI — the MVP stance

FR15 is v1, but leaving the MVP stance unstated would let operators assume more than they have.

**A standard `NetworkPolicy` cannot express what Aksh needs.** It selects on pod IP, and every
container in a pod shares one — so it cannot say "only Aksh's UID may egress". It is not a
weaker version of Aksh's control; it is a control at a different granularity.

**And the obvious policies would break Aksh.** An earlier draft recommended "restrict egress to
cluster DNS only" and "deny egress to the API server". Both are wrong for the same reason the
paragraph above gives: a `NetworkPolicy` applies to the *whole pod*. DNS-only egress would block
`aksh-proxy`'s own traffic to Entra and to every upstream; denying the API server would break
S2's direct policy watch (ADR-S0-07). The recommendations would have disabled the control they
were meant to reinforce — a good illustration of why pod-granularity is the wrong instrument
here.

What is actually safe is a **pod-wide allowlist that includes every Aksh dependency**:

| Allow | Why |
| ----- | --- |
| UDP/TCP 53 to the cluster DNS service | resolution, incl. DEV-01's carve-out |
| 443 to the Kubernetes API server | S2's policy watch |
| 443 to the Entra authority host | S3's token exchange |
| 443 to the policy-permitted upstream ranges | the actual traffic |

This narrows **B14** from "any resolver on the internet" to "the cluster's resolver", which is a
real reduction in the exfiltration channel — but it cannot distinguish the agent from the proxy,
so it constrains *destinations*, never *which container* reached them. It closes no vector Aksh
claims to close, and is documented as a recommendation precisely so that "we have NetworkPolicy"
is never mistaken for "we have interception".

### 3. Known functional limitations

Not bypasses — things Aksh *breaks* — collected because each will otherwise be discovered as a
bug report:

| Limitation | Source |
| ---------- | ------ |
| HTTP/3 and QUIC do not work | B4 |
| ~~Plaintext HTTP destinations unreachable~~ — **removed.** Source analysis proved plaintext is unavoidable for kagent, and ADR-S1-05 now supports it for in-cluster destinations. External plaintext is still refused | S1 §6.1 |
| OTLP telemetry defaults to gRPC with `insecure: true` (h2c on 4317). Denied as T5 today, so telemetry breaks unless reconfigured for TLS | S7 B54 |
| WebSocket upgrades are rejected. Confirmed **not** to affect kagent: its MCP transports are `SSE`/`STREAMABLE_HTTP` only and A2A is JSONRPC. A transitive library could still open one | ADR-S1-04 |
| Certificate-pinning clients fail | S0; MITM is the mechanism |
| A pod carrying an Istio sidecar cannot be protected | B13 |
| `hostUsers: false` pods cannot be protected | B12 |
| Every container must carry an explicit security context (defaulted by the mutator) | S5 §3 |
| An agent whose HTTP client uses a bundled trust store may not honour the CA | **OQ-S5-01 — unresolved and blocking** |

### 4. Supply chain

Single image (ADR-S0-08), digest-pinned in the injected pod spec (S5 §4) so a mutable tag
cannot silently change what runs inside a protected pod. The build produces an SBOM and the
image is signed; the validating webhook checks the digest it injected, not a signature, because
signature verification at admission is an existing platform concern rather than one Aksh should
reimplement.

The `aksh-init` role needs `iptables`, so it cannot be fully distroless. The **proxy** role can
be, and shipping a distroless proxy variant meaningfully reduces the attack surface of the
container that holds the credentials. Recorded as OQ-S7-04.

### 5. Test strategy

Five levels. Each maps to claims made elsewhere; a claim with no test is not a claim.

#### 5.1 Unit and property

- **Plaintext Service resolution** (S1 §6.1) — the second-highest-value table after paths, since
  it is where a credential could leave the cluster. Vectors for: `ExternalName`, headless,
  selectorless-with-manual-external-`EndpointSlice` (B55), no ready endpoint, non-Pod endpoint
  address, ClusterIP reuse after delete/recreate (B56), stale index, index unavailable, and a
  plaintext request against a rule with `allowPlaintext: false`.
- **Path canonicalisation** (S2 §5.1.1) — the single highest-value table in the suite, since it
  is where a prefix rule gets defeated. Vectors for `..`, `%2F`, `%5C`, duplicate slashes,
  segment boundaries (`/api` must not match `/apix`), case sensitivity, query handling.
- **`credentialIdentity` golden vectors** (S3 §2.3) — three components must agree; length
  prefixing, sort order, the composed-scope decision, and the `"none"` sentinel.
- **Policy precedence** — golden files asserting the total order and that ties resolve by the
  documented tie-break, run twice with shuffled input to prove order-independence (INV-7).
- **Redaction** — a property test formatting `Token` under every `fmt` verb and flag, plus
  nested in exported and unexported fields of another struct.
- **`Disposition` zero value denies** — the fail-open trap of OQ-S4-01.

#### 5.2 Contract

Each interface in S0's inventory gets a conformance suite its implementations must pass:
`AuditSink` (honours the deadline; never drops silently), `TokenCache` (the §4 state machine,
including that a valid token is served while the breaker is open), `Matcher` (determinism),
`PolicyStore` (staleness boundaries at exactly `<` and `>=`).

#### 5.3 Integration

Component pairs against real dependencies: policy informer against a real API server
(envtest); the token broker against a mock IdP exercising 429s, 5xx, `invalid_scope`, clock
skew, and lifetimes shorter than the refresh window; the webhooks against envtest admission.

#### 5.4 End-to-end on kind

Extends the existing PoC harness (`poc/k8s/`), which already proves the mechanism works on a
real node. Additions:

- the **positive path**: policy allows, token injected, upstream observes it;
- the **negative matrix**: one test per "Closed" row in §1 — the catalogue *is* the test plan,
  and a row without a test is not closed;
- the **lifecycle matrix** (S5 §5): initial start, proxy-only restart, agent-only restart, node
  reboot — each asserting that egress fails closed while the proxy is down and that agent trust
  survives a proxy restart;
- **upgrade**: injector rolling upgrade with mixed sidecar versions in the fleet.

The e2e upstream must present a certificate Aksh's trust store accepts — the PoC's
`AKSH_INSECURE_UPSTREAM` is deleted (S1 §5.2), so the harness provisions a real trust chain.

#### 5.5 Performance

Budgets are claims (S4 §7), so they are measured, not asserted:

| Measurement | Reported as |
| ----------- | ----------- |
| Per-stage P95/P99 | Separately per stage — an aggregate cannot attribute a regression |
| Token cache **miss** | Its own distribution (S4 §7 excludes it deliberately) |
| Leaf cache **miss** | Its own distribution — 152 µs measured, S1 |
| Audit write | Its own distribution, incl. the pipe-full backpressure path (OQ-S6-01) |
| Connection setup incl. TLS | S1 owns |

A certificate-minting benchmark was run during design (the 198 µs/152 µs figures in S1 are
measured, not estimated) but **the harness is not in this repository** — it lived in the design
workspace. Reproducing it in-tree is part of implementation, and it becomes a regression guard: if
per-connection minting cost ever returns to milliseconds, someone has reintroduced per-connection
key generation.

#### 5.6 Chaos

Each of these must degrade the way its document claims, not merely "not crash":

| Fault | Expected |
| ----- | -------- |
| API server unreachable | Serve cached snapshot until `maxStaleness`, then deny all |
| Entra unreachable | Valid tokens keep serving; denial begins per-credential at expiry |
| Audit sink blocked | Deny + emergency signal + readiness fails; **recovers automatically** |
| Injector down | New protected pods rejected; running pods unaffected |
| Node log pressure | Audit backpressure denies rather than queueing unboundedly |

### 6. Traceability

Every MVP requirement, where it is designed, and where it is proven.

| FR | Design | Test | Status |
| -- | ------ | ---- | ------ |
| FR1 sidecar for kagent | S5 §2, §8 | 5.4 e2e | ⏳ CA trust **confirmed working** (httpx 0.28.1 honours `SSL_CERT_FILE`), which was the blocking risk. Now pending only the narrower obligations: assert `httpx >= 0.28` at runtime, set `AWS_CA_BUNDLE` for Bedrock, and dispose of B54 |
| FR2 injected into the network path | S1 §1, S5 §1 | 5.4 negative matrix B1–B13 | ⚠️ **DEV-01** — DNS excluded |
| FR3 tokens outside the agent | S3 §1, §6; INV-1 | 5.1 redaction, 5.4 B25–B30 | ✅ |
| FR4 acquire/refresh/rotate/cache/expire | S3 §4, §7 | 5.2 contract, 5.3 mock IdP | ✅ |
| FR5 inject only after policy allows | S4 §1 | 5.4 positive + negative | ✅ |
| FR6 policy-as-code via CRDs | S2 §1–§2 | 5.3 envtest | ⏳ **pending the normative schema** (OQ-S2-07); the design is complete, the artefact is not |
| FR7 allow/deny by FQDN, path, method, MCP server/tool, API category | S2 §2, §5 | 5.1 precedence, 5.1 paths | ⚠️ **DEV-02 + DEV-03** — FQDN, path and method only |
| FR8 fail closed | S4 §4 | 5.6 chaos, one case per matrix row | ✅ |
| FR9 structured audit | S6 §2 | 5.2 `AuditSink`, 5.4 e2e | ⏳ **pending the outcome-by-outcome field-presence matrix** — early denials have no validated request, policy or credential, and S6 currently presents those objects as always present |

**Four deviations**, all in S0's register, all needing product sign-off: DEV-01 (FR2, DNS),
DEV-02 (FR7, MCP tool), DEV-03 (FR7, API category), DEV-04 (FR2, ingress — the MRD marks both
directions MVP while the roadmap puts ingress in v1; the LLD followed the roadmap).

DEV-02 and DEV-03 narrow the same requirement: what remains of FR7 in the MVP is **FQDN, path
and method**.

**Whether this list is exhaustive is not yet provable.** OQ-S0-03, OQ-S1-02 and OQ-S1-06 have
not established what protocols kagent agents actually use. If they need WebSocket or plaintext
HTTP, §3's limitations become further deviations. The claim is "these are the deviations we
know of", not "these are all of them".

| NFR | Closure criterion | Where |
| --- | ----------------- | ----- |
| Security | Every "Closed" row in §1 has a passing test | 5.4 |
| Availability | INV-4's bounded-degradation rows behave as documented | 5.6 |
| Performance | Per-stage P95/P99 published, with excluded costs reported separately | 5.5 |
| Operability | Named metrics with a cardinality budget; no agent-controlled labels | S6 §4, 5.1 |
| Compatibility | Policy is plain YAML; injection survives rollout | 5.3, 5.4 |
| Extensibility | `Matcher` is a seam | 5.2 |
| Compliance | Stable versioned audit schema | S6 §2 |
| Resource safety | Every queue, cache and pool bounded and tested | 5.5, 5.6 |

### 7. Definition of done

MVP implementation is complete when:

1. every "Closed" row in §1 has a passing test — the catalogue is the acceptance criterion, and
   rows currently marked "Designed, not yet closed" (B33, B38, B39) or "OPEN" (B26) are
   *blockers*, not caveats;
2. FR1–FR9 pass their traceability tests, and **DEV-01 through DEV-04 have product sign-off** —
   reporting a deviation is not the same as having it accepted, and the earlier draft required
   only the former;
3. per-stage latency budgets are published from measurement **and met**; publishing numbers that
   miss the budget is not done;
4. the chaos matrix degrades as documented;
5. **every implementation-shaping open question is closed**, not merely owned — specifically:
   OQ-S7-01 (kagent CA trust — if this fails, the MVP does not work on its primary target and
   nothing else compensates), OQ-S2-07 (the normative CRD schema), OQ-S1-01/OQ-S5-04 (resource
   bounds and limits, which are numbers the tests need), OQ-S3-01/OQ-S5-05 (the WIF federated
   credential shape), OQ-S5-07 (iptables backend detection), OQ-S5-09 (CA profile and lifetime),
   OQ-S6-01 (audit write budget), OQ-S6-03 (audit record size bound), and OQ-S5-02/B26 (the
   agent's `TokenRequest` permission, which defeats INV-1 outright if unchecked);
6. an **INV-1…INV-10 matrix** exists, naming for each invariant the document that implements it
   and the test IDs that prove it — several are currently asserted without a named test;
7. exact contracts exist and agree across documents for the audit schema (field presence per
   outcome), the metric set (producer, full label set, enum values), and S0's interface
   inventory (every crossing type registered);
8. no PoC shortcut survives: `AKSH_INSECURE_UPSTREAM`, `AKSH_UPSTREAM_OVERRIDE`,
   per-connection RSA minting, the hardcoded policy map, and the stub broker are all gone, with
   a test for each.

---

## Interfaces

S7 defines none. It consumes every interface in S0's inventory and asserts their contracts.

---

## Failure modes

S7 is a strategy document; its own failure mode is being wrong about coverage. Two guards:

- **The catalogue is the test plan.** A vector may not be marked "Closed" without a linked
  test, so drift shows up as an unlinked row rather than as silent optimism.
- **"Accepted" rows are re-reviewed each release.** All eight — B14, B31, B32, B35, B36, B37,
  B48, B49 — are decisions, not facts, and the conditions that justified them can change.

---

## Decisions (ADRs)

### ADR-S7-01 — The bypass catalogue is the acceptance criterion
*Context.* Security test suites usually grow by intuition and drift from the threat model.
*Decision.* §1 is normative: every "Closed" row requires a linked passing test, and a vector
without one is not closed.
*Consequences.* Coverage is auditable, and new vectors enter tests by first entering the
catalogue. Costs discipline in review — a reviewer must add a row rather than only a test.

### ADR-S7-02 — Recommend NetworkPolicy, never rely on it
*Context.* Operators will ask whether NetworkPolicy substitutes for, or complements, Aksh.
*Decision.* Recommend two narrow policies (DNS restriction, API-server denial); document that
neither closes an Aksh-claimed vector.
*Consequences.* Prevents "we have NetworkPolicy" being read as "we have interception", which is
the misunderstanding most likely to produce a false sense of coverage. NetworkPolicy cannot
distinguish containers sharing a pod IP, so it is a different granularity, not a weaker Aksh.

### ADR-S7-03 — Accepted risks are listed, not hidden
*Context.* **Eight** vectors are accepted rather than closed: B14 (DNS), B31 (upstream
reflection), B32 (revocation window), B35 (credential shadowing), B36 and B37 (namespace trust
domain), B48 (timing) and B49 (transport-rejection oracle).
*Decision.* Each appears in §1 with the same prominence as a closed one, and in the traceability
matrix where it affects a requirement.
*Consequences.* A reader can see the true boundary of the control. The alternative — describing
only what we stop — is how security products acquire reputations they cannot support.

---

## v1 forward-compatibility

| v1 need | Effect on S7 |
| ------- | ------------ |
| **FR15** mesh/CNI anti-bypass | Closes or narrows **B14** (DNS). The capture-backend seam is S1's `DestinationResolver`; S7 gains a backend matrix |
| **FR14** response redaction | Reduces **B31** for accidental leakage; the deliberate case stays accepted |
| **FR13** approval hooks | Needs the suspension protocol OQ-S0-07 shows is missing — a v1 prerequisite, not an MVP gap |
| **Ingress** | Doubles the negative matrix; the catalogue structure is unchanged |

---

## Open questions

| ID | Question | Closed by |
| -- | -------- | --------- |
| **OQ-S7-01** | ~~Does the kagent runtime honour `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`?~~ — **closed by source analysis: yes.** kagent's lock resolves `httpx` to **0.28.1**, whose `create_ssl_context` consults `SSL_CERT_FILE` before falling back to `certifi`; verified for the OpenAI, Anthropic, Ollama, google-genai, MCP and A2A clients. **Two caveats, both actionable:** the *specifier* is `>=0.25.0`, not a pin, and httpx **before 0.28 ignored** `SSL_CERT_FILE` — so `httpx >= 0.28` is a supported-version requirement on kagent that must be asserted at runtime, not assumed. And AWS Bedrock goes through botocore, which needs `AWS_CA_BUNDLE` set as well. The distroless image's `/etc/ssl/certs` is not writable by UID 65532, so the environment-variable path is the only one available — which is fine, since it works. Replaced by a narrower obligation: assert `httpx >= 0.28` and CA trust at runtime rather than trusting the lockfile. | *closed by evidence* |
| **OQ-S7-02** | The e2e suite needs a kind cluster at the 1.29 floor *and* at 1.33, since native sidecars are beta at one and GA at the other. Is the matrix affordable in CI, or is 1.29 tested only pre-release? | implementation |
| **OQ-S7-03** | How is the DNS-exfiltration risk of B14 *monitored*, given it is accepted rather than closed? Cluster DNS query logging is the obvious answer and lives outside Aksh — but "accepted" should not mean "invisible". | implementation |
| **OQ-S7-04** | Should the proxy role ship as a distroless variant separate from the `iptables`-carrying init role? It reduces the attack surface of the container holding the credentials, at the cost of two images from one build. | implementation |
| **OQ-S7-05** | Several accepted risks (B35, B36, B37) share a root cause: policy authorship and workload authorship are not separated. Is there a single mechanism — binding policy to an admission-controlled ServiceAccount identity (OQ-S2-06) — that closes all three at once? If so it may be worth pulling into the MVP rather than accepting three risks. | v1 design |
