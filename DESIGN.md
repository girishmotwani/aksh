# Aksh — Design

This document is the single entry point to Aksh's design. It states the problem, the
adversary, the invariants that must always hold, and how the running system is put
together. It is deliberately self-contained: read it end to end and you should be able to
navigate the code without reading anything else first.

The detailed per-component designs live in [`docs/design/`](docs/design/) and are indexed
at the end. Where a design document and the code disagree, **the code is authoritative**.

---

## 1. The problem

An AI agent running in Kubernetes needs to call external APIs on a user's behalf —
Microsoft Graph, an MCP server, a model endpoint. Doing that the obvious way means handing
the agent runtime a long-lived credential and trusting it not to leak it. That trust is
misplaced twice over:

- The agent's behaviour is driven by model output, which is influenced by untrusted input.
  Prompt injection turns "call the API" into "exfiltrate the token".
- The agent process, its dependencies and its tool plugins all run with the credential in
  reach. The blast radius of any one of them is the credential's full scope.

Aksh removes the credential from the agent entirely. The agent makes an ordinary outbound
HTTPS request with no `Authorization` header. Aksh intercepts it, decides whether policy
allows it, attaches a freshly brokered token, and records what happened.

**Egress only.** MVP intercepts outbound traffic. Ingress is out of scope.

---

## 2. Threat model

The **agent container is untrusted**. It is assumed to be capable of anything a process in
that container can do: reading its own filesystem and environment, opening arbitrary
sockets, spawning processes, and attempting to reach the API server or the cloud IMDS
endpoint directly.

The trust boundary is the **container boundary inside the pod**. `aksh-proxy` runs as a
separate container, under a separate UID, with its own mounts. The agent and the proxy
share a network namespace and a pod, and nothing else.

| Trusted | Untrusted |
| ------- | --------- |
| Kernel and kubelet | The agent container's process tree, filesystem and dependencies |
| `aksh-proxy` and `aksh-init` containers | Anything the model can be persuaded to emit |
| The Kubernetes API server and its RBAC | Upstream responses |
| The identity provider (Entra) | The agent's choice of destination, method, path and headers |

**Out of scope:** a compromised node or kubelet, a malicious cluster administrator, and
side-channel extraction of a token from the proxy's own memory.

---

## 3. Invariants

These are the properties that hold on every path. They are numbered because the component
designs and the test suite cite them by number.

| ID | Invariant |
| -- | --------- |
| **INV-1** | The agent never possesses credential material. Tokens exist only inside `aksh-proxy`; the credential's projected volume is mounted into `aksh-proxy` only. |
| **INV-2** | The MITM CA private key is never readable by the agent container. |
| **INV-3** | Interception cannot be disabled by the workload. Traffic that cannot be intercepted is **blocked**, not passed. Unintercepted egress is a bypass, not a gap. |
| **INV-4** | Fail closed. Every degraded state — stale policy past its bound, unavailable token issuer, unavailable audit sink — resolves to *deny*, not *allow*. |
| **INV-5** | No secret material appears in any log, metric, audit record or error response. |
| **INV-6** | Every decision is recorded, and the allow record is durable **before** the credential leaves the process. |
| **INV-7** | Decisions are deterministic. The same request against the same policy snapshot always yields the same outcome. |
| **INV-8** | One validated identity per request. Policy can never authorise one representation of a destination while the upstream receives a different one. |
| **INV-9** | Any `Authorization` header the agent supplied is stripped, whether or not policy attaches one of its own. |
| **INV-10** | A pod shaped to defeat enforcement (reserved UID, `NET_ADMIN`, host network, shared PID namespace, …) is **rejected at admission**, with the offending field named. |

INV-4's cost is deliberate and worth stating plainly: if the audit sink is gone, requests
are denied. Permitting a request that is authorised but unauditable would contradict
INV-6, so the two invariants are enforced together.

---

## 4. Architecture

```
 Agent workload container  (untrusted, UID != proxy UID)
   │  outbound connect() / sendmsg()
   ▼
 eBPF cgroup hooks  (connect4, sockops, sock_create, sendmsg4,
   │                 connect6-deny, sendmsg6)
   │  redirect to the local proxy listener; original destination recorded
   │  in cookie/pair maps so it can be recovered after DNAT
   ▼
 aksh-proxy listener  (127.0.0.1:15001)
   │
   ├─▶ 1. TLS terminate      pod-local CA, ALPN pinned to http/1.1
   ├─▶ 2. Request validate   HTTP/1.x parse, smuggling-resistant
   ├─▶ 3. Policy match       AkshPolicy snapshot: FQDN / path / method
   ├─▶ 4. Credential inject  Entra WIF token; fail closed on acquire error
   └─▶ 5. Relay upstream     to the kernel-attested original destination
                                        │
                                        ▼
                          ┌──────────────────────────────┐
                          │ Audit sink (stdout, JSON)    │
                          │ Prometheus /metrics          │
                          │ /healthz, /readyz            │
                          │        — all on :15020 —     │
                          └──────────────────────────────┘
```

Every stage runs in-process in the proxy. **The eBPF layer only redirects sockets — it
never parses HTTP.** That split is what keeps the kernel-side code small enough to reason
about and the policy logic in ordinary, testable Go.

### 4.1 Components

| Component | Form | Responsibility |
| --------- | ---- | -------------- |
| `aksh-init` | init container | Loads and attaches the eBPF programs, programs the capture maps, then exits. If it fails, the pod does not start. |
| `aksh-proxy` | sidecar container | The data plane and enforcement pipeline: terminate, validate, match, broker, relay, audit. Watches `AkshPolicy` directly. |
| `aksh-injector` | cluster-scoped Deployment | Serves two admission webhooks — a *mutating* one that injects `aksh-init` and `aksh-proxy` and distributes the CA bundle, and a *validating* one that enforces INV-10. |

### 4.2 Why capture is at the cgroup, not in iptables

The redirect is implemented with eBPF programs attached to the pod's cgroup v2, not with
`iptables REDIRECT`. Three reasons:

1. **The workload cannot undo it.** cgroup attachment is not visible or mutable from
   inside the agent container, and requires capabilities INV-10 denies it.
2. **The original destination survives.** `connect4` records the pre-redirect destination
   keyed by socket cookie, so the proxy recovers the true upstream without relying on
   `SO_ORIGINAL_DST` semantics or on anything the client told it.
3. **The proxy's own egress is excludable precisely.** Aksh's UID is excluded, so the
   proxy's upstream dials are not re-captured — a loop guard that a port-based iptables
   rule cannot express as cleanly.

IPv6 outbound is **denied** rather than passed, because MVP does not intercept it and
INV-3 makes unintercepted egress a bypass. DNS is the single carve-out.

---

## 5. The request path

The pipeline is a fixed order. Nothing later may compensate for something earlier being
skipped.

```
accept
  └─ TLS terminate ......... mint/serve a leaf for the requested SNI from the pod-local CA
       └─ parse ............ HTTP/1.x only; reject the HTTP/2 preface and ambiguous framing
            └─ canonicalise  build RequestFacts: identity, method, path, port (INV-8)
                 └─ match ... evaluate against the current PolicySnapshot (INV-7)
                      ├─ no match / deny → record, respond with a coarse denial (ADR-S0-13)
                      └─ allow
                           └─ strip agent Authorization (INV-9)
                                └─ acquire token, if the rule names a credential
                                     └─ durably record ALLOW (INV-6)
                                          └─ attach Authorization, relay upstream
```

Two details carry most of the security weight:

- **Canonicalisation happens once, before matching**, and the same canonical form is what
  is sent upstream. This is INV-8, and it is what closes the class of attacks where policy
  sees `example.com` and the server sees something else.
- **The audit write precedes the credential leaving the process.** Not after, not
  concurrently. This is INV-6, and it is why the audit sink being down is a deny condition.

Denial responses returned to the agent are deliberately coarse. Telling an untrusted
caller *why* it was denied is a policy-oracle; the detail exists only in the audit record.

---

## 6. Policy

`AkshPolicy` is a namespaced CRD (`v1alpha1`). A policy names a set of destinations, the
methods and paths allowed against them, and optionally a `CredentialSelector` describing
which credential the rule wants.

- `spec.selector` scopes a policy to matching pods by label.
- Matching is **deny by default**: a request that matches no rule is denied.
- A snapshot is immutable, versioned and deterministically ordered, so INV-7 holds.
- A rule may allow a destination **without** naming a credential, in which case Aksh
  forwards with no `Authorization` — INV-9 still strips anything the agent supplied.

`CredentialSelector` is provider-neutral by construction. It ships `provider`, `resource`
and `scopes`; it deliberately does not have a field called `audience` holding an
Entra-specific scope value, because that would bake one provider's semantics into the
public API.

Each sidecar watches the API server directly. There is no central policy control plane and
no central token broker in MVP — a shared broker would be a single point of both failure
and credential concentration.

---

## 7. Credentials

Aksh is the **OAuth client**, not a token scraper. It acquires tokens itself using the
pod's workload identity, so there is never a long-lived secret to hand anyone.

- Tokens are cached per resolved credential identity and refreshed ahead of expiry.
- If the issuer is unreachable, cached tokens serve until expiry and then the affected
  requests are denied. The blast radius is per-audience, not global.
- No token, and no fragment of one, appears in a log, metric, error or audit record
  (INV-5). Audit records the credential's *identity*, never its value.

---

## 8. Failure modes

Component-level; per-request failures follow the fail-closed matrix above.

| Failure | Behaviour | Consequence |
| ------- | --------- | ----------- |
| `aksh-init` cannot program capture | Pod does not start | **Safe.** No interception means no enforcement, so the pod must not run. |
| Rules installed, proxy not yet listening | Agent connections refused | **Safe but disruptive.** Startup ordering is a safety property. |
| `aksh-proxy` crashes mid-life | Agent egress fails entirely | **Safe.** Restart policy and readiness handle recovery. |
| API server unreachable | Cached snapshot serves until the staleness bound, then deny | Bounded and observable. |
| Token issuer unreachable | Cached tokens serve until expiry, then deny for affected audiences | Blast radius is per-audience. |
| Audit sink unavailable | Requests denied, subject to a bounded local buffer | The highest-cost invariant, chosen knowingly. |
| `aksh-injector` unavailable | Creation of protected pods is rejected (`failurePolicy: Fail`) | Running pods unaffected. `Ignore` was rejected: it would make the enforcement component's failure mode "enforcement silently switches off". |

---

## 9. Key decisions

| # | Decision | Rationale |
| - | -------- | --------- |
| 1 | **Custom Go data plane, not Envoy** | The required behaviour is a few thousand lines of policy logic. Envoy would bring a build and extension burden far larger than the thing being built. |
| 2 | **Aksh is the OAuth client, not a token scraper** | Scraping implies the credential exists somewhere the agent could also reach it. |
| 3 | **Transparent interception is the product** | Explicit-proxy mode is a development aid. An agent that can choose whether to use the proxy is not constrained by it. |
| 4 | **Redirect all outbound TCP; exclude only Aksh's UID** | An allow-list of ports is an enumeration of what you remembered. |
| 5 | **The mutating webhook is the only enforcement path** | `extraContainers`-style opt-in is a convenience, not a control: it cannot enforce INV-10. |
| 6 | **Per-sidecar token brokering** | No central broker service to compromise, overload, or lose. |
| 7 | **Sidecars watch the API server directly** | No policy control plane in MVP; one less component in the deny path. |
| 8 | **One module, one image, subcommands** | Proxy and injector ship together and cannot version-skew. |
| 9 | **`v1alpha1`, additive-only evolution** | v1 features must land without breaking MVP clusters. |
| 10 | **Coarse external denial responses** | Detailed denials are a policy oracle for an untrusted caller. |

---

## 10. Detailed design index

| # | Document | What it answers |
| - | -------- | --------------- |
| S0 | [`S0-architecture.md`](docs/design/S0-architecture.md) | The pieces, the adversary, the invariants, and the named contracts between components. **Required reading.** |
| S1 | [`S1-data-plane.md`](docs/design/S1-data-plane.md) | How a packet gets from the agent into Aksh, is decrypted, and reaches the real upstream. |
| S1a | [`S1a-dataplane-capture.md`](docs/design/S1a-dataplane-capture.md) | eBPF capture, destination resolution, TLS termination and the upstream dialer, in implementation detail. |
| S1b | [`S1b-request-path.md`](docs/design/S1b-request-path.md) | HTTP/1.x parsing, validation, canonicalisation and pipeline integration. |
| S1c | [`S1c-transport.md`](docs/design/S1c-transport.md) | Connection pooling and resource-bound enforcement. |
| S2 | [`S2-policy-crd.md`](docs/design/S2-policy-crd.md) | What an `AkshPolicy` looks like and how a request is matched deterministically. |
| S3 | [`S3-token-broker.md`](docs/design/S3-token-broker.md) | How credentials are acquired, cached, refreshed and protected. |
| S4 | [`S4-enforcement-pipeline.md`](docs/design/S4-enforcement-pipeline.md) | The per-request order of operations and the fail-closed matrix. |
| S5 | [`S5-injection-pki.md`](docs/design/S5-injection-pki.md) | How Aksh gets into the pod, and how the MITM CA is managed safely. |
| S6 | [`S6-observability.md`](docs/design/S6-observability.md) | The evidence every decision produces, and what the operator sees. |
| S7 | [`S7-security-testing.md`](docs/design/S7-security-testing.md) | The bypass catalogue, and how enforcement is proven. |
| S8 | [`S8-proxy-runtime.md`](docs/design/S8-proxy-runtime.md) | Process lifecycle, wiring and the runtime server. |
| S9b | [`S9b-production-wiring.md`](docs/design/S9b-production-wiring.md) | Production configuration and end-to-end wiring. |

Supporting material:

- [`docs/design/README.md`](docs/design/README.md) — reading order, conventions and the open-questions register.
- [`docs/design/interface-guide.md`](docs/design/interface-guide.md) — the cross-component interface inventory.
- [`docs/FEASIBILITY.md`](docs/FEASIBILITY.md) — the original feasibility study that established the approach.
- [`README.md`](README.md) — requirements, configuration, limitations and how to run the end-to-end harness.

---

## 11. Current state and limitations

Phases 1–9 are implemented: eBPF capture, TLS termination, the request path, the policy
engine, credential brokering, audit and metrics, the sidecar injector, and a kind-based
end-to-end harness. See the **Limitations** and **Roadmap** sections of the root
[`README.md`](README.md) for the authoritative, current list of what is and is not done.

The main standing constraints are architectural rather than incidental:

- **HTTP/1.1 only.** The request path rejects the HTTP/2 preface. HTTP/2 and HTTP/3
  support are v1 work.
- **TCP only, IPv4 only.** QUIC, arbitrary UDP and IPv6 are denied rather than passed, per
  INV-3.
- **MCP servers, not MCP tools.** Policy matches destinations, not individual tool calls
  within a session.
