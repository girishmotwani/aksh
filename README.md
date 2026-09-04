# Aksh — Security Sidecar Proxy for Kagent

Aksh is a purpose-built **security sidecar proxy for Kagent**.
It **separates reasoning from authority**: eBPF cgroup hooks transparently
capture an agent container's outbound traffic and redirect it to a co-located
proxy, which terminates TLS, evaluates policy, injects brokered credentials only
when allowed, and produces audit evidence for every request. The untrusted LLM
runtime never holds a raw, long-lived credential and cannot route around the
enforcement boundary.

- **Transparent & unbypassable** — interception happens at the socket layer via
  eBPF, not via an SDK, proxy env var, or client config. A prompt-injected or
  compromised agent cannot opt out of it.
- **Credential custody** — OAuth/OIDC tokens live outside the agent process;
  Aksh injects `Authorization` only after a request is allowed and overwrites
  any caller-supplied token, so an agent cannot smuggle its own.
- **Fail closed** — a request is denied when policy lookup, token acquisition,
  or audit logging fails.
- **Proven low overhead** — a full TLS-terminating forward proxy for **sub-
  millisecond** added median latency, flat throughput to **4000 qps**, ~18 MiB
  RSS, no leak over a 6-hour AKS soak ([evidence](test/e2e/aks-soak/README.md)).
- **Zero application changes** — installed by an admission webhook; the agent is
  unmodified.

**Maturity:** the dataplane, TLS termination, policy engine, credential
brokering, audit/metrics, sidecar-injecting admission webhook, Helm chart, CI,
and published container images are implemented and deployable
([Deploying](deploy/README.md)), and validated end-to-end on both `kind` and a
real **AKS** cluster. It is pre-1.0: the scope is deliberately narrow today
(egress-only, HTTP/1.x, Entra WIF plus file-backed static bearer credentials) —
see [Limitations](#limitations).

## Why

Agentic applications create dense, multi-hop network flows (agent↔agent, agent↔LLM,
agent↔MCP/tools, agent↔cloud, agent↔SaaS). Existing controls (identity providers, API gateways,
service meshes, MCP gateways) are fragmented and none of them are purpose-built around an
**untrusted LLM runtime** that must never hold raw, long-lived credentials.

Aksh is the **local enforcement boundary around the agent process**:

- **Token custody** — stores and manages OAuth/OIDC credentials *outside* the agent runtime.
- **Header injection on allow** — adds `Authorization` only after a policy permits the request,
  overwriting any caller-supplied value so an agent cannot smuggle its own token.
- **Policy-as-code** — allow/deny by FQDN, path, method via a Kubernetes CRD (`AkshPolicy`).
- **Fail closed** — denies the request when token acquisition, policy lookup, or audit
  logging fails.
- **Audit & metrics** — a structured audit record and Prometheus metrics for every decision.

## How Aksh compares

Aksh is **not** a general-purpose AI gateway, and it does not try to be. It is
strong on exactly one axis — a **transparent, unbypassable, per-pod egress
boundary with credential custody** — and deliberately narrow everywhere else.
Where it overlaps with other tools it is often *complementary*, not a
replacement.

| Approach | What it does well | Where Aksh differs |
| --- | --- | --- |
| **AI/agent gateways** (e.g. agentgateway, MCP gateways) | Rich L7 semantics: HTTP/2 + gRPC, MCP tool-level RBAC, A2A, multi-tenant routing, a mature ecosystem | Gateways are **opt-in**: the agent must be configured to route through them, so a compromised or prompt-injected agent can connect directly and bypass them. Aksh captures at the socket layer, so egress **cannot** be routed around, and it removes credentials from the agent process entirely. Aksh is HTTP/1.x and FQDN/path/method only — far less protocol-aware. The two compose: Aksh as the enforcement floor, a gateway for protocol governance. |
| **Service meshes** (Istio/Envoy) | Mature mTLS, ingress+egress, HTTP/2/gRPC, broad platform support | A mesh authenticates *workloads to each other*; it does not broker a third-party OAuth token out of an untrusted runtime, and its sidecar interception is iptables-based and scoped to mesh-enrolled traffic. Aksh is purpose-built for "the LLM must never hold the credential" and captures all container egress. |
| **Egress firewalls / NetworkPolicy / Cilium FQDN** | Efficient L3/L4 (and some L7) allow/deny of destinations; Cilium is also eBPF and very mature | These block *where* traffic goes but cannot terminate TLS, do request-level HTTP authorization, or inject brokered credentials. Aksh adds identity and per-request authorization on top of destination control. |
| **OAuth2 proxies** (oauth2-proxy, generic auth proxies) | Simple, well-understood credential handling, usually for *ingress* | They are not transparent egress interceptors and do not use kernel capture; an agent chooses whether to use them. Aksh injects credentials on the outbound path with no client cooperation. |

The honest summary: if you need broad protocol coverage, MCP/A2A semantics, or a
battle-tested multi-cloud data plane today, a gateway or mesh is more mature. If
your threat model is *an untrusted agent runtime that must never hold raw
credentials and must not be able to route around policy*, that is exactly what
Aksh is built for — and it does it with zero application changes and sub-
millisecond overhead.

## Architecture

```
 Agent workload container
   │  outbound connect()/sendmsg()
   ▼
 eBPF cgroup hooks (connect4, sockops, sock_create, sendmsg4, connect6-deny, sendmsg6)
   │  redirect to local proxy listener (DNAT via cookie/pair maps)
   ▼
 aksh-proxy listener (127.0.0.1:15001)
   │
   ├─▶ TLS terminate (pod-local CA, ALPN pinned to http/1.1)
   ├─▶ HTTP/1.x request parse + validate (smuggling-resistant)
   ├─▶ Policy match (AkshPolicy CRD snapshot: FQDN/path/method)
   ├─▶ Credential inject (Entra WIF token; fail-closed on acquire error)
   └─▶ Relay to upstream (original destination)
                                            │
                                            ▼
                              ┌─────────────────────────────┐
                              │ Audit sink (stdout/JSON)     │
                              │ Prometheus /metrics          │
                              │ /healthz, /readyz             │
                              │  — all on :15020 —           │
                              └─────────────────────────────┘
```

Every stage runs in-process in the proxy; the eBPF layer only redirects
sockets, it does not parse HTTP.

For the threat model, the invariants, the per-request pipeline and the design
rationale, see **[`DESIGN.md`](DESIGN.md)**.

## Try it

An end-to-end harness proves the **production** `aksh-proxy` binary on a real
[kind](https://kind.sigs.k8s.io/) cluster: a policy-matched flow is allowed and
relayed to an upstream, an unmatched flow gets a uniform 403, and evidence is
pulled from Prometheus metrics, the audit sink, and pod logs.

```powershell
# from repo root; PowerShell script — requires Docker, kind, kubectl on PATH, Go 1.26
./test/e2e/run.ps1              # creates cluster, drives traffic, prints evidence, tears down
./test/e2e/run.ps1 -KeepUp      # keep the cluster for manual inspection
```

See [`test/e2e/README.md`](test/e2e/README.md) and
[`test/e2e/EVIDENCE.md`](test/e2e/EVIDENCE.md) for a captured run and the
non-root eBPF / capability wiring it exercises.

### AKS soak & performance

A second, repeatable harness ([`test/e2e/aks-soak/`](test/e2e/aks-soak/README.md))
provisions a real **AKS** cluster from Bicep, deploys aksh-captured and baseline
load generators plus in-cluster Prometheus, and measures the proxy under load.
It exists because AKS exercises production-only behaviour that `kind` does not
(per-pod cgroup namespaces, the namespaced cgroup mount, and AppArmor blocking
the per-pod bpffs mount).

```powershell
cd test/e2e/aks-soak
./run.ps1 -Soak            # provision AKS, deploy, run the timed soak, write EVIDENCE.md
./perf-tests.ps1           # supplemental connection-churn + QPS-ramp tests
```

Captured results on a `Standard_E4s_v5` (4 vCPU) node:

- **6h soak (200 qps, warm connections):** median add-latency **~+0.87ms**
  (p99 ~+1.1ms) over baseline, CPU flat **~40 mcores**, memory flat **~18 MiB**,
  **no leak**, 0 errors across 12k+ allowed flows.
- **QPS ramp:** latency stays **flat from 100 to 4000 qps**
  (p50 ~1.5-1.9ms, p99 ~3.7-5.5ms) with the target rate hit exactly at every
  step — **no saturation knee**; CPU scales ~linearly (~0.1 core / 1000 qps).
- **Connection churn:** a full TLS-terminating forward proxy for under a
  millisecond of added median latency. New TLS handshakes are capped at
  **50/s (burst 100)** by a deliberate resource guard
  (`internal/dataplane/listener/options.go`); this default is currently
  hard-coded rather than config/env-tunable, which matters for workloads with
  low connection reuse.

See [`test/e2e/aks-soak/README.md`](test/e2e/aks-soak/README.md) for the full
methodology and evidence tables.

## Requirements

- **Go 1.26** — pinned in [`go.mod`](go.mod) (`go 1.26.0`).
- **Linux kernel 5.15+** with the **cgroup v2 unified hierarchy** (the
  `sock_ops`/`sockmap` support the capture layer relies on is only dependable
  from 5.15; see `internal/dataplane/capture/options.go`).
- Capabilities for the eBPF loader: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW`,
  `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`, `CAP_PERFMON`, plus `CAP_SETUID`/
  `CAP_SETGID`/`CAP_SETPCAP` to drop privileges after load (see
  `test/e2e/manifests/50-aksh-pod.yaml`). Non-root eBPF loading requires file
  capabilities (`setcap`) on the binary — Kubernetes `securityContext.capabilities`
  alone does not reach a non-root uid's effective set.
- eBPF toolchain (clang, `bpf2go`) is only needed to *regenerate* the
  committed bindings, not to build or run the proxy — see
  [`internal/dataplane/bpf/README.md`](internal/dataplane/bpf/README.md).

## Configuration

Configuration is `defaults -> optional YAML file (AKSH_CONFIG_FILE) -> AKSH_*
environment variables`, resolved in [`internal/config/config.go`](internal/config/config.go).
Unknown YAML keys are rejected. The most operationally relevant variables:

| Variable | Purpose | Default |
| -------- | ------- | ------- |
| `AKSH_LISTENER_ADDRESS` | Data-plane listener bind address | `127.0.0.1:15001` |
| `AKSH_CA_PRIV_DIR` / `AKSH_CA_PUB_DIR` | Pod-local CA key/cert material dirs | `/var/run/aksh/ca-priv` / `/var/run/aksh/ca-pub` |
| `AKSH_POLICY_NAMESPACE` | Namespace to watch for `AkshPolicy` objects | *(required, no default)* |
| `AKSH_POLICY_MAX_STALENESS` | Deny-all threshold once the policy snapshot ages out | `45s` |
| `AKSH_POLICY_POD_LABELS_PATH` | Downward-API labels file used to match `AkshPolicy` `spec.selector` against this pod. Must be a `downwardAPI` volume exposing `metadata.labels`; startup fails closed if it cannot be read | `/etc/aksh/podinfo/labels` |
| `AKSH_CAPTURE_POD_PATH` | Pod cgroup2 path to attach the eBPF programs to | *(required, no default)* |
| `AKSH_CAPTURE_PROXY_UID` / `AKSH_CAPTURE_PROXY_GID` | uid/gid excluded from capture (the proxy's own egress) | *(required, non-zero)* |
| `AKSH_CAPTURE_DNS_SERVER` | `host:port` DNS exception let through capture uninspected | *(unset disables the exception)* |
| `AKSH_CAPTURE_BYPASS_CIDRS` | Comma-separated IPv4 prefixes excluded from capture entirely — see [Capture bypass prefixes](#capture-bypass-prefixes) | *(unset — nothing is bypassed)* |
| `AKSH_SA_TOKEN_PATH` | Projected service-account token path for Entra WIF | `/var/run/secrets/aksh/token` |
| `AKSH_ENTRA_TENANT_ID` / `AKSH_ENTRA_CLIENT_ID` | Entra workload-identity-federation identity | *(required, no default)* |
| `AKSH_ENTRA_AUTHORITY` | Entra authority endpoint | `https://login.microsoftonline.com` |
| `AKSH_STATIC_TOKEN_PATH` | File holding a static bearer credential (e.g. an API key) for the `static` credential provider; mounted only into the Aksh sidecar — see [Static bearer credentials](#static-bearer-credentials) | *(unset disables the `static` provider)* |
| `AKSH_AUDIT_SINK` | Audit record sink; cannot be disabled | `stdout` |
| `AKSH_CONTROLPLANE_PORT` | `/metrics`, `/healthz`, `/readyz` port | `15020` |

### Capture bypass prefixes

`AKSH_CAPTURE_BYPASS_CIDRS` (YAML: `capture.bypassCIDRs`) is a comma-separated
list of IPv4 prefixes, for example
`AKSH_CAPTURE_BYPASS_CIDRS=10.96.0.0/12,10.244.0.0/16`.

**Traffic to a bypassed prefix is not captured, not inspected, not policed by
`AkshPolicy`, not credential-injected, and produces no audit record.** It never
reaches the proxy at all — the eBPF `connect4` hook leaves the connect alone, so
these destinations are outside the security boundary entirely. Keep the list as
narrow as the pod actually needs.

It exists because an agent pod must reach its own in-cluster control plane over
plaintext (for kagent: `POST /api/sessions` and `POST /api/tasks` against the
controller). Without a bypass those connections are captured and rejected as
plaintext, and the agent cannot start. See issue #80.

Rules, all enforced at startup with no `AKSH_ALLOW_UNSAFE_STARTUP` override:

- IPv4 only, at most 64 prefixes.
- `/8` or longer — `0.0.0.0/0` and other very wide prefixes are rejected.
- No host bits set: write `10.96.0.0/12`, not `10.96.0.1/12`.
- The bypass is **port-independent**, unlike the single-`host:port` DNS
  exception, because a control plane does not sit on one well-known port.
- It is checked *after* the proxy-uid and loopback exemptions, so it cannot
  change how the proxy's own egress is treated.

The kernel map holding these prefixes is frozen by the loader once written, so a
proxy that still holds `CAP_BPF` at run time cannot widen its own bypass.

### Static bearer credentials

Entra Workload Identity Federation is the dynamic credential provider: Aksh
exchanges the pod's projected ServiceAccount token for a short-lived access
token on every acquisition. Many APIs, however, authenticate with a long-lived
API key rather than an OAuth token. For those, Aksh supports a **static bearer
credential provider** that keeps the key out of the agent.

Set `AKSH_STATIC_TOKEN_PATH` (YAML: `token.static.path`) to a file holding the
bearer credential. A policy rule whose `credential.provider` is `static` then
causes Aksh to read that file and inject `Authorization: Bearer <key>` after the
request is allowed — exactly like the Entra path, and still overwriting any
caller-supplied `Authorization`. The `credential.resource` field is used only as
a stable cache/identity label; the key itself never appears in policy:

```yaml
credential:
  provider: static
  resource: openai-api-key   # identity label only, not the key
```

Custody model: the agent container is given a **dummy** key, and the real key is
mounted read-only **only into the Aksh sidecar**. The injector wires this for
you when the runtime profile sets `staticToken.secretName`/`secretKey` (CLI:
`-static-token-secret-name` / `-static-token-secret-key`; env:
`AKSH_INJECTOR_STATIC_TOKEN_SECRET_NAME` / `AKSH_INJECTOR_STATIC_TOKEN_SECRET_KEY`):
it adds a `Secret`-backed volume (`aksh-static-token`) mounted at
`/var/run/secrets/aksh-static` in the aksh container, stamps
`AKSH_STATIC_TOKEN_PATH=/var/run/secrets/aksh-static/token`, and the validating
webhook denies any application container that tries to mount that volume. A
configured-but-missing/empty secret **fails closed at startup** (local self-test,
no network call).

Limitation: the static provider has **no refresh protocol**. Aksh re-reads the
file on each acquisition and honours a bounded synthetic cache expiry, so a
rotated `Secret` takes effect once the kubelet rewrites the projected file and
the cache entry expires — there is no proactive refresh or revocation signal as
there is for a short-lived Entra token.

## Limitations

- **Managed-Kubernetes platform validation is in progress.** aksh is verified
  on `kind` and now also proven on **AKS** (cgroup v2, kernel 5.15+ node image)
  via the [`test/e2e/aks-soak`](test/e2e/aks-soak/README.md) harness, which
  handles the production-only cgroup-namespace, namespaced-mount, and AppArmor
  behaviours. GKE/EKS validation and the `hostPID` + `hostPath` interaction with
  Pod Security Admission are not yet documented. Tracked as issue #63.
- **Audit records are not yet pod-attributable.** The audit schema has
  `pod.namespace/name/uid`, `agent.serviceAccount`, `policy.evaluatorVersion`
  and per-stage `timings` fields, but the request path does not populate them
  yet — they are emitted empty. Tracked as issue #62.
- **HTTP/1.x only.** ALPN is pinned to `http/1.1`; the request path does not
  speak HTTP/2.
- **Entra WIF is the only *dynamic* credential provider.** A file-backed
  `static` bearer provider is also supported for API-key services (see [Static
  bearer credentials](#static-bearer-credentials)); it keeps the key outside the
  agent but has no refresh protocol beyond re-reading the file and cache expiry.
- **Egress only.** Ingress is not enforced.

## Roadmap

| Milestone | Theme | Highlights |
| --------- | ----- | ---------- |
| **Today** | Secure token custody for agents | Sidecar injection, Entra ID OAuth/OIDC, static `AkshPolicy` CRD, egress-only enforcement, header injection on allow, audit logs, Prometheus metrics, fail-closed |
| **Next** | Agent runtime policy boundary | Ingress + egress, multi-IdP, MCP-aware controls, method/path/payload constraints, approval hooks, mesh/CNI/NetworkPolicy anti-bypass |
| **Later** | Data-flow & semantic control | Data classification, cross-service exfiltration controls, response redaction, prompt-injection/tool-poisoning hooks, policy recommendation, WASM policy plugins |

The "Today" row is implemented and deployable; see [Deploying](deploy/README.md)
to install it.

## Positioning

For platform, security, and AI infrastructure teams adopting Kubernetes-native
agents, Aksh is a zero-trust sidecar that keeps OAuth/OIDC credentials out of
agent runtimes and enforces CRD-defined policy on an agent's outbound traffic.
Unlike generic OAuth proxies or API gateways, Aksh is captured directly into the
agent's network path via eBPF and is purpose-built for token isolation,
request-level authorization, and an enforcement boundary the agent cannot route
around. MCP-aware controls and data-flow control are on the roadmap, not shipped
today — see [How Aksh compares](#how-aksh-compares) and [Roadmap](#roadmap).

## Repository layout

| Path | Contents |
| ---- | -------- |
| `api/` | `AkshPolicy` CRD Go types (`v1alpha1`) |
| `cmd/` | `aksh-proxy` (preflight checks, policy startup, main run loop) and `aksh-injector` (the admission-webhook server) entrypoints |
| `internal/` | The proxy implementation: eBPF capture (`dataplane/bpf`, `dataplane/capture`), TLS termination (`pki`, `dataplane/tlsterm`), HTTP request path (`dataplane/requestpath`, `pipeline`), policy (`policy`), credential brokering (`token`, `token/entra`), audit/metrics (`audit`), control-plane server and wiring (`runtime`), config (`config`), the sidecar-injecting admission webhook (`injector`) |
| `docs/` | Design notes, ADRs, and phase-by-phase design docs |
| `test/` | `test/e2e`: the kind end-to-end harness and its manifests/Dockerfile; `test/e2e/aks-soak`: the repeatable AKS soak / performance harness (Bicep infra, load generators, Prometheus, `run.ps1`, `perf-tests.ps1`) |

## License

[MIT](LICENSE)
