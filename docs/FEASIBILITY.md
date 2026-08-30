# Aksh — Feasibility Study

**Status:** Complete. All core claims validated with a working proof-of-concept (PoC).
**Question asked:** Can we build a sidecar that keeps OAuth/OIDC tokens out of the agent
runtime, is injected into the packet path *the same way Istio injects Envoy*, and only
injects `Authorization` after CRD policy allows the request — **without** the weight and
build pain of Envoy?

**Answer:** Yes. A ~200-line Go proxy built on `elazarl/goproxy` demonstrates every MVP
behavior end-to-end, in both explicit-proxy and transparent (iptables-REDIRECT) modes.

> **Note on `poc/` references.** This document is a historical record of that study.
> The throwaway PoC code it refers to (paths beginning `poc/`) was never intended to ship
> and is not published in this repository; the shipping implementation lives under
> `internal/` and `cmd/`.

---

## 1. Design decisions

### 1.1 Proxy engine: custom Go over Envoy / HAProxy / Linkerd

| Option | Verdict | Why |
| ------ | ------- | --- |
| **Envoy** | Rejected | Powerful but heavy; C++ build/extension story (WASM/ext_authz) is painful for a small team; overkill for token custody. |
| **HAProxy** | Rejected | Great L4/L7 balancer but token custody + Entra brokering + CRD policy would live in an external agent anyway; we'd still write most of Aksh. |
| **Linkerd** | Rejected | Opinionated mesh; micro-proxy is not meant to be extended with custom auth-brokering logic. |
| **Traefik + ForwardAuth** | Viable fallback | Clean middleware model, but adds a second moving part and still needs a custom auth service. |
| **Custom Go + `elazarl/goproxy`** | **Chosen** | Single static binary, trivial cross-compile, full control over MITM + policy + token injection, native controller-runtime for CRDs. |

### 1.2 Architecture model: broker, not passive MITM of Entra

Two models were considered:

- **Model A — MITM the agent's traffic to Entra**, scrape tokens off the wire. *Rejected:*
  fragile (breaks on Entra TLS/pinning/flow changes) and it doesn't actually isolate the
  credential — the agent still runs the OAuth flow and can see the token.
- **Model B — Aksh is the OAuth client (broker).** *Chosen:* the agent never runs an auth
  flow and never holds a credential. Aksh acquires tokens from Entra itself
  (client-credentials / OBO / workload-identity-federation via MSAL/`azidentity`),
  caches them keyed by audience, and injects `Authorization` on allowed egress only.

### 1.3 Two injection paths (both validated)

1. **Explicit proxy** — set `HTTPS_PROXY`/`HTTPS_PROXY` in the agent container. Easy, but
   the agent (or its libraries) can opt out. Good for dev / non-hostile workloads.
2. **Transparent (Istio-style)** — an `initContainer` installs iptables `REDIRECT` rules
   in the pod netns; the agent does a normal `connect()` and the kernel redirects it to
   Aksh. Aksh recovers the intended destination via `getsockopt(SO_ORIGINAL_DST)` — the
   **exact mechanism Envoy uses under Istio**. The agent cannot bypass it.

> We do **not** ask the agent to "turn off HTTPS." Aksh terminates TLS via MITM using an
> Aksh-owned CA that is injected into the agent's trust store
> (`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS`). The agent still speaks
> TLS; Aksh is a trusted man-in-the-middle inside the pod boundary.

---

## 2. How transparent injection works (mirrors Istio/Envoy)

Istio's sidecar injection = a **mutating admission webhook** that adds two things to the
pod: the Envoy sidecar container, and an `istio-init` **initContainer** that programs
iptables. Aksh reuses the identical pattern:

```
# initContainer (runs in the pod network namespace, needs NET_ADMIN), mirroring istio-iptables:
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 15001
iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 1337 -j RETURN   # don't redirect Aksh's own egress (loop prevention)
```

- The agent runs as a normal UID and calls `connect(graph.microsoft.com:443)`.
- The kernel rewrites the destination to `127.0.0.1:15001` (Aksh) and stashes the original
  destination on the socket.
- Aksh (running as **UID 1337**, so its own upstream calls skip the rule) accepts the
  connection and calls `getsockopt(SO_ORIGINAL_DST)` to learn where the agent *meant* to
  go — just like Envoy.
- Aksh reads the TLS SNI, mints a per-host leaf signed by the Aksh CA, terminates TLS,
  applies policy, injects the token, and re-originates TLS to the real upstream.

No eBPF is required for the MVP (Istio's default is also iptables; its eBPF/`ambient`
mode is an optimization, not a requirement).

---

## 3. What the PoC proves

The PoC (`elazarl/goproxy`, Go 1.23, ~200 LOC) was exercised two ways.

### 3.1 Explicit-proxy mode (macOS/Windows/Linux)
- MITM of agent TLS using the Aksh CA. ✅
- Policy **ALLOW** → `Authorization: Bearer <aksh-issued>` injected; upstream sees it. ✅
- Policy **DENY** (no matching AkshPolicy) → **403, fail-closed**. ✅
- Token custody: the agent never receives the token; Aksh mints/holds it keyed by
  audience. ✅

### 3.2 Transparent mode (Linux kernel, tested in WSL2 Ubuntu)
Real iptables `REDIRECT` + `SO_ORIGINAL_DST`, agent isolated by UID:

| Test | Setup | Result |
| ---- | ----- | ------ |
| **ALLOW** | uid-1500 "agent" → `graph.microsoft.com` (REDIRECTed) | Intercepted → MITM → policy allow → token injected → upstream received `Authorization` → **HTTP 200**. ✅ |
| **DENY** | uid-1500 "agent" → `evil.example.com` | **403 fail-closed** (no AkshPolicy). ✅ |
| **BYPASS sanity** | root calls the resource directly (not via Aksh) | Upstream sees **no** `Authorization` — confirms injection only happens through Aksh. ✅ |

Evidence (Aksh log, transparent run):
```
intercepted conn: original-dst=...
ALLOW GET https://graph.microsoft.com/get  -> injected token for https://graph.microsoft.com/.default
DENY  GET https://evil.example.com/  (no AkshPolicy)
```

### 3.3 Validated on a real Kubernetes node (kind) — caveat closed

The transparent path was re-run as a genuine **Istio-style pod** on a `kind` node
(real containerd, Linux 5.15): a `NET_ADMIN` **initContainer** installs the iptables
`REDIRECT` rule, the **aksh sidecar** runs as uid 1337, and a uid-1500 **agent** container
curls an `echo` **Service** (a real ClusterIP = genuine remote destination).

On a real node, `SO_ORIGINAL_DST` returns the correct destination with **no override**:

```
intercepted conn: original-dst=10.96.201.209:443     <-- real ClusterIP:443, correct port
ALLOW GET https://graph.microsoft.com/get -> injected token for https://graph.microsoft.com/.default
DENY  GET https://evil.example.com/  (no AkshPolicy)
DENY  GET https://direct/            (agent tried to bypass -> still intercepted)
```

| Test (in-pod) | Result |
| ------------- | ------ |
| **ALLOW** graph.microsoft.com | origDst `10.96.201.209:443` recovered → token injected → upstream got `Authorization` → **HTTP 200**. ✅ |
| **DENY** evil.example.com | **403 fail-closed**. ✅ |
| **Bypass attempt** (agent → ClusterIP directly) | still REDIRECTed to aksh → **403** — the agent cannot bypass. ✅ |

This confirms the earlier WSL-loopback `SO_ORIGINAL_DST` behavior was purely an
environmental artifact: on a real node the destination is a routed remote IP and the
mechanism works exactly as stock Envoy/Istio relies on it. No `AKSH_UPSTREAM_OVERRIDE`
is used here — aksh dials the real recovered `origDst`.

### 3.4 Earlier WSL-only workaround (superseded by 3.3)

During bring-up on **WSL2's loopback**, `SO_ORIGINAL_DST` returned Aksh's own redirect
port (`:15001`) instead of the original `:443` — a WSL conntrack quirk. For that hermetic
run we routed upstream by TLS SNI via a PoC-only `AKSH_UPSTREAM_OVERRIDE` knob. The kind
run in §3.3 supersedes this and needs no such workaround.

### 3.5 Entra token broker (identity flow) validated on kind

The stub token was replaced with a real **federated client-credentials exchange** and run
on the kind cluster. The design: **the agent's identity is its Kubernetes ServiceAccount**,
federated to an Entra app; aksh (in the same pod) reads the pod's **projected SA token**
and trades it for an access token — transparently, with the agent running zero auth code.

Flow exercised in-cluster:

1. The agent pod runs as ServiceAccount `agent-sa` and mounts a **projected SA token**
   with audience `api://AzureADTokenExchange` (readable by the aksh sidecar).
2. On an allowed request, aksh's broker POSTs `grant_type=client_credentials` +
   `client_assertion=<projected SA token>` to the token endpoint.
3. The endpoint validates the SA token (via the Kubernetes **TokenReview** API — the same
   check real Entra performs out-of-band against the cluster's OIDC issuer/JWKS) and mints
   an access token whose **subject is the agent's identity**.
4. aksh caches it (keyed by audience, refresh-ahead) and injects it; **fail-closed** if
   acquisition fails.

Evidence (kind run):
```
# token endpoint (mock Entra)
issued access token: sub=system:serviceaccount:default:agent-sa aud=https://graph.microsoft.com/.default appid=aksh-agent-app
# aksh sidecar
broker: acquired token for audience=https://graph.microsoft.com/.default
        (iss=https://mock-entra.aksh.local/ sub=system:serviceaccount:default:agent-sa appid=aksh-agent-app)
ALLOW GET https://graph.microsoft.com/get -> injected token for https://graph.microsoft.com/.default
# upstream received a real ~343-char Bearer JWT (vs the ~65-char stub)
upstream-received-authorization: Bearer eyJhbGciOiJIUzI1Ni...(len 343)
```

This validated the **acquire → cache → inject** broker plumbing end-to-end, with the token
carrying the agent's ServiceAccount identity. A **mock Entra** endpoint stands in for real
Entra so the run is hermetic (no Azure tenant); the aksh broker code is identical for real
Entra — only the endpoint URL and the federated-credential trust differ. Going to real
Entra additionally requires publishing the cluster's OIDC discovery/JWKS to a public URL
(standard self-managed Workload Identity Federation setup) and creating the app + federated
credential.

---

### 3.6 Real kagent agent — declarative injection, no webhook (kind)

The `curl` stand-in was replaced with a **real [kagent](https://kagent.dev) agent** to prove
Aksh integrates with an actual agent framework. kagent (installed via its official Helm
charts, controller `v0.9.12`) reconciles an `Agent` custom resource into a Deployment whose
`kagent` container (uid **65532**) calls its LLM over HTTPS at the `ModelConfig`'s
`openAI.baseUrl`.

The key result: **Aksh attaches to the kagent pod purely through the stock `Agent` CRD** —
no mutating webhook, no controller fork. kagent's `spec.declarative.deployment` exposes
`extraContainers`, `volumes`, `serviceAccountName`, `labels`, `env`, and `volumeMounts`,
which is the entire injection surface:

- `extraContainers` → the **aksh sidecar** (its own image, uid 0, `NET_ADMIN`);
- `serviceAccountName: agent-sa` → the **federated identity** aksh brokers tokens for;
- `volumes` → the projected `api://AzureADTokenExchange` SA token + the **shared Aksh CA** Secret;
- `env` on the `kagent` container → `SSL_CERT_FILE` so the agent trusts the CA up front;
- the `ModelConfig` carries a **dummy** `apiKeySecret` — the agent holds **no real model key**.

kagent's CRD has **no `initContainers` hook**, so (unlike the Istio-style init in §2) the
aksh sidecar programs its own iptables `REDIRECT` at startup (`-m owner ! --uid-owner 0`,
redirecting the agent's uid-65532 egress on :443), then drops into the transparent proxy.
The hermetic LLM is a **mock "Azure OpenAI"** endpoint (`kagent/mockllm/`) — Azure OpenAI
authenticates callers with exactly an `Authorization: Bearer <AAD token>`, which is precisely
what the aksh broker injects, so the stand-in mirrors the real auth contract.

**Validated live on kind:** the real controller reconciled the `Agent` into a **2-container
pod** (`kagent` + injected `aksh`), and the manifests pass server-side validation against the
real CRDs. The aksh sidecar came up fully operational in that pod:
```
aksh: installed REDIRECT rule
REDIRECT ... tcp dpt:443 ! owner UID match 0 redir ports 15001
CA: loaded fixed CA from /aksh-ca/ca.pem
policy: loaded 1 rule(s) from AKSH_POLICY
token broker: Entra federated exchange via http://mock-entra.default.svc.cluster.local:8080/token (client_id=aksh-agent-app)
Aksh transparent listener on :15001 (iptables REDIRECT target)
```

This confirms the novel integration claim — **Aksh injects into a real kagent-managed pod
with zero framework changes, and the agent runs with no model credential.**

**End-to-end capture (live on kind).** Sending the agent a single A2A `message/send` made the
kagent runtime emit its LLM call; the aksh sidecar intercepted it, brokered an Entra token for
the agent's own workload identity, and injected it — the kagent agent never held a credential.
The agent's A2A reply carried the mock LLM's report of what it received:
```
"aksh PoC: hermetic Azure OpenAI stand-in reached. The credential I received was
 ****** 352) — the kagent agent carried no key; aksh injected it."
```
and the aksh sidecar log shows the full broker → inject sequence for that request:
```
broker: acquired token for audience=https://cognitiveservices.azure.com/.default
  (iss=https://mock-entra.aksh.local/ sub=system:serviceaccount:kagent:agent-sa appid=aksh-agent-app)
ALLOW POST https://kagent-mockllm.kagent.svc.cluster.local/v1/chat/completions
  -> injected token for https://cognitiveservices.azure.com/.default
```
Note `sub=system:serviceaccount:kagent:agent-sa`: the brokered token is bound to the agent
pod's **own** Kubernetes identity, and the injected credential (~352-char AAD JWT) reached the
mock LLM even though the `ModelConfig`/agent held only a dummy key. `poc/kagent/README.md`
gives the one-command trigger to reproduce this on any stable cluster.

> Host note: this WSL host's kind node is intermittently restarted by a WSL cgroup-v1
> `devices.allow` daemon bug (unrelated to Aksh); a clean `wsl --shutdown` plus trimming the
> kagent demo workload gives a stable-enough window to run the trigger above.

---

## 4. Component mapping (PoC → product)

| Concern | PoC | Productionization |
| ------- | --- | ----------------- |
| Data plane | `goproxy` MITM handler = enforcement point | Same, hardened; connection pooling, timeouts, metrics |
| Control plane | in-memory `policyStore` | `controller-runtime` watching `AkshPolicy` CRDs → feeds the store |
| Token custody | `tokenStore` + **federated client-credentials broker** (`broker.go`) exchanging the projected SA token; **mock Entra** endpoint validating via TokenReview | Point the broker at **real Entra**; add OBO/WIF variants, refresh-ahead loop, per-audience scoping |
| Identity | agent pod SA (`agent-sa`) → mock Entra app | pod SA federated to a real Entra app / user-assigned managed identity |
| Injection | manual `HTTPS_PROXY` / manual iptables; **kagent: sidecar attached via the stock `Agent` CRD** (`extraContainers`/`volumes`/`serviceAccountName`/`env`), self-installed iptables | mutating webhook adds sidecar + `istio-init`-style initContainer + CA into trust store (kagent has no initContainer hook, so the webhook covers iptables setup) |
| Trust | Aksh CA generated at start | CA per-pod or per-namespace, mounted; short-lived leaves |
| Fail-closed | 403 on any policy/token failure | Same, plus audit-log-write-failure = deny (FR8) |

---

## 5. Risks & mitigations

| Risk | Mitigation |
| ---- | ---------- |
| Agent bypasses proxy (explicit mode) | Use transparent iptables mode + `NetworkPolicy`/CNI egress lock so only Aksh's UID can egress (FR15). |
| Cert pinning in agent libs | Document supported clients; provide CA-injection guidance; pinning-heavy clients are unsupported for MVP. |
| TLS MITM performance | Cache minted leaves per host; reuse upstream connections; publish P95/P99 budgets during MVP. |
| Token blast radius | Narrow audiences/scopes per AkshPolicy; short-lived tokens; never log token values. |
| initContainer needs `NET_ADMIN` | Same posture as Istio; scope via PodSecurity / dedicated namespace. |

---

## 6. Conclusion & recommended next steps

Feasibility is **confirmed**. A lightweight Go sidecar delivers Envoy-class transparent
injection (iptables `REDIRECT` + `SO_ORIGINAL_DST`) with far less weight, plus the token
custody, CRD policy, and fail-closed behavior the MRD requires.

Recommended path to MVP:
1. ~~Validate transparent mode on a real node~~ — **done** (kind, §3.3): `SO_ORIGINAL_DST`
   returns the correct destination and the agent cannot bypass the sidecar.
2. ~~Wire the token broker~~ — **done** (kind, §3.5): federated client-credentials exchange
   of the pod's projected SA token, injecting a JWT that carries the agent's identity,
   against a **mock Entra**. Remaining: point it at **real Entra + live Microsoft Graph**
   (publish cluster OIDC/JWKS + create the app & federated credential).
3. Define the **`AkshPolicy` CRD** + `controller-runtime` reconciler.
4. Build the **mutating webhook + initContainer + sidecar** manifests and CA injection.
5. Add **audit logging + Prometheus metrics** and codify fail-closed on audit failure.
6. ~~Swap the `curl` stand-in for a real **kagent** workload~~ — **done** (kind, §3.6):
   a real kagent `Agent` (controller v0.9.12) runs with the aksh sidecar attached purely
   through the stock `Agent` CRD and no model key of its own; an A2A message triggered the
   agent's LLM call and aksh brokered + injected an Entra token bound to the agent's own SA
   identity (`sub=system:serviceaccount:kagent:agent-sa`), captured end-to-end.

The PoC source used for this study lives under `poc/` (goproxy handler, transparent
`SO_ORIGINAL_DST` listener, federated token broker + mock Entra endpoint, hermetic TLS
echo server, and the kind manifests), with the **kagent integration** under `poc/kagent/`
(mock Azure-OpenAI endpoint + `Agent`/`ModelConfig` manifests that inject the aksh sidecar
declaratively).
