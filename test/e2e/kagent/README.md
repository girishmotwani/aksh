# kagent end-to-end harness

A real [kagent](https://kagent.dev) AI agent running behind an aksh sidecar in a
kind cluster, driven end to end.

`test/e2e/run.ps1` proves the data plane works using a synthetic `curl` loop.
This harness answers a different question: **does aksh work under a real AI
agent that nobody modified to accommodate it?** The agent is asked a question
over A2A JSON-RPC, it calls its configured LLM over TLS, and that call is
captured, terminated, matched against an `AkshPolicy`, relayed and audited.

```
pwsh test/e2e/kagent/run.ps1              # full run, tears the cluster down
pwsh test/e2e/kagent/run.ps1 -KeepUp      # leave it up to poke at
pwsh test/e2e/kagent/run.ps1 -SkipInstall # reuse kagent/mockllm, rebuild aksh only
```

Exits non-zero if any check fails.

## Topology

```
             kind cluster, namespace "kagent"
 ┌───────────────────────────────────────────────────────────────┐
 │                                                               │
 │  ┌── pod: aksh-agent-shim  (hostPID, 3 containers) ─────────┐  │
 │  │                                                          │  │
 │  │  kagent    uid 1000  the real 0.9.12 agent image,        │  │
 │  │                      running the controller-generated    │  │
 │  │                      config. Unmodified.                 │  │
 │  │                                                          │  │
 │  │  aksh      uid 1774  eBPF capture + TLS terminate +      │  │
 │  │                      policy + audit.  EXEMPT from its    │  │
 │  │                      own capture (proxy uid).            │  │
 │  │                                                          │  │
 │  │  driver    uid 0     curl loop: keeps the accept probe   │  │
 │  │                      fed and exercises the deny leg.     │  │
 │  └──────────────────────────────────────────────────────────┘  │
 │        │ captured TLS to api.openai.com          │ bypassed    │
 │        ▼                                         ▼             │
 │   ┌──────────┐                        ┌────────────────────┐   │
 │   │ mockllm  │◄─ CoreDNS rewrite      │ kagent-controller  │   │
 │   │  :8443   │   api.openai.com →     │       :8083        │   │
 │   └──────────┘   mockllm.kagent.svc   └────────────────────┘   │
 └───────────────────────────────────────────────────────────────┘
```

What is real and what is faked:

| | |
|---|---|
| **real** | kagent 0.9.12 controller, Agent CRD, agent container, its generated config |
| **real** | the agent's *verifying* TLS handshake — nothing disables verification anywhere |
| **real** | aksh: eBPF capture, TLS termination, policy match, audit, pod attribution |
| **fake** | the LLM. `mockllm` serves a leaf for `api.openai.com`, and CoreDNS maps that name to it |

Faking only the LLM is deliberate. The SNI aksh sees is the SNI it would see
against real OpenAI, so the `AkshPolicy` under test is a policy a user would
actually write — not a test-shaped one.

## Three design decisions worth knowing about

### 1. The shim Deployment, and why the agent isn't just patched

aksh needs `hostPID`. Preflight V6 proves the resolved cgroup really contains
the proxy by looking for `os.Getpid()` in a descendant `cgroup.procs`, and those
files list **host** pids; without `hostPID` the proxy cannot see itself and
fails closed.

The Agent CRD exposes `spec.declarative.deployment.{extraContainers,volumes,
volumeMounts,env,securityContext,podSecurityContext}` — but **not `hostPID`**.
Patching `hostPID` onto the controller-generated Deployment does not stick: the
patch is accepted, `metadata.generation` increments, and the controller reverts
it on the next reconcile (measured, not assumed).

So the work is split. The `Agent` CR (`70-agent-aksh.yaml`) exists purely to
make the controller generate the real agent config into `Secret/aksh-agent`,
and a Deployment we own (`80-agent-shim.yaml`) mounts that secret and runs the
real agent image with `hostPID` plus the sidecar. The agent config is
controller-generated; only the pod spec is ours.

The shim is labelled `app: aksh-kagent-e2e`, deliberately **not** `app: kagent`,
so the controller's Service does not select it. The harness therefore addresses
the agent by **pod IP**.

### 2. The pod CA is pre-seeded, not generated at run time

aksh terminates the agent's TLS, so the agent must trust aksh's pod CA. The
agent's config points at a **file path**: `tls_ca_cert_path`, derived by the
controller from the ModelConfig's `caCertSecretRef`/`caCertSecretKey`
(`60-modelconfig-aksh.yaml`). That file has to exist before the agent starts,
which rules out letting the proxy mint a CA at run time.

So `certs/genca.go` generates the CA up front, it is loaded into
`Secret/aksh-pod-ca`, and that one secret is mounted into **both** containers —
as trust material for the agent, and as `AKSH_CA_PRIV_DIR`/`AKSH_CA_PUB_DIR`
for the proxy. This exercises `internal/pki/provider.go`'s supported *load*
path (both `ca-key.pem` and `ca-cert.pem` present) rather than a test-only one.

The key must be **PKCS#8** — `x509.ParsePKCS8PrivateKey` is the only parser on
that path.

### 3. The bypass must be narrow

The agent talks to `kagent-controller` over **plaintext HTTP**
(`KAGENT_URL=http://kagent-controller.kagent:8083`). aksh has no plaintext path
for that traffic, so without a capture bypass the agent cannot serve at all —
this is issue #80, and this harness is where it was reproduced in situ.

The bypass is the kagent-controller ClusterIP as a **`/32`**. It is tempting to
bypass `10.96.0.0/12` instead, but that would also bypass the mock LLM, and the
traffic under test would stop being captured — the harness would pass while
testing nothing. ClusterIPs are cluster-assigned, so `run.ps1` reads them live
and writes `ConfigMap/aksh-kagent-net`; the manifest consumes them via
`configMapKeyRef`.

### Why the driver container is not decoration

`runtime/orchestrator.go` sets `acceptProbeTimeout = 5s`: if no redirected
connection arrives shortly after startup, the proxy terminates. A kagent agent
takes ~15s to become ready and only dials its model when someone asks it
something, so a uid-0 container has to produce captured egress from the first
second. It doubles as the prober for the deny leg (`blocked.test`).

## What is asserted

| | Check |
|---|---|
| A | the agent answers over A2A with the mock LLM's reply |
| B | the agent's own `POST /v1/chat/completions` is audited: `allow`, identity `api.openai.com`, attributed to the policy, with pod attribution |
| C | `blocked.test` is audited `deny` / `policy_no_match` |
| **D** | **negative:** point the policy at a host that doesn't match ⇒ the agent can no longer reach its model, and the call is audited as a deny ⇒ restore |
| **E** | **negative:** replace the bypass with `192.0.2.0/32` (TEST-NET-1 — valid, covers nothing) ⇒ the agent cannot serve ⇒ |
| F | restore the real bypass ⇒ working again |

D and E are the point. A–C would all pass against an aksh that captured nothing
and a policy that was never consulted; the negative legs are what make them
load-bearing.

## Troubleshooting

**Agent returns `httpx.ReadError` calling the controller.** The bypass is
missing or wrong. Check `ConfigMap/aksh-kagent-net`'s `bypassCIDRs` against the
live `kagent-controller` ClusterIP — the ClusterIP changes whenever the cluster
is recreated. This is #80.

**Proxy exits with `runtime: empty control-plane bind address`.** `POD_IP` was
not injected. The bind host is reconciled from the pod IP and loopback is
rejected.

**Proxy exits ~5s after start with an accept-probe failure.** The driver
container isn't producing captured traffic — check it is uid 0 (not the proxy
uid, which is exempt from capture) and that its `--resolve` target is right.

**Agent TLS handshake fails against aksh.** The agent isn't trusting the pod
CA. Confirm `Secret/aksh-pod-ca` is mounted at the `tls_ca_cert_path` in
`Secret/aksh-agent`'s `config.json`, and that `ca-key.pem` is PKCS#8.

**CoreDNS crash-loops on `Unexpected '}'`.** Something round-tripped the
Corefile through `kubectl get -o jsonpath`, which flattens newlines. `run.ps1`
writes the Corefile from a literal here-string for exactly this reason.

**A negative check "passes" suspiciously fast.** Verify the object actually
changed before believing it. A PowerShell *parse* error aborts the entire
script, so a patch step can silently never have run while the surrounding run
still reports success.

## Generated, not committed

`run.ps1` produces these; they are gitignored:

- `rendered/` — helm output for kagent 0.9.12
- `certs/ca-cert.pem`, `certs/ca-key.pem` — the pod CA
- `mockllm/certs/` — the mock's CA and serving cert

kagent is pinned to **0.9.12**; 0.10.x is a breaking rearchitecture.
`values-minimal.yaml` disables the ~10 bundled agents, both MCP servers and the
UI — roughly 1.6 CPU and 4.7Gi of requests that a single-node kind cluster
should not be asked to carry for one outbound LLM call.
