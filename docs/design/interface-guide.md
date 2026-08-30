# Aksh — Interface Guide

How the named interfaces map to the request journey through Aksh.

## The request journey — one HTTPS call through Aksh

Imagine the kagent wants to call `GET https://graph.microsoft.com/v1.0/me`. Here's what
happens:

### Step 1: The kernel captures the connection

The agent thinks it's connecting to `graph.microsoft.com:443`. But iptables rules (installed
by `aksh-init`) silently rewrite the destination to Aksh's local listener on port 15001.

→ **`DestinationResolver`** answers: "What was the *real* destination before the kernel
rewrote it?" It reads the original IP:port from the kernel via `SO_ORIGINAL_DST`. Without
this, Aksh would only know the agent connected "to itself" and wouldn't know where to forward
the request.

### Step 2: Aksh terminates the agent's TLS

The agent starts a TLS handshake saying "I want to talk to graph.microsoft.com" (that's the
SNI). Aksh needs to present a certificate *for that hostname* that the agent will trust.

→ **`LeafSource`** answers: "Give me a TLS certificate for `graph.microsoft.com`." It mints a
short-lived certificate on the fly, signed by Aksh's own CA, and caches it. The agent trusts
Aksh's CA (injected into its trust store), so the handshake succeeds. This is the MITM — Aksh
can now read the plaintext HTTP request.

→ **`CAProvider`** is the CA behind `LeafSource` — it holds the private key used to sign those
leaf certificates. It also reports a generation number so the leaf cache knows when to
invalidate (e.g., after a pod restart).

### Step 3: Aksh reads the HTTP request and builds facts

Now Aksh has the plaintext request: `GET /v1.0/me`, `Host: graph.microsoft.com`. It validates
that the Host header matches the SNI (INV-8), and packages everything into a canonical form.

→ **`RequestFacts`** is that canonical form — the validated identity
(`graph.microsoft.com`), HTTP method (`GET`), path (`/v1.0/me`), port (443). It's the single
source of truth that all downstream decisions use. No component re-derives these from raw
headers; everyone trusts `RequestFacts`.

### Step 4: Policy evaluation

Aksh checks: "Is this agent allowed to call `graph.microsoft.com GET /v1.0/me`?"

→ **`PolicyStore`** holds the current set of `AkshPolicy` CRDs, watched from the Kubernetes
API.

→ **`PolicySnapshot`** is an immutable, point-in-time copy of all policies. Immutable so that
a policy change mid-request can't cause inconsistency.

→ **`Matcher`** evaluates the `RequestFacts` against the snapshot and produces a
**`MatchResult`**: which rule matched (if any), and what credential it names.

### Step 5: Token acquisition

The matched policy rule says "use the Graph credential". Aksh needs an actual OAuth token.

→ **`CredentialSelector`** (already implemented) describes *what* credential is needed —
provider, resource, scopes.

→ **`TokenProvider`** resolves that into a real token by calling Entra via Workload Identity
Federation.

→ **`TokenCache`** stores tokens so Aksh doesn't call Entra on every request.

→ **`Token`** (already implemented) holds the secret value, redacted from all output.

### Step 6: Audit — the point of no return

Before the token leaves Aksh, the decision is durably recorded.

→ **`AuditSink`** writes the **`AuditEvent`** (a snapshot of the decision — identity, method,
path, disposition, policy version, credential identity — but deliberately **not** the token
value).

→ **`MetricsRecorder`** increments counters and histograms.

If the audit write fails → the request is **denied** (INV-4, INV-6).

### Step 7: Inject and forward

Aksh injects the `Authorization: Bearer <token>` header and opens a **real** TLS connection
to the actual `graph.microsoft.com`.

→ **`UpstreamDialer`** connects to the real destination (the IP from Step 1), verifies the
upstream's real TLS certificate against the validated identity, and keys the connection pool on
identity + credential so connections are never reused across different credentials.

### Step 8: Admission (separate flow — pod creation time)

When a pod is created, before it ever runs:

→ **`Injector`** has two jobs: `Patch()` adds the Aksh sidecar containers and CA trust volumes
to the pod. `Validate()` checks the final pod shape after all webhooks have run — ensuring no
container claims Aksh's UID, no one has `NET_ADMIN`, etc. (INV-10).

## The pipeline orchestration

→ **`Stage`** is one step in the ordered enforcement pipeline (steps 0–9 from S4). Each stage
gets a **`RequestContext`** (mutable, accumulates state as the request flows through stages)
and returns a `Decision`.

→ **`ResponseStage`** is the same but for the response path (reserved for v1 response
redaction).

→ **`FaultClass`** classifies errors without leaking request data or secrets into error
messages.

## Visual summary

```
Agent → [kernel REDIRECT] → Aksh listener
                               │
                    DestinationResolver  "where was this really going?"
                               │
                        LeafSource/CA    "here's a cert the agent trusts"
                               │
                      [TLS terminated]
                               │
                       RequestFacts      "validated: graph.microsoft.com GET /v1.0/me"
                               │
              PolicyStore → Snapshot → Matcher → MatchResult
                               │
                     TokenProvider/Cache  "here's a Bearer token"
                               │
                        AuditSink        "decision recorded BEFORE token leaves"
                               │
                      UpstreamDialer     "real TLS to the real destination"
                               │
                          [response relayed to agent]
```
