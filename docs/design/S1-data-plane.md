# S1 — Interception & Data Plane

> **Status:** Reviewed · **Depends on:** S0 · **Depended on by:** S4 (pipeline), S5 (injection), S7 (bypass testing)

> **PARTIALLY SUPERSEDED (Phase 5A).** Sections 1 (interception rule set), 2 (connection
> ingestion) and the capture-related parts of section 3 (TLS termination) -- namely where the
> SNI is captured, how the connection arrives at the terminator, and ALPN gating on the
> accepted connection -- are superseded by `S1a-dataplane-capture.md` for the eBPF capture
> backend. iptables is no longer used; the original destination is recovered from a BPF map
> rather than `SO_ORIGINAL_DST`. The remainder of S1 stays authoritative: the rejection
> taxonomy T1-T9, the timeout budget, the TLS termination design (ADR-S1-01, shared leaf key,
> leaf cache, resumption disabled, ALPN and SNI rules), the plaintext Service-registry rules
> (ADR-S1-05), the upstream transport and pool key, and HTTP handling. OQ-S1-01 (numeric
> resource bounds) is closed by S1a section 13.
>
> **The table in S1a section 2 is the normative supersession map**; this paragraph is a
> summary of it, and where the two disagree the table wins.

How a packet leaves the agent, arrives at Aksh, gets decrypted, and reaches the real
upstream — and what Aksh refuses to carry.

---

## Scope

**Decides:** the iptables program *(superseded: capture is eBPF, see `S1a-dataplane-capture.md`
section 6)*; how the true destination is recovered *(superseded: a BPF map lookup, not
`SO_ORIGINAL_DST`, see S1a section 8.1)*; TLS termination and
certificate minting; how the validated identity of INV-8 is actually established; the upstream
transport; which HTTP protocols are supported and how bodies are relayed; the resource bounds
that keep a hostile agent from exhausting the sidecar; and the taxonomy of transport-level
rejections.

**Does not decide:** what policy *says* (S2), where credentials come from (S3), the order in
which enforcement steps run (S4), how the rules get installed into a pod (S5), or what a
decision is recorded as (S6).

## Requirements covered

**FR2** (injection into the network path) and the mechanical half of **FR5** (the ability to
modify headers at all). Implements **INV-3** (interception cannot be disabled), **INV-8**
(one validated identity), **INV-9** (credential headers stripped), and the S1 share of the
**resource-safety** NFR and the **performance** NFR.

---

## Design

### 1. The interception rule set

The rules run in the pod's network namespace, installed by `aksh-init` (S5). They implement
ADR-S0-04: **redirect everything, exclude only Aksh**.

#### 1.1 Chain design

All rules live in a dedicated chain, never appended directly to `OUTPUT`. This is what makes
installation idempotent (§1.3) and makes Aksh's rules distinguishable from anyone else's.

```
*nat
:AKSH_OUTPUT       - [0:0]
:AKSH_REDIRECT     - [0:0]

# Everything leaving the pod enters our chain, and only our chain.
-A OUTPUT -p tcp -j AKSH_OUTPUT

# ---- exclusions, in order; first match wins ----

# (1) Aksh's own egress. Without this, Aksh's upstream connection is redirected
#     back into Aksh: an infinite loop. This is the ONLY identity-based exclusion.
#     Aksh also marks its own connections, so that a marked packet arriving at the
#     listener positively identifies a broken exclusion (§2.2 case B) — comparing
#     destinations cannot detect that, because a recursed connection carries the
#     real external destination and looks entirely ordinary.
-A AKSH_OUTPUT -m owner --uid-owner ${AKSH_UID} -j MARK --set-mark ${AKSH_MARK}
-A AKSH_OUTPUT -m mark --mark ${AKSH_MARK} -j RETURN

# (2) Traffic that genuinely never leaves the pod. Note the destination match:
#     `-o lo` ALONE IS WRONG. Linux routes any packet addressed to an address
#     assigned to the host — including the pod's own routable CNI address — out
#     via `lo`, before netfilter runs. A bare `-o lo -j RETURN` therefore excludes
#     pod-IP-addressed traffic from interception entirely, which a hostile agent
#     can trigger simply by dialling its own pod IP. Scope to real loopback only.
-A AKSH_OUTPUT -o lo -d 127.0.0.0/8 -j RETURN

# (3) DNS to the cluster resolver — the single named exception of S0 §2 / DEV-01.
-A AKSH_OUTPUT -p tcp -d ${CLUSTER_DNS} --dport 53 -j RETURN

# ---- everything else is captured, including traffic to the pod's own IP ----
-A AKSH_OUTPUT -j AKSH_REDIRECT
-A AKSH_REDIRECT -p tcp -j REDIRECT --to-ports ${AKSH_PORT}
COMMIT
```

Three properties are deliberate and must not be "optimised" away:

- **No `--dport` filter.** The redirect covers *all* destination TCP ports (INV-3, port axis).
  A rule scoped to 443 would let an agent reach any upstream on 8443 with no interception at
  all. This is the single most likely regression in this document, because every example
  everywhere — including the PoC — uses 443.
- **The loopback exclusion is scoped by destination, not just by interface.** This was
  confirmed empirically during review: with a bare `-o lo -j RETURN`, a connection to the
  pod's own routable address matched the exclusion (the `127.0.0.0/8` rule never saw it) and
  reached the target listener without ever passing through Aksh. Because an agent can read its
  own pod IP trivially (Downward API, `hostname -i`) and DNS is not intercepted (DEV-01), that
  is a complete, silent bypass of policy and audit. The destination match closes it.
- **Exclusion (1) is the only UID rule, and it is an exclusion, not an allowlist.** Aksh does
  not need to know the agent's UID, which is what makes it robust against kagent pinning no
  `securityContext` (ADR-S0-04). Its corollary is that the reserved UID becomes a total
  bypass if the workload can claim it, which is why INV-10 rejects such pods at admission.

#### 1.2 Blocking what cannot be intercepted

The NAT table only redirects TCP. Per INV-3, everything else must be **blocked**, not ignored:

```
*filter
:AKSH_EGRESS_GUARD - [0:0]
-A OUTPUT -j AKSH_EGRESS_GUARD
-A AKSH_EGRESS_GUARD -m owner --uid-owner ${AKSH_UID} -j RETURN
-A AKSH_EGRESS_GUARD -o lo -d 127.0.0.0/8 -j RETURN                  # scoped, per §1.1
-A AKSH_EGRESS_GUARD -p udp -d ${CLUSTER_DNS} --dport 53 -j RETURN   # DEV-01
-A AKSH_EGRESS_GUARD -p udp -j REJECT      # QUIC/HTTP-3, arbitrary UDP
-A AKSH_EGRESS_GUARD ! -p tcp -j REJECT    # SCTP, ICMP tunnels, everything else
COMMIT
```

`REJECT` rather than `DROP`: a rejected connection fails fast and visibly, where a dropped one
hangs until timeout and looks like a network fault. An agent library that finds QUIC blocked
will fall back to TCP, which is the outcome we want; one that hangs may just retry forever.

**HTTP/3 is therefore unavailable to the agent, by design.** This is a real functional
limitation and S7 must state it as such. It is preferable to the alternative, which is an
uninspected encrypted egress channel.

#### 1.3 Installation: atomic, first-position, and verified

Three separate properties, each closing a distinct failure.

**Atomic.** Rules are applied with a single `iptables-restore --noflush` transaction over a
generation-suffixed chain pair (`AKSH_OUTPUT_<gen>`), followed by an atomic jump swap. There
is **never** a moment where the chains exist empty or the jump is absent. The naive
"flush, then re-insert" sequence is forbidden: a TCP connection opened during the gap is
recorded by conntrack *without* a NAT mapping, and because the filter chain permits TCP,
restoring the rules does not recapture that flow — it egresses directly, unaudited, for its
entire lifetime. That is a persistent INV-3 violation produced by a few milliseconds of
carelessness.

Correspondingly, **live re-application is not a supported operation**. Rules are installed
once by `aksh-init` before any agent process exists. Changing them requires a pod restart.
Removing the ability to reconfigure in place removes the window entirely.

**First-position.** Both jumps are inserted with `-I` at position 1, not appended with `-A`.
An appended jump sits behind any pre-existing terminating rule in the pod namespace, which
would silently bypass Aksh while reporting successful installation. `aksh-init` additionally
**fails** if it finds a pre-existing conflicting redirect it did not create (§1.5).

**Verified.** Installation is not complete until it is *proven*. `aksh-init` performs a
**pre-flight probe from a non-Aksh UID**: it opens a connection to a known address and
asserts Aksh observed it as redirected. If the probe does not arrive, `aksh-init` fails and
the pod does not start. This is a production control, not a test — a test asserts the design
was right once; the probe asserts this specific pod is actually protected. It is what catches
the wrong-backend failure of §1.5, whose symptom is otherwise "rules look installed and do
nothing".

#### 1.4 IPv6 — closing OQ-S0-11

INV-3 requires interception across address families or an outright block. Ignoring IPv6 in a
dual-stack pod is a complete bypass: the agent simply connects over IPv6 and no rule applies.
The decision and its ICMPv6 carve-out are recorded in ADR-S1-03.

#### 1.5 Backend detection and coexistence

`iptables` may be backed by `iptables-legacy` or `iptables-nft`. Rules written through one
backend are invisible to the other, so choosing wrong produces rules that appear installed and
do nothing.

The backend must be detected **in the pod's own network namespace**, by inspecting which
backend already holds rules there — *not* by looking at the node's kube-proxy mode, which is a
different namespace and a different rule set. The §1.3 pre-flight probe is the backstop: even
if detection is wrong, the probe fails and the pod does not start.

**Istio coexistence is not supported in the MVP.** Both program conflicting `OUTPUT`
redirects, both want a reserved UID, and both want to terminate the agent's TLS; the composed
behaviour is undefined. S5's injector must refuse to inject into a pod already carrying an
Istio sidecar, and say why. Making them compose is a v1 problem (S0's FR15 capture-backend
seam).

### 2. Connection ingestion

#### 2.1 Recovering the true destination

After `REDIRECT`, `conn.RemoteAddr()` reports the pod's own address — the original destination
survives only as a socket option.

The PoC obtains it via `syscall.GetsockoptIPv6Mreq`, exploiting the fact that the struct
happens to be 16 bytes. That is struct-punning: it is IPv4-only, and it depends on a layout
coincidence. **The product reads the option into a raw byte buffer and parses it explicitly**,
using `SOL_IP`/`SO_ORIGINAL_DST` for IPv4 sockets and `SOL_IPV6`/`IP6T_SO_ORIGINAL_DST`
(both option 80) for IPv6, decoding `sockaddr_in` or `sockaddr_in6` respectively.

Recovery failure is not recoverable and not maskable: if the destination cannot be
established, the connection is closed (§7, class T1). It is never guessed from SNI — that
would let the agent choose its own destination, defeating INV-8 rule 4.

#### 2.2 Self-addressed traffic and recursion detection

Two distinct conditions must be told apart, and the naive test — "is the recovered destination
my own listener?" — conflates them and does not actually detect recursion.

**Case A — the agent dialled a pod-local address** (the pod's routable IP, or Aksh's own
listener port on that IP). Now intercepted (§1.1), so it reaches Aksh. There is no external
identity to validate, so INV-8 rule 1 denies it. It is an **ordinary denial** returning the
uniform response, **not** an alert — otherwise an agent can manufacture false
misconfiguration alarms at will simply by dialling `podIP:15001` in a loop.

**Case B — Aksh's own egress is being redirected back into Aksh.** This is the genuine
recursion, and it is *not* detectable by comparing the destination: if exclusion (1) were
missing, Aksh's upstream connection would arrive carrying the real external destination, which
looks entirely normal. Recursion is instead detected structurally: Aksh sets a **packet mark**
on its own outbound connections, and the redirect chain matches on the mark's absence. A
marked connection arriving at the listener means the exclusion is broken. That condition
alerts (class T2) and is a startup-probe assertion (§1.3), not a per-request check.

Distinguishing case A requires knowing the pod's own addresses: Aksh enumerates its interface
addresses at startup and refreshes on change, so "pod-local" means the full assigned set, not
just `127.0.0.0/8`.

> This supersedes the narrower reading of INV-8 rule 5. S0 says pod-local destinations are
> "dropped"; S1 refines that to *denied with the uniform response*, because a distinguishable
> drop is itself an oracle and an alert-flooding vector. The security outcome — no credential,
> no upstream connection — is identical.

The PoC's `AKSH_UPSTREAM_OVERRIDE`, a workaround for a WSL loopback quirk, **does not exist in
the product**. Neither does `AKSH_INSECURE_UPSTREAM` (§5.2). S0 §9 forbids both.

### 3. TLS termination

#### 3.1 Certificate minting — the PoC's most expensive mistake

The PoC generates a fresh RSA-2048 key for every connection. Measured on a Xeon 8370C:

| Strategy | Cost per connection |
| -------- | ------------------- |
| PoC: RSA-2048 keygen + sign | **198 ms** (measured) |
| **Shared key, sign only** | **152 µs** (measured) |
| Shared key + cache hit | a map lookup |

For reference, the underlying key generations measured 268 ms (RSA-2048) and 20 µs
(ECDSA P-256) — a ~13,000× difference, which is why the shared key is ECDSA. The ~1,300×
figure quoted elsewhere is the *end-to-end* ratio: PoC-style minting (198 ms) versus
shared-key signing (152 µs).

198 ms of CPU before any useful work is both a latency disaster and a denial-of-service
vector: an agent opening connections in a loop pins every core on key generation. The design
is therefore three independent changes, all required (ADR-S1-01):

1. **One long-lived ECDSA P-256 leaf key**, generated at startup and reused for every leaf.
   Only the certificate varies. This removes key generation from the request path entirely.
   (mitmproxy does the same.) The leaf key is *not* the CA key — reusing the CA key as a leaf
   key would expose it in every handshake.
2. **ECDSA P-256** rather than RSA-2048, which is ~1300× cheaper to generate and cheaper to
   sign with.
3. **A bounded leaf cache** keyed by `(validated identity, CA generation)`. Bounded because
   the agent controls the SNI and could otherwise mint unbounded distinct hostnames — a
   memory-exhaustion vector. LRU, with a fixed maximum entry count and a TTL shorter than the
   leaf lifetime. Cache misses cost 152 µs, so eviction is cheap; unbounded growth is not.

Leaf lifetime is short (hours) and clock-skew tolerant (`NotBefore` backdated). Leaves are
regenerated on CA rotation, which is what the `CA generation` component of the cache key is
for (S5 owns rotation).

#### 3.2 ALPN and protocol selection

Aksh advertises **`h2` and `http/1.1`**, in that order, and lets the agent choose.

The measured spike confirms that end-to-end HTTP/2 through the MITM works with stock library
code, and that an h2-capable client downgrades cleanly when offered only `http/1.1`.
Precisely, the spike exercised **h2→h2 and h1.1→h2**; it did not exercise h2→h1.1, gRPC, or a
broad client matrix, and this document does not claim it did. Those remain S7 work
(OQ-S1-05).

Offering only `http/1.1` would therefore be *safe for the ordinary HTTP clients tested* — but
not for gRPC, which requires h2 end to end. Since MCP and agent-to-agent traffic may be gRPC
(OQ-S0-03), restricting to h1.1 would silently break those flows.

Downstream and upstream protocols are negotiated **independently**. Translation between them
is handled by the standard library (§6) and was demonstrated in the spike.

`ServerName` is captured in the `GetCertificate` callback, which fires after the ClientHello
and before the certificate is sent — the only point where SNI is available. Note that
`http.Server` clones its `TLSConfig` when serving begins, so ALPN cannot be varied per
connection after startup; any per-destination protocol decision must be made when the config
is built.

#### 3.3 TLS parameters

TLS 1.2 minimum downstream and upstream; 1.3 preferred. Cipher suites are the Go defaults,
which are maintained against current guidance — pinning our own list would rot. Client
certificates are not requested downstream (the agent has no identity to present that we would
trust) and are not presented upstream in the MVP; mutual TLS to upstreams is a v1 concern.

### 4. Establishing the validated identity

This section implements INV-8 and is the security core of S1. Order matters.

```
1. accept()                                   → else close
2. recover original destination (§2.1)        → T1 on failure
3. reject if marked as Aksh's own (§2.2 B)    → T2 (alerting; misconfiguration)
3b. PROTOCOL DISCRIMINATOR — peek the first bytes without consuming them:
     TLS record (0x16 ...)        -> the TLS branch below
     an HTTP/1.x method token     -> the PLAINTEXT branch of §6.1
     the HTTP/2 client preface    -> T5 (h2c unsupported; see S7 B54)
     anything else                -> T5
   This step is why §4's sequence no longer reads as TLS-only. Without it a literal
   implementation would start a handshake on every connection and reject plaintext
   before §6.1 could run.

4. TLS handshake (TLS branch only):
     GetConfigForClient(hello) fires FIRST and is the SNI capture point.
       - it sees the CURRENT ClientHello on every full handshake
       - candidate SNI := hello.ServerName; canonicalise to an IDNA A-label,
         lowercase, strip trailing dot
       - no SNI, or SNI is an IP literal, or SNI fails canonicalisation → T3
       - build the per-connection config: ALPN, and the leaf from
         LeafSource.Get(candidateSNI)                       ← minted DURING the handshake
     handshake failure                                      → T4
     no supported ALPN                                      → T5
5. after handshake, re-read tls.ConnectionState.ServerName and ALPN and assert they
   equal what step 4 captured. TLS 1.3 PSK resumption does NOT invoke
   GetConfigForClient, so resumption is DISABLED (session tickets off) rather than
   trusted — a resumed connection would otherwise carry a previously-validated
   identity forward, contradicting INV-8 rule 7. The cost is one full handshake per
   connection, which §3.1 already made cheap.
6. per request / per HTTP-2 stream:
     a. parse request
     b. split Host or :authority into host + optional port
     c. hand to the enforcement pipeline (S4): candidate SNI, the parsed authority host
        and port, and the recovered destination.
        S4 stage ① performs the comparisons (c/d below) and, on mismatch, produces an
        AUDITED denial. S1 does not reject T6 itself: an authority/SNI mismatch is an
        authorisation outcome, and INV-6 requires those to be recorded — a rejection here
        would never become a Decision and so would never be audited, losing exactly the
        confused-deputy attempt most worth alerting on.
          · host must equal the canonical candidate SNI                      → else T6
          · port, if present, must equal the recovered destination port      → else T6
     d. VALIDATED IDENTITY := the canonical A-label form (never the raw bytes),
        established by S4 ① and used thereafter
```

Note the ordering correction: the leaf certificate is required *during* the handshake, so it
cannot be fetched after it. `GetConfigForClient` rather than `GetCertificate` is the capture
point because it also lets ALPN and other per-connection config depend on the ClientHello.

Step 6 runs **per request**, not per connection (INV-8 rule 7). HTTP/2 multiplexes many
requests over one connection, and an agent can open a connection with an allowed SNI and then
send streams carrying different `:authority` values — step 6(c) is what rejects exactly that.
Connections are also long-lived, so evaluating once at handshake time would let the first
request's authorisation carry the rest.

The port comparison in (d) is what makes non-default ports work correctly: SNI carries no
port, so comparing the raw `Host` string against SNI would reject legitimate
`example.com:8443`. Comparing the *authority's* port against the *recovered destination's*
port instead binds the agent's claim to the kernel's fact.

**Canonical representation.** The validated identity is stored and used in exactly one form —
lowercase IDNA A-label — by the leaf cache key, the policy match key (S2), the credential
lookup (S3), the upstream verification name, and the outbound `Host`/`:authority`. The
outbound request target is **synthesised** from the canonical identity and the parsed path
rather than passed through, so S2 can never authorise one representation while the upstream
receives another. S2 must define path matching against the same representation Aksh forwards
(§6 step 3).

### 5. Upstream transport

#### 5.1 Where to connect

Aksh dials the **recovered destination**, not a fresh DNS resolution of the SNI. Re-resolving
would introduce a TOCTOU window and would double-resolve every request. The recovered
destination is kernel-attested; the identity is verified separately by §5.2, so a mismatched
pair fails at TLS rather than being trusted.

#### 5.2 Verification

The upstream certificate is verified against the **system root store** and against the
**validated identity** — not the SNI as supplied, not the destination IP. This is the step
that closes the confused-deputy hole in INV-8 rule 4: an agent that points an allowed
hostname at an attacker's IP gets a verification failure, not a credential delivered to the
attacker.

`InsecureSkipVerify` is never set. The PoC's `AKSH_INSECURE_UPSTREAM` existed only for its
self-signed echo server and is deleted; S7's e2e harness must instead give its test upstream
a certificate Aksh's trust store accepts.

#### 5.3 Connection pooling

Upstream connections are pooled and reused. A single shared `http.Transport` is **not**
sufficient: it pools by its own internal key and may reuse a connection without ever
consulting a custom dialer, which would silently defeat the partition below.

The design is therefore a **bounded manager of immutable transports**, one per key:

```
(validated identity, recovered destination, resolved credential identity | no-auth sentinel,
 trust-config generation, negotiated protocol policy)
```

Including the **credential identity** is a correctness requirement, not an optimisation: a
pooled connection carrying requests authorised under one credential must never be reused for
another. The **trust-config generation** is included so CA or trust-store rotation retires old
connections rather than leaving them alive with stale verification.

The manager itself is **bounded and LRU**, with transports closed on eviction. Bounding
connections alone is insufficient, because the agent chooses the identity and therefore
chooses the *keys* — an unbounded manager is a memory-exhaustion vector via key cardinality
rather than connection count.

#### 5.4 Timeouts

Every phase is bounded. A hostile agent's cheapest attack is to open connections and never
finish them.

| Phase | Default | Why |
| ----- | ------- | --- |
| Downstream TLS handshake | 10 s | Bounds slow-handshake attacks |
| Request header read | 10 s | Bounds Slowloris |
| Upstream connect | 5 s | Fail fast to a dead upstream |
| Upstream TLS handshake | 10 s | |
| Upstream response header | 30 s | Some APIs are genuinely slow |
| Idle (both sides) | 90 s | Reclaims pooled connections |
| **Per-stream progress deadline** | 60 s without progress | See below — this, not the idle timeout, is what bounds an active stream |
| Total request | none by default | Streaming and long-poll responses are legitimate; bounded by progress deadlines and body limits instead |

There is deliberately **no** default total-request cap: capping it would break legitimate
streaming (LLM token streams are the obvious case).

But the idle timeout is **not** sufficient on its own, and assuming it is would leave the
worst exhaustion case open. Go's server `IdleTimeout` measures the gap *between* requests, and
a transport's idle timeout applies only to *pooled, idle* connections. Neither bounds a
request body that is trickling, nor a response body that stalls after headers. A hostile agent
paired with a hostile upstream can hold a connection, an HTTP/2 stream slot, and a pool entry
open indefinitely while remaining technically "active".

The bound is therefore a **progress deadline per stream**: if no bytes move in either
direction for the configured window, the stream is cancelled. Cancellation is per-stream and
must not tear down the shared HTTP/2 connection carrying other streams. Together with the byte
cap in §7 this closes OQ-S0-13 for both size and duration; the idle timeout remains only as a
pool-reclamation mechanism.

### 6. HTTP handling

The relay is built on **`net/http/httputil.ReverseProxy`**, not the PoC's
`http.ReadRequest` + `io.Copy` (ADR-S1-02). The PoC's approach re-implements, badly, things
the standard library already gets right: hop-by-hop header removal, HTTP/2 translation,
flush intervals for streaming, trailer handling, error propagation, and — critically —
request parsing hardened against smuggling. The spike demonstrated `ReverseProxy` performing
h1.1-downstream-to-h2-upstream translation transparently.

Header handling is owned by **S4's pipeline**, not by `Rewrite`, and the distinction matters:
`Rewrite` runs after the pipeline has already matched and audited, so sanitising there would
leave an agent-supplied credential visible to every stage. The actual sequence is:

- **before any stage** (S4 stage ⓪): strip credential and proxy-identity headers, and install
  the trailer filter;
- **at S4 stage ①**: set `Host`/`:authority` to the validated identity, which does not exist
  before then;
- **in `Rewrite`, immediately before `RoundTrip`** (S4 stage ⑦): inject the credential, and
  nothing else.

For reference, the operations are:

1. **Strip** `Authorization` and `Proxy-Authorization` unconditionally (INV-9), *before*
   anything else, so no path can forward an agent-supplied credential. Stripping covers
   **both `Header` and `Trailer`** — an `Authorization` trailer would otherwise sail past a
   header-only filter — and the `Connection` header is inspected so an agent cannot nominate
   a credential header as connection-scoped to alter its handling.
2. Strip hop-by-hop headers (`ReverseProxy` does this, but it is asserted in tests rather
   than assumed), **plus an explicit denylist of proxy-identity headers the agent must not be
   able to forge**: `X-Forwarded-*`, `X-Real-IP`, `Forwarded`, `Via`,
   `X-Forwarded-Client-Cert`, `X-Envoy-*`, and any `X-Aksh-*`. An allowed upstream may
   legitimately trust these from a proxy; the agent must not be able to author them.
3. Set `Host`/`:authority` to the validated identity, so what reaches the upstream is what
   policy matched, not what the agent wrote.
4. Inject the credential, if the pipeline supplied one (S4).

**Bodies stream; they are not buffered.** The MVP does not inspect request bodies (S0's FR12
boundary), but it does *carry* them, so streaming semantics must be preserved now.

**The FR12 seam is a pre-`RoundTrip` body gate, not a `Rewrite` wrapper.** This distinction is
load-bearing and easy to get wrong: `Rewrite` runs *after* S4 has authorised the request, and
the transport may send request headers — including the injected credential — before it ever
reads the body. A body wrapper installed there therefore cannot implement a fail-closed body
policy, because the credential has already left. S4 must instead own an explicit gate that
runs **before** audit and credential injection, and that may boundedly spool the body, decide,
and reconstruct the stream. In the MVP the gate is present and always passes through without
reading, so bodies stream exactly as described; enabling FR12 flips a stage on rather than
re-ordering the pipeline. Reserving it now is what makes the FR12 claim in the v1 table true.

**Not supported in the MVP**, each returning a defined rejection rather than a tunnel:

| Feature | Disposition |
| ------- | ----------- |
| `CONNECT` | Rejected (INV-8 rule 6). Honouring it would turn Aksh into an opaque TCP tunnel with no identity. |
| WebSocket / `Upgrade` | Rejected in MVP. Long-lived bidirectional frames cannot be evaluated per request, so allowing them would silently weaken enforcement. Recorded as OQ-S1-02 — this **will** be needed for MCP over WebSocket. |
| `Expect: 100-continue` | Handled by the standard library; asserted in tests. |
| Non-TLS plaintext on an intercepted port | **Supported, in a scoped and deliberately weaker form — see §6.1.** An earlier draft rejected it as architecturally unavoidable. Source analysis of kagent proved that wrong and fatal: plaintext in-cluster HTTP is normal kagent operation on every turn, so rejecting it would have made the MVP non-functional on its primary target. |

#### 6.1 Plaintext HTTP — required, and weaker by construction

**Why this exists.** An earlier draft rejected all non-TLS traffic, reasoning that without SNI
there is no identity. Analysis of kagent's source showed that would have broken the product on
its own target workload. kagent's controller constructs four in-cluster endpoints with a literal
`http://` scheme, and they are not user-configurable:

| Constructed at | Endpoint |
| -------------- | -------- |
| `manifest_builder.go:407` | `KAGENT_URL = http://<controller>.<ns>:8083` — injected into **every** agent pod |
| `compiler.go:94` | `http://<controller>.<ns>:8083/...` |
| `conversion.go:61` | A2A subagent — `http://<svc>.<ns>:<port><path>` |
| `conversion.go:78` | MCP server — `http://<name>.<ns>:<port>/mcp` |

An agent talks plaintext to its own controller on every turn. Refusing it would have severed
the agent from its session and task persistence, its MCP tools, and its subagents.

**The identity problem is real, and the answer is not "use the `Host` header".** In plaintext
the `Host` header *is* readable — that is the easy part. The hard part is that TLS was doing
something else for us: INV-8 rule 4 verifies the **upstream's certificate** against the
validated identity, which is what stops an agent pointing an allowed hostname at an attacker's
address. With no certificate there is nothing to verify against, so `Host` alone is an
agent-chosen string with no anchor.

**So the anchor becomes the Service registry — but a ClusterIP alone is not enough.** Review of
an earlier version of this section found a real hole: a **selectorless** Service with manually
authored `EndpointSlice`s can point at **arbitrary external IPs**, and an `ExternalName` Service
is a DNS alias. So "the destination is a ClusterIP" does *not* mean "the backend is in the
cluster", and a credential could have left the cluster in plaintext while this document claimed
external plaintext was refused. The resolution rules are correspondingly stricter:

```
1. destination is recovered as usual (§2.1)
2. it MUST resolve, by EXACT match, to a Service.spec.clusterIPs entry in the informer
   index. Note: an exact index, NOT a service-CIDR range check — Kubernetes 1.29 has no
   universally available ServiceCIDR API, and an inferred range would either silently
   pass everything or silently reject everything.
3. that Service MUST be:
     - not ExternalName          (a DNS alias to somewhere else)
     - not headless              (no ClusterIP to anchor on)
     - selector-backed, with at least one READY endpoint whose address is a Pod IP
       in this cluster            (this is the rule that closes the selectorless
                                   manual-EndpointSlice escape)
4. VALIDATED IDENTITY := <service>.<namespace>.<clusterDomain>
5. the Host header, if present, must resolve to the SAME Service -> else T6
6. policy matches on the validated identity, exactly as for TLS
```

The Service's **UID and generation** are bound into the decision, recorded in audit, and included
in S1 §5.3's pool key, so a Service deleted and recreated on the same ClusterIP — or mutated to
point elsewhere — cannot be silently inherited by a pooled connection or a cached decision.

**What this still does not give you, stated plainly.** There is no upstream authentication:
anything that can answer on that ClusterIP is trusted to be that Service. Rule 3 narrows *who
can arrange that* to someone able to mutate Services or EndpointSlices — which is a meaningful
privilege, not a trivial one — but it does not eliminate it. And the honest framing matters:
plaintext in a cluster is not something Aksh introduces, **but injecting a brokered bearer token
over it is**. That exposure is Aksh's, which is why §6.1's credential rule is an opt-in rather
than a default, and why the operator granting it should be the one who decides.

Two consequences for other documents: the audit record carries a closed-enum
`transport` field (`tls` | `plaintext`) so the two assurance levels are distinguishable
(S6), and **credential injection over plaintext requires the matching rule to have opted in**
via `allowPlaintext` (S2). A plaintext request that matches no opted-in rule is an **ordinary
audited denial** — never "forward without the credential", which would look like success while
silently dropping authorisation.

Resolving a ClusterIP needs read access to Services and EndpointSlices, a genuine privilege
increase over S5 §7's `akshpolicies`-only grant — recorded as OQ-S1-07.

### 7. Resource bounds

The S1 share of the resource-safety NFR. Every one of these is reachable by a hostile agent,
and every one is bounded and observable:

| Bound | Reason |
| ----- | ------ |
| Max concurrent downstream connections | Socket and memory exhaustion |
| Max concurrent HTTP/2 streams per connection | h2 multiplexing multiplies the above |
| Leaf cache entries (LRU) | Agent controls SNI, so controls cache keys |
| Upstream pool size, per key and total | Amplification against upstreams |
| Max request header size | Memory |
| Max response body size | Hostile upstream + hostile agent (OQ-S0-13). Enforced by a **byte-counting wrapper around the streamed body**, aborting the response past the limit — not by buffering, which §6 forbids. The limit is a backstop against an unbounded hostile stream, so it is set generously above realistic response sizes rather than as a content policy; setting it tightly would break the same legitimate streaming that §5.4 protects. |
| Handshake rate | 152 µs per miss is cheap but not free |

On exceeding a limit the connection is rejected, a metric increments, and the event is
recorded — never silently queued. Defaults are set with reference to the sidecar's memory
limit and are configurable per S0 §9.

### 8. Rejection taxonomy

S0's ADR-S0-13 makes HTTP-level denials uniform, and requires transport-level failures — which
cannot produce an HTTP response — to be enumerated separately. This is that enumeration.

| Class | Condition | Behaviour | Metric |
| ----- | --------- | --------- | ------ |
| **T1** | Original destination unrecoverable | Close immediately | `aksh_transport_reject_total{class="no_original_dst"}` |
| **T2** | Recovered destination is Aksh's own listener (§2.2 case B) | Close; **alerts** — indicates broken rules | `…{class="loop_guard"}` |
| **T3** | No SNI offered | TLS alert `unrecognized_name`, close | `…{class="no_sni"}` |
| **T4** | TLS handshake failure | TLS alert, close | `…{class="handshake"}` |
| **T5** | No supported ALPN, or non-TLS bytes | Close | `…{class="unsupported_protocol"}` |
| **T6** | Authority/SNI or port mismatch | Uniform HTTP denial. Decided by **S4 stage ①**, not here, so that it is audited — listed in this table only because it is the one member of the T-series that is an authorisation outcome rather than a transport rejection | `…{class="identity_mismatch"}` |
| **T8** | Plaintext to a destination that is **not** an exact ClusterIP match, or whose Service is `ExternalName`, headless, or lacks a ready in-cluster Pod endpoint | Close | `…{class="plaintext_unresolvable"}` |
| **T9** | Plaintext where the Service index is unavailable or stale beyond its bound | Close; **fail closed** | `…{class="plaintext_registry_unavailable"}` |
| **T7** | A resource bound exceeded | Close | `…{class="resource_limit", bound="<name>"}` — the `bound` label carries which of §7's limits fired, since an operator cannot act on "some limit was hit" |

T1–T5 and T7 are distinguishable from each other by an observer, which is an accepted coarse
oracle (ADR-S0-13). T6 is deliberately *not* distinguishable from a policy denial, because it
is an authorisation outcome and would otherwise leak policy contents.

**Wire behaviour is phase- and protocol-specific**, and "close the connection" is not always
available or correct. Enumerated so S4 records the right disposition and S7 can assert it:

| Condition | HTTP/1.1 | HTTP/2 | Disposition recorded |
| --------- | -------- | ------ | -------------------- |
| Oversized request headers | `431`, then close | `RST_STREAM(ENHANCE_YOUR_CALM)` | rejected, pre-decision |
| Too many concurrent streams | n/a | refused via `SETTINGS`; excess streams reset | rejected, pre-decision |
| Malformed request / parser failure | `400`, close | `RST_STREAM(PROTOCOL_ERROR)` | rejected, pre-decision |
| Connection or handshake-rate limit | close | close | rejected, pre-decision |
| Response body cap or progress deadline hit **after** an allow | truncate + close | `RST_STREAM(CANCEL)` | **completion failure, not a denial** — the request *was* authorised and audited; the transfer failed |

The last row matters: a post-allow truncation must not be recorded as a denial, or the audit
trail will misrepresent what was authorised. S6 needs both dispositions.

---

## Interfaces

```go
// DestinationResolver recovers the pre-NAT destination of an intercepted connection.
// Implementations are platform-specific; there is no portable fallback, and callers
// must treat failure as fatal to the connection rather than substituting a guess.
type DestinationResolver interface {
    OriginalDestination(conn *net.TCPConn) (netip.AddrPort, error)
}

// LeafSource supplies the certificate presented to the agent. It is called DURING
// the TLS handshake (from GetConfigForClient), so it takes the *candidate* SNI —
// canonicalised but not yet cross-checked against the request authority, which has
// not been read at that point. Validation against the authority happens later
// (§4 step 6); this contract must not be misread as receiving a validated identity.
// Implementations are expected to cache and MUST bound that cache: the agent
// chooses the SNI, and therefore chooses the keys.
type LeafSource interface {
    Get(candidateSNI string) (*tls.Certificate, error)
}

// UpstreamDialer establishes a verified TLS connection to the true destination.
// Verification is against the system roots AND the validated identity — never the
// destination address, and never skipped.
type UpstreamDialer interface {
    Dial(ctx context.Context, dst netip.AddrPort, identity string, alpn []string) (net.Conn, error)
}
```

S1 hands the enforcement pipeline the candidate SNI, the parsed authority host and port, the
canonical request target, the method, and the recovered destination — §4 step 6(c). S4 stage ①
performs the identity comparison and builds the `RequestFacts` (defined in S2) that S2 matches
against.

`CAProvider` (S5) supplies the signing material `LeafSource` uses; `LeafSource` keys its cache
by the CA generation that provider reports, so rotation invalidates cleanly.

---

## Failure modes

| Failure | Behaviour | Class |
| ------- | --------- | ----- |
| `ip6tables` unavailable on a dual-stack pod | `aksh-init` fails; pod does not start | fail-closed by construction (§1.4) |
| Wrong iptables backend selected | Rules silently ineffective — **the most dangerous failure in this document** | Detected in production by `aksh-init`'s pre-flight probe (§1.3), which fails the pod; S7 verifies the detector itself works |
| Original destination unrecoverable | Connection closed | T1 |
| Agent dials the pod's own routable IP | Intercepted, then denied for lack of a validated identity | ordinary denial (§2.2 case A) |
| Loop guard triggers (Aksh's own listener) | Connection closed **and alerted** — rules are wrong | T2 |
| Agent offers no SNI | Connection closed | T3 |
| Upstream certificate fails verification | **Completion failure**, not a denial — it occurs after S4 stage ⑥ has committed the allow record, and rewriting that record would make the audit trail describe something that did not happen (S4 §1.0). Never downgraded to a successful connection. | — |
| Upstream unreachable | **Completion failure** (same reasoning) | — |
| Leaf cache full | LRU eviction; 152 µs re-mint | not a failure |
| Resource bound hit | Connection rejected, metric incremented | T7 |

---

## Decisions (ADRs)

### ADR-S1-01 — Shared-key ECDSA leaves with a bounded cache
*Context.* The PoC mints an RSA-2048 leaf per connection.
*Evidence.* Measured: 198 ms per connection, versus 152 µs for a shared-key ECDSA sign and a
map lookup on a cache hit.
*Decision.* One long-lived ECDSA P-256 leaf key reused across all leaves; certificates minted
per identity; bounded LRU cache keyed by `(identity, CA generation)`.
*Consequences.* Removes ~198 ms and a CPU-exhaustion vector from the connection path. The
shared leaf key becomes a single sensitive object — it is not the CA key, and compromise
allows impersonation only for the lifetime of the issued leaves. The cache bound is a security
control, not a tuning knob, because the agent chooses the keys.

### ADR-S1-02 — Build on `httputil.ReverseProxy`
*Context.* The PoC hand-rolls `http.ReadRequest` + `io.Copy`.
*Decision.* Use `httputil.ReverseProxy` with a custom `Rewrite` and `Transport`.
*Consequences.* Inherits hardened request parsing, hop-by-hop handling, h1/h2 translation,
streaming flush behaviour, and trailer support — all things ADR-S0-01 warned we would
otherwise own ourselves. Cost: less control over exact framing, and we must assert the
behaviours we depend on in tests rather than trusting them silently.

### ADR-S1-03 — Program IPv6 equivalently, or refuse to start
*Context.* INV-3 requires interception across address families; the PoC is IPv4-only.
*Options.* Ignore IPv6 (a bypass); block IPv6 outright; intercept it equivalently.
*Decision.* Intercept equivalently. If the pod has IPv6 addresses and `ip6tables` is
unavailable, `aksh-init` fails and the pod does not start.

The IPv6 rules are a direct translation with `::1/128` replacing `127.0.0.0/8`, **except that
`! -p tcp -j REJECT` must not be translated literally.** IPv6 depends on ICMPv6 for basic
operation — Neighbor Solicitation and Advertisement in particular — so a blanket non-TCP
reject breaks address resolution. The symptom is nastily delayed: IPv6 works while cached
neighbour state is valid and fails later. The guard therefore carves out the required ICMPv6
control types (neighbour discovery, `packet-too-big` for PMTU) and rejects the rest. This is a
**second named exception to INV-3**, narrower than DEV-01: it admits no user data path, only
link-layer control, and is recorded here rather than left implicit.

Listeners bind `tcp4` and `tcp6` **separately** rather than relying on a dual-stack socket,
because IPv4-mapped addresses on a v6 socket make it ambiguous which `getsockopt` level to
use for destination recovery (§2.1). Separate listeners make the address family unambiguous.

*Consequences.* Closes OQ-S0-11. Costs a hard dependency on `ip6tables` in dual-stack
clusters, which is preferable to running with half the address space unprotected.

### ADR-S1-05 — Support in-cluster plaintext HTTP, anchored on the recovered destination
*Context.* The draft rejected all non-TLS traffic. kagent's controller constructs four
`http://` in-cluster endpoints that every agent uses on every turn (§6.1), so rejection would
have made the MVP non-functional on its primary target.
*Options.* (A) Reject plaintext — breaks kagent. (B) Exclude the service CIDR from interception
— restores function but blows an unaudited hole through the middle of the control. (C) Intercept
plaintext, deriving identity from the kernel-attested destination resolved through the Service
registry, with `Host` checked against it.
*Decision.* **(C)**, restricted to in-cluster destinations.
*Consequences.* kagent works, and the traffic is still matched, audited and policy-controlled —
which (B) would have surrendered entirely. The assurance is genuinely lower: no upstream
authentication, so anything answering on that ClusterIP is trusted to be that Service. Review
tightened this twice over: the anchor is an **exact ClusterIP index**, not a service-CIDR range
(1.29 has no universally available ServiceCIDR API, and an inferred range fails silently in
either direction); and the Service must be selector-backed with a ready in-cluster Pod endpoint,
because a selectorless Service with manual `EndpointSlice`s can point at arbitrary external IPs —
which would have let a credential leave the cluster in plaintext while this document claimed
otherwise. Costs a Services and EndpointSlices read grant (OQ-S1-07). Plaintext is **not** an
INV-3 exception: it is intercepted, parsed, matched and audited like any other traffic, so no
new deviation is required.

### ADR-S1-04 — Reject rather than tunnel
*Context.* `CONNECT`, WebSocket upgrades, non-TLS traffic, and unknown ALPN all have an
"accept and pass bytes through" option.
*Decision.* `CONNECT`, upgrades, and unknown ALPN are rejected. Aksh never degrades into an
opaque tunnel. (Plaintext HTTP was later carved out of this by ADR-S1-05 — it is not a tunnel:
it is fully parsed, matched and audited.)
*Consequences.* Enforcement cannot be silently weakened by protocol choice (INV-8 rule 6).
Costs real functionality: WebSocket-based MCP transports will not work until OQ-S1-02 is
resolved, and S7 must list this as a known limitation rather than a defect.

---

## v1 forward-compatibility

| v1 need | Seam in S1 | Why additive |
| ------- | ---------- | ------------ |
| **Ingress** | A second chain (`AKSH_INBOUND` → a second listener port) and a second `ReverseProxy` instance | Egress chains, the listener, and all three interfaces are untouched; ingress adds rules and an instance. |
| **FR12** body inspection | The **pre-`RoundTrip` body gate** owned by S4 (§6) | The gate exists in MVP as an always-pass-through stage placed before audit and credential injection. Enabling inspection turns the stage on; it does not re-order the pipeline or change body ownership. A `Rewrite`-based wrapper would *not* have been additive, because it runs after authorisation. |
| **FR14** response redaction | `ResponseStage` (S4) attaches to `ReverseProxy.ModifyResponse` | Reserved and pass-through in MVP; a defined hook, not a new architecture. |
| **FR15** eBPF / CNI capture | `DestinationResolver` | **This row is now history, and the seam is proven.** eBPF capture is no longer forward-compatibility work: it is delivered in Phase 5A by S1a, which replaces iptables entirely as the sole capture backend. The seam held exactly as designed - `DestinationResolver` kept its signature and nothing above it changed, only the implementation behind it (`SO_ORIGINAL_DST` -> a BPF map lookup). The row now covers any *further* capture backend, for example an Istio-CNI variant. This was S0's "capture-backend seam". |
| **WebSocket / MCP-over-WS** | ADR-S1-04's rejection is a *decision*, not an assumption | Lifting it adds an upgrade path; no existing contract changes. |

---

## Open questions

| ID | Question | Closed by |
| -- | -------- | --------- |
| **OQ-S1-01** | What are the actual default values for every bound in §7? They must be derived from the sidecar's memory and CPU limits, which S5 sets — so the two must be decided together. | S5 |
| **OQ-S1-02** | ~~Does kagent need WebSocket?~~ — **closed by source analysis: no.** `RemoteMCPServerProtocol` admits only `SSE` and `STREAMABLE_HTTP` (`remotemcpserver_types.go:35-36`), A2A is JSONRPC-only, and kagent's runtime imports no WebSocket client. *Residual:* `websockets` is present transitively (google-adk, google-genai, kubernetes, uvicorn), so a library could open one on its own — a watch item for S7, not a declared transport. | *closed by evidence* |
| **OQ-S1-03** | ~~Is the metrics/health listener reachable by the agent?~~ — **closed by S6 §5 / ADR-S6-04.** Two rules, not one: a `nat` exclusion for pod-local port 15020 *before* the catch-all (or the port is rewritten before any filter rule sees it), then a `filter` reject with an owner-match. Carried in S1 §1's canonical rule set. | *closed in S6* |
| **OQ-S1-04** | How does `aksh-init` detect the node's iptables backend (`legacy` vs `nft`)? Choosing wrong yields rules that appear installed and do nothing — the failure mode with the worst blast radius here. | S5 |
| **OQ-S1-05** | What is the P95/P99 latency budget for the S1 hop specifically, now that certificate minting is off the request path? S0's NFR matrix assigns the per-hop budget to S1 and the harness to S7, so both must sign it off. Also covers the untested protocol matrix (h2→h1.1, gRPC, non-Go clients, ECDSA/FIPS compatibility). | **S1 + S7** |
| **OQ-S1-06** | ~~Are plaintext destinations needed?~~ — **closed by source analysis: yes, unavoidably.** kagent's controller builds four `http://` in-cluster endpoints used on every turn. Rejecting plaintext would have made the MVP non-functional on its primary target. Resolved by ADR-S1-05 and §6.1. | *closed by evidence* |
| **OQ-S1-07** | §6.1 needs read access to **Services and EndpointSlices** — a privilege increase over S5 §7's `akshpolicies`-only grant, and one that lets a compromised sidecar enumerate the cluster's services and their backends. Can it be namespace-scoped, given an agent may legitimately call a Service in another namespace? What is the index's staleness bound, and does it reuse S2 §7's `maxStaleness` or need its own? | S5 |
| **OQ-S1-08** | What is the cluster domain (`cluster.local` is conventional, not guaranteed)? §6.1 builds the validated identity from it, so a wrong value makes every plaintext policy fail to match. Configured, or discovered? | S5 |
