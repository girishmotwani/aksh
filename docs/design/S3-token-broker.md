# S3 — Token Broker & Credential Custody

> **Status:** Reviewed · **Depends on:** S0, S2 · **Depended on by:** S1 (pool key), S4 (acquisition step), S6 (audit fields), S7 (credential-theft testing)

How Aksh obtains, caches, refreshes and protects credentials the agent must never see.

---

## Scope

**Decides:** how a `CredentialSelector` (S2) becomes a concrete token; the provider
abstraction; what Aksh itself authenticates with; the cache key, refresh policy, and failure
behaviour; how credential material is protected in memory and kept out of every output; and
the identity S1 and S6 need to key on.

**Does not decide:** which requests get a credential (S2), when acquisition happens relative
to audit (S4), or the audit record's shape (S6).

## Requirements covered

**FR3** (tokens outside the agent runtime), **FR4** (acquire, refresh, rotate, cache, expire),
the token half of **FR8** (fail closed on acquisition failure), and S3's share of the
**resource-safety** and **availability** NFRs. Implements **INV-1** (both halves) and
**INV-5** (no secret material in output).

---

## Design

### 1. What Aksh authenticates as

ADR-S0-06 requires **Workload Identity Federation** and explicitly rejects a mounted client
secret. This section makes that decision concrete.

The chain has three links:

```
Kubernetes projected SA token  ──►  Entra federated credential  ──►  access token
   (short-lived, audience-        (exchanged; no secret            (per resource+scopes,
    scoped, file-mounted)          stored anywhere)                 cached, injected)
```

1. The kubelet projects a **ServiceAccount token** into `aksh-proxy` only (INV-10), with an
   explicit `audience` matching the Entra federated-credential configuration — **not** the
   default API-server audience. A default-audience token is a cluster credential; feeding it
   into an external IdP flow widens what a leak costs.
2. Aksh exchanges it for an Entra token. Nothing long-lived is stored on disk or in the
   environment at any point.
3. The result is cached (§4) and injected by S4.

**The projected token is a file, and files change.** The kubelet rotates it well before
expiry. Aksh therefore **re-reads the file on every exchange** rather than caching its
contents. Reading a rotated-away token is the single most likely cause of a mysterious
authentication failure hours after startup, and it is entirely avoidable.

#### 1.1 Provider configuration is explicit; credential chains are forbidden

ADR-S0-06 rejects the client-secret fallback. That rejection is only enforceable if the
provider cannot silently find a credential some other way — and the convenient SDK entry points
(`DefaultAzureCredential` and its equivalents) do exactly that, walking a chain that includes
environment client secrets and managed identity. Using one would quietly reinstate the rejected
option, and it would fail *open* in the worst sense: everything would appear to work.

The Entra provider is therefore configured **explicitly and completely**, with no chain and no
discovery:

| Setting | Source | Notes |
| ------- | ------ | ----- |
| `tenantId` | config | required |
| `clientId` | config | the app registration holding the federated credential |
| `authorityHost` | config, default `https://login.microsoftonline.com` | must be HTTPS |
| `saTokenPath` | projected volume path | S5 sets it; `aksh-proxy` only |
| `saTokenAudience` | config | must match the federated credential's configured audience |

Rules: **startup fails** if any required setting is absent — an incomplete identity
configuration must never degrade into a working-but-different one. The provider constructs the
client-credentials-with-assertion request itself; it uses **no** ambient credential source, no
environment variables other than those above, and no IMDS. The token endpoint is contacted over
verified HTTPS, and redirects to a different authority are rejected.

Two RBAC constraints belong to S5 but are stated here because they are *this* document's
security properties:

- The **agent's** ServiceAccount must not hold `create` on `serviceaccounts/token` for the
  Entra audience. If it does, the agent mints the federation token itself and brokers its own
  credentials — Aksh becomes decorative.
- `aksh-proxy`'s own RBAC is read-only on `AkshPolicy` and nothing else.

### 2. Resolving a `CredentialSelector`

S2's selector is provider-neutral by construction. S3 is where it acquires meaning, and the
mapping must be exact or S1's pool key, S3's cache key and S6's audit field will disagree
about what "the same credential" means.

#### 2.1 Canonicalisation

| Field | Canonical form |
| ----- | -------------- |
| `provider` | lowercase; empty ⇒ `entra` |
| `resource` | URI-normalised: lowercase scheme and host, default port removed, **trailing slash removed**, path otherwise preserved |
| `scopes` | de-duplicated, then **sorted**; empty rejected at admission (S2) |

Sorting is not cosmetic. `[a, b]` and `[b, a]` request the same thing, and without a canonical
order they would occupy two cache entries, produce two upstream token requests, and appear as
two different credentials in the audit trail.

#### 2.2 The Entra mapping

For `provider: entra`, the OAuth 2.0 scope list sent to the token endpoint joins each entry in
`scopes` to `resource`:

```
resource = https://graph.microsoft.com
scopes   = [".default"]
          →  scope = "https://graph.microsoft.com/.default"
```

An entry that is already an absolute URI is used as-is; a relative entry is appended to
`resource` with exactly one `/` between them. This is precisely the string S2 refused to let
operators write directly, reconstructed here where provider semantics legitimately live.

**The split is not canonical, and the identity is computed after composition.**
`(resource=https://a.com/b, scopes=[c])` and `(resource=https://a.com, scopes=[b/c])` compose
to the *same* wire scope `https://a.com/b/c`, so hashing the pre-composition fields would give
two identities for one credential — the same fragmentation §2.1 fixed for scope *ordering*,
reintroduced one level up. `credentialIdentity` is therefore computed over the **composed,
sorted wire scopes**, not the raw `resource`/`scopes` pair.

**`resource` is not guaranteed to be a URI.** Some Entra resources are bare GUIDs. "Does not
parse as a URI" is not a portable test — most libraries happily parse a GUID as a *relative*
URI — so the rule is stated positively instead:

> If `resource` parses as an **absolute** URI (has a scheme **and** a host), apply the URI
> normalisation of §2.1. Otherwise treat it as an opaque token and only lowercase it.

Lowercasing the opaque form is what stops the same GUID in different cases fragmenting the
cache. Composed scopes are additionally validated against the OAuth `scope` grammar —
no spaces, no control characters — and rejected if they fail, since a scope containing a space
would silently become two scopes on the wire.

#### 2.3 Credential identity

```
credentialIdentity := SHA-256( provider ∥ resource ∥ sorted-scopes )   [domain-separated]
```

This one value is used in three places that must agree: **S3's cache key**, **S1's upstream
pool key**, and **S6's audit record**. Defining it once here is what stops them drifting.

It hashes the *request*, not the token — so it is safe to log (INV-5), stable across restarts,
and identical across replicas.

**The no-credential case.** S2 makes `credential` optional: a rule may allow a destination with
no credential at all, and S1's pool key already anticipates a "no-auth sentinel". That sentinel
is defined **here**, since this section exists to stop S1, S3 and S6 inventing three answers:

```
credentialIdentity := "none"    when the matched rule names no credential
```

The literal string `none` is provably distinct from any value of the hash construction below,
which is fixed-length lowercase hex — so the two can never collide, and no escaping is needed.

**Encoding, specified exactly** so three independent implementations agree:

```
credentialIdentity = lowerhex( SHA-256(
      LP("aksh-cred-v1") ∥ LP(provider) ∥ LP(n) ∥ LP(w[0]) ∥ ... ∥ LP(w[n-1]) ) )

  LP(x) = uint32-big-endian(byteLength(x)) ∥ UTF-8 bytes of x
  w[]   = the COMPOSED wire scopes of §2.2, de-duplicated, sorted BYTEWISE ascending
  n     = len(w), encoded as its decimal ASCII representation
```

Every detail here is load-bearing, because "three implementations agree" is the entire point:

- **Length-prefixed, not NUL-separated.** An earlier draft used NUL separators. S2 constrains
  only the *length* of `resource` and `scopes`, not their charset, so a scope containing a NUL
  byte would encode identically to two separate scopes — a collision an attacker with policy
  authorship could construct deliberately. Length prefixing is unambiguous for any byte string.
- **The count `n` is included**, so a list cannot be confused with a differently-split list.
- **Bytewise sort**, not locale- or rune-aware collation, which differs between languages.
- **UTF-8**, stated explicitly.
- **Composed wire scopes only.** `provider` is included; `resource` is **not** included
  separately, because it is already folded into every composed scope. Including it as well
  would be harmless but is omitted so that the formula has exactly one source of truth.
- **Lowercase hex** output, safe simultaneously as a map key, a Prometheus label and a logged
  field.
- **`aksh-cred-v1`** is both the domain separator and the version. Any change to this
  derivation — including adding `issuer`/`subject` — bumps it.

S7 owns **golden vectors** for this function. It is consumed by three components and a
disagreement between them is silent, so it is exactly the kind of thing that needs fixtures
rather than prose.

**When `issuer` and `subject` arrive** (ADR-S2-06), they must be **added to this derivation**.
This is not automatic — the formula names its fields explicitly. Omitting them would collapse
different subjects onto one cache entry and let one subject's token serve another's request,
which for on-behalf-of delegation is precisely the bug that matters.

S6 additionally records `provider` and `resource` in clear, because an operator cannot act on a
hash.

**`credentialIdentity` is deliberately pod-invariant** — it hashes only the credential request,
so every replica of an agent produces the same value. ADR-S0-06 requires audit records to
attribute to the *pod* separately, since replicas share a ServiceAccount. S6's schema must
therefore carry a pod identifier of its own; `credentialIdentity` does not discharge that
obligation and must not be mistaken for doing so.

### 3. The provider abstraction

```go
// TokenProvider turns a canonicalised CredentialSelector into a token. This is the seam
// that makes FR10 (multi-IdP) additive: Entra is one implementation, selected by
// CredentialSelector.Provider, and a new IdP is a new implementation plus a new enum
// value in S2's schema — no caller changes.
type TokenProvider interface {
    // Resolve canonicalises a selector into this provider's wire form (§2.1-2.3).
    // It lives on the provider, not in shared code, because composition is
    // provider-specific: Entra's "resource + /.default" is not universal. Keeping it
    // here is what actually makes "a new IdP is a new implementation" true.
    Resolve(sel CredentialSelector) (ResolvedCredential, error)
    // Acquire returns a token. It MUST NOT cache: caching, refresh-ahead and
    // single-flight belong to TokenCache (§4), and duplicating them here would give two
    // layers with different opinions about freshness.
    Acquire(ctx context.Context, rc ResolvedCredential) (Token, error)
    // Provider reports the enum value this implementation serves.
    Provider() string
}

// ResolvedCredential is the canonical form S1, S3 and S6 share. Owning it here means
// nobody re-derives credentialIdentity independently and drifts.
type ResolvedCredential struct {
    Identity   string   // credentialIdentity (§2.3), or "none"
    Provider   string
    Resource   string   // canonical; for audit legibility only
    WireScopes []string // composed, de-duplicated, bytewise-sorted
}

// AcquireError classifies a failure. An untyped error would force TokenCache to guess,
// and the three classes have genuinely different handling (§5.1): only Transient feeds
// the breaker, only Permanent is negative-cached, and Local is neither — it is our own
// queue or cancellation and says nothing about the IdP's health.
type AcquireError struct {
    Class      AcquireErrorClass // Transient | Permanent | Local
    RetryAfter time.Duration     // honoured from a 429 when present
    err        error
}

// Token redacts at ITS OWN level, not merely at the wrapped secret's level. See §6 —
// this is not a stylistic choice; the obvious alternative provably leaks.
type Token struct {
    Value     secret // EXPORTED, deliberately — see §6
    ExpiresAt time.Time
}

// fmt.Formatter is REQUIRED, not just String/GoString: those cover only %s/%q/%v/%#v.
// A stray %d or %x on a Token would otherwise fall through to fmt's reflective path and
// can surface raw bytes in its type-error output. Formatter intercepts EVERY verb.
func (Token) Format(f fmt.State, verb rune) { io.WriteString(f, "Token{[REDACTED]}") }
func (Token) String() string                { return "Token{[REDACTED]}" }
func (Token) GoString() string              { return "Token{[REDACTED]}" }
func (Token) MarshalJSON() ([]byte, error)  { return []byte(`"[REDACTED]"`), nil }
func (Token) MarshalText() ([]byte, error)  { return []byte("[REDACTED]"), nil }

// secret carries the same full set, because Token.Value is exported and can be
// formatted on its own.
func (secret) Format(f fmt.State, verb rune) { io.WriteString(f, "[REDACTED]") }
func (secret) String() string                { return "[REDACTED]" }
func (secret) GoString() string              { return "[REDACTED]" }
func (secret) MarshalJSON() ([]byte, error)  { return []byte(`"[REDACTED]"`), nil }
func (secret) MarshalText() ([]byte, error)  { return []byte("[REDACTED]"), nil }

// Reveal is the ONLY way to obtain the plaintext. Two call sites exist in the whole
// codebase: header injection (S4) and the provider's own exchange. Named so that
// `grep -rn Reveal` is a complete audit of where plaintext can escape.
func (s secret) Reveal() string { return s.v }
```

Separating `TokenProvider` from `TokenCache` is the main structural decision here
(ADR-S3-01). Providers become thin and individually testable, and every provider inherits
identical freshness and failure semantics rather than re-implementing them — which is the
usual way two IdP integrations end up behaving differently under load.

### 4. Cache and refresh

```go
// TokenCache is the only component that decides whether a cached token is still good.
type TokenCache interface {
    // Get returns a usable token plus the metadata S6 must audit. Returning the metadata
    // here — rather than making S4 or S6 recompute it — is what keeps the audit record and
    // the cache honest about the same acquisition.
    Get(ctx context.Context, sel CredentialSelector) (TokenResult, error)
}

// TokenResult carries everything §9's audit contract needs.
type TokenResult struct {
    Token    Token
    Resolved ResolvedCredential
    CacheHit bool
}
```

**Key:** `credentialIdentity` (§2.3). Nothing else — not the destination, not the policy that
selected it. Two rules naming the same credential legitimately share a token.

**Refresh-ahead.** A token is refreshed before expiry, not on it. Refreshing on expiry
guarantees that some request pays the full acquisition latency, and guarantees a hard failure
whenever the IdP is briefly unavailable at exactly the wrong moment. Refresh-ahead converts
both into background work.

The window is:

```
refreshAhead = min( max(20% of lifetime, 5 minutes), 50% of lifetime )
```

The outer `min` is load-bearing and easy to omit. With only `max(20%, 5min)`, the 5-minute
floor dominates for any token shorter than 25 minutes, and at exactly a 5-minute lifetime the
**whole** token life sits inside the refresh window from the instant it is minted — every use
immediately re-qualifies for refresh, and the mechanism designed to avoid repeated refresh
becomes continuous refresh at a rate driven by request volume rather than expiry. Since
OQ-S3-02 leaves token lifetime open and short lifetimes are the lever on the revocation
window (§7), this is a configuration we may well choose. Capping the window at half the
lifetime keeps the behaviour sane at every lifetime.

**Refresh triggering is itself single-flighted**, per credential key — not just cache misses.
Otherwise every concurrent in-window *hit* spawns its own background refresh.

**Jitter.** The refresh point is jittered by ±10%. Without it, sidecars that started together
refresh together, and a large deployment becomes a synchronised thundering herd against Entra
— self-inflicted, and worst precisely when scale matters.

**Single-flight.** Concurrent misses for one key collapse into one in-flight acquisition; the
rest wait. An agent can trivially issue hundreds of concurrent requests, and without this each
becomes a token request.

**Clock skew.** Expiry is evaluated with a 60-second safety margin against the local clock.
Aksh does not trust its own clock to be closely synchronised, and a token believed valid 30
seconds longer than it is produces a confusing upstream 401 rather than a clean refresh.

**Usable lifetime.** All freshness arithmetic uses `usableUntil = ExpiresAt − 60s` (the skew
margin), never `ExpiresAt`. Two consequences must be stated or short tokens break:

- A token whose remaining life is already **≤ 60 s on arrival is unusable**. A successful
  acquisition returning an unusable token is treated as **one classified failure** — it feeds
  backoff and is reported — rather than being discarded and immediately retried, which would
  be an infinite acquisition loop driven by a misconfigured IdP lifetime.
- Jitter is sampled **once per acquisition**, against the usable lifetime, and stored. Sampling
  it per evaluation would make the refresh point jump around under concurrent reads.

**The `Get` state machine.** Ordering matters and an earlier draft had it wrong — it could deny
a request while holding a perfectly valid token, because the breaker was consulted before the
cache. The gates protect *acquisition*; they must never gate a token we already have.

```
Get(sel):
  1. id := credentialIdentity(sel)                       (§2.3)
  2. entry := cache[id]
  3. if entry exists and now < entry.usableUntil:
       a. if now >= entry.refreshAt: trigger a background refresh
          (single-flighted per id; subject to breaker + negative cache;
           its failure is logged and metered, never surfaced to this request)
       b. RETURN entry.token                             ← valid token ALWAYS wins
  4. no usable token, so acquisition is REQUIRED. Now the gates apply, in order:
       a. negative cache hit  → DENY (does not increment the breaker)
       b. breaker open        → DENY
       c. in-flight slot      → block up to the acquisition timeout, else DENY
       d. single-flight acquire; on failure write negative-cache/breaker state
          BEFORE releasing waiters; all waiters receive the same failure
  5. RETURN the acquired token, or DENY
```

Step 3 is what makes ADR-S3-02 true rather than aspirational: an IdP outage, an open breaker,
and a negative-cache entry are all invisible to a request that can be served from a valid
token. Denial begins only when the token is genuinely unusable — so the blast radius of an
Entra outage is bounded per-credential and deferred by up to a token lifetime, rather than
immediate and total.

The same rule governs the **projected SA token file**: it is read only on the acquisition path
(step 4), so a transient file problem cannot deny requests that a cached token can serve.

#### 4.1 Startup self-test

The failure table's "Entra unreachable at startup ⇒ not ready" needs a mechanism, or it is
indistinguishable from an ordinary first cache miss — which by the per-credential rule would
deny only that one credential, not affect readiness.

The self-test is deliberately **local-only**. It asserts, before reporting ready:

1. the provider configuration of §1.1 is complete;
2. the projected SA token file exists, is readable, and parses as a JWT whose `aud` matches
   `saTokenAudience` and which is not already expired;
3. the first policy snapshot has been built (S2 §7).

It does **not** contact Entra. That restraint is the important part, and an earlier draft got it
wrong by probing "the first credential named by a selecting policy". Three things were wrong
with that: "first" is undefined and arbitrary; a single malformed credential would have blocked
*every* credential, contradicting the per-credential blast radius this document is otherwise
careful about; and — worst — tying readiness to an **external** dependency means an Entra
outage fails the startup probe, Kubernetes restarts the sidecar, and the restart discards the
breaker and backoff state. Across a fleet that is a synchronised restart storm hammering an IdP
that is already unwell.

So: configuration and identity-material faults, which are deployment faults and genuinely local,
fail readiness. IdP availability, which is not local, is handled per-credential at request time
by §4's state machine and never touches readiness.

### 5. Failure behaviour

| Condition | Behaviour |
| --------- | --------- |
| Cache hit, valid | Serve |
| Cache hit, inside refresh-ahead window, refresh failing | **Serve** the still-valid token; increment a staleness metric |
| Cache miss, acquisition fails | **Deny** (INV-4, FR8) |
| Cache hit, expired, refresh fails | **Deny** — for that credential only |
| Projected SA token file missing or unreadable | **Deny**, and fail readiness — a deployment fault, not a request fault |
| Entra returns `invalid_scope` / `unauthorized_client` | **Deny**, do **not** retry — a configuration error retried in a loop is a self-inflicted outage. Negative-cache briefly (§5.1). |
| Entra returns 429 or 5xx | **Deny** this request; retry in the background with backoff |

Denial is per-credential, never global. An outage affecting one resource must not deny
requests to another.

#### 5.1 Backoff, negative caching, circuit breaking

Retries use exponential backoff with jitter and a ceiling. **Permanent** errors — malformed
scope, unknown client, revoked federation — are negative-cached briefly so a misconfigured
policy does not generate one token request per agent request. The negative cache is *short*
precisely because the fix is usually an operator changing configuration, and a long negative
cache would make the fix appear not to work.

After **5** consecutive *transient* failures for one credential the breaker opens: requests are
denied immediately without contacting the IdP, and a single probe is allowed every **30 s**.
This protects Entra from Aksh as much as Aksh from Entra — a fleet of sidecars retrying hard
against a struggling IdP is a denial-of-service attack the operator did not intend to launch.

The two mechanisms must be ordered precisely, or they mask each other:

1. **Negative cache is checked first.** A hit denies immediately and **does not** increment the
   breaker's counter — a permanently misconfigured credential should not trip a breaker whose
   purpose is protecting against *availability* failures.
2. **Breaker is checked second.** Only transient errors — timeouts, 429, 5xx — increment its
   counter. Permanent errors (`invalid_scope`, `unauthorized_client`) never do.
3. **On a failed single-flight acquisition, the negative-cache or breaker state is written
   before waiters are released.** Otherwise the released waiters immediately re-enter, miss the
   not-yet-written state, and launch a second full acquisition — turning one failure into a
   burst.

All waiters on a failed single-flight acquisition receive the same failure. They do not retry
individually: the acquisition that failed is the one they were waiting for, and retrying
per-waiter is how a single IdP blip becomes a stampede.

### 6. Protecting credential material

INV-1 covers both brokered tokens and Aksh's own federation credential; INV-5 forbids either
appearing in any output. Prose is not enough, so the type system does the work.

The realistic leak is not a deliberate `log.Print(token)` — it is a struct logged whole while
debugging, a request dumped with `httputil.DumpRequest`, or a panic that formats its
arguments. Redaction must therefore be a property of the type, not of reviewer attention.

> **The trap that must not be walked into.** The obvious design — an *unexported* field of a
> redacting `secret` type — **does not work, and was verified not to work.** Go's `fmt` cannot
> call `String()`/`GoString()` on a value reached through an unexported field
> (`reflect.Value.CanInterface()` is false), so it falls back to printing the raw bytes:
>
> ```go
> type Token struct { value secret; ExpiresAt time.Time }  // WRONG
> fmt.Printf("%v",  tok) // {{super-secret-token-ABC123} 2026-...}   ← LEAKS
> fmt.Printf("%+v", tok) // {value:{s:super-secret-token-ABC123} ...} ← LEAKS
> fmt.Printf("%#v", tok) // Token{value:secret{s:"super-..."}, ...}   ← LEAKS
> ```
>
> It leaks identically whether `Token` is a direct `Printf` argument, boxed in an
> `interface{}`, or held in a `map[string]any` — which is exactly the shape of a structured
> logging field set. It leaks for the *primary* named vector, "a struct logged whole".

Four rules, all required:

1. **Both `Token` and `secret` implement `fmt.Formatter`**, not merely `String`/`GoString`.
   Those two cover `%s %q %v %#v` and nothing else; a stray `%d` or `%x` falls through to
   `fmt`'s reflective path, which can surface raw bytes in its type-error output. `Formatter`
   intercepts every verb and flag combination.
2. **`Token.Value` is exported**, so a reflective formatter reaches a value it can call
   methods on — see the trap above.
3. **`Token` and `secret` must never be held in an *unexported* field of any other loggable
   struct** unless that struct also redacts. Not compiler-enforced; it recurs at every nesting
   level; stated as a hard constraint because nothing will warn about it.
4. **Redaction governs `fmt` and `encoding/json` only.** It does **not** govern `encoding/gob`,
   reflection-based struct mappers, or any binary encoder, none of which consult these methods.
   Those encoders are therefore **forbidden** on any type transitively containing a `secret`,
   and S7 asserts it.

#### 6.1 The materialisation boundary

Redaction protects the token while it is a `Token`. At two points it must become a plain
string, and no type can protect it there — so the boundary is made as small as possible:

- **Header injection (S4).** The plaintext is written directly into the outbound request's
  `Authorization` header **immediately before the transport round-trip**, on a request object
  that is not shared with anything else. No middleware, logging wrapper, tracing hook, or
  `httputil.DumpRequest` may run on the request *after* injection. This is why ADR-S3-03's
  claim is scoped to what it can actually deliver: type redaction catches dumps of the
  *pre-injection* request, and the ordering rule — not the type — is what protects the
  post-injection one.
- **The provider's exchange**, where the projected SA token becomes `client_assertion`. The
  same rule applies, and it applies to **both** secrets: S7's leak test must drive a known
  value through *each* of them, not only the access token.

`Reveal()` is the only accessor, so `grep -rn 'Reveal('` is a complete audit of both.

- The value is reachable only through an explicit accessor whose call sites are auditable, and
  which exists in exactly two places: header injection (S4) and the provider's own exchange.
- **Never** written to disk, an environment variable, a metric label, a span attribute, or an
  error message. Errors carry `credentialIdentity`, never the token.
- Request/response dumping helpers are forbidden anywhere a token may be present; S7 asserts
  this by driving a known test token through the proxy and grepping all output for it.
- Go cannot reliably zero memory (the GC may copy), so this document does **not** claim
  scrubbing. It claims the token is never *written out*. Overclaiming would be worse than
  admitting the limit. The residual risk is process-memory disclosure, and INV-10 covers only
  the `ptrace` vector of it. Two others are neither ptrace nor capability-gated, and are
  therefore requirements on this document rather than on INV-10:
  **no `net/http/pprof` or equivalent profiling endpoint is served by `aksh-proxy`** (a heap
  dump contains live tokens), and **core dumps are disabled** (`RLIMIT_CORE` 0), since an OOM
  or panic would otherwise write process memory to disk.

### 7. Rotation, expiry, revocation

- **Access tokens** expire naturally; refresh-ahead handles them.
- **The projected SA token** rotates under Aksh; re-reading per exchange (§1) handles it.
- **Revocation is the honest gap.** OAuth bearer tokens cannot be recalled once issued. If a
  policy is deleted, Aksh stops *injecting* immediately — the policy snapshot gates injection
  (S2) — but any token already sent upstream remains valid at the resource server until it
  expires. Shorter lifetimes narrow the window; nothing closes it.

  This bounds what "revoke access" means operationally, and S7 must state it rather than let
  operators infer that deleting a policy is instantaneous.

### 8. Bounds — S3's share of resource safety

| Bound | Value | Why |
| ----- | ----- | --- |
| Distinct cached credentials | **default 256, configurable to S2's 2048 rule ceiling**, LRU | The agent cannot choose credentials — only policy can — so the true ceiling is S2's per-agent rule bound of 2048. 256 is a memory-conscious default, **not** a claim that policy cannot exceed it: a legitimate policy naming more than 256 distinct credentials would thrash the LRU, re-acquiring continuously and defeating refresh-ahead — exactly the IdP load the breaker and jitter exist to prevent, and for legitimate traffic rather than an attack. The cache therefore emits an eviction-rate metric, and exceeding it sustainedly is an operator signal to raise the bound. |
| Concurrent in-flight acquisitions | **8** | Single-flight bounds per-key concurrency; this bounds it *across* keys, so a policy naming many credentials cannot fan out into an IdP flood. **Overflow blocks** until a slot frees or the acquisition timeout expires, then denies — it does not deny immediately, because a brief queue is preferable to a spurious denial under a burst. |
| Negative-cache entries | **256**, LRU, TTL **30 s** | Bounded like any other agent-reachable structure. |
| Breaker: consecutive failures to open | **5** | |
| Breaker: probe interval when open | **30 s** | |
| IdP request rate, per credential | token-bucket | Breaker plus bucket bounds sustained load. |
| Acquisition timeout | **10 s** | An acquisition slower than this has already blown the request budget. |
| Waiter queue for the in-flight limit | **bounded, 128**, FIFO; over-limit denies immediately | An unbounded waiter queue is just a slower unbounded resource. |
| IdP request rate, **per provider** (all credentials) | token bucket, **10/s sustained, burst 20** | The per-credential bucket does not bound aggregate load across 2048 possible rules. This does. |
| Breaker and negative-cache state entries | **256 each**, LRU | Otherwise the state tracking the abuse is itself unbounded. |

**Refreshes and breaker probes are scheduled ahead of first-acquisitions.** Without that
priority, a hostile agent generating misses across many distinct credentials can starve the
background refresh of a healthy, in-use token until it expires — turning a rate limit into an
outage. Local queue timeouts and rate-limit rejections are classified as **local** failures and
never increment the breaker, which exists to describe the IdP's health, not ours.

### 9. What S3 must emit

Contracts with S6, stated here so the two cannot drift.

**Audit fields** (per decision):

| Field | With a credential | No credential (S2 allows this) |
| ----- | ----------------- | ------------------------------ |
| `credentialIdentity` | hex digest (§2.3) | `"none"` |
| `provider` | e.g. `entra` | omitted |
| `resource` | canonical | omitted |
| `scopes` | composed wire scopes | omitted |
| `cacheHit` | true/false | omitted |
| `tokenExpiresAt` | RFC 3339 | omitted |

**Never** the token value (INV-5). Note that `credentialIdentity` is pod-invariant; S6 carries
pod identity separately (§2.3).

Field presence follows the *outcome*, not the rule: on an allow where acquisition failed there
is no `tokenExpiresAt` and `cacheHit` is false, so S6's schema must treat these as
outcome-conditional rather than always-present.

**Metrics:** acquisitions by result *and `AcquireError.Class`*, acquisition latency, cache hit
ratio, **cache eviction rate** (§8's thrashing signal), **refresh failures while serving a
still-valid token** (§4 step 3a — otherwise a silent degradation), tokens near expiry, breaker
state, negative-cache size, and waiter-queue depth. Labelled by `provider` and
`credentialIdentity`, and **never** by `resource` free-text, which is operator-controlled and
would be a cardinality hazard.

---

## Interfaces

Defined above: `TokenProvider` (§3), `TokenCache` (§4), `Token` (§3). `CredentialSelector` is
defined by S2 and consumed here; `credentialIdentity` (§2.3) is the shared key S1, S3 and S6
all use.

---

## Failure modes

| Failure | Behaviour | Blast radius |
| ------- | --------- | ------------ |
| Entra unreachable, cached token valid | Serve | none |
| Entra unreachable, token expired | Deny | one credential |
| Entra unreachable at startup | **Ready anyway** — the self-test is local-only (§4.1). Acquisition failures remain per-credential at request time; an external outage must never fail a startup probe, or Kubernetes restarts the sidecar and discards its breaker state across the fleet | one credential at a time |
| Provider configuration incomplete, or SA token unreadable/expired/wrong audience | Deny all; **not ready** | this pod — a genuinely local deployment fault (§1.1, §4.1) |
| SA token file missing | Requests servable from a **valid cached token still succeed** (§4 step 3); everything requiring acquisition denies, and readiness fails | this pod — deployment fault |
| Federated credential misconfigured | Deny, negative-cached; breaker **does not** open — permanent errors never increment it (§5.1) | one credential |
| Clock skew beyond the 60 s margin | Upstream 401s | one credential; S7 tests it |
| Token formatted into a log **before** injection | Prevented by `fmt.Formatter` redaction (§6) | — |
| Token present in a request dump **after** injection | Prevented by the ordering rule of §6.1, not by the type — no hook may run post-injection | — |

---

## Decisions (ADRs)

### ADR-S3-01 — `TokenProvider` acquires; `TokenCache` decides freshness
*Context.* Caching could live inside each provider or above all of them.
*Decision.* Above. Providers implement acquisition only and are forbidden from caching.
*Consequences.* Every provider inherits identical refresh-ahead, single-flight, jitter, backoff
and breaker semantics, so a second IdP cannot quietly behave differently under load. Providers
stay small and testable. The cost is that a provider wrapping a vendor SDK with its own
internal cache must have it disabled, or two layers will disagree about freshness — S3
requires it disabled.

### ADR-S3-02 — Serve a valid cached token during an IdP outage
*Context.* A strict reading of "fail closed on token acquisition failure" (FR8) would deny
whenever refresh fails, even while holding a perfectly valid token.
*Decision.* Serve while the token is genuinely valid; deny once it expires.
*Consequences.* An Entra outage degrades gradually and per-credential rather than instantly and
globally. Consistent with INV-4, which conditions allow on *establishing* authorisation — a
valid token establishes it. The trade is that a credential revoked at the IdP keeps working
until expiry, which §7 already identifies as an unclosable property of bearer tokens.

### ADR-S3-03 — Type-level redaction rather than discipline
*Context.* INV-5 forbids secrets in any output.
*Options.* Convention and code review; a linter; an unprintable type.
*Decision.* An unexported `secret` type whose `String`, `GoString`, `MarshalJSON` and
`MarshalText` all redact.
*Consequences.* Catches the realistic leaks — a struct logged whole, a dumped request, a
formatted panic — which review does not catch reliably. Costs slight awkwardness at the two
legitimate call sites, which is the point: they become greppable. Does **not** claim memory
scrubbing (§6).

### ADR-S3-04 — Audience-scoped projected token, re-read per exchange
*Context.* The projected SA token is Aksh's root credential.
*Decision.* Project it with an explicit Entra audience, into `aksh-proxy` alone, and re-read
the file on every exchange.
*Consequences.* A leak costs an Entra federation attempt rather than cluster API access.
Re-reading eliminates the rotation failure mode at the cost of a file read per exchange —
negligible next to a network round trip, and exchanges are rare because of caching.

---

## v1 forward-compatibility

| v1 need | Seam | Why additive |
| ------- | ---- | ------------ |
| **FR10** multi-IdP (Okta, Auth0, Keycloak, generic OIDC) | `TokenProvider` + S2's `provider` enum | A new provider is a new implementation plus a new enum value. `TokenCache`, the key derivation and the audit fields are unchanged because they are already provider-neutral. |
| **On-behalf-of / user delegation** | `CredentialSelector.subject` | ⚠️ **Not safely additive as a bare optional field**, and ADR-S2-06 is corrected accordingly. Under S0 §10 an MVP cluster *prunes* it, so a policy requesting a delegated subject would execute under the broader ServiceAccount identity instead — the wrong principal, silently. Bumping §2.3's version tag does nothing when the field never arrived. It must land via a **new CRD version with conversion**, or via a discriminated credential structure whose unknown variants an MVP schema rejects (S2 §4.1). §2.3's derivation must *also* be extended and its tag bumped, or different subjects collapse onto one cache entry. |
| **Multiple issuers per provider** | `CredentialSelector.issuer` | As above — same pruning hazard, same two required changes. |
| **Central broker service** (if WIF-less environments must be supported) | `TokenProvider` | A remote-broker provider implements the same interface; the cache above it is unchanged. |
| **Proof-of-possession / sender-constrained tokens** | `Token`, plus `credentialIdentity` and S1's pool key | `Token` being a struct rather than a string means binding material can be carried without changing the interfaces — but the claim stops there. Sender-constrained tokens also change cache identity (a bound token is not interchangeable) and S1's connection partitioning (binding is per-connection). Those seams are named here rather than implied, because "just add a field to `Token`" would be wrong. |

---

## Open questions

| ID | Question | Closed by |
| -- | -------- | --------- |
| **OQ-S3-01** | Which Entra federated-credential subject shape — one per agent ServiceAccount, or one per namespace with the SA as a claim? Per-SA is the tighter blast radius but scales linearly with agent count and may hit Entra's per-application federated-credential limit. Needs a real tenant to answer. | S5, S7 |
| **OQ-S3-02** | What token lifetime do we request, given §7 makes lifetime the only lever on the revocation window? Shorter is safer but multiplies IdP load across a fleet; the trade needs the fleet-size numbers from OQ-S2-03. | S7 |
| **OQ-S3-03** | Should the breaker be per-credential (as specified) or also per-IdP-endpoint? If many credentials share one struggling endpoint, per-credential breakers open independently and slowly. Probably needs both tiers; deferred until there is load data. | S7 |
| **OQ-S3-04** | Should the MVP validate the token it receives — issuer, audience, expiry sanity — or trust the IdP response? Validation costs little and catches a misconfigured federated credential early, but overlaps what the resource server does. | S7 |
