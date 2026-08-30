# S2 — `AkshPolicy` CRD & Policy Engine

> **Status:** Reviewed · **Depends on:** S0, S1 · **Depended on by:** S3 (credential selection), S4 (decision), S6 (policy identity in audit), S7 (conformance)

The user-facing API, and how a request is matched against it deterministically.

---

## Scope

**Decides:** the CRD's group, version, kind, and full schema; which workloads a policy binds
to; the rule and constraint model; how a rule names a credential; the matching and precedence
algorithm; default-deny; how CRDs compile into an immutable snapshot with a stable identity;
cache freshness and its bound; and validation.

**Does not decide:** how a token is obtained from a `CredentialSelector` (S3); the order in
which matching runs relative to other stages (S4); what an audit record looks like (S6).

## Requirements covered

**FR6** (policy-as-code via CRDs), **FR7** (destination allow/deny by FQDN, path, method, MCP
server, API category — narrowed per DEV-02), the policy half of **FR8** (fail closed on policy
lookup failure), and the **extensibility** NFR (a future OPA/CEL/Rego backend). Implements
**INV-7** (determinism) and supplies the identity **INV-8** matches on.

---

## Design

### 1. Shape of the API

```
Group:    aksh.dev
Version:  v1alpha1
Kind:     AkshPolicy
Scope:    Namespaced
```

Namespaced, not cluster-scoped, because a policy grants access to credentials and must be
governable by whoever owns the namespace. A cluster-scoped policy would let any namespace
author affect another's agents. Cross-namespace grants are deliberately impossible in the MVP.

An agent's effective policy is **the union of all `AkshPolicy` objects in its own namespace
that select it**. There is no inheritance and no cluster-wide default.

#### 1.1 The `spec.egress` envelope — a normative requirement from S0

Rules live under `spec.egress.rules`, **not** `spec.rules`. This looks like pointless nesting
today, when egress is all there is. It is not: S0's v1 table makes it a normative requirement,
because when ingress arrives it must be able to land as `spec.ingress` without relocating
every existing rule. Moving `spec.rules` → `spec.egress.rules` later would be a breaking
change to every policy ever written.

### 2. Schema

```yaml
apiVersion: aksh.dev/v1alpha1
kind: AkshPolicy
metadata:
  name: graph-readonly
  namespace: agents
spec:
  # Which agents this policy applies to. Required — an unset selector is rejected,
  # NOT treated as "all". A typo that silently widened scope would be a security bug.
  selector:
    matchLabels:
      app.kubernetes.io/name: research-agent

  egress:
    rules:
      - name: graph-read                 # required; unique within the policy; used in audit
        to:
          host: graph.microsoft.com      # exact FQDN, or a single-label wildcard: *.example.com
        match:                           # optional; absent means "any request to this host"
          methods: [GET, HEAD]
          paths:
            - type: Prefix               # Exact | Prefix
              value: /v1.0/me
        allowPlaintext: false            # see §3.2 — default false; ACTIVE in the MVP
        credential:                      # optional; absent means forward with no Authorization
          provider: entra                # default when unset
          resource: https://graph.microsoft.com
          scopes: [".default"]
status:
  conditions: [...]
  observedGeneration: 3
```

#### 2.1 Field semantics

| Field | Required | Notes |
| ----- | -------- | ----- |
| `spec.selector` | **yes** | Standard label selector against the **agent pod**. Explicitly required: an empty selector means "everything" in Kubernetes convention, and defaulting to that would turn an authoring mistake into a cluster-wide grant. |
| `egress.rules[].name` | yes | Stable identifier appearing in audit records (S6). Immutable once set, enforced by CEL. |
| `egress.rules[].to.host` | yes | Exact FQDN, or a wildcard with exactly one leading `*.` label. Case-insensitive, stored and matched as a lowercase IDNA A-label — the same canonical form S1 §4 produces. Bare IPs are rejected (S1 has no identity for them). |
| `egress.rules[].match` | no | Absent = match any request to the host. Present = **all** specified dimensions must match (AND). |
| `egress.rules[].match.methods` | no | Uppercase HTTP methods. Absent = any. |
| `egress.rules[].match.paths` | no | List of matchers, OR'd together. Matched against the **same canonical request target S1 forwards** (S1 §4), never the raw agent-supplied string, so policy and upstream can never disagree. |
| `egress.rules[].credential` | no | See §3. Absent is meaningful, not an omission: the rule allows the destination with **no** credential. |

`to.host` deliberately carries no port. The port is bound by S1's INV-8 rule (d) to the
recovered destination, so expressing it in policy would create a second, weaker source of
truth for something the kernel already attests.

#### 2.2 MCP servers and API categories

FR7 names "MCP server/tool" and "API category" as match dimensions.

- **MCP server** identity is expressed with the existing `to.host` + `match.paths` fields. An
  MCP server *is* an HTTP endpoint; it needs no separate concept. **Tool** granularity is out
  of MVP scope per DEV-02 (the tool name lives in the JSON-RPC body).
- **API category** is *not* given a dedicated field in the MVP. A category is a named grouping
  of destinations — which is exactly what a policy with several rules already is. Adding a
  `category:` enum now would fix a taxonomy before we know its members, and taxonomies are the
  hardest thing to change compatibly. Recorded as ADR-S2-04.

### 3. `CredentialSelector` — provider-neutral by construction

S0 assigns this contract to S2 because it is part of the CRD and S2 freezes the CRD first.

```yaml
credential:
  provider: entra                        # enum; default "entra"
  resource: https://graph.microsoft.com  # the API being called
  scopes: [".default"]                   # provider-interpreted
```

The tempting shape — a single `audience: "https://graph.microsoft.com/.default"` string — is
**rejected**. That value is an Entra *scope*, not a portable audience; baking it into a field
called `audience` would hardcode one provider's semantics into the public API and make FR10
(multi-IdP) a breaking change. Splitting `resource` from `scopes` and naming the `provider`
explicitly is what makes another provider an additive enum value later.

`credential` is **optional**. A rule may allow a destination without attaching a credential —
a public API, or an upstream authenticated some other way. INV-9 still applies: any
agent-supplied `Authorization` is stripped regardless. This is why S1's pool key carries a
"no-auth sentinel" rather than assuming every request has a credential identity.

#### 3.1 Permitting a destination is an act of trust (discharging ASM-1)

S0's ASM-1 places an explicit obligation on this document: the CRD's own documentation must
make clear what an operator is asserting when they permit a destination.

> **Writing a rule with a `credential` is an assertion that the destination is trusted with
> that credential's token.** Aksh hands the upstream a real bearer token — that is what a
> bearer token is — and the MVP relays responses without inspection. A permitted upstream can
> therefore reflect the token back to the agent in its response body, and Aksh cannot prevent
> that: an upstream can encode a token in any form it likes.
>
> The allow-list *is* the mitigation. There is no second line of defence in the MVP; response
> redaction (FR14) reduces accidental leakage in v1 but never the deliberate case. S6's audit
> record names the destination, so misplaced trust is at least attributable after the fact.

This text is normative for the generated CRD field documentation, not just for this design
document — an operator reading `kubectl explain akshpolicy.spec.egress.rules.credential` must
see it.

#### 3.2 `allowPlaintext`

S1 §6.1 supports in-cluster plaintext HTTP because kagent requires it, and that hop is
unauthenticated. Injecting a brokered bearer token over it is an exposure Aksh creates, so it is
opt-in per rule:

```yaml
allowPlaintext: false   # default
```

Semantics, stated precisely because a vaguer version was rejected in review:

- It is **rule eligibility**, evaluated *before* precedence: a plaintext request simply does not
  match a rule with `allowPlaintext: false`.
- A plaintext request matching **no** opted-in rule is an **ordinary audited denial**. It is
  explicitly *not* "forward without the credential", which would look like success while
  silently dropping authorisation.
- It has no effect on TLS requests.
- It contributes **no** specificity (§5.2): it gates eligibility, it does not rank.

**It is a *widening* field, not a narrowing one**, and an earlier draft misclassified it. The
safe value is the default `false`; setting it `true` *grants* something. So §4.1's
rejecting-placeholder discipline does **not** apply — and could not, since plaintext is MVP
functionality that must work now, not be rejected. It ships as an ordinary active field with a
safe default, which is exactly the case §10 says additive evolution is for.

### 4. Constraints must be discriminated — the S0 §10 obligation

S0 §10 establishes that Kubernetes **prunes** unknown CRD fields rather than rejecting them,
so "add an optional narrowing field later" is unsafe: applied to an older cluster, the
constraint is silently dropped and the policy enforced *more permissively than written*.

S2 must therefore make future constraints arrive in a form an MVP schema **rejects**. The
mechanism is a discriminated list — but *how* it is expressed matters, and the obvious
expression does not work:

```yaml
match:
  methods: [GET]
  paths: [...]
  constraints: []                # discriminated; MUST be empty in MVP
```

> **The empty-enum trap.** The natural way to write "no constraint types exist yet" is
> `type: {type: string, enum: []}`. **This does not work.** Verified against a live
> Kubernetes v1.29.14 API server: an empty `enum` array is treated as *"no constraint"*, not
> *"nothing is valid"*. A v1 policy carrying `constraints: [{type: MCPTool, mcpTool: {...}}]`
> is **accepted**: the unknown `mcpTool` sibling is pruned, but `type: MCPTool` is silently
> persisted — exactly the silent under-enforcement this section exists to prevent, and worse,
> because the discriminator survives into the snapshot.
>
> `fieldValidation=Strict` does not save us either; S0 §10 already established it is
> client-chosen and cannot be relied on.

The MVP schema therefore uses **both** of the following, verified to reject correctly under a
non-strict client:

1. **`maxItems: 0` on the `constraints` array.** Rejects any entry regardless of its `type`.
   This is the primary mechanism and the reason no placeholder enum value has to be invented.
2. **An explicit CEL rule enumerating known types** (`self.all(c, c.type in [...])`, an empty
   list today). Unlike a bare schema `enum: []`, a CEL rule with an empty membership set
   evaluates false and rejects. This is what a later version relaxes by adding the new type to
   the list *and* raising `maxItems`.

**Defence in depth:** if an unrecognised `type` ever reaches compilation anyway — a schema
regression, a hand-edited etcd object — compilation **fails the whole snapshot** and the
previous snapshot is retained. It must never silently drop the constraint, because dropping a
narrowing constraint widens the rule.

When a real constraint type ships, `maxItems` is raised, the CEL membership list gains the
type, and the type's own properties are defined. All three are additive.

#### 4.1 The discipline is not only about `constraints`

The mechanism above protects one field. The *hazard* — a narrowing field silently pruned into
a wider policy — applies to every security-relevant addition, and three known v1 additions
escape `constraints` entirely:

| v1 addition | If naively added later | Guard shipped in MVP |
| ----------- | ---------------------- | -------------------- |
| **`deny` effect** (ADR-S2-02 defers it) | A deny rule applied to an MVP cluster is pruned to an **allow** rule. Catastrophic and silent. | Ship a required `effect` discriminator on every rule now, with `maxItems`-equivalent CEL restricting it to `["Allow"]`. An MVP cluster then rejects `effect: Deny` instead of granting it. |
| **`spec.ingress`** | Pruned entirely; the operator believes ingress is controlled and it is not. | Ship `spec.ingress` as a declared object with a CEL rule asserting it is absent. Rejected, not pruned. |
| **`credential.issuer` / `subject`** (ADR-S2-06) | Pruned, so the request silently falls back to the **default** issuer — a different credential than written. | These are only *widening* if the default is what the author wanted. Ship both as declared fields with a CEL rule asserting they are unset. |

The rule to carry forward: **any field whose presence changes which credential is used, or
which requests are permitted, must exist in the MVP schema in a rejecting form.** A field that
does not exist cannot be rejected — it can only be pruned. This is the generalisation of §4,
and it is cheap only because it is done now.

> **Consequence for reviewers:** any future match dimension that *narrows* access must arrive
> as a `constraints` entry, never as a new sibling field of `methods`/`paths`. S2's schema
> comment must say so, or the discipline will be lost the first time someone adds a field.

### 5. Matching and precedence

#### 5.1 Algorithm

Given a request carrying the validated identity, canonical path, and method from S1:

```
candidates := every rule, across all selecting policies, whose to.host matches the identity
              (exact beats wildcard; see 5.2)
              AND whose match block is satisfied in full

if candidates is empty        → DENY (default-deny)
else                          → the single most specific candidate wins (5.2)
```

There is no `deny` verb in the MVP. Default-deny plus allow-rules is complete for the MVP's
expressiveness, and adding explicit deny later is *widening* the language, not narrowing a
rule — so §4's discipline does not forbid it. Introducing deny now would immediately raise
allow/deny precedence questions we do not need to answer yet.

#### 5.1.1 Path canonicalisation — the shared algorithm

Path matching is the easiest place in this design to build a bypass, so the algorithm is
specified rather than assumed. It is **shared with S1**: the representation matched here is
byte-identical to the one forwarded upstream (S1 §4), because authorising one representation
while forwarding another is precisely how prefix rules get defeated.

Before matching, the request target is canonicalised:

1. Split off the query string. **The query is not matched in the MVP** and does not
   participate in prefix comparison — a rule for `/v1.0/me` matches `/v1.0/me?$select=id`.
2. Percent-decode only unreserved characters. An encoded separator (`%2F`, `%5C`) is
   **not** decoded — it is a literal character, not a path separator.
3. Reject, rather than normalise, any target containing a backslash, a null byte, or a
   malformed percent-escape. Rejection is safer than a normalisation the upstream may
   perform differently.
4. Collapse duplicate slashes and resolve `.`/`..` segments. **If resolution would escape the
   root, reject.** A target that still contains `..` after resolution is rejected.
5. Compare case-**sensitively**. Paths are case-sensitive in HTTP; folding them would let
   `/Admin` slip past a rule for `/admin`.

Prefix matching is **segment-aware**: a `Prefix` matcher for `/api` matches `/api` and
`/api/v1`, and does **not** match `/apix`. Lexical prefix matching is a real bypass, not a
theoretical one.

The point of step 3/4's rejections is that Aksh and the upstream must not be able to disagree.
If Aksh authorises prefix `/safe` for `/safe/../admin` and the upstream's framework then
resolves that to `/admin`, the policy has been defeated without anything appearing wrong. The
only safe answer is that ambiguous targets never reach the upstream at all.

S7 owns conformance vectors for this algorithm; it is the single highest-value test table in
the suite.

#### 5.2 Specificity ordering — and why it is designed the way it is


Candidates are ordered by a total, deterministic comparison:

1. **Host specificity** — exact FQDN beats wildcard.
2. **Path specificity** — `Exact` beats `Prefix`; longer matched prefix beats shorter. When a
   rule lists several OR'd path matchers and more than one matches, the rule's path
   specificity is that of its **most specific matching entry**. Stating this is not pedantry:
   the extensibility NFR anticipates a second, independently-written `Matcher`, and two
   implementations resolving it differently would break INV-7.
3. **Method specificity** — compared by **cardinality**: an explicit list beats an absent one,
   and among explicit lists, fewer methods beats more. Ranking `[GET]` above `[GET, HEAD,
   POST]` mirrors how paths are ranked and reduces how often unrelated rules fall through to
   the name tie-break.
4. **Tie-break** — lexicographic by `(namespace, policy name, rule name)`.

Step 4 exists to satisfy INV-7: without an explicit total order, two equally-specific rules
would resolve by map iteration or informer arrival order, and the same request could decide
differently on two replicas of the same agent. Ties are also **surfaced**, not just broken: a
tie means two rules are indistinguishable, which is usually an authoring error, so it raises a
status condition and a metric.

#### 5.2.1 Constraint count is deliberately *not* an ordering term

An earlier draft ranked "more constraints satisfied" above "fewer", and leaned on that to
argue FR14 was additive. **That reasoning is unsound and has been removed.** Constraint
*count* is not a proxy for restrictiveness: a rule with one `MCPTool` constraint allowing
`[read_file]` is far more restrictive than a rule with two constraints, one of which allows
`[read_file, write_file, delete_file]` and one of which is near-vacuous. Ranking by count
would have promoted the *less* restrictive rule.

Instead:

- Two candidates that differ **only** in their constraints are treated as **`Ambiguous`** and
  resolved by the tie-break, with the ambiguity surfaced.
- When a real constraint type ships, it must define **its own fixed specificity
  contribution**, occupying the reserved `RuleRank.ConstraintRank` position whose neutral
  value is zero — so adding it cannot reorder any pair of existing MVP rules. Fixing the
  position now, rather than the values, is what keeps the seam honest.

This is a weaker forward-compatibility claim than the earlier draft made, and an honest one.
What still holds — and is what FR14 actually needs — is that constraints can only ever *add*
conditions, so a v1 constraint can only ever make a rule match **fewer** requests. It can
never cause a rule to match a request it previously did not, which is the property that keeps
existing policies' meaning intact.

#### 5.2.2 Residual risk: credential shadowing

Ordering is winner-take-all: only the winning rule's `credential` is applied. Because host
specificity is evaluated first, a rule with an **exact** host and no `match` block outranks a
**wildcard**-host rule with a narrow, specific path — even though the second is far more
narrowly scoped for that path.

So in a namespace containing:

- Policy A: `*.example.com`, `paths: [Exact: /admin]`, credential `admin`
- Policy B: `sub.example.com` (exact), no match block, credential `readonly`

a request to `sub.example.com/admin` matches **B**, and A's carefully-scoped grant is not
applied. The step-4 tie detector never fires, because exact-beats-wildcard is a genuine win.

This qualifies §5.3's claim below: adding a policy can never remove *access*, but it **can
change which credential a given request receives** — and the credential is the asset (INV-1).

Mitigation in the MVP: whenever more than one candidate matches a request and the candidates
carry **different credentials**, the result is flagged `Ambiguous` and recorded as such in the
audit event (S6), even though the ordering itself is unambiguous. Operators get the visibility
the design already believes ties deserve. The residual risk is named here rather than
engineered away, in the style of S0's ASM-1.

#### 5.3 Union across policies

Multiple policies may select the same agent; their rules are unioned before ordering. The
`(namespace, policy, rule)` tie-break therefore spans policies, and adding a policy can never
*remove* access — only add it. Removing access requires editing or deleting the granting
policy, which is the behaviour operators expect from an allow-list system.

**Qualified by §5.2.2.** Stated precisely, the monotonic property is about S2's *matched-rule
set*: adding a policy never removes a rule from the candidate set. It is **not** an end-to-end
access guarantee, because adding a policy can change which rule *wins* and therefore which
credential is applied — which can in turn cause an S3 acquisition failure or a loss of upstream
privilege. S4 must not rely on the stronger reading.

#### 5.4 Trust-domain assumption

`spec.selector` is an ordinary label selector, and Kubernetes RBAC is namespace-scoped rather
than selector-scoped. So anyone with write access to `AkshPolicy` in a namespace can write a
selector matching **any** pod in that namespace and attach **any** credential to it —
including another team's agent.

Namespacing therefore prevents *cross-namespace* grants, and nothing more. The MVP's operating
assumption is stated plainly:

> **ASM-S2-1 — one namespace is one trust domain, for policy authors *and* workload authors.**
> Operators must not co-locate agents of differing trust levels in a namespace where multiple
> parties can author `AkshPolicy` **or mutate pod labels**. Aksh does not enforce this and
> cannot detect a violation.

The second half matters as much as the first and is easy to miss: `spec.selector` matches on
labels, so anyone who can *set a label* can select their workload into an existing grant
without any `AkshPolicy` write access at all. Label-write and policy-write are therefore
equivalent privileges here, which is not how RBAC is usually reasoned about. Binding policies
to an admission-controlled immutable identity (the agent's ServiceAccount, which S5 already
controls) would close this; it is out of MVP scope and recorded as OQ-S2-06.

Constraining a selector to labels its author is separately authorised for is a real mechanism,
but a substantially larger one, and out of MVP scope. Naming the gap is the MVP obligation;
S7 must carry it in the bypass catalogue.

### 6. Compilation and identity

CRDs are user-facing and mutable; the matcher needs something immutable and fast. Between them
sits a **compiled snapshot**.

- Compilation validates, canonicalises (IDNA, lowercase, path normalisation), pre-sorts by the
  §5.2 order, and builds host lookup structures. It happens on change, not per request.
- A snapshot is **immutable**. Updates build a new one and swap it atomically. A request that
  begins under one snapshot completes under it, so a mid-flight policy change can never yield
  a half-old, half-new decision.
- Each snapshot has a **`policyVersion`**, specified precisely because S6 records it as
  evidence and S7 asserts replica agreement on it:
  `SHA-256` over a domain-separated, length-prefixed canonical encoding of every contributing
  rule in sorted order — namespace, policy name, rule name, canonical host, wildcard flag,
  sorted method set, sorted canonical path matchers, and the credential selector. Sets are
  sorted and de-duplicated before hashing so that two semantically identical policies hash
  identically.
  It is content-derived, not a counter, so it is stable across restarts and identical across
  replicas. **It attests inputs, not behaviour:** two sidecars running different Aksh versions
  could hash identically and still enforce differently, so audit records carry the evaluator
  version alongside it (S6). Rule references also carry the policy's Kubernetes UID, so a
  deleted-and-recreated policy of the same name is distinguishable.

### 7. Freshness, staleness, and fail-closed — closing OQ-S0-05

Each sidecar watches the API server directly (ADR-S0-07), scoped to its own namespace and to
policies selecting it.

INV-4 permits serving from a populated cache during an API-server outage, up to a bound. That
bound is defined here:

| State | Behaviour |
| ----- | --------- |
| Snapshot present, watch healthy, latest observed resource version **compiled** | Normal |
| Snapshot present, watch healthy, but the latest observed state **failed to compile** | Treated as **loss of freshness from the moment that state was observed**, and subject to the same `maxStaleness` lease. Without this, a healthy watch plus a persistently failing compile would serve known-obsolete policy *forever* — a revoked grant would never stop applying. Compile failure is not a quieter kind of success. |
| Snapshot present, watch broken **< `maxStaleness`** | Serve the snapshot. Increment a staleness gauge; raise a status condition. |
| Snapshot present, watch broken **≥ `maxStaleness`** | **Deny all** — the snapshot is no longer trustworthy evidence |
| No snapshot ever built | **Deny all** — no basis for any decision |

`maxStaleness` defaults to **5 minutes** and is operator-configurable (S0 §9), not
policy-configurable. Policy-configurable staleness would let a policy author extend the window
during which their own revocation fails to take effect — the person who benefits from
staleness should not be the person who sets it.

Five minutes is a deliberate trade: long enough to ride out an API-server restart or a leader
election, short enough that a revoked policy stops mattering quickly. It is stated as a
default precisely so operators can argue with it.

**Startup ordering matters.** The sidecar must not report ready until its first snapshot is
built, or S1's listener would accept connections that are then denied for an empty cache —
technically fail-closed, but indistinguishable from a policy error and confusing to debug.

Watch gaps (`410 Gone`) trigger a full re-list. A re-list produces a new snapshot atomically;
it never empties the existing one first.

**Silence is not health.** A watch that has delivered nothing is indistinguishable from a
watch that has died, so freshness cannot be inferred from "no error". Aksh requires periodic
positive evidence — watch bookmarks, and a periodic re-list — and treats their absence as
staleness. `PolicyStore` therefore reports a freshness *state* and its cause, not just an age.

### 8. Validation

The Kubernetes version floor is 1.29 (ADR-S0-10), and CRD CEL validation
(`x-kubernetes-validations`) reached **GA in 1.29** — exactly at the floor. This closes
OQ-S0-04 favourably: **validation is in-schema, and no validating webhook is required for
policy.** One less privileged component, and errors surface at `kubectl apply` rather than
asynchronously in a status field.

CEL rules the schema carries:

| Rule | Why |
| ---- | --- |
| `selector` is present and non-empty | An empty selector would mean "all agents" |
| `to.host` is a valid DNS name, or `*.` plus one | Rejects bare IPs and multi-label wildcards |
| `rules[].name` is unique within the policy | Names appear in audit; duplicates make records ambiguous |
| `rules[].name` is immutable | Renaming would silently break audit continuity |
| `constraints` has `maxItems: 0`, **and** a CEL rule asserts `self.all(c, c.type in [])` | **The §4 mechanism.** Both, not either: `maxItems` rejects any entry at all, the CEL allow-list is what a later version relaxes. A bare `enum: []` does **not** work and must not be substituted. |
| `credential.scopes` non-empty when `credential` is present | A credential with no scopes is always an authoring error |

**`AkshPolicy` has no `status` in the MVP** (ADR-S2-07). An earlier draft promised
`Ready`/`Degraded`/`observedGeneration`, which is not implementable: ADR-S0-06 grants sidecars
**read-only** RBAC on policy and ADR-S0-07 deliberately omits a controller, so nothing is
entitled to write status — and a sidecar certainly cannot write one while the API server is
the thing that is unreachable. Worse, the conditions are per-sidecar facts (this snapshot,
this pod, this request), so N replicas cannot truthfully share one object-level condition.

Everything that draft wanted to report is reported **sidecar-locally** instead: staleness and
compile failure as metrics and readiness (§7), ambiguity as a metric and an audit field
(§5.2.2, S6). Validation errors surface synchronously at `kubectl apply` via CEL, which is
where an author actually looks.

### 9. Bounds — the S2 share of the resource-safety NFR

S0's NFR matrix assigns **policy cache size** to S2. An unbounded rule set is a memory and
compile-time denial-of-service vector against *every* sidecar watching the namespace, and per
§5.4 a careless or hostile namespace author can create one.

| Bound | Enforced | Behaviour when exceeded |
| ----- | -------- | ----------------------- |
| `egress.rules` per policy | `maxItems: 256` | Rejected at `kubectl apply` |
| `match.paths` per rule | `maxItems: 32` | Rejected at `kubectl apply` |
| `match.methods` per rule | `maxItems: 9` (the HTTP method set) | Rejected at `kubectl apply` |
| `to.host` length | `maxLength: 253` (DNS maximum) | Rejected at `kubectl apply` |
| `paths[].value` length | `maxLength: 1024` | Rejected at `kubectl apply` |
| `rules[].name` length | `maxLength: 63` | Rejected at `kubectl apply` |
| `credential.resource` length | `maxLength: 512` | Rejected at `kubectl apply` |
| `credential.scopes` | `maxItems: 32`, `maxLength: 256` each | Rejected at `kubectl apply` |
| **Total rules considered per agent** (across all selecting policies) | Compile time, **2048** | **Compilation refuses; the previous snapshot is retained**, an alert is raised, and — critically — the snapshot is subject to the §7 staleness lease from that moment, so it cannot serve obsolete policy indefinitely. Never partially compile: a truncated rule set is one with silently missing grants. |
| **`AkshPolicy` objects per namespace** | `ResourceQuota` on the CRD, recommended **64** | A watch cannot server-side filter CRDs by `spec.selector`, so **every** sidecar in the namespace receives and parses **every** policy — including ones that do not select it. Per-agent rule limits therefore do not bound the work a hostile author can impose. This is the only bound that does, and it is operator-applied rather than schema-enforced. S5 ships it in the install manifests. |
| Compiled snapshot memory | Compile time, derived from the sidecar's memory limit (default **16 MiB**) | As above |

Schema bounds are preferred wherever the limit is expressible on a single object, because they
fail synchronously at apply time. Cross-object limits necessarily fail later, which is why
their failure mode is "retain the last good snapshot" rather than "swap in a partial one".

---

## Interfaces

```go
// PolicySnapshot is an immutable, fully-compiled, deterministically-ordered rule set.
// Version() is a content hash: identical content yields an identical version on every
// replica and across restarts. Recorded in every audit event (S6).
// Implementations MUST NOT hand out mutable internal state: Rules() returns a defensive
// copy, or the snapshot is kept opaque behind lookup methods. A shared backing array
// would make "immutable" a comment rather than a property.
type PolicySnapshot interface {
    Version() string
    Rules() []CompiledRule
}

// CompiledRule is one rule in its canonical, pre-sorted form. Exposed because S4 needs
// the credential and provenance, and S7 asserts ordering against it.
type CompiledRule struct {
    Ref        string   // "<namespace>/<policy>/<rule>" — appears in audit (S6)
    Host       string   // canonical A-label; leading "*." for a wildcard
    Wildcard   bool
    Methods    []string // empty = any
    Paths      []PathMatcher
    AllowPlaintext bool // §3.2 — rule eligibility for non-TLS requests; default false
    Credential *CredentialSelector // nil = allow with no credential
    Rank       RuleRank // precomputed §5.2 ordering key; comparison must not re-derive it
}

type PathMatcher struct {
    Exact bool   // false = prefix
    Value string // canonical, matching the representation S1 forwards
}

// RuleRank is the STATIC part of the §5.2 ordering key — the part that depends only on
// the rule, not on the request. Path rank cannot live here: a rule may carry several
// OR'd matchers and its path specificity is that of the entry matching *this* request
// (§5.2 step 2), which is unknowable at compile time. Snapshots are therefore sorted by
// the static key only, as a pre-filter; final ordering uses MatchRank below.
//
// Splitting them is not a refinement — a single compile-time rank literally cannot
// implement the stated ordering, and a matcher that tried would break INV-7.
type RuleRank struct {
    HostExact   bool
    MethodCount int    // 0 = absent (least specific); otherwise fewer is more specific
    TieBreak    string // "<namespace>/<policy>/<rule>" — unique, so ordering is total
    // Reserved: when a constraint type ships it contributes a fixed, per-type value
    // HERE, between MethodCount and TieBreak. Its neutral value is zero, so adding it
    // cannot reorder any pair of existing MVP rules. Fixing the position now is what
    // keeps FR14 additive (§5.2.1).
    ConstraintRank int // always 0 in MVP
}

// MatchRank is the full ordering key for one candidate against one request. Derived per
// request from RuleRank plus the path entry that actually matched.
type MatchRank struct {
    Static   RuleRank
    PathExact bool
    PathLen   int
}

// PolicyStore provides the current snapshot and how stale it is. Age is explicit in the
// contract because INV-4's fail-closed behaviour is a function of staleness, and a caller
// must not have to infer it. Deliberately says nothing about where policy comes from, so
// replacing the direct watch with a control plane in v1 changes no signature (ADR-S0-07).
type PolicyStore interface {
    // Current returns the snapshot and its age. ok is false when no snapshot has ever
    // been built, which is a distinct condition from a stale one and must not be
    // collapsed into it.
    Current() (snap PolicySnapshot, age time.Duration, ok bool)
}

// Matcher evaluates a request against a snapshot. It returns what policy SAYS; it does
// not decide the request's fate — that is S4's Decision, which also accounts for token
// acquisition and audit. Keeping them separate is what stops S2 depending on S4.
type Matcher interface {
    // The error return distinguishes "policy says no" from "the evaluator failed", which
    // S4 must treat differently: the first is an ordinary denial, the second is a
    // fail-closed *fault* that should alert. Collapsing them would hide an evaluator
    // outage behind a wall of normal-looking denials.
    // ctx carries cancellation, which an out-of-process evaluator (the extensibility NFR's
    // OPA/Rego backend) needs and an in-process one ignores.
    Match(ctx context.Context, snap PolicySnapshot, req RequestFacts) (MatchResult, error)
}

// RequestFacts is the canonical, already-validated view S1 produces and S4 assembles.
// Every field is canonical (INV-8): identity is a lowercase IDNA A-label, path is the
// same representation that will be forwarded upstream, so policy can never authorise
// one representation while the upstream receives another.
//
// NOTE: this is a cross-component contract introduced by S2 and therefore added to S0's
// interface inventory in the same change, per S0's own governance rule.
type RequestFacts struct {
    Identity string // validated identity — never raw agent input
    Method   string
    Path     string
    // Port comes from the recovered destination, not the agent's authority. No MVP rule
    // matches on it (§2.1 deliberately omits port from to.host), so it is carried rather
    // than used: S1 needs it for the INV-8 authority/port check, and OQ-S2-04's possible
    // IP/port matcher would consume it. It is not dead.
    Port uint16
    // Transport is a closed enum (tls | plaintext) set by S1's protocol discriminator.
    // Matching consults it for AllowPlaintext eligibility (§3.2), and S6 audits it.
    Transport Transport
}

// MatchResult is policy's verdict plus the provenance S6 needs to record it.
type MatchResult struct {
    Matched    bool
    PolicyRef  string              // "<namespace>/<policy>/<rule>"
    Version    string              // snapshot version — same value for every decision from it
    Credential *CredentialSelector // nil is meaningful: allow with no credential
    // Ambiguous is set when (a) a specificity tie was broken by RuleRank.TieBreak, or
    // (b) multiple candidates matched carrying DIFFERENT credentials, even if the
    // ordering was unambiguous (§5.2.2 credential shadowing). Surfaced, not hidden.
    Ambiguous  bool
}

// CredentialSelector is the public, CRD-facing description of a wanted credential.
// Provider-neutral by construction: "resource" and "scopes" are separate, and the
// provider is named, so adding an IdP is an additive enum value rather than a
// reinterpretation of an existing string (FR10).
type CredentialSelector struct {
    Provider string   // "entra" by default
    Resource string
    Scopes   []string
}
```

---

## Failure modes

| Failure | Behaviour | Consistent with |
| ------- | --------- | --------------- |
| No rule matches | Deny, uniform response | INV-4 row 1, ADR-S0-13 |
| No snapshot ever built | Deny all; sidecar not ready | INV-4 row 3 |
| Watch broken, age < `maxStaleness` | Serve snapshot; gauge + condition | INV-4 row 2 |
| Watch broken, age ≥ `maxStaleness` | Deny all | INV-4 row 2 |
| A policy fails validation | Rejected at `kubectl apply` by CEL | never reaches the cache |
| A policy is semantically valid but ambiguous (§5.2 tie) | Deterministically resolved, flagged `Degraded`, `Ambiguous` in the audit record | INV-7 |
| Compilation panics on malformed cached data | Retain the previous snapshot; do not swap; alert | never widen access on error |

---

## Decisions (ADRs)

### ADR-S2-01 — In-schema CEL validation; no validating webhook for policy
*Context.* Policy needs cross-field validation (unique names, immutability, enum discipline).
*Evidence.* CRD CEL validation is GA in 1.29, our floor.
*Decision.* Validate in-schema with `x-kubernetes-validations`.
*Consequences.* Closes OQ-S0-04. Removes a privileged component from the MVP; errors surface
synchronously at apply time. Ties us to the 1.29 floor more tightly — below it, validation
silently weakens, which is another reason ADR-S0-10 says *unsupported*, not *degraded*.
S5 still needs its own validating webhook for pod admissibility (INV-10); that is unrelated.

### ADR-S2-02 — Allow-only; no `deny` verb in the MVP
*Context.* Policy languages usually grow both.
*Decision.* Default-deny plus allow rules; no explicit deny.
*Consequences.* No allow/deny precedence semantics to define, so §5.2's ordering stays a
simple specificity comparison. Adding deny later *widens* the language rather than narrowing a
rule, so it is compatible under S0 §10. The cost is real and should not be understated: with allow-only rules, "allow everything under
`/api` **except** `/api/admin`" is **not expressible at all**. Adding a narrower allow rule for
`/api/admin` grants it; omitting it does not deny it, because the broader `/api` rule already
matches. Exceptions require a deny verb. The MVP's answer is to enumerate the permitted
prefixes positively instead, which is workable while rule counts are small and is the trigger
to revisit when they are not. §4.1 ships the `effect` discriminator so that adding deny later
is safe.

### ADR-S2-03 — Constraints are discriminated from day one
*Context.* S0 §10: Kubernetes prunes unknown fields; a pruned *narrowing* field silently
widens access.
*Decision.* Ship an empty `constraints` list guarded by **`maxItems: 0` plus a CEL
allow-list** over a required `type` string. A bare OpenAPI `enum: []` is explicitly
**forbidden** — it was measured to enforce nothing on v1.29.14 (§4).
*Consequences.* An MVP cluster rejects a v1 policy rather than under-enforcing it. Costs a
slightly heavier schema for a feature with no MVP members — the entire value is that it cannot
be added later, because adding it later *is* the failure.

### ADR-S2-04 — No `category` field in the MVP
*Context.* FR7 names "API category" as a match dimension.
*Options.* Ship an enum now; ship a free-form string; express categories as rule groupings.
*Decision.* No dedicated field. A category is a named set of destinations, which a policy with
several rules already expresses.
*Consequences.* Avoids fixing a taxonomy before its members are known — an enum shipped now
would be wrong and, being a *match* dimension, expensive to change. If a first-class category
proves necessary it arrives as a `constraints` type (§4) or a separate grouping resource,
both additive.

**This is a third deviation from the MRD, not merely a design choice, and is registered as
DEV-03 in S0's deviation register.** "Group the rules in one policy" is a convention, not a
reusable category match model: nothing lets an operator name a category once and reference it,
and nothing validates that two policies mean the same thing by it. S7 must trace FR7's
category dimension as **not met as written**, and it needs the same product sign-off DEV-01
and DEV-02 need. S2 cannot approve its own deviation.

### ADR-S2-05 — `maxStaleness` is operator-configurable, not policy-configurable
*Context.* INV-4 permits bounded serving from a stale cache; someone must set the bound.
*Decision.* Operator configuration, default 5 minutes.
*Consequences.* A policy author cannot extend the window during which their own revocation
fails to take effect. Costs uniformity — one bound for all policies in a sidecar — which is
the right default for a security control.

### ADR-S2-06 — `CredentialSelector` ships three of the five fields S0 named
*Context.* S0's interface inventory and its FR10 row both describe `CredentialSelector` as
carrying *provider, issuer, client/subject identity, resource, scopes*. S2 ships `provider`,
`resource`, `scopes`.
*Decision.* Omit `issuer` and `subject` from the MVP schema.
*Rationale.* Under ADR-S0-06 the MVP has exactly one identity path — Workload Identity
Federation with one ServiceAccount per agent — so the issuer is fixed by the provider and the
subject is fixed by the pod's own identity. Per-rule fields for either would be inert, and an
inert field in a public API is one people will find a use for that we did not intend.
*Consequences.* **Corrected during S3's review:** an earlier version of this ADR called both
"widening" additions exempt from §4's discipline. That was wrong, and dangerously so. Under
S0 §10 an MVP cluster *prunes* an unknown `subject`, so a v1 policy requesting a delegated
subject would silently execute under the broader ServiceAccount identity — the wrong principal,
with no error. "Widening" was the wrong test: the right one is §4.1's, *does the field's
presence change which credential is used?* For both fields it does.

They must therefore arrive either via a **new CRD version with conversion**, or as a
discriminated credential structure whose unknown variants an MVP schema rejects (§4.1). S3 §2.3
must additionally be extended to hash them, or different subjects collapse onto one cache entry.
S0's inventory is updated in the same change so the documents do not disagree.

## v1 forward-compatibility

| v1 need | Seam | Why additive |
| ------- | ---- | ------------ |
| **Ingress** | `spec.ingress`, sibling to `spec.egress` | The envelope exists from day one (§1.1); existing rules never move. |
| **FR10** multi-IdP | `credential.provider` enum | Provider is already named and `resource`/`scopes` are already separate, so a new IdP is a new enum value, not a reinterpretation of an existing string. |
| **FR11** data-flow policy | `constraints` + S4's `ResponseStage` | Provenance conditions arrive as constraint types. Rejected, not pruned, on older clusters. |
| **FR14** MCP tool controls | `constraints[].type: MCPTool` | The literal worked example in §4. Because constraints only ever narrow and only ever raise specificity (§5.2 step 4), an existing MVP rule's relative precedence cannot change. |
| **Explicit deny** | New verb | Widening the language, not narrowing a rule (ADR-S2-02). |
| **OPA/CEL/Rego backends** (extensibility NFR) | `Matcher` | `Match` takes a snapshot and facts and returns a result. An alternative evaluator implements the same interface; `PolicyStore` and `MatchResult` are untouched. |
| **Central policy control plane** | `PolicyStore` | The contract names no transport, so replacing the direct watch changes no signature (ADR-S0-07). |

---

## Open questions

| ID | Question | Closed by |
| -- | -------- | --------- |
| **OQ-S2-01** | ~~Does the sidecar need pods RBAC to evaluate `spec.selector`?~~ — **closed by S5 §7: no.** It only ever needs to know whether a policy selects *itself*, so labels come from a Downward API projection and `aksh-proxy` holds read-only RBAC on `akshpolicies` and nothing else. | *closed in S5* |
| **OQ-S2-02** | Should path matching support regular expressions? `Exact`/`Prefix` covers the common cases and is trivially deterministic; regex introduces ReDoS as a denial-of-service vector reachable from policy content. Deferred deliberately — adding a `PathMatcher` type later is additive. S7 decides from real policies whether the expressiveness is actually missed. | S7 |
| **OQ-S2-03** | With one watch per sidecar (ADR-S0-07), at what agent count does API-server load force the control plane that ADR-S0-07 deferred? Needs a measured answer, not a guess, so the trigger to build it is evidence-based. | S7 |
| **OQ-S2-04** | ~~Does plaintext need a new match dimension?~~ — **closed in §3.2: no.** S1 §6.1's identity is `<service>.<namespace>.<clusterDomain>`, an ordinary FQDN that `to.host` already matches. The `allowPlaintext` eligibility flag ships as an **active** MVP field with a safe default of `false`; it is *widening*, so §4.1's rejecting-placeholder discipline does not apply — and could not, since plaintext must work in the MVP rather than be rejected. | *closed in S2* |
| **OQ-S2-05** | Does a specificity tie (§5.2 step 4) warrant an alert-level signal, or is it common enough in practice to be noise? ADR-S2-07 removed the `Degraded` condition, so the signal is a metric plus an audit field; the question is its severity. Needs real policies to answer. | S7 |
| **OQ-S2-06** | Should a policy bind to an admission-controlled immutable identity (the agent's ServiceAccount, which S5 already governs) rather than to mutable pod labels? Labels make label-write privilege equivalent to policy-write privilege (§5.4), which is not how operators reason about RBAC. Would be a **narrowing** change to `spec.selector`, so per §4.1 it needs a rejecting placeholder now if it is to remain additive. | S5 |
| **OQ-S2-07** | §2 gives an illustrative resource, not the normative structural OpenAPI schema with its literal CEL expressions, defaults, list-map keys, and `x-kubernetes-*` markers. The mechanisms are specified prose-precisely (§4, §4.1, §9), but an implementer still has to author the schema, and §4's whole point is that one wrong construct (a bare `enum: []`) silently reopens the hole. The normative schema must be produced and its admission behaviour verified against a non-strict client on a 1.29 cluster before implementation starts. | S7 (as a conformance fixture) |
