# Aksh — MVP Low-Level Design

This directory is the low-level design (LLD) for the **Aksh MVP**. It is the bridge between
the requirements in [`../README.md`](../README.md) and the feasibility evidence in
[`../FEASIBILITY.md`](../FEASIBILITY.md) on one side, and implementation on the other.

It is written to be read by a human engineer and executed by an AI implementer. Nothing in
this directory is code, and no code exists yet.

## Scope

| | |
| --- | --- |
| **In scope (MVP)** | FR1–FR9, **egress only** |
| **Out of scope (v1+)** | FR10–FR15, ingress interception |
| **Rule** | v1 features must land as **additive-only** changes. Every document ends with a *v1 forward-compatibility* section that names its extension points and argues why no breaking change is required. |

The MVP boundary comes from the roadmap in the root [`README.md`](../../README.md): MVP is
"secure token custody for kagent", v1 is "agent runtime policy boundary".

## Reading order

The documents are sequential. Each one assumes the vocabulary, interfaces, and decisions of
the ones before it. **S0 is required reading**; everything else depends on it.

| # | Document | What it answers | Status |
| - | -------- | --------------- | ------ |
| S0 | [`S0-architecture.md`](S0-architecture.md) | What are the pieces, who is the adversary, what must always be true, and what are the named contracts between components? | ✅ Reviewed |
| S1 | [`S1-data-plane.md`](S1-data-plane.md) | How does a packet get from the agent into Aksh, get decrypted, and reach the real upstream? | ✅ Reviewed |
| S2 | [`S2-policy-crd.md`](S2-policy-crd.md) | What does an `AkshPolicy` look like, and how is a request matched against it deterministically? | ✅ Reviewed |
| S3 | [`S3-token-broker.md`](S3-token-broker.md) | How does Aksh get, cache, refresh, and protect credentials the agent must never see? | ✅ Reviewed |
| S4 | [`S4-enforcement-pipeline.md`](S4-enforcement-pipeline.md) | In what order do those pieces run per request, and what happens when any of them fails? | ✅ Reviewed |
| S5 | [`S5-injection-pki.md`](S5-injection-pki.md) | How does Aksh get into the pod, and how is the MITM certificate authority managed safely? | ✅ Reviewed |
| S6 | [`S6-observability.md`](S6-observability.md) | What evidence does every decision produce, and what does the operator see? | ✅ Reviewed |
| S7 | [`S7-security-testing.md`](S7-security-testing.md) | How can this be bypassed, and how do we prove it works? | ⬜ Not started |

Status legend: ⬜ Not started · 🟡 Drafted · 🟠 In review · ✅ Reviewed

## Document conventions

### Required sections

Every `SN-*.md` document uses this skeleton, in this order:

| Section | Purpose |
| ------- | ------- |
| **Scope** | What this document decides, and explicitly what it does not. |
| **Requirements covered** | The FR/NFR IDs this document is accountable for. |
| **Design** | The substance. Subsections are per-document. |
| **Interfaces** | The named contracts this document defines or implements, as Go interface blocks. Each interface is defined in exactly one document and referenced elsewhere by name. |
| **Failure modes** | A table of failure × observable behavior × response. Must be consistent with the fail-closed matrix in S4. |
| **Decisions (ADRs)** | Numbered records: context → options → decision → consequences. |
| **v1 forward-compatibility** | **Mandatory.** Names the extension points and shows how the v1 requirements in this area attach additively. |
| **Open questions** | Anything deliberately unresolved, with the stage that must close it. |

### Style rules

- **Precise where it is a contract, prose where it is an algorithm.** Interfaces, CRD
  schemas, wire formats, metric names, and audit field names are specified exactly.
  Algorithms are described in prose or pseudocode, not Go function bodies.
- **No unexplained networking jargon.** Terms are defined once in the S0 glossary and used
  consistently thereafter. Assume a competent backend engineer with no networking
  background.
- **Every "must" is testable.** If a statement cannot be turned into a test case, it is
  either a decision (put it in an ADR) or a wish (delete it).
- **Name the requirement.** Design statements that exist to satisfy a requirement cite the
  FR/NFR ID inline.
- **PoC is evidence, not design.** The feasibility proof-of-concept proves mechanisms work.
  Where the PoC took a shortcut that is unsafe in production, the relevant document must
  explicitly close it.
- **Diagrams in mermaid**, so they render on GitHub and stay diffable.

### Identifier conventions

| Kind | Convention | Example |
| ---- | ---------- | ------- |
| ADR | `ADR-SN-NN` | `ADR-S2-03` |
| Open question | `OQ-SN-NN` | `OQ-S1-02` |
| Requirement | as in [`../README.md`](../README.md) | `FR5` |

## Process

Each document is drafted, then adversarially reviewed twice — once for logic errors and
gaps, once for completeness against the requirements, cross-document consistency, security
posture, and whether its forward-compatibility claim actually holds. Findings are applied
to the document. A stage is complete, and the next stage begins, only when the review
returns no must-fix findings.

Review transcripts are not kept in the repository; their outcome is the document itself and
the ADRs and open questions recorded in it.

## Open questions — the reconciled register

Each document carries its own *Open questions* table; this is the single reconciled view, and
it is the authoritative one. Where a question was restated across documents, the aliases are
listed together — the row count exceeds the
question count because several were restated across documents. Both Tier 1 questions are now
**resolved by source analysis**; what remains is artefacts, numbers and sign-off.

Ordered by what they block, not by document.

### Tier 1 — resolved by source analysis of kagent

Both questions that could have changed the design have been answered by reading kagent's source
(clone analysed at `kagent-dev/kagent@main`). One came back well, one did not.

| Question | Answer |
| -------- | ------ |
| Does kagent's runtime honour `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`? | **Yes.** The lock resolves `httpx` to 0.28.1, which consults `SSL_CERT_FILE` before falling back to `certifi`. CA distribution works as designed. Two residual obligations: the specifier is `>=0.25.0` and httpx **before 0.28 ignored** the variable, so `httpx >= 0.28` becomes a supported-version requirement asserted at runtime rather than assumed; and AWS Bedrock needs `AWS_CA_BUNDLE` as well. |
| What protocols do agents actually speak? | LLM providers over HTTPS with SSE-over-POST streaming; MCP over `SSE` or `STREAMABLE_HTTP` only; A2A over JSON-RPC. **No WebSocket** in any declared transport. **But four in-cluster legs are plaintext `http://`** — the controller, A2A subagents and MCP servers — constructed by kagent's own controller and used on every turn. |

**The plaintext finding changed the design.** The draft rejected all non-TLS traffic, which
would have severed every agent from its own controller and made the MVP non-functional on its
primary target. ADR-S1-05 and S1 §6.1 now support in-cluster plaintext, anchored on the
kernel-attested destination resolved through the Service registry rather than on anything the
agent claims. The assurance is deliberately lower than the TLS path and is marked as such.

That change was itself reviewed — it was the only unreviewed design in the set — and the review
found five must-fix problems in it, including a real hole: a **selectorless Service with manual
`EndpointSlice`s can point at arbitrary external IPs**, so "the destination is a ClusterIP" did
not mean "the backend is in the cluster", and a brokered credential could have left the cluster
in plaintext while the document claimed otherwise. The resolution rules are now stricter (exact
ClusterIP index rather than an inferred service CIDR; selector-backed Services with a ready
in-cluster Pod endpoint; Service UID and generation bound into the decision, the audit record
and the connection pool).

Three items fell out and are **new**:

- **OQ-S1-07** — ClusterIP resolution needs Services *and* EndpointSlices read access, a real
  privilege increase over the `akshpolicies`-only grant.
- **OQ-S1-08** — the cluster domain is conventionally `cluster.local` but not guaranteed, and a
  wrong value makes every plaintext policy fail to match.
- **B54** — kagent's OTLP exporter defaults to plaintext gRPC (h2c on 4317). It is denied as
  T5 today, so **telemetry is broken until someone decides** between supporting h2c and
  requiring OTLP over TLS. This now gates the definition of done.

### Tier 2 — artefacts that do not exist yet

The design is decided; the thing is not written.

| Artefact | Question | Note |
| -------- | -------- | ---- |
| **Normative CRD schema** — literal OpenAPI, CEL expressions, defaults, list-map keys | OQ-S2-07 | The largest single gap. S2 ships an *illustrative* resource, and §4's entire pruning defence depends on getting one construct right — a bare `enum: []` was measured to fail on a live 1.29 cluster |
| Audit field-presence matrix, per outcome | — | Early denials have no validated request, policy or credential; S6 presents those objects as always present |
| One authoritative metric table — producer, full label set, enum values | — | S1, S3, S5 and S6 currently disagree on names and labels |
| INV-1…INV-10 → test-ID matrix | — | Several invariants are asserted with no named test |
| S0 interface-inventory completeness | — | `Disposition`, `AcquireErrorClass`, S2's compiled types and S6's label types cross boundaries unregistered |

### Tier 3 — numbers that do not exist yet

| Question | Aliases | Note |
| -------- | ------- | ---- |
| Sidecar resource requests/limits **and** every S1 bound | OQ-S1-01, OQ-S5-04 | One decision, not two: the bounds derive from the limits. A bound without a number is not testable |
| CA cryptographic profile and lifetime | OQ-S5-09 | Algorithm, constraints, validity, and what happens when a pod outlives its CA given in-place rotation is forbidden |
| Entra federated-credential shape — per ServiceAccount or per namespace | OQ-S3-01, OQ-S5-05 | Needs a real tenant; start the access request early |
| iptables backend detection (`legacy` vs `nft`) | OQ-S1-04, OQ-S5-07 | S1 §1.3's pre-flight probe is the fail-closed backstop, so a wrong guess is disruptive rather than dangerous |
| Audit record size bound | OQ-S6-03 | The audit write is on the request path |
| Requested token lifetime | OQ-S3-02 | The only lever on the revocation window (S3 §7) |

### Tier 4 — product sign-off, not engineering

The four deviations in S0's register: **DEV-01** (FR2, DNS), **DEV-02** (FR7, MCP tool-level),
**DEV-03** (FR7, API category), **DEV-04** (FR2, egress-only). A design document cannot accept
its own deviations. DEV-04 is a genuine conflict between the MRD and the roadmap and needs
someone to choose. This gates release, not start.

### Tier 5 — measure or decide during implementation

OQ-S4-03/OQ-S6-01 (audit write budget), OQ-S1-05 (per-hop latency), OQ-S2-03 (watch scaling),
OQ-S5-06 (`hostUsers` analysis), OQ-S5-02 (agent `TokenRequest` permission — note this defeats
INV-1 if unchecked, so it needs an install-time check even though it is not a design decision),
OQ-S5-10 (quota activation), OQ-S5-11 (injector upgrade skew), OQ-S6-02 (owned audit file),
OQ-S3-03/04, OQ-S2-02/05, OQ-S0-12 (local development), OQ-S7-02/03/04.

### Tier 6 — explicitly v1, not MVP gaps

| Question | Aliases | Note |
| -------- | ------- | ---- |
| FR13's suspension-and-resume protocol | OQ-S0-07, OQ-S4-02 | S4 attempted to close this and the closure did not survive review: a closure-held store supplies *storage*, but FR13 needs a *protocol*. Does not block the MVP, which never returns `Pending` |
| Binding policy to an admission-controlled identity rather than mutable labels | OQ-S2-06, OQ-S5-08, OQ-S7-05 | Closes three accepted risks at once (B35, B36, B37), so it may be worth pulling forward |
| Proposing an `InitContainers` extension upstream to kagent | OQ-S0-08 | Would make a webhook-free path viable. Not blocking |

### Suggested sequence

~~CA-trust spike → protocol discovery~~ **(done)** → decide `allowPlaintext` and B54's
disposition → CRD schema (now unblocked, and it must carry `allowPlaintext` in rejecting form
per §4.1 since it cannot be added later) → resource limits and bounds together → the three
contract tables → implementation. Product sign-off runs in parallel throughout.

## Source of truth

- **Requirements:** [`../README.md`](../README.md) — derived from the MRD, *"Aksh — Security
  Sidecar for Kagents"*.
- **Validated mechanisms:** [`../FEASIBILITY.md`](../FEASIBILITY.md).

## Current state

All eight documents are drafted, reviewed and merged. S0–S5 had two adversarial passes each;
S6 and S7 had one each plus a final end-to-end pass across the whole set. Both Tier 1 open
questions were subsequently closed by source analysis of kagent, one of which forced a design
change (ADR-S1-05, in-cluster plaintext support).

The design is **not** implementation-ready as it stands. S7 §7's definition of done lists the
gates that remain — most importantly the kagent CA-trust spike (OQ-S7-01), the normative CRD
schema (OQ-S2-07), the resource bounds, and product sign-off on the four recorded deviations.
Those are named deliberately rather than papered over.

Each completed document went through the loop above and the reviews found substantive defects
that were fixed rather than waved through — several were caught by empirical testing rather
than argument:

| Stage | A defect the review caught |
| ----- | -------------------------- |
| S0 | `extraContainers` cannot deliver enforcement (kagent exposes no `InitContainers`), so the mutating webhook is not optional; and Kubernetes *prunes* unknown CRD fields rather than rejecting them, which inverts the whole compatibility strategy |
| S1 | A bare `-o lo -j RETURN` exclusion also matches the pod's **own routable IP**, silently bypassing interception entirely — reproduced in a network namespace |
| S2 | An empty CEL `enum: []` enforces nothing — reproduced on a live v1.29.14 cluster, where a v1-only constraint was silently accepted and persisted |
| S3 | Go's `fmt` cannot call `String()` on a value reached through an **unexported** field, so the "redacting secret type" printed raw tokens under `%v`, `%+v` and `%#v` — reproduced directly |

Anyone resuming should read S0 first, then the *Open questions* table of each completed
document: several are explicitly owed by a later stage, and S3–S7 are expected to close them.
