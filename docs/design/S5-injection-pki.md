# S5 — Injection, PKI & Lifecycle

> **Status:** Reviewed (2 passes) · **Depends on:** S0, S1, S2, S3 · **Depended on by:** S6 (what to expose), S7 (bypass and upgrade testing)

How Aksh gets into a pod, how the CA that makes MITM possible is managed, and how the whole
thing starts, rotates and stops without opening a window.

---

## Scope

**Decides:** the two admission webhooks and their configuration; the injected pod shape; the
UID reservation; startup and shutdown ordering; CA scope, storage, rotation and trust
distribution; the webhook's own serving certificate; RBAC; kagent integration; and upgrade.

**Does not decide:** what the sidecar does with traffic (S1), policy (S2), tokens (S3), or
ordering within a request (S4).

## Requirements covered

**FR1** (run as a sidecar for kagent workloads) and the deployment half of **FR2** (be injected
into the network path). Enforces **INV-2** (CA key never leaves), **INV-10** (pod
admissibility), and the ordering half of **INV-4** (an unready Aksh must not mean an
unprotected agent).

---

## Design

### 1. Two webhooks, not one

ADR-S0-05 makes the webhook the only enforcement path; ADR-S0-12 makes it `failurePolicy: Fail`
and adds a validating webhook. This section is those decisions realised.

| | Mutating | Validating |
| --- | --- | --- |
| Resource | `pods` CREATE | `pods` CREATE, `pods/ephemeralcontainers` UPDATE |
| Job | Inject `aksh-init` + `aksh-proxy`, volumes, and CA trust | Assert the final pod satisfies INV-10 |
| `failurePolicy` | `Fail` | `Fail` |
| `reinvocationPolicy` | `IfNeeded` | — |
| Scope | **every** pod in a namespace labelled `aksh.dev/injection=enabled` | the same set — identical scope |

**There is no pod-level opt-out at all.** A first draft allowed `aksh.dev/inject: "false"`, and
a second kept it for the mutator only. Both are wrong for the same reason: annotations are set
by whoever authors the pod spec, which in this threat model is the hostile party. An opt-out is
a zero-authentication, self-service way to run without iptables rules and without a proxy — and
no amount of *validating* UIDs and capabilities compensates for a pod that simply has no
interception (INV-3).

Exemption is therefore an **operator** decision expressed where only an operator can express it:
the namespace label. A workload that must not be intercepted goes in an unlabelled namespace.
The granularity is coarser and that is the point — protection is not something the protected
party may decline.

**Why the validating webhook is not optional.** A mutating webhook cannot guarantee the shape
of the *admitted* pod. Other mutating webhooks run after ours — a mesh injector, a policy
engine, a future controller — and may remove our containers, add one claiming the reserved
UID, or restore a dropped capability. Our mutator has already returned by then. The validating
webhook runs after **all** mutation and is the only place the final shape can be checked.

`reinvocationPolicy: IfNeeded` matters for the reverse case: if a later webhook adds a
container, we want to be re-invoked so the pod is re-examined. Our patch must therefore be
**idempotent** — keyed on a marker annotation `aksh.dev/injected: <version>`, and a no-op when
already present at the same version.

**Ephemeral containers are covered.** `kubectl debug` attaches a container to a running pod
via a subresource that bypasses the CREATE path entirely. Without the UPDATE rule, an operator
could attach a container claiming the reserved UID and egress uncontrolled — through a
supported, unremarkable-looking command.

### 2. The injected pod

```yaml
metadata:
  annotations:
    aksh.dev/injected: "v0.1.0"
spec:
  automountServiceAccountToken: false  # the agent must not receive an API token (§4)
  initContainers:
    - name: aksh-init                 # ordinary init container: runs, programs, exits
      securityContext:
        runAsUser: 0
        capabilities: { add: ["NET_ADMIN", "NET_RAW"], drop: ["ALL"] }
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
    - name: aksh-proxy                # NATIVE SIDECAR — an initContainer that never exits
      restartPolicy: Always           # this is what makes it a sidecar (k8s ≥1.29)
      securityContext:
        runAsUser: 1774               # the reserved UID — see §3
        runAsGroup: 1774
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
        readOnlyRootFilesystem: true
        seccompProfile: { type: RuntimeDefault }
      startupProbe:                   # exec, NOT tcpSocket — see §5
        exec: { command: ["/usr/local/bin/aksh", "probe", "--startup"] }
        periodSeconds: 1
        failureThreshold: 30
      readinessProbe:                 # ongoing: snapshot freshness, audit sink, self-test
        exec: { command: ["/usr/local/bin/aksh", "probe", "--ready"] }
        periodSeconds: 5
      volumeMounts:
        - { name: aksh-ca-pub,   mountPath: /var/run/aksh/ca, readOnly: false }  # writer
        - { name: aksh-ca-priv,  mountPath: /var/run/aksh/ca-private }           # §6.1
        - { name: aksh-token,    mountPath: /var/run/aksh/token, readOnly: true }
        - { name: aksh-api-token, mountPath: /var/run/aksh/api, readOnly: true }
        - { name: aksh-downward, mountPath: /var/run/aksh/pod, readOnly: true }
  containers:
    - name: <agent>                   # untouched except for trust configuration
      env:
        - { name: SSL_CERT_FILE,        value: /var/run/aksh/ca/ca.pem }
        - { name: REQUESTS_CA_BUNDLE,   value: /var/run/aksh/ca/ca.pem }
        - { name: NODE_EXTRA_CA_CERTS,  value: /var/run/aksh/ca/ca.pem }
      volumeMounts:
        - { name: aksh-ca-pub, mountPath: /var/run/aksh/ca, readOnly: true }
  volumes:
    - name: aksh-ca-pub               # PUBLIC certificate only — never the key (INV-2)
      emptyDir: {}                    # written by aksh-proxy, read-only into the agent
    - name: aksh-ca-priv              # CA key; mounted ONLY into aksh-proxy — see §6.1
      emptyDir: {}
    - name: aksh-token                # Entra-audience token — aksh-proxy ONLY (S3 §1)
      projected:
        sources:
          - serviceAccountToken: { audience: api://AzureADTokenExchange, path: token }
    - name: aksh-api-token            # API-audience token, for the AkshPolicy watch (S2 §7)
      projected:                      # separate from the Entra one so neither is over-scoped
        sources:
          - serviceAccountToken: { path: token }
    - name: aksh-downward             # pod labels for selector evaluation (§7, closes OQ-S2-01)
      downwardAPI:
        items:
          - { path: labels, fieldRef: { fieldPath: metadata.labels } }
          - { path: namespace, fieldRef: { fieldPath: metadata.namespace } }
          - { path: name, fieldRef: { fieldPath: metadata.name } }
          - { path: uid, fieldRef: { fieldPath: metadata.uid } }   # S6 audit attribution
```

Three details carry weight:

- **`aksh-proxy` is a native sidecar**, not an ordinary container: an `initContainer` with
  `restartPolicy: Always`. Kubernetes then starts it before app containers and stops it after
  them (ADR-S0-10). Ordinary containers have no ordering at all.
- **`aksh-init` is a plain init container** that runs before it, so rules exist before the proxy
  and long before the agent. Ordering is `aksh-init` → `aksh-proxy` (ready) → agent.
- **The token volume is mounted only into `aksh-proxy`.** Mounting it pod-wide would hand the
  agent the credential the whole design exists to withhold (INV-1, INV-10).

### 3. The reserved UID — closing OQ-S0-06

S1's interception excludes exactly one UID. Anything running as that UID egresses uncontrolled,
so the reservation is a **total** bypass if the workload can claim it.

**Aksh reserves UID/GID 1774.** Not 1337: that is Istio's, and a pod carrying both would have
each tool's exclusion silently whitelist the other's proxy.

The reservation is enforced at admission, not by convention. A container that leaves
`runAsUser` unset resolves it from the image at runtime, which admission cannot see — so
"not obviously 1774" is not good enough, and every container must carry an explicit UID.

**But requiring the author to supply it would reject the primary target workload.** kagent's
translator passes `securityContext` straight through and sets nothing by default, so a stock
`Agent` produces a pod with no `runAsUser` at all. A validator that simply rejected it would
mean no kagent agent could be protected without hand-patching every deployment — FR1's own use
case failing at the first step.

So the two webhooks split the work (closing OQ-S5-03):

- The **mutating** webhook *defaults* **every** field the validator requires and the author
  omitted — `runAsUser` (a fixed non-reserved UID), `runAsGroup`, `runAsNonRoot: true`,
  `allowPrivilegeEscalation: false`, `privileged: false`, `capabilities.drop: [ALL]` with an
  empty `add`, and `automountServiceAccountToken: false`. Defaulting only `runAsUser` would
  still have rejected stock kagent, which supplies none of the others either. Where the author
  *did* supply a conflicting value, the pod is **rejected** rather than silently overwritten:
  normalising an absent field is helpful, overriding a stated intention is not. Normalisation
  re-runs on reinvocation, since a later webhook may strip what we set.
- The **validating** webhook then rejects any container — including init, sidecar and ephemeral
  containers — that has `runAsUser: 1774`, or that still lacks an explicit UID after mutation
  (which can only happen if a later webhook removed it).

Combined with `runAsNonRoot: true` and dropped `SETUID`/`SETGID`, a container cannot reach the
reserved UID either statically or dynamically. Defaulting does change the pod, which is a real
cost — an image expecting its own default UID may fail to start — so the chosen UID is
configurable and the change is surfaced in the annotation rather than applied silently.

### 4. The admissibility profile — enforcing INV-10

The validating webhook rejects a pod, with the offending field named, unless:

| Check | Rejects |
| ----- | ------- |
| Every non-Aksh container declares an explicit `runAsUser` **within `1..2147483647`** and ≠ 1774, plus `runAsNonRoot: true` | UID impersonation and image-default UIDs — **and integer aliasing**: a plain inequality check passes `runAsUser: 4294969070`, which narrows to 1774 on runtimes that truncate to `uint32`. Bounding the range closes it. |
| `aksh-init` and `aksh-proxy` are the **first two init containers**, in that order | A pre-existing init container would otherwise run — and egress — before any rule exists |
| Aksh's container names, image digests, volume names and mount paths match the canonical shape exactly | Name-based trust is forgeable: a container merely *named* `aksh-proxy` would inherit every exception. Images are digest-pinned, and the marker annotation is a hint for humans, never proof of injection — the validator re-derives the shape rather than trusting the marker. |
| Every non-Aksh container sets `allowPrivilegeEscalation: false`, `privileged: false`, `capabilities.drop: [ALL]`, **and an empty `capabilities.add`** | `drop: [ALL]` does **not** forbid adding back — `add: ["SETUID"]` alongside it is legal and lets a container become UID 1774, a total bypass. `privileged: true` must be rejected explicitly for the same reason. |
| `aksh-init` is the **only** container permitted a non-empty `capabilities.add`, and only `NET_ADMIN`/`NET_RAW` | rule tampering, raw sockets bypassing NAT |
| `shareProcessNamespace` and `hostPID` are false | reading proxy memory for tokens and the CA key |
| `hostNetwork` is false | pod-level iptables rules would not apply at all |
| `automountServiceAccountToken: false` on the pod, and no ServiceAccount-token volume is mounted into any non-Aksh container | Otherwise Kubernetes mounts an API token into the hostile agent. That token belongs to the **pod's** ServiceAccount — the same one carrying Aksh's policy-read RBAC — so the agent would inherit it. Aksh projects what it needs explicitly instead (§2). |
| `aksh-token`, `aksh-api-token` and `aksh-ca-priv` are mounted only into `aksh-proxy` | direct credential theft |
| `hostUsers` is **not** `false` — i.e. user namespaces are rejected pending analysis | The reserved-UID mechanism keys iptables `--uid-owner` on the in-namespace UID, and capability semantics are relative to the owning user namespace. No concrete bypass was identified, and `capabilities.drop: [ALL]` should still hold — but the interaction is unanalysed on a feature that is stable and reachable at our floor, and the whole interception model rests on UID semantics. Rejected until proven composable, consistent with how Istio coexistence is handled. Recorded as OQ-S5-06. |
| The pod does not already carry an Istio sidecar | undefined composed interception (S1 §1.5). Detected by the presence of a container named `istio-proxy` **or** the `sidecar.istio.io/status` annotation — checking both, since either alone is evadable |
| `aksh-ca-pub` is mounted `readOnly: true` into every container except `aksh-proxy` | An agent that could rewrite its own trust anchor only breaks its own connections, so this is completeness rather than a live vulnerability — but a checklist that does not police the volume it ships is a checklist that will drift |
| Applies equally on `pods/ephemeralcontainers` UPDATE | attach-a-debug-container bypass |

Pod Security Admission at **`baseline`** is the prerequisite. `restricted` cannot be used:
`aksh-init` runs as UID 0 and adds `NET_ADMIN`, both of which `restricted` forbids, and PSA has
no per-container exception. Aksh's validator therefore carries the restricted-equivalent checks
itself, plus the ones PSA never makes — the reserved UID above all.

### 5. Startup and shutdown

**Startup** is the dangerous window, because `aksh-init` installs rules regardless of whether
`aksh-proxy` is listening. Between those two events, agent traffic is redirected to a port
nobody is accepting on: fail-closed, but indistinguishable from a broken deployment.

Native sidecar ordering closes it, *provided* readiness means the right thing. Kubernetes gates
app-container start on the sidecar's **startup probe**.

A `tcpSocket` probe only proves that a TCP handshake completed — which is true the instant the
process calls `listen()`, regardless of whether it has done anything else. An ordinary
implementation that binds early and finishes initialising afterwards would pass the probe
immediately and reopen the very window this section claims to close. The probe type is not what
carries the safety property, so the requirement is stated on the process instead:

> **`aksh-proxy` MUST NOT bind or listen on the data-plane port until all of the following have
> succeeded:** S3's local-only startup self-test (§4.1), S2's first policy snapshot (§7), and
> CA generation with the public certificate written to `aksh-ca-pub` (§6.1).

Deferring the bind is necessary but **not sufficient**, because a `tcpSocket` probe targets the
*pod IP*, which every container shares. During a proxy-only restart the hostile agent could bind
`:15001` itself and satisfy the probe while Aksh is still initialising — the probe would confirm
that *something* is listening, not that Aksh is. The startup probe is therefore an **`exec`**
probe that asks the proxy process directly, so listener ownership is never in doubt.

A second `exec` **readiness** probe covers the ongoing case a startup probe cannot: S2's snapshot
going stale, S3's local self-test regressing, or the audit sink failing after start.

This is the mechanism S0's INV-4 startup-ordering row assigns to S5. It lives in the process,
not the manifest — S7 must assert the data-plane port is *refused* during initialisation, and
must include the agent-binds-the-port case.

**Restart cases** need stating separately, because a startup probe only covers the first one:

| Case | Behaviour |
| ---- | --------- |
| Initial pod start | `aksh-init` → `aksh-proxy` (startup probe) → agent. Window closed. |
| Proxy-only restart | Rules persist; agent egress fails closed while the proxy is down; the CA reloads (§6.1.1) so agent trust survives; the exec probe prevents the agent binding the port from masking it. |
| Agent-only restart | Proxy unaffected; the agent re-reads `ca.pem`, which is unchanged. |
| Node reboot / sandbox recreation | Treated as an initial start — `emptyDir` contents are lost, so a new CA is generated, which is correct because the agent is also new. |

S7 owns this as a lifecycle conformance matrix.

**Shutdown** is the mirror image, and native sidecars terminate after app containers.
`aksh-proxy` handles `SIGTERM` by refusing new connections while draining in-flight ones. Its
drain window is **not** the full `terminationGracePeriodSeconds`: app containers are signalled
first and must exit before sidecars receive `SIGTERM`, and all containers share **one** pod-level
budget. The proxy therefore gets whatever the agent's own shutdown leaves behind, which may be
very little. This does not threaten correctness — ADR-S5-04 means the rules stay regardless —
but it does mean the grace period must be tuned for both, and S7's conformance tests must not
assume the proxy has the whole budget. It does **not** remove the iptables rules: a pod whose proxy is
gone but whose rules remain fails closed, whereas removing rules first would give a still-running
agent a window of unmediated egress. The rules die with the network namespace.

### 6. CA and PKI

#### 6.1 Scope: one CA per pod

The CA that signs MITM leaves is generated **by `aksh-proxy`, in memory, at startup, per pod**.

The alternative — a cluster or namespace CA distributed to every sidecar — is rejected. Its
private key would exist in every agent pod, so compromising *one* sidecar would yield a key
trusted by *every* agent, letting the attacker impersonate any upstream to any workload. A
per-pod CA confines that to one pod, which is already compromised.

The CA certificate must reach the agent's trust store in the same pod. It travels through a
shared `emptyDir` (`aksh-ca-pub`) that `aksh-proxy` writes and the agent mounts **read-only**.
Ordering (§5) guarantees the agent starts only after the proxy is ready, and the proxy writes
the certificate before it begins listening — so the file always exists by the time any agent
process runs.

#### 6.1.1 The CA must survive a sidecar-only restart

An earlier draft kept the CA purely in memory and asserted that "rotation is a proxy restart,
which is a pod restart". **That is false for native sidecars**, and the error is consequential.
Sidecars have independent restart lifecycles: an OOM-kill or liveness restart of `aksh-proxy`
does **not** restart the agent. A fresh in-memory CA would then be signed by a key the
still-running agent has never seen — and HTTP clients typically load their trust store once at
process start, so *every* subsequent agent request would fail TLS verification, permanently,
until someone deleted the pod. Fail-closed, but a genuine and entirely avoidable outage
triggered by any transient proxy fault.

The CA **key and its certificate** are therefore persisted together to `aksh-ca-priv`, an
`emptyDir` mounted **only into `aksh-proxy`**. The contract is precise, because "generate if
absent" is not by itself safe:

- On start the proxy loads the existing key **and** certificate. Persisting only the key would
  let a restart mint a *different* certificate from the same key, and the agent pinned the
  certificate.
- Generation happens **exactly once per pod**, written atomically (temp file, `fsync`, rename)
  so a crash mid-write cannot leave a half-written pair that the next start treats as absent and
  silently rotates beneath a live agent.
- On reload the proxy verifies the certificate matches the key and matches the copy already
  published in `aksh-ca-pub`. **Any mismatch is fatal** — it means the agent trusts something we
  can no longer sign for, and failing to start is the only honest response.
- `CAProvider.Generation()` changes only when the CA genuinely changes, which within a pod's
  life means never. A proxy restart empties S1's in-memory leaf cache anyway; it must not be
  mistaken for a rotation, or S1 would invalidate on every restart for no reason.

This refines INV-2 and the refinement is stated rather than glossed: the invariant's purpose is
that **the agent container can never read the CA key**, and a volume mounted into no other
container upholds that. What it gives up is "never written to disk at all" — the key now exists
in an `emptyDir`, which is node-local storage readable by root on the node. That is acceptable
only because node compromise is explicitly outside the threat model (S0 §6); if that ever
changes, this decision is the first to revisit. The alternative — accepting a permanent agent
outage on any proxy restart — trades a real availability failure for a defence against an
attacker the model already concedes.

Leaves are short-lived and minted from a long-lived ECDSA key (S1 §3.1). CA *rotation* remains a
pod restart, which is now an honest statement rather than an assumed one.

#### 6.2 Trust distribution — and its honest limit

The agent must trust the Aksh CA or every request fails TLS verification. The mechanism is the
three environment variables in §2, covering the common Go, Python-requests and Node runtimes.

This is **best-effort, and the design must say so.** A runtime that pins certificates, or that
uses a bundled trust store such as Python's `certifi` rather than the system one, will not
honour them. OQ-S0-02 asks precisely this of kagent's Python runtime and is **not yet answered**
— it is restated here as OQ-S5-01 because it is now blocking: if kagent's HTTP client ignores
`REQUESTS_CA_BUNDLE`, transparent interception of kagent agents does not work at all, and no
amount of correct design elsewhere compensates.

The fallback, if it proves necessary, is to also write the CA into the image's system trust
bundle location — which requires a writable path in the agent container and is therefore a
different, more invasive shape.

#### 6.3 The webhook's own certificate

`aksh-injector` serves TLS to the API server, so it needs a certificate the API server trusts —
a bootstrap problem, since it cannot inject its own.

Idempotence alone does **not** make this safe across replicas: two replicas self-signing
independently would publish different certificates and race to patch `caBundle`, so admission
would intermittently fail closed depending on which replica the Service routed to.

The contract is therefore:

- The install creates an **empty Secret** of a fixed name. Replicas bootstrap into it with a
  **compare-and-swap** (`resourceVersion` precondition): exactly one wins and generates the
  material, the losers re-read it. No replica serves until it has loaded the shared material, so
  every replica presents the same certificate.
- `caBundle` is patched from the same shared material, so it always matches what is served.
- Rotation is **two-phase**: publish a `caBundle` trusting both old and new, wait for all
  replicas to load the new leaf, then drop the old. A single-phase swap would strand replicas
  behind one Service serving a certificate the API server no longer trusts.
- Pre-creating the Secret also removes the need for `create` on secrets, which cannot be scoped
  to a name — only `get`/`update` on one named object, which can.

This avoids a cert-manager dependency for a single certificate; if a cluster already runs
cert-manager, ADR-S5-03 is the first thing worth revisiting.

### 7. RBAC

| Subject | Grants |
| ------- | ------ |
| `aksh-proxy` | **read-only** on `akshpolicies` in its own namespace. Nothing else. Not pods (§8), not secrets, not tokens. |
| `aksh-injector` | read pods and namespaces; patch its own two webhook configurations by name; read/write its own serving-cert Secret |
| The **agent's** ServiceAccount | must **not** hold `create` on `serviceaccounts/token` for the Entra audience — otherwise it mints the federation token itself and brokers its own credentials (S3 §1). The validating webhook cannot check this; it is an install-time and audit-time obligation, recorded as OQ-S5-02. |

**Closing OQ-S2-01:** the sidecar evaluates `spec.selector` against **its own pod's labels,
supplied via the Downward API** — not by listing pods. It only ever needs to know whether a
policy selects *itself*, so pod read access would be strictly more privilege than the task
requires. Labels are projected as a file and re-read on change.

### 7.1 Install-time manifests

Two things the install ships that are easy to lose because they are not part of the pod shape:

- **A `ResourceQuota` limiting `akshpolicies` per namespace** (recommended **64**), which S2 §9
  identifies as the *only* bound on a hostile-author denial-of-service: a watch cannot
  server-side filter CRDs by selector, so every sidecar in a namespace receives and parses every
  policy, including ones that do not select it. Per-agent rule limits cannot bound that; only a
  cap on object count can.
- **`PodSecurityAdmission` at `baseline`** on protected namespaces — **not `restricted`**, which
  would reject Aksh's own `aksh-init` (UID 0, `NET_ADMIN`) and therefore every protected pod.
  PSA has no per-container exception mechanism, so the restricted-equivalent checks live in
  Aksh's validating webhook (§4) with one narrowly-scoped `aksh-init` exception.

### 7.2 `aksh-injector` availability

`failurePolicy: Fail` makes the injector availability-critical for pod *creation* in protected
namespaces (ADR-S0-12 assigns this to S5). The posture:

| | |
| --- | --- |
| Replicas | **≥ 2**, with anti-affinity across nodes |
| Disruption | a `PodDisruptionBudget` of `minAvailable: 1` |
| Webhook `timeoutSeconds` | **5** — short, because the API server blocks on it; the work is CPU-only with no external calls, so a longer timeout only lengthens outages |
| Leader election | **not used.** Both webhooks are stateless request/response; the only shared state is the serving-cert Secret, and its rotation is made idempotent instead (§6.3) so two replicas racing converge rather than conflict |
| Injector upgrade | rolling, with the new replica passing readiness before the old is removed |

Note the asymmetry worth stating plainly: an injector outage stops *new* protected pods, and
does not affect running ones. That is the correct direction for a security control, but it does
mean an injector failure during a large rollout looks like a cluster-wide deployment freeze, so
its alerting is a first-class S6 concern rather than an afterthought.

### 8. kagent integration

`extraContainers` is a development convenience only (ADR-S0-05): kagent exposes no
`InitContainers`, so it cannot install the iptables rules before the agent starts.

**OQ-S0-01 — does kagent's controller reconcile away our mutations?** It does not, and the
reason is structural: kagent's controller owns the **Deployment**, while our webhook mutates
**Pods** created from it. The controller reconciles the Deployment's pod *template*, which it
compares against its own desired state; the injected containers exist only on the Pod object,
which the controller does not manage. Every rollout produces fresh pods that pass through the
webhook again.

The corollary is that our injection is invisible in the Deployment, so `kubectl get deploy -o
yaml` will not show it — a legitimate operability complaint, and the reason the marker
annotation exists on the pod.

Aksh does not require any kagent change for the MVP, and `Agent` CRDs need no modification:
enabling protection is a **namespace label**.

### 9. Upgrade and rollback

Upgrading the sidecar image changes the injected pod spec, which affects only **newly created**
pods. Existing agents keep running the old sidecar until they are restarted — deliberate: an
automatic restart of every protected workload on upgrade would be an outage disguised as a
patch.

The `aksh.dev/injected: <version>` annotation makes the fleet's state queryable, so an operator
can drive a rollout at their own pace.

**The injector must remain compatible with the sidecar version already running in pods**, since
the two versions coexist for the whole rollout. Rollback is symmetric — and, because
`failurePolicy: Fail`, an injector that crash-loops after upgrade blocks creation of protected
pods, which is why S7 must cover injector upgrade explicitly.

---

## Interfaces

```go
// CAProvider supplies the signing material S1's LeafSource uses, and reports a generation
// that invalidates the leaf cache on rotation.
type CAProvider interface {
    // Signer returns the CA certificate and key. The key is never exposed to the agent
    // (INV-2 as refined in §6.1.1): there is no accessor yielding private PEM, and the
    // only persistence is a volume mounted into aksh-proxy alone. Note this is NOT
    // "never leaves the process" — that wording was withdrawn, because an in-memory-only
    // CA breaks the agent's trust on any sidecar-only restart.
    Signer() (*x509.Certificate, crypto.Signer)
    // Generation increments on rotation. S1 keys its leaf cache on it (S1 §3.1).
    Generation() uint64
    // PublicPEM is what may be written to the shared volume for the agent's trust store.
    PublicPEM() []byte
}

// Injector renders the sidecar patch. One renderer, so the mutating webhook and any
// future path cannot drift into producing different pod shapes.
type Injector interface {
    Mutate(pod *corev1.Pod) (patch []byte, err error)
    // Admissible reports whether the FINAL pod satisfies INV-10. Used by the validating
    // webhook, and deliberately separate from Mutate: the pod it judges is not the pod
    // Mutate produced, because other webhooks run in between (§1).
    Admissible(pod *corev1.Pod) error
}
```

---

## Failure modes

| Failure | Behaviour |
| ------- | --------- |
| `aksh-injector` down | Protected pods cannot be created (`failurePolicy: Fail`). Running pods unaffected. |
| `aksh-init` fails (no `ip6tables`, wrong backend, probe fails) | Pod does not start — S1 §1.3 |
| `aksh-proxy` fails its startup probe | Agent containers never start (native sidecar ordering) |
| `aksh-proxy` crashes mid-life | Rules remain; agent egress fails closed; kubelet restarts it |
| Agent runtime ignores the CA env vars | **All agent TLS fails.** Loud, not silent — but a total functional break. OQ-S5-01 |
| Webhook serving cert expires | Admission fails closed; protected pods cannot be created |
| Pod violates INV-10 | Rejected at admission with the offending field named |

---

## Decisions (ADRs)

### ADR-S5-01 — One CA per pod, generated in memory
*Context.* The MITM CA could be cluster-wide, per-namespace, or per-pod.
*Decision.* Per-pod, generated once at first start and persisted — with its certificate — to a
volume mounted only into `aksh-proxy`, so a sidecar-only restart reloads rather than regenerates.
*Consequences.* Compromising one sidecar yields a CA trusted only by that pod's agent — which
is already compromised. A shared CA would have made one sidecar compromise into cluster-wide
upstream impersonation. Costs: no cross-pod certificate reuse (irrelevant, leaves are per-host
and cheap), and rotation equals restart (acceptable, since the CA's lifetime is the pod's).

### ADR-S5-02 — UID 1774, enforced at admission
*Context.* S1's interception excludes exactly one UID; claiming it is a total bypass.
*Options.* Istio's 1337; a random per-pod UID; a fixed Aksh UID.
*Decision.* Fixed **1774**, with admission rejecting any other container that claims it or that
fails to declare an explicit non-1774 UID.
*Consequences.* Avoids Istio's 1337, where co-installation would make each tool's exclusion
whitelist the other's proxy. A per-pod random UID was rejected: it would have to be known by
`aksh-init`, the proxy and the validating webhook, and the coordination is more fragile than the
thing it protects. Requiring an *explicit* UID on every container is mildly intrusive and is the
point — an unset `runAsUser` is invisible to admission.

### ADR-S5-03 — Self-signed webhook certificate, self-patched `caBundle`
*Context.* The injector needs a certificate the API server trusts, and cannot inject its own.
*Options.* cert-manager; a manual certificate; self-signing with self-patching.
*Decision.* Self-sign and patch its own `caBundle`.
*Consequences.* No cert-manager dependency for one certificate. Costs RBAC to patch two named
cluster-scoped objects — a real privilege, scoped as narrowly as the API allows. If a cluster
already runs cert-manager, this is the first thing worth reconsidering.

### ADR-S5-04 — Do not remove iptables rules on shutdown
*Context.* A tidy shutdown would restore the netns.
*Decision.* Leave the rules; they die with the namespace.
*Consequences.* A pod whose proxy has stopped but whose agent still runs fails **closed**.
Removing rules first would open a window of unmediated egress at exactly the moment supervision
is disappearing. Costs nothing real, since the namespace is torn down anyway.

---

## v1 forward-compatibility

| v1 need | Seam | Why additive |
| ------- | ---- | ------------ |
| **Ingress** | The same injector renders an additional listener port and inbound chain | The pod shape gains a port; nothing existing changes. |
| **FR15** NetworkPolicy / CNI anti-bypass | Install-time manifests plus a capture-backend selection in `aksh-init` | S0 reframed this as a capture-backend seam rather than "just manifests". S1's `DestinationResolver` is the interface; S5 chooses which backend to install. |
| **Istio coexistence** | Currently rejected at admission (§4) | Lifting the rejection is a relaxation, not a redesign — but requires S1's chain layout to compose, which is the actual work. |
| **cert-manager for the webhook** | `CAProvider` and the bootstrap are separate concerns | ADR-S5-03 can be swapped without touching the pod shape. |

---

## Open questions

| ID | Question | Closed by |
| -- | -------- | --------- |
| **OQ-S5-01** | ~~Does the kagent runtime honour `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`?~~ — **closed by source analysis: yes.** kagent's lock resolves `httpx` to **0.28.1**, whose `create_ssl_context` consults `SSL_CERT_FILE` before falling back to `certifi`; verified for the OpenAI, Anthropic, Ollama, google-genai, MCP and A2A clients. **Two caveats, both actionable:** the *specifier* is `>=0.25.0`, not a pin, and httpx **before 0.28 ignored** `SSL_CERT_FILE` — so `httpx >= 0.28` is a supported-version requirement on kagent that must be asserted at runtime, not assumed. And AWS Bedrock goes through botocore, which needs `AWS_CA_BUNDLE` set as well. The distroless image's `/etc/ssl/certs` is not writable by UID 65532, so the environment-variable path is the only one available — which is fine, since it works. §6.2's fallback is not needed. | *closed by evidence* |
| **OQ-S5-02** | The agent ServiceAccount must not hold `create` on `serviceaccounts/token` for the Entra audience (S3 §1), but the validating webhook cannot see RBAC. Is there a supported way to assert this at admission, or does it remain an install-time convention plus an audit check? | S7 |
| **OQ-S5-03** | ~~Reject pods lacking an explicit `runAsUser`, or default it?~~ — **closed in §3: default it.** Rejecting would have turned away stock kagent pods, which set no `securityContext` at all — FR1's own target failing at the first step. The mutator defaults every field the validator requires and the author omitted, **rejects** rather than overwrites a conflicting stated value, and records the normalisation in the marker annotation. | *closed in S5* |
| **OQ-S5-04** | §2's resource requests and limits are unspecified, and S1's bounds (OQ-S1-01) are supposed to be derived from them. The two must be decided together, with a measured working set rather than a guess. | S7 |
| **OQ-S5-09** | §6 does not specify the CA's cryptographic profile or lifetime: algorithm and size, path-length and name constraints, key file permissions, validity period, and what happens if a long-lived pod outlives its CA — in-place rotation being forbidden by ADR-S5-01, the answer has to be forced pod replacement before expiry, with S6 alerting on approaching expiry. | S6, S7 |
| **OQ-S5-10** | A static install cannot place a `ResourceQuota` (§7.1) into namespaces created later. Does enabling protection need to be an explicit activation step — an operator action that creates the quota and the baseline *before* applying the namespace label — so that protection cannot be switched on without its prerequisites? | S7 |
| **OQ-S5-11** | During a rolling injector upgrade, one admission's mutating and validating calls can hit different versions. Does that need N/N−1 cross-compatibility as a stated requirement, or versioned Services with an atomic switch? | S7 |
| **OQ-S5-06** | `hostUsers: false` (user namespaces) is rejected at admission pending analysis (§4). Does the reserved-UID exclusion survive a user namespace — specifically, does iptables `--uid-owner` in the pod netns see the in-namespace UID, and do dropped capabilities remain dropped? If it composes safely the rejection should be lifted, since user namespaces are a hardening feature we should not be blocking. | S7, by spike |
| **OQ-S5-07** | Inherited from **OQ-S1-04**: how does `aksh-init` detect whether the node's iptables is `legacy`- or `nft`-backed? S1 §1.3's pre-flight probe is a production fail-closed backstop, so a wrong guess fails the pod rather than silently under-enforcing — which downgrades this from dangerous to merely disruptive, but it still needs an answer. | S7 |
| **OQ-S5-08** | Inherited from **OQ-S2-06**: should a policy bind to the agent's ServiceAccount — an identity the injector controls — rather than to mutable pod labels? S2 notes that changing `spec.selector` later is a *narrowing* change needing a rejecting placeholder in the frozen schema, so deferring this has a real forward-compatibility cost. S5 is the natural home because the injector is what could supply an immutable identity. | S7 |
| **OQ-S5-05** | Which Entra federated-credential shape (OQ-S3-01) — per agent ServiceAccount, or per namespace with the SA as a claim — determines what the injector must configure at install time. Needs a real tenant. | S7 |
