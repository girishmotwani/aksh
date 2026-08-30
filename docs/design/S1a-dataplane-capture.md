# S1a: Data-Plane Capture and Connection Path (eBPF)

> Status: Conditionally approved for implementation - see the merge gates M1-M3 in section 6.7.3
> Phase: 5A
> Supersedes: S1 sections 1, 2, and the capture-related parts of section 3
> Superseded by: none
> Related: S0-architecture.md, S1-data-plane.md, S4-enforcement-pipeline.md,
> S5-injection-pki.md, S6-observability.md, S7-security-testing.md,
> interface-guide.md

## 1. Metadata

| Field | Value |
| ----- | ----- |
| Document id | S1a |
| Title | Data-Plane Capture and Connection Path (eBPF) |
| Status | **Conditionally approved for implementation.** The design is approved as a specification and implementation may start. Merge of the implementation is gated on the three kernel-behaviour validations M1-M3 in section 6.7.3, which close OQ-S1a-01 and OQ-S1a-08. Until M1-M3 are recorded with evidence, two fail-closed-critical behaviours are assumptions, and the code must not be merged as if they were facts |
| Phase | 5A (capture and connection path) |
| Branch | `impl/phase-5a-dataplane`, off `impl/phase-4-pipeline` |
| Supersedes | S1 sections 1, 2, and the capture-related parts of section 3 |
| Superseded by | none |
| Consumes | `internal/pki.CAProvider`, `internal/audit.MetricsRecorder`, `internal/audit.AuditSink`, `internal/policy.Transport`, `internal/pipeline.IdentityInput` |
| Implements | `internal/dataplane.DestinationResolver`, `internal/dataplane.LeafSource`, `internal/dataplane.UpstreamDialer` |
| Hands off to | 5B (request path and pipeline integration), 5C (pooling and resource-bound enforcement) |
| Empirical basis | `poc/ebpf-redirect` (validated proof of concept, kernel 5.15) |

### 1.1 Glossary

| Term | Meaning |
| ---- | ------- |
| Capture | The kernel-side mechanism that forces the agent's outbound TCP connections into the Aksh listener |
| Original destination | The address the agent passed to `connect()`, before Aksh rewrote it |
| Pod cgroup | The cgroup v2 directory that is the common ancestor of every container in this pod |
| `connect4` | A `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program with attach type `BPF_CGROUP_INET4_CONNECT` |
| `sock_ops` | A `BPF_PROG_TYPE_SOCK_OPS` program with attach type `BPF_CGROUP_SOCK_OPS` |
| Socket cookie | A kernel-assigned 64-bit identifier, unique for the life of a socket |
| Proxy UID | The numeric UID the Aksh proxy process runs as after its privilege drop. **1774**, per ADR-S5-02. Not the PoC's 1337, which is Istio's reserved UID |
| bpffs | The BPF filesystem, normally mounted at `/sys/fs/bpf`, used to pin links across process restarts |
| T1..T9 | The transport rejection taxonomy defined in S1 section 8 and restated in section 14 |

---

## 2. Supersession map

This table is normative. Where S1a and S1 disagree on a superseded section, S1a wins. Where
a section is marked authoritative, S1 remains the specification and S1a must not contradict
it.

| S1 section | Title | Status after S1a | Where it now lives |
| ---------- | ----- | ---------------- | ------------------ |
| 1 | Interception rule set (iptables) | **Superseded in full** | S1a section 6. iptables is removed entirely; there is no fallback (ADR-S1a-01) |
| 1.x | `AKSH_OUTPUT` chain, REDIRECT rules, owner-uid match, packet MARK | **Superseded in full** | S1a sections 6.2, 6.3, 6.5 |
| 2 | Connection ingestion (`SO_ORIGINAL_DST`, listener) | **Superseded in full** | S1a sections 8.1 and 9. Original-destination recovery is a BPF map lookup, not a socket option |
| 2.2 | Self-connection and pod-local destination cases | **Superseded in mechanism, retained in policy** | S1a section 9.2 keeps both cases and both outcomes; only the detection mechanism changes |
| 3 | TLS termination | **Partially superseded** | The *capture-related* parts (where SNI is captured, how the connection arrives, ALPN gating on the accepted connection) are restated in S1a section 11. The **design** of TLS termination - ADR-S1-01, the shared ECDSA leaf key, the leaf cache shape, resumption disabled, ALPN order, TLS 1.2 minimum, no client certs - remains **S1 authoritative** |
| 4 | Connection and request flow | Authoritative | S1a section 5.3 shows the capture prefix only |
| 5.1-5.3 | Upstream transport, verification, pool key | Authoritative | S1a section 8.3 provides a non-pooled 5A implementation that conforms to it |
| 5.4 | Timeout budget | **Authoritative and unchanged** | Restated verbatim in S1a section 13.2 |
| 6 | HTTP handling, plaintext Service-registry rules (ADR-S1-05) | **Authoritative and unchanged** | S1a section 10.3 classifies plaintext and rejects it as T9 until the Service index exists |
| 7 | Resource bounds | **Authoritative in structure, completed by S1a** | S1a section 13 supplies every number and closes OQ-S1-01 |
| 8 | Rejection taxonomy T1-T9 | **Authoritative and unchanged** | Restated in eBPF terms in S1a section 14; no class is added, removed or renumbered |
| ADR-S1-01 | Shared leaf key and leaf cache | Authoritative | - |
| ADR-S1-02 | `httputil.ReverseProxy` | Authoritative | Out of 5A scope |
| ADR-S1-03 | INV-3 exceptions (DNS, ICMPv6) | **Partially superseded** | The DNS exception (DEV-01) is retained. The **ICMPv6 carve-out is withdrawn** as unnecessary under cgroup hooks; see section 6.9.1 |
| ADR-S1-04 | Reject rather than tunnel | Authoritative | Applied in S1a section 10.3 |
| ADR-S1-05 | Plaintext Service-registry rules | **Authoritative and unchanged** | - |
| OQ-S1-01 | Numeric resource bounds | **Closed by S1a section 13** | - |

Sections of S1 not listed above are unaffected.

---

## 3. Scope and requirements covered

### 3.1 In scope

1. eBPF capture: program set, map set, attach model, pod-cgroup scoping, loop prevention.
2. Privilege model: capability set, drop sequence, `CGO_ENABLED=0` constraint.
3. Startup preflight and fail-closed behaviour when capture cannot be established.
4. Attachment lifecycle: load, attach, verify, pin, restart, detach.
5. Original-destination recovery: `internal/dataplane.DestinationResolver`.
6. Listener and connection ingestion on `127.0.0.1:15001`.
7. Protocol discrimination (TLS / HTTP/1.x / h2c / unknown).
8. TLS termination and the leaf certificate cache: `internal/dataplane.LeafSource`.
9. A simple, non-pooled `internal/dataplane.UpstreamDialer`.
10. A minimal end-to-end passthrough demo on a `kind` cluster.
11. Concrete resource bounds, closing OQ-S1-01.
12. The rejection taxonomy restated for eBPF, and the S7 bypass cases re-answered.

### 3.2 Out of scope

HTTP parsing and pipeline integration (5B); connection pooling and the *enforcement*
machinery for the bounds declared here (5C); real CA lifecycle and rotation (PKI phase);
IPv6 *implementation* (designed here, denied at runtime); admission-webhook and injector
changes (S5); response redaction; body inspection; WebSocket and `CONNECT` tunnelling.

### 3.3 Acceptance criteria coverage

| # | Acceptance criterion (from the Phase 5A brief) | Satisfied by |
| - | ---------------------------------------------- | ------------ |
| AC-1 | eBPF is the only capture backend; no iptables path exists | 6.1, 20 (ADR-S1a-01) |
| AC-2 | Programs attach only to the pod's own cgroup v2 path | 6.1.1, 6.1.2, 6.1.3, 20 (ADR-S1a-02) |
| AC-3 | Pod cgroup path is resolved from `/proc/self/cgroup` with no API or Downward API use, and fails closed | 6.1.2, 6.1.3, 6.7 |
| AC-4 | Minimum kernel 5.15 is asserted at preflight | 6.7 (check P2) |
| AC-5 | Loop prevention uses the proxy UID, sourced from a BPF config map written by Go | 6.5, 20 (ADR-S1a-06) |
| AC-6 | Privilege drop sequence is specified and fails closed; `CGO_ENABLED=0` is required | 6.6 |
| AC-7 | Sidecar fails closed at startup if capture cannot be established | 6.7, 6.8.1 |
| AC-8 | The three frozen `internal/dataplane` interfaces are implemented unchanged | 8, 8.1, 8.2, 8.3 |
| AC-9 | Byte-order convention between C and Go is documented prominently | 6.4.3, 22 (R-04) |
| AC-10 | BPF artefacts are built with `bpf2go` and committed; regeneration is documented and reproducible | 6.4.4, 19.4, 20 (ADR-S1a-05) |
| AC-11 | IPv6 is designed in full but fails closed in 5A | 6.9.2, 20 (ADR-S1a-04), 23.1 |
| AC-12 | Numeric resource bounds are decided, closing OQ-S1-01 | 13.1 |
| AC-13 | Rejection taxonomy T1-T9 is restated in eBPF terms | 14 |
| AC-14 | S7 bypass cases B1, B2, B3, B50, B51, B52 are re-answered, and new eBPF attack surface is analysed | 15 |
| AC-15 | A minimal end-to-end demo runs on a `kind` cluster with real pod-cgroup scoping | 12 |

---

## 4. Overview and design principles

### 4.1 Executive summary

Phase 5A replaces iptables REDIRECT with a pair of cgroup-attached eBPF programs. A
`cgroup/connect4` program rewrites the destination of every TCP `connect()` made by a process
in the pod cgroup - except the proxy's own - to `127.0.0.1:15001`, and stashes the true
destination in a map keyed by the socket cookie. A `cgroup/sock_ops` program, firing when the
connection reaches `ESTABLISHED` and therefore after the kernel has assigned a source port,
re-keys that record by `(source address, source port)` into a second map. The listener, on
accepting a connection, looks the tuple up and recovers a destination that the agent could
not have influenced.

The rest of 5A is the connection path built on top of that: bind and accept, classify the
first bytes, terminate TLS with a per-identity leaf minted from a shared key, dial the true
destination with real verification, and relay. Everything above the connection - HTTP,
policy, credentials, audit - is 5B and beyond.

### 4.2 Design principles

1. **Fail closed at every step (INV-4).** If capture cannot be established, the process
   exits non-zero before it serves anything - the listener socket may exist during the probe
   gate (6.7), but the accept loop never starts unless every gate passed. If the destination
   cannot be recovered, the
   connection is closed, never guessed. If the SNI is absent, the handshake fails. There is
   no degraded mode and no fallback backend, because a fallback that is worse than the primary
   is an attacker's preferred path.
2. **The kernel is the source of truth for destination.** The agent supplies the SNI and the
   `Host` header; those are claims. The destination comes from a map the agent cannot write.
   INV-8's whole structure depends on that asymmetry surviving the change of mechanism.
3. **Scope is a security boundary, not a configuration detail.** Attaching to the root cgroup
   would capture every process on the node. The attach point is the pod cgroup, and startup
   refuses to proceed if it cannot prove that is what it got.
4. **One source of truth for every shared constant.** The proxy UID, the listener address and
   the map sizes exist once, in Go, and are pushed into the kernel at load time. The PoC's
   duplicated `1337` is a defect, not a style choice.
5. **Nothing in the hot path allocates a secret.** 5A moves no credentials. That is what makes
   it safe to ship a passthrough handler and a self-signed CA for the demo.
6. **Platform-dependent code is quarantined.** Everything that can be tested without a kernel
   is a pure function in a file with no build tag, so the majority of the phase's logic is
   testable on Windows and in CI.
7. **Prefer a proof over an assumption.** Startup does not assume the attach worked; it
   performs a live redirect self-probe, proves its own UID is excluded, and refuses to run if
   either probe does not come back.

### 4.3 What changes relative to the proof of concept

| Aspect | PoC | 5A |
| ------ | --- | -- |
| Attach point | Root cgroup - captures the entire host | Pod cgroup only, verified (ADR-S1a-02) |
| Proxy UID | `PROXY_UID` literal in C **and** `proxyUID` in Go | Written into a BPF config map from Go; C has no literal (ADR-S1a-06) |
| Address family | IPv4 only, IPv6 silently uncaptured | IPv4 captured, IPv6 explicitly denied at `connect6` (ADR-S1a-04) |
| Non-TCP egress | Unhandled | Blocked by `sock_create` and `sendmsg` hooks (ADR-S1a-07) |
| Destination record | Left in the map after lookup | Consumed on lookup, plus a freshness stamp (ADR-S1a-09) |
| Link lifetime | Dies with the process | Pinned to bpffs, survives restart (ADR-S1a-08) |
| Byte order | `binary.LittleEndian` | `binary.NativeEndian` with named helpers, same bytes |
| Startup | Load, attach, hope | 14 startup gates in two phases, including a live redirect probe and a live UID-exclusion probe |
| Build | `clang` required | Committed object and bindings; `clang` only to regenerate |

---

## 5. Architecture

### 5.1 Component diagram

:::mermaid
graph TB
  subgraph kernel["Kernel - pod cgroup v2"]
    C4["aksh_connect4<br>cgroup/connect4"]
    C6["aksh_connect6_deny<br>cgroup/connect6"]
    SO["aksh_sockops<br>cgroup/sock_ops"]
    SC["aksh_sock_create<br>cgroup/sock_create"]
    SM["aksh_sendmsg4 / sendmsg6<br>cgroup/sendmsg*"]
    M1[("cookie_orig_dst<br>LRU_HASH")]
    M2[("pair_orig_dst<br>LRU_HASH")]
    M3[("aksh_config<br>ARRAY")]
    C4 --> M1
    SO --> M1
    SO --> M2
    C4 --> M3
    C6 --> M3
    SC --> M3
    SM --> M3
  end

  subgraph user["aksh-proxy - userspace"]
    PF["Preflight"]
    RES["PodCgroupResolver"]
    LD["Loader"]
    PD["PrivilegeDropper"]
    DR["BPFDestinationResolver<br>implements DestinationResolver"]
    LN["Listener :15001"]
    DS["Discriminator"]
    TT["TLS terminator"]
    LS["CachedLeafSource<br>implements LeafSource"]
    UD["DirectDialer<br>implements UpstreamDialer"]
    PH["PassthroughHandler<br>5A only"]
  end

  PF --> RES
  RES --> LD
  LD --> PD
  LD -.loads.-> C4
  LD -.loads.-> SO
  LD -.writes.-> M3
  DR -.reads.-> M2
  LN --> DR
  LN --> DS
  DS --> TT
  TT --> LS
  TT --> PH
  PH --> UD

  AGENT["agent container"] -.connect.-> C4
  AGENT -.redirected TCP.-> LN
  UD --> UP["true destination"]
:::

### 5.2 Dependency graph

:::mermaid
graph LR
  CAP["internal/dataplane/capture"] --> DP["internal/dataplane"]
  CAP --> AUD["internal/audit"]
  CAP --> EBPF["github.com/cilium/ebpf"]
  LIS["internal/dataplane/listener"] --> DP
  LIS --> POL["internal/policy"]
  LIS --> AUD
  TLS["internal/dataplane/tlsterm"] --> DP
  TLS --> PKI["internal/pki"]
  TLS --> AUD
  UPS["internal/dataplane/upstream"] --> DP
  UPS --> AUD
  CMD["cmd/aksh-proxy"] --> CAP
  CMD --> LIS
  CMD --> TLS
  CMD --> UPS
:::

There are no cycles and no upward dependencies: `internal/dataplane` holds only interfaces
and depends on nothing in the repository, exactly as the interface guide requires.
`internal/dataplane/listener` imports `internal/policy` only for the `Transport` enum, so
that 5A cannot invent a parallel vocabulary for something policy already names.

### 5.3 High-level connection flow

:::mermaid
sequenceDiagram
  participant A as Agent process (uid 1000)
  participant K as Kernel (pod cgroup hooks)
  participant P as aksh-proxy (uid 1774)
  participant U as Upstream

  A->>K: connect(93.184.216.34:443)
  K->>K: connect4: uid != proxy_uid, TCP, not loopback
  K->>K: cookie_orig_dst[cookie] = {93.184.216.34:443, uid, stamp}
  K->>K: rewrite dst to 127.0.0.1:15001
  K-->>A: connect() proceeds to 127.0.0.1:15001
  K->>K: sock_ops ACTIVE_ESTABLISHED: src port now assigned
  K->>K: pair_orig_dst[(src ip, src port)] = value; delete cookie entry
  K-->>P: accept() returns conn from 127.0.0.1:ephemeral
  P->>K: LookupAndDelete(pair_orig_dst, (src ip, src port))
  K-->>P: 93.184.216.34:443
  P->>P: peek 24 bytes -> TLS
  P->>P: GetConfigForClient captures SNI, mints leaf
  A->>P: TLS handshake completes against the Aksh leaf
  P->>U: dial 93.184.216.34:443, TLS with ServerName = validated identity
  U-->>P: verified against system roots
  P->>U: relay (5A) / request path (5B)
:::

The single ordering guarantee this design rests on is that `sock_ops` fires strictly before
`accept()` can return. Section 6.3 explains why that is a guarantee and not a race we tolerate.

---

## 6. Capture layer

### 6.1 Attach model and pod-cgroup scoping

#### 6.1.1 Why the pod cgroup, and not the alternatives

A cgroup-attached BPF program applies to every process in that cgroup and every descendant.
There are three candidate attach points.

| Candidate | Effect | Verdict |
| --------- | ------ | ------- |
| Root cgroup (`/sys/fs/cgroup`) | Captures every process on the node, including other tenants' pods, the kubelet and the CNI | **Rejected.** This is the PoC's defect. It converts a per-pod sidecar into a node-wide interceptor, violates tenant isolation, and would redirect other pods' traffic into a listener that will reject it |
| The proxy's own container cgroup | Captures only the proxy | **Rejected.** Captures nothing the proxy is meant to intercept |
| **The pod cgroup** | Captures every container in this pod, including the agent and the proxy; the proxy is then excluded by UID | **Chosen** |

The pod cgroup is the correct boundary because it is exactly the set of processes the sidecar
is responsible for, it is created by the kubelet before any container starts, and it is
destroyed when the pod is destroyed, so the attachment cannot outlive its subject.

Attaching to the pod cgroup necessarily captures the proxy itself, since the proxy is a
container in the pod. Section 6.5 handles that.

#### 6.1.2 Resolving the pod cgroup path

The resolution uses only `/proc/self/cgroup` and the filesystem. There is no Kubernetes API
call, no Downward API field, and no environment variable naming the path - each of those
would add a dependency, a failure mode, and a value the pod's own manifest could lie about.

**Inputs**

- `/proc/self/cgroup` - the cgroup v2 line has the form `0::<path>`.
- The proxy's own cgroup2 mount, normally `/sys/fs/cgroup`.
- A read-only bind of the host's cgroup2 root, mounted at `/host/sys/fs/cgroup`. This is a
  new pod-shape requirement; see 6.1.4.

**The cgroup-namespace problem.** Since Kubernetes 1.22 with cgroup v2, the kubelet places
pods in a private cgroup namespace. Inside the container, `/proc/self/cgroup` is rendered
relative to the namespace root, so it commonly reads exactly `0::/`. The path we need - the
pod cgroup - is *above* that namespace root and is therefore not nameable from inside. This
is the single hardest part of the phase, and getting it wrong silently produces either a
root-cgroup attach (over-capture) or a container-cgroup attach (no capture).

**Algorithm**

```
ResolvePodCgroup(procCgroup, localMount, hostMount string) (string, error)

 1. Read procCgroup. Find the line whose first two fields are "0" and "" (the
    cgroup v2 unified line). If absent -> E_NO_CGROUP2. If a v1 hierarchy is present
    and no v2 line is, the node is cgroup v1 -> E_NO_CGROUP2 (5A requires unified).
    Call the third field "rel".

 2. Confirm localMount is a cgroup2 filesystem:
    statfs(localMount).Type == CGROUP2_SUPER_MAGIC (0x63677270), else E_NO_CGROUP2.

 3. Case A - rel != "/" (no cgroup namespace, or a partially namespaced view):
      candidate := path.Clean(path.Join(hostMount, rel))
      This is the container's cgroup. Go to step 5.

 4. Case B - rel == "/" (private cgroup namespace, the common Kubernetes case):
      a. selfIno := stat(localMount).Ino
         cgroup2 is a single filesystem, so the same directory has the same inode
         through the namespace-local mount and through the host mount.
      b. Walk hostMount depth-first, at most 12 levels deep and at most
         MaxWalkDirs = 50,000 directories in total, skipping nothing, and collect
         every directory whose Ino == selfIno.
         If the 50,000th directory is visited before the walk completes, abort
         immediately with E_CGROUP_WALK_LIMIT. Do NOT return the matches found so
         far: a partial walk cannot distinguish "one match" from "the second match
         is in the part we did not visit", and V2-V6 cannot recover that
         distinction later.
      c. exactly one match  -> candidate := that path
         zero matches       -> E_CGROUPNS_OPAQUE
         more than one      -> E_AMBIGUOUS_CGROUP
      This candidate is the container's cgroup directory as named on the host.

 5. podPath := path.Dir(candidate)
    The kubelet's layout is <qos>/<pod>/<container>. The container cgroup's parent is
    the pod cgroup under both the systemd driver
    (/kubepods.slice/kubepods-burstable-podUID.slice/cri-containerd-HASH.scope) and the
    cgroupfs driver (/kubepods/burstable/podUID/HASH).

 6. Run the verification assertions in 6.1.3 against podPath. Any failure is fatal.

 7. Return podPath (a host-mount-relative absolute path, e.g.
    /host/sys/fs/cgroup/kubepods.slice/kubepods-burstable-pod<uid>.slice).
```

The walk in step 4b is bounded on **both** axes. It skips no directory, because a cgroup tree
of a running node is a few thousand directories at most and this runs exactly once at startup;
but "a few thousand at most" is an expectation about a healthy node, not a guarantee, and an
unbounded breadth turns a corrupted or adversarially wide cgroup tree into a startup stall
with no error - the one failure mode a preflight must never have. The depth bound is 12
levels; the breadth bound is 50,000 directories visited, roughly an order of magnitude above
the largest tree a fully packed node produces (a few hundred pods times a handful of
container and runtime cgroups each), so it cannot fire on a healthy node.

Exceeding either bound is **fail-closed**: `E_CGROUP_WALK_LIMIT` aborts `ResolvePodCgroup`,
which fails gate P5, which exits the process non-zero before any program is loaded or
attached. No capture is configured, the listener never binds, and no agent traffic is ever
accepted by a process that did not resolve its attach point. Both bounds are constants rather
than options: they are correctness guards, and an operator who can raise them can turn the
guard off.

#### 6.1.3 Verification assertions

Every one of these runs before any program is attached. Failing any of them aborts startup.
The point is that a wrong attach point is not detectable later, so it must be proved now.

| # | Assertion | Failure code | Why |
| - | --------- | ------------ | --- |
| V1 | `podPath` is a directory and `statfs` reports `CGROUP2_SUPER_MAGIC` | `E_CGROUP_SCOPE` | Guards against resolving into a non-cgroup path |
| V2 | `podPath` is not equal to `hostMount` | `E_CGROUP_SCOPE` | **The PoC defect.** Attaching to the root captures the node |
| V3 | `podPath` is a strict descendant of `hostMount` | `E_CGROUP_SCOPE` | Guards against `..` traversal or a symlinked mount |
| V4 | `podPath` has depth >= 2 below `hostMount` | `E_CGROUP_SCOPE` | The pod cgroup is always at least `<qos>/<pod>`; depth 1 means we resolved a QoS-class cgroup and would capture every pod in that class |
| V5 | `podPath` contains `cgroup.procs` and `cgroup.controllers` | `E_CGROUP_SCOPE` | It is a real cgroup, not a stray directory |
| V6 | The proxy's own PID appears in some descendant's `cgroup.procs` | `E_CGROUP_SCOPE` | Proves the resolved cgroup actually contains us; a resolution that lands on a *different* pod would pass V1-V5 |
| V7 | `podPath` has at least two child directories, or exactly one when the agent container has not started yet | warning only | The pod normally has multiple container cgroups; one is legal during startup so this cannot be fatal |
| V8 | The basename matches `pod[0-9a-f-]{36}` (cgroupfs) or `.*pod[0-9a-f_-]{36}\.slice` (systemd), case-insensitive | warning only | A strong signal, but the naming is a kubelet implementation detail and must not be load-bearing |

V6 is the assertion that actually matters and is the one that would have caught the PoC
defect from the other direction. V8 is deliberately a warning: making a security control
depend on kubelet directory-naming conventions would be brittle in exactly the way V2-V6 are
not.

#### 6.1.4 New pod-shape requirements on S5

The injector must add, for the proxy container only:

| Requirement | Value | Reason |
| ----------- | ----- | ------ |
| `hostPath` volume | `/sys/fs/cgroup`, `type: Directory`, mounted read-only at `/host/sys/fs/cgroup` | The pod cgroup is not nameable from inside a cgroup namespace (6.1.2 case B) |
| `hostPath` volume | `/sys/fs/bpf`, `type: Directory`, mounted at `/sys/fs/bpf` | Link pinning (6.8.2). **The subtree `<pinRoot>/aksh` must be exclusively owned by the proxy UID with mode 0700; gate P15 refuses to pin otherwise (MC-S1a-01, 6.8.6)** |
| Per-pod bpffs | **Required for production; not available in 5A** | A shared host bpffs is the residual exposure in MC-S1a-01. S5 must replace the `hostPath` bpffs with a bpffs instance mounted for this pod alone. OQ-S1a-05 is now about *which mechanism*, not *whether* |
| Start-up capabilities | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP` | 6.6.1 |
| `runAsUser` | 0 at start; the process drops to 1774 itself | The drop must happen after attach, so it cannot be done by the kubelet |
| Native sidecar | `initContainers` entry with `restartPolicy: Always` | Capture must be established before the agent's first packet (6.8.3) |

The read-only host cgroup mount is real, new attack surface and is analysed in section 15.3.
I am not aware of a way to avoid it while keeping the "no API call, no Downward API"
constraint; the alternative I considered - having the injector write the path into an
environment variable - was rejected because it moves a security-critical value into something
the pod spec controls.

### 6.2 `connect4` program logic

Attach type `BPF_CGROUP_INET4_CONNECT`, program type `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`,
context `struct bpf_sock_addr *ctx`.

```
aksh_connect4(ctx):
 1. cfg = lookup(aksh_config, 0)
    if cfg == NULL              -> return 1   (allow, uncaptured: fail open here is
                                               unavoidable because a missing config
                                               means the loader is mid-init; the
                                               loader writes the config BEFORE attach,
                                               so this branch is unreachable in
                                               practice and is a verifier requirement)
 2. if ctx->protocol != IPPROTO_TCP -> return 1   (UDP is handled by sendmsg4/sock_create)
 3. if (cfg->flags & FLAG_CAPTURE_ENABLED) == 0 -> return 1
 4. uid = bpf_get_current_uid_gid() & 0xffffffff
    if uid == cfg->proxy_uid    -> return 1   (loop prevention, section 6.5)
 5. dst = ctx->user_ip4                        (network byte order)
    if (dst & 0x000000ff) == 127 on a little-endian host, i.e. the first octet is 127
                                -> return 1   (127.0.0.0/8 is never redirected)
 6. if cfg->dns_ip4 != 0 && dst == cfg->dns_ip4
       && ctx->user_port == cfg->dns_port
                                -> return 1   (DEV-01, the single INV-3 exception.
                                               Both operands are network-order bytes,
                                               so this is a plain 16-bit comparison
                                               with no byte swap - see 6.4.3)
 7. cookie = bpf_get_socket_cookie(ctx)
    v = { .ip = ctx->user_ip4, .port = ctx->user_port, .flags = DST_IPV4,
          .uid = uid, .pad = 0, .stamp_ns = bpf_ktime_get_ns() }
    if bpf_map_update_elem(&cookie_orig_dst, &cookie, &v, BPF_ANY) != 0
                                -> return 0   (FAIL CLOSED: connect() returns EPERM.
                                               If we cannot record the destination we
                                               must not redirect, because the listener
                                               would be unable to recover it and would
                                               close with T1 anyway - returning EPERM
                                               gives the agent a truthful error instead
                                               of a confusing connection reset)
 8. ctx->user_ip4  = cfg->listener_ip4      (network order, 127.0.0.1)
    ctx->user_port = cfg->listener_port     (network order, 15001)
    return 1
```

Two things are worth stating explicitly because they are capabilities iptables did not have:

- **Returning 0 makes `connect()` fail with `EPERM`.** The redirect path itself can refuse.
  iptables could drop a packet but could not make the syscall fail, so a misconfiguration
  produced a hang or a reset. Here a failure to record the destination produces an immediate,
  correct error.
- **The hook runs before routing.** The destination is rewritten in the socket's address
  before the routing decision is made, so S1 section 2.2's concern about the kernel routing
  self-addressed packets over `lo` and bypassing a `PREROUTING`/`OUTPUT` rule (S7 B3) cannot
  arise. See section 15.3.

Step 5 checks the loopback prefix on the network-order value. In C this is written as
`(bpf_ntohl(ctx->user_ip4) >> 24) == 127`, which is endian-independent and is what the
implementation must use; the pseudocode above shows the intent.

### 6.3 `sock_ops` program logic

Attach type `BPF_CGROUP_SOCK_OPS`, program type `BPF_PROG_TYPE_SOCK_OPS`, context
`struct bpf_sock_ops *skops`.

```
aksh_sockops(skops):
 1. if skops->family != AF_INET                          -> return 0
 2. if skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB   -> return 0
 3. cookie = bpf_get_socket_cookie(skops)
 4. v = lookup(cookie_orig_dst, cookie)
    if v == NULL                                         -> return 0
       (not one of ours: either the proxy's own upstream connection, a loopback
        connection, or the DNS exception)
 5. k = { .ip = skops->local_ip4,          /* network byte order, see 6.4.3 */
          .port = skops->local_port }      /* HOST byte order, kernel-provided */
 6. bpf_map_update_elem(&pair_orig_dst, &k, v, BPF_ANY)
 7. bpf_map_delete_elem(&cookie_orig_dst, &cookie)
 8. return 0
```

**Why `ACTIVE_ESTABLISHED` and not something earlier.** The source port is what the listener
will use as the lookup key, and it is not assigned until the socket is bound - which for an
unbound connecting socket happens inside `connect()`. `BPF_SOCK_OPS_TCP_CONNECT_CB` fires
before the port is guaranteed stable; `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` fires when the
client processes the SYN-ACK.

**Why this is an ordering guarantee, not a race.** For a loopback TCP connection the sequence
is: client sends SYN; server (the listener's kernel side) responds SYN-ACK and creates a
request socket; client receives SYN-ACK, transitions to `ESTABLISHED`, fires
`ACTIVE_ESTABLISHED`, and only then sends the final ACK; the server receives that ACK,
promotes the request socket into the accept queue, and only then can `accept()` return it.
The map write therefore always happens strictly before the listener can observe the
connection. This is why the PoC was reliable, and it is a property of the TCP state machine,
not of timing.

The `pair_orig_dst` write uses `BPF_ANY` so that a reused `(ip, port)` tuple overwrites the
previous record rather than failing. Combined with delete-on-lookup in userspace (section
8.1), a stale record cannot be inherited by a later connection.

### 6.4 Map definitions

#### 6.4.1 Layouts

```c
/* value of both destination maps - 24 bytes, naturally aligned, no implicit padding */
struct orig_dst {
    __u32 ip;        /* offset  0  network byte order                     */
    __u16 port;      /* offset  4  network byte order                     */
    __u16 flags;     /* offset  6  bit0 DST_IPV4, bit1 DST_IPV6 reserved  */
    __u32 uid;       /* offset  8  host order, real uid that connect()ed  */
    __u32 pad;       /* offset 12  must be zero                           */
    __u64 stamp_ns;  /* offset 16  bpf_ktime_get_ns() at connect4         */
};

/* key of pair_orig_dst - 8 bytes, no padding on any ABI */
struct pair_key {
    __u32 ip;        /* offset 0  network byte order                      */
    __u32 port;      /* offset 4  HOST byte order, __u32 because that is  */
                     /*           the width of bpf_sock_ops.local_port    */
};

/* value of aksh_config - 32 bytes, all padding explicit */
struct aksh_config {
    __u32 proxy_uid;      /* offset  0  host order                     */
    __u32 listener_ip4;   /* offset  4  network order                  */
    __u16 listener_port;  /* offset  8  network order                  */
    __u16 flags;          /* offset 10  host order                     */
    __u32 dns_ip4;        /* offset 12  network order, 0 = disabled    */
    __u16 dns_port;       /* offset 16  network order, as listener_port*/
    __u16 pad;            /* offset 18  must be zero                   */
    __u32 pad2;           /* offset 20  must be zero                   */
    __u64 reserved;       /* offset 24  8-byte aligned                 */
};
```

**Why `pair_key.port` is a `__u32` and not a `__u16`.** This is a deliberate widening and the
reason has to survive, because a later reader who "corrects" it to `__u16` breaks capture
silently. The three sides are:

| Side | Declaration | Value written | Width of the source |
| ---- | ----------- | ------------- | ------------------- |
| C, key type | `__u32 port` at offset 4 | `k.port = skops->local_port` (6.3 step 5) | `bpf_sock_ops.local_port` is declared `__u32` in `uapi/linux/bpf.h` and carries a host-order port |
| C, writer | `sock_ops` only | `connect4` never writes `pair_key`; the 16-bit `ctx->user_port` it handles belongs to `orig_dst.port`, a different field of a different struct | - |
| Go | `Port uint32` at offset 4 | `Port: uint32(peer.Port())` (8.1 step 3) | `netip.AddrPort.Port()` is a `uint16`, zero-extended |

The kernel's field is already 32 bits wide, so `__u32` is the width that requires **no**
conversion anywhere in the BPF program: `k.port = skops->local_port` is an assignment between
identical types. Narrowing the key to `__u16` would introduce an implicit truncation in the
one place in this design that is hardest to test, for no gain - the struct would still be
8 bytes after the compiler re-inserted the alignment padding it now holds explicitly.

The 16-bit-to-32-bit placement is therefore: **zero extension into the low half, upper 16 bits
always zero, on both sides.** The kernel guarantees it because a TCP port is at most 65535 and
`local_port` is assigned from a `__u16` source; Go guarantees it because `uint32(uint16)` is a
zero extension by language definition. There is no sign extension anywhere (both types are
unsigned) and no byte swap (both sides hold a host-order integer, not port bytes). Two
distinct source ports can therefore never collide in the key, and a key built by Go is
byte-identical to the key written by `sock_ops` for the same connection.

Two tests hold this down, both in section 19.1: `binary.Size(pairKey{}) == 8` with the `Port`
field at offset 4, and a table test asserting `uint32(uint16(65535)) == 0x0000FFFF` with the
top half clear after marshalling. The `aksh_config` round-trip integration test (19.2) covers
the C side of the same property for that struct.

`struct orig_dst` grows from the PoC's 8 bytes to 24. The three additions each pay for
themselves: `uid` makes T2 detectable in userspace with certainty rather than inference
(section 6.5.3), `stamp_ns` bounds staleness (section 8.1), and `flags` is what makes the
IPv6 extension a value change rather than a layout change. `pad` is explicit so that C and Go
agree about the hole the compiler would otherwise insert.

`struct aksh_config` is **32 bytes, not 24**: the fields up to and including `pad` occupy 20
bytes, and `__u64 reserved` is 8-byte aligned, so the compiler places it at offset 24 and
inserts a four-byte hole at offset 20. That hole is written out as `pad2` for the same reason
`orig_dst.pad` exists - an invisible hole is a C/Go ABI break waiting to happen, and this
struct carries the capture kill switch. Both `pad` and `pad2` are zero on write and are not
read by any program; the P10 read-back comparison (section 6.7) covers all 32 bytes, so a
layout disagreement between C and Go fails startup rather than producing a silently wrong
`proxy_uid`.

#### 6.4.2 Map table

| Name | Type | Key | Value | Max entries | Written by | Read by |
| ---- | ---- | --- | ----- | ----------- | ---------- | ------- |
| `cookie_orig_dst` | `BPF_MAP_TYPE_LRU_HASH` | `__u64` socket cookie | `struct orig_dst` | 16384 | `connect4` | `sock_ops` (read + delete) |
| `pair_orig_dst` | `BPF_MAP_TYPE_LRU_HASH` | `struct pair_key` | `struct orig_dst` | 16384 | `sock_ops` | userspace (lookup + delete) |
| `aksh_config` | `BPF_MAP_TYPE_ARRAY` | `__u32` (always 0) | `struct aksh_config` | 1 | userspace, before attach | all programs |

`LRU_HASH` rather than `HASH` because an entry whose connection is abandoned between
`connect()` and `ESTABLISHED` is never cleaned up by anything else; LRU turns a leak into a
bounded, self-correcting cache. Eviction of a live entry degrades to a T1 close, which is
fail-closed. See section 13.1 for why 16384 rather than the proposed 65536.

`aksh_config` is an `ARRAY` and is written once, before attach. It is then **frozen** with
`BPF_MAP_FREEZE` (`(*ebpf.Map).Freeze()`), which is what makes "not writable at runtime" a
control rather than an intention: after the freeze every `bpf(BPF_MAP_UPDATE_ELEM)` against
it returns `EPERM`, for this process and for any other, and the freeze cannot be undone for
the life of the map. That matters because `CAP_BPF` is deliberately retained after the
privilege drop (6.6.1) and `CAP_BPF` is sufficient to write a map: without the freeze, a
compromised proxy could clear `flagCaptureEnabled` and turn capture off from inside its own
address space. See 6.8.2 step 5 for where the freeze sits in the load sequence.

#### 6.4.3 The byte-order convention - read this before writing any code

**This is the single most likely source of silent breakage in the phase.**

The kernel presents these fields inconsistently, and the design deliberately preserves that
inconsistency rather than normalising it, because normalising would require the BPF program
to do byte swaps whose correctness cannot be tested without a kernel.

| Field | Byte order | Source |
| ----- | ---------- | ------ |
| `bpf_sock_addr.user_ip4` | **network** | Kernel provides it in network order |
| `bpf_sock_addr.user_port` | **network** | Kernel provides it in network order |
| `bpf_sock_ops.local_ip4` | **network** | Kernel provides it in network order |
| `bpf_sock_ops.local_port` | **host** | Kernel provides it in host order - unlike every neighbouring field |
| `bpf_sock_ops.remote_port` | **network** | Note the asymmetry with `local_port`; 5A does not use it, but anyone extending this program will trip over it |

The rule, stated once:

> A `__u32` holding an IPv4 address always holds the four address bytes in **network order**,
> regardless of the host's endianness. A `__u16`/`__u32` holding a port holds a **host-order
> integer** in `pair_key.port` and `bpf_sock_ops.local_port`, and **network-order bytes** in
> `orig_dst.port`, `bpf_sock_addr.user_port`, `aksh_config.listener_port` and
> `aksh_config.dns_port`.

**Every port field Aksh itself defines is network order; only the two kernel-defined
host-order fields are host order, and they are host order because the kernel made them so.**
That is the whole convention, and it is why `aksh_config` is internally consistent:
`listener_port` and `dns_port` are both network-order bytes, both written through
`hostPortToNet` in 6.4.4, and both compared byte-wise in the BPF programs against
`bpf_sock_addr.user_port`, which is also network order. Making `dns_port` network order rather
than host order costs nothing and *removes* a `bpf_ntohs` from the `connect4` fast path
(6.2 step 6) - consistency and the cheaper datapath happen to point the same way here. The
only host-order integers in the design are `pair_key.port`, which mirrors
`bpf_sock_ops.local_port`, and `orig_dst.uid`, which is not a port at all.

Userspace must construct the lookup key so that the address word contains the same bytes the
kernel put there. The PoC does this with `binary.LittleEndian.Uint32(srcIP)`, which is correct
on amd64 and arm64 but expresses the wrong intent. 5A uses `binary.NativeEndian`, which
produces byte-identical results on every little-endian platform, is correct on big-endian,
and says what it means:

```go
// NEW - internal/dataplane/capture/byteorder.go   (NO build tag: unit-tested on Windows)

// netIPToAddr converts a netip.Addr into the __u32 the BPF programs store, i.e. the
// four address bytes in network order, reinterpreted as a native-endian word.
func netIPToAddr(a netip.Addr) uint32 {
    b := a.Unmap().As4()
    return binary.NativeEndian.Uint32(b[:])
}

// addrToNetIP is the exact inverse of netIPToAddr.
func addrToNetIP(v uint32) netip.Addr {
    var b [4]byte
    binary.NativeEndian.PutUint32(b[:], v)
    return netip.AddrFrom4(b)
}

// netPortToHost converts a port held as network-order bytes in a __u16
// (orig_dst.port) into a host-order integer.
func netPortToHost(v uint16) uint16 {
    var b [2]byte
    binary.NativeEndian.PutUint16(b[:], v)
    return binary.BigEndian.Uint16(b[:])
}

// hostPortToNet is the exact inverse of netPortToHost.
func hostPortToNet(v uint16) uint16 {
    var b [2]byte
    binary.BigEndian.PutUint16(b[:], v)
    return binary.NativeEndian.Uint16(b[:])
}
```

These four functions are pure, have no build tag, and are covered by round-trip and
known-value table tests (section 19.1). They are the only place in the codebase permitted to
perform this conversion; no call site may open-code a `binary.LittleEndian` call. That rule
is enforced by review and by a `go vet`-adjacent grep in the test suite.

Note that `netPortToHost` and `hostPortToNet` are the same operation on little-endian
hardware and are both `bits.ReverseBytes16`. They are written as an explicit pair anyway,
because the names are what make a call site reviewable.

#### 6.4.4 Values pushed from Go at load time

The C source contains **no** UID, no listener address, no port and no DNS address. All of
them are written into `aksh_config` index 0 before the programs are attached:

```go
cfg := akshConfig{
    ProxyUID:     opts.ProxyUID,                         // 1774, from Go options
    ListenerIP4:  netIPToAddr(netip.AddrFrom4([4]byte{127, 0, 0, 1})),
    ListenerPort: hostPortToNet(opts.ListenerPort),      // 15001
    Flags:        flagCaptureEnabled | flagBlockNonTCP | flagDenyIPv6,
    DNSIP4:       netIPToAddr(opts.DNSServer.Addr()),    // DEV-01
    DNSPort:      hostPortToNet(opts.DNSServer.Port()),  // network order, as ListenerPort
}
if err := objs.AkshConfig.Update(uint32(0), &cfg, ebpf.UpdateAny); err != nil {
    return fmt.Errorf("E_CONFIG_WRITE: %w", err)
}
```

Map `max_entries` is likewise not fixed in C: the loader calls `spec.Maps["cookie_orig_dst"]
.MaxEntries = opts.MapEntries` on the `ebpf.CollectionSpec` before `NewCollection`, so the
sizes in section 13.1 are configurable without regenerating the object.

Generation is an explicit developer step, not part of `go build`:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target bpfel -type orig_dst -type pair_key -type aksh_config akshbpf ./bpf/aksh_capture.c -- -I./bpf/include -O2 -g -Wall -Werror
```

Reproducibility is addressed in ADR-S1a-05.

### 6.5 Loop prevention via the proxy UID

#### 6.5.1 The mechanism

Because the programs are attached to the pod cgroup, and the proxy is a container in the pod,
the proxy's own upstream connections hit `connect4`. Without an exclusion, `DialUpstream`
would be redirected back to `127.0.0.1:15001` and the proxy would talk to itself forever.

S1 section 1 solved this with an iptables `--uid-owner` match plus a packet MARK. The MARK
existed because the iptables solution needed a way to carry "already handled" state across
chains. In the eBPF design the exclusion happens in the one place a connection can be
redirected, so the MARK has no job and is deleted rather than reimplemented (ADR-S1a-03).

The exclusion is `uid == cfg->proxy_uid`, evaluated with `bpf_get_current_uid_gid()`, which
returns the **real** UID of the calling task. Not the effective UID: the real UID cannot be
changed back by a process that has dropped privileges, whereas an effective UID can be
juggled by a process holding `CAP_SETUID`. Since the agent container is required to run as a
UID that is not 1774 (INV-10, enforced by the admission webhook in S5, and re-checked at
startup as gate P13), an agent process cannot present the proxy's UID.

#### 6.5.2 Single source of truth

The PoC declares `#define PROXY_UID 1337` in C and `const proxyUID = 1337` in Go and relies on
a human keeping them equal. That is a defect: the failure mode of divergence is either a
capture loop (if C's value is wrong) or a total capture bypass for one UID (if Go's is), and
neither is caught by a compiler.

In 5A the value exists exactly once, in Go, in `capture.Options.ProxyUID`, and reaches the
kernel through `aksh_config`. It is also the value passed to `setuid()` in the privilege drop,
so a divergence is impossible by construction: the same variable is used for both. Startup
logs it, and gate P13 asserts `getuid() == opts.ProxyUID` after the drop, with gate P14
proving that the kernel side agrees by refusing to capture that UID.

**The value itself is 1774, not the PoC's 1337.** This is a correction, not a preference. S5
ADR-S5-02 reserves 1774 precisely because 1337 is Istio's reserved UID, and a pod carrying
both proxies would have each whitelisting the other - a mutual, silent bypass. The PoC
hard-coded 1337; the Phase 5A brief specifies no numeric UID at all, requiring only that
proxy-UID exclusion be specified and kept in sync, so this design takes the value from
ADR-S5-02 rather than from the proof of concept. INV-10's admission checks, which reject any
container claiming the reserved UID, are written against 1774, so shipping 1337 would have
left the reserved-UID check guarding a UID nothing used. See section 20, ADR-S1a-06.

#### 6.5.3 Detecting a loop that happens anyway

Defence in depth, because "impossible by construction" is a claim and T2 exists to catch it
being wrong:

1. `orig_dst.uid` carries the UID that called `connect()`. If the resolver ever reads a record
   whose `uid` equals the proxy UID, the exclusion failed. That is `ErrLoopGuard` -> **T2**,
   and it is logged at ERROR and counted as an alert, because it means a capture loop is
   possible.
2. `listener.SelfDialRegistry` records the local address of every connection the
   `DirectDialer` opens, and the listener checks the peer address of every accepted connection
   against it. A hit means the proxy connected to itself -> **T2** + alert. This catches a
   loop that arrives without a map record at all, which the `uid` check by itself cannot see.

```go
// NEW - internal/dataplane/listener/selfdial.go   (platform independent)

type SelfDialRegistry struct {
    mu    sync.RWMutex
    addrs map[netip.AddrPort]struct{}
}

func NewSelfDialRegistry() *SelfDialRegistry
func (r *SelfDialRegistry) Add(a netip.AddrPort)
func (r *SelfDialRegistry) Remove(a netip.AddrPort)
func (r *SelfDialRegistry) Contains(a netip.AddrPort) bool
```

### 6.6 Privilege model

#### 6.6.1 Capability set

| Phase | Capabilities | Why |
| ----- | ------------ | --- |
| Start (uid 0) | `CAP_BPF` | `bpf(BPF_PROG_LOAD)`, `bpf(BPF_MAP_CREATE)`, map access |
| | `CAP_NET_ADMIN` | Required in addition to `CAP_BPF` to load and attach `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` and `BPF_PROG_TYPE_SOCK_OPS`. `CAP_BPF` alone is not sufficient for these program types |
| | `CAP_SETUID`, `CAP_SETGID` | The drop itself |
| | `CAP_SETPCAP` | To reduce the bounding set |
| After drop (uid 1774) | `CAP_BPF` **only** | Map lookups in `Resolve` |

`CAP_BPF` must be **retained** after the UID drop. On kernels with
`kernel.unprivileged_bpf_disabled` set - which is the default on many distributions and was
verified on 5.15 during the PoC - an unprivileged process cannot perform `bpf()` map lookups
at all, and `Resolve` would fail for every connection. Dropping it would turn the proxy into
a machine that rejects all traffic with T1.

`CAP_SYS_ADMIN` is never requested. `CAP_NET_BIND_SERVICE` is not needed because 15001 is
above 1024.

#### 6.6.2 Drop sequence

The order below is the PoC's, validated. Each step is fail-closed: any error aborts the
process with a non-zero exit, because a partial drop is worse than no drop.

```
 1. Assert CGO_ENABLED=0 at build time and re-assert at runtime (6.6.3).
 2. Complete ALL privileged work first: load programs, write and freeze aksh_config, attach
    links, pin links, bind the listener, run the redirect self-probe. Nothing after this
    point needs anything but CAP_BPF.
 3. prctl(PR_SET_KEEPCAPS, 1) - without this the kernel clears the permitted set on the
    uid transition and step 6 has nothing to retain.
 4. setgroups(0, NULL) - clear supplementary groups. Doing this AFTER setgid would fail,
    and skipping it leaves the process in root's groups.
 5. setgid(1774) - group before user; after setuid we no longer have CAP_SETGID.
 6. setuid(1774) - via unix.AllThreadsSyscall, see 6.6.3.
 7. capset: retain CAP_BPF in permitted and effective; clear everything else.
 8. Drop CAP_SETPCAP, CAP_NET_ADMIN, CAP_SETUID, CAP_SETGID from the bounding set with
    prctl(PR_CAPBSET_DROP, ...) so they cannot be regained by any exec.
 9. prctl(PR_SET_KEEPCAPS, 0).
10. prctl(PR_SET_NO_NEW_PRIVS, 1) - belt and braces; no exec can gain privileges.
11. Verify: getuid()==1774, geteuid()==1774, getgid()==1774, getgroups() is empty,
    the effective set is exactly {CAP_BPF}, and setuid(0) FAILS. If any check does not
    hold -> E_PRIVDROP, exit non-zero.
```

Step 11 is not decoration. A privilege drop that silently did not happen is precisely the
kind of failure that is invisible until it matters, and `setuid(0)` failing is the only
direct proof that the transition is irreversible.

> **[Reconciled P9a]** The Linux implementation (`privdrop_linux.go`, `DropPrivileges(cfg
> PrivDropConfig) error`) realises steps 3-9 as a **two-phase capset** rather than a single
> naive capset: `CAP_SETPCAP` is *transiently retained* across the `setuid(1774)` transition
> (so the process can still call `PR_CAPBSET_DROP` afterwards) and is only then dropped from
> both the effective/permitted set and the bounding set. This is a legitimate deviation from
> the one-shot reading of steps 7-8 above and was confirmed correct by reviewers. Step 11
> `verifyDrop` enforces, fail-closed with `E_PRIVDROP`: `uid==gid==1774`, `PR_GET_KEEPCAPS==0`,
> `PR_GET_NO_NEW_PRIVS==1`, effective/bounding sets == exactly `{CAP_BPF}`, and a `setuid(0)`
> probe (via `AllThreadsSyscall`) that fails with **`EPERM`** (any other errno, or success,
> fails verification). The bounding-set drop loop is fail-closed and breaks only on `EINVAL`.

#### 6.6.3 Why `CGO_ENABLED=0` is mandatory

A Go program is multi-threaded before `main` runs. `setuid()` is per-thread on Linux, so
dropping privileges correctly requires changing the UID on **every** thread.
`golang.org/x/sys/unix.AllThreadsSyscall` does this by signalling every thread in the process.

**In a cgo-linked binary `AllThreadsSyscall` returns `ENOTSUP`.** The Go runtime cannot
enumerate and signal threads it did not create, so the function refuses rather than doing a
partial job. This was observed directly in the PoC. The consequence of not noticing would be
severe: a proxy running with some threads still at uid 0, and - because the UID is also the
loop-prevention key - a proxy whose own connections are sometimes captured and sometimes not.

Therefore:

- The binary is built with `CGO_ENABLED=0`. This is asserted in the Dockerfile and in the
  build documentation.
- At startup, before the drop, the process calls `AllThreadsSyscall(SYS_GETUID, 0, 0, 0)` as a
  probe. If it returns `ENOTSUP`, startup aborts with `E_CGO_ENABLED` and a message naming
  `CGO_ENABLED=0`. This is preflight check P1 and it runs first, because every later check is
  wasted work if this one fails.
- `CGO_ENABLED=0` also forces Go's pure-Go resolver, which is desirable anyway: the cgo
  resolver would call `getaddrinfo` and produce connections from C library threads.

### 6.7 Startup gates and fail-closed behaviour

Startup has two phases, and the split matters because one of the gates needs a bound socket
and the rest must not have one.

- **Phase A - static preflight (P1-P11, and P15 when pinning).** Environment, capabilities,
  program load, config write, attach verification and the pin-root ownership gate. No socket
  is bound in this phase. It is entirely a set of assertions about the machine and the kernel
  objects.
- **Phase B - probe gate (P12-P14).** The listener binds but does **not** serve: the socket
  exists, the accept loop is not running, and the only thing reading from it is the probe
  code. The redirect self-probe runs, privileges are dropped, and the exclusion probe runs.
  Only when all three pass does the accept loop start and the process report Ready.

Binding is not serving. The listener is bound in phase B because the self-probe needs a real
socket at `127.0.0.1:15001` to land on (6.7.1); it accepts nothing but the probe's own
connections until phase B completes. If any gate fails, the listener is closed and the process
exits non-zero, so no agent connection is ever accepted by a process that has not proved
capture works.

Any failure in either phase exits non-zero with the named code. There is no `--best-effort`,
no `--allow-degraded` and no environment variable that relaxes any of these, because a switch
that disables capture is a switch that disables the product (INV-4).

**Phase A - static preflight. No socket is bound.**

| # | Check | Failure code |
| - | ----- | ------------ |
| P1 | `AllThreadsSyscall` is supported (not a cgo build) | `E_CGO_ENABLED` |
| P2 | Kernel >= 5.15, parsed from `uname()` release, comparing major and minor numerically and tolerating vendor suffixes | `E_KERNEL_TOO_OLD` |
| P3 | `/sys/fs/cgroup` is `CGROUP2_SUPER_MAGIC` (unified hierarchy) | `E_NO_CGROUP2` |
| P4 | `/host/sys/fs/cgroup` is present and is `CGROUP2_SUPER_MAGIC` | `E_NO_CGROUP2` |
| P5 | Pod cgroup resolves and passes V1-V8 (6.1.2, 6.1.3) | `E_CGROUP_SCOPE`, `E_CGROUPNS_OPAQUE`, `E_AMBIGUOUS_CGROUP`, `E_CGROUP_WALK_LIMIT` |
| P6 | bpffs is mounted at the configured pin root; if absent and `MountBPFFS` is set, mount it | `E_NO_BPFFS` |
| P7 | Effective capabilities include `CAP_BPF` and `CAP_NET_ADMIN` | `E_MISSING_CAPS` |
| P8 | `RLIMIT_MEMLOCK` is raised, or `rlimit.RemoveMemlock()` succeeds (a no-op on kernels using memcg accounting) | `E_MEMLOCK` |
| P9 | All programs load and verify | `E_PROG_LOAD` |
| P10 | `aksh_config` written, read back byte-identical over all 32 bytes, then frozen with `BPF_MAP_FREEZE` (6.8.2 step 5) | `E_CONFIG_WRITE`, `E_CONFIG_FREEZE` |
| P11 | Links attach; the attached program ids are then re-queried from the kernel and matched against the loaded ids | `E_ATTACH`, `E_ATTACH_VERIFY` |
| P15 | **Pin-root ownership gate (MC-S1a-01, 6.8.6).** Runs when `PinLinks` is true, after P11's attach and immediately before step 7 of 6.8.2 creates any pin: `<pinRoot>` is `BPF_FS_MAGIC`; `<pinRoot>/aksh` and `<pinRoot>/aksh/<podUID>` are directories owned by the proxy UID and GID with mode exactly 0700, created by this process with that mode or already ours; the health check is enabled | `E_PIN_ROOT_UNSAFE` |

P15 is numbered after P14 because gate numbers are stable identifiers rather than an ordering;
it runs inside phase A, at the point named in its row. It is listed in the phase A table
because it must complete before the process holds any pinned object.

**Phase B - probe gate. The listener is bound but is not serving.**

| # | Check | Failure code |
| - | ----- | ------------ |
| P12 | The redirect self-probe succeeds (6.7.1) | `E_PROBE` |
| P13 | Privilege drop completes and all of 6.6.2 step 11's assertions hold, including `getuid() == opts.ProxyUID`, which is the startup re-check of INV-10 | `E_PRIVDROP` |
| P14 | The UID-exclusion probe succeeds (6.7.2) | `E_PROBE_UID` |

Phase A also emits a startup summary at INFO listing the kernel version, the resolved pod
cgroup path, the attached program names, the effective capabilities, and every resource bound
from section 13. Capture configuration that is not logged is capture configuration nobody
audits.

#### 6.7.1 The redirect self-probe

P11 proves the links exist. It does not prove they work; a program can be attached to the
right cgroup and still not redirect - for example if `flagCaptureEnabled` were unset, or if a
higher-priority program in a multi-attach chain returned early.

The probe runs in phase B, immediately after the listener binds and before the accept loop
starts:

```
1. The listener socket is already bound at 127.0.0.1:15001 (phase B, before serving).
   The probe drives it through Listener.AcceptProbe (9.1) rather than owning the
   socket: the accept loop of section 9.2 has not started, and AcceptProbe refuses to
   run once it has.
2. From a goroutine running as the CURRENT uid (still 0, so NOT the proxy uid, so the
   connect4 exclusion does not apply), dial 192.0.2.1:65535 (RFC 5737 TEST-NET-1,
   guaranteed unroutable, so nothing is disturbed if the redirect does NOT happen -
   the connect simply fails).
3. If capture works, connect4 rewrites the destination and the connection lands on
   127.0.0.1:15001. The probe takes it from AcceptProbe with a 2s deadline, calls
   Resolve() on it, and asserts the recovered destination is exactly 192.0.2.1:65535.
4. Any deviation - connect succeeded but went nowhere, accept timed out after 2s,
   Resolve returned an error, or the recovered destination differs -> E_PROBE.
5. Close both sides. The probe connection is not counted against any bound, and its
   pair_orig_dst record is consumed by the Resolve in step 3.
```

The redirect target is `127.0.0.1:15001`, not an ephemeral port, which is precisely why the
probe cannot run in phase A: there is no way to prove the redirect works without a socket
listening where the redirect points. Binding early is safe because binding is not serving;
serving is what phase B gates.

This proves, end to end, in the real pod: `connect4` rewrote the destination, `sock_ops` wrote
the pair record, and `Resolve` recovered it. It is the difference between "we attached
something" and "capture works".

The probe deliberately runs as uid 0, before the drop, so it exercises the non-excluded path.
It cannot prove that a process in the *agent* container is captured, only that a process in
this cgroup is; that gap is stated in section 21.

#### 6.7.2 The UID-exclusion probe

6.7.1 proves that a non-excluded process **is** captured. It says nothing about the other half
of the mechanism: that the proxy's own connections are **not**. That half is load-bearing -
if the `uid == cfg->proxy_uid` comparison in `connect4` were wrong (a byte-order slip on
`bpf_get_current_uid_gid()`, a config write that landed in the wrong field, a `setuid` that
did not take on every thread), the redirect probe would still pass and the failure would first
appear in production as a capture loop. Proving one direction and assuming the other is
exactly the assumption ADR-S1a-06 exists to remove.

P14 therefore runs the mirror-image probe, after the drop, as uid 1774:

```
1. Precondition: P13 has completed, so getuid() == opts.ProxyUID on every thread.
2. Dial 192.0.2.1:65535 again, with a 250 ms deadline, from the dropped process.
3. Expected outcome: the connect does NOT complete. TEST-NET-1 is unroutable, so an
   uncaptured connect can only time out or fail with EHOSTUNREACH / ENETUNREACH.
   Any of those is a PASS: the connection was not redirected.
4. Failure outcome: the connect SUCCEEDS within the deadline. To an address guaranteed
   unroutable, a successful connect can only mean it was redirected to the local
   listener - which means the proxy UID is being captured -> E_PROBE_UID, exit
   non-zero. The error names the observed uid and the configured proxy_uid so the
   divergence is in the log rather than inferred from a loop counter.
5. Belt and braces: assert that no pair_orig_dst record exists for the probe's source
   tuple. A record without a completed connect would also mean connect4 acted on a
   proxy-UID connection.
6. Close whatever was opened. The probe is bounded at 250 ms and adds that to startup.
```

The asymmetry with 6.7.1 is deliberate: the redirect probe asserts a positive (the
destination came back), while the exclusion probe asserts a negative (nothing happened). A
negative assertion needs a bounded wait, hence the 250 ms deadline, and it is conservative in
the right direction - a slow node makes the probe pass, never fail, and the runtime T2
controls in 6.5.3 remain the ongoing detection for a loop that appears later. The residual
gap is that P14 exercises the proxy's *own* process rather than an arbitrary process running
as 1774; the "Loop prevention" integration test in section 19.2 covers that case on a real
kernel by attaching to a scratch cgroup and dialling as the configured proxy UID.

#### 6.7.3 Pre-merge kernel validation gates M1-M3

P1-P15 are runtime gates: they run in the pod, every start. This subsection is about a
different kind of gate. Three behaviours that the fail-closed argument depends on are, at the
time of writing, **reasoned expectations about the kernel rather than observed facts**. The
document says so in section 21 and in the open questions, and the status in section 1 is
conditional for exactly this reason. What was missing was a place that says what "validated"
means and who is allowed to declare it.

Each of these runs on the section 12 kind demo, on the 5.15 floor kernel, and each records
its evidence in the phase's implementation notes. **The implementation must not be merged
while any of them is unrecorded**, and none of them may be closed by argument.

| # | Validation | Closes | Method | Evidence required | If it fails |
| - | ---------- | ------ | ------ | ----------------- | ----------- |
| **M1** | A pinned cgroup `bpf_link` does not prevent the kubelet from removing the pod cgroup | OQ-S1a-01 | Run the demo pod with `PinLinks=true`, delete the pod, then assert on the node that the pod cgroup directory is gone and that `/sys/fs/cgroup` shows no orphan under the QoS slice. Repeat 10 times to exclude a race | The node-side directory listing before and after deletion, and the pin state, captured in the implementation notes | `PinLinks` defaults to `false`, section 6.8.3's restart guarantee is lost, and the restart gap in R-02 becomes permanent for 5A. This is a documented design change, not a silent one |
| **M2** | The attachment health check can read link info with `CAP_BPF` alone, after the drop | OQ-S1a-08 | After P13, call `BPF_OBJ_GET` plus `BPF_OBJ_GET_INFO_BY_FD` on a pinned link from the dropped process and assert both succeed and that the returned `prog_id` and `cgroup_id` match the recorded ids | The syscall return values and the compared ids, from the demo run | Fall back to the reduced check named in 6.8.5: hold an fd per link from before the drop and `stat` the pin path for existence only. That detects unpinning but not replacement, which must then be recorded as a narrowing of the N4 mitigation |
| **M3** | `BPF_MAP_FREEZE` on `aksh_config` succeeds with `CAP_BPF` on 5.15 and makes subsequent `BPF_MAP_UPDATE_ELEM` return `EPERM` | The iteration-1 freeze control | After step 5 of 6.8.2, attempt a write to the frozen map from the same process and assert `EPERM`; assert the BPF programs still read it correctly by running the P12 probe afterwards | The failed-write errno and a passing P12 in the same run | The kill-switch immutability argument in 6.4.2 is unsupported. The fallback is to drop `CAP_BPF` after attach and re-open the maps from retained fds, which is a larger change and would need its own review |

M3 is included even though `BPF_MAP_FREEZE` has been available since 5.2, because the freeze
was added in iteration 1 and has never been executed on the floor kernel by this project.
Assuming a control works because the man page says it does is the same class of mistake M1 and
M2 exist to prevent.

**These are merge gates, not implementation gates.** Implementation starts now; the code is
written against the design as specified. What M1-M3 gate is the claim that the fail-closed
posture holds on a real kernel, and that claim is what merging asserts.

### 6.8 Attachment lifecycle

#### 6.8.1 State machine

:::mermaid
stateDiagram-v2
  [*] --> PreflightStatic
  PreflightStatic --> Loaded: P1-P9 pass
  PreflightStatic --> Failed: any check fails
  Loaded --> Configured: aksh_config written, verified and frozen (P10)
  Loaded --> Failed: E_PROG_LOAD
  Configured --> Attached: links created or updated
  Configured --> Failed: E_CONFIG_WRITE / E_CONFIG_FREEZE
  Attached --> Pinned: links pinned to bpffs
  Attached --> Failed: E_ATTACH / E_ATTACH_VERIFY (P11)
  Pinned --> Bound: listener bound, NOT serving
  Bound --> Probed: redirect self-probe recovers the destination (P12)
  Bound --> Failed: E_PROBE
  Probed --> Dropped: privileges reduced to CAP_BPF (P13)
  Probed --> Failed: E_PRIVDROP
  Dropped --> ExclusionProved: proxy-UID connect is NOT captured (P14)
  Dropped --> Failed: E_PROBE_UID
  ExclusionProved --> Serving: accept loop starts, Ready reported
  Serving --> Draining: SIGTERM
  Draining --> [*]
  Failed --> [*]: close any bound socket, exit non-zero, never serve
:::

`Failed` always exits non-zero and never reaches `Serving`. `Bound` is not `Serving`: in
`Bound`, `Probed` and `Dropped` the socket exists but the accept loop has not started and only
the probe code touches it, so no agent connection can be accepted by a process that has not
passed every gate. On failure the socket is closed before exit, so a partially started proxy
does not leave a listening port behind. The kubelet restarts the container, the sidecar never
becomes Ready, and - because the proxy is a native sidecar - the agent container never starts.
A pod that cannot intercept never runs an agent.

#### 6.8.2 Load, attach, pin

```
1. spec, err := loadAkshbpf()                       // from the committed, embedded object
2. Override map sizes on the spec from Options.
3. objs, err := ebpf.NewCollection(spec)            // programs verified here
4. Write aksh_config, read back, compare all 32 bytes (P10).
5. objs.AkshConfig.Freeze()                        // BPF_MAP_FREEZE; irreversible
6. For each (program, attach type):
     link.AttachCgroup(link.CgroupOptions{
         Path:    podCgroupPath,
         Attach:  attachType,
         Program: prog,
     })
   with attach flags BPF_F_ALLOW_MULTI so that a co-resident mesh sidecar's programs
   are not displaced. We are a guest in this cgroup, not its owner.
7. Run gate P15 (6.8.6), then pin each link at
   <pinRoot>/aksh/<podUID>/<progName>.link, and pin pair_orig_dst at
   <pinRoot>/aksh/<podUID>/pair_orig_dst. Immediately after each BPF_OBJ_PIN,
   chown(pinPath, ProxyUID, ProxyGID) so the post-drop CAP_BPF-only process
   (uid 1774) can BPF_OBJ_GET the pin; a pin left root-owned 0600 yields
   EACCES(13) to that process (see 6.8.6). The fds are retained for the life of the
   process; pinning is in addition to holding them, never instead of it.
8. Re-query the cgroup's attached program ids and assert ours are present (P11).
```

> **[Reconciled P9a]** The Linux orchestration entry point implemented in `loader_linux.go` is
> the package-level free function `LoadAndAttach(opts *Options) (*AttachInfo, error)` (matching
> the frozen stub signature; there is **no** `ctx` parameter). Because the signature is frozen,
> cancellation of the load and of the attachment health-check goroutine is driven through a new
> `Options.Context context.Context` field (a nil `Context` means `context.Background()`); this
> satisfies UT #118. `AttachInfo` records the real kernel program ids and cgroup id. On any
> error or ctx-cancel the loader fail-closed unwinds the partial kernel objects; idempotency is
> an atomic check-and-reserve under `loaderMu` (no lock is held across syscalls). The program-id
> read is a `programID (uint32, error)` seam and `attach()` additionally rejects an `id==0`
> fail-closed. Failure codes: `E_MEMLOCK`, `E_KERNEL_TOO_OLD`, `E_PROG_LOAD`, `E_PIN_ROOT_UNSAFE`,
> `E_ATTACH`. (Closes Findings improvement #9 / TD-2 loader-name half.)

**Step 5, the freeze, is a security step and not a tidiness step.** `BPF_MAP_FREEZE` has
existed since kernel 5.2 and is therefore available at the 5.15 floor; it requires
`bpf_capable()`, which this process satisfies through `CAP_BPF`. Freezing makes the map
read-only *to the `bpf()` syscall only*: the BPF programs continue to read it with
`bpf_map_lookup_elem` exactly as before, because the freeze restricts updates, not lookups.
None of the programs writes `aksh_config`, so nothing in the datapath regresses. The freeze
happens after the P10 read-back, so a layout or byte-order error is still an abort rather than
something locked in, and before attach, so no program ever runs against a still-writable
config. `aksh_config` is not pinned, so a proxy restart creates a fresh map and freezes it
again; the freeze therefore does not interact with the restart path in 6.8.3.

The two destination maps are **not** frozen and must not be: `connect4` and `sock_ops` write
them on every connection, and userspace deletes from `pair_orig_dst` on every lookup. Only the
config map - the one whose contents can disable capture - is made immutable.

`BPF_F_ALLOW_MULTI` is deliberate. `BPF_F_ALLOW_OVERRIDE` would let us displace another
program and would let another program displace us - the second half of which is a capture
bypass. With `ALLOW_MULTI`, all attached programs run and the connection is redirected if any
of them redirects it. Interaction with another sidecar that also rewrites the destination is
undefined and is recorded as a limitation (section 21).

`<podUID>` in the pin path comes from the resolved pod cgroup basename, not from the Downward
API, keeping the "no Downward API" constraint. If the basename does not match V8's pattern, a
hash of the full path is used instead.

#### 6.8.3 Restart and idempotency

The proxy container can restart - a crash, an OOM kill, a liveness failure - while the agent
container keeps running. During that window, if the links were unpinned, capture would be
absent and the agent's traffic would flow **directly to the internet, unfiltered**. That is
the worst outcome in the entire design: a silent, complete bypass with no error anywhere.

Pinning prevents it. The links persist in bpffs independently of the process. On restart:

```
1. Try link.LoadPinnedLink(<pinRoot>/aksh/<podUID>/<progName>.link).
2. If it loads: call link.Update(newProg) - an ATOMIC program swap with no window in
   which the cgroup is unattached.
3. If it does not load (first start, or a stale pin from a previous pod on this node):
   remove any stale pin and attach fresh.
4. Stale-pin detection: a pin whose recorded cgroup id does not match the currently
   resolved pod cgroup id is stale and is removed. Pins for pod UIDs that no longer
   exist under the host cgroup root are also removed, bounded to 100 per startup so a
   corrupted bpffs cannot stall startup indefinitely.
```

Maps are **not** re-created on restart if the pinned `pair_orig_dst` loads, so connections in
flight across the restart keep their records.

**In-flight connections.** Already-accepted downstream connections die with the process; the
agent sees a connection reset and retries, which is correct and visible. Connections that were
redirected but not yet accepted find no listener and are refused; the agent sees
`ECONNREFUSED`. Neither case leaks traffic. Records for those connections remain in
`pair_orig_dst` and are removed by the freshness bound and LRU pressure.

**Uncertainty, stated plainly.** I believe a pinned cgroup `bpf_link` does not prevent the
kubelet from removing the pod cgroup: `cgroup_bpf_release()` detaches programs when the cgroup
is destroyed, and the pinned link then refers to a released cgroup. I have not verified this
on 5.15, and if it is wrong the consequence is leaked pod cgroups on the node, which is a
serious operational bug. This is **OQ-S1a-01** and is a required validation on the kind demo.
`Options.PinLinks` exists so that the behaviour can be turned off; if it is turned off, a
proxy restart is a capture gap and the trade-off must be made knowingly.

#### 6.8.4 Detach and shutdown

On `SIGTERM`:

```
1. Stop accepting; the accept loop returns.
2. Wait up to DrainTimeout (30s) for in-flight connections; then force close.
3. Do NOT detach the BPF programs. Do NOT unpin.
```

Step 3 is deliberate and is the opposite of what feels tidy. Detaching on shutdown creates
exactly the bypass window described in 6.8.3: between the proxy stopping and its replacement
attaching, the agent's traffic would be unfiltered. Leaving the links attached means that
during a proxy outage the agent's connections are redirected to a port with nothing listening
and are **refused**. Failing closed is loud and safe; failing open is quiet and wrong.

Cleanup happens when the pod is destroyed and the kernel releases the cgroup. An explicit
`aksh-proxy detach` subcommand exists for operators and is documented as a debugging tool that
opens a bypass while the pod is running.

#### 6.8.5 Attachment health check

The startup gates prove capture works at t=0. Nothing in the design so far proves it is still
working at t=1 hour. Two of the recorded risks are precisely about losing attachment while the
process keeps running: N4 (a co-resident pod with `CAP_BPF` unpins or replaces our links) and
R-03. A silent loss of attachment is the worst failure in the phase - the agent's traffic goes
straight out, unfiltered, with no error anywhere - so detection cannot be left implicit.

A single goroutine, started when the accept loop starts and stopped by the same context,
re-verifies attachment on an interval.

| Property | Value |
| -------- | ----- |
| Interval | `Options.AttachCheckInterval`, default **30 s**, range [10 s, 60 s]. **It cannot be disabled.** `0` is rejected by `Validate()` and there is no `AllowUnsafeStartup` escape for it, because the check is half of MC-S1a-01 (6.8.6) and a capture-integrity control with an off switch is not a control |
| Mechanism (`PinLinks == true`) | Re-open each pinned link with `BPF_OBJ_GET` and read its `BPF_OBJ_GET_INFO_BY_FD` link info. Assert the pin still exists, that its `prog_id` equals the id recorded at attach, and that its `cgroup_id` equals the resolved pod cgroup id. This detects removal *and* replacement, which is what N4 actually threatens |
| Mechanism (`PinLinks == false`) | There is no pin to inspect and no external actor that can reach the links, because the process holds the only fds. The check degrades to asserting those fds are still valid and logs at DEBUG that it is running in the reduced mode |
| Capability | The check must run with `CAP_BPF` only, since it runs after the drop. `BPF_OBJ_GET` plus `BPF_OBJ_GET_INFO_BY_FD` is chosen for that reason: `BPF_PROG_QUERY` on a cgroup is the more direct check but needs `CAP_NET_ADMIN`, which is gone by then. See OQ-S1a-08 |
| Action on failure | Log `capture.attach_lost` at **ERROR** with the link name, the expected and observed ids, and the check that failed; increment the `capture:attach_lost` decision counter; then **exit non-zero**. There is no re-attach attempt: attaching needs `CAP_NET_ADMIN`, which the process dropped deliberately, so the only honest response is to terminate and let the kubelet restart the container into a full, privileged startup that re-attaches and re-probes |
| Action on transient error | An error that is not a proof of detachment - `EINTR`, `ENOMEM`, a read that fails for a reason unrelated to the link - is logged at WARN and retried on the next tick. Three consecutive inconclusive checks are escalated to the failure path, because "I cannot tell" sustained is not different from "it is gone" |
| Metric | `RecordDecision("blocked", "capture:attach_lost", "")` on failure; the successful path emits nothing, because a per-minute success counter is noise |

Exiting does not by itself stop the bypass: if the links are gone, the agent container is
already unprotected and killing the proxy does not change that. What exiting does is make the
condition **loud** - the sidecar goes un-Ready, the restart re-attaches and re-runs every gate
in 6.7, and the event is in the log with an ERROR level that section 17.2 lists as alertable.
The alternative, continuing to serve while knowing capture is gone, would be the design
pretending to enforce something it no longer enforces.

The check reads kernel objects and shares no mutable state with the connection path; its row
is in the section 16 table.

#### 6.8.6 MC-S1a-01: the mandatory pin-root control

Iteration 1 left the shared-bpffs exposure (N4, R-03, OQ-S1a-05) as an acknowledged trade-off
with a detection mechanism attached. That is not enough for a **direct capture-bypass path**:
INV-4 is a fail-closed invariant, and an invariant defended only by a comment is defended by
nobody. 5A therefore carries a mandatory control, **MC-S1a-01**, made of two halves that are
both required and neither of which is configurable away.

**Half one: a pin is only created into a subtree this process exclusively owns (gate P15).**

```
Before any pin is created, with PinLinks == true:
 1. statfs(pinRoot).Type == BPF_FS_MAGIC (0xcafe4a11), else E_NO_BPFFS.
 2. mkdir <pinRoot>/aksh          mode 0700, then <pinRoot>/aksh/<podUID> mode 0700,
    each created with the mode rather than created and chmod-ed, so there is no
    window in which the directory exists with a wider mode. Record, per directory,
    whether THIS call created it (mkdir returned success) or it already existed
    (mkdir returned EEXIST). That distinction drives step 3 and it is the only
    place ownership may be established.
 2a. If this call created the directory: fchownat it to
    (opts.ProxyUID, opts.ProxyGID) immediately, before any pin is written into it.
    P15 runs in phase A, before the privilege drop of 6.6, so the process still
    holds UID 0 and the chown succeeds; that is precisely why the gate is placed
    there and not after the drop. Creation is done with O_DIRECTORY|O_NOFOLLOW and
    the chown is issued against that fd, not against the path, so the directory
    that is chowned is provably the one that was just created.
 3. For each of the two directories, lstat and assert: it is a directory, not a
    symlink; st_uid == opts.ProxyUID; st_gid == opts.ProxyGID; the permission bits
    are exactly 0700. For a directory created in step 2a this re-reads and confirms
    the handoff rather than trusting it. For a pre-existing directory it is the
    whole of the check.
 4. Any deviation -> E_PIN_ROOT_UNSAFE, exit non-zero. For a PRE-EXISTING directory,
    do NOT chmod or chown it into shape: a directory of ours that already existed
    with the wrong mode or the wrong owner was made by somebody else, and repairing
    it would destroy the only evidence of that. The step 2a chown is not an exception
    to this rule, because it applies only to a directory this process itself created
    in this call, which by definition no other party has ever owned.
 5. Record the two directories' inode numbers; the health check re-asserts steps 3
    against those inodes on every tick, so a directory swapped underneath us is
    detected as well as one that was wrong at startup.
 6. Retain the `O_DIRECTORY|O_NOFOLLOW` fd from step 2a for the life of the process,
    and immediately before each pin write, `fstat` it and re-assert step 3 against
    the retained fd, then `lstat` the path and assert it resolves to the same inode.
    Pin, then re-assert once more that the pinned entry sits under that inode.
 7. Immediately after each successful `BPF_OBJ_PIN`, `chown(pinPath, ProxyUID,
    ProxyGID)` the pinned link/map to the post-drop identity (1774:1774). This is
    the load-bearing ownership handoff, not tidiness: `BPF_OBJ_GET` resolves the
    pin through the ordinary VFS, so a post-drop `CAP_BPF`-only process can only
    open a pin it owns.
```

> **[Reconciled P9a]** The WSL2 kernel spike (5.15.167.4) established the exact ownership
> facts now encoded by `loader_linux.go` and UT #111-113: a link pin left **root-owned 0600**
> yields **`EACCES` (13)** to a post-drop `CAP_BPF`-only process performing `BPF_OBJ_GET`
> (a bpffs *file-permission* failure, not a capability failure); chowning the pin to the
> post-drop uid (1774) makes `BPF_OBJ_GET`/`BPF_OBJ_GET_INFO_BY_FD` succeed. Opening the pin
> with **`BPF_F_RDONLY` is a rejected alternative** — it fails with **`EINVAL` (22)** on 5.15
> and is not a usable escape hatch for the `EACCES` case. (Closes Findings improvement #1 / #2
> and TD-3.)

**On the check-to-use gap, stated honestly.** Step 6 narrows the window between
verification and the pin write; it does not eliminate it. The elimination would be to
anchor `BPF_OBJ_PIN` to a directory fd rather than a path, which is exactly what the
`BPF_F_PATH_FD` flag does - and it landed in **6.5**, far above this design's 5.15 floor
(ADR-S1a-05). On 5.15 the pin call takes a path and resolves it itself, so no amount of
userspace care can make the pin write and the verification a single atomic operation. The
residual is therefore: a privileged co-resident attacker who can swap `<pinRoot>/aksh/<podUID>`
in the microseconds between the step 6 re-assert and the kernel's own path walk could place
one pin in a directory of their choosing. That attacker already needs root or
`CAP_DAC_OVERRIDE` on a shared bpffs, which is the same precondition as the N4 case this
section exists to bound, and the post-pin inode re-assert makes a successful swap loud
rather than silent. When the kernel floor rises above 6.5, `BPF_F_PATH_FD` closes this
properly and step 6 should be replaced by it; that is recorded in section 23.

**Why DAC is a real control here and not a nicety.** Iteration 1 asserted that "bpffs
permissions are advisory against a `CAP_BPF` holder". **That was wrong and is corrected here.**
`BPF_OBJ_GET` resolves a path through the ordinary VFS and is subject to ordinary permission
checks; `CAP_BPF` grants the ability to call `bpf()`, not the ability to traverse a directory
that denies you. A co-resident pod therefore needs, in addition to `CAP_BPF` and a
`/sys/fs/bpf` `hostPath`, either UID 1774 in its own user namespace mapping to ours, UID 0,
or `CAP_DAC_OVERRIDE`, before it can open our pins at all. That is a materially smaller set of
pods than "anything with `CAP_BPF`", and P15 is what makes the statement true rather than
hoped for.

**Half two: the attachment health check is mandatory (6.8.5).** It cannot be set to `0`, it
cannot be relaxed past 60 s, and its failure action is termination, not a log line. It is the
control for the residual case that half one does not close - a co-resident pod running as root
that opens a pin and calls `BPF_LINK_DETACH` or `BPF_LINK_UPDATE`. That case loses capture,
and the only thing that helps is noticing quickly and refusing to keep serving.

**Why unpinning alone can no longer disable capture.** Step 7 of 6.8.2 retains the link fds
for the life of the process. A `bpf_link` is refcounted; removing its bpffs entry drops one
reference, and the link stays attached while this process holds an fd. So the cheapest attack
in N4 - unlink the pin - costs us the *restart* guarantee and nothing else, and the health
check reports it within 30 s. Detaching the link is a different and louder operation that
requires opening the pin first, which is what half one is for.

**What is left, stated plainly.** A co-resident pod that is root, holds `CAP_BPF`, and mounts
the node's `/sys/fs/bpf` can still detach our links, and we will exit within 30 s rather than
prevent it. Only a bpffs this pod does not share removes that, and a per-pod bpffs cannot be
mounted from inside the pod at 5A's capability set - `mount(2)` needs `CAP_SYS_ADMIN`, which
this design deliberately does not request. It is therefore an S5 injector requirement (6.1.4)
and OQ-S1a-05 is recast accordingly: the question is no longer "should we?" but "by which
mechanism, and when". The alternative of not pinning at all was considered and rejected: it
removes this exposure but reopens the restart bypass in 6.8.3, which needs no adversary at
all, and trading an attacker-gated bypass for an unconditional one is not a security
improvement.

**MC-S1a-01 is a requirement, not a recommendation.** An implementation that pins without
P15, or that ships an off switch for the health check, does not conform to this design.

### 6.9 Non-TCP egress and IPv6

#### 6.9.1 Replacing S1's iptables filter guard

S1 section 1 relied on an iptables `filter`/`OUTPUT` rule to drop non-TCP egress, so that an
agent could not exfiltrate over UDP or a raw socket (INV-3's protocol axis, S7 B4). Removing
iptables removes that guard, and dropping it silently would be a regression, so 5A replaces it
in the same place the rest of capture lives:

| Program | Attach type | Behaviour |
| ------- | ----------- | --------- |
| `aksh_sock_create` | `BPF_CGROUP_INET_SOCK_CREATE` | Return 0 (deny, `EPERM` from `socket()`) for any `type` other than `SOCK_STREAM`, unless the caller is the proxy UID. This blocks raw sockets, `SOCK_DGRAM` and `SOCK_SEQPACKET` at creation |
| `aksh_sendmsg4` | `BPF_CGROUP_UDP4_SENDMSG` | Return 0 unless the destination is exactly the DEV-01 DNS server and port, or the caller is the proxy UID. The port comparison is `ctx->user_port == cfg->dns_port`, byte-wise on two network-order fields, exactly as in `connect4` step 6 |
| `aksh_sendmsg6` | `BPF_CGROUP_UDP6_SENDMSG` | Return 0 unconditionally, except for the proxy UID |

The DNS exception (DEV-01) remains the single named INV-3 exception and is now enforced
narrowly - one address, one port, from `aksh_config` - rather than by an iptables rule
matching a port number.

**ADR-S1-03's ICMPv6 carve-out is withdrawn.** It existed because iptables filters *packets*,
so a rule dropping non-TCP egress would also drop kernel-generated Neighbour Discovery and
Path MTU Discovery, breaking IPv6 at the link layer. cgroup hooks filter *socket operations
performed by processes in the cgroup*; kernel-generated ICMPv6 has no such socket and is
untouched. The carve-out is not needed and adding it would create a permitted egress path for
no benefit.

**User-initiated ICMPv6 is a different case, and it is denied on purpose.** `ping6` and
anything else that opens `SOCK_RAW` or `SOCK_DGRAM` with `IPPROTO_ICMPV6` is blocked at socket
creation by `aksh_sock_create`, which permits only `SOCK_STREAM` for non-proxy UIDs. That is
the desired behaviour and not an oversight: a raw socket is a general-purpose egress channel
that carries arbitrary bytes past every control in this design, so it is exactly what INV-3
exists to close. The cost is that IPv6 diagnostics from inside the agent container do not
work, which is consistent with IPv6 being denied outright in 5A (6.9.2) and is recorded in
section 21. The kernel's own NDP and PMTU traffic, which is what ADR-S1-03 was actually
protecting, is unaffected because it never passes through a socket in this cgroup.

#### 6.9.2 IPv6 - designed, denied

IPv6 is fully designed so that the later phase is an implementation, not a redesign.

| Element | Design |
| ------- | ------ |
| Capture | `aksh_connect6` mirrors `connect4`, reading `ctx->user_ip6[4]` and rewriting to `::1` port 15001 |
| Value type | `struct orig_dst` gains `__u32 ip6[4]` at offset 24 (total 40 bytes); `flags & DST_IPV6` selects which address field is live. The current layout's `flags` and `pad` fields exist so this is an append, not a rewrite |
| Key type | `struct pair_key6 { __u32 ip6[4]; __u32 port; }` in a third map, `pair6_orig_dst`, because widening the existing key would change every IPv4 lookup |
| `sock_ops` | The same handler, branching on `skops->family`, reading `local_ip6[4]` |
| Listener | A second `tcp6` listener on `[::1]:15001`; `Resolve` dispatches on the peer's family |
| Attach | Both `connect4` and `connect6` links on the same pod cgroup |
| Denial in 5A | `aksh_connect6_deny` is attached at `BPF_CGROUP_INET6_CONNECT` and returns 0 unconditionally for non-proxy UIDs, so `connect()` fails with `EPERM` |

`EPERM` at `connect()` is the right failure: `getaddrinfo` returns both families, Happy
Eyeballs tries IPv6 first, gets an immediate error, and falls back to IPv4 within
milliseconds. A silent drop would produce a multi-second stall on every connection.

`Options.IPv6Mode` is a closed enum with values `IPv6Deny` and `IPv6Capture`. Only `IPv6Deny`
is legal in 5A; `Validate()` rejects `IPv6Capture` with "IPv6 capture is not implemented in
phase 5A". The option exists now so that the later phase does not have to change the shape of
the configuration.

---

## 7. Core data types

All types below are **new** unless stated otherwise. Existing types are quoted verbatim and
are not modified.

### 7.1 Kernel-facing types (Go mirrors of the C structs)

```go
// NEW - internal/dataplane/capture/types.go
// Field order, sizes and padding mirror section 6.4.1 exactly. cilium/ebpf marshals
// these with native endianness; section 6.4.3 defines what the bytes mean.

type origDst struct {
    IP      uint32 // network-order address bytes
    Port    uint16 // network-order port bytes
    Flags   uint16 // bit0 dstIPv4, bit1 dstIPv6 (reserved)
    UID     uint32 // host order; real UID that called connect()
    Pad     uint32
    StampNS uint64 // CLOCK_MONOTONIC nanoseconds, taken in connect4
}

type pairKey struct {
    IP   uint32 // network-order address bytes
    Port uint32 // host-order port, zero-extended from uint16; see 6.4.1
}

type akshConfig struct {
    ProxyUID     uint32
    ListenerIP4  uint32 // network order
    ListenerPort uint16 // network order; written with hostPortToNet
    Flags        uint16
    DNSIP4       uint32 // network order; 0 disables the exception
    DNSPort      uint16 // network order; written with hostPortToNet, as ListenerPort
    Pad          uint16 // must be zero
    Pad2         uint32 // must be zero; mirrors the C compiler's alignment hole
    Reserved     uint64
}

const (
    flagCaptureEnabled uint16 = 1 << 0
    flagBlockNonTCP    uint16 = 1 << 1
    flagDenyIPv6       uint16 = 1 << 2

    dstIPv4 uint16 = 1 << 0
    dstIPv6 uint16 = 1 << 1
)
```

### 7.2 Connection-facing types

```go
// NEW - internal/dataplane/listener/types.go

// Protocol is the closed enum produced by the discriminator. It is not a parallel of
// policy.Transport: it distinguishes wire framings, two of which map onto the single
// policy.Transport value TransportPlaintext. Transport() performs that mapping so that
// no call site invents its own.
type Protocol int

const (
    ProtocolUnknown Protocol = iota // zero value rejects (INV-4)
    ProtocolTLS
    ProtocolHTTP1
    ProtocolH2CPreface
)

func (p Protocol) String() string
func (p Protocol) Transport() (policy.Transport, bool) // false for Unknown and H2CPreface

// RejectClass is the closed enum for S1 section 8's transport rejections.
type RejectClass int

const (
    RejectNone RejectClass = iota
    RejectNoOriginalDst            // T1
    RejectLoopGuard                // T2
    RejectNoSNI                    // T3
    RejectHandshake                // T4
    RejectUnsupportedProtocol      // T5
    RejectIdentityMismatch         // T6 - decided by S4 stage 1, never raised in 5A
    RejectResourceLimit            // T7
    RejectPlaintextUnresolvable    // T8
    RejectPlaintextRegistryUnavail // T9
)

func (r RejectClass) String() string // "no_original_dst", "loop_guard", ...
func (r RejectClass) Code() string   // "T1", "T2", ...

// ConnContext is the per-connection state 5A owns. It is created at accept, is confined
// to the connection's own goroutine, and is what 5A hands to 5B.
type ConnContext struct {
    ConnID         string         // 128-bit random hex; correlates log lines, not a RequestID
    Downstream     net.Conn       // the peeked-and-restored connection
    PeerAddr       netip.AddrPort // the agent socket's local tuple
    OriginalDst    netip.AddrPort // kernel-attested, from BPFDestinationResolver
    OriginUID      uint32         // from orig_dst.uid
    Protocol       Protocol
    Transport      policy.Transport
    CandidateSNI   string // canonical A-label; empty for plaintext
    NegotiatedALPN string
    AcceptedAt     time.Time
}
```

### 7.3 The handoff to 5B

5A does not construct `pipeline.IdentityInput`; 5B does, from `ConnContext` plus the parsed
request. The mapping is fixed now so the shapes cannot drift:

| `pipeline.IdentityInput` field (existing) | Source |
| ----------------------------------------- | ------ |
| `SNI string` | `ConnContext.CandidateSNI` |
| `AuthorityHost string` | 5B, from `Host` or `:authority` |
| `AuthorityPort uint16` | 5B, from `Host` or `:authority` |
| `DestinationPort uint16` | `ConnContext.OriginalDst.Port()` - the kernel-attested port |

The existing doc comment on `DestinationPort` says "kernel-attested port from
`SO_ORIGINAL_DST`". The value is now kernel-attested from a BPF map. The field's contract -
the port the agent actually dialled, which the agent cannot forge - is unchanged. 5B corrects
the comment; no signature changes.

---

## 8. API reference - the three frozen interfaces

The interfaces below are quoted from `internal/dataplane/interfaces.go` and are **not
modified by this phase**. `internal/dataplane/dataplane_test.go` asserts their existence and
method sets and stays green.

```go
// DestinationResolver recovers the pre-NAT destination of an
// intercepted connection. The destination is kernel-attested: it is
// read from a BPF map written by the capture programs, not from a
// socket option (see docs/design/S1a-dataplane-capture.md section 6.3).
type DestinationResolver interface {
	Resolve(conn net.Conn) (netip.AddrPort, error)
}

// LeafSource supplies a TLS certificate for a requested SNI,
// minted on the fly and backed by a cache.
type LeafSource interface {
	CertificateFor(ctx context.Context, serverName string) (*tls.Certificate, error)
}

// UpstreamDialer establishes a verified TLS connection to the true
// destination. The pool key includes credID per INV-8 rule 7 - a pooled
// connection must never be reused across credential identities.
type UpstreamDialer interface {
	DialUpstream(ctx context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error)
}
```

(The `UpstreamDialer` comment in the repository uses a Unicode dash where this document, which
is ASCII-only, uses a hyphen. The source file is unchanged.)

The `DestinationResolver` doc comment used to name `SO_ORIGINAL_DST`, which stopped being
accurate the moment the destination started coming from a BPF map. **That comment has now
been corrected in the repository** (see 24.2): it reads as quoted above. A doc comment is not
part of the signature, so correcting it does not break the freeze - no identifier, parameter,
return type or method set changed, and `internal/dataplane/dataplane_test.go` stays green. The
correction was made rather than deferred because a comment that names the wrong mechanism is
how the next reader learns the wrong thing.

| Interface | 5A implementation | Package |
| --------- | ----------------- | ------- |
| `DestinationResolver` | `capture.BPFDestinationResolver` | `internal/dataplane/capture` |
| `LeafSource` | `tlsterm.CachedLeafSource` | `internal/dataplane/tlsterm` |
| `UpstreamDialer` | `upstream.DirectDialer` | `internal/dataplane/upstream` |

### 8.1 `capture.BPFDestinationResolver`

```go
// NEW - internal/dataplane/capture/resolver.go   (//go:build linux)

// BPFDestinationResolver recovers the pre-redirect destination of an accepted
// connection from the pair_orig_dst BPF map. It is safe for concurrent use.
type BPFDestinationResolver struct {
    pairMap  *ebpf.Map // pair_orig_dst
    proxyUID uint32
    maxAge   time.Duration // freshness bound, default 15s
    now      func() uint64 // CLOCK_MONOTONIC nanoseconds; injectable for tests
    metrics  audit.MetricsRecorder
}

func NewBPFDestinationResolver(
    pairMap *ebpf.Map,
    proxyUID uint32,
    maxAge time.Duration,
    metrics audit.MetricsRecorder,
) (*BPFDestinationResolver, error)

func (r *BPFDestinationResolver) Resolve(conn net.Conn) (netip.AddrPort, error)
```

`Resolve` behaviour, in order. Every error is terminal for the connection; none is retried and
none is substituted with a guess (INV-8).

```
 1. addr, ok := conn.RemoteAddr().(*net.TCPAddr); if !ok -> ErrNotTCP              -> T1
 2. peer := addr.AddrPort() with Addr().Unmap()
    if !peer.Addr().Is4() -> ErrAddressFamily (IPv6 is denied in 5A)               -> T1
 3. key := pairKey{IP: netIPToAddr(peer.Addr()), Port: uint32(peer.Port())}
    (zero extension of a uint16 into the low half of the __u32; sock_ops wrote the
     same 32-bit host-order value from bpf_sock_ops.local_port - see 6.4.1)
 4. val, err := pairMap.LookupAndDelete(key)
       ErrKeyNotExist -> ErrNoOriginalDestination                                  -> T1
       other error    -> ErrMapUnavailable (wrapped)                               -> T1
 5. if val.UID == r.proxyUID -> ErrLoopGuard                                        -> T2 + alert
 6. if now() - val.StampNS > maxAge -> ErrStaleEntry                                -> T1
    (unsigned subtraction; a stamp in the future is a clock anomaly and is also stale)
 7. if val.Flags & dstIPv4 == 0 -> ErrMalformedEntry                                -> T1
 8. dst := netip.AddrPortFrom(addrToNetIP(val.IP), netPortToHost(val.Port))
 9. if !dst.IsValid() || dst.Port() == 0 -> ErrMalformedEntry                       -> T1
10. return dst, nil
```

Design points:

- **`LookupAndDelete`, not `Lookup`.** The PoC leaves the entry in place, reasoning that
  `sock_ops` refreshes a reused tuple before the next `accept()`. That holds for *redirected*
  connections, but a connection reaching the listener **without** being redirected - for
  example a process in the pod dialling `127.0.0.1:15001` directly, which `connect4` step 5
  deliberately does not capture - could inherit a stale entry left by an earlier connection
  that used the same ephemeral port, and would be attributed a destination it never asked for.
  Consuming the entry makes that impossible.
  `BPF_MAP_TYPE_LRU_HASH` has supported `BPF_MAP_LOOKUP_AND_DELETE_ELEM` since 5.14, below our
  5.15 floor.
- **The freshness stamp is defence in depth.** With consumption in place the only remaining
  window is an entry written for a connection that is never accepted, whose ephemeral port is
  later reused by a non-redirected connection to the listener. 15 s bounds it: comfortably
  above the 5 s upstream-connect budget and any realistic accept latency, comfortably below
  ephemeral-port reuse intervals under normal churn.
- **`maxAge` uses `CLOCK_MONOTONIC`.** `bpf_ktime_get_ns()` is monotonic and unaffected by
  wall-clock steps, so `now()` must read `CLOCK_MONOTONIC`
  (`unix.ClockGettime(unix.CLOCK_MONOTONIC, ...)`). Using `time.Now()` here would be a bug.
  The injected `now` exists so the unit test proves the comparison rather than the clock.
- **On non-Linux builds** the package exposes `capture.ErrUnsupportedPlatform` and a
  constructor that always fails, so `cmd/aksh-proxy` compiles on Windows and refuses to run.

> **[Reconciled P9a]** `resolver_linux.go` adds two constructor sentinels beyond the sketch
> above: `ErrMissingMap` (nil pair map, UT #119) and `ErrInvalidMaxAge` (non-positive
> `maxAge`, UT #120). At resolve time every rejection wraps the T1 umbrella
> `ErrNoOriginalDestination` (so `errors.Is(err, ErrNoOriginalDestination)` classifies them
> uniformly), and the stale/malformed cases *additionally* wrap `ErrStaleEntry` /
> `ErrMalformedEntry` via `errors.Join(...)` so the specific cause survives for diagnostics
> (both classify via `errors.Is`). The injectable `now func() uint64` CLOCK_MONOTONIC seam,
> a future-stamp guard, and a nil-conn guard are implemented as specified above.

### 8.2 `tlsterm.CachedLeafSource`

```go
// NEW - internal/dataplane/tlsterm/leafsource.go   (platform independent)

// CachedLeafSource mints per-identity leaf certificates signed by the CAProvider,
// using one long-lived ECDSA P-256 key for every leaf (ADR-S1-01), and caches them
// in a bounded LRU keyed by (canonical identity, CA generation).
type CachedLeafSource struct {
    ca       pki.CAProvider
    leafKey  *ecdsa.PrivateKey // generated once at construction
    mu       sync.Mutex
    lru      *list.List // MRU at front; elements hold *leafEntry
    index    map[leafCacheKey]*list.Element
    maxEntry int
    ttl      time.Duration
    lifetime time.Duration
    backdate time.Duration
    limiter  *rate.Limiter // mint rate, section 13
    now      func() time.Time
    metrics  audit.MetricsRecorder
}

type leafCacheKey struct {
    identity   string // canonical A-label, lowercase, no trailing dot
    generation int64  // pki.CAProvider.Generation()
}

type leafEntry struct {
    key     leafCacheKey
    cert    *tls.Certificate
    expires time.Time
}

func NewCachedLeafSource(ca pki.CAProvider, opts LeafOptions) (*CachedLeafSource, error)

func (s *CachedLeafSource) CertificateFor(ctx context.Context, serverName string) (*tls.Certificate, error)
```

`CertificateFor` behaviour:

```
1. if ctx.Err() != nil -> return ctx.Err()
2. id, err := CanonicaliseServerName(serverName)
      empty, IP literal, longer than 253 bytes, any label longer than 63 bytes, IDNA
      failure, or any character outside LDH after A-label conversion
                                                 -> ErrInvalidServerName          -> T3
3. gen := s.ca.Generation()
4. lock; e, ok := index[{id, gen}]
      ok and e.expires.After(now): move to front; unlock; record hit; return cert
      ok and expired:              remove; fall through
   unlock
5. if !limiter.Allow() -> ErrMintRateExceeded                                      -> T7
6. caCert, caKey, err := s.ca.CA(); err -> ErrCAUnavailable (fail closed)          -> T4
7. mint:
     SerialNumber:          crypto/rand, 128 bits, positive
     Subject.CommonName:    id
     DNSNames:              [id]
     NotBefore:             now - backdate
     NotAfter:              now + lifetime
     KeyUsage:              DigitalSignature
     ExtKeyUsage:           ServerAuth
     BasicConstraintsValid: true, IsCA: false
     PublicKey:             s.leafKey.Public()
     SignatureAlgorithm:    ECDSAWithSHA256
     signed by (caCert, caKey)
8. lock; insert at front; if len > maxEntry evict from the back; unlock
9. entries created under a stale generation are never returned, because the generation is
   part of the key; they age out by LRU pressure and TTL rather than by an explicit sweep
```

Notes:

- The cache key is **exact**. No wildcard normalisation, no suffix matching, no "close enough"
  fallback: a leaf-cache hit for the wrong identity is a cross-identity confusion bug, the
  highest-severity failure this component can have.
- **`Generation()` returns `int64`**, matching `internal/pki` in code. S5's prose writes
  `Generation() uint64` and `Signer() (*x509.Certificate, crypto.Signer)`. The **code is
  authoritative**: the real interface is
  `CA() (*x509.Certificate, crypto.Signer, error)` and `Generation() int64`. The S5 prose is
  stale and should be corrected in the PKI phase (OQ-S1a-03). 5A changes neither.
- `CanonicaliseServerName` lives in `tlsterm`, is a pure function, and is exported so that 5B
  applies the identical transformation to `Host` and `:authority`. INV-8 compares canonical
  forms, not raw bytes, and two implementations of "canonical" would be a confusion bug
  waiting to happen.
- 5A ships `pki.SelfSignedProvider`: a test and demo implementation that generates an
  in-memory ECDSA P-256 CA at construction, returns `Generation() == 1` forever, and exposes
  `CertPEM() []byte` so the demo can publish it to the agent's trust store. It lives beside
  the interface in `internal/pki`, is documented as **not the production provider**, and its
  constructor refuses to run unless `Options.AllowSelfSignedCA` is set.

### 8.3 `upstream.DirectDialer`

```go
// NEW - internal/dataplane/upstream/direct.go   (platform independent)

// DirectDialer establishes one TLS connection per call to the kernel-attested
// destination and verifies the peer against the validated identity. It performs no
// pooling: that is Phase 5C (ADR-S1a-10). credID is accepted, validated and recorded,
// because 5C makes it part of the pool key.
type DirectDialer struct {
    dialer      *net.Dialer
    rootCAs     *x509.CertPool // nil means system roots
    nextProtos  []string
    connectTO   time.Duration // 5s
    handshakeTO time.Duration // 10s
    sem         chan struct{} // bounds concurrent upstream dials
    registry    *listener.SelfDialRegistry
    metrics     audit.MetricsRecorder
}

func NewDirectDialer(opts UpstreamOptions, reg *listener.SelfDialRegistry, m audit.MetricsRecorder) (*DirectDialer, error)

func (d *DirectDialer) DialUpstream(ctx context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error)
```

`DialUpstream` behaviour:

```
1. validate addr.IsValid() && addr.Port() != 0            else ErrInvalidDestination
   validate serverName is canonical and non-empty         else ErrNoServerName
       (5A never dials without an identity to verify against; a plaintext upstream is
        not reachable through this method - see ADR-S1a-11)
   validate credID is either "" (no-auth sentinel) or a non-empty opaque string
2. acquire d.sem, else ErrUpstreamConcurrency                                     -> T7
3. if addr matches the proxy's own listener endpoint - that is, addr.Port() equals
   opts.ListenerPort and addr.Addr() is a loopback address (IPv4 127.0.0.0/8 **or**
   IPv6 ::1, tested with addr.Addr().IsLoopback() so that neither family and no
   4-in-6 mapped form such as ::ffff:127.0.0.1 slips through), the unspecified
   address, or one of this pod's local addresses - fail immediately with ErrLoopGuard
   -> T2 + alert, before any socket is created. The IPv6 forms are checked even though
   5A dials tcp4 only: the guard is cheap, and 23.1's IPv6 phase must not silently
   inherit a half-covered loop guard. This is the deterministic half of the loop guard:
   the only address a self-dial could use to reach our own accept loop is refused
   before connect(), so no timing window exists on the path that actually matters.
4. tcp, err := d.dialer.DialContext(ctxWithTimeout(connectTO), "tcp4", addr.String())
5. register tcp.LocalAddr() in d.registry, before the TLS handshake begins;
   deregister on Close
6. tc := tls.Client(tcp, &tls.Config{
       ServerName:         serverName,   // the VALIDATED identity, never the raw SNI
       RootCAs:            d.rootCAs,    // system roots by default
       MinVersion:         tls.VersionTLS12,
       NextProtos:         d.nextProtos,
       InsecureSkipVerify: false,        // never set; no option can set it
   })
7. tc.HandshakeContext(ctxWithTimeout(handshakeTO)); on failure close and return the error
8. return a wrapper net.Conn that releases d.sem and deregisters on Close
```

**On the registration ordering.** `tcp.LocalAddr()` is only knowable after `connect()`
returns, so step 5 cannot precede step 4 and a window exists in which a dialed connection
is live but not yet in the registry. Two different loops have to be considered, and only
one of them is closed:

- **Direct self-dial** - the dialer is asked for the proxy's own listener endpoint. This is
  closed deterministically by step 3, which refuses before a socket is created. No timing
  window exists, because no connection is ever made.
- **Redirected loop** - capture sends our own egress back to us despite the UID exclusion.
  Here the registry check is a *race*, not a guarantee: the accepting goroutine and the
  dialing goroutine are unsynchronised, and Go's scheduler makes no ordering promise
  between step 5 and the accept. A connection that lands inside the window is classified by
  the map record instead. **This is acceptable only because it is not the primary control.**
  The `orig_dst.uid == proxy_uid` check of 6.5 is the primary one, it is derived from a
  kernel-written record rather than from process-local state, and it has no window at all.
  The registry is defence in depth for the sub-case where no map record exists, and losing
  it for a few microseconds degrades a second-layer check rather than opening a bypass.

We deliberately do not paper over this with a sleep or a retry on the accept path: that
would add latency to every connection to slightly narrow a window on a check that is
already backed by a race-free one.

- `InsecureSkipVerify` is unreachable through `UpstreamOptions`. There is no
  `AKSH_INSECURE_UPSTREAM` and no equivalent. S0 forbids it, and S1 section 5.2 already
  deleted the PoC's version.
- `serverName` is the **validated identity**, supplied by 5B. In the 5A demo, where no
  pipeline exists, the demo entrypoint passes the canonical candidate SNI. The code says so
  in a comment, because that shortcut is only sound while there is no credential to leak -
  and in 5A there is none.
- `credID` is otherwise unused in 5A. Its presence in the frozen signature is exactly what
  lets 5C add pooling without touching a single call site.
- **This is deliberately slower than production.** One TCP connection and one full TLS
  handshake per downstream connection is 5C's problem; making it fast now would mean designing
  the pool twice and designing it without the request path to test it against.

---

## 9. Listener and connection ingestion

### 9.1 The listener

```go
// NEW - internal/dataplane/listener/listener.go

type Listener struct {
    ln        net.Listener
    resolver  dataplane.DestinationResolver
    disc      *Discriminator
    handler   ConnHandler // 5A: passthrough; 5B: the request path
    registry  *SelfDialRegistry
    sem       chan struct{} // max concurrent downstream connections
    hsLimiter *rate.Limiter // handshake rate
    opts      Options
    metrics   audit.MetricsRecorder
    log       *slog.Logger
    wg        sync.WaitGroup
    state     atomic.Int32 // stateNew | stateBound | stateServing | stateClosed (9.1)
}

// ConnHandler is the 5A/5B seam. 5A's PassthroughHandler relays bytes; 5B replaces it
// with the request path without changing the listener.
type ConnHandler interface {
    Handle(ctx context.Context, cc *ConnContext) error
}

func New(opts Options, resolver dataplane.DestinationResolver, h ConnHandler, m audit.MetricsRecorder, log *slog.Logger) (*Listener, error)

// Bind opens the listening socket. It does not accept. It is phase A of the
// two-phase startup in 6.7 and must be called exactly once.
func (l *Listener) Bind() error

// Addr reports the bound address. It is valid only after Bind.
func (l *Listener) Addr() netip.AddrPort

// AcceptProbe accepts exactly one connection for the redirect self-probe (6.7.1).
// It returns ErrServing once Serve has been called, so the probe cannot race the
// accept loop, and ErrNotBound before Bind.
func (l *Listener) AcceptProbe(deadline time.Time) (net.Conn, error)

func (l *Listener) Serve(ctx context.Context) error
func (l *Listener) Shutdown(ctx context.Context) error
```

`Bind` and `Serve` are separate calls, and that separation is what makes the two-phase startup
in 6.7 implementable rather than aspirational. **`Bind` returns only an error.** Iteration 1
had it return the `net.Listener` so the probe could accept on it, and that leaked the
listener's most important internal: a caller holding it could `Close` it, `Accept` on it
concurrently with the accept loop, or keep it alive past `Shutdown`, and none of those misuses
is detectable inside `Listener`. The socket now never escapes. What the probe actually needs
is not the listener but one accepted connection, so that is what `AcceptProbe` gives it, with
the lifecycle constraint expressed as a state check rather than as a comment: `AcceptProbe`
returns `ErrNotBound` before `Bind` and `ErrServing` after `Serve`, so the "probe gate only"
rule is enforced by the type rather than trusted to the caller. `Serve` returns an error if
`Bind` was not called first, so the ordering cannot be got wrong either way. `Shutdown` closes
the socket whether or not `Serve` ever ran, which is how a failed gate leaves no listening
port behind.

The state is a single `atomic.Int32` holding `stateNew`, `stateBound`, `stateServing` or
`stateClosed`, transitioned with `CompareAndSwap`. It replaces the `closed atomic.Bool` of
iteration 1 - a boolean cannot distinguish "bound" from "serving", which is the distinction
the probe gate rests on - and it needs no mutex, so the section 16 lock-ordering statement is
unchanged.

The listener binds `tcp4` on `127.0.0.1:15001`. Binding loopback rather than `0.0.0.0` is a
control, not a default: the redirect always targets `127.0.0.1`, so nothing legitimate arrives
from off-pod, and a wildcard bind would make the sidecar an open relay reachable from any pod
that can route to this one.

### 9.2 Accept loop

```
for {
  conn, err := ln.Accept()
      net.ErrClosed           -> return (shutdown)
      temporary or timeout    -> log WARN, backoff 5ms doubling to 1s, continue
      other                   -> log ERROR, backoff, continue

  if !tryAcquire(sem) {
      metrics: T7 bound="max_downstream_conns"; conn.Close(); continue
  }

  go func() {
     defer release(sem); defer conn.Close()
     cc := &ConnContext{ConnID: randHex16(), Downstream: conn, AcceptedAt: now()}

     // 1. Self-connection detection (S1 section 2.2 case B). This runs BEFORE the map
     //    lookup, because a recursed connection has no map record and would otherwise
     //    be misreported as T1, hiding a loop behind a benign-looking counter.
     if registry.Contains(peerAddrPort(conn)) { reject(T2, alert); return }

     // 2. Original destination (section 8.1).
     dst, err := resolver.Resolve(conn)
     if err != nil { reject(classFor(err)); return }   // T1, or T2 on ErrLoopGuard
     cc.OriginalDst = dst

     // 3. Pod-local destination (S1 section 2.2 case A): ordinary denial, NOT an alert.
     if isPodLocal(dst.Addr()) { reject(T1, quiet); return }

     // 4. Handshake rate limit.
     if !hsLimiter.Allow() { reject(T7, bound="handshake_rate"); return }

     // 5. Discriminate (section 10), under the 10s handshake deadline.
     // 6. Hand to the ConnHandler.
  }()
}
```

`isPodLocal` is evaluated against the full set of addresses assigned to the pod's interfaces,
enumerated at startup and re-enumerated every 30 s, because a CNI can add addresses after the
sidecar starts. S1 section 2.2 requires the full assigned set, not just `127.0.0.0/8`, and
requires the outcome to be an ordinary denial rather than an alert - otherwise the agent can
manufacture alarms at will by dialling its own pod IP in a loop.

In 5A there is no pipeline, so there is nowhere to record an *audited* denial: the connection
is closed as T1 with the `pod_local` metric label and logged at DEBUG. 5B converts it into a
proper audited denial.

**Transport denials in 5A are not durably audited. This is a formal, bounded deviation, not
an oversight, and it is recorded as DEV-S1a-01 so that 5A cannot claim full INV-6
conformance.**

| Field | Value |
| ----- | ----- |
| Id | **DEV-S1a-01** |
| Deviation from | INV-6 obligation 1 (*coverage*: both allow and deny decisions produce an audit record). Obligation 2 (*ordering*) is untouched, because 5A moves no credentials |
| Scope | Exactly the transport-layer outcomes 5A can produce: T1, T2, T5, T7, T9 and the pod-local denial of step 3. Nothing else. No allow path exists in 5A that could fall under it |
| What happens instead | The connection is closed, `RecordDecision("rejected", "<class>", "")` is called (section 17.1), and a `conn.rejected` line is logged with the class and reason. T2 is additionally logged at ERROR and alertable. The outcome is therefore observable; what it is not is *durable evidence* in the S6 sense |
| Owner | 5B (pipeline and audit wiring) |
| Closure criteria | 5B routes every connection through a `Decision`, so a pod-local or transport denial becomes an ordinary stage-6 audited denial. DEV-S1a-01 is closed when the pod-local case in particular produces an `AuditEvent` through `audit.AuditSink`, and the closure is a required item in the 5B design review |
| Expiry | The deviation does not survive 5B. If 5B ships without closing it, that is a review failure, not an inherited condition |

**Why I did not wire a minimal audit path in 5A instead.** I looked at doing it, because
"write it now" is usually the right answer, and the seam does not fit:

- `audit.AuditSink` takes `pipeline.AuditEvent`, whose fields are `Method`, `Path`,
  `PolicyVersion`, `RuleName`, `CredentialID`, `CacheHit`, `Ambiguous` and friends. A
  connection that was closed before a single byte was parsed has none of them. Every field
  would be a zero value, which is not a record, it is a shape.
- `AuditEvent.DenyReason` is a **closed** enum (`internal/pipeline/deny_reason.go`) and it
  contains no transport vocabulary: there is no `no_original_dst`, no `loop_guard`, no
  `pod_local`, no `resource_limit`. The only reachable encodings are `ReasonInternal` or
  `ReasonNone`, both of which would be false, and both of which would pollute the audit stream
  that S4 and S6 are building with records that cannot be classified. Widening the enum from
  5A is a change to a frozen S4 type made by a phase that has no pipeline, which is exactly the
  seam-overloading mistake section 17.1 already regrets making once.
- There is no `AuditSink` **implementation** in the tree: `internal/audit` declares the
  interface and S6 owns the durable writer. 5A wiring a sink would mean 5A also inventing the
  sink, its buffering, and its durability semantics - the very things S0 section 4 says are
  S6's to define.
- The architecture already draws this line. S1 section 2.2 classifies the pod-local case as an
  ordinary denial, and S4's stage 1 (identity) rationale moves T6 into the pipeline **because**
  an
  authorisation outcome must be audited - which is only a meaningful argument if transport
  rejections sit outside that requirement. 5A is not opening a hole; it is sitting inside a
  boundary the architecture already drew, and DEV-S1a-01 exists so that the one genuinely
  uncomfortable case - the pod-local denial, which is arguably a destination *policy* outcome
  rather than a transport one - is named rather than quietly filed under "transport".

Section 15.4 records INV-6 as **partially upheld with DEV-S1a-01** rather than upheld, and
section 21 carries the same statement as a limitation.

### 9.3 Connection lifecycle

| Stage | Deadline | On expiry |
| ----- | -------- | --------- |
| Accept to classified | 10 s (the downstream handshake budget covers the peek) | Close, T5 |
| TLS handshake | 10 s | Close, T4 |
| Handler (5A passthrough) | idle 90 s each direction; progress 60 s | Close |
| Shutdown drain | 30 s | Force close |

Every connection is closed exactly once, by `defer conn.Close()` on the goroutine that owns
it. Nothing else may close a downstream connection; a handler returns an error instead. Single
ownership is what makes the concurrency model in section 16 provable rather than hopeful.

---

## 10. Protocol discrimination

### 10.1 Peek, without consuming

```go
// NEW - internal/dataplane/listener/discriminator.go   (platform independent)

const PeekSize = 24 // exactly the length of the HTTP/2 client connection preface

type Discriminator struct{ timeout time.Duration }

// Classify reads at most PeekSize bytes from conn without consuming them and returns
// the classification plus a net.Conn that replays what was read.
func (d *Discriminator) Classify(conn net.Conn) (Protocol, net.Conn, error)
```

The returned `net.Conn` is a `peekedConn` wrapping a `*bufio.Reader` of size `PeekSize` around
the original connection. `Read` is served from the reader; `Write`, `Close`, `LocalAddr`,
`RemoteAddr` and the three deadline setters delegate to the underlying connection.
`bufio.Reader.Peek(n)` does not consume, so the TLS server sees the ClientHello from byte
zero and no protocol implementation needs to know that discrimination happened.

**24 bytes** is exactly `len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")`, the longest prefix any rule
needs. TLS needs 3; an HTTP/1.x method token needs at most 8 (`OPTIONS` plus a space). Peeking
more would risk blocking on a client that sends a short first segment; peeking less would make
h2c indistinguishable from a request for a resource named `*`.

Short reads are handled by deciding on the shortest sufficient prefix:

```
read with a 10s deadline into buf, growing:
  at >= 3 bytes:  buf[0]==0x16 && buf[1]==0x03 && buf[2]<=0x04     -> ProtocolTLS
  at >= 16 bytes: HasPrefix(buf, "PRI * HTTP/2.0\r\n")             -> ProtocolH2CPreface
  at >= 8 bytes, or on EOF/deadline with fewer:
        the leading token up to the first space is in the closed method set,
        and is followed by a space                                  -> ProtocolHTTP1
  otherwise                                                         -> ProtocolUnknown
EOF or deadline before a decision                                   -> ProtocolUnknown
```

The closed method set is exactly `GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE,
CONNECT`. Matching is byte-exact and case-sensitive, because HTTP methods are case-sensitive
and accepting `get` would be inventing a tolerance the standard does not grant - and every
invented tolerance is a parser-differential opportunity.

`CONNECT` classifies as `ProtocolHTTP1` rather than being rejected here: at this layer a
plaintext `CONNECT` is indistinguishable from any other plaintext request, and ADR-S1-04's
rejection of `CONNECT` is a request-level decision that belongs in 5B, where it can be
recorded properly rather than dropped silently.

### 10.2 TLS detection, precisely

`buf[0] == 0x16` is `ContentType.handshake`. `buf[1] == 0x03 && buf[2] <= 0x04` is the legacy
record version, which every real TLS 1.0 to 1.3 ClientHello sets to `0x0301` or `0x0303`
(TLS 1.3 pins the record layer to `0x0303`). SSLv2-style ClientHello framing is **not**
accepted: it has been prohibited since RFC 6176 and Go's TLS server rejects it regardless. The
record length is not validated here; the TLS stack does that properly two function calls
later, and duplicating it would create a second parser to keep correct forever.

### 10.3 Outcomes

| Classification | 5A outcome | Class | Rationale |
| -------------- | ---------- | ----- | --------- |
| `ProtocolTLS` | Proceed to TLS termination (section 11) | - | The normal path |
| `ProtocolHTTP1` | **Close** | **T9** `plaintext_registry_unavailable` | S1 section 6.1 requires the destination to resolve exactly to a Service ClusterIP through an informer index. That index does not exist until 5B/5C. T9 means precisely "the Service index is unavailable", so this is the correct existing class, genuinely fail-closed, and not a placeholder (ADR-S1a-11) |
| `ProtocolH2CPreface` | Close | **T5** | h2c is unsupported (S1 section 4, S7 B54). S7 B54 remains open: OTLP over h2c does not work today and 5A does not change that |
| `ProtocolUnknown` | Close | **T5** | Anything neither TLS nor recognisable HTTP is not tunnelled (ADR-S1-04) |

`policy.Transport` is reused rather than duplicated: `Protocol.Transport()` maps
`ProtocolTLS -> policy.TransportTLS` and `ProtocolHTTP1 -> policy.TransportPlaintext`, and
returns `false` for the two rejected classifications so no caller can accidentally treat an
unknown framing as plaintext.

### 10.4 What 5A deliberately does not do

The plaintext branch is classified and rejected, not implemented. Implementing it requires the
Services and EndpointSlices informer index, the exact-ClusterIP match, the ExternalName,
headless and selectorless exclusions, and the Service UID and generation binding - all of S1
section 6.1, all of it 5B and 5C work, none of it weakened here. The demo in section 12 is
therefore HTTPS-only, which is stated as a limitation rather than presented as a choice.

---

## 11. TLS termination and the leaf cache

This section implements S1 section 3 unchanged. It is restated only as far as needed to be
implementable; where it repeats S1, S1 remains the authority.

### 11.1 Handshake configuration

```go
base := &tls.Config{
    MinVersion:             tls.VersionTLS12,
    NextProtos:             []string{"h2", "http/1.1"}, // S1 section 3.2; order is significant
    SessionTicketsDisabled: true,                       // S1 section 4
    ClientAuth:             tls.NoClientCert,           // S1 section 3.3
    GetConfigForClient:     term.configForClient,
}
```

`GetConfigForClient` is the SNI capture point, not `GetCertificate`, because it fires before
certificate selection and lets ALPN and everything else depend on the ClientHello. It runs on
every **full** handshake, and disabling session tickets is what guarantees every handshake is
full - so no connection can carry a previously validated identity forward.

```
configForClient(hello *tls.ClientHelloInfo) (*tls.Config, error):
  1. id, err := CanonicaliseServerName(hello.ServerName)
        err -> return nil, ErrNoSNI
               Go sends unrecognized_name and the connection closes            -> T3
               (this covers absent SNI, an IP literal, and any IDNA failure)
  2. cert, err := leafSource.CertificateFor(hello.Context(), id)
        ErrInvalidServerName -> T3;  ErrMintRateExceeded -> T7;  otherwise      -> T4
  3. cfg := base.Clone(); cfg.Certificates = []tls.Certificate{*cert}
  4. record id on the ConnContext; return cfg
```

After `HandshakeContext` returns:

```
cs := tlsConn.ConnectionState()
if cs.DidResume                                     -> T4 + alert  (must be impossible)
if cs.ServerName != cc.CandidateSNI                 -> T4 + alert  (must be impossible)
if cs.NegotiatedProtocol not in {"h2", "http/1.1"}  -> T5
cc.NegotiatedALPN = cs.NegotiatedProtocol
```

The two "must be impossible" assertions are cheap and are exactly the class of invariant that
silently stops holding after a library upgrade. They are assertions, not error handling.

Clock skew: `LeafBackdate` defaults to 5 minutes. Cluster nodes are normally NTP-synchronised
so 5 minutes is generous, but the failure mode when it is too small is a total outage for the
affected agent with a confusing "certificate is not yet valid" error. The value is therefore
configurable and is logged at startup. I would not reduce it below 5 minutes, and I see no
reason to raise it: a skew larger than that already breaks the agent's ability to verify
anything else.

### 11.2 Cache behaviour

The mechanics are in section 8.2. The properties that make the cache a security control rather
than a performance tweak:

- **Bounded** at 1024 entries, because the agent chooses the SNI and therefore chooses the
  keys. An unbounded cache here is an agent-controlled memory-exhaustion primitive.
- **Keyed on `(identity, CA generation)`**, so a CA change invalidates implicitly. Within a
  pod's lifetime `Generation()` never changes (ADR-S5-01: rotation is a pod restart), so in
  practice the generation component costs one integer comparison and buys correctness free.
- **TTL 1 h, shorter than the 24 h leaf lifetime**, so a cached leaf is always replaced well
  before expiry and no handshake can present an expired cached certificate.
- **Eviction is cheap**: a miss costs a 152 us ECDSA signature (measured, S1 section 3.1), not
  a 198 ms RSA keygen-and-sign. This is the whole point of ADR-S1-01's shared key, and it is
  why over-eviction is not a concern worth tuning for.

---

## 12. The 5A demo - minimal end-to-end passthrough

The demo exists to prove the phase: an intercepted HTTPS request from an agent container is
decrypted by Aksh, re-encrypted to the true destination, and returned. It runs on a **kind**
cluster so that real pod-cgroup scoping is exercised. WSL2 would let a root-cgroup attach pass
unnoticed, which is precisely the defect this phase fixes.

### 12.1 What the demo includes

| Included | Excluded |
| -------- | -------- |
| eBPF load, pod-cgroup attach, preflight, self-probe, privilege drop | Policy matching, tokens, audit sink |
| Listener, discriminator, TLS termination with a self-signed demo CA | Plaintext HTTP (T9 by design) |
| `DirectDialer` to the real destination with real verification | Pooling, HTTP parsing, header rewriting |
| Byte relay between the terminated session and the upstream session | IPv6 (denied) |

`PassthroughHandler` performs the relay: after the downstream handshake it calls
`DialUpstream(ctx, cc.OriginalDst, cc.CandidateSNI, "")` and copies bytes in both directions
under the idle and progress deadlines from section 13.2. It is labelled in code as a 5A-only
handler that 5B replaces.

### 12.2 Prerequisites

A Linux host or VM with a cgroup v2 unified hierarchy and kernel 5.15 or newer, plus `docker`,
`kind` 0.23 or newer, `kubectl` and Go 1.26. `clang` 18 is needed **only** to regenerate the
BPF object; the committed artefacts mean the demo does not need it.

### 12.3 Exact commands

```bash
# 0. Confirm the host is cgroup v2 unified and new enough.
stat -fc %T /sys/fs/cgroup            # expect: cgroup2fs
uname -r                              # expect: 5.15 or newer

# 1. Create the cluster.
cat > hack/demo/kind.yaml <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
EOF
kind create cluster --name aksh-5a --config hack/demo/kind.yaml

# 2. Build the sidecar image. CGO_ENABLED=0 is mandatory (section 6.6.3).
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o hack/demo/aksh-proxy ./cmd/aksh-proxy
docker build -t aksh/proxy:5a -f hack/demo/Dockerfile hack/demo
kind load docker-image aksh/proxy:5a --name aksh-5a

# 3. Deploy the demo pod: agent container plus the aksh-proxy native sidecar.
kubectl apply -f hack/demo/demo-pod.yaml
kubectl wait --for=condition=Ready pod/aksh-demo --timeout=120s

# 4. Confirm capture was established and PROVED, not assumed.
kubectl logs aksh-demo -c aksh-proxy | grep -E 'preflight|cgroup|probe|privilege'
# expect, in order:
#   preflight ok kernel=... cgroup2=yes bpffs=yes caps=CAP_BPF,CAP_NET_ADMIN
#   pod cgroup resolved path=/kubepods.slice/kubepods-burstable-pod<uid>.slice checks=V1..V8 ok
#   attached connect4,sockops,sock_create,sendmsg4,connect6_deny,sendmsg6 links=pinned
#   self-probe ok redirected=192.0.2.1:65535 recovered=192.0.2.1:65535
#   privileges dropped uid=1774 gid=1774 caps=CAP_BPF
#   exclusion-probe ok uid=1774 outcome=not_captured

# 5. The demo itself: an intercepted HTTPS request from the agent container.
kubectl exec aksh-demo -c agent -- \
  curl -sS --cacert /etc/aksh/ca.crt -o /dev/null -w '%{http_code} %{ssl_verify_result}\n' \
  https://example.com/
# expect: 200 0

# 6. Prove Aksh was in the path rather than bypassed.
kubectl logs aksh-demo -c aksh-proxy | grep 'conn accepted'
# expect a line with orig_dst=<example.com IP>:443 sni=example.com alpn=h2

# 7. Prove the certificate the agent saw was ours.
kubectl exec aksh-demo -c agent -- sh -c \
  'echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -issuer'
# expect: issuer=CN = aksh-demo-ca

# 8. Prove capture is not port-specific (S7 B1) and that plaintext fails closed.
#    Port 8443 is deliberately a non-standard TLS port. The upstream need not exist:
#    what B1 asserts is that connect4 redirected it at all, which is proved by the
#    proxy recovering 8443 as the original destination port. A port-scoped capture
#    would produce no log line here at all.
kubectl exec aksh-demo -c agent -- sh -c \
  'curl -sS --max-time 5 https://example.com:8443/ >/dev/null 2>&1; echo "exit=$?"'
kubectl logs aksh-demo -c aksh-proxy | grep ':8443'
# expect: a line recording the recovered destination port 8443. Match on the port
# only: example.com's A record is not stable, so asserting a literal IP would make
# the demo fail for a reason that has nothing to do with capture.
kubectl exec aksh-demo -c agent -- curl -sS --cacert /etc/aksh/ca.crt -o /dev/null \
  -w '%{http_code}\n' https://example.com/
kubectl exec aksh-demo -c agent -- curl -sS --max-time 5 http://example.com/ ; echo "exit=$?"
# plaintext is rejected T9 by design: expect a non-zero exit and a T9 log line

# 9. Prove IPv6 fails closed (S7 B2).
kubectl exec aksh-demo -c agent -- curl -sS --max-time 5 -6 https://example.com/ ; echo "exit=$?"
# expect a non-zero exit; the kernel returned EPERM at connect(), no capture attempted

# 10. Prove non-TCP egress is blocked (S7 B4).
kubectl exec aksh-demo -c agent -- sh -c 'curl -sS --max-time 5 --http3 https://example.com/' ; echo "exit=$?"

# 11. Prove the proxy itself is not captured (S7 B52): no T2 anywhere.
kubectl logs aksh-demo -c aksh-proxy | grep -c 'class=T2'    # expect 0

# 12. Prove capture survives a proxy restart (section 6.8.3).
kubectl exec aksh-demo -c aksh-proxy -- kill 1
kubectl wait --for=condition=Ready pod/aksh-demo --timeout=60s
kubectl logs aksh-demo -c aksh-proxy | grep 'links=reused'
kubectl exec aksh-demo -c agent -- curl -sS --cacert /etc/aksh/ca.crt -o /dev/null -w '%{http_code}\n' https://example.com/

# 13. Teardown.
kind delete cluster --name aksh-5a
```

### 12.4 Demo pod shape - the parts that matter

```yaml
spec:
  initContainers:
    - name: aksh-proxy
      image: aksh/proxy:5a
      restartPolicy: Always            # native sidecar: Ready before app containers start
      securityContext:
        runAsUser: 0                   # drops to 1774 itself, after attach
        capabilities:
          drop: ["ALL"]
          add: ["BPF", "NET_ADMIN", "SETUID", "SETGID", "SETPCAP"]
      volumeMounts:
        - { name: host-cgroup, mountPath: /host/sys/fs/cgroup, readOnly: true }
        - { name: bpffs,       mountPath: /sys/fs/bpf }
        - { name: ca,          mountPath: /etc/aksh }
  containers:
    - name: agent
      image: curlimages/curl:8.9.1
      command: ["sleep", "infinity"]
      securityContext:
        runAsUser: 1000                # explicit, numeric, and not 1774 (INV-10)
        allowPrivilegeEscalation: false
        capabilities: { drop: ["ALL"] }
      env:
        - { name: SSL_CERT_FILE, value: /etc/aksh/ca.crt }
      volumeMounts:
        - { name: ca, mountPath: /etc/aksh, readOnly: true }
  volumes:
    - { name: host-cgroup, hostPath: { path: /sys/fs/cgroup, type: Directory } }
    - { name: bpffs,       hostPath: { path: /sys/fs/bpf,    type: Directory } }
    - { name: ca,          emptyDir: {} }
```

The proxy writes the demo CA to `/etc/aksh/ca.crt` on the shared `emptyDir` before it becomes
Ready, and the agent trusts it through `SSL_CERT_FILE`. This is a demo mechanism; the real
trust-distribution design is S5's.

The `hostPath` mounts and the `runAsUser: 0` start are the pod shape S5 must eventually render
through the injector. The security consequences of both are in section 15.3 (N1, N3, N4).

---

## 13. Resource bounds and the timeout budget

This section closes **OQ-S1-01**. Every bound in S1 section 7 now has a number. Where I
disagree with a value proposed at planning time, I say so rather than complying silently.

### 13.1 Bounds

| Bound | Value | Rationale | Class on breach |
| ----- | ----- | --------- | --------------- |
| Max concurrent downstream connections | **512** | The dominant per-connection cost is two TLS sessions (downstream and upstream) at roughly 32 KiB of buffers each, plus goroutine stacks: on the order of 40 MiB at 512, which fits a modest sidecar limit with room for the maps and the leaf cache. It is also far above any realistic agent - an LLM agent making tool calls runs tens of concurrent connections, not hundreds. **Accepted as proposed** | T7 `bound="max_downstream_conns"` |
| Max HTTP/2 streams per connection | **100** | Go's `http2` server defaults to 250. 100 is a deliberate tightening and is still well above what any agent needs. **Accepted as proposed, but insufficient on its own** - see the next row | T7 `bound="max_h2_streams"`; `SETTINGS` refusal, then `RST_STREAM(ENHANCE_YOUR_CALM)` |
| **Max global in-flight requests** | **2048** (a starting value, see below) | **This is an addition, not in the proposed list, and I argue it is required.** 512 connections times 100 streams is 51,200 concurrent requests, each of which in 5B takes a pipeline slot, a token lookup and an audit write. A per-connection cap does not bound the product; only a global cap does. **Derivation, so the number is not a guess:** the *floor* is `max_downstream_conns` = 512, because a cap below that would reject on plain HTTP/1.1 traffic where every connection has one request in flight, and a resource bound that fires in the ordinary case is a bug. Four times the floor is the smallest multiple that also absorbs a full HTTP/1.1 fan-out plus retries without touching the cap, giving 2048. The *ceiling* comes from the memory the cap admits: each in-flight request can hold up to `max_header_bytes` (64 KiB) of attacker-chosen bytes, so 2048 admits 128 MiB worst case, already about three times the ~40 MiB connection-buffer budget derived for `max_downstream_conns`. The next step, 4096, would admit 256 MiB and make headers the dominant memory consumer in the sidecar by an order of magnitude. 2048 is therefore the largest multiple of the connection cap whose worst case stays within the same order as the rest of the budget, and the smallest that never binds on ordinary traffic - the two bounds meet at one value. **It is nonetheless a starting value, not a measured one.** The named tuning signal is the pair of T7 counters: a sustained non-zero `resource_limit:max_inflight_requests` rate while `max_downstream_conns` rejections stay at zero means this cap, and not the connection cap, is the binding constraint and should be raised with a matching reduction in `max_header_bytes` or an increase in the sidecar memory request. 5B owns the measurement because 5B enforces the bound | T7 `bound="max_inflight_requests"` |
| Leaf cache entries | **1024** | The agent chooses the SNI, so it chooses the keys. 1024 leaves at roughly 1 KiB of DER plus overhead is about 2 MiB, and a real agent talks to fewer than 50 distinct hosts. A miss costs 152 us (measured), so over-eviction is harmless. **Accepted as proposed** | evict; no rejection |
| Leaf cache TTL | **1 h** | Must be shorter than the leaf lifetime so a cached entry can never be presented near expiry. **Accepted as proposed** | - |
| Leaf lifetime | **24 h** | Short enough that a leaked leaf is worthless quickly; long enough that TTL, not expiry, drives churn. **Accepted as proposed** | - |
| Leaf `NotBefore` backdate | **5 min** | Tolerates ordinary node clock skew. **Accepted as proposed**, with the caveat in section 11.1: too small is an outage, so it is configurable and logged | - |
| Max request header size | **64 KiB** | Go's default is 1 MiB, which at 512 connections is 512 MiB of attacker-controlled memory. 64 KiB is far above any legitimate request (typical agent requests are under 4 KiB) and 16 times cheaper. **Accepted as proposed**; enforced in 5B where headers are parsed, declared here so the number has one home | T7 `bound="max_header_bytes"`; 431 or `RST_STREAM` |
| TLS handshake rate | **50/s sustained, burst 100** | **Accepted with an explicit caveat.** At 152 us per mint this is 7.6 ms of CPU per second, so this limiter is not protecting the CPU - the connection cap already does that, and for memory the two are redundant. What it actually protects is the accept path against a connection-churn flood. The risk runs the other way: an agent legitimately fanning out 100 parallel tool calls at start-up will burst, and with resumption disabled **every** connection is a full handshake. Burst 100 covers a full refill of the 512-connection pool in five seconds. I would not change either value without measurement, and both are configurable | T7 `bound="handshake_rate"` |
| Leaf mint rate | **50/s, burst 100** | The same limiter class applied at the mint site, so a cache-miss storm across distinct SNIs is bounded independently of the handshake rate | T7 `bound="leaf_mint_rate"` |
| Concurrent upstream dials | **512** | Matched to the downstream cap: 5A is non-pooled, so one downstream connection means at most one upstream connection. 5C replaces this with the pool bounds | T7 `bound="upstream_concurrency"` |
| BPF `cookie_orig_dst` entries | **16384** | **I argue against the proposed 65536.** This map holds one entry per *in-flight* `connect()`, between the syscall and the completion of the TCP handshake - a window of milliseconds. 65536 is 128 times the maximum number of concurrent downstream connections and costs locked memory that on a small sidecar can be several percent of the limit. 16384 is still 32 times the connection cap, ample headroom for connections that are redirected and then abandoned. The memory cost of 65536 is an **estimate, not a measurement**: an LRU hash entry costs its key and value plus roughly 48 bytes of `htab_elem` header, and the map also pre-allocates the bucket array and per-CPU LRU freelists, which puts 65536 entries across both maps somewhere in the region of **6-10 MiB** depending on kernel version and CPU count. The range is wide because the overhead is a kernel implementation detail rather than a documented contract; the decision does not rest on the figure, it rests on the 32x headroom. Map sizing has **no correctness consequence**: LRU eviction of a live entry degrades to a T1 close, which is fail-closed. This is purely a resource decision and I would rather spend the memory on the leaf cache. Configurable, ceiling 65536 | T1 at the listener; `connect4` fails closed with `EPERM` on insert failure |
| BPF `pair_orig_dst` entries | **16384** | Same reasoning; entries are consumed on lookup (section 8.1), so steady-state occupancy is bounded by the number of redirected-but-not-yet-accepted connections | as above |
| Destination-record freshness | **15 s** | Above the 5 s upstream-connect budget and any realistic accept latency; below any plausible ephemeral-port reuse interval | T1 |
| Discriminator peek | **24 bytes** | Exactly the h2c preface length; nothing needs more (section 10.1) | T5 |
| Max response body size | **deferred to 5B/5C** | S1 section 7 requires a byte-counting wrapper around the streamed body. 5A has no concept of a body, and a number chosen here would be a guess that 5B has to re-derive from the response path. Recorded as OQ-S1a-04 rather than fabricated | - |
| Shutdown drain | **30 s** | Long enough for in-flight requests, short enough to fit inside a typical 30 s `terminationGracePeriodSeconds` | force close |

Every breach increments a metric, is logged with its `bound` label, and closes the connection.
Nothing is silently queued (S1 section 7).

### 13.2 Timeout budget - unchanged from S1 section 5.4

Restated verbatim so that an implementer reading only S1a still gets it right. These values
are **not** revised by this phase.

| Phase | Default |
| ----- | ------- |
| Downstream TLS handshake | 10 s |
| Request header read | 10 s |
| Upstream connect | 5 s |
| Upstream TLS handshake | 10 s |
| Upstream response header | 30 s |
| Idle, both sides | 90 s |
| Per-stream progress deadline | 60 s without progress |
| Total request | none by default |

The 10 s downstream-handshake budget also covers the discriminator peek, because the peek
happens immediately before the handshake and the two together are what an agent could stall.

---

## 14. Rejection taxonomy T1-T9 in eBPF terms

The taxonomy from S1 section 8 is unchanged: no class is added, removed or renumbered. What
changes is the mechanism that raises each class. The metric family remains
`aksh_transport_reject_total{class="..."}`.

| Class | Metric label | Raised when (eBPF terms) | Wire behaviour | Alert |
| ----- | ------------ | ------------------------ | -------------- | ----- |
| T1 | `no_original_dst` | `pair_orig_dst` lookup misses; or the record is older than 15 s; or `flags` lacks `DST_IPV4`; or the recovered port is 0; or the peer is not IPv4; or the map is unreadable. Also raised for a pod-local destination (S1 section 2.2 case A) with `reason="pod_local"` | TCP close, no response | No |
| T2 | `loop_guard` | `orig_dst.uid == proxy_uid` in the recovered record, **or** the accepted peer address is present in `SelfDialRegistry` | TCP close | **Yes** - this means the UID exclusion or the config map failed and a capture loop is possible |
| T3 | `no_sni` | `CanonicaliseServerName` rejects the ClientHello's `server_name`: absent, empty, an IP literal, longer than 253 bytes, a label longer than 63 bytes, or an IDNA failure | TLS alert `unrecognized_name`, then close | No |
| T4 | `handshake` | The downstream handshake fails; or the CA is unavailable at mint time; or a post-handshake assertion fails (`DidResume` true, or `ConnectionState().ServerName` differs from the captured SNI) | TLS alert, then close | Only for the two post-handshake assertions |
| T5 | `unsupported_protocol` | The discriminator returns `ProtocolUnknown` or `ProtocolH2CPreface`; or the negotiated ALPN is outside `{h2, http/1.1}` | Close (no alert can be sent for a non-TLS connection) | No |
| T6 | `identity_mismatch` | **Never raised by 5A.** SNI and authority disagree - decided by S4 stage 1 so that it is audited rather than dropped at transport. Listed for completeness; 5B raises it | n/a in 5A | n/a |
| T7 | `resource_limit` with `bound="<name>"` | Any bound in section 13.1: `max_downstream_conns`, `max_h2_streams`, `max_inflight_requests`, `max_header_bytes`, `handshake_rate`, `leaf_mint_rate`, `upstream_concurrency` | Per S1's wire-behaviour table: 431 or `RST_STREAM(ENHANCE_YOUR_CALM)` for header and stream limits; connection close for connection and handshake limits | No |
| T8 | `plaintext_unresolvable` | A plaintext connection whose recovered destination is not an exact Service ClusterIP match. **Not reachable in 5A**, since all plaintext is T9 before the lookup would happen | Close | No |
| T9 | `plaintext_registry_unavailable` | The Service index is unavailable. **In 5A this is every plaintext connection**, because the index does not exist yet (ADR-S1a-11) | Close | No |

Three notes on the mapping, because they are the places a reader could reasonably get it
wrong:

- **A `connect()` refused in the kernel is not a transport rejection.** IPv6 denial, non-TCP
  denial and a `cookie_orig_dst` insert failure all cause `connect()` to return `EPERM`
  without a connection ever reaching the listener, so there is no connection to classify.
  These are counted separately in `aksh_capture_denied_total{hook="connect6|sock_create|sendmsg4|sendmsg6", reason="..."}`.
  Folding them into T1 would conflate "we blocked something" with "we lost track of
  something", which are opposite conditions.
- **T1 versus T2 ordering matters.** The `SelfDialRegistry` check runs before the map lookup,
  because a genuine loop produces no map record and would otherwise be counted as T1 - hiding
  an alerting condition behind a routine counter.
- **T7's `bound` label is mandatory.** A `resource_limit` counter without the bound name is
  operationally useless: it tells you something is saturated but not what to raise.

---

## 15. Security analysis

### 15.1 S7 bypass cases re-answered

| Case | Original concern | Answer under eBPF |
| ---- | ---------------- | ----------------- |
| **B1** | Agent connects to a non-standard port to evade port-specific interception | **Closed, and more strongly than before.** `connect4` has no port predicate at all: every TCP `connect()` by a non-proxy UID in the pod cgroup is redirected regardless of destination port. The iptables rule set needed an explicit port list or a `-p tcp` catch-all that had to be maintained; here there is nothing to maintain because there is no port match. Demo step 8 exercises it |
| **B2** | Agent uses IPv6 to reach a destination for which only IPv4 was intercepted | **Closed by explicit denial.** `aksh_connect6_deny` is attached at `BPF_CGROUP_INET6_CONNECT` and returns 0 for every non-proxy UID, so `connect()` fails with `EPERM`. This is a real improvement on the iptables design, where an incomplete `ip6tables` rule set failed *open* and silently. Here the failure mode is an agent that cannot use IPv6 at all, which is loud, testable (demo step 9) and safe. It is a functional limitation until the IPv6 phase (section 23.1) |
| **B3** | Agent connects to its own pod IP or to a loopback address so that the kernel routes over `lo` and bypasses a `PREROUTING`/`OUTPUT` rule | **Closed by construction.** `cgroup/connect4` runs inside the `connect()` syscall, **before** any routing decision is made. There is no routing path that can avoid it, because there is no packet yet. This is the clearest structural advantage of the eBPF design over iptables. The pod-local *policy* concern remains and is handled separately in userspace at section 9.2 step 3, as an ordinary denial rather than an alert |
| **B50** | Agent forges the `Host` header or the SNI to impersonate an allowed destination | **Unchanged and still closed.** The destination comes from `pair_orig_dst`, written by the kernel from the address the agent passed to `connect()`. The agent can write any SNI and any `Host` it likes; INV-8's comparison is against a value it did not supply. The change of mechanism from `SO_ORIGINAL_DST` to a BPF map preserves the property exactly: in both cases the value originates in the kernel and is not derived from any byte the agent sent on the wire |
| **B51** | Agent connects directly to the listener on `127.0.0.1:15001`, hoping to supply its own notion of the destination | **Closed, and better than before.** `connect4` step 5 deliberately does not capture `127.0.0.0/8`, so such a connection reaches the listener with **no** `pair_orig_dst` record. `Resolve` therefore returns `ErrNoOriginalDestination` and the connection is closed as T1. Delete-on-lookup (section 8.1) closes the residual variant in which the agent times its direct dial to land on an ephemeral port whose stale record it could inherit - under the PoC's non-consuming lookup that was a genuine, if fiddly, destination-forgery primitive |
| **B52** | Agent runs as the proxy UID (1774) and is therefore excluded from capture | **Closed by two independent controls.** First, the admission webhook (S5, INV-10) rejects any pod whose agent container runs as 1774, and gate P13 re-checks it at startup rather than trusting the webhook was applied. Second, the exclusion uses the **real** UID from `bpf_get_current_uid_gid()`, not the effective UID, so a process cannot temporarily assume 1774 the way it could with `seteuid`. The agent container also runs with `allowPrivilegeEscalation: false` and no `CAP_SETUID`, so it cannot change UID at all. Gate P14 additionally proves at startup that the exclusion is real rather than assumed (6.7.2), and demo step 11 asserts zero T2 events |

### 15.2 Regression check: what iptables did that eBPF must still do

| iptables responsibility | eBPF replacement |
| ----------------------- | ---------------- |
| REDIRECT TCP to 15001 | `aksh_connect4` |
| `--uid-owner` exclusion for the proxy | `uid == cfg->proxy_uid` in `connect4` |
| Packet MARK to avoid re-processing | **Deleted, not replaced.** The MARK existed only to carry state across iptables chains. There are no chains here: exclusion happens once, at the only place redirection can occur (ADR-S1a-03) |
| `filter`/`OUTPUT` drop of non-TCP egress | `aksh_sock_create`, `aksh_sendmsg4`, `aksh_sendmsg6` (section 6.9.1) |
| DNS carve-out (DEV-01) | `cfg->dns_ip4` and `cfg->dns_port`, matched exactly in `connect4` and `sendmsg4` |
| ICMPv6 carve-out (ADR-S1-03) | **Withdrawn as unnecessary.** cgroup hooks filter socket operations by processes in the cgroup, not packets; kernel-generated NDP and PMTU have no such socket and continue to work. User-initiated ICMPv6 (`ping6`) is denied by `aksh_sock_create`, which is intended: a raw socket is an exfiltration channel (6.9.1). Retaining the carve-out would create a permitted egress path for no benefit |

### 15.3 New attack surface that eBPF introduces and iptables did not

This is the part that deserves the most scrutiny, because it is genuinely new.

| # | Surface | Assessment | Mitigation |
| - | ------- | ---------- | ---------- |
| N1 | **`CAP_BPF` and `CAP_NET_ADMIN` at startup.** A compromised proxy binary at startup can load arbitrary BPF programs and, with `CAP_NET_ADMIN`, reconfigure networking | High impact, but the proxy already had `CAP_NET_ADMIN` under iptables, so this is not a net increase for that capability. `CAP_BPF` is new | Both are held only until attach completes; the drop (6.6.2) retains `CAP_BPF` alone and clears the bounding set so nothing can regain them. `PR_SET_NO_NEW_PRIVS` blocks regain via exec |
| N2 | **`CAP_BPF` retained after the drop.** The proxy can read and write any BPF map it can find, and load programs on kernels that allow it | Medium. It is unavoidable: without it, map lookups fail on kernels with `unprivileged_bpf_disabled`, and every connection becomes T1 | Only `CAP_BPF` is retained, not `CAP_SYS_ADMIN`; the bounding set is cleared; and the proxy runs as an unprivileged UID that owns nothing else in the pod. The one map whose contents could switch capture off, `aksh_config`, is frozen with `BPF_MAP_FREEZE` before attach (6.8.2 step 5), so retained `CAP_BPF` does not imply the ability to disable capture. The destination maps remain writable by necessity, but writing them can only produce a wrong destination for a connection the writer already controls |
| N3 | **Read-only host cgroup mount** at `/host/sys/fs/cgroup`. The proxy can enumerate every pod on the node and read their cgroup metadata | Medium. It is an information disclosure - pod UIDs, container ids, resource settings - not a control-plane capability | Mounted `readOnly: true`; used only during startup resolution; and the same information is available from the kubelet's read-only port to anything with node access. It is documented as a requirement in 6.1.4 so a reviewer sees it rather than discovering it |
| N4 | **Shared bpffs at `/sys/fs/bpf`.** Pins are visible to every pod on the node that mounts the same host path. A co-resident malicious pod with `CAP_BPF` could unpin or replace another pod's links | **The most serious new surface.** Unpinning another pod's link would open a silent capture bypass in *that* pod | **MC-S1a-01 (6.8.6) is the mandatory control.** Gate P15 refuses to pin unless `<pinRoot>/aksh` and `<pinRoot>/aksh/<podUID>` are 0700 and owned by the proxy UID, and `BPF_OBJ_GET` is subject to ordinary DAC, so an attacker needs root or `CAP_DAC_OVERRIDE` in addition to `CAP_BPF`. The link fds are retained for the process lifetime, so unpinning alone costs the restart guarantee and not capture. The attachment health check (6.8.5) is mandatory, runs every 30 s, cannot be disabled, and exits non-zero on any mismatch. Residual: a root co-resident pod can still detach a link and we detect rather than prevent it; **OQ-S1a-05** is now about which per-pod bpffs mechanism S5 uses, not whether |
| N5 | **LRU eviction of a live map entry** under a flood of `connect()` calls, causing legitimate connections to be rejected as T1 | Low. It is a self-inflicted denial of service by the agent, and it is fail-closed | 16384 entries is 32 times the connection cap; eviction produces T1, never a wrong destination. A sustained T1 rate is an alertable signal |
| N6 | **Startup race**: connections made by the agent between container start and program attach are not captured | **Closed by ordering, not by luck.** The proxy is a native sidecar (`initContainers` with `restartPolicy: Always`), so the kubelet does not start the agent container until the proxy is Ready, and the proxy does not report Ready until every startup gate in 6.7 has passed, including both probes |
| N7 | **Restart gap**: a proxy crash leaves the agent running | Closed by link pinning (6.8.3) plus the decision never to detach on shutdown (6.8.4). During a proxy outage, connections are **refused**, not passed through |
| N8 | **Socket-cookie reuse.** A cookie is unique for the life of a socket, but the value space is reused after the socket is freed | Low. A reused cookie could in principle collide with a stale `cookie_orig_dst` entry, but `sock_ops` deletes the entry on use, and a collision would produce a wrong destination only if `connect4` failed to write for the new socket - in which case it returned `EPERM` and no connection exists |
| N9 | **`BPF_F_ALLOW_MULTI` co-existence.** Another sidecar's `connect4` program also runs, and the order is not defined by us | Low but real. If a service-mesh sidecar also rewrites the destination, the outcome depends on attachment order | Documented as a limitation (section 21). The alternative, `BPF_F_ALLOW_OVERRIDE`, is strictly worse: it would let another program displace ours, which is a capture bypass |
| N10 | **The verifier is part of the trusted computing base.** A verifier bug is a kernel compromise | Accepted. It applies to every eBPF user, is mitigated by requiring 5.15 or newer, and the programs themselves are small, loop-free and use only stable UAPI structures |

### 15.4 Invariant conformance

| Invariant | How 5A upholds it |
| --------- | ----------------- |
| INV-3 (all egress traverses the proxy) | `connect4` has no port or address predicate beyond loopback; non-TCP is denied; IPv6 is denied. DEV-01 (DNS) remains the single named exception; ADR-S1-03's ICMPv6 exception is withdrawn |
| INV-4 (fail closed) | 14 startup gates in two phases, plus two live probes, all fatal; `connect4` returns `EPERM` when it cannot record a destination; `Resolve` never guesses; the zero value of `Protocol` rejects; there is no fallback backend and no flag that disables capture, and `aksh_config` is frozen so that capture cannot be switched off at runtime |
| INV-6 (no credential before audit) | **Partially upheld, with DEV-S1a-01.** Obligation 2 (ordering) is trivially upheld: 5A moves no credentials, and the `PassthroughHandler` is explicitly a pre-credential component. Obligation 1 (coverage) is **not** met for transport-level denials, which are counted and logged but not durably recorded, because no `AuditEvent` and no `AuditSink` implementation exist before 5B. The gap is bounded and owned by DEV-S1a-01 (section 9.2) |
| INV-8 (host validation) | The destination is kernel-attested and agent-uninfluenceable; SNI is canonicalised before use; the leaf cache key is exact; `DialUpstream` verifies against the validated identity with `InsecureSkipVerify` unreachable |
| INV-10 (agent UID is not the proxy UID) | Enforced by the S5 webhook, re-checked at gate P13, and proved live at gate P14; the exclusion uses the real UID; T2 alerts if it ever fails |

---

## 16. Thread-safety model

| Component | Concurrency | Protection |
| --------- | ----------- | ---------- |
| Accept loop | One goroutine | Sole owner of `ln`; the only caller of `Accept` |
| Per-connection handling | One goroutine per connection | `ConnContext` is created by that goroutine and never shared. No mutex is needed because there is no sharing, which is the strongest form of safety available |
| `BPFDestinationResolver` | Called from every connection goroutine | Stateless apart from the `*ebpf.Map` handle. `cilium/ebpf` map operations are individual `bpf()` syscalls and are safe for concurrent use; `LookupAndDelete` is atomic in the kernel, so two goroutines cannot both consume the same entry |
| `CachedLeafSource` | Called from every handshake | One `sync.Mutex` guarding `lru` and `index`. **The lock is never held across the mint**: the mint happens outside the lock, and the insert re-checks the index, so a concurrent miss on the same identity mints twice and one result wins. That is deliberate: minting is 152 us and holding a global lock across it would serialise every handshake in the process |
| `SelfDialRegistry` | Written by the dialer, read by the accept path | `sync.RWMutex`. Reads dominate |
| Connection semaphore | Buffered channel of `struct{}`, capacity 512 | Non-blocking `select` acquire; release in a `defer`, exactly once |
| Rate limiters | `golang.org/x/time/rate.Limiter` | Internally synchronised |
| `akshConfig` map | Written once before attach, read by the kernel | No concurrent writer exists; the map is frozen with `BPF_MAP_FREEZE` after the P10 read-back, so no writer can exist afterwards even in-process |
| Attachment health check | One goroutine, every `AttachCheckInterval` (6.8.5, default 30 s, mandatory) | Owns nothing the connection path touches. It reads kernel link info, the immutable ids recorded at attach, and the pin-directory inodes recorded by P15; on failure it logs and terminates the process rather than mutating shared state |
| Pod-local address set | Written by a 30 s refresher, read by every connection | `atomic.Pointer` to an immutable slice; readers never block and never see a partial update |

**Lock ordering.** There is exactly one mutex on the connection path (the leaf cache) and one
RWMutex off it (the registry), and no code path holds both. A deadlock is therefore not
possible by construction rather than by discipline. Any future change that introduces a second
lock on the connection path must declare an ordering in this section.

**No goroutine leaks.** Every per-connection goroutine terminates when its connection closes;
`Shutdown` closes the listener, waits on the `sync.WaitGroup` up to the drain deadline, and
then force-closes the remainder. The 30 s refresher exits on context cancellation.

---

## 17. Observability

5A uses the **existing** `internal/audit` seams only. It does not add a metrics package, does
not import a Prometheus client, and does not define a new sink interface. S6 owns that.

### 17.1 Metrics

The available recorder is, verbatim from `internal/audit`:

```go
type MetricsRecorder interface {
	RecordDecision(disposition, reason, identity string)
	RecordLatency(stage string, duration time.Duration)
	RecordTokenCacheHit(credID string, hit bool)
}
```

> **[Reconciled P9a]** The interface sketch above is **stale**. The real `audit.MetricsRecorder`
> has **no `RecordDecision` method**. The implemented decision counter is
> `Decisions(pipeline.Disposition, pipeline.DenyReason, audit.TransportKind, bool)` (the final
> `bool` is a fault flag). `capture.BPFDestinationResolver` records its rejections through
> `Decisions(...)`, using the deny reasons `pipeline.ReasonPodLocalDestination` (the quiet
> pod-local reject) and `pipeline.ReasonLoopGuard`. The `RecordDecision(...)` mappings named in
> the table below are therefore historical prose; treat `Decisions(...)` as the binding API
> until the OQ-S1a-02 metrics rework lands. (Closes Findings-journal note on the §17.1 stale API.)

| Event | Call |
| ----- | ---- |
| Transport rejection | `RecordDecision("rejected", "<class>", "<identity or empty>")` where `<class>` is `RejectClass.String()`, for example `no_original_dst` |
| Resource-bound rejection | `RecordDecision("rejected", "resource_limit:<bound>", "")` |
| Capture-layer denial (`EPERM` in the kernel, no connection) | `RecordDecision("blocked", "capture:<hook>", "")` |
| Leaf cache hit or miss | `RecordTokenCacheHit("leaf:"+identity, hit)` |
| Stage latency | `RecordLatency("dst_resolve" \| "discriminate" \| "downstream_handshake" \| "upstream_connect" \| "upstream_handshake" \| "leaf_mint", d)` |

**This is an acknowledged compromise and I want it recorded as one.** S1 section 8 specifies
the metric family `aksh_transport_reject_total{class="..."}`, and `MetricsRecorder` cannot
express it: `RecordDecision` takes a disposition, a reason and an identity, none of which is a
transport class, and overloading `reason` conflates transport rejections with policy denials
in whatever backend S6 eventually builds. Using `RecordTokenCacheHit` for leaf-cache hits is
worse - the parameter is literally named `credID` and a leaf identity is not a credential.

I am doing it anyway rather than widening a frozen interface mid-phase, because the
alternative is 5A inventing a metrics contract that S6 would then have to unpick. The correct
fix is for S6 to add `RecordTransportReject(class, bound string)` and
`RecordCacheEvent(cache, key string, hit bool)`. That is **OQ-S1a-02**, and until it lands the
mapping above is the single documented encoding so that at least the conflation is uniform
and reversible.

Additionally, capture-layer counters that have no natural home in `MetricsRecorder` -
`aksh_capture_denied_total`, `aksh_capture_map_entries`, `aksh_capture_attached` - are emitted
as structured log events only. Inventing a second metrics path for them would be exactly the
mistake described above.

### 17.2 Logged events

Structured `log/slog` with a closed set of event names. No log line contains a header value, a
request body, a token, a certificate private key, or a full URL path.

| Event | Level | Fields |
| ----- | ----- | ------ |
| `preflight.check` | INFO / ERROR | `check`, `result`, `code`, `detail` |
| `capture.cgroup_resolved` | INFO | `path`, `case` (`A` or `B`), `checks_passed`, `depth` |
| `capture.attached` | INFO | `programs`, `cgroup`, `flags`, `pinned`, `reused` |
| `capture.probe` | INFO / ERROR | `expected`, `recovered`, `duration_ms` |
| `capture.probe_exclusion` | INFO / ERROR | `uid`, `outcome` (`not_captured` or `captured`), `duration_ms` |
| `capture.privileges_dropped` | INFO | `uid`, `gid`, `caps`, `setuid_zero_failed` |
| `capture.attach_lost` | **ERROR** | `link`, `check`, `expected_id`, `observed_id` |
| `capture.denied` | DEBUG | `hook`, `reason`, `uid` |
| `conn.accepted` | DEBUG | `conn_id`, `peer`, `orig_dst`, `protocol` |
| `conn.rejected` | INFO / ERROR | `conn_id`, `class`, `code`, `reason`, `bound` |
| `conn.loop_detected` | **ERROR** | `conn_id`, `peer`, `uid`, `source` (`map_uid` or `self_dial`) |
| `tls.terminated` | DEBUG | `conn_id`, `sni`, `alpn`, `version`, `leaf_cache` |
| `tls.assert_failed` | **ERROR** | `conn_id`, `assertion` (`did_resume` or `server_name`) |
| `upstream.dialed` | DEBUG | `conn_id`, `addr`, `server_name`, `alpn`, `duration_ms` |
| `conn.closed` | DEBUG | `conn_id`, `bytes_in`, `bytes_out`, `duration_ms`, `reason` |
| `shutdown.drain` | INFO | `in_flight`, `deadline_s`, `forced` |

The four ERROR-level events are the ones an operator should alert on: they mean the loop
guard, the TLS assertions, attachment, or a startup gate failed, and each of those is a
control rather than a statistic.

SNI is logged because it is the identity being decided about and S4 already audits it. Paths
and headers are not, because they are request content and belong to 5B's audit path where
redaction rules exist.

---

## 18. Configuration

One options struct per package, each with a `Validate()` method returning the first error.
Every field has an explicit default; nothing is inferred from the environment except where
noted. `Validate()` runs before preflight, so a configuration error is reported before any
privileged work happens.

```go
// NEW - internal/dataplane/capture/options.go

type IPv6Mode int

const (
    IPv6Deny    IPv6Mode = iota // the only legal value in 5A
    IPv6Capture                 // reserved for the IPv6 phase
)

type Options struct {
    ProxyUID        uint32        // default 1774; must be > 0 and != 0
    ProxyGID        uint32        // default 1774
    ListenerAddr    netip.AddrPort// default 127.0.0.1:15001; Addr must be loopback IPv4
    ProcCgroupPath  string        // default "/proc/self/cgroup"
    LocalCgroupMount string       // default "/sys/fs/cgroup"
    HostCgroupMount string        // default "/host/sys/fs/cgroup"
    PinRoot         string        // default "/sys/fs/bpf"
    PinLinks        bool          // default false [Reconciled P9a]; was documented "true".
                                  // Gate M1 (6.7.3) is unverified/BLOCKED, so pinning is
                                  // opt-in; pinning is gated by P15 (6.8.6) when enabled
    PinRootPrivate  bool          // default false; true only when the deployer has
                                  // mounted a bpffs for this pod alone (6.1.4). It
                                  // relaxes nothing: it is logged in the startup
                                  // summary so the residual N4 exposure is auditable
    MountBPFFS      bool          // default false
    MapEntries      uint32        // default 16384; range [1024, 65536]
    DestMaxAge      time.Duration // default 15s; range [1s, 120s]
    AttachCheckInterval time.Duration // default 30s; range [10s, 60s]; 0 is REJECTED (6.8.6)
    MinKernel       KernelVersion // default 5.15; not configurable below 5.15
    IPv6            IPv6Mode      // default IPv6Deny; IPv6Capture is REJECTED in 5A
    BlockNonTCP     bool          // default true
    DNSServer       netip.AddrPort// DEV-01; zero value disables the exception
    RunProbe        bool          // default true; gates P12 and P14; false is rejected unless AllowUnsafeStartup
    AllowUnsafeStartup bool       // default false; documented as test-only
}
```

```go
// NEW - internal/dataplane/listener/options.go

type Options struct {
    Addr               netip.AddrPort // default 127.0.0.1:15001
    MaxConns           int            // default 512; range [1, 65535]
    HandshakeRate      float64        // default 50
    HandshakeBurst     int            // default 100
    PeekTimeout        time.Duration  // default 10s
    HandshakeTimeout   time.Duration  // default 10s
    IdleTimeout        time.Duration  // default 90s
    ProgressTimeout    time.Duration  // default 60s
    DrainTimeout       time.Duration  // default 30s
    PodLocalRefresh    time.Duration  // default 30s
}
```

```go
// NEW - internal/dataplane/tlsterm/options.go

type LeafOptions struct {
    CacheEntries    int           // default 1024; range [16, 65536]
    CacheTTL        time.Duration // default 1h
    LeafLifetime    time.Duration // default 24h; must exceed CacheTTL
    Backdate        time.Duration // default 5m
    MintRate        float64       // default 50
    MintBurst       int           // default 100
    NextProtos      []string      // default {"h2", "http/1.1"}; must be a subset of that set
    MinVersion      uint16        // default tls.VersionTLS12; TLS 1.0 and 1.1 are REJECTED
    AllowSelfSignedCA bool        // default false; required by pki.SelfSignedProvider
}
```

```go
// NEW - internal/dataplane/upstream/options.go

type UpstreamOptions struct {
    MaxConcurrent    int           // default 512
    ConnectTimeout   time.Duration // default 5s
    HandshakeTimeout time.Duration // default 10s
    NextProtos       []string      // default {"h2", "http/1.1"}
    RootCAs          *x509.CertPool// nil means system roots
}
```

Validation rules that are security controls rather than sanity checks, and are therefore
tested explicitly:

| Rule | Reason |
| ---- | ------ |
| `IPv6 == IPv6Capture` is rejected with "IPv6 capture is not implemented in phase 5A" | Prevents a configuration that would silently pass IPv6 traffic |
| `MinVersion < tls.VersionTLS12` is rejected | S1 section 3.3; there is no downgrade switch |
| `ProxyUID == 0` is rejected | Running the proxy as root after the drop defeats the drop |
| `ListenerAddr.Addr()` must be IPv4 loopback | A wildcard bind makes the sidecar an open relay |
| `LeafLifetime <= CacheTTL` is rejected | Otherwise a cached leaf can be served after expiry |
| `BlockNonTCP == false` requires `AllowUnsafeStartup` | It is an INV-3 hole and must be deliberate |
| `RunProbe == false` requires `AllowUnsafeStartup` | Skipping the probes means capture and the UID exclusion are assumed, not proved |
| `AttachCheckInterval == 0`, or a value outside [10 s, 60 s], is rejected outright - there is no `AllowUnsafeStartup` route | The check is half of MC-S1a-01 (6.8.6). A silent loss of attachment that is never noticed is the worst failure in the phase, so this control has no off switch (N4, R-03) |
| `NextProtos` outside `{h2, http/1.1}` is rejected | Prevents negotiating a protocol the pipeline cannot inspect |
| There is **no** option that sets `InsecureSkipVerify` | S0 section 9 |
| There is **no** option that disables capture at runtime | INV-4 |

---

## 19. Testing strategy

The split is by what the test needs, not by what it covers. Anything that can be tested
without a kernel is written so that it can be.

### 19.1 Platform-independent unit tests (no build tag; must pass on Windows)

| Area | Tests |
| ---- | ----- |
| Byte-order helpers | Round-trip `netIPToAddr`/`addrToNetIP` and `netPortToHost`/`hostPortToNet` over a table of addresses and ports; known-value assertions against the exact `__u32` the PoC produced for `127.0.0.1` and `192.0.2.1`; a golden test asserting `netIPToAddr(1.2.3.4)` equals `binary.NativeEndian.Uint32([]byte{1,2,3,4})`. **This is the highest-value test file in the phase** (section 6.4.3) |
| Kernel struct layout | `binary.Size` of `origDst`, `pairKey` and `akshConfig` equals 24, 8 and 32, with each field at the offset section 6.4.1 states; `pairKey.Port` marshals `uint32(uint16(65535))` as `0x0000FFFF` with the high half clear, proving the zero-extension contract; `akshConfig.ListenerPort` and `DNSPort` both round-trip through `hostPortToNet`/`netPortToHost` |
| Listener lifecycle | `AcceptProbe` returns `ErrNotBound` before `Bind` and `ErrServing` after `Serve`; `Serve` fails without `Bind`; `Bind` twice fails; `Shutdown` is safe before `Serve` and idempotent. Proves the state machine in 9.1 rather than trusting the call order |
| Cgroup path resolution | `ResolvePodCgroup` against `testdata` fixtures: a systemd-driver `/proc/self/cgroup`, a cgroupfs-driver one, a namespaced `0::/` one, a cgroup v1 one, an empty file, and a malformed file. The filesystem side is behind a small `fs.StatFS`-shaped seam so the walk is testable without a real cgroup tree. A synthetic fixture wider than `MaxWalkDirs` asserts `E_CGROUP_WALK_LIMIT` and that no candidate is returned |
| Verification assertions | V1-V8 each proved to fail for a crafted path: the root mount, a depth-1 path, a path outside the mount, a path missing `cgroup.procs`, a path not containing our PID |
| Discriminator | Table test over: a real captured ClientHello prefix, the exact h2c preface, each of the nine methods, a lowercase method, a 2-byte read then EOF, a 23-byte partial preface, a slow-loris connection that never sends, and random binary. Asserts both the classification and that the returned `net.Conn` replays every byte |
| SNI canonicalisation | Uppercase, trailing dot, IDNA U-label, an already-A-label, an IPv4 literal, an IPv6 literal, empty, 254 bytes, a 64-byte label, embedded NUL, embedded space, a wildcard `*.example.com` |
| Leaf cache | Hit, miss, TTL expiry, LRU eviction order, generation change invalidating, concurrent double-miss on one identity, mint-rate exhaustion. Uses `pki.SelfSignedProvider` and an injected clock |
| `Protocol` and `RejectClass` enums | Every value has a distinct non-empty `String()` and `Code()`; the zero value is the rejecting one |
| Options validation | Every rule in section 18's table, positive and negative |
| `SelfDialRegistry` | Add, contains, remove, absent; concurrent access under `-race` |
| `DirectDialer` | Against an in-process TLS server: success, wrong `ServerName` fails, an untrusted CA fails, connect timeout, handshake timeout, concurrency limit, self-dial registration and deregistration |
| `capture` stubs | The non-Linux constructor returns `ErrUnsupportedPlatform` |

### 19.2 Kernel-dependent integration tests

Build tag `//go:build linux && ebpf_integration`. Run as root on a 5.15-or-newer host:

```
go test -tags ebpf_integration -exec sudo ./internal/dataplane/...
```

| Test | Asserts |
| ---- | ------- |
| Load and verify | All six programs load; the verifier accepts them; map sizes match `Options` |
| Config round-trip | `aksh_config` reads back byte-identical over all 32 bytes, proving the Go and C layouts agree - the second most likely silent-breakage source after byte order |
| Config freeze | After `Freeze()`, a further `Update` on `aksh_config` returns `EPERM`, and a `connect4` redirect still works, proving the freeze blocks writers without blocking program reads (6.8.2 step 5) |
| UID-exclusion gate | With the process running as the configured proxy UID, the P14 probe reports `not_captured`; with the config's `proxy_uid` deliberately set to a different value, the same probe reports `captured` and startup fails with `E_PROBE_UID` |
| Attachment health check | With the links detached out of band, the next check fails and the process exits non-zero; with the links intact, it passes on repeated ticks (6.8.5) |
| Attach to a scratch cgroup | The test creates its own cgroup under `/sys/fs/cgroup`, moves itself into it, attaches there, and asserts capture applies inside and **not** outside. This is the direct test of ADR-S1a-02 |
| Redirect and recover | A `connect()` to an unroutable TEST-NET address lands on the listener and `Resolve` returns exactly that address |
| Loop prevention | A connection made while running as the configured proxy UID is not redirected |
| Delete-on-lookup | A second `Resolve` for the same tuple returns `ErrNoOriginalDestination` |
| Freshness | An entry written with a backdated stamp yields `ErrStaleEntry` |
| IPv6 denial | `connect()` over IPv6 returns `EPERM` |
| Non-TCP denial | `socket(AF_INET, SOCK_DGRAM)` returns `EPERM`; a UDP `sendmsg` to the configured DNS server succeeds |
| Pin-root ownership gate (P15) | Pinning into a `<pinRoot>/aksh` created 0755, or owned by another uid, or replaced with a symlink, each fails with `E_PIN_ROOT_UNSAFE` and leaves no pin behind; the correct 0700 case pins successfully. This is the MC-S1a-01 test (6.8.6) |
| Unpin does not detach | With the link fd retained, removing the pin out of band leaves capture working; the redirect still succeeds and the health check reports the missing pin and exits non-zero. Proves the refcount argument in 6.8.6 rather than assuming it |
| Pin and reattach | Links pinned, the process exits, a new process reuses them via `link.Update`, and capture is continuous across the swap |
| Privilege drop | After the drop: uid 1774, empty supplementary groups, effective set exactly `{CAP_BPF}`, `setuid(0)` fails, and a map lookup still succeeds |
| Preflight negatives | Each failure code is reachable: a v1 cgroup fixture, a root-cgroup path, missing capabilities, a too-old kernel string |

### 19.3 End-to-end

The section 12 demo, scripted as `hack/demo/run.sh`, exercising steps 4 through 12 with
assertions. It is run manually and in a nightly job, not in the per-PR build, because it needs
a Linux host with Docker.

### 19.4 Build and generation

- `go build ./...` and `go test ./...` work on Windows with no clang and no kernel, because the
  BPF object and its Go bindings are committed and everything kernel-touching is behind
  `//go:build linux`.
- Regeneration is explicit: `go generate ./internal/dataplane/bpf/...` with clang 18.
- CI (Linux) runs `go generate` and then `git diff --exit-code` over `internal/dataplane/bpf`,
  so a source change without a regenerated artefact fails the build. This is the mechanism
  that keeps the committed object honest.
- The Go toolchain and the clang version are pinned, and the object's SHA-256 is recorded in
  `internal/dataplane/bpf/README.md` next to the exact command that produced it.

---

## 20. Design decisions

### ADR-S1a-01: eBPF is the only capture backend; iptables is removed

**Context.** S1 specified iptables REDIRECT. The PoC proved eBPF works. The obvious
compromise is to keep iptables as a fallback for kernels or environments where eBPF fails.

**Options.** (a) eBPF only. (b) eBPF with an iptables fallback. (c) iptables only.

**Decision.** (a). If eBPF cannot be set up, the sidecar fails closed at startup and refuses
to run.

**Consequences.** Two capture backends would mean two rule sets, two threat models, two sets
of bypass cases, and - crucially - an attacker-preferred path, since the fallback is the one
that gets less testing. A fallback also weakens the fail-closed story: "we could not do the
strong thing, so we did the weak thing" is exactly the reasoning INV-4 exists to forbid. The
cost is a narrower supported matrix (kernel 5.15 or newer, cgroup v2 unified) and no path on
older or unusual hosts. That cost is acceptable because the alternative is a security control
with a documented weaker mode.

### ADR-S1a-02: Attach to the pod cgroup, never the root cgroup

**Context.** The PoC attaches at `/sys/fs/cgroup`, capturing every process on the node.

**Options.** (a) Root cgroup. (b) The proxy's container cgroup. (c) The pod cgroup.

**Decision.** (c), with V1-V8 (section 6.1.3) asserted before any attach, and startup failure
if any is not satisfied.

**Consequences.** Correct scoping requires solving the cgroup-namespace problem, which needs a
read-only host cgroup mount (6.1.4) - real new attack surface, analysed at N3. The alternative
of taking the path from an environment variable set by the injector was rejected because it
moves a security-critical value into something the pod spec controls. Root attach is not a
configurable option; there is no flag for it.

### ADR-S1a-03: UID-based loop prevention; the packet MARK is deleted

**Context.** S1 used an iptables `--uid-owner` match plus a packet MARK.

**Options.** (a) Port an equivalent MARK using `bpf_set_hash` or a socket-local storage flag.
(b) UID exclusion only. (c) A dedicated network namespace for the proxy.

**Decision.** (b), using the **real** UID from `bpf_get_current_uid_gid()`, plus the two
independent detection paths in 6.5.3.

**Consequences.** The MARK existed only to carry "already handled" state across iptables
chains. There are no chains here: exclusion happens once, at the single point where a
connection can be redirected, so a MARK would be state with no reader. Option (c) would give
the strongest isolation but requires a second network namespace and cross-namespace plumbing
for every connection, which is a much larger change than the problem justifies. The residual
risk is an agent running as UID 1774, closed by INV-10, the S5 webhook, gates P13 and P14, and
the agent container's inability to change UID.

### ADR-S1a-04: IPv4 capture, IPv6 designed and explicitly denied

**Context.** The PoC is IPv4-only and silently lets IPv6 through, which is bypass case B2.

**Options.** (a) Implement IPv6 now. (b) Deny IPv6 at `connect6`. (c) Leave it unhandled.

**Decision.** (b). The full IPv6 design is in 6.9.2 so the later phase is an implementation,
not a redesign.

**Consequences.** (c) is a silent bypass and is not acceptable. (a) doubles the map set, the
key types, the listener set and the test matrix in a phase that is already the largest in the
project. (b) makes IPv6 a loud, testable functional limitation: `EPERM` at `connect()`, which
Happy Eyeballs turns into an IPv4 fallback within milliseconds. Agents in IPv6-only clusters
cannot use Aksh until the IPv6 phase, which is stated in section 21.

### ADR-S1a-05: `bpf2go` with the object and bindings committed to the repository

**Context.** Building BPF from source requires clang and Linux headers. Most of this team
develops on Windows, and CI has no clang.

**Options.** (a) Build BPF in CI and require clang everywhere. (b) Commit the generated `.o`
and Go bindings. (c) Ship the C source and compile at container-build time.

**Decision.** (b). `go generate` is an explicit, documented developer step; the artefacts are
committed; CI regenerates on Linux and fails on any diff.

**Consequences.** Committing a binary artefact is normally a smell, and it deserves the
scrutiny: the risk is an object that does not correspond to the committed C source. That is
mitigated by the CI regenerate-and-diff check, which makes a mismatch a build failure rather
than a runtime surprise, and by recording the toolchain version and the artefact's SHA-256
next to the generation command. Reproducibility is achievable here because the programs use
only stable UAPI structures (`bpf_sock_addr`, `bpf_sock_ops`) and require no `vmlinux.h`, no
CO-RE relocations and no BTF from the build host - so the object depends on the pinned clang
version and nothing else. Option (c) would make every image build require clang and would make
the object vary by build host, which is worse on both counts.

### ADR-S1a-06: The proxy UID reaches the kernel through a BPF config map

**Context.** The PoC has `#define PROXY_UID 1337` in C and `const proxyUID = 1337` in Go, kept
equal by hand.

**Options.** (a) Keep the duplicate. (b) Generate the C header from Go. (c) A BPF config map
written at load time.

**Decision.** (c). `aksh_config` also carries the listener address and port, the DNS exception
and the feature flags. The C source contains none of these as literals.

**Consequences.** Divergence becomes impossible rather than merely unlikely: the same Go
variable is written to the map and passed to `setuid()`. Option (b) would work but adds a
generation step to keep in sync, which is the same class of problem one level removed. The cost
is one map lookup per hook invocation, which is a hash lookup in an array map of one element -
negligible, though I am labelling that an expectation rather than a measurement, since no
figure exists. The map is written before attach and is not writable after the privilege drop,
so it cannot become a runtime capture-disable switch.

**The value is corrected to 1774 at the same time.** The PoC's 1337 is Istio's reserved UID and
S5 ADR-S5-02 chose 1774 specifically to avoid it, because a pod carrying both proxies would
have each excluding the other from capture - a mutual, silent bypass. INV-10's admission checks
are already written against 1774, so shipping 1337 would have left the reserved-UID check
guarding a value nothing used. The brief specifies no numeric UID, so there is nothing in it to
deviate from; this is a deliberate departure from the PoC, recorded here and in section 6.5.2
rather than made silently.

### ADR-S1a-07: Non-TCP egress is blocked by cgroup socket hooks

**Context.** Removing iptables removes the `filter`/`OUTPUT` rule that dropped non-TCP egress
(INV-3's protocol axis, S7 B4).

**Options.** (a) Accept the regression. (b) Keep a minimal iptables rule just for this.
(c) Add `sock_create` and `sendmsg` cgroup programs.

**Decision.** (c), as specified in 6.9.1.

**Consequences.** (a) reopens a closed bypass and is not acceptable. (b) contradicts ADR-S1a-01
and reintroduces a second mechanism for one rule. (c) keeps the entire capture story in one
place and one threat model, and gives a more precise DNS exception - one address and one port
from the config map, rather than an iptables rule matching a port number. It also lets
ADR-S1-03's ICMPv6 carve-out be withdrawn (15.2), because cgroup hooks filter socket
operations rather than packets. The cost is three more programs to verify and test.

### ADR-S1a-08: BPF links are pinned to bpffs

**Context.** A proxy container can restart while the agent container keeps running.

**Options.** (a) Unpinned links that die with the process. (b) Pinned links that survive.

**Decision.** (b), plus the decision in 6.8.4 never to detach on shutdown.

**Consequences.** With (a), a proxy crash means the agent's traffic flows directly to the
internet, unfiltered, with no error anywhere - the worst possible failure in this design.
With (b), during a proxy outage connections are redirected to a port with nothing listening
and are **refused**: loud, and safe. `link.Update` gives an atomic program swap on restart with
no unattached window. The costs are a shared bpffs (attack surface N4, the weakest point in
this design) and the unverified assumption that a pinned cgroup link does not block
pod-cgroup removal (OQ-S1a-01, closed by merge gate M1 in 6.7.3). The bpffs cost is no longer
carried by argument alone: **MC-S1a-01 (6.8.6) is a mandatory control on the pin subtree and
on the health check**, and OQ-S1a-05 now tracks the per-pod bpffs *mechanism* that removes the
residual exposure. `Options.PinLinks` still exists, but disabling it is not a mitigation for
N4 - it reopens the very bypass this ADR closes.

### ADR-S1a-09: Destination records are consumed on lookup and carry a freshness stamp

**Context.** The PoC leaves `pair_orig_dst` entries in place after userspace reads them.

**Options.** (a) Leave them, as the PoC does. (b) Consume on lookup. (c) Consume, and add a
monotonic stamp checked against a maximum age.

**Decision.** (c). `struct orig_dst` grows from 8 to 24 bytes to carry `uid`, `flags` and
`stamp_ns`.

**Consequences.** Under (a), a connection that reaches the listener **without** being
redirected - which `connect4` step 5 explicitly permits for `127.0.0.0/8` - can inherit a
stale record left by an earlier connection on the same ephemeral port, and be attributed a
destination it never requested. That is a destination-forgery primitive and it closes bypass
case B51's residual variant. The stamp then bounds the one remaining window: a record written
for a connection that was never accepted. The costs are 16 extra bytes per entry and a
`CLOCK_MONOTONIC` read per resolve. Both are trivially worth it.

### ADR-S1a-10: A simple non-pooled `UpstreamDialer` in 5A

**Context.** The frozen `UpstreamDialer` signature carries `credID` because 5C will make it
part of the pool key. 5A needs a working dialer for the demo.

**Options.** (a) Implement pooling now. (b) A one-connection-per-call dialer. (c) No dialer,
and no end-to-end demo.

**Decision.** (b).

**Consequences.** Pooling correctness depends on the pool key (S1 section 5.3), which includes
the resolved credential identity and the negotiated protocol policy - neither of which exists
until 5B. Building the pool now means building it against a guess and then rebuilding it. (c)
would leave the phase unproven end to end, which is the one thing the demo exists to prevent.
The cost is a full TCP connect and TLS handshake per downstream connection, which is
acceptable for a demo and unacceptable for production; section 23.2 states the handoff.

### ADR-S1a-11: Plaintext is classified and rejected as T9 in 5A

**Context.** S1 section 6.1 and ADR-S1-05 define plaintext handling through a Services and
EndpointSlices informer index that does not exist yet.

**Options.** (a) Implement the Service index now. (b) Pass plaintext through unvalidated.
(c) Classify it and reject with an existing class. (d) Add a new rejection class.

**Decision.** (c), using **T9** `plaintext_registry_unavailable`.

**Consequences.** (b) is an INV-8 hole. (d) would add a class to a taxonomy S1 froze, for a
condition T9 already describes exactly - the Service index is unavailable, which is precisely
true. (a) is 5B and 5C work and would drag the informer, the ClusterIP index, the
ExternalName, headless and selectorless exclusions, and the Service UID and generation binding
into this phase. The cost is that the 5A demo is HTTPS-only and in-cluster plaintext does not
work until 5B, which is stated in section 21 rather than hidden.

### ADR-S1a-12: Peek-based protocol discrimination with a 24-byte buffer

**Context.** The listener must distinguish TLS from plaintext HTTP before deciding whether to
terminate.

**Options.** (a) Assume everything on 15001 is TLS. (b) Decide from the original destination
port. (c) Peek at the first bytes.

**Decision.** (c), 24 bytes, non-consuming.

**Consequences.** (a) breaks in-cluster plaintext permanently. (b) is exactly the
port-based assumption that bypass case B1 exists to punish - a TLS server on port 8080 is
common. (c) costs one buffered read and works regardless of port. 24 bytes is the exact h2c
preface length, so no rule needs more; short reads are handled by deciding on the shortest
sufficient prefix (section 10.1).

---

## 21. Limitations

1. **The self-probe cannot prove agent-container coverage.** It runs as the proxy's own
   startup process, in the proxy's container cgroup, which is a descendant of the pod cgroup.
   It proves that a process in this cgroup subtree is captured, and gate P14 proves that the
   proxy's own UID is not. Neither proves that a process in the *agent's* container is
   captured, because there is no process there yet when the probes run, and P14 exercises the
   proxy's own process rather than an arbitrary process running as 1774. The section 19.2
   "Loop prevention" integration test covers the latter on a real kernel; only the section 12
   demo closes the former, and only for the shapes it exercises.
2. **No IPv6.** IPv6 egress fails with `EPERM`, and user-initiated ICMPv6 such as `ping6` is
   denied at socket creation (6.9.1), so IPv6 diagnostics from inside the pod do not work
   either. Aksh cannot be used by agents that require IPv6, and it cannot run in an IPv6-only
   cluster, until the IPv6 phase.
3. **No plaintext.** All plaintext connections are rejected as T9 until the Service index
   exists in 5B/5C. In-cluster plaintext HTTP does not work in 5A.
4. **No HTTP/3 or QUIC.** They are UDP, and non-TCP egress is denied. Agents using QUIC fall
   back to TCP, which is the desired behaviour but is a functional limitation for anything
   that cannot.
5. **Kernel 5.15 or newer, cgroup v2 unified only.** There is no fallback (ADR-S1a-01). Nodes
   on older kernels or a cgroup v1 hierarchy cannot run Aksh at all.
6. **A read-only host cgroup mount is required**, which is elevated pod shape and needs
   cluster-admin acceptance (6.1.4, N3).
7. **A shared host bpffs is required for pinning**, with the residual exposure at N4. This is
   the weakest point in the design. It is no longer left as a trade-off: **MC-S1a-01
   (section 6.8.6) is a mandatory control** - gate P15 blocks pinning into a subtree we do not
   exclusively own, the link fds are retained so unpinning cannot disable capture, and the
   attachment health check cannot be turned off. What remains is a root co-resident pod that
   can detach a link, which is detected within 30 s rather than prevented, and which only a
   per-pod bpffs from S5 removes (6.1.4, OQ-S1a-05).
8. **The pinned-link versus cgroup-removal behaviour is unverified** (OQ-S1a-01). If pinning
   does block pod-cgroup removal, cgroups leak on the node.
9. **Co-existence with another `connect4`-rewriting sidecar is undefined** (N9). Aksh and a
   service-mesh sidecar that also redirects will interact in an attachment-order-dependent way.
10. **No connection pooling.** One TCP connection and one TLS handshake per downstream
    connection. Unsuitable for production load; 5C fixes it.
11. **The CA is test-only.** `pki.SelfSignedProvider` generates an in-memory CA with a fixed
    generation and no rotation. Real CA lifecycle is the PKI phase.
12. **Transport denials are not durably audited in 5A** (**DEV-S1a-01**, section 9.2). Pod-local
    and T1/T2/T5/T7/T9 outcomes close the connection, increment a counter and log, but produce
    no audit record, so 5A does not claim full INV-6 conformance. Owned by 5B, with closure
    criteria stated in 9.2.
13. **Metrics are encoded through a seam that does not fit.** Transport rejections are folded
    into `RecordDecision` and leaf-cache events into `RecordTokenCacheHit`. This is documented,
    uniform and reversible, but it is a compromise (section 17.1, OQ-S1a-02).
14. **No `CONNECT` or WebSocket support.** Out of scope, and rejected at request level in 5B.

---

## 22. Risks and mitigations

| # | Risk | Likelihood | Impact | Mitigation |
| - | ---- | ---------- | ------ | ---------- |
| R-01 | **Cgroup resolution lands on the wrong cgroup** - the root, a QoS class, or another pod - producing over-capture or no capture | Medium. The namespace case is genuinely subtle and kubelet layouts differ by driver and version | Critical | Eight verification assertions (6.1.3), of which V2, V4 and V6 each independently catch a distinct failure; startup fails closed; the resolved path is logged; unit tests over fixture files for both drivers and both namespace cases; the kind demo exercises the real thing |
| R-02 | **Pinned links block pod-cgroup removal**, leaking cgroups on the node | Low, but unverified | High operationally | OQ-S1a-01: an explicit validation step on the kind demo before this ships. `Options.PinLinks` allows disabling, at the cost of a restart capture gap |
| R-03 | **Shared bpffs lets a co-resident pod unpin or detach our links**, silently opening a bypass in our pod | Low, and now lower - it needs a co-resident pod with `CAP_BPF`, a `/sys/fs/bpf` hostPath, **and** root or `CAP_DAC_OVERRIDE` to get past the 0700 pin subtree | Critical | **A mandatory control now exists: MC-S1a-01 (6.8.6).** Gate P15 blocks pinning into any directory not exclusively owned by the proxy UID at mode 0700, failing startup with `E_PIN_ROOT_UNSAFE`; the link fds are held for the process lifetime so unpinning cannot by itself disable capture; and the attachment health check is mandatory at 10-60 s (default 30 s) with no off switch, logging `capture.attach_lost` at ERROR and exiting non-zero. Residual exposure is a root co-resident pod detaching a link, detected within 30 s. S5 must supply a per-pod bpffs to close it (6.1.4); OQ-S1a-05 tracks the mechanism |
| R-04 | **Byte-order mistake between C and Go**, producing lookups that always miss (fail closed, noisy) or - far worse - that hit the wrong entry | Medium. It is the classic footgun and the kernel's own field conventions are inconsistent | High | Section 6.4.3 states the convention once; four named helper functions are the only permitted conversion site; round-trip and known-value unit tests run on every platform; the `aksh_config` round-trip integration test proves the C and Go layouts agree |
| R-05 | **A leaf-cache bug serves a certificate for the wrong identity**, which is a cross-identity MITM | Low | Critical | Exact key matching with no normalisation beyond canonicalisation, no wildcards, no suffix logic; the CA generation is part of the key; a post-handshake assertion compares `ConnectionState().ServerName` with the captured SNI and alerts on mismatch |
| R-06 | **No fallback narrows the supported cluster matrix**, and a customer on a 5.10 kernel simply cannot run Aksh | High likelihood of occurring | Medium | Accepted deliberately (ADR-S1a-01). Preflight P2 produces a precise, actionable error naming the required kernel version, rather than a mysterious failure |
| R-07 | **The privilege drop silently does not happen** in a build that accidentally enables cgo | Low | High | Preflight P1 probes `AllThreadsSyscall` before anything else and aborts with `E_CGO_ENABLED`; step 11 of the drop verifies uid, gid, groups, the capability set, and that `setuid(0)` fails |
| R-08 | **LRU eviction under load** rejects legitimate connections as T1 | Low | Low | 32x headroom over the connection cap; eviction is fail-closed; a sustained T1 rate is an alertable signal; the map size is configurable |
| R-09 | **The committed BPF object drifts from its C source** | Medium, since it depends on developer discipline | High | CI runs `go generate` and `git diff --exit-code`, making drift a build failure; the SHA-256 and the exact toolchain are recorded next to the generation command |
| R-10 | **The handshake rate limit is wrong in either direction** - too low and legitimate agent fan-out is throttled, too high and it does nothing | Medium | Medium | Stated explicitly as unmeasured (section 13.1); both values are configurable and are logged at startup; T7 with `bound="handshake_rate"` makes throttling visible rather than mysterious |

---

## 23. Future considerations

### 23.1 IPv6 implementation

The design is complete in 6.9.2. The implementation phase must:

1. Add `aksh_connect6`, replacing `aksh_connect6_deny`.
2. Extend `struct orig_dst` with `__u32 ip6[4]` at offset 24, using the existing `flags` field
   to select the live address. Because `flags` and `pad` already exist, this is an append and
   not a layout change - which is why they exist.
3. Add `pair6_orig_dst` with `struct pair_key6`, rather than widening the IPv4 key.
4. Branch `aksh_sockops` on `skops->family` and read `local_ip6[4]`.
5. Add a `tcp6` listener on `[::1]:15001`, and dispatch in `Resolve` on the peer's family.
6. Attach both `connect4` and `connect6` links to the same pod cgroup.
7. Allow `IPv6Mode == IPv6Capture` in `Validate()`.
8. Extend the integration suite and the demo with IPv6 equivalents of every IPv4 case.
9. Remove limitation 2 and re-answer bypass case B2 in its captured form.

### 23.2 Handoff to 5B (request path and pipeline integration)

| Contract | Detail |
| -------- | ------ |
| Seam | `listener.ConnHandler`. 5B replaces `PassthroughHandler` with the request path. The listener, discriminator, resolver and TLS terminator do not change |
| Input | `*ConnContext` (7.2), fully populated: `OriginalDst` kernel-attested, `CandidateSNI` canonical, `NegotiatedALPN` set, `Transport` set |
| Identity | 5B builds `pipeline.IdentityInput` per the table in 7.3, using `tlsterm.CanonicaliseServerName` for `Host` and `:authority` so both sides of the INV-8 comparison are canonicalised identically |
| Rejection classes | T6 becomes reachable (S4 stage 1). T8 becomes reachable once the Service index exists. T9 stops being the answer for all plaintext |
| Bounds | `max_header_bytes` (64 KiB), `max_h2_streams` (100) and `max_inflight_requests` (2048) are declared in section 13.1 and enforced by 5B. All three are **5A-declared, 5B-enforced**, and `max_inflight_requests` in particular is a derived starting value whose tuning signal is named in 13.1; 5B's design review checklist must confirm that each of the three is enforced, that its breach emits T7 with the right `bound` label, and that the in-flight cap has been checked against measurement rather than inherited unexamined |
| Audit | 5B introduces `audit.AuditSink` on the connection path. 5A's pod-local denial (limitation 12) becomes an audited denial |
| Metrics | 5B should carry OQ-S1a-02 to S6 rather than extending 5A's encoding compromise |

### 23.3 Handoff to 5C (pooling and resource-bound enforcement)

| Contract | Detail |
| -------- | ------ |
| Seam | `dataplane.UpstreamDialer`. 5C replaces `upstream.DirectDialer` with a pooling implementation. **No call site changes**, because `credID` is already in the frozen signature |
| Pool key | S1 section 5.3, unchanged: (validated identity, recovered destination, resolved credential identity or the no-auth sentinel, trust-config generation, negotiated protocol policy). `DirectDialer` already validates `credID` in the form the key needs |
| Bounds | Section 13.1's numbers are declarations; 5C builds the enforcement machinery for the pool-side ones and replaces `upstream_concurrency` with pool limits |
| Response body cap | OQ-S1a-04, deliberately left open for 5C rather than guessed here |
| `SelfDialRegistry` | Must remain correct with pooled connections: register on dial, deregister on final close, not on return-to-pool |

---

## 24. File deliverables

### 24.1 New files

| Path | Contents |
| ---- | -------- |
| `docs/design/S1a-dataplane-capture.md` | This document |
| `internal/dataplane/bpf/aksh_capture.c` | All six BPF programs and three maps |
| `internal/dataplane/bpf/include/` | Minimal UAPI headers required by the programs |
| `internal/dataplane/bpf/gen.go` | The `//go:generate` directive (6.4.4) |
| `internal/dataplane/bpf/akshbpf_bpfel.go` | **Generated, committed** Go bindings |
| `internal/dataplane/bpf/akshbpf_bpfel.o` | **Generated, committed** BPF object |
| `internal/dataplane/bpf/README.md` | Regeneration command, pinned clang version, artefact SHA-256 |
| `internal/dataplane/capture/interfaces.go` | Package-local interfaces per the interface guide |
| `internal/dataplane/capture/types.go` | `origDst`, `pairKey`, `akshConfig`, flags |
| `internal/dataplane/capture/byteorder.go` | The four conversion helpers (no build tag) |
| `internal/dataplane/capture/cgroup.go` | `PodCgroupResolver`, V1-V8 (no build tag; filesystem behind a seam) |
| `internal/dataplane/capture/preflight.go` | P1-P15, split into the two phases of 6.7 |
| `internal/dataplane/capture/loader_linux.go` | Load, configure, freeze, attach, pin, verify, probe, attachment health check |
| `internal/dataplane/capture/loader_other.go` | Stubs returning `ErrUnsupportedPlatform` |
| `internal/dataplane/capture/resolver_linux.go` | `BPFDestinationResolver` |
| `internal/dataplane/capture/resolver_other.go` | Stub |
| `internal/dataplane/capture/privdrop_linux.go` | The 11-step drop sequence |
| `internal/dataplane/capture/privdrop_other.go` | Stub |
| `internal/dataplane/capture/options.go` | `Options` and `Validate()` |
| `internal/dataplane/capture/errors.go` | Sentinel errors and the `E_*` codes |
| `internal/dataplane/listener/listener.go` | `Listener`, accept loop, `ConnHandler` |
| `internal/dataplane/listener/discriminator.go` | `Discriminator`, `peekedConn` |
| `internal/dataplane/listener/types.go` | `Protocol`, `RejectClass`, `ConnContext` |
| `internal/dataplane/listener/selfdial.go` | `SelfDialRegistry` |
| `internal/dataplane/listener/podlocal.go` | Pod-local address set with atomic refresh |
| `internal/dataplane/listener/passthrough.go` | `PassthroughHandler` (5A only) |
| `internal/dataplane/listener/options.go` | `Options` and `Validate()` |
| `internal/dataplane/tlsterm/terminator.go` | `GetConfigForClient`, post-handshake assertions |
| `internal/dataplane/tlsterm/leafsource.go` | `CachedLeafSource` |
| `internal/dataplane/tlsterm/sni.go` | `CanonicaliseServerName` |
| `internal/dataplane/tlsterm/options.go` | `LeafOptions` and `Validate()` |
| `internal/dataplane/upstream/direct.go` | `DirectDialer` |
| `internal/dataplane/upstream/options.go` | `UpstreamOptions` and `Validate()` |
| `internal/pki/selfsigned.go` | `SelfSignedProvider` (test and demo only) |
| `cmd/aksh-proxy/main.go` | Wiring: options, phase-A preflight, capture, bind, phase-B probe gate, drop, serve |
| `hack/demo/kind.yaml`, `Dockerfile`, `demo-pod.yaml`, `run.sh` | The section 12 demo |

### 24.2 Modified files

| Path | Change |
| ---- | ------ |
| `docs/design/S1-data-plane.md` | Supersession header only; no other change |
| `internal/dataplane/interfaces.go` | **Doc comment only, and it is done, not planned**: `DestinationResolver`'s comment no longer names `SO_ORIGINAL_DST` and now states that the destination is kernel-attested from a BPF map (section 8). No signature, identifier or method-set change; `go build ./...` and `go test ./internal/dataplane/...` pass |
| `go.mod`, `go.sum` | Add `github.com/cilium/ebpf`, `golang.org/x/sys`, `golang.org/x/time`; promote `golang.org/x/net` from indirect to direct for `idna` |

### 24.3 Test files

| Path | Tag |
| ---- | --- |
| `internal/dataplane/capture/byteorder_test.go` | none |
| `internal/dataplane/capture/cgroup_test.go` + `testdata/` | none |
| `internal/dataplane/capture/options_test.go` | none |
| `internal/dataplane/capture/preflight_test.go` | none |
| `internal/dataplane/capture/loader_integration_test.go` | `linux && ebpf_integration` |
| `internal/dataplane/capture/resolver_integration_test.go` | `linux && ebpf_integration` |
| `internal/dataplane/capture/privdrop_integration_test.go` | `linux && ebpf_integration` |
| `internal/dataplane/listener/discriminator_test.go` + `testdata/` | none |
| `internal/dataplane/listener/listener_test.go` | none |
| `internal/dataplane/listener/selfdial_test.go` | none |
| `internal/dataplane/tlsterm/leafsource_test.go` | none |
| `internal/dataplane/tlsterm/sni_test.go` | none |
| `internal/dataplane/tlsterm/terminator_test.go` | none |
| `internal/dataplane/upstream/direct_test.go` | none |
| `internal/pki/selfsigned_test.go` | none |

---

## 25. References

### 25.1 Internal

| Document | Relevance |
| -------- | --------- |
| `docs/design/S0-architecture.md` | INV-3, INV-4, INV-6, INV-8, INV-10; DEV-01 |
| `docs/design/S1-data-plane.md` | The superseded and retained specification (section 2) |
| `docs/design/S4-enforcement-pipeline.md` | Stage 1 identity validation; T6 ownership |
| `docs/design/S5-injection-pki.md` | `CAProvider`, ADR-S5-01, pod shape and the injector |
| `docs/design/S6-observability.md` | Metric families; the destination of OQ-S1a-02 |
| `docs/design/S7-security-testing.md` | Bypass cases B1, B2, B3, B4, B50, B51, B52, B54 |
| `docs/design/interface-guide.md` | Interface and package conventions |
| `internal/dataplane/interfaces.go` | The three frozen interfaces |
| `internal/pki/interfaces.go` | `CAProvider` (authoritative over S5's prose) |
| `internal/policy/interfaces.go`, `compiled.go` | `Transport`, `RequestFacts` |
| `internal/pipeline/types.go` | `IdentityInput` and the pipeline vocabulary |
| `internal/audit/interfaces.go` | `AuditSink`, `MetricsRecorder` |
| `poc/ebpf-redirect/` | The validated proof of concept: map layouts, program logic, byte order, privilege drop |

### 25.2 External

| Reference | Relevance |
| --------- | --------- |
| Linux `bpf(2)`, `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`, `BPF_PROG_TYPE_SOCK_OPS` | Program and attach semantics |
| `include/uapi/linux/bpf.h` | `bpf_sock_addr`, `bpf_sock_ops`, `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` |
| `cgroups(7)`, `cgroup_namespaces(7)` | The namespace behaviour in 6.1.2 |
| `capabilities(7)`, `prctl(2)`, `credentials(7)` | `CAP_BPF`, `PR_SET_KEEPCAPS`, `PR_CAPBSET_DROP`, `PR_SET_NO_NEW_PRIVS` |
| `github.com/cilium/ebpf` and `bpf2go` | Loader, map access, link pinning, `link.Update` |
| RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 6176 (SSLv2 prohibited) | Section 10.2 and 11.1 |
| RFC 9113 section 3.4 (HTTP/2 connection preface) | The 24-byte peek |
| RFC 5737 (TEST-NET-1, `192.0.2.0/24`) | The self-probe destination |
| RFC 5890 and 5891 (IDNA2008) | `CanonicaliseServerName` |
| Kubernetes sidecar containers (`initContainers` with `restartPolicy: Always`) | Ordering guarantee N6 |

---

## 26. Open questions

| # | Question | Owner | Needed by | Current position |
| - | -------- | ----- | --------- | ---------------- |
| **OQ-S1a-01** | Does a pinned cgroup `bpf_link` prevent the kubelet from removing the pod cgroup on 5.15? | 5A implementation | Before merge | I believe `cgroup_bpf_release()` detaches on cgroup destruction and pinning does not block removal, but this is an assumption, not a verified fact. **Validation on the kind demo is a required implementation task.** If the assumption is wrong, `PinLinks` defaults to false and section 6.8.3's restart guarantee is lost |
| **OQ-S1a-02** | `audit.MetricsRecorder` cannot express `aksh_transport_reject_total{class=...}` or a leaf-cache hit | S6 | 5B | 5A encodes transport rejections as `RecordDecision("rejected", "<class>", ...)` and leaf-cache events as `RecordTokenCacheHit("leaf:"+id, hit)`. Both are acknowledged compromises (section 17.1). S6 should add `RecordTransportReject(class, bound string)` and `RecordCacheEvent(cache, key string, hit bool)` |
| **OQ-S1a-03** | S5's prose declares `Signer() (*x509.Certificate, crypto.Signer)`, `Generation() uint64` and `PublicPEM() []byte`; `internal/pki/interfaces.go` declares `CA() (*x509.Certificate, crypto.Signer, error)` and `Generation() int64` | PKI phase | Before the PKI phase | **The code is authoritative.** 5A consumes the code. S5's prose is stale and should be corrected; 5A does not change either |
| **OQ-S1a-04** | What is the maximum response body size (S1 section 7)? | 5C | 5C | Deliberately not answered here. 5A has no concept of a response body, and a number chosen now would be a guess 5C has to re-derive from the response path |
| **OQ-S1a-05** | By which mechanism, and when, does S5 give the proxy a per-pod bpffs instead of the shared host `/sys/fs/bpf`? | S5 and 5A implementation | Before production | **No longer an open trade-off: a mandatory interim control exists.** MC-S1a-01 (6.8.6) is required in 5A - gate P15 blocks pinning into a subtree the proxy does not exclusively own at 0700, the link fds are retained so unpinning cannot disable capture, and the attachment health check is mandatory with no off switch. What is still open is the *mechanism* for a per-pod bpffs, which 5A cannot implement because `mount(2)` needs `CAP_SYS_ADMIN` and this design will not request it. Candidates: the injector mounting a bpffs instance per pod; a CSI or device-plugin helper; a node-agent that pre-creates a per-pod subtree with the pod's UID and mounts it with `subPath`. Whichever is chosen, 6.1.4 already records it as a production requirement, and the cost - losing pins across a restart if the per-pod instance is not persistent - must be weighed against the restart gap in 6.8.3 rather than against nothing |
| **OQ-S1a-06** | Is the 50/s, burst 100 handshake rate correct for real agent fan-out? | 5C, with measurement | 5C | Unmeasured. The limiter is a connection-churn control, not a crypto-cost control (section 13.1). It needs a real workload before either value is trusted |
| **OQ-S1a-07** | How should Aksh behave when another sidecar also attaches a `connect4` program to the same pod cgroup? | 5A implementation and S5 | Before any service-mesh coexistence claim | Undefined today (N9). `BPF_F_ALLOW_MULTI` means both run and the order is not ours to choose. Detection is possible - the attach-verify step can see other programs - and at minimum Aksh should log a warning naming them |
| **OQ-S1a-08** | Can the attachment health check (6.8.5) read link info with `CAP_BPF` alone on 5.15? | 5A implementation | Before merge | `BPF_OBJ_GET` plus `BPF_OBJ_GET_INFO_BY_FD` is expected to be permitted for a `CAP_BPF` holder that owns the pin, and `BPF_PROG_QUERY` on a cgroup is deliberately not used because it needs `CAP_NET_ADMIN`, which is gone after the drop. This is an expectation, not a verified fact, and it is a required validation on the kind demo alongside OQ-S1a-01. If it turns out to need more than `CAP_BPF`, the fallback is to keep an open fd per link from before the drop and re-`stat` the pin path for existence only, which still detects unpinning but not replacement |




