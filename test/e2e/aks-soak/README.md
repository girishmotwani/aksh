# aksh AKS Soak / Performance Harness

A repeatable, checked-in harness that stands up a **real AKS cluster**, deploys
the `aksh` egress proxy in front of a load generator, and measures the
**end-to-end latency, CPU and memory cost of aksh under sustained load** over a
multi-hour soak. Everything is driven by one script (`run.ps1`) and one Bicep
template (`infra/main.bicep`); no manual cluster surgery is required.

Unlike the kind-based harness in `test/e2e/`, this runs on stock AKS, which
exposes production-only behaviour that kind does not (per-pod **cgroup
namespaces** and the containerd **AppArmor** profile). Getting capture working
here is itself the proof that aksh runs on real AKS - see
[Why AKS is different](#why-aks-is-different-vs-kind).

## What it measures

Two fortio load generators drive identical HTTPS traffic at the same QPS to the
same echo upstream:

| Pod | aksh in path? | Purpose |
|-----|---------------|---------|
| `loadgen-aksh` | **yes** - every request is eBPF-captured, TLS-terminated and policy-evaluated by the proxy sidecar | measured latency |
| `loadgen-baseline` | no - talks directly to the upstream | control / baseline |

The **latency delta** (`loadgen-aksh` minus `loadgen-baseline`) is the
end-to-end cost aksh adds. An in-cluster **Prometheus** (backed by a PVC so it
survives the whole soak) scrapes:

- the proxy's own metrics on `:15020` - `aksh_decisions_total`,
  `aksh_decision_duration_seconds` (per-stage), etc.
- kubelet **cAdvisor** - `container_cpu_usage_seconds_total` and
  `container_memory_working_set_bytes`, so aksh CPU/memory is attributable
  per container.

`run.ps1` periodically snapshots all of this into `EVIDENCE.md`.

## Prerequisites

- Azure CLI (`az`) logged in, with access to a subscription that permits the
  chosen VM size (see note below).
- `kubectl`.
- PowerShell 7+.

The harness writes a **dedicated** `.kubeconfig` next to `run.ps1` and never
touches your default kubeconfig.

## Usage

```powershell
cd test/e2e/aks-soak

# Full run: deploy infra + build images + deploy workloads + start the 6h soak.
./run.ps1 -Soak

# Faster iteration against an already-deployed cluster / already-pushed images:
./run.ps1 -SkipInfra -SkipBuild -Soak

# One-off evidence snapshot (no deploy), appends a row to EVIDENCE.md:
./run.ps1 -SkipInfra -SkipBuild -ReportOnly
```

### Supplemental performance tests (`perf-tests.ps1`)

The 6h soak reuses warm keep-alive connections, so it does not exercise
per-new-connection handshake cost or find the throughput knee. `perf-tests.ps1`
covers both against the already-deployed cluster (loadgens are driven in `idle`
mode via `kubectl exec`, so no background traffic interferes):

```powershell
./perf-tests.ps1 -SkipRedeploy   # loadgens already idle from a prior run
./perf-tests.ps1                 # otherwise: redeploys loadgens in idle mode first
```

It writes two evidence files (both git-ignored):

- **`CHURN.md`** - handshake / connection-churn characterization. Compares
  keep-alive (steady-state), churn *under* the handshake-rate limit (true
  per-connection TLS tax), and churn *over* the limit (the resource guard
  engaging).
- **`RAMP.md`** - a QPS ramp (100 -> 4000 qps, warm connections) with achieved
  rate, latency percentiles, and counter-delta aksh CPU per step, to locate any
  saturation knee.

> **Handshake-rate limit (production consideration).** aksh's listener caps
> *new* TLS handshakes at **50/s (burst 100)** by default
> (`internal/dataplane/listener/options.go`, applied via
> `listener.DefaultOptions()` in `internal/runtime/factory.go`). This is a
> deliberate DoS guard, but the value is currently **hard-coded** - not exposed
> via config or env. Excess handshakes are shed as
> `aksh_transport_reject_total{bound="handshake_rate",class="resource_limit"}`
> (and surface to clients as connection failures). Workloads with low connection
> reuse that need more than 50 new connections/s would require this limit to be
> raised, which today means a code change. Recommended follow-up: surface it as
> a config/env knob.

Key parameters (see the `param(...)` block in `run.ps1` for all):

| Param | Default | Meaning |
|-------|---------|---------|
| `-Qps` | 200 | fortio request rate per loadgen |
| `-Conn` | 16 | concurrent connections |
| `-Interval` | 60 | seconds per fortio batch (interim report cadence) |
| `-DurationHours` | 6 | soak length |
| `-SampleMinutes` | 15 | evidence snapshot cadence during `-Soak` |
| `-NodeVmSize` | `Standard_E4s_v5` | AKS node size |
| `-Soak` | off | run the timed collection loop and write `EVIDENCE.md` |
| `-ReportOnly` | off | collect one snapshot and exit |

> **VM-size note.** The default is `Standard_E4s_v5`. Some subscriptions
> restrict which VM SKUs may be deployed in a given region; override
> `-NodeVmSize` if that default is not available to you.

## Files

| Path | Role |
|------|------|
| `run.ps1` | the driver: infra -> build -> deploy -> wait -> collect evidence |
| `perf-tests.ps1` | supplemental churn + QPS-ramp tests (writes `CHURN.md`, `RAMP.md`) |
| `infra/main.bicep` | ACR + AKS (cgroup v2, Ubuntu node image) |
| `infra/loadgen.Dockerfile` | fortio's static binary on a shell base (stock `fortio/fortio` is distroless, which breaks the batch loop) |
| `manifests/40-echo.yaml` | echo upstream (`allowed.test`), fixed clusterIP in the AKS service CIDR |
| `manifests/50-capture.yaml` | single aksh-captured pod used to de-risk capture on AKS (proof-of-life) |
| `manifests/60-prometheus.yaml` | in-cluster Prometheus (aksh + cAdvisor scrape jobs, PVC-backed) |
| `manifests/70-loadgen-aksh.yaml` | aksh-captured fortio load generator |
| `manifests/71-loadgen-baseline.yaml` | baseline fortio load generator (no aksh) |

Base CRD/RBAC/policy come from the shared `test/e2e/manifests/` (`00`-`30`) and
the upstream CA from `test/e2e/certs/ca.crt`, applied by `run.ps1`.

## Why AKS is different (vs kind)

Three production-only behaviours had to be handled for capture to work at all;
they are baked into the loadgen manifest and are the reason this harness exists:

1. **Per-pod cgroup namespaces.** On AKS (cgroup v2) kubelet gives each pod a
   private cgroup namespace, so `/proc/self/cgroup` reads `0::/`. The proxy's
   Case-A path fails closed on that; it must fall back to inode-based discovery
   (`DiscoverPodCgroup`) to recover the real pod cgroup. kind does not use
   cgroup namespaces, so this path is never exercised there.
2. **The container's own namespaced cgroup mount** must be used as the discovery
   anchor (`AKSH_CAPTURE_LOCAL_CGROUP_MOUNT=/sys/fs/cgroup`), not the host bind
   (which resolves to the opaque inode 1).
3. **AppArmor.** AKS enforces the default containerd AppArmor profile, which
   denies `mount(2)` even with `CAP_SYS_ADMIN`, blocking the per-pod bpffs
   mount. The aksh container therefore sets `appArmorProfile: type: Unconfined`.
   > Production follow-up: the injector likely needs to set this too for AKS.

## Teardown

The cluster is **left running** so the soak can finish (tearing down loses the
evidence). When done:

```powershell
az group delete -g aksh-soak-rg --yes --no-wait
```

## Evidence

`EVIDENCE.md` (git-ignored; it is a per-run artifact) accumulates one row per
snapshot:

```
| UTC | aksh p50 | aksh p90 | aksh p99 | base p50 | base p90 | base p99 | dp50 | dp90 | dp99 | aksh cpu (m) | aksh mem (Mi) | allow | deny |
```

A representative snapshot at 200 qps / 16 connections (all 200s, capture
confirmed via the proxy's own allow decisions):

| aksh p50 | aksh p90 | aksh p99 | base p50 | base p90 | base p99 | dp50 | dp90 | dp99 | aksh cpu | aksh mem |
|---------:|---------:|---------:|---------:|---------:|---------:|-----:|-----:|-----:|---------:|---------:|
| 1.40ms | 1.91ms | 2.74ms | 0.55ms | 0.94ms | 1.79ms | +0.85ms | +0.98ms | +0.96ms | ~43 mcores | ~18 MiB |

### Supplemental perf results

From `perf-tests.ps1` on `Standard_E4s_v5` (4 vCPU), captured in
`CHURN.md` / `RAMP.md`:

- **Steady-state (keep-alive) tax:** ~+0.87ms p50 / +1.0ms p99 - a full
  TLS-terminating forward proxy for under a millisecond of added median latency.
- **QPS ramp:** aksh sustains **100 -> 4000 qps** with **flat** latency
  (p50 ~1.5-1.9ms, p99 ~3.7-5.5ms) and hits the target rate exactly at every
  step - **no saturation knee** on this node. CPU scales cleanly linearly
  (~0.1 core per 1000 qps; 0.015 cores @ 100 qps -> 0.433 cores @ 4000 qps).
- **Handshake rate:** below the 50/s limit, churn is clean (0 rejects); at
  200 new conn/s the limiter admits ~1585 and sheds ~4415 as designed (see the
  hard-coded-limit note above).
