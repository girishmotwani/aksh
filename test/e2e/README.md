# aksh kind e2e harness (P9c + injector #67)

End-to-end proof that the **production** `aksh-proxy` binary, deployed to a real
[kind](https://kind.sigs.k8s.io/) cluster with eBPF cgroup capture running as a
**non-root** uid, **allows** a policy-matched egress flow and **denies** an
unmatched one — with evidence from Prometheus metrics, the audit sink, and pod
logs.

The harness also deploys the **`aksh-injector`** admission webhook **via its Helm
chart** (`deploy/helm/aksh-injector`, rendered with the pinned `alpine/helm`
image and applied) and proves its contract on the live cluster: runtime caBundle
reconciliation, canonical sidecar **injection** into a plain opted-in pod,
**INV-10 denial** of a tampering workload, and **opt-out** of unlabeled
namespaces. See [`EVIDENCE.md`](./EVIDENCE.md) for a captured run of both.

> The egress-enforcement proof still runs on the hand-written golden pod
> (`manifests/50-aksh-pod.yaml`), not a webhook-injected pod, because the
> canonical injected sidecar is a placeholder that cannot start a functional
> proxy on kind without deployment config (Entra + node-capture settings) and
> #62 attribution. Making the egress proof run on an injected pod is tracked in
> **issue #87**.

> Run under **PowerShell 7 (`pwsh`)**, not Windows PowerShell 5.1: the harness
> relies on `$PSNativeCommandUseErrorActionPreference` to keep native-command
> stderr (e.g. kind progress) from being raised as a terminating error.

## Run it

```powershell
# from repo root; requires docker + kind + kubectl on PATH
./test/e2e/run.ps1              # creates cluster, drives traffic, prints evidence, tears down
./test/e2e/run.ps1 -KeepUp      # keep the cluster for manual inspection
```

Expected result:

| Flow           | HTTP | Path                                  | Disposition |
|----------------|------|---------------------------------------|-------------|
| `allowed.test` | 200  | captured → proxy → relayed to echo    | `allow` (matches rule `allow-echo`) |
| `blocked.test` | 403  | captured → proxy → uniform deny       | `deny` (`policy_no_match`) |

See [`EVIDENCE.md`](./EVIDENCE.md) for a captured run.

## Layout

```
test/e2e/
  Dockerfile              production proxy image + file caps (setcap) for non-root eBPF
  echo/                   http/1.1-only HTTPS upstream (the allowed destination)
  certs/gencert.go        generates throwaway CA + allowed.test leaf (gitignored output)
  manifests/00..50        namespace, CRD, RBAC, policy, echo target, aksh pod
  run.ps1                 one-shot driver: build -> load -> apply -> drive -> capture
```

## Why the harness is shaped this way (TSG)

- **Non-root eBPF via file caps.** Kubernetes does not promote
  `securityContext.capabilities.add` into the ambient/effective set for a
  non-root `runAsUser` — they only reach the bounding set, so a non-root eBPF
  loader gets `EPERM` on `BPF_MAP_CREATE`. The image `setcap`s the binary
  (`cap_bpf,...+ep`), which grants permitted+effective at execve regardless of
  uid — the same mechanism Cilium/Pixie use. Symptom if broken: `map create:
  operation not permitted`.
- **CAP_BPF retained across priv-drop.** The runtime drops privileges after
  loading eBPF; it must keep `CAP_BPF` (`orchestrator.go` `KeepCapabilities`)
  or later map operations fail. Regression: `TestRun_PrivDropReceivesUIDGID1774`.
- **Proxy runs as uid 1774, workload as uid 0.** Capture *excludes* the proxy's
  own uid so its upstream dials are not re-captured; the workload (uid 0) is
  captured. An idle workload starves the accept-probe and the proxy exits —
  the workload therefore drives a **continuous** loop.
- **`--http1.1` everywhere.** The request path is HTTP/1.1-only (rejects the
  HTTP/2 preface). The echo upstream serves http/1.1 only to avoid the known
  h2-ALPN relay gap in the request path.
  Symptom if broken: `response_failed` on the allow path.
- **`SSL_CERT_FILE` trust bundle.** The proxy dials the echo upstream over TLS
  using system roots plus the throwaway upstream CA. Symptom if broken:
  `handshake_failed` (fault=true) on `upstream_dial`.
- **CandidateSNI populated from ClientHello.** The TLS handler canonicalises the
  ClientHello SNI into the ConnContext so `PostHandshakeAssert` has an
  authoritative candidate; without it **every** TLS connection fails with
  `handshake_failed` (negotiated ServerName vs candidate SNI ""). Regression:
  `TestHandle_PopulatesCandidateSNIFromClientHello_AssertPasses`.
- **Scrape metrics from the node, not in-pod.** An in-pod `curl` to `:15020`
  is itself captured/redirected. `run.ps1` scrapes via
  `docker exec <cluster>-control-plane curl http://<podIP>:15020/metrics`.
- **`disposition="allow"` in metrics is a listener rollup**, emitted whenever
  `handler.Handle` returns nil — which *includes* clean 403 denies. The
  authoritative per-request disposition is in the **audit sink JSON on stdout**
  (`kubectl logs ... -c aksh | Select-String '"disposition"'`), not the metric.
- **Policy snapshot staleness.** `match_stage.go` denies with
  `policy_cache_stale` once the snapshot age exceeds `defaultMaxStaleness`
  (5 min) if the policy watch has not re-published. For a long-lived debug pod
  the snapshot can age out and deny everything; recreate the pod (or shorten the
  test) to observe allows within the freshness window. Tracked as a follow-up
  (watch should keep the snapshot fresh on an idle, connected watch).

## Requirements

- Docker, `kind`, `kubectl` on `PATH`.
- Locally-built images `kind load` cleanly; do not push to a registry.
