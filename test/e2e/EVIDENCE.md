# P9c e2e evidence — aksh allow/deny on a kind cluster

Captured from a live run of `test/e2e/` on a real kind cluster with the
**production** `aksh-proxy` image, eBPF cgroup capture running as **uid 1774**
(non-root, via file caps), a captured workload (uid 0) driving both flows, and
an http/1.1-only echo upstream at clusterIP `10.96.100.100:8443`.

Pod `aksh-e2e` startTime `2026-08-24T01:05:17Z`, podIP `10.244.0.27`.

## 1. Workload — allow=200, block=403, both through the proxy (VIA=127.0.0.1)

```
[workload] ALLOW -> ALLOWED-UPSTREAM-OK host=allowed.test path=/ method=GET
 CODE=200 VIA=127.0.0.1
[workload] BLOCK ->  CODE=403 VIA=127.0.0.1
[workload] ALLOW -> ALLOWED-UPSTREAM-OK host=allowed.test path=/ method=GET
 CODE=200 VIA=127.0.0.1
[workload] BLOCK ->  CODE=403 VIA=127.0.0.1
```

`VIA=127.0.0.1` proves the workload's egress was captured and redirected to the
proxy listener (not sent directly to the upstream). `ALLOWED-UPSTREAM-OK` is the
echo server's body — the allow flow was relayed all the way to the upstream and
returned 200. The block flow got a uniform 403 from the proxy.

## 2. Audit sink (authoritative disposition) — allow vs deny

```json
{"decision":{"disposition":"allow","reason":"unspecified","fault":false},
 "request":{"identity":"allowed.test","method":"GET","path":"/","port":8443},
 "policy":{"ref":"aksh-e2e/allow-echo-upstream/allow-echo",
           "version":"7db97e7d37484c0271989ebfa20f0ff4aa0b885aa883d098ce183e25a9472437"}}

{"decision":{"disposition":"deny","reason":"policy_no_match","fault":false},
 "request":{"identity":"blocked.test","method":"GET","path":"/","port":8443},
 "policy":{"ref":"","version":""}}
```

`allowed.test` matched policy rule `aksh-e2e/allow-echo-upstream/allow-echo`;
`blocked.test` matched no rule → `policy_no_match` deny. Neither is a fault
(`fault:false`) — both are correct policy outcomes.

## 3. Metrics (scraped from the node) — stages traversed

```
aksh_decision_duration_seconds_count{stage="accept_to_dispatch"} 29
aksh_decision_duration_seconds_count{stage="resolve"}            29
aksh_decision_duration_seconds_count{stage="tls_config_build"}   29
aksh_decision_duration_seconds_count{stage="upstream_dial"}      14
aksh_decisions_total{disposition="allow",fault="false",reason="unspecified",transport="tls"} 43
```

`resolve=29` — every captured connection recovered its original destination via
eBPF. `upstream_dial=14` — only the allow flows dialed the upstream (the ~half
that were `allowed.test`); the deny flows never reached the dialer.
(`disposition="allow"` here is the listener rollup for *handled* connections,
which includes clean denies — the true dispositions are in §2.)

## 4. Echo upstream — served allowed.test ONLY (deny never reached it)

```
echo served host=allowed.test path=/ method=GET from=10.244.0.27:52276
echo served host=allowed.test path=/ method=GET from=10.244.0.27:44800
echo served host=allowed.test path=/ method=GET from=10.244.0.27:44806
```

The upstream logged `allowed.test` requests only — `blocked.test` was denied at
the proxy and never forwarded. This is the strongest end-to-end confirmation
that deny is enforced before egress leaves the pod.

## Production bugs found and fixed during this e2e (both under TDD)

1. **CAP_BPF dropped across priv-drop** — the runtime dropped privileges after
   loading eBPF without keeping `CAP_BPF`, so post-drop map operations failed
   with `EPERM`. Fixed in `internal/runtime/orchestrator.go`
   (`KeepCapabilities: ["CAP_BPF"]`). Regression:
   `TestRun_PrivDropReceivesUIDGID1774`.
2. **CandidateSNI never populated** — the TLS handler wired
   `GetConfigForClient` but never wrote `cc.CandidateSNI`, so
   `PostHandshakeAssert(state, "")` failed on **every** TLS connection
   (`handshake_failed`, negotiated ServerName vs candidate SNI ""). Unit tests
   masked it by pre-setting `CandidateSNI`. Fixed in
   `internal/runtime/tls_conn_handler.go` by canonicalising the ClientHello SNI
   into the ConnContext inside the handshake. Regressions:
   `TestHandle_PopulatesCandidateSNIFromClientHello_AssertPasses`,
   `TestHandle_ClientHelloSNIOverridesPresetCandidate`.

## Known follow-up (not a P9c blocker)

- **Policy snapshot staleness on a long-lived pod.** `match_stage.go` denies
  `policy_cache_stale` once the snapshot age exceeds 5 min if the watch has not
  re-published; a long-running debug pod can age out and deny everything. Allows
  are observed on a freshly-created pod within the freshness window. The watch
  should keep the snapshot fresh on an idle-but-connected watch — filed as a
  follow-up.

---

# Injector (#67) e2e evidence — sidecar injection + INV-10 on a kind cluster

Captured from the same `test/e2e/run.ps1` harness, extended to deploy the
`aksh-injector` admission webhook **via its Helm chart** (`deploy/helm/aksh-injector`,
rendered and applied) and prove its full contract on a real cluster before the
egress proof above runs. The chart's default values match the e2e image names, so
no overrides are needed; the run also gates the chart templating.

> Follow-up: the egress proof runs on the golden pod, not an injected pod, because
> the canonical injected sidecar cannot start a functional proxy on kind without
> deployment config + #62 attribution. Tracked in issue #87.

## 1. caBundle reconciliation — webhooks patched at runtime (fail-closed bootstrap)

The manifests ship `caBundle: ""` + `failurePolicy: Fail`. The injector
generates a self-signed CA at startup and patches both configurations:

```
aksh-injector: generated webhook CA notAfter=2036-...
aksh-injector: patched webhook caBundle configuration=mutating   resourceVersion=616
aksh-injector: patched webhook caBundle configuration=validating resourceVersion=617
aksh-injector: serving webhook addr=[::]:9443
```

Harness assertion: both `clientConfig.caBundle` fields are non-empty (len=756).

## 2. Sidecar INJECTION — a plain opted-in pod is mutated to canonical shape

Namespace `aksh-inject` labelled `aksh.dev/inject=enabled`; a single-container
`app` pod is submitted with no sidecar. The mutating webhook prepends the
canonical `aksh` sidecar (`patchBytes=3460`):

```
aksh-injector: pod mutation allowed namespace=aksh-inject name=inject-target patchBytes=3460
```

Asserted on the persisted object:
- `spec.containers[0].name == aksh`, image `aksh-proxy:latest`, `runAsUser 1774`
- annotation `aksh.dev/injected=v1`, `spec.hostPID=true`, `fsGroup=1774`
- the original `app` container preserved (`containers: aksh app`)

## 3. INV-10 DENIAL — a tampering workload is rejected by the validating webhook

A pod whose own `app` container adds the reserved capture capability `NET_ADMIN`
is denied (after the mutating webhook injects the sidecar):

```
admission webhook "validate.pods.aksh.dev" denied the request:
spec.containers[name=app].securityContext.capabilities.add: must not add privileged capabilities
```

## 4. OPT-OUT — an unlabeled namespace is untouched

The same plain pod applied to the unlabeled `default` namespace is left with a
single `app` container (namespaceSelector opt-in respected).

## Production bug found and fixed during this e2e (under TDD)

**Injected pods denied by the validating webhook (`source drift`).** The
injector compared aksh volume sources with `reflect.DeepEqual`. On a real
cluster the API server defaults `hostPath.type` (nil -> `""`) and the
configMap/projected `defaultMode` **after** the mutating webhook returns its
patch, so the object the validating webhook then sees never matched the
canonical source and **every** injected pod was denied
(`spec.volumes[name=hostcgroup]: source drift from required aksh volume`). The
in-memory unit tests missed it (no API defaulting). Fixed with a
defaulting-tolerant `volumeSourceEquivalent` comparison in
`internal/injector/canonical.go` that ignores the server-defaulted cosmetic
fields while still comparing every security-relevant field exactly. Regressions:
`TestValidate_APIServerDefaultedVolumes_Allowed`,
`TestValidate_DriftedVolumeSource_StillDenied`.

## Known follow-ups surfaced by this e2e (not #67 blockers)

- **Injected pods carry no Downward-API audit attribution.** `canonicalEnv`
  predates #62 and does not inject `AKSH_POD_NAME/NAMESPACE/UID` /
  `AKSH_AGENT_SERVICE_ACCOUNT`, so an injected proxy's audit records would have
  an empty pod block. The hand-written golden egress pod sets them (and passes
  the attribution assertion); the injector template should be extended to add
  the Downward-API attribution env (a canonical-shape change requiring a UT
  update).
- **kind-specific proxy overrides are not injected.** The injected sidecar omits
  `AKSH_CAPTURE_MOUNT_BPFFS` and the hybrid-node local-cgroup override the kind
  node needs, so a fully-injected pod would not become Ready on this kind node
  (Case A). The egress proof above therefore runs against the golden pod, which
  carries those e2e-only overrides.
