# kagent end-to-end harness on AKS

A real [kagent](https://kagent.dev) AI agent running behind an aksh sidecar on a
real **AKS** cluster, driven end to end. This is the AKS counterpart to
[`test/e2e/kagent/`](../kagent/README.md) (which runs the identical scenario on
[kind](https://kind.sigs.k8s.io/)).

The kind harness proves the behaviour; this one proves it survives a
production-shaped node. AKS forces three things kind does not, and each one has
broken aksh at least once before:

1. **Per-pod cgroup namespaces.** `/proc/self/cgroup` reads `0::/`, so the
   proxy's Case-A path cannot derive its pod cgroup and must fall back to
   inode-based discovery (`DiscoverPodCgroup`, "Case-B"), anchored on the
   container's own namespaced cgroup mount.
2. **An enforcing AppArmor profile.** The node's default containerd profile
   denies `mount(2)` even with `CAP_SYS_ADMIN`, blocking the per-pod bpffs
   mount, so the aksh container runs `appArmorProfile: type: Unconfined`.
3. **Registry-pulled images.** There is no `kind load`; images are built into
   the cluster's ACR and pulled by the node's kubelet identity.

Everything else -- the agent, its controller-generated config, the verifying TLS
handshake, the policy, the audit assertions, and the two negative legs -- is the
same as the kind harness, so read [that README](../kagent/README.md) for the
topology, the shim-vs-Agent-CRD rationale, the pre-seeded pod CA, and why the
bypass must be narrow. Only the AKS-specific deltas are documented here.

## Usage

```powershell
# Provision a dedicated cluster (ACR + AKS via Bicep), build, run, leave it up:
pwsh test/e2e/kagent-aks/run.ps1

# Run against an already-deployed cluster (e.g. the shared soak cluster), fast:
pwsh test/e2e/kagent-aks/run.ps1 -SkipInfra -ResourceGroup aksh-soak-rg -DeploymentName aksh-soak

# Re-drive assertions only (images + kagent already installed):
pwsh test/e2e/kagent-aks/run.ps1 -SkipInfra -SkipBuild -SkipInstall -ResourceGroup aksh-soak-rg -DeploymentName aksh-soak

# Remove the kagent namespace + CoreDNS rewrite when done (never deletes the cluster):
pwsh test/e2e/kagent-aks/run.ps1 -SkipInfra -SkipBuild -SkipInstall -Cleanup -ResourceGroup aksh-soak-rg -DeploymentName aksh-soak
```

Exits non-zero if any check fails.

| Param | Default | Meaning |
|-------|---------|---------|
| `-SubscriptionId` | _(required)_ | Azure subscription to deploy into |
| `-ResourceGroup` | `aksh-kagent-rg` | RG for the ACR + AKS |
| `-Location` | `eastus2` | region |
| `-NodeVmSize` | `Standard_E4s_v5` | AKS node size (change if your subscription restricts this SKU) |
| `-DeploymentName` | `aksh-kagent` | Bicep deployment name to read ACR/AKS outputs from |
| `-Tag` | `kagent-e2e` | image tag for `aksh-proxy` and `mockllm` in the ACR |
| `-SkipInfra` | off | reuse an already-deployed cluster/ACR |
| `-SkipBuild` | off | reuse already-pushed `:$Tag` images |
| `-SkipInstall` | off | reuse kagent/mockllm/CoreDNS rewrite |
| `-Cleanup` | off | delete the kagent namespace + CoreDNS rewrite on exit |

The cluster is **never** deleted by this harness (it is designed to share the
soak cluster). Tear the whole thing down only when you are finished with both:

```powershell
az group delete -g aksh-soak-rg --yes --no-wait
```

## What differs from the kind harness

| Concern | kind | AKS (here) |
|---------|------|------------|
| Cluster | `kind create/delete cluster` | Bicep (`infra/main.bicep`: ACR + AKS, plain Azure CNI, Ubuntu nodes); reused, not torn down |
| Images | `kind load docker-image` | `az acr build` into the cluster's ACR, pulled via the kubelet's `AcrPull` |
| aksh sidecar | `manifests/80-agent-shim.yaml` | `manifests/80-agent-shim.yaml` **here**: adds AppArmor Unconfined, `AKSH_CAPTURE_LOCAL_CGROUP_MOUNT=/sys/fs/cgroup`, and drops the pod-path wrapper (Case-B auto-discovers) |
| DNS rewrite | overwrite the `coredns` ConfigMap | the AKS-owned `coredns-custom` ConfigMap (`api.openai.com` -> mock) so AKS does not reconcile it away |
| Reaching the agent | `docker exec <kind-node> curl <podIP>:8080` | `kubectl exec -c driver -- curl localhost:8080` (the pod network is not routable from the host and the shim has no Service) |

The agent, mockllm, RBAC, policy, model config, Agent CR, CA generators and the
kagent Helm values are all shared from `../kagent/` -- this harness owns only the
Bicep infra, the AKS shim, and its driver.

## What is asserted

Identical to the kind harness (A-F). All six pass on AKS:

| | Check | Result on AKS |
|---|-------|---------------|
| A | agent answers over A2A with the mock LLM's reply | pass |
| B | agent's own `POST /v1/chat/completions` audited `allow`, identity `api.openai.com`, attributed to the policy, with pod attribution | pass |
| C | `blocked.test` audited `deny` / `policy_no_match` | pass |
| D | **negative:** point the policy at a non-matching host => agent can no longer reach its model, call audited `deny` => restore | pass |
| E | **negative:** replace the bypass with `192.0.2.0/32` (covers nothing) => agent cannot serve | pass |
| F | restore the bypass => agent works again | pass |

## Captured evidence

Node: `Ubuntu 24.04 LTS`, kernel `6.8.0-...-azure` (cgroup v2 unified). The aksh
sidecar came up, mounted its bpffs, discovered its pod cgroup by inode, and
captured the agent's egress. Representative audit records:

```json
// B: the agent's real LLM call, terminated + policed + attributed
{"schema":"aksh.dev/audit/v1","pod":{"namespace":"kagent","name":"aksh-agent-shim-...","uid":"..."},
 "agent":{"serviceAccount":"aksh-kagent"},"decision":{"disposition":"allow","reason":"unspecified"},
 "request":{"identity":"api.openai.com","method":"POST","path":"/v1/chat/completions","port":443},
 "policy":{"ref":"kagent/allow-openai/allow-openai","evaluatorVersion":"aksh-eval-v1"},
 "timings":{"total_us":29,"match_us":3}}

// C: the deny leg
{"decision":{"disposition":"deny","reason":"policy_no_match"},
 "request":{"identity":"blocked.test","method":"GET","path":"/","port":443}}
```

D and E are the point: A-C would all pass against an aksh that captured nothing
and a policy that was never consulted; the negative legs are what make them
load-bearing, and they hold on AKS.

## Generated, not committed

`run.ps1` produces these under `test/e2e/kagent-aks/` (all gitignored):

- `.kubeconfig` -- dedicated kubeconfig for the target cluster
- `.certs/` -- the pod CA (`ca-cert.pem`, `ca-key.pem`)
- `.mockllm/` -- the mock's self-contained build context + its throwaway certs
- `.rendered/` -- kagent Helm output

kagent is pinned to **0.9.12** (0.10.x is a breaking rearchitecture). The Bicep
deliberately uses **plain Azure CNI**, not Cilium: "Azure CNI powered by Cilium"
attaches its own eBPF to the same cgroups aksh hooks and the two conflict.
