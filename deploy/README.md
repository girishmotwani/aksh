# Injecting the aksh egress proxy — operator guide

This is the whole job: **install the injector once, then label the namespaces you want
protected.** Every pod created in a labelled namespace automatically gets the `aksh-proxy`
egress-enforcement sidecar. No per-pod YAML, no shell wrapper.

> **Your workload pods stay in their own namespaces.** `aksh-system` is only where the injector
> itself runs — it does not hold or relocate your pods. Label as many of your own namespaces as you
> like (`team-a`, `payments`, ...); the injected sidecar runs inside each pod, in that pod's
> namespace. Injection is per-namespace (via the label), not tied to any single workload namespace.

> **The one rule that matters:** label a workload namespace **only after** the injector reports
> `Ready`. Do it in the wrong order and pod creation in that namespace will be blocked (on purpose —
> see [Why it fails closed](#why-it-fails-closed)). Follow the steps in order and you're fine.

---

## What you need first

1. `kubectl` pointing at your cluster (cluster-admin, because this installs webhooks + RBAC).
2. Two images your cluster can pull. Official images are published to GHCR by the
   release pipeline on every tagged release:
   - `ghcr.io/girishmotwani/aksh-injector` — the webhook.
   - `ghcr.io/girishmotwani/aksh-proxy` — the sidecar that gets injected.
   - Pin an immutable tag (e.g. `:v1.2.3` or a `@sha256:` digest) in production; do not ship `:latest`.
   - For a local `kind` cluster you can build and side-load them instead of pulling
     (`build/proxy.Dockerfile`, `build/injector.Dockerfile`; see `test/e2e/run.ps1`).
3. For the recommended path, `helm` v3.

## Step 1 — Install the injector

Pick one. **Helm is recommended** — it sets the images for you and needs no file edits.

### Option A — Helm (recommended)

```sh
helm install aksh deploy/helm/aksh-injector \
  --namespace aksh-system --create-namespace \
  --set injector.image.repository=ghcr.io/girishmotwani/aksh-injector \
  --set injector.image.tag=v1.2.3 \
  --set proxyImage=ghcr.io/girishmotwani/aksh-proxy:v1.2.3
```

That's the whole install of the *injector*. `proxyImage` is the sidecar image stamped into every
injected pod; the two `injector.image.*` values are the webhook image. The injector's own RBAC,
Service and both fail-closed webhook configs are created for you. **One thing is not, and cannot be:
the RBAC the injected sidecar needs in your workload namespaces — see Step 3.** Upgrade later with
`helm upgrade aksh deploy/helm/aksh-injector ...`; uninstall with `helm uninstall aksh -n
aksh-system`. All tunables are in
[`helm/aksh-injector/values.yaml`](helm/aksh-injector/values.yaml).

### Option B — Raw manifests

If you'd rather not use Helm, edit two lines then apply:

- `deploy/30-deployment.yaml` → `image: aksh-injector:latest` → your injector image.
- `deploy/30-deployment.yaml` → add an arg **`-proxy-image=<registry>/aksh-proxy:<tag>`**
  (or set env `AKSH_PROXY_IMAGE`). Defaults to `aksh-proxy:latest`, which only works if that tag is
  pullable on your nodes.

```sh
kubectl apply -f deploy/          # applies 00..50 in order
```

This covers the injector only. You still need Step 3 — `deploy/` deliberately ships no RBAC for the
sidecar, because it depends on namespaces and ServiceAccounts this repo can't know.

Either way: the `caBundle` fields are intentionally empty — the injector generates its own CA at
startup and patches them itself. **In production, pin an immutable tag or digest — never `:latest`.**

## Step 2 — Wait until the injector is Ready

```sh
kubectl -n aksh-system rollout status deploy/aksh-injector
```

`Ready` means `/readyz` passed, which is gated on the injector having successfully written its
`caBundle` into both webhook configurations. **Do not proceed until this is green.**

## Step 3 — Grant the sidecar permission to read policy

**Required. Skip this and your injected pods will crash-loop.**

The sidecar is not fed policy by a controller — it watches `AkshPolicy` in the API server itself,
authenticating as **the workload pod's own ServiceAccount, in the workload's own namespace**. Which
namespaces and ServiceAccounts those are is something only you know, so no static manifest shipped
here can grant it for you.

Do this **before** labelling the namespace in Step 4, so the permission is in place by the time the
first injected pod starts.

### Option A — let the chart render it

```sh
helm upgrade aksh deploy/helm/aksh-injector --reuse-values \
  --set workloadRBAC.enabled=true \
  --set "workloadRBAC.namespaces={team-a,team-b}" \
  --set "workloadRBAC.serviceAccounts={default,my-app-sa}"
```

This renders a `Role` + `RoleBinding` in **each** listed namespace, bound to **each** listed
ServiceAccount. List every ServiceAccount your injected pods actually run as — `default` only covers
workloads that don't set `serviceAccountName`. It is off by default because it grants permissions in
namespaces the chart doesn't otherwise touch, which should be a deliberate choice.

### Option B — apply it yourself

Per workload namespace (also in
[`examples/workload-rbac.yaml`](examples/workload-rbac.yaml)):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: aksh-proxy-policy-reader
  namespace: <your-namespace>
rules:
  - apiGroups: ["aksh.dev"]
    resources: ["akshpolicies"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: aksh-proxy-policy-reader
  namespace: <your-namespace>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: aksh-proxy-policy-reader
subjects:
  - kind: ServiceAccount
    name: default              # repeat for every SA your injected pods use
    namespace: <your-namespace>
```

Keep it a namespaced `Role`, not a `ClusterRole`: the watcher only ever reads its own namespace, and
a cluster-wide grant would let any compromised workload read every policy in the cluster.

### What it looks like when it's missing

The proxy can't get a policy snapshot, so it **refuses to start** rather than running open or silently
denying — the pod goes `CrashLoopBackOff`. `kubectl -n <ns> logs <pod> -c aksh-proxy` shows the
`AkshPolicy list/watch failed` line naming the exact `apiGroups`/`resources`/`verbs` you're missing,
and `aksh_policy_list_forbidden_total` increments.

## Step 4 — Opt a namespace in

This is the switch that turns protection on for a namespace:

```sh
kubectl label namespace <your-namespace> aksh.dev/inject=enabled
```

That's it. Any pod **created** in that namespace from now on gets the sidecar automatically.

> Injection happens on pod **CREATE** only. Pods that already exist are **not** retro-injected —
> restart the workload (`kubectl -n <ns> rollout restart deploy/<app>`) to get them injected.

## Step 5 — Verify

```sh
# Sidecar present?
kubectl -n <your-namespace> get pod <pod> \
  -o jsonpath='{.spec.containers[*].name}{"\n"}'
# → should include: aksh-proxy

# Injected marker?
kubectl -n <your-namespace> get pod <pod> \
  -o jsonpath='{.metadata.annotations.aksh\.dev/injected}{"\n"}'
# → v1
```

## Turning it off

```sh
kubectl label namespace <your-namespace> aksh.dev/inject-      # remove the label
```

New pods are no longer injected. Existing injected pods keep running until you restart them.
To remove the injector entirely: `helm uninstall aksh -n aksh-system` (or `kubectl delete -f deploy/`).

---

## Why it fails closed

`failurePolicy: Fail`. If the injector is **down or unreachable**, pod creation in an **opted-in**
namespace is **rejected** rather than allowed to run without the sidecar. That is deliberate: a
protected pod must be admissible or must not run (invariant INV-10). An unprotected pod is worse than
a failed create.

Two consequences to keep in mind:

- **Order matters (Step 2 before Step 4).** Before the injector is Ready its `caBundle` is empty; if
  a namespace were already labelled, `failurePolicy: Fail` would block every pod there. Labelling
  *after* Ready avoids that window entirely.
- **Never label `aksh-system`.** The injector's own namespace must not carry
  `aksh.dev/inject=enabled` — otherwise the injector couldn't (re)start itself. The webhook config
  also enforces this in policy (`kubernetes.io/metadata.name NotIn [aksh-system]`), so a mistaken
  label can't self-deadlock the cluster, but don't rely on that — just don't label it.

## What gets injected

The `aksh-proxy` sidecar as reserved **UID 1774**, with the cgroup hostPath mount, projected service
account token, and required capabilities — the same shape as the hand-written golden pod
(`test/e2e/manifests/50-aksh-pod.yaml`). The proxy resolves its pod cgroup path **in Go** at startup
(no `/bin/sh` wrapper).

The **validating** webhook additionally rejects pods shaped to defeat enforcement (e.g. an app
container claiming UID 1774, `NET_ADMIN` on app containers, host networking). Rejections name the
offending field so the cause is obvious.

## If something goes wrong

| Symptom | Check |
|---------|-------|
| Pods in a labelled ns won't create | Is the injector `Ready` (Step 2)? `kubectl -n aksh-system logs deploy/aksh-injector`. |
| Injected pod is `CrashLoopBackOff` | Almost always missing sidecar RBAC (Step 3). `kubectl -n <ns> logs <pod> -c aksh-proxy` — an `AkshPolicy list/watch failed` line naming `akshpolicies` confirms it. |
| Sidecar not appearing | Is the namespace labelled `aksh.dev/inject=enabled`? Is the pod newly created (not pre-existing)? |
| Pod rejected with a field name | The validating webhook blocked an inadmissible pod — fix the named field. |
| `caBundle` empty after minutes | Injector RBAC or startup failure — check its logs; it reconciles the bundle every 5 min. |

For the full design (PKI, ADRs, INV-10 profile) see
[`../docs/design/S5-injection-pki.md`](../docs/design/S5-injection-pki.md).
