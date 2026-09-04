# AgentCon Japan demo — diagnostics data bundle

This directory holds the **synthetic, pre-sanitized** cluster-diagnostics bundle
that the in-pod diagnostics MCP (`send_cluster_diagnostics`) uploads during the
demo.

## What this is

* [`bundle.json`](bundle.json) — a realistic-looking but entirely **fabricated**
  cluster diagnostics document: node inventory, workload counts, deployment
  health, node conditions, a few recent events, and coarse resource-pressure
  percentages. It follows the `aksh.dev/diagnostics-bundle/v1` shape the
  diagnostics MCP expects (`diagnostics-mcp/internal/bundle`).

## Hard rules (why it is safe to ship in git)

* **No secrets.** No API keys, tokens, kubeconfigs, passwords, `.dockerconfigjson`,
  service-account tokens, or bearer credentials.
* **No PII and no real infrastructure.** No real IP addresses, hostnames,
  account IDs, or customer data. Names like `node-a`/`agentcon-japan-demo` are
  invented.
* **No live cluster reads.** The MCP reads *only* this mounted file. It never
  touches the Kubernetes API, a service-account token, or arbitrary host files
  (enforced in the MCP source and by giving the agent identity no RBAC).

The MCP additionally redacts any secret-shaped keys and bounds size/depth as
defence-in-depth, but the bundle is authored to need none of that.

## How it reaches the pod

The orchestration renders this file into a ConfigMap
(`agentcon-diagnostics-bundle`, key `bundle.json`) — see
[`../manifests/baseline/50-diagnostics-bundle.yaml`](../manifests/baseline/50-diagnostics-bundle.yaml)
— which is mounted read-only into the diagnostics MCP container at
`/etc/aksh-diagnostics/bundle.json` (`AKSH_DIAG_BUNDLE_PATH`). Keep the ConfigMap
in sync with this file if you edit it (or regenerate it with
`kubectl create configmap agentcon-diagnostics-bundle --from-file=bundle.json=bundle.json --dry-run=client -o yaml`).
