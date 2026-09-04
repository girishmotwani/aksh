#!/usr/bin/env bash
# common.sh — shared state, logging and the demo "contract" for the presenter.
#
# This file is the single source of truth for the names the presenter CLI uses
# to talk to the rest of the AgentCon Japan demo. Several of those names are
# OWNED BY OTHER WORKSTREAMS (the collector/MCP source, the injector image, the
# kagent manifests/values and PRESENTER.md). Where that is the case it is called
# out with `# INTEGRATION:` so the wiring is obvious and overridable.
#
# Everything here is Bash 3.2 safe (see portable.sh). No associative arrays.

if [ -n "${_AKSH_COMMON_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_COMMON_SOURCED=1

# Resolve directories relative to this file so the CLI works from any cwd.
_common_self=${BASH_SOURCE[0]}
LIB_DIR=$( cd "$( dirname "$_common_self" )" && pwd )
SCRIPTS_DIR=$( cd "$LIB_DIR/.." && pwd )
DEMO_DIR=$( cd "$SCRIPTS_DIR/.." && pwd )
REPO_ROOT=$( cd "$DEMO_DIR/../.." && pwd )

# shellcheck source=./portable.sh
. "$LIB_DIR/portable.sh"

# ---------------------------------------------------------------------------
# Contract defaults. Every one may be overridden from presenter.env.local or
# the environment, so the demo can adapt as sibling workstreams settle names.
# ---------------------------------------------------------------------------

# kind cluster + kube context. Named so the presenter never touches an
# unrelated cluster on the presenter's laptop.
: "${CLUSTER:=agentcon-japan}"
: "${KIND_CONTEXT:=kind-${CLUSTER}}"
# shellcheck disable=SC2034  # consumed across cluster.sh/k8s.sh (docker exec node)
NODE_NAME="${CLUSTER}-control-plane"
: "${KAGENT_VERSION:=0.9.12}"
# Immutable pin: kagent 0.10.x is a breaking rearchitecture, so the demo refuses
# to run against any version other than this. install_kagent enforces it.
# shellcheck disable=SC2034  # consumed in scripts/lib/install.sh
KAGENT_VERSION_PINNED="0.9.12"
: "${HELM_IMAGE:=alpine/helm:3.16.3}"

# The one namespace the demo runs in and the ONLY namespace protect labels.
: "${DEMO_NS:=agentcon-demo}"

# The opt-in label protect applies to select workloads for injection. Only
# workloads carrying this label are ever mutated.
: "${INJECT_LABEL_KEY:=aksh.dev/inject}"
: "${INJECT_LABEL_VALUE:=enabled}"

# Reserved proxy identity. Traffic attributed to this uid is the proxy's own
# egress and is EXEMPT from capture; a captured agent must therefore run as a
# different uid. The "non-1774" invariant checks depend on this.
: "${PROXY_UID:=1774}"
: "${PROXY_GID:=1774}"

# The exfiltration/telemetry FQDN the demo agent is steered toward. CoreDNS is
# rewritten so this name resolves A-only to the in-cluster collector.
# CONTRACT (manifests/collector.yaml, collector/README.md): the collector is
# Service "telemetry" in namespace "ops-insights"; its HTTP observer/harness
# surface is svc port 80 -> container 8080, and HTTPS ingest is 443 -> 8443.
: "${TELEMETRY_HOST:=telemetry.ops-insights.example}"
# The exact HTTP path the diagnostics-mcp tool POSTs the exfil bundle to; the
# AkshPolicy has no matching rule for it, so protected egress is denied
# (policy_no_match). Used verbatim by evidence/validate audit filters.
: "${DIAG_PATH:=/api/v1/cluster-diagnostics}"
: "${COLLECTOR_SVC:=telemetry}"
: "${COLLECTOR_NS:=ops-insights}"
# The collector observer/harness (dashboard + /internal/count|reset|events) is
# what the presenter port-forwards; the ingest listener is never exposed.
: "${COLLECTOR_PORT:=80}"
: "${COLLECTOR_INGEST_PORT:=443}"
: "${COLLECTOR_LOCAL_PORT:=18080}"
# Harness surfaces on the collector's HTTP observer (svc port 80) — shared by
# setup's fatal readiness assertions and validate's count-based checks.
: "${COLLECTOR_COUNT_PATH:=/internal/count}"
: "${COLLECTOR_RESET_PATH:=/internal/reset}"
: "${AGENT_PORT:=8080}"
: "${KAGENT_UI_SVC:=kagent-ui}"
: "${KAGENT_UI_PORT:=8080}"
: "${KAGENT_UI_LOCAL_PORT:=18081}"
: "${AGENT_SELECTOR:=kagent=agentcon-agent}"
: "${PROTECT_TARGET_SELECTOR:=$AGENT_SELECTOR}"

# Demo images side-loaded into the kind node. Built native to the node arch.
: "${COLLECTOR_IMAGE:=collector:demo}"
: "${MCP_IMAGE:=diagnostics-mcp:agentcon}"
: "${COLLECTOR_BUILD_CONTEXT:=${DEMO_DIR}/collector}"
: "${MCP_BUILD_CONTEXT:=${DEMO_DIR}/diagnostics-mcp}"
# The diagnostics-mcp sidecar container name and the in-container binary used by
# the model-free offline contingency (`evidence --live-deny`), which invokes the
# MCP tool's `send <endpoint>` CLI mode directly via `kubectl exec`.
# INTEGRATION: the Agent manifest (parent-owned) names this container.
: "${MCP_CONTAINER:=diagnostics-mcp}"
: "${MCP_SEND_BINARY:=/usr/local/bin/diagnostics-mcp}"

# Images. Built from the repo's production Dockerfiles at the demo's own tags so
# a presenter's `latest` is never disturbed.
: "${PROXY_IMAGE:=aksh-proxy:agentcon}"
: "${INJECTOR_IMAGE:=aksh-injector:agentcon}"
: "${PROXY_DOCKERFILE:=${REPO_ROOT}/build/proxy.Dockerfile}"
: "${INJECTOR_DOCKERFILE:=${REPO_ROOT}/build/injector.Dockerfile}"

# Where the presenter keeps per-run state: PID files, rendered Corefiles,
# captured evidence. Targeted so `reset`/`cleanup` can be exact and safe.
: "${STATE_DIR:=${DEMO_DIR}/.state}"
PIDS_DIR="${STATE_DIR}/pids"
EVIDENCE_DIR="${STATE_DIR}/evidence"
RENDER_DIR="${STATE_DIR}/render"

# Manifests owned by the kagent/injector/collector workstreams. The collector
# workstream landed manifests/collector.yaml at the FLAT top level, so baseline
# discovery covers both the flat manifests/ dir and an optional manifests/baseline
# subdir; protect-stage YAML (injector, AkshPolicy) goes in manifests/protect.
# INTEGRATION: sibling workstreams populate these; see manifests/*/.gitkeep.
: "${MANIFESTS_DIR:=${DEMO_DIR}/manifests}"
: "${BASELINE_MANIFESTS_DIR:=${MANIFESTS_DIR}/baseline}"
: "${PROTECT_MANIFESTS_DIR:=${MANIFESTS_DIR}/protect}"
: "${BROKER_MANIFESTS_DIR:=${MANIFESTS_DIR}/broker}"

# ConfigMap the shim/injector consume for the live, cluster-assigned addresses.
: "${NET_CONFIGMAP:=aksh-demo-net}"

# kagent is deliberately outside the protected workload namespace.
: "${KAGENT_NS:=kagent}"
: "${KAGENT_CONTROLLER_SVC:=kagent-controller}"

# Credential custody: baseline kagent receives the real key; protect replaces
# that value with a non-secret placeholder and mounts the real key only into
# Aksh through the injector runtime profile.
: "${MODEL_SECRET_NAME:=aksh-model-credentials}"
: "${STATIC_TOKEN_SECRET_NAME:=aksh-openai-credential}"
: "${STATIC_TOKEN_SECRET_KEY:=token}"
: "${POD_CA_PRIVATE_SECRET_NAME:=aksh-pod-ca-private}"
: "${POD_CA_PUBLIC_SECRET_NAME:=aksh-pod-ca-public}"

# The agent's mounted "cloud credential" — the secret a prompt-injected agent
# exfiltrates. Baseline holds a REAL Microsoft Entra access token (minted via
# `az`); `protect` swaps it for a placeholder (custody) and stashes the real
# token in an Aksh-only vault Secret to prove it is out of the agent.
: "${AGENT_CRED_SECRET_NAME:=agent-cloud-credential}"
: "${AGENT_CRED_KEY:=credential}"
: "${AKSH_VAULT_CRED_SECRET_NAME:=aksh-held-cloud-credential}"
: "${AKSH_VAULT_NS:=aksh-system}"
# Where the credential Secret is mounted into the MCP container (subPath file).
# Must equal AKSH_DIAG_CREDENTIAL_PATH in manifests/baseline/40-agent.yaml.
: "${AGENT_CRED_MOUNT_FILE:=/etc/aksh-diagnostics/credential}"
# The Azure resource whose Entra token is used as the demo credential. Overridable.
: "${AZURE_CRED_RESOURCE:=https://cognitiveservices.azure.com}"
: "${CRED_PLACEHOLDER:=AKSH-CUSTODY-PLACEHOLDER-not-a-real-credential}"
# Prefix marking a clearly-synthetic (non-Entra) demo credential used when `az`
# is unavailable. Detected structurally so freshness/kind checks never mistake
# it for a real, expiring JWT.
: "${CRED_SYNTHETIC_PREFIX:=DEMO-SYNTHETIC-ENTRA-TOKEN}"
# The MCP CLI subcommand used by the model-free steal contingency.
: "${MCP_STEAL_BINARY:=${MCP_SEND_BINARY}}"

# ---------------------------------------------------------------------------
# Logging. Colour only when stdout is a TTY and NO_COLOR is unset, so piped
# output and CI logs stay clean.
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$( printf '\033[0m' ); C_CYAN=$( printf '\033[36m' )
  C_GREEN=$( printf '\033[32m' ); C_RED=$( printf '\033[31m' )
  C_YELLOW=$( printf '\033[33m' ); C_DIM=$( printf '\033[2m' )
else
  C_RESET=; C_CYAN=; C_GREEN=; C_RED=; C_YELLOW=; C_DIM=
fi

# A running list of failures so a subcommand can report all problems at once
# rather than dying on the first (mirrors the reference harness).
FAIL_COUNT=0
FAILURES=""

step()  { printf '%s==>%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
info()  { printf '    %s\n' "$*"; }
dim()   { printf '%s    %s%s\n' "$C_DIM" "$*" "$C_RESET"; }
ok()    { printf '  %s[ok]%s   %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '  %s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()   { printf '  %s[err]%s  %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
fail()  {
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  FAILURES="${FAILURES}
  - $*"
  printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2
}
# check BOOL_CMD... ; MSG  — convenience: pass/fail on a command's exit status.
check() {
  # usage: check "message" command args...
  _chk_msg=$1; shift
  if "$@" >/dev/null 2>&1; then ok "$_chk_msg"; return 0
  else fail "$_chk_msg"; return 1; fi
}
check_bool() {
  # usage: check_bool "message" 0|1   (0 = ok)
  if [ "$2" -eq 0 ]; then ok "$1"; else fail "$1"; fi
}

die() { err "$*"; exit 1; }

# Print the accumulated failure summary and return non-zero if any failed.
report_failures() {
  printf '\n'
  if [ "$FAIL_COUNT" -gt 0 ]; then
    printf '%sFAILED (%s):%s%s\n' "$C_RED" "$FAIL_COUNT" "$C_RESET" "$FAILURES" >&2
    return 1
  fi
  printf '%sALL CHECKS PASSED%s\n' "$C_GREEN" "$C_RESET"
  return 0
}

ensure_state_dirs() {
  mkdir -p "$STATE_DIR" "$PIDS_DIR" "$EVIDENCE_DIR" "$RENDER_DIR"
}

# ---------------------------------------------------------------------------
# Tooling presence. The CLI never assumes a tool exists; it asks and produces
# an actionable message. `have CMD` is the one-liner used everywhere.
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

require_tools() {
  # usage: require_tools kind kubectl docker
  _rt_missing=""
  for _rt_t in "$@"; do
    if ! have "$_rt_t"; then _rt_missing="${_rt_missing} ${_rt_t}"; fi
  done
  if [ -n "$_rt_missing" ]; then
    err "missing required tool(s):${_rt_missing}"
    err "install them and re-run; see 'demo.sh doctor' for guidance"
    return 1
  fi
  return 0
}

# kubectl / kind wrappers pinned to the demo context+cluster so a stray
# kube-context on the presenter's laptop can never be targeted by accident.
kc()   { kubectl --context "$KIND_CONTEXT" "$@"; }
kcn()  { kubectl --context "$KIND_CONTEXT" -n "$DEMO_NS" "$@"; }
kind_() { kind "$@"; }

cluster_exists() {
  kind get clusters 2>/dev/null | grep -x "$CLUSTER" >/dev/null 2>&1
}
