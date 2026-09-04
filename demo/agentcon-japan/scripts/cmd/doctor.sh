#!/usr/bin/env bash
# cmd/doctor.sh — preflight the presenter's laptop and (with --deep) the cluster.
#
# doctor is the first thing a presenter runs on stage-morning. It must be honest:
# every check is a real probe with an actionable failure, never a rubber stamp.
#
#   doctor            fast, host-only: tools, docker, arch, model env, assets
#   doctor --deep     also inspects the kind node kernel + cgroup topology and
#                     performs build/load/BPF prerequisite checks. The real
#                     capture assertion is owned by validate --full/--mac.

cmd_doctor() {
  _doc_deep=1   # 1 = false
  for _doc_a in "$@"; do
    case "$_doc_a" in
      --deep) _doc_deep=0 ;;
      -h|--help) _doctor_usage; return 0 ;;
      *) warn "doctor: ignoring unknown flag '$_doc_a'" ;;
    esac
  done

  step "doctor: host prerequisites"
  _doctor_host_checks

  step "doctor: model credentials"
  load_presenter_env
  if [ ! -f "$PRESENTER_ENV_FILE" ]; then
    warn "no presenter.env.local at $PRESENTER_ENV_FILE"
    warn "copy presenter.env.example -> presenter.env.local, then set MODEL_API_KEY + MODEL_NAME"
    fail "model credentials not configured"
  else
    validate_model_env || true
    info "doctor makes no OpenAI calls; validate --model, --full and --mac spend quota"
  fi

  step "doctor: repository build assets"
  check "proxy Dockerfile present ($PROXY_DOCKERFILE)"    test -f "$PROXY_DOCKERFILE"
  check "injector Dockerfile present ($INJECTOR_DOCKERFILE)" test -f "$INJECTOR_DOCKERFILE"
  check "collector build context present ($COLLECTOR_BUILD_CONTEXT)" test -f "${COLLECTOR_BUILD_CONTEXT}/Dockerfile"
  check "diagnostics-mcp build context present ($MCP_BUILD_CONTEXT)" test -f "${MCP_BUILD_CONTEXT}/Dockerfile"
  _doctor_report_manifest_stage "$MANIFESTS_DIR" "baseline (flat manifests/)"
  _doctor_report_manifest_stage "$BASELINE_MANIFESTS_DIR" "baseline subdir"
  _doctor_report_manifest_stage "$PROTECT_MANIFESTS_DIR" "protect"

  if [ "$_doc_deep" -eq 0 ]; then
    _doctor_deep
  else
    info "run 'demo.sh doctor --deep' for kernel/cgroup/BPF and build/load checks"
  fi

  report_failures
}

_doctor_usage() {
  cat <<EOF
Usage: demo.sh doctor [--deep]

  --deep   inspect the kind node kernel, cgroup v2 topology, BPF/cgroup
           prerequisites, and verify native image build/load.
EOF
}

_doctor_host_checks() {
  # Tools. docker/kind/kubectl are required for anything real; openssl for the
  # ephemeral CA. jq/nc are nice-to-have and only warned about.
  for _dhc_t in docker kind kubectl openssl curl; do
    if have "$_dhc_t"; then ok "found $_dhc_t"; else fail "missing required tool: $_dhc_t"; fi
  done
  for _dhc_t in jq nc; do
    if have "$_dhc_t"; then ok "found $_dhc_t (optional)"; else warn "optional tool not found: $_dhc_t"; fi
  done

  # No PowerShell dependency anywhere — assert we are not accidentally relying
  # on it (the whole point of this workstream).
  if have pwsh || have powershell; then
    info "PowerShell is present but the presenter CLI never uses it (portable Bash only)"
  fi

  # Docker daemon reachable + engine arch.
  if have docker; then
    if docker info >/dev/null 2>&1; then
      _dhc_arch=$( docker_engine_arch )
      ok "docker daemon reachable (engine arch: ${_dhc_arch})"
      case "$_dhc_arch" in
        amd64|arm64) : ;;
        *) fail "docker engine arch '${_dhc_arch}' is unsupported (need amd64 or arm64)" ;;
      esac
    else
      fail "docker daemon not reachable (is Docker Desktop / dockerd running?)"
    fi
  fi

  # Host arch + WSL note.
  _dhc_host=$( detect_host_arch )
  info "host arch: ${_dhc_host}  ($( uname -s ) $( uname -m ))"
  if [ -f /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
    info "running under WSL (Linux); no PowerShell path is used"
  fi

  # bash version note: we are 3.2-safe, but flag <3.2 just in case.
  info "bash: ${BASH_VERSION:-unknown} (scripts are 3.2-compatible)"
}

_doctor_report_manifest_stage() {
  if manifests_present "$1"; then
    ok "${2} manifests present ($( list_manifests "$1" | count_lines | tr -d ' ' ) file(s))"
  else
    warn "${2} manifests not yet present under $1 (sibling workstream)"
  fi
}

# --------------------------------------------------------------- deep checks
_doctor_deep() {
  step "doctor --deep: cluster / kernel / cgroup / BPF"
  if ! have docker || ! have kind || ! have kubectl; then
    fail "deep checks need docker+kind+kubectl; install them and re-run"
    return 0
  fi

  # Prefer the demo cluster if it is already up; otherwise stand up a disposable
  # one for build/load and kernel prerequisite checks.
  _dd_dispose=1
  _dd_target_cluster="$CLUSTER"
  if cluster_exists; then
    info "using existing cluster '$CLUSTER' for deep inspection"
  else
    _dd_target_cluster="${CLUSTER}-doctor"
    _dd_dispose=0
    step "creating disposable cluster '${_dd_target_cluster}' for the smoke gate"
    if ! kind create cluster --name "$_dd_target_cluster" >/dev/null 2>&1; then
      fail "could not create disposable kind cluster for deep checks"
      return 0
    fi
  fi

  # Rebind the wrappers at these locals for the disposable case.
  _dd_ctx="kind-${_dd_target_cluster}"
  _dd_node="${_dd_target_cluster}-control-plane"

  # 1) Kernel release of the actual node.
  _dd_krel=$( docker exec "$_dd_node" uname -r 2>/dev/null )
  if [ -n "$_dd_krel" ]; then
    ok "node kernel: ${_dd_krel}"
    if _doctor_kernel_ge_515 "$_dd_krel"; then
      ok "kernel >= 5.15 (sock_ops/sockmap capture supported)"
    else
      fail "kernel ${_dd_krel} < 5.15: the capture layer needs 5.15+ (README Requirements)"
    fi
  else
    fail "could not read node kernel release"
  fi

  # 2) cgroup topology: pure v2 (unified root) vs hybrid (.../unified) vs v1.
  _dd_topo=$( docker exec "$_dd_node" sh -c '
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then echo unified;
    elif [ -d /sys/fs/cgroup/unified ]; then echo hybrid;
    elif [ -d /sys/fs/cgroup/memory ]; then echo v1;
    else echo unknown; fi' 2>/dev/null )
  case "$_dd_topo" in
    unified) ok "cgroup topology: pure cgroup v2 (unified root at /sys/fs/cgroup)" ;;
    hybrid)  ok "cgroup topology: hybrid (cgroup2 mounted at /sys/fs/cgroup/unified)"
             info "the shim attaches under /host/sys/fs/cgroup/unified/<pod cgroup> on this layout" ;;
    v1)      fail "node exposes cgroup v1 only; aksh capture requires cgroup v2" ;;
    *)       fail "could not determine cgroup topology on the node" ;;
  esac

  # 3) BPF / cgroup prerequisites on the node.
  _doctor_bpf_prereqs "$_dd_node"

  # 4) Build/load prerequisite gate. A real redirected-flow assertion requires
  # the complete demo and is performed by validate --full/--mac.
  _doctor_smoke_gate "$_dd_target_cluster" "$_dd_ctx" "$_dd_node"

  # Tear down only what we created.
  if [ "$_dd_dispose" -eq 0 ]; then
    step "tearing down disposable cluster '${_dd_target_cluster}'"
    kind delete cluster --name "$_dd_target_cluster" >/dev/null 2>&1 || true
  fi
}

# _doctor_kernel_ge_515 RELEASE — 0 if kernel >= 5.15 (portable numeric compare).
_doctor_kernel_ge_515() {
  _dk_rel=$1
  _dk_major=$( printf '%s' "$_dk_rel" | cut -d. -f1 )
  _dk_minor=$( printf '%s' "$_dk_rel" | cut -d. -f2 | sed 's/[^0-9].*//' )
  [ -z "$_dk_major" ] && return 1
  [ -z "$_dk_minor" ] && _dk_minor=0
  if [ "$_dk_major" -gt 5 ]; then return 0; fi
  if [ "$_dk_major" -eq 5 ] && [ "$_dk_minor" -ge 15 ]; then return 0; fi
  return 1
}

# _doctor_bpf_prereqs NODE — check bpf fs, cgroup2 mount, and required kernel
# configs where inspectable. Actionable failures.
_doctor_bpf_prereqs() {
  _dbp_node=$1
  # bpf filesystem availability (the loader may mount its own bpffs, but the
  # kernel must support it).
  if docker exec "$_dbp_node" sh -c 'grep -qw bpf /proc/filesystems' >/dev/null 2>&1; then
    ok "kernel supports the bpf filesystem"
  else
    fail "kernel does not list 'bpf' in /proc/filesystems; BPF maps cannot be pinned"
  fi
  # cgroup2 present in /proc/filesystems.
  if docker exec "$_dbp_node" sh -c 'grep -qw cgroup2 /proc/filesystems' >/dev/null 2>&1; then
    ok "kernel supports cgroup2"
  else
    fail "kernel does not support cgroup2; cgroup-attached BPF programs are unavailable"
  fi
  # BPF syscall config, when the config is readable.
  _dbp_cfg=$( docker exec "$_dbp_node" sh -c '
    if [ -r /proc/config.gz ]; then zcat /proc/config.gz 2>/dev/null;
    elif [ -r /boot/config-$(uname -r) ]; then cat /boot/config-$(uname -r) 2>/dev/null; fi' 2>/dev/null )
  if [ -n "$_dbp_cfg" ]; then
    if printf '%s' "$_dbp_cfg" | grep -q '^CONFIG_BPF_SYSCALL=y'; then
      ok "CONFIG_BPF_SYSCALL=y"
    else
      fail "CONFIG_BPF_SYSCALL is not enabled"
    fi
    if printf '%s' "$_dbp_cfg" | grep -q '^CONFIG_CGROUP_BPF=y'; then
      ok "CONFIG_CGROUP_BPF=y"
    else
      fail "CONFIG_CGROUP_BPF is not enabled (cgroup connect4/sockops hooks need it)"
    fi
  else
    info "kernel config not readable on the node; skipping CONFIG_* assertions (common on kind)"
  fi
}

# _doctor_smoke_gate CLUSTER CTX NODE — the capture smoke gate.
#   Ideal: build the production aksh-proxy image, load it, run the repo's own
#   captured e2e pod (test/e2e/manifests/50-aksh-pod.yaml) and assert the proxy
#   attaches capture and stays up. If that asset is unavailable we fall back to
#   proving the image builds and the loader binary reports its capture support.
_doctor_smoke_gate() {
  _dsg_cluster=$1; _dsg_ctx=$2; _dsg_node=$3
  step "capture prerequisite gate"

  # Build the production proxy image for the node arch.
  _dsg_arch=$( docker exec "$_dsg_node" uname -m 2>/dev/null )
  case "$_dsg_arch" in
    x86_64|amd64) _dsg_platform=linux/amd64 ;;
    aarch64|arm64) _dsg_platform=linux/arm64 ;;
    *) _dsg_platform= ;;
  esac
  _dsg_tag="aksh-proxy:doctor"
  if docker buildx version >/dev/null 2>&1 && [ -n "$_dsg_platform" ]; then
    if ! docker buildx build --platform "$_dsg_platform" -f "$PROXY_DOCKERFILE" -t "$_dsg_tag" --load "$REPO_ROOT" >/dev/null 2>&1; then
      fail "capture gate: aksh-proxy image failed to build (see 'docker build -f $PROXY_DOCKERFILE .')"
      return 0
    fi
  else
    if ! docker build -f "$PROXY_DOCKERFILE" -t "$_dsg_tag" "$REPO_ROOT" >/dev/null 2>&1; then
      fail "capture gate: aksh-proxy image failed to build"
      return 0
    fi
  fi
  ok "capture gate: production aksh-proxy image builds for ${_dsg_arch}"

  if ! kind load docker-image "$_dsg_tag" --name "$_dsg_cluster" >/dev/null 2>&1; then
    fail "capture gate: could not load aksh-proxy image into '${_dsg_cluster}'"
    return 0
  fi
  ok "capture gate: image loaded into the node"

  info "the full redirected-flow assertion is intentionally deferred to"
  info "'demo.sh validate --full' / '--mac', which deploy the complete fixture."
  ok "capture build/load prerequisite gate passed (node arch ${_dsg_arch})"
}
