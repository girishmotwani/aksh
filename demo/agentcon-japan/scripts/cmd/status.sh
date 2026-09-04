#!/usr/bin/env bash
# cmd/status.sh — a fast, read-only "where is the demo right now" report. Safe to
# run at any moment on stage; changes nothing.

cmd_status() {
  load_presenter_env
  ensure_state_dirs

  step "status: host"
  info "host arch     : $( detect_host_arch ) ($( uname -s ))"
  if have docker && docker info >/dev/null 2>&1; then
    info "docker engine : reachable, arch $( docker_engine_arch )"
  else
    info "docker engine : NOT reachable"
  fi

  step "status: model credentials"
  if [ -f "$PRESENTER_ENV_FILE" ]; then
    _st_ok=0
    for _st_v in $MODEL_REQUIRED_VARS; do
      eval "_st_val=\${$_st_v:-}"
      if [ -z "${_st_val:-}" ]; then _st_ok=1; fi
    done
    if [ "$_st_ok" -eq 0 ]; then
      info "presenter.env.local: MODEL_NAME=${MODEL_NAME:-unset}, MODEL_API_KEY=$( key_state "${MODEL_API_KEY:-}" )"
    else
      info "presenter.env.local: present but INCOMPLETE (run 'demo.sh doctor')"
    fi
  else
    info "presenter.env.local: MISSING"
  fi

  step "status: cluster"
  if cluster_exists; then
    info "kind cluster  : '${CLUSTER}' UP (node arch $( kind_node_arch ))"
    _status_cluster_detail
  else
    info "kind cluster  : '${CLUSTER}' not present"
  fi

  step "status: port-forwards"
  port_forward_status

  step "status: evidence"
  _st_count=$( list_regular_files "$EVIDENCE_DIR" | count_lines | tr -d ' ' )
  info "evidence files: ${_st_count} under ${EVIDENCE_DIR}"
  return 0
}

_status_cluster_detail() {
  # Namespace + key addresses, read live.
  if kc get ns "$DEMO_NS" >/dev/null 2>&1; then
    info "namespace     : ${DEMO_NS} present"
  else
    info "namespace     : ${DEMO_NS} absent"
    return 0
  fi
  _scd_dns=$( kube_dns_ip )
  _scd_ctrl=$( kagent_controller_ip )
  info "kube-dns IP   : ${_scd_dns:-unknown}"
  info "controller IP : ${_scd_ctrl:-unknown}${_scd_ctrl:+ (bypass ${_scd_ctrl}/32)}"
  if [ -n "$( resolve_in_cluster "$TELEMETRY_HOST" )" ]; then
    info "telemetry DNS : ${TELEMETRY_HOST} -> $( resolve_in_cluster "$TELEMETRY_HOST" )"
  else
    info "telemetry DNS : ${TELEMETRY_HOST} does not resolve in-cluster"
  fi
  # Is aksh in the path anywhere?
  _scd_injected=$( kcn get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.containers[*].name}{"\n"}{end}' 2>/dev/null | grep -c aksh )
  if [ "${_scd_injected:-0}" -gt 0 ]; then
    info "aksh sidecar  : present in ${_scd_injected} pod(s) -> PROTECTED"
  else
    info "aksh sidecar  : not present -> BASELINE (no aksh in path)"
  fi
}
