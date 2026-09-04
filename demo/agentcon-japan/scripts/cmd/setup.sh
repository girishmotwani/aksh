#!/usr/bin/env bash
# cmd/setup.sh — stand up the BASELINE demo: a real kagent agent + the collector
# it talks to, with NO aksh in the path yet. This is the "before" state the talk
# opens on; `protect` is the "after".
#
# Idempotent and interruption-safe: every step reuses existing cluster state and
# can be re-run after a Ctrl-C without leaving the demo wedged.

cmd_setup() {
  for _s_a in "$@"; do
    case "$_s_a" in
      -h|--help) echo "Usage: demo.sh setup   # baseline cluster, no aksh"; return 0 ;;
    esac
  done

  require_tools docker kind kubectl openssl || return 1
  ensure_state_dirs

  step "setup: model credentials"
  load_presenter_env
  if ! validate_model_env; then
    die "model credentials invalid/missing; fix presenter.env.local (see 'demo.sh doctor')"
  fi

  step "setup: cluster"
  ensure_cluster
  info "node arch: $( kind_node_arch )"

  # Item 5: never build a baseline on top of a half-protected cluster. If the
  # namespace is already protected, perform a verified reset back to baseline
  # first, and refuse to continue if it is still protected afterwards.
  if namespace_is_protected; then
    warn "namespace ${DEMO_NS} is currently PROTECTED; performing a verified reset to baseline first"
    if ! cmd_reset; then
      die "setup: could not reset the protected namespace to baseline"
    fi
    if namespace_is_protected; then
      die "setup: namespace still protected after reset; aborting to avoid a mixed state"
    fi
    ok "verified reset: namespace is back to baseline"
  fi

  step "setup: build + load demo images (native to the node arch)"
  build_and_load_collector || return 1
  build_and_load_mcp || return 1

  step "setup: pinned kagent control plane + UI"
  install_kagent || return 1

  step "setup: namespaces"
  ensure_namespace "$DEMO_NS"
  ensure_namespace "$COLLECTOR_NS"

  step "setup: shared demo CA and baseline model credential"
  create_pod_ca_secret || return 1
  create_model_secret_real || return 1
  create_agent_credential_real || return 1
  create_upstream_ca_configmap || return 1

  step "setup: render and apply baseline Agent/ModelConfig/MCP manifests"
  apply_rendered_manifests_dir "$BASELINE_MANIFESTS_DIR" baseline || return 1

  step "setup: collector TLS ingest leaf signed by the shared demo CA"
  create_collector_tls_secret || return 1
  apply_manifests_dir "$MANIFESTS_DIR" "collector" || return 1
  kc -n "$COLLECTOR_NS" rollout restart deployment collector >/dev/null 2>&1 || true

  step "setup: steer ${TELEMETRY_HOST} at the in-cluster collector (A-only)"
  if ! coredns_apply_rewrite; then
    fail "CoreDNS rewrite failed; refusing to report a usable baseline"
    return 1
  fi

  step "setup: publish live cluster-assigned addresses"
  _setup_write_net_configmap

  step "setup: wait for baseline workloads"
  _setup_wait_baseline

  step "setup: baseline invariants"
  _setup_baseline_invariants

  info ""
  info "baseline is up. Next: 'demo.sh open' to expose it, or 'demo.sh protect' to insert aksh."
  report_failures
}

# _setup_write_net_configmap — read live kube-dns + kagent-controller ClusterIPs
# and publish them so the injector/shim consume the EXACT controller /32 bypass,
# never the broad service CIDR.
_setup_write_net_configmap() {
  _swnc_dns=$( kube_dns_ip )
  _swnc_ctrl=$( kagent_controller_ip )
  if [ -z "$_swnc_dns" ]; then
    warn "could not read kube-dns ClusterIP; DNS exception will be unset"
  fi
  if [ -z "$_swnc_ctrl" ]; then
    warn "could not read ${KAGENT_CONTROLLER_SVC} ClusterIP yet (controller not up?);"
    warn "protect will re-read it. Bypass left empty for now."
    _swnc_bypass=""
  else
    _swnc_bypass="${_swnc_ctrl}/32"
    ok "controller bypass will be the exact /32: ${_swnc_bypass}"
  fi
  kc -n "$DEMO_NS" create configmap "$NET_CONFIGMAP" \
    --from-literal=dnsServer="${_swnc_dns:+${_swnc_dns}:53}" \
    --from-literal=bypassCIDRs="${_swnc_bypass}" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null
  ok "published ConfigMap/${NET_CONFIGMAP} (dns=${_swnc_dns:-unset} bypass=${_swnc_bypass:-unset})"
}

_setup_wait_baseline() {
  # The collector is fixed baseline infra the demo always needs: its rollout is
  # a FATAL assertion, not a best-effort wait.
  if ! kc -n "$COLLECTOR_NS" get deployment collector >/dev/null 2>&1; then
    fail "collector Deployment not found in ${COLLECTOR_NS} (manifests/collector.yaml not applied?)"
    return 1
  fi
  if wait_rollout_ns "$COLLECTOR_NS" collector 180s >/dev/null 2>&1; then
    ok "rollout complete: ${COLLECTOR_NS}/collector"
  else
    fail "collector did not become Ready in 180s (is Secret/collector-tls present and valid?)"
    return 1
  fi
  if ! wait_secret agentcon-agent 180; then
    fail "kagent controller did not generate Secret/agentcon-agent"
    return 1
  fi
  kcn rollout restart deployment agentcon-agent >/dev/null 2>&1 || true
  if wait_rollout agentcon-agent 300s >/dev/null 2>&1; then
    ok "rollout complete: agentcon-agent"
  else
    fail "agentcon-agent did not become ready in 300s"
    return 1
  fi
}

_setup_baseline_invariants() {
  # The telemetry host resolves A-only to the collector, as seen by a real pod
  # via kube-dns (not the kind node resolver).
  if invariant_a_only "$TELEMETRY_HOST"; then
    _sbi_ip=$( resolve_in_cluster "$TELEMETRY_HOST" )
    ok "invariant: ${TELEMETRY_HOST} resolves A-only in-cluster (${_sbi_ip})"
    # Stronger: the A record must be the collector's ClusterIP.
    _sbi_collector=$( collector_ip )
    if [ -n "$_sbi_collector" ] && [ "$_sbi_ip" = "$_sbi_collector" ]; then
      ok "invariant: ${TELEMETRY_HOST} -> collector ClusterIP (${_sbi_collector})"
    else
      fail "invariant: ${TELEMETRY_HOST} resolves to ${_sbi_ip:-nothing}, not the collector ClusterIP (${_sbi_collector:-unknown})"
    fi
  else
    fail "invariant: ${TELEMETRY_HOST} is not A-only (or does not resolve) from a pod via kube-dns"
  fi

  # Item 6: the collector's HTTPS ingest readiness and HTTP observer count are
  # FATAL assertions — the demo cannot proceed if the exfil target is not live.
  if collector_ingest_ready; then
    ok "invariant: collector HTTPS ingest is ready (/readyz 200 on :${COLLECTOR_INGEST_PORT})"
  else
    fail "invariant: collector HTTPS ingest not ready on :${COLLECTOR_INGEST_PORT} (TLS Secret/leaf wrong?)"
  fi
  _sbi_count=$( collector_observer_count )
  if [ -n "$_sbi_count" ]; then
    ok "invariant: collector observer count reachable (count=${_sbi_count})"
  else
    fail "invariant: collector observer count endpoint unreachable (${COLLECTOR_COUNT_PATH} on :${COLLECTOR_PORT})"
  fi
}
