#!/usr/bin/env bash
# cmd/protect.sh — insert aksh into the running baseline. This is the "after".
#
# It builds/loads the native aksh images, installs the injector + AkshPolicy,
# seeds the ephemeral pod CA, labels ONLY the agentcon-demo workload for
# injection, rolls the generated Agent pod so the sidecar is admitted, and then
# checks the load-bearing invariants: IPv4 loopback listener, A-only telemetry
# resolution, and that the captured workload is a NON-1774 uid.
#
# Idempotent: re-running re-applies desired state and re-checks invariants.

cmd_protect() {
  for _p_a in "$@"; do
    case "$_p_a" in
      -h|--help) echo "Usage: demo.sh protect   # insert aksh into the baseline"; return 0 ;;
    esac
  done

  require_tools docker kind kubectl openssl || return 1
  ensure_state_dirs
  load_presenter_env

  if ! cluster_exists; then
    die "cluster '$CLUSTER' is not up; run 'demo.sh setup' first"
  fi

  step "protect: build + load native aksh images"
  build_and_load_proxy || return 1
  build_and_load_injector || return 1

  step "protect: pod CA + static broker credential"
  create_pod_ca_secret || return 1
  create_static_token_secret || return 1
  create_model_secret_dummy || return 1
  create_upstream_ca_configmap || return 1

  step "protect: exact controller /32 bypass (never the service CIDR)"
  _protect_refresh_bypass || return 1

  step "protect: install AkshPolicy and protected ModelConfig"
  # The CRD is a prerequisite for the AkshPolicy the protect manifests carry.
  apply_manifest_if_present "${REPO_ROOT}/test/e2e/manifests/10-crd.yaml" "AkshPolicy CRD" || return 1
  apply_rendered_manifests_dir "$PROTECT_MANIFESTS_DIR" protect || return 1

  _protect_dns=$( kube_dns_ip )
  _protect_bypass=$( controller_bypass_cidr )
  _protect_host=$( capture_host_cgroup_mount ) || {
    fail "unsupported cgroup topology: $( node_cgroup_topology )"
    return 1
  }
  _protect_local=$( capture_local_cgroup_mount ) || return 1

  step "protect: install and wait for the configured Aksh injector"
  install_aksh_injector "${_protect_dns}:53" "$_protect_bypass" "$_protect_host" "$_protect_local" || return 1

  step "protect: opt ONLY agentcon-demo into injection"
  _protect_label_target

  # Custody happens LAST, immediately before the roll, so there is no window in
  # which the agent Secret holds a placeholder while an un-recreated pod still
  # mounts the real token (the mount is subPath and only updates on pod
  # recreation). If anything above fails, the cluster is left at the safe
  # baseline (real token in the agent, no aksh) rather than a half-protected
  # state.
  step "protect: custody — move the real credential into Aksh's vault"
  custody_move_credential_to_aksh || return 1
  # Evict the pre-custody pod NOW (before the rollout) so no pod keeps the real
  # token mounted via subPath. Hard gate: if eviction cannot be confirmed,
  # protect fails rather than risk a pod still holding the real credential.
  _protect_evict_agent_pods || return 1

  step "protect: roll the generated Agent pod so the sidecar is admitted"
  _protect_roll_agent

  step "protect: invariants"
  _protect_invariants

  info ""
  info "aksh is in the path. Run 'demo.sh validate --full' to prove it end-to-end."
  report_failures
}

# _protect_refresh_bypass — re-read the live controller ClusterIP (it changes
# whenever the cluster is recreated) and update the net ConfigMap with the exact
# /32. Refuses to write a broad CIDR.
_protect_refresh_bypass() {
  _prb_ctrl=$( kagent_controller_ip )
  _prb_dns=$( kube_dns_ip )
  if [ -z "$_prb_ctrl" ]; then
    fail "could not read ${KAGENT_CONTROLLER_SVC} ClusterIP; cannot set the /32 bypass"
    return 1
  fi
  _prb_cidr="${_prb_ctrl}/32"
  # Hard guard: never allow anything wider than a /32 to be published here.
  case "$_prb_cidr" in
    */32) : ;;
    *) fail "refusing non-/32 bypass '$_prb_cidr'"; return 1 ;;
  esac
  kc -n "$DEMO_NS" create configmap "$NET_CONFIGMAP" \
    --from-literal=dnsServer="${_prb_dns:+${_prb_dns}:53}" \
    --from-literal=bypassCIDRs="$_prb_cidr" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null
  ok "bypass set to exact controller /32: ${_prb_cidr}"
}

_protect_label_target() {
  kc label namespace "$DEMO_NS" \
    "${INJECT_LABEL_KEY}=${INJECT_LABEL_VALUE}" --overwrite >/dev/null
  ok "namespace/${DEMO_NS} opted into injection"
}

# _protect_evict_agent_pods — delete the currently-running target pods right
# after the custody swap so no pod keeps mounting the real token (the subPath
# credential mount only refreshes on pod recreation). The Deployment recreates
# them from the same template — now against the placeholder Secret and, since
# the namespace is already labeled, with the aksh sidecar injected.
#
# This is a HARD gate: a failure to list, a failure to delete, or any captured
# pre-custody pod still present afterward returns non-zero so protect fails
# loudly rather than leaving a pod that may still mount the real credential.
_protect_evict_agent_pods() {
  if ! _pep_pods=$( kcn get pods -l "$PROTECT_TARGET_SELECTOR" \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null ); then
    fail "custody: could not list agent pods to evict (cannot confirm the real token is unmounted)"
    return 1
  fi
  # No pods is a valid state (nothing mounts the credential yet).
  if [ -z "$_pep_pods" ]; then
    return 0
  fi
  if ! kcn delete pods -l "$PROTECT_TARGET_SELECTOR" --wait=true >/dev/null 2>&1; then
    fail "custody: could not evict the pre-custody agent pod(s); a pod may still mount the real token"
    return 1
  fi
  # Verify every captured pre-custody pod is actually gone. A newly recreated
  # pod (different name) is fine — it mounts only the placeholder.
  while IFS= read -r _pep_p; do
    [ -z "$_pep_p" ] && continue
    if kcn get pod "$_pep_p" >/dev/null 2>&1; then
      fail "custody: pre-custody pod ${_pep_p} still present after eviction"
      return 1
    fi
  done <<EOF
$_pep_pods
EOF
  ok "evicted the pre-custody agent pod(s); the real token is no longer mounted anywhere"
  return 0
}

_protect_roll_agent() {
  _pra_names=$( kcn get deployments -l "$PROTECT_TARGET_SELECTOR" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null )
  if [ -z "$_pra_names" ]; then
    warn "no target Deployment to roll; skipping"
    return 0
  fi
  while IFS= read -r _pra_d; do
    [ -z "$_pra_d" ] && continue
    kcn rollout restart deployment "$_pra_d" >/dev/null 2>&1 || true
    if wait_rollout "$_pra_d" 240s >/dev/null 2>&1; then
      ok "rolled ${_pra_d} with the aksh sidecar admitted"
    else
      fail "rollout of ${_pra_d} did not complete in 240s"
    fi
  done <<EOF
$_pra_names
EOF
}

_protect_invariants() {
  _pi_pod=$( running_pod_name "$PROTECT_TARGET_SELECTOR" )
  if [ -z "$_pi_pod" ]; then
    fail "no Running protected pod found for '${PROTECT_TARGET_SELECTOR}'"
    return 0
  fi
  info "protected pod: ${_pi_pod}"

  # A-only telemetry resolution still holds.
  if invariant_a_only "$TELEMETRY_HOST"; then
    ok "invariant: ${TELEMETRY_HOST} resolves A-only ($( resolve_in_cluster "$TELEMETRY_HOST" ))"
  else
    fail "invariant: ${TELEMETRY_HOST} is not A-only in-cluster"
  fi

  # The captured workload is a non-1774 uid (proxy uid is exempt from capture).
  if invariant_non_1774 "$_pi_pod"; then
    ok "invariant: a non-1774 workload container is present and therefore captured"
  else
    fail "invariant: every container runs as 1774 (proxy uid) -> nothing is captured"
  fi

  # The proxy listener is IPv4 loopback and IPv6 connects are denied.
  if invariant_ipv4_loopback "$_pi_pod" aksh; then
    ok "invariant: proxy listener is IPv4 loopback (no [::1] bind observed)"
  else
    fail "invariant: proxy appears to bind IPv6 loopback; IPv4-only expected"
  fi

  # The sidecar container is actually present (injection happened).
  _pi_has_aksh=$( kcn get pod "$_pi_pod" \
    -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -x aksh )
  if [ -n "$_pi_has_aksh" ]; then
    ok "invariant: aksh sidecar container was injected"
  else
    fail "invariant: no 'aksh' container in the protected pod (injection did not fire)"
  fi

  # Custody: the recreated pod must mount ONLY the placeholder. Because the
  # credential mount is subPath, the real token is not evicted until the pod is
  # recreated; assert that eviction actually happened on the live pod.
  custody_verify_agent_mount
}
