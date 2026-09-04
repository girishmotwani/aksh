#!/usr/bin/env bash
# cmd/protect.sh — insert aksh into the running baseline. This is the "after".
#
# Two entry points share one core:
#   * cmd_protect — the FINAL step: a deny-by-default policy (only the model
#     host is allowed) PLUS credential custody (the real token is moved into
#     aksh's vault and the agent keeps only a placeholder). The exfil is blocked
#     outright (HTTP 403).
#   * cmd_broker — the MIDDLE step: a policy that ALSO allows the telemetry
#     endpoint but WITHOUT a credential provider, and NO custody. The exfil POST
#     is allowed and reaches the collector, but aksh strips the caller's
#     Authorization and injects nothing, so the credential arrives EMPTY. This
#     showcases aksh's credential-broker boundary: allowed egress still cannot
#     carry a secret to an unbrokered destination.
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
      -h|--help) echo "Usage: demo.sh protect   # insert aksh (deny telemetry + custody)"; return 0 ;;
    esac
  done
  _aksh_insert protect "$PROTECT_MANIFESTS_DIR" 1
}

# cmd_broker — the MIDDLE step: allow telemetry (no credential provider), NO
# custody, so the exfil reaches the collector but with the credential stripped.
cmd_broker() {
  for _b_a in "$@"; do
    case "$_b_a" in
      -h|--help) echo "Usage: demo.sh broker   # insert aksh, allow telemetry but strip the credential"; return 0 ;;
    esac
  done
  _aksh_insert broker "$BROKER_MANIFESTS_DIR" 0
}

# _aksh_insert MODE MANIFESTS_DIR DO_CUSTODY — the shared insertion flow.
_aksh_insert() {
  _ai_mode=$1
  _ai_manifests=$2
  _ai_custody=$3

  require_tools docker kind kubectl openssl || return 1
  ensure_state_dirs
  load_presenter_env

  if ! cluster_exists; then
    die "cluster '$CLUSTER' is not up; run 'demo.sh setup' first"
  fi

  step "${_ai_mode}: build + load native aksh images"
  build_and_load_proxy || return 1
  build_and_load_injector || return 1

  step "${_ai_mode}: pod CA + static broker credential"
  create_pod_ca_secret || return 1
  create_static_token_secret || return 1
  create_model_secret_dummy || return 1
  create_upstream_ca_configmap || return 1

  step "${_ai_mode}: exact controller /32 bypass (never the service CIDR)"
  _protect_refresh_bypass || return 1

  step "${_ai_mode}: install AkshPolicy and protected ModelConfig"
  # The CRD is a prerequisite for the AkshPolicy the manifests carry.
  apply_manifest_if_present "${REPO_ROOT}/test/e2e/manifests/10-crd.yaml" "AkshPolicy CRD" || return 1
  apply_rendered_manifests_dir "$_ai_manifests" "$_ai_mode" || return 1

  _protect_dns=$( kube_dns_ip )
  _protect_bypass=$( controller_bypass_cidr )
  _protect_host=$( capture_host_cgroup_mount ) || {
    fail "unsupported cgroup topology: $( node_cgroup_topology )"
    return 1
  }
  _protect_local=$( capture_local_cgroup_mount ) || return 1

  step "${_ai_mode}: install and wait for the configured Aksh injector"
  install_aksh_injector "${_protect_dns}:53" "$_protect_bypass" "$_protect_host" "$_protect_local" || return 1

  step "${_ai_mode}: opt ONLY agentcon-demo into injection"
  _protect_label_target

  if [ "$_ai_custody" -eq 1 ]; then
    # Custody happens LAST, immediately before the roll, so there is no window in
    # which the agent Secret holds a placeholder while an un-recreated pod still
    # mounts the real token (the mount is subPath and only updates on pod
    # recreation). If anything above fails, the cluster is left at the safe
    # baseline (real token in the agent, no aksh) rather than a half-protected
    # state.
    step "${_ai_mode}: custody — move the real credential into Aksh's vault"
    custody_move_credential_to_aksh || return 1
    # Evict the pre-custody pod NOW (before the rollout) so no pod keeps the real
    # token mounted via subPath. Hard gate: if eviction cannot be confirmed,
    # protect fails rather than risk a pod still holding the real credential.
    _protect_evict_agent_pods || return 1
  else
    # BROKER step: no custody. The agent keeps the real token so the strip is
    # demonstrated on a genuine credential — aksh removes it from the allowed
    # request. Restore the real credential in case a prior 'protect' left the
    # placeholder + vault in place.
    step "${_ai_mode}: restore the agent's real credential (no custody in this step)"
    _broker_restore_agent_credential || return 1
  fi

  step "${_ai_mode}: roll the generated Agent pod so the sidecar is admitted"
  _protect_roll_agent

  step "${_ai_mode}: invariants"
  _protect_invariants "$_ai_custody"

  info ""
  if [ "$_ai_custody" -eq 1 ]; then
    info "aksh is in the path (deny + custody). Run 'demo.sh validate --full' to prove it end-to-end."
  else
    info "aksh is in the path (telemetry ALLOWED, credential stripped). The exfil reaches the collector with an EMPTY credential."
  fi
  report_failures
}

# _broker_restore_agent_credential — ensure the agent holds the REAL credential
# (undo any prior custody swap) and remove the vault, so the broker step shows
# the strip acting on a genuine token. Idempotent.
_broker_restore_agent_credential() {
  kc -n "$AKSH_VAULT_NS" delete secret "$AKSH_VAULT_CRED_SECRET_NAME" --ignore-not-found >/dev/null 2>&1 || true
  create_agent_credential_real || return 1
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
  _pi_custody=${1:-1}
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
  # recreated; assert that eviction actually happened on the live pod. Skipped
  # in the BROKER step, which deliberately keeps the real token so the strip is
  # shown acting on a genuine credential.
  if [ "$_pi_custody" -eq 1 ]; then
    custody_verify_agent_mount
  else
    info "custody: not applied in this step (broker) — the agent keeps the real token; aksh strips it in transit"
  fi
}
