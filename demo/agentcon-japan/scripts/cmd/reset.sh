#!/usr/bin/env bash
# cmd/reset.sh — return the cluster to BASELINE without destroying it: stop the
# port-forwards, remove aksh from the path (protect manifests + injector +
# policy + labels), restore the baseline model credential + DNS, and VERIFY the
# result. Errors propagate; the command fails (non-zero) unless every teardown
# and every verification actually held.
#
# Safe to run mid-talk if something wedges; leaves a re-runnable baseline.

cmd_reset() {
  for _r_a in "$@"; do
    case "$_r_a" in
      -h|--help) echo "Usage: demo.sh reset   # back to baseline; keep the cluster"; return 0 ;;
    esac
  done
  load_presenter_env
  ensure_state_dirs

  _reset_fail=0

  step "reset: stop port-forwards"
  stop_all_port_forwards

  if ! cluster_exists; then
    info "cluster '$CLUSTER' not present; nothing in-cluster to reset"
    shred_local_secrets
    ok "reset complete (local state only)"
    return 0
  fi

  step "reset: remove aksh from the path"
  _reset_unlabel || _reset_fail=1
  kcn delete akshpolicy agentcon-agent-egress --ignore-not-found >/dev/null 2>&1 || true
  kcn delete rolebinding agentcon-agent-policy-reader --ignore-not-found >/dev/null 2>&1 || true
  kcn delete role agentcon-agent-policy-reader --ignore-not-found >/dev/null 2>&1 || true
  kcn delete secret "$STATIC_TOKEN_SECRET_NAME" --ignore-not-found >/dev/null 2>&1 || true
  kc -n "$AKSH_VAULT_NS" delete secret "$AKSH_VAULT_CRED_SECRET_NAME" --ignore-not-found >/dev/null 2>&1 || true
  if ! create_model_secret_real; then
    fail "reset: could not restore the real baseline model Secret"
    _reset_fail=1
  fi
  if ! create_agent_credential_real; then
    fail "reset: could not restore the baseline agent cloud credential"
    _reset_fail=1
  fi
  if ! apply_rendered_manifests_dir "$BASELINE_MANIFESTS_DIR" baseline-reset >/dev/null; then
    fail "reset: could not re-apply baseline manifests"
    _reset_fail=1
  fi
  # Roll the workloads back to a sidecar-free spec.
  _reset_roll_back || _reset_fail=1

  step "reset: restore CoreDNS to the demo's baseline rewrite"
  # Baseline still needs the telemetry rewrite, so re-apply it rather than the
  # pre-demo original (cleanup does the full original restore).
  if ! coredns_apply_rewrite >/dev/null 2>&1; then
    fail "reset: could not re-apply baseline CoreDNS rewrite"
    _reset_fail=1
  fi

  step "reset: verify the cluster is genuinely back at baseline"
  _reset_verify || _reset_fail=1

  if [ "$_reset_fail" -ne 0 ]; then
    err "reset did NOT fully restore baseline; see failures above"
    return 1
  fi
  ok "reset complete: cluster is back at BASELINE and re-runnable"
  return 0
}

_reset_unlabel() {
  kc label namespace "$DEMO_NS" "${INJECT_LABEL_KEY}-" >/dev/null 2>&1 || true
  info "namespace/${DEMO_NS} removed from injection"
  return 0
}

_reset_roll_back() {
  _rrb_names=$( kcn get deployments -l "$PROTECT_TARGET_SELECTOR" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null )
  _rrb_rc=0
  while IFS= read -r _rrb_d; do
    [ -z "$_rrb_d" ] && continue
    kcn rollout restart deployment "$_rrb_d" >/dev/null 2>&1 || true
    if wait_rollout "$_rrb_d" 240s >/dev/null 2>&1; then
      info "rolled ${_rrb_d} back to a sidecar-free spec"
    else
      fail "reset: rollback rollout of ${_rrb_d} did not complete in 240s"
      _rrb_rc=1
    fi
  done <<EOF
$_rrb_names
EOF
  return $_rrb_rc
}

# _reset_verify — assert the observable facts that define a real baseline.
_reset_verify() {
  _rv_rc=0

  # 1) The opt-in inject label is absent from the namespace.
  _rv_lbl=$( kc get namespace "$DEMO_NS" \
    -o "jsonpath={.metadata.labels['${INJECT_LABEL_KEY}']}" 2>/dev/null )
  if [ -z "$_rv_lbl" ]; then
    ok "verify: namespace inject label is absent"
  else
    fail "verify: namespace still carries ${INJECT_LABEL_KEY}=${_rv_lbl}"
    _rv_rc=1
  fi

  # 2) A new Running agent pod exists and has NO aksh sidecar.
  _rv_pod=$( running_pod_name "$AGENT_SELECTOR" )
  if [ -z "$_rv_pod" ]; then
    fail "verify: no Running agent pod after rollback"
    _rv_rc=1
  else
    if kcn get pod "$_rv_pod" \
        -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null \
        | grep -qx aksh; then
      fail "verify: agent pod ${_rv_pod} still has an aksh sidecar"
      _rv_rc=1
    else
      ok "verify: new agent pod ${_rv_pod} has no aksh sidecar"
    fi
  fi

  # 3) The Aksh-only static credential Secret is gone.
  if kcn get secret "$STATIC_TOKEN_SECRET_NAME" >/dev/null 2>&1; then
    fail "verify: static credential Secret/${STATIC_TOKEN_SECRET_NAME} still present"
    _rv_rc=1
  else
    ok "verify: static credential Secret removed"
  fi

  # 3b) Custody restored: the agent's mounted cloud credential is no longer the
  #     protect-time placeholder (base64 compare only; value never decoded).
  _rv_cred=$( kcn get secret "$AGENT_CRED_SECRET_NAME" -o "jsonpath={.data.${AGENT_CRED_KEY}}" 2>/dev/null )
  _rv_ph=$( printf '%s' "$CRED_PLACEHOLDER" | b64_encode )
  if [ -z "$_rv_cred" ]; then
    fail "verify: agent credential Secret/${AGENT_CRED_SECRET_NAME} missing"
    _rv_rc=1
  elif [ "$_rv_cred" = "$_rv_ph" ]; then
    fail "verify: agent credential still holds the custody placeholder"
    _rv_rc=1
  else
    ok "verify: agent cloud credential restored (placeholder cleared)"
  fi
  if kc -n "$AKSH_VAULT_NS" get secret "$AKSH_VAULT_CRED_SECRET_NAME" >/dev/null 2>&1; then
    fail "verify: Aksh custody vault Secret still present after reset"
    _rv_rc=1
  else
    ok "verify: Aksh custody vault Secret removed"
  fi

  # 4) The baseline model Secret holds the REAL key again — proven by comparing
  #    base64 encodings only (the real key is never decoded/printed).
  _rv_cur=$( kcn get secret "$MODEL_SECRET_NAME" -o "jsonpath={.data.MODEL_API_KEY}" 2>/dev/null )
  _rv_expected=$( printf '%s' "$MODEL_API_KEY" | b64_encode )
  if [ -z "$_rv_cur" ]; then
    fail "verify: model Secret/${MODEL_SECRET_NAME} missing MODEL_API_KEY"
    _rv_rc=1
  elif [ "$_rv_cur" != "$_rv_expected" ]; then
    fail "verify: model Secret does not match the presenter key"
    _rv_rc=1
  else
    ok "verify: baseline model Secret holds the real key (placeholder cleared)"
  fi

  # 5) DNS still works: the telemetry host resolves A-only via kube-dns.
  if invariant_a_only "$TELEMETRY_HOST"; then
    ok "verify: ${TELEMETRY_HOST} resolves A-only in-cluster"
  else
    fail "verify: ${TELEMETRY_HOST} does not resolve A-only after reset"
    _rv_rc=1
  fi

  return $_rv_rc
}
