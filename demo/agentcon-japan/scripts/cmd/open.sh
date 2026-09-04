#!/usr/bin/env bash
# cmd/open.sh — expose the demo locally via two kubectl port-forwards, each with
# a PID file and a health wait, then (optionally) open a browser. Idempotent:
# re-running reuses healthy forwards and repairs dead ones.

cmd_open() {
  _o_browser=1  # 1 = do not auto-open
  for _o_a in "$@"; do
    case "$_o_a" in
      --browser) _o_browser=0 ;;
      -h|--help) echo "Usage: demo.sh open [--browser]"; return 0 ;;
    esac
  done

  require_tools kubectl curl || return 1
  ensure_state_dirs
  if ! cluster_exists; then
    die "cluster '$CLUSTER' is not up; run 'demo.sh setup' first"
  fi

  step "open: collector UI/metrics"
  # INTEGRATION: collector Service name/port owned by the collector workstream.
  if kc -n "$COLLECTOR_NS" get svc "$COLLECTOR_SVC" >/dev/null 2>&1; then
    start_port_forward "collector" "$COLLECTOR_NS" "svc/${COLLECTOR_SVC}" "$COLLECTOR_PORT" "$COLLECTOR_LOCAL_PORT" \
      || fail "collector port-forward failed"
  else
    fail "Service/${COLLECTOR_SVC} not found in ${COLLECTOR_NS}"
  fi

  step "open: kagent UI"
  if kc -n "$KAGENT_NS" get svc "$KAGENT_UI_SVC" >/dev/null 2>&1; then
    start_port_forward "kagent-ui" "$KAGENT_NS" "svc/${KAGENT_UI_SVC}" "$KAGENT_UI_PORT" "$KAGENT_UI_LOCAL_PORT" \
      || fail "kagent UI port-forward failed"
  else
    fail "Service/${KAGENT_UI_SVC} not found in ${KAGENT_NS}"
  fi

  if ! curl -fsS -m 10 "http://127.0.0.1:${COLLECTOR_LOCAL_PORT}/healthz" >/dev/null 2>&1; then
    fail "collector UI health check failed through its port-forward"
  fi
  if ! curl -fsS -m 10 "http://127.0.0.1:${KAGENT_UI_LOCAL_PORT}/" >/dev/null 2>&1; then
    fail "kagent UI health check failed through its port-forward"
  fi

  info ""
  info "collector : http://127.0.0.1:${COLLECTOR_LOCAL_PORT}/"
  info "kagent UI : http://127.0.0.1:${KAGENT_UI_LOCAL_PORT}/"

  if [ "$_o_browser" -eq 0 ]; then
    open_browser "http://127.0.0.1:${COLLECTOR_LOCAL_PORT}/"
    open_browser "http://127.0.0.1:${KAGENT_UI_LOCAL_PORT}/"
  else
    info "(pass --browser to auto-open; on WSL/headless the URL is just printed)"
  fi

  report_failures
}
