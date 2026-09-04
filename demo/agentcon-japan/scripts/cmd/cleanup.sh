#!/usr/bin/env bash
# cmd/cleanup.sh — tear the demo all the way down: stop port-forwards, delete the
# named kind cluster, and only THEN shred local secret material. Only ever
# touches the named cluster — never --all.
#
# Safety contract (council finding #8):
#   * recovery material (the ephemeral pod CA on disk and the CoreDNS backup) is
#     PRESERVED until the cluster deletion is verified, so a failed delete leaves
#     a recoverable state;
#   * cleanup NEVER claims success if the CoreDNS restore or the cluster deletion
#     fails — it returns non-zero and says what to do.

cmd_cleanup() {
  _c_keep_state=1
  for _c_a in "$@"; do
    case "$_c_a" in
      --keep-evidence) _c_keep_state=0 ;;
      -h|--help) echo "Usage: demo.sh cleanup [--keep-evidence]"; return 0 ;;
    esac
  done
  load_presenter_env
  ensure_state_dirs

  _cleanup_fail=0

  step "cleanup: stop port-forwards"
  stop_all_port_forwards

  step "cleanup: restore CoreDNS (best-effort, before the cluster goes)"
  if cluster_exists; then
    if ! coredns_restore; then
      fail "cleanup: CoreDNS restore failed"
      _cleanup_fail=1
    fi
  else
    info "cluster not present; no CoreDNS to restore"
  fi

  step "cleanup: delete the named kind cluster"
  delete_cluster || true

  # VERIFY deletion before touching any recovery material.
  if cluster_exists; then
    fail "cluster '${CLUSTER}' still exists after delete; NOT shredding recovery material"
    err  "pod CA and CoreDNS backup are preserved under ${STATE_DIR}; re-run cleanup once Docker/kind can delete the cluster"
    return 1
  fi
  ok "cluster deletion verified: '${CLUSTER}' is gone"

  step "cleanup: shred local secret material (safe now the cluster is gone)"
  shred_local_secrets

  step "cleanup: local state"
  # Remove PID files, rendered artifacts and the (now-moot) CoreDNS backup.
  rm -rf "$PIDS_DIR" "$RENDER_DIR" 2>/dev/null || true
  rm -f "${STATE_DIR}/coredns-configmap.backup.yaml" \
        "${STATE_DIR}/coredns-configmap.backup.cluster-uid" 2>/dev/null || true
  if [ "$_c_keep_state" -eq 1 ] && [ -d "$EVIDENCE_DIR" ]; then
    _c_n=$( list_regular_files "$EVIDENCE_DIR" | count_lines | tr -d ' ' )
    info "kept ${_c_n} evidence file(s) under ${EVIDENCE_DIR}"
  fi

  if [ "$_cleanup_fail" -ne 0 ]; then
    err "cleanup finished with failures (see above); not reporting success"
    return 1
  fi
  ok "cleanup complete: cluster '${CLUSTER}' removed, local secrets shredded"
  return 0
}
