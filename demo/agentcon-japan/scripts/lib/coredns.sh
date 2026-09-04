#!/usr/bin/env bash
# coredns.sh — steer telemetry.ops-insights.example at the in-cluster collector
# with an A-only rewrite, and be able to put CoreDNS back exactly as it was.
#
# Why a whole-Corefile rewrite and not `kubectl get -o jsonpath` round-trip:
# jsonpath flattens the newlines and CoreDNS then crash-loops on "Unexpected
# '}'". So we back up the live ConfigMap verbatim, and restore from that backup.

if [ -n "${_AKSH_COREDNS_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_COREDNS_SOURCED=1

COREDNS_BACKUP="${STATE_DIR}/coredns-configmap.backup.yaml"
COREDNS_BACKUP_UID="${STATE_DIR}/coredns-configmap.backup.cluster-uid"

# _coredns_cluster_uid — a stable identity for the CURRENT cluster (the
# kube-system namespace UID). Empty if the cluster is unreachable.
_coredns_cluster_uid() {
  kc get namespace kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null
}

# coredns_backup — snapshot the live coredns ConfigMap AND record the cluster
# UID it came from, so a stale backup left over from a previous cluster in the
# persistent state dir is never mistaken for a current one. Returns non-zero if
# the live ConfigMap cannot be read (caller MUST abort rather than mutate).
coredns_backup() {
  ensure_state_dirs
  _cb_uid=$( _coredns_cluster_uid )
  if [ -z "$_cb_uid" ]; then
    warn "cannot reach the cluster to snapshot CoreDNS"
    return 1
  fi
  # A backup is only valid if it exists AND was taken from THIS cluster.
  if [ -f "$COREDNS_BACKUP" ] && [ -f "$COREDNS_BACKUP_UID" ] &&
     [ "$( cat "$COREDNS_BACKUP_UID" 2>/dev/null )" = "$_cb_uid" ]; then
    info "current-cluster CoreDNS backup already present; keeping the original"
    return 0
  fi
  if kc -n kube-system get configmap coredns -o yaml > "${COREDNS_BACKUP}.partial" 2>/dev/null; then
    mv -f "${COREDNS_BACKUP}.partial" "$COREDNS_BACKUP"
    printf '%s\n' "$_cb_uid" > "$COREDNS_BACKUP_UID"
    ok "backed up original CoreDNS ConfigMap (cluster ${_cb_uid})"
    return 0
  fi
  rm -f "${COREDNS_BACKUP}.partial"
  warn "could not read CoreDNS ConfigMap to back up"
  return 1
}

# coredns_write_rewrite — render a Corefile that:
#   * rewrites TELEMETRY_HOST -> the collector Service (A resolution), and
#   * answers AAAA for that name with an empty NOERROR so the client is forced
#     onto the IPv4 A record (the "A-only" invariant). The `template` block is
#     evaluated before the rewrite, matching on the original qname.
coredns_write_rewrite() {
  ensure_state_dirs
  _cwr_collector_fqdn="${COLLECTOR_SVC}.${COLLECTOR_NS}.svc.cluster.local"
  _cwr_file="${RENDER_DIR}/Corefile"
  # Note: template must come before kubernetes so the AAAA for the telemetry
  # name is synthesised (empty) rather than NXDOMAIN'd by the k8s plugin.
  cat > "$_cwr_file" <<EOF
.:53 {
    errors
    health {
       lameduck 5s
    }
    ready
    template IN AAAA ${TELEMETRY_HOST} {
       rcode NOERROR
    }
    rewrite name ${TELEMETRY_HOST} ${_cwr_collector_fqdn}
    kubernetes cluster.local in-addr.arpa ip6.arpa {
       pods insecure
       fallthrough in-addr.arpa ip6.arpa
       ttl 30
    }
    prometheus :9153
    forward . /etc/resolv.conf {
       max_concurrent 1000
    }
    cache 30
    loop
    reload
    loadbalance
}
EOF
  printf '%s\n' "$_cwr_file"
}

# coredns_apply_rewrite — back up (ABORT if no current-cluster backup can be
# secured), install the rewrite, restart+wait CoreDNS.
coredns_apply_rewrite() {
  if ! coredns_backup; then
    err "refusing to mutate CoreDNS without a verified current-cluster backup"
    return 1
  fi
  _car_file=$( coredns_write_rewrite )
  step "Rewriting CoreDNS: ${TELEMETRY_HOST} -> ${COLLECTOR_SVC}.${COLLECTOR_NS} (A-only)"
  kc -n kube-system create configmap coredns \
    --from-file=Corefile="$_car_file" --dry-run=client -o yaml \
    | kc apply -f - >/dev/null || return 1
  kc -n kube-system rollout restart deployment coredns || return 1
  kc -n kube-system rollout status deployment coredns --timeout=180s || return 1
}

# coredns_restore — put the original Corefile back from the backup, or (if no
# backup exists) leave CoreDNS alone. Used by reset; cleanup deletes the whole
# cluster so it does not need this.
coredns_restore() {
  if [ ! -f "$COREDNS_BACKUP" ]; then
    info "no CoreDNS backup to restore (nothing changed, or already restored)"
    return 0
  fi
  step "Restoring original CoreDNS ConfigMap"
  if ! kc apply -f "$COREDNS_BACKUP" >/dev/null 2>&1; then
    warn "failed to restore CoreDNS from backup ($COREDNS_BACKUP)"
    return 1
  fi
  if ! kc -n kube-system rollout restart deployment coredns >/dev/null 2>&1 ||
     ! kc -n kube-system rollout status deployment coredns --timeout=180s >/dev/null 2>&1; then
    warn "CoreDNS backup applied but rollout did not complete; preserving backup"
    return 1
  fi
  rm -f "$COREDNS_BACKUP" "$COREDNS_BACKUP_UID"
  ok "CoreDNS restored to its original configuration"
}
