#!/usr/bin/env bash
# k8s.sh — kubectl helpers: live ClusterIP reads, rollout waits, invariants.
#
# Everything targets the demo context/namespace via the kc/kcn wrappers so a
# stray kube-context can never be hit. No jq dependency: we read exact fields
# with -o jsonpath, which kubectl ships everywhere.

if [ -n "${_AKSH_K8S_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_K8S_SOURCED=1

# svc_cluster_ip NAMESPACE SERVICE — the live ClusterIP, or empty.
svc_cluster_ip() {
  kc -n "$1" get svc "$2" -o jsonpath='{.spec.clusterIP}' 2>/dev/null
}

# kube_dns_ip — the cluster's DNS service ClusterIP (kube-dns).
kube_dns_ip() { svc_cluster_ip kube-system kube-dns; }

# kagent_controller_ip — the kagent controller ClusterIP. The bypass for the
# agent's plaintext control-plane traffic is this address as a /32 — NEVER the
# broad service CIDR, which would also bypass the model traffic under test.
# INTEGRATION: the kagent workstream owns the controller Service name; override
# KAGENT_CONTROLLER_SVC if it differs.
: "${KAGENT_CONTROLLER_SVC:=kagent-controller}"
: "${KAGENT_NS:=${DEMO_NS}}"
kagent_controller_ip() { svc_cluster_ip "$KAGENT_NS" "$KAGENT_CONTROLLER_SVC"; }

# controller_bypass_cidr — the exact /32 the injector/shim must bypass.
controller_bypass_cidr() {
  _cbc=$( kagent_controller_ip )
  [ -n "$_cbc" ] && printf '%s/32\n' "$_cbc"
}

# wait_rollout DEPLOY [TIMEOUT] — wait for a Deployment to finish rolling.
wait_rollout() {
  _wr_deploy=$1
  _wr_to=${2:-240s}
  kcn rollout status deployment "$_wr_deploy" --timeout="$_wr_to"
}

# wait_rollout_ns NAMESPACE DEPLOY [TIMEOUT] — as above, explicit namespace (the
# collector lives in ops-insights, not the demo namespace).
wait_rollout_ns() {
  kc -n "$1" rollout status deployment "$2" --timeout="${3:-240s}"
}

# wait_secret NAME [SECONDS] — poll until a Secret exists (controller-generated
# Agent secrets appear asynchronously). Portable timeout via wait_for.
wait_secret() {
  wait_for "${2:-120}" 3 sh -c "kubectl --context '$KIND_CONTEXT' -n '$DEMO_NS' get secret '$1' -o name 2>/dev/null | grep -q ."
}

# ready_pod_record LABEL_SELECTOR — one non-terminating Ready pod as NAME|IP.
ready_pod_record() {
  kcn get pods -l "$1" --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.status.podIP}{"|"}{.metadata.deletionTimestamp}{"|"}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' 2>/dev/null \
    | awk -F'|' '$2 != "" && $3 == "" && $4 == "True" {print $1 "|" $2; exit}'
}

running_pod_name() { ready_pod_record "$1" | awk -F'|' '{print $1}'; }
running_pod_ip()   { ready_pod_record "$1" | awk -F'|' '{print $2}'; }

# apply_server_side FILE — kagent CRDs exceed the client-side apply annotation
# limit, so server-side apply is required, not a preference.
apply_server_side() {
  kc apply --server-side --force-conflicts -f "$1"
}

ensure_namespace() {
  kc create namespace "$1" --dry-run=client -o yaml | kc apply -f - >/dev/null
}

# ---------------------------------------------------------------------------
# Invariant checks used by `protect` and `validate`. Each returns 0 when the
# invariant holds. They inspect the LIVE cluster, never a cached assumption.
# ---------------------------------------------------------------------------

# invariant_ipv4_loopback POD CONTAINER — the proxy listener binds IPv4
# loopback (127.0.0.1), and IPv6 connects are denied. We assert the listener
# address the proxy logs / its config is a 127.0.0.1:PORT, not [::1] or a
# routable address.
invariant_ipv4_loopback() {
  _iil_pod=$1; _iil_ctr=${2:-aksh}
  _iil_sockets=$( kcn exec "$_iil_pod" -c "$_iil_ctr" -- ss -ltn 2>/dev/null )
  printf '%s\n' "$_iil_sockets" | grep -Eq '127\.0\.0\.1:15001([[:space:]]|$)' || return 1
  printf '%s\n' "$_iil_sockets" | grep -Eq '(\[::1\]|\*|:::):15001([[:space:]]|$)' && return 1
  return 0
}

# invariant_non_1774 POD — the CAPTURED workload container must run as a uid
# other than the proxy uid (1774), because the proxy's own uid is exempt from
# capture. If the app ran as 1774 its egress would silently escape the boundary.
invariant_non_1774() {
  _in_pod=$1
  # Read every container's runAsUser; the proxy container is allowed to be 1774,
  # but at least one NON-proxy container must be captured (uid != 1774).
  _in_uids=$( kcn get pod "$_in_pod" \
    -o jsonpath='{range .spec.containers[*]}{.name}={.securityContext.runAsUser}{"\n"}{end}' 2>/dev/null )
  _in_has_captured=1
  while IFS= read -r _in_row; do
    [ -z "$_in_row" ] && continue
    _in_name=${_in_row%%=*}
    _in_uid=${_in_row#*=}
    case "$_in_name" in
      aksh|aksh-proxy|proxy) continue ;;   # the proxy is meant to be 1774
    esac
    if [ "$_in_uid" != "$PROXY_UID" ]; then
      _in_has_captured=0
    fi
  done <<EOF
$_in_uids
EOF
  return $_in_has_captured
}

# ---------------------------------------------------------------------------
# In-cluster DNS resolution. The kind NODE's getent uses the node's
# /etc/resolv.conf (host/systemd-resolved), NOT kube-dns, so it does not prove
# what a POD sees. These helpers resolve from inside a real pod, whose resolver
# is kube-dns — the resolution path that actually matters for the demo.
# ---------------------------------------------------------------------------

DNS_RESOLVER_FILE="${RENDER_DIR}/dns-resolve.sh"

# _write_dns_resolver — emit a POSIX-sh resolver that prints "A <ip>"/"AAAA <ip>"
# lines. Written to a FILE and fed to the pod over `exec -i ... sh -s` so no
# quoting of the script through kubectl is required (BSD/GNU safe).
_write_dns_resolver() {
  ensure_state_dirs
  cat > "$DNS_RESOLVER_FILE" <<'RESOLVER'
#!/bin/sh
# $1 = hostname to resolve. Tries glibc getent, then python3, then nslookup.
H="$1"
if command -v getent >/dev/null 2>&1; then
  getent ahostsv4 "$H" 2>/dev/null | awk '{print "A " $1}' | sort -u
  getent ahostsv6 "$H" 2>/dev/null | grep -v '::ffff:' | awk '$1 ~ /:/ {print "AAAA " $1}' | sort -u
elif command -v python3 >/dev/null 2>&1; then
  python3 - "$H" <<'PY'
import socket, sys
host = sys.argv[1]
for family, tag in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
    try:
        for rec in socket.getaddrinfo(host, None, family):
            print(tag, rec[4][0])
    except Exception:
        pass
PY
elif command -v nslookup >/dev/null 2>&1; then
  nslookup -type=A "$H" 2>/dev/null | awk '/^Address: / {print "A " $2}'
  nslookup -type=AAAA "$H" 2>/dev/null | awk '/^Address: / {print "AAAA " $2}'
fi
RESOLVER
}

# dns_probe_pod — a Running pod in the demo namespace whose resolver is kube-dns.
# Prefers the agent pod (the very client whose egress the demo captures).
dns_probe_pod() {
  _dpp=$( running_pod_name "$AGENT_SELECTOR" )
  if [ -n "$_dpp" ]; then printf '%s\n' "$_dpp"; return 0; fi
  kcn get pods --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# pod_resolve HOST — resolve HOST from inside a real pod (kube-dns). Prints
# "A <ip>" / "AAAA <ip>" lines. Returns 2 if no probe pod is available.
pod_resolve() {
  _pr_host=$1
  _pr_pod=$( dns_probe_pod )
  [ -z "$_pr_pod" ] && return 2
  _write_dns_resolver
  kcn exec -i "$_pr_pod" -c kagent -- sh -s "$_pr_host" < "$DNS_RESOLVER_FILE" 2>/dev/null
}

# invariant_a_only HOST — HOST resolves to an A record and NO AAAA, as seen by a
# real pod via kube-dns. Returns 0 pass, 1 violated, 2 could-not-verify.
invariant_a_only() {
  _iao_out=$( pod_resolve "$1" ) || return 2
  printf '%s\n' "$_iao_out" | grep -q '^A ' || return 1
  printf '%s\n' "$_iao_out" | grep -q '^AAAA ' && return 1
  return 0
}

# resolve_in_cluster HOST — the first IPv4 kube-dns returns for HOST, as seen by
# a real pod (for logging / equality checks).
resolve_in_cluster() {
  pod_resolve "$1" 2>/dev/null | awk '$1 == "A" { print $2; exit }'
}

# ---------------------------------------------------------------------------
# Collector reachability (IP-based, not DNS): setup's fatal readiness gates and
# validate's count checks both use these. The node can reach ClusterIPs.
# ---------------------------------------------------------------------------
collector_ip() { svc_cluster_ip "$COLLECTOR_NS" "$COLLECTOR_SVC"; }

# collector_observer_count — the collector's stored-event count (integer) from
# the HTTP observer, or empty/non-zero if unreachable.
collector_observer_count() {
  _coc_ip=$( collector_ip )
  [ -z "$_coc_ip" ] && return 1
  _coc_body=$( docker exec "$NODE_NAME" curl -s -m 10 \
    "http://${_coc_ip}:${COLLECTOR_PORT}${COLLECTOR_COUNT_PATH}" 2>/dev/null )
  printf '%s' "$_coc_body" | tr -cd '0-9\n' | head -1
}

# collector_ingest_ready — 0 iff the HTTPS ingest listener answers /readyz 200.
collector_ingest_ready() {
  _cir_ip=$( collector_ip )
  [ -z "$_cir_ip" ] && return 1
  _cir_code=$( docker exec "$NODE_NAME" curl -sk -o /dev/null -w '%{http_code}' -m 10 \
    "https://${_cir_ip}:${COLLECTOR_INGEST_PORT}/readyz" 2>/dev/null )
  [ "$_cir_code" = "200" ]
}

# ---------------------------------------------------------------------------
# Protection state + exact pod-cgroup derivation.
# ---------------------------------------------------------------------------

# namespace_is_protected — 0 if the demo namespace is currently protected: the
# opt-in inject label is present OR any pod already carries an aksh sidecar.
namespace_is_protected() {
  _nip_lbl=$( kc get namespace "$DEMO_NS" \
    -o "jsonpath={.metadata.labels['${INJECT_LABEL_KEY}']}" 2>/dev/null )
  if [ "$_nip_lbl" = "$INJECT_LABEL_VALUE" ]; then return 0; fi
  if kcn get pods -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.name}{"\n"}{end}{end}' 2>/dev/null \
     | grep -qx aksh; then return 0; fi
  return 1
}

# derive_pod_cgroup_path POD — the EXACT cgroup2 path on the node for POD, found
# by locating the directory named for the pod UID under the node's cgroup2
# mount. Prints the node-absolute path on success; returns non-zero if the exact
# path cannot be derived (caller must then FAIL, never warn).
derive_pod_cgroup_path() {
  _dpcp_pod=$1
  _dpcp_uid=$( kcn get pod "$_dpcp_pod" -o jsonpath='{.metadata.uid}' 2>/dev/null )
  [ -z "$_dpcp_uid" ] && return 1
  # systemd cgroup driver substitutes '-' with '_' in the slice name; cgroupfs
  # keeps the raw UID. Search for either form.
  _dpcp_uid_us=$( printf '%s' "$_dpcp_uid" | tr '-' '_' )
  case "$( node_cgroup_topology )" in
    unified) _dpcp_mount=/sys/fs/cgroup ;;
    hybrid)  _dpcp_mount=/sys/fs/cgroup/unified ;;
    *)       return 1 ;;
  esac
  _dpcp_path=$( docker exec "$NODE_NAME" sh -c "find '$_dpcp_mount' -type d \\( -name '*pod${_dpcp_uid}*' -o -name '*pod${_dpcp_uid_us}*' \\) 2>/dev/null | head -1" 2>/dev/null )
  [ -z "$_dpcp_path" ] && return 1
  printf '%s\n' "$_dpcp_path"
}

# pod_cgroup_has_procs NODE_PATH — 0 if the derived pod cgroup (or a descendant)
# actually contains process ids, i.e. the workload really lives in that cgroup
# the proxy attached to.
pod_cgroup_has_procs() {
  _pchp_path=$1
  _pchp_n=$( docker exec "$NODE_NAME" sh -c "cat '$_pchp_path'/cgroup.procs '$_pchp_path'/*/cgroup.procs 2>/dev/null | grep -c '[0-9]'" 2>/dev/null )
  [ -n "$_pchp_n" ] && [ "$_pchp_n" -gt 0 ] 2>/dev/null
}

# exact_attachment_record EXPECTED_PATH < logs — print the first bounded Aksh
# attach record whose complete fields exactly match the expected pod cgroup.
exact_attachment_record() {
  awk -v expected="$1" '
    /aksh-proxy: eBPF capture attached/ {
      path = id = count = ""
      for (i = 1; i <= NF; i++) {
        split($i, field, "=")
        if (field[1] == "pod_cgroup_path") path = field[2]
        if (field[1] == "cgroup_id") id = field[2]
        if (field[1] == "program_count") count = field[2]
      }
      if (path == expected && id ~ /^[1-9][0-9]*$/ && count ~ /^[1-9][0-9]*$/) {
        print
        exit
      }
    }'
}

# collector_leak_count — how many stored collector events carry a leaked
# credential (a "stolen_credential" field). Read from the node against the
# collector observer; empty on failure.
collector_leak_count() {
  _clc_ip=$( collector_ip )
  [ -z "$_clc_ip" ] && return 1
  docker exec "$NODE_NAME" curl -s -m 10 \
    "http://${_clc_ip}:${COLLECTOR_PORT}/internal/events" 2>/dev/null \
    | grep -o 'stolen_credential' | grep -c 'stolen_credential' || true
}
