#!/usr/bin/env bash
# cluster.sh — kind cluster lifecycle + Docker engine architecture handling.
#
# The demo must run on a WSL/Linux amd64 laptop and on an Apple Silicon macOS
# laptop with Docker Desktop (arm64). The images the cluster runs MUST be native
# to the kind node's architecture — you cannot `kind load` an amd64 image and
# run it in an arm64 node (or vice-versa) without emulation the demo does not
# set up. So the presenter always builds native, and only *cross-builds* arm64
# on amd64 as a build-only validation (never loaded/run).

if [ -n "${_AKSH_CLUSTER_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_CLUSTER_SOURCED=1

# docker_engine_arch — the architecture of the Docker ENGINE (the daemon), not
# the client. On Apple Silicon Docker Desktop the client may report x86 under
# Rosetta while the Linux VM is arm64; the node arch follows the engine.
docker_engine_arch() {
  _dea=$( docker version --format '{{.Server.Arch}}' 2>/dev/null )
  case "$_dea" in
    amd64|x86_64) printf 'amd64\n' ;;
    arm64|aarch64) printf 'arm64\n' ;;
    '') detect_host_arch ;;            # daemon unreachable: fall back to host
    *) printf '%s\n' "$_dea" ;;
  esac
}

# kind_node_arch — the architecture reported by the running kind node kernel.
#   Falls back to the docker engine arch when the cluster is not up yet.
kind_node_arch() {
  if cluster_exists; then
    _kna=$( docker exec "$NODE_NAME" uname -m 2>/dev/null )
    case "$_kna" in
      x86_64|amd64) printf 'amd64\n'; return 0 ;;
      aarch64|arm64) printf 'arm64\n'; return 0 ;;
    esac
  fi
  docker_engine_arch
}

# ensure_cluster — create the named kind cluster if absent (idempotent).
ensure_cluster() {
  if cluster_exists; then
    info "reusing existing kind cluster '$CLUSTER'"
    return 0
  fi
  step "Creating kind cluster '$CLUSTER'"
  if [ -n "${KIND_CONFIG:-}" ] && [ -f "$KIND_CONFIG" ]; then
    kind create cluster --name "$CLUSTER" --config "$KIND_CONFIG"
  else
    kind create cluster --name "$CLUSTER"
  fi
}

# delete_cluster — remove ONLY the named cluster (never a --all).
delete_cluster() {
  if cluster_exists; then
    step "Deleting kind cluster '$CLUSTER'"
    kind delete cluster --name "$CLUSTER"
  else
    info "cluster '$CLUSTER' not present; nothing to delete"
  fi
}

# node_kernel_release / node_is_cgroup2 — real facts read from the kind node,
# used by `doctor --deep`. Return empty/non-zero rather than guessing.
node_kernel_release() {
  docker exec "$NODE_NAME" uname -r 2>/dev/null
}

# node_cgroup_topology — classify the node's cgroup layout the way the capture
# layer cares about:
#   unified   pure cgroup v2 (only cgroup2 on /sys/fs/cgroup)  -> best
#   hybrid    cgroup v1 tree with a cgroup2 mount at .../unified
#   v1        legacy cgroup v1 only (capture unsupported)
#   unknown   could not determine
node_cgroup_topology() {
  _nct=$( docker exec "$NODE_NAME" sh -c '
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
      echo unified
    elif [ -d /sys/fs/cgroup/unified ]; then
      echo hybrid
    elif [ -d /sys/fs/cgroup/memory ] || [ -d /sys/fs/cgroup/cpu ]; then
      echo v1
    else
      echo unknown
    fi' 2>/dev/null )
  [ -n "$_nct" ] && printf '%s\n' "$_nct" || printf 'unknown\n'
}

# capture_host_cgroup_mount / capture_local_cgroup_mount return the paths that
# must be stamped into the injected proxy for the node's actual cgroup layout.
# The hostPath itself is always mounted at /host/sys/fs/cgroup.
capture_host_cgroup_mount() {
  case "$( node_cgroup_topology )" in
    unified) printf '/host/sys/fs/cgroup\n' ;;
    hybrid)  printf '/host/sys/fs/cgroup/unified\n' ;;
    *)       return 1 ;;
  esac
}

capture_local_cgroup_mount() {
  case "$( node_cgroup_topology )" in
    unified) printf '/sys/fs/cgroup\n' ;;
    hybrid)  printf '/host/sys/fs/cgroup/unified\n' ;;
    *)       return 1 ;;
  esac
}
