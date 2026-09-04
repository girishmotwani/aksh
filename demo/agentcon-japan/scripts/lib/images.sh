#!/usr/bin/env bash
# images.sh — build the aksh images native to the kind node and load them.
#
# The eBPF objects are committed (go:embed), so a plain CGO_ENABLED=0 build is
# enough — no clang at build time. The ONE thing that matters here is the target
# architecture: the binary that runs in the kind node must be built for the
# node's arch, or the eBPF loader/relocations behave unpredictably (and in the
# amd64-node case an arm64 image simply will not exec).

if [ -n "${_AKSH_IMAGES_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_IMAGES_SOURCED=1

# _build_native TAG DOCKERFILE — build DOCKERFILE for the node's native arch.
#   Uses buildx with an explicit --platform when available (deterministic), and
#   falls back to a plain `docker build` (which is native by definition) when
#   buildx is not installed. --load brings the image into the local engine so
#   `kind load` can find it.
_build_native() {
  _bn_tag=$1
  _bn_dockerfile=$2
  _bn_arch=$( kind_node_arch )
  case "$_bn_arch" in
    amd64|arm64) : ;;
    *) err "unsupported node architecture '$_bn_arch' (need amd64 or arm64)"; return 1 ;;
  esac
  step "Building ${_bn_tag} for linux/${_bn_arch}"
  if docker buildx version >/dev/null 2>&1; then
    docker buildx build \
      --platform "linux/${_bn_arch}" \
      -f "$_bn_dockerfile" \
      -t "$_bn_tag" \
      --load \
      "$REPO_ROOT"
  else
    warn "docker buildx not available; using plain build (native arch only)"
    docker build -f "$_bn_dockerfile" -t "$_bn_tag" "$REPO_ROOT"
  fi
}

# _load_into_kind TAG — make the image available to the named cluster's node.
_load_into_kind() {
  step "Loading $1 into kind cluster '$CLUSTER'"
  kind load docker-image "$1" --name "$CLUSTER"
}

build_and_load_proxy() {
  _build_native "$PROXY_IMAGE" "$PROXY_DOCKERFILE" || return 1
  _load_into_kind "$PROXY_IMAGE"
}

build_and_load_injector() {
  _build_native "$INJECTOR_IMAGE" "$INJECTOR_DOCKERFILE" || return 1
  _load_into_kind "$INJECTOR_IMAGE"
}

# _build_native_ctx TAG CONTEXT — build a self-contained demo component (its own
# Go module + Dockerfile) native to the node arch and load it. Used for the
# collector and diagnostics-mcp images, whose build context is their own dir.
_build_native_ctx() {
  _bnc_tag=$1; _bnc_ctx=$2
  if [ ! -f "${_bnc_ctx}/Dockerfile" ]; then
    warn "no Dockerfile in ${_bnc_ctx}; skipping build of ${_bnc_tag}"
    return 2
  fi
  _bnc_arch=$( kind_node_arch )
  step "Building ${_bnc_tag} for linux/${_bnc_arch}"
  if docker buildx version >/dev/null 2>&1; then
    docker buildx build --platform "linux/${_bnc_arch}" -t "$_bnc_tag" --load "$_bnc_ctx"
  else
    docker build -t "$_bnc_tag" "$_bnc_ctx"
  fi
}

build_and_load_collector() {
  _build_native_ctx "$COLLECTOR_IMAGE" "$COLLECTOR_BUILD_CONTEXT" || return $?
  _load_into_kind "$COLLECTOR_IMAGE"
}

build_and_load_mcp() {
  _build_native_ctx "$MCP_IMAGE" "$MCP_BUILD_CONTEXT" || return $?
  _load_into_kind "$MCP_IMAGE"
}

# crossbuild_validate_arm64 — build-only arm64 validation for an amd64 host.
#   This proves the image builds clean for Apple Silicon presenters WITHOUT
#   trying to load/run an arm64 image in an amd64 kind node (which cannot work).
#   On an arm64 host this is a no-op (the native build already covered it).
crossbuild_validate_arm64() {
  _cva_host=$( docker_engine_arch )
  if [ "$_cva_host" = "arm64" ]; then
    info "host engine is arm64; native build already validates arm64"
    return 0
  fi
  if ! docker buildx version >/dev/null 2>&1; then
    warn "docker buildx not available; cannot cross-build linux/arm64 validation"
    return 2
  fi
  step "Cross-building linux/arm64 (validation only; NOT loaded into kind)"
  _cva_rc=0
  # No --load: we only need the build to succeed, not to import an arm64 image
  # into an amd64 engine where it could never run.
  for _cva_spec in \
    "${PROXY_IMAGE}-arm64-validate|${PROXY_DOCKERFILE}|${REPO_ROOT}" \
    "${INJECTOR_IMAGE}-arm64-validate|${INJECTOR_DOCKERFILE}|${REPO_ROOT}" \
    "${COLLECTOR_IMAGE}-arm64-validate|${COLLECTOR_BUILD_CONTEXT}/Dockerfile|${COLLECTOR_BUILD_CONTEXT}" \
    "${MCP_IMAGE}-arm64-validate|${MCP_BUILD_CONTEXT}/Dockerfile|${MCP_BUILD_CONTEXT}"
  do
    _cva_tag=${_cva_spec%%|*}
    _cva_rest=${_cva_spec#*|}
    _cva_df=${_cva_rest%%|*}
    _cva_ctx=${_cva_rest#*|}
    docker buildx build --platform linux/arm64 -f "$_cva_df" -t "$_cva_tag" "$_cva_ctx" || {
      _cva_rc=$?
      break
    }
  done
  if [ "$_cva_rc" -eq 0 ]; then
    ok "linux/arm64 proxy image builds cleanly (Apple Silicon presenters covered)"
  else
    fail "linux/arm64 cross-build failed (exit $_cva_rc)"
  fi
  return $_cva_rc
}

# image_exists_local TAG — is the tag present in the local engine?
image_exists_local() {
  docker image inspect "$1" >/dev/null 2>&1
}
