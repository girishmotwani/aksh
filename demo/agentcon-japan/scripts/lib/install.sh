#!/usr/bin/env bash
# install.sh — render/install the pinned kagent control plane and Aksh injector.

if [ -n "${_AKSH_INSTALL_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_INSTALL_SOURCED=1

helm_template_to_file() {
  _htf_out=$1
  shift
  docker run --rm \
    -v "${REPO_ROOT}:/repo:ro" \
    -w /repo \
    "$HELM_IMAGE" "$@" > "$_htf_out"
}

install_kagent() {
  # Immutable pin. kagent 0.10.x is a breaking rearchitecture; the demo's
  # manifests, values and selectors are written against 0.9.12 only.
  if [ "${KAGENT_VERSION}" != "${KAGENT_VERSION_PINNED}" ]; then
    fail "KAGENT_VERSION is pinned to ${KAGENT_VERSION_PINNED} (got '${KAGENT_VERSION}'); refusing — 0.10.x is a breaking rearchitecture"
    return 1
  fi
  ensure_state_dirs
  ensure_namespace "$KAGENT_NS"
  _ik_dir="${RENDER_DIR}/kagent"
  mkdir -p "$_ik_dir"

  step "Rendering kagent ${KAGENT_VERSION}"
  helm_template_to_file "${_ik_dir}/crds.yaml" \
    template kagent-crds \
    oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
    --version "$KAGENT_VERSION" --namespace "$KAGENT_NS" || return 1
  helm_template_to_file "${_ik_dir}/kagent.yaml" \
    template kagent \
    oci://ghcr.io/kagent-dev/kagent/helm/kagent \
    --version "$KAGENT_VERSION" --namespace "$KAGENT_NS" \
    --values /repo/demo/agentcon-japan/values-demo.yaml || return 1

  apply_server_side "${_ik_dir}/crds.yaml" || return 1

  # The chart-generated default ModelConfig references this Secret even though
  # the demo Agent uses its own ModelConfig in agentcon-demo.
  kc -n "$KAGENT_NS" create secret generic kagent-openai \
    --from-literal=OPENAI_API_KEY=sk-unused-demo-placeholder \
    --dry-run=client -o yaml | kc apply -f - >/dev/null || return 1

  kc apply -f "${_ik_dir}/kagent.yaml" >/dev/null || return 1
  wait_rollout_ns "$KAGENT_NS" kagent-controller 300s || return 1
  wait_rollout_ns "$KAGENT_NS" kagent-ui 300s || return 1
}

render_injector_values() {
  _riv_dns=$1
  _riv_bypass=$2
  _riv_host=$3
  _riv_local=$4
  _riv_out=$5
  cat > "$_riv_out" <<EOF
namespace: aksh-system
createNamespace: true
injector:
  image:
    repository: aksh-injector
    tag: agentcon
    pullPolicy: IfNotPresent
proxyImage: aksh-proxy:agentcon
runtimeProfile:
  entra:
    tenantId: "11111111-1111-1111-1111-111111111111"
    clientId: "22222222-2222-2222-2222-222222222222"
    authority: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111"
  cgroup:
    hostMount: "${_riv_host}"
    localMount: "${_riv_local}"
  capture:
    dnsServer: "${_riv_dns}"
    bypassCidrs: "${_riv_bypass}"
  ca:
    secretName: ${POD_CA_PRIVATE_SECRET_NAME}
    certKey: ca-cert.pem
    privateKeyKey: ca-key.pem
    publicCertKey: ca-cert.pem
  staticToken:
    secretName: ${STATIC_TOKEN_SECRET_NAME}
    secretKey: ${STATIC_TOKEN_SECRET_KEY}
  podAttribution: true
webhook:
  injectLabel:
    key: ${INJECT_LABEL_KEY}
    value: ${INJECT_LABEL_VALUE}
EOF
}

install_aksh_injector() {
  _iai_dns=$1
  _iai_bypass=$2
  _iai_host=$3
  _iai_local=$4
  ensure_state_dirs
  _iai_dir="${RENDER_DIR}/aksh-injector"
  mkdir -p "$_iai_dir"
  render_injector_values "$_iai_dns" "$_iai_bypass" "$_iai_host" "$_iai_local" "${_iai_dir}/values.yaml"

  step "Rendering Aksh injector"
  helm_template_to_file "${_iai_dir}/aksh-injector.yaml" \
    template aksh /repo/deploy/helm/aksh-injector \
    --namespace aksh-system \
    --values /repo/demo/agentcon-japan/.state/render/aksh-injector/values.yaml || return 1
  kc apply -f "${_iai_dir}/aksh-injector.yaml" >/dev/null || return 1
  # Applying the rendered manifest resets both webhook configs' caBundle to ""
  # (the chart ships it empty; the injector patches it at runtime). On a fresh
  # install the new pod patches it during startup before becoming Ready, but on
  # an idempotent RE-RUN the Deployment spec is unchanged, so no rollout occurs
  # and the running pod keeps serving while the caBundle is transiently empty —
  # a window in which pod admission fails with "unknown authority". Force a
  # restart so the pod that ends up Ready has freshly re-patched the caBundle
  # (the injector's readiness gates on caBundle consistency), closing the race
  # before we label the namespace and roll the agent.
  kc -n aksh-system rollout restart deployment aksh-injector >/dev/null 2>&1 || true
  wait_rollout_ns aksh-system aksh-injector 240s || return 1
  wait_injector_webhook_ready 120 || return 1
}

# wait_injector_webhook_ready — block until every aksh-injector pod reports
# Ready. The injector's readiness probe passes only when both webhook
# configurations carry its current CA bundle, so this also gates on caBundle
# consistency (which a plain rollout-status can miss when a re-apply resets the
# caBundle without changing the Deployment).
wait_injector_webhook_ready() {
  _wiwr_deadline=$(( $( date +%s ) + ${1:-120} ))
  while [ "$( date +%s )" -lt "$_wiwr_deadline" ]; do
    _wiwr_states=$( kc -n aksh-system get pods -l app.kubernetes.io/name=aksh-injector \
      -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null )
    if [ -n "$_wiwr_states" ] \
       && ! printf '%s\n' "$_wiwr_states" | grep -q "False" \
       && printf '%s\n' "$_wiwr_states" | grep -q "True"; then
      ok "aksh injector Ready (webhook caBundle consistent)"
      return 0
    fi
    sleep 3
  done
  fail "aksh injector did not report Ready in time (webhook caBundle may be inconsistent)"
  return 1
}
