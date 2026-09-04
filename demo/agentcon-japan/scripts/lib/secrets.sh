#!/usr/bin/env bash
# secrets.sh — ephemeral pod-CA material and in-cluster Secrets, created WITHOUT
# ever writing a rendered Kubernetes Secret (which would embed the presenter's
# model key in a file on disk / in shell history).
#
# Two rules this module exists to enforce:
#   1. The model API key reaches the cluster ONLY via `kubectl create secret
#      --from-literal ... | kubectl apply -f -` piped over the API — no Secret
#      YAML containing it is ever rendered to a file.
#   2. The pod CA is ephemeral: minted into the gitignored state dir per run,
#      loaded into a Secret, and shredded from disk by reset/cleanup.
#
# The proxy's PKI loader parses the CA key with x509.ParsePKCS8PrivateKey, so
# the key MUST be PKCS#8 — `openssl genpkey` emits PKCS#8 by default.

if [ -n "${_AKSH_SECRETS_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_SECRETS_SOURCED=1

CA_DIR="${STATE_DIR}/pod-ca"
CA_KEY="${CA_DIR}/ca-key.pem"
CA_CERT="${CA_DIR}/ca-cert.pem"

# gen_pod_ca — mint an ephemeral pod CA (PKCS#8 key + self-signed cert) if not
# already present for this run. Idempotent.
gen_pod_ca() {
  require_tools openssl || return 1
  mkdir -p "$CA_DIR"
  chmod 700 "$CA_DIR" 2>/dev/null || true
  if [ -s "$CA_KEY" ] && [ -s "$CA_CERT" ]; then
    _gpca_key_pub=$( openssl pkey -in "$CA_KEY" -pubout 2>/dev/null )
    _gpca_cert_pub=$( openssl x509 -in "$CA_CERT" -pubkey -noout 2>/dev/null )
    _gpca_text=$( openssl x509 -in "$CA_CERT" -noout -text 2>/dev/null )
    if [ -n "$_gpca_key_pub" ] && [ "$_gpca_key_pub" = "$_gpca_cert_pub" ] &&
       openssl x509 -checkend 3600 -noout -in "$CA_CERT" >/dev/null 2>&1 &&
       printf '%s' "$_gpca_text" | grep -q 'CA:TRUE' &&
       printf '%s' "$_gpca_text" | grep -q 'Certificate Sign'; then
      info "reusing validated ephemeral pod CA in $CA_DIR"
      return 0
    fi
    warn "existing pod CA is invalid, mismatched, or expiring; regenerating"
    rm -f "$CA_KEY" "$CA_CERT"
  fi
  step "Minting ephemeral pod CA (PKCS#8)"
  # ECDSA P-256 keeps the material small and is accepted by the loader.
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$CA_KEY" >/dev/null 2>&1 || {
      # Fallback to RSA if the EC params are unavailable on an old openssl.
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CA_KEY" >/dev/null 2>&1
    }
  chmod 600 "$CA_KEY" 2>/dev/null || true
  _gpca_cfg="${CA_DIR}/ca.cnf"
  cat > "$_gpca_cfg" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = aksh-agentcon-pod-ca
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
  openssl req -x509 -new -nodes -key "$CA_KEY" \
    -config "$_gpca_cfg" -days 2 -out "$CA_CERT" >/dev/null 2>&1 || {
      err "failed to self-sign ephemeral pod CA"
      return 1
    }
  ok "ephemeral pod CA ready (valid 2 days, gitignored)"
}

# Split private and public CA material so application containers can trust the
# public certificate without being able to reference the signing key Secret.
create_pod_ca_secret() {
  gen_pod_ca || return 1
  step "Creating private/public pod CA Secrets"
  kc -n "$DEMO_NS" create secret generic "$POD_CA_PRIVATE_SECRET_NAME" \
    --from-file=ca-cert.pem="$CA_CERT" \
    --from-file=ca-key.pem="$CA_KEY" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null || return 1
  kc -n "$DEMO_NS" create secret generic "$POD_CA_PUBLIC_SECRET_NAME" \
    --from-file=ca-cert.pem="$CA_CERT" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null || return 1
  _cpcs_private=$( kcn get secret "$POD_CA_PRIVATE_SECRET_NAME" -o jsonpath='{.data.ca-cert\.pem}' 2>/dev/null )
  _cpcs_public=$( kcn get secret "$POD_CA_PUBLIC_SECRET_NAME" -o jsonpath='{.data.ca-cert\.pem}' 2>/dev/null )
  _cpcs_key=$( kcn get secret "$POD_CA_PRIVATE_SECRET_NAME" -o jsonpath='{.data.ca-key\.pem}' 2>/dev/null )
  if [ -z "$_cpcs_private" ] || [ "$_cpcs_private" != "$_cpcs_public" ] || [ -z "$_cpcs_key" ]; then
    err "private/public pod CA Secrets are missing or inconsistent"
    return 1
  fi
  ok "private/public pod CA Secrets verified"
}

create_secret_from_stdin() {
  _csfs_name=$1
  _csfs_key=$2
  _csfs_value=$3
  _csfs_manifest=$( printf '%s' "$_csfs_value" | kcn create secret generic "$_csfs_name" \
    --from-file="${_csfs_key}=/dev/stdin" --dry-run=client -o yaml ) || return 1
  printf '%s\n' "$_csfs_manifest" | kcn apply -f - >/dev/null || return 1
  unset _csfs_manifest
}

create_model_secret_real() {
  # Validate presence first so we never create a half-populated secret.
  for _cms_v in $MODEL_REQUIRED_VARS; do
    eval "_cms_val=\${$_cms_v:-}"
    if [ -z "${_cms_val:-}" ]; then
      err "cannot create model secret: $_cms_v is unset (run 'demo.sh doctor')"
      return 1
    fi
  done
  : "${MODEL_ENDPOINT:=$MODEL_ENDPOINT_DEFAULT}"
  step "Creating baseline model Secret/${MODEL_SECRET_NAME}"
  create_secret_from_stdin "$MODEL_SECRET_NAME" MODEL_API_KEY "$MODEL_API_KEY" || return 1
  ok "baseline OpenAI key stored for kagent (no Secret YAML or key argv)"
}

create_model_secret_dummy() {
  step "Replacing kagent's model key with a non-secret placeholder"
  create_secret_from_stdin "$MODEL_SECRET_NAME" MODEL_API_KEY "sk-aksh-managed-placeholder" || return 1
  ok "kagent model key replaced with placeholder"
}

create_static_token_secret() {
  step "Creating Aksh-only OpenAI credential Secret/${STATIC_TOKEN_SECRET_NAME}"
  create_secret_from_stdin "$STATIC_TOKEN_SECRET_NAME" "$STATIC_TOKEN_SECRET_KEY" "$MODEL_API_KEY" || return 1
  ok "Aksh-only OpenAI credential stored"
}

create_upstream_ca_configmap() {
  kcn create configmap upstream-ca --dry-run=client -o yaml | kcn apply -f - >/dev/null
}

# shred_local_secrets — remove ephemeral CA material from disk.
shred_local_secrets() {
  if [ -d "$CA_DIR" ]; then
    rm -f "$CA_KEY" "$CA_CERT" 2>/dev/null || true
    rmdir "$CA_DIR" 2>/dev/null || true
    info "removed ephemeral pod CA material from disk"
  fi
  if [ -d "$COLLECTOR_TLS_DIR" ]; then
    rm -f "${COLLECTOR_TLS_DIR}"/* 2>/dev/null || true
    rmdir "$COLLECTOR_TLS_DIR" 2>/dev/null || true
  fi
  shred_cloud_credential
}

# ---------------------------------------------------------------------------
# collector-tls: the HTTPS ingest leaf for the telemetry collector. Per
# manifests/collector.yaml the DEMO SCRIPT owns this Secret's creation so no key
# material lives in source control, and so the leaf's CN/SAN is exactly the
# telemetry host the agent dials — that is what makes the SNI aksh captures the
# same SNI a real exfil would present.
# ---------------------------------------------------------------------------
COLLECTOR_TLS_DIR="${STATE_DIR}/collector-tls"
COLLECTOR_TLS_KEY="${COLLECTOR_TLS_DIR}/tls.key"
COLLECTOR_TLS_CERT="${COLLECTOR_TLS_DIR}/tls.crt"

gen_collector_tls() {
  require_tools openssl || return 1
  gen_pod_ca || return 1
  mkdir -p "$COLLECTOR_TLS_DIR"
  chmod 700 "$COLLECTOR_TLS_DIR" 2>/dev/null || true
  if [ -s "$COLLECTOR_TLS_KEY" ] && [ -s "$COLLECTOR_TLS_CERT" ]; then
    if openssl verify -CAfile "$CA_CERT" "$COLLECTOR_TLS_CERT" >/dev/null 2>&1 &&
       openssl x509 -in "$COLLECTOR_TLS_CERT" -noout -text 2>/dev/null | grep -q "DNS:${TELEMETRY_HOST}" &&
       openssl x509 -checkend 3600 -noout -in "$COLLECTOR_TLS_CERT" >/dev/null 2>&1; then
      info "reusing validated collector TLS leaf in $COLLECTOR_TLS_DIR"
      return 0
    fi
    warn "existing collector TLS leaf is invalid or signed by another CA; regenerating"
    rm -f "$COLLECTOR_TLS_KEY" "$COLLECTOR_TLS_CERT"
  fi
  step "Minting ephemeral collector TLS leaf (CN/SAN=${TELEMETRY_HOST})"
  _gct_csr="${COLLECTOR_TLS_DIR}/tls.csr"
  _gct_ext="${COLLECTOR_TLS_DIR}/leaf.ext"
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$TELEMETRY_HOST" > "$_gct_ext"
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$COLLECTOR_TLS_KEY" -out "$_gct_csr" \
    -subj "/CN=${TELEMETRY_HOST}" \
    >/dev/null 2>&1 || return 1
  openssl x509 -req -in "$_gct_csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$COLLECTOR_TLS_CERT" -days 2 -sha256 -extfile "$_gct_ext" \
    >/dev/null 2>&1 || {
      err "failed to sign collector TLS leaf with the demo CA"
      return 1
    }
  chmod 600 "$COLLECTOR_TLS_KEY" 2>/dev/null || true
  ok "collector TLS leaf ready (valid 2 days, gitignored)"
}

create_collector_tls_secret() {
  gen_collector_tls || return 1
  # The namespace is created by manifests/collector.yaml; ensure it exists so
  # the Secret can land even if applied first.
  ensure_namespace "$COLLECTOR_NS"
  step "Creating Secret/collector-tls in ${COLLECTOR_NS} (over the API; no rendered Secret file)"
  kc -n "$COLLECTOR_NS" create secret tls collector-tls \
    --cert="$COLLECTOR_TLS_CERT" --key="$COLLECTOR_TLS_KEY" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null || return 1
  _ccts_expected=$( b64_encode < "$COLLECTOR_TLS_CERT" )
  _ccts_actual=$( kc -n "$COLLECTOR_NS" get secret collector-tls -o jsonpath='{.data.tls\.crt}' 2>/dev/null )
  if [ -z "$_ccts_actual" ] || [ "$_ccts_actual" != "$_ccts_expected" ]; then
    err "collector TLS Secret does not contain the newly signed certificate"
    return 1
  fi
  ok "collector-tls installed (ingest listener can now serve)"
}

# ---------------------------------------------------------------------------
# Cloud credential (the secret a prompt-injected agent exfiltrates).
#
# In the BASELINE this is a REAL Microsoft Entra access token, minted on the
# presenter's machine with `az account get-access-token`. The token is a real,
# signed Entra JWT (aud=cognitiveservices.azure.com) — so a leak is undeniably
# a real credential — but it authenticates nothing sensitive here and expires
# in ~1h. If `az` is unavailable or not logged in, a clearly-synthetic demo
# credential is used instead so the demo still runs.
#
# The token is minted into the gitignored state dir with 600 perms and never
# printed; it reaches the cluster only via `kubectl create secret` over the API.
# ---------------------------------------------------------------------------
CLOUD_CRED_DIR="${STATE_DIR}/cloud-credential"
CLOUD_CRED_FILE="${CLOUD_CRED_DIR}/credential"

# mint_cloud_credential — populate CLOUD_CRED_FILE with a real Entra token when
# possible, else a synthetic marker. Reuses a cached credential within a run,
# but re-mints a real token that has expired (Entra access tokens live ~1h, so a
# rehearsal or a delayed start must not leak a dead token). Never prints the value.
mint_cloud_credential() {
  mkdir -p "$CLOUD_CRED_DIR"; chmod 700 "$CLOUD_CRED_DIR" 2>/dev/null || true
  if [ -s "$CLOUD_CRED_FILE" ]; then
    if _cloud_cred_fresh; then
      info "reusing minted cloud credential for this run"
      return 0
    fi
    info "cached Entra token is expired/near-expiry; re-minting a fresh one"
    rm -f "$CLOUD_CRED_FILE"
  fi
  if have az && az account show >/dev/null 2>&1; then
    step "Minting a REAL Microsoft Entra access token (aud=${AZURE_CRED_RESOURCE})"
    if az account get-access-token --resource "$AZURE_CRED_RESOURCE" \
         --query accessToken -o tsv > "${CLOUD_CRED_FILE}.partial" 2>/dev/null \
       && [ -s "${CLOUD_CRED_FILE}.partial" ]; then
      # Strip any trailing newline az may add.
      tr -d '\n' < "${CLOUD_CRED_FILE}.partial" > "$CLOUD_CRED_FILE"
      rm -f "${CLOUD_CRED_FILE}.partial"
      chmod 600 "$CLOUD_CRED_FILE" 2>/dev/null || true
      _mcc_kind=$( _cloud_cred_kind )
      ok "minted a real Entra token (${_mcc_kind}); it is the credential the agent will hold"
      return 0
    fi
    rm -f "${CLOUD_CRED_FILE}.partial"
    warn "az is present but token minting failed; using a synthetic demo credential"
  else
    warn "az not available/logged in; using a synthetic demo credential (run 'az login' for a real Entra token)"
  fi
  printf '%s' "${CRED_SYNTHETIC_PREFIX}.not-a-real-credential.${RANDOM:-0}${RANDOM:-0}" > "$CLOUD_CRED_FILE"
  chmod 600 "$CLOUD_CRED_FILE" 2>/dev/null || true
  ok "using a synthetic demo credential (no real cloud secret exposed)"
}

# _cloud_cred_kind — classify the cached credential by structure, never by
# value: "synthetic" for the exact synthetic prefix, "entra-jwt" for a
# three-segment JWT, and "unknown" for anything else (e.g. a truncated or
# partially written token). Callers treat "unknown" as unsafe to reuse.
_cloud_cred_kind() {
  _cck=$( cat "$CLOUD_CRED_FILE" 2>/dev/null )
  case "$_cck" in
    "$CRED_SYNTHETIC_PREFIX"*) printf 'synthetic\n' ;;
    *.*.*)                     printf 'entra-jwt\n' ;;
    *)                         printf 'unknown\n' ;;
  esac
}

# _jwt_exp — print the numeric `exp` (epoch seconds) of the cached JWT, or empty
# if the credential is not a decodable JWT. Decodes only the base64url payload
# with openssl (already a required tool); never prints the token or its claims.
_jwt_exp() {
  _je=$( cat "$CLOUD_CRED_FILE" 2>/dev/null )
  case "$_je" in *.*.*) : ;; *) return 0 ;; esac
  _je_payload=${_je#*.}
  _je_payload=${_je_payload%%.*}
  # base64url -> base64, then pad to a multiple of 4.
  _je_payload=$( printf '%s' "$_je_payload" | tr '_-' '/+' )
  case $(( ${#_je_payload} % 4 )) in
    2) _je_payload="${_je_payload}==" ;;
    3) _je_payload="${_je_payload}=" ;;
  esac
  printf '%s' "$_je_payload" | openssl base64 -d -A 2>/dev/null \
    | grep -o '"exp":[0-9]\{1,\}' | head -1 | grep -o '[0-9]\{1,\}'
}

# _cloud_cred_fresh — true only if the cached credential is safe to reuse: the
# synthetic marker (never expires), or a JWT with >5 minutes of life left. It
# FAILS CLOSED: any JWT-shaped credential whose exp cannot be parsed (malformed
# cache, missing/odd exp) is treated as stale and re-minted, so a dead or
# corrupt token is never leaked in place of a live one.
_cloud_cred_fresh() {
  [ "$( _cloud_cred_kind )" = "synthetic" ] && return 0
  _ccf_exp=$( _jwt_exp )
  [ -z "$_ccf_exp" ] && return 1
  _ccf_now=$( date +%s )
  [ "$_ccf_exp" -gt $(( _ccf_now + 300 )) ]
}

# create_agent_credential_real — mount the REAL minted credential into the agent
# (BASELINE: the agent holds the secret and can be tricked into leaking it).
create_agent_credential_real() {
  mint_cloud_credential || return 1
  step "Creating Secret/${AGENT_CRED_SECRET_NAME} (BASELINE: real credential in the agent)"
  create_secret_from_stdin "$AGENT_CRED_SECRET_NAME" "$AGENT_CRED_KEY" "$( cat "$CLOUD_CRED_FILE" )" || return 1
}

# _agent_cred_is_placeholder — true if the agent's mounted credential Secret
# already holds the custody placeholder (base64 compare only; never decoded).
_agent_cred_is_placeholder() {
  _acp_cur=$( kcn get secret "$AGENT_CRED_SECRET_NAME" \
    -o "jsonpath={.data.${AGENT_CRED_KEY}}" 2>/dev/null )
  [ -n "$_acp_cur" ] || return 1
  [ "$_acp_cur" = "$( printf '%s' "$CRED_PLACEHOLDER" | b64_encode )" ]
}

# custody_move_credential_to_aksh — the PROTECT-time custody transition:
#   1. stash the real credential in an Aksh-only vault Secret (aksh-system),
#   2. replace the agent's mounted credential with a non-secret placeholder,
#   3. shred the presenter-local copy so the real token lives ONLY in the vault.
# After this the agent Secret holds only a decoy; the running pod picks up the
# placeholder when protect rolls it (the mount is subPath, so recreation is
# required — custody_verify_agent_mount asserts that on the live pod).
#
# Idempotent and non-destructive: if custody is ALREADY in place (agent holds
# the placeholder and the vault Secret exists), it preserves the existing vault
# rather than re-minting — so a re-run cannot overwrite the real vaulted token
# with a fresh (or synthetic-fallback) one.
custody_move_credential_to_aksh() {
  if _agent_cred_is_placeholder \
     && kc -n "$AKSH_VAULT_NS" get secret "$AKSH_VAULT_CRED_SECRET_NAME" >/dev/null 2>&1; then
    ok "custody already in place; preserving the vaulted credential in ${AKSH_VAULT_NS}/${AKSH_VAULT_CRED_SECRET_NAME}"
    shred_cloud_credential
    return 0
  fi
  mint_cloud_credential || return 1
  step "Custody: moving the real credential out of the agent and into Aksh's vault"
  ensure_namespace "$AKSH_VAULT_NS"
  # Stash the real credential where only Aksh (cluster operator) can read it.
  printf '%s' "$( cat "$CLOUD_CRED_FILE" )" | kc -n "$AKSH_VAULT_NS" create secret generic \
    "$AKSH_VAULT_CRED_SECRET_NAME" --from-file="${AGENT_CRED_KEY}=/dev/stdin" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null || return 1
  # Replace the agent's mounted credential with a placeholder (custody).
  create_secret_from_stdin "$AGENT_CRED_SECRET_NAME" "$AGENT_CRED_KEY" "$CRED_PLACEHOLDER" || return 1
  # The real token now lives only in the vault; drop the presenter-local copy.
  shred_cloud_credential
  ok "the agent now mounts only a placeholder; the real credential is in ${AKSH_VAULT_NS}/${AKSH_VAULT_CRED_SECRET_NAME}"
}

# custody_verify_agent_mount — assert, on the LIVE protected pod, that the
# mounted credential is the placeholder and NOT a real token. The diagnostics
# container is distroless (no shell/coreutils), so it invokes the in-container
# diagnostics-mcp binary's shell-free "credcheck" mode, which prints only a
# structural classification ("placeholder"/"jwt"/"other"/...), never the value.
custody_verify_agent_mount() {
  _cvm_pod=$( running_pod_name "$PROTECT_TARGET_SELECTOR" )
  if [ -z "$_cvm_pod" ]; then
    fail "custody: no running protected pod to verify the credential mount"
    return 1
  fi
  _cvm_kind=$( kcn exec "$_cvm_pod" -c "$MCP_CONTAINER" -- "$MCP_STEAL_BINARY" credcheck 2>/dev/null | tr -d '\r\n' )
  case "$_cvm_kind" in
    placeholder)
      ok "custody: the protected pod mounts only the placeholder (real token evicted from the agent)"
      return 0 ;;
    "")
      fail "custody: could not classify the mounted credential (credcheck produced no output)"
      return 1 ;;
    *)
      fail "custody: the protected pod's mounted credential is '${_cvm_kind}', not the placeholder; the real token may still be in the agent"
      return 1 ;;
  esac
}

# shred_cloud_credential — remove the minted token from local disk.
shred_cloud_credential() {
  if [ -d "$CLOUD_CRED_DIR" ]; then
    rm -f "$CLOUD_CRED_FILE" "${CLOUD_CRED_FILE}.partial" 2>/dev/null || true
    rmdir "$CLOUD_CRED_DIR" 2>/dev/null || true
  fi
}
