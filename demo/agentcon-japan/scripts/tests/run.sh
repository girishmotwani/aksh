#!/usr/bin/env bash
# tests/run.sh — lightweight, cluster-free test harness for the presenter CLI.
#
# These tests exercise the PURE, portable helpers (arch detection, path
# resolution, secret redaction/scrubbing, env parsing, kernel comparison, JSON
# escaping) plus a `bash -n` syntax gate over every script. They run anywhere,
# with no docker/kind/kubectl, so CI and a presenter can both trust the CLI
# before stage time.
#
# Bash 3.2-safe; no external test framework.

set -u
_t_self=${BASH_SOURCE[0]}
TESTS_DIR=$( cd "$( dirname "$_t_self" )" && pwd )
DEMO_ROOT=$( cd "$TESTS_DIR/../.." && pwd )
LIB="${DEMO_ROOT}/scripts/lib"
CMD="${DEMO_ROOT}/scripts/cmd"

PASS=0
FAILN=0

_ok()   { PASS=$(( PASS + 1 )); printf '  ok   %s\n' "$1"; }
_bad()  { FAILN=$(( FAILN + 1 )); printf '  FAIL %s\n' "$1"; }

# assert_eq EXPECTED ACTUAL NAME
assert_eq() {
  if [ "$1" = "$2" ]; then _ok "$3"; else _bad "$3 (expected '$1' got '$2')"; fi
}
# assert_contains HAYSTACK NEEDLE NAME
assert_contains() {
  case "$1" in
    *"$2"*) _ok "$3" ;;
    *) _bad "$3 (missing '$2')" ;;
  esac
}
# assert_not_contains HAYSTACK NEEDLE NAME
assert_not_contains() {
  case "$1" in
    *"$2"*) _bad "$3 (unexpectedly contains '$2')" ;;
    *) _ok "$3" ;;
  esac
}
# assert_true CMD... NAME(last arg)
assert_rc0() {
  _ar_name=$1; shift
  if "$@" >/dev/null 2>&1; then _ok "$_ar_name"; else _bad "$_ar_name (rc!=0)"; fi
}
assert_rc_nonzero() {
  _arn_name=$1; shift
  if "$@" >/dev/null 2>&1; then _bad "$_arn_name (rc==0)"; else _ok "$_arn_name"; fi
}

# --------------------------------------------------------------- syntax gate
echo "== syntax: bash -n over every script =="
_syntax_bad=0
for _f in "${DEMO_ROOT}/demo.sh" "${LIB}"/*.sh "${CMD}"/*.sh "${TESTS_DIR}"/*.sh; do
  [ -f "$_f" ] || continue
  if bash -n "$_f" 2>/dev/null; then
    _ok "syntax $( basename "$_f" )"
  else
    _bad "syntax $( basename "$_f" )"
    _syntax_bad=1
  fi
done

# Only source the libs if syntax passed, else sourcing would abort the harness.
if [ "$_syntax_bad" -eq 0 ]; then
  # State dir under the (gitignored) demo .state so tests never litter the repo.
  export STATE_DIR="${DEMO_ROOT}/.state/test-$$"
  . "${LIB}/portable.sh"
  . "${LIB}/common.sh"
  . "${LIB}/env.sh"
  . "${LIB}/evidence.sh"
  . "${LIB}/cluster.sh"
  . "${LIB}/k8s.sh"
  . "${LIB}/manifests.sh"
  . "${CMD}/doctor.sh"

  echo "== portable helpers =="
  # detect_host_arch normalisation (indirectly: it must be amd64|arm64|verbatim)
  _arch=$( detect_host_arch )
  case "$_arch" in
    amd64|arm64) _ok "detect_host_arch returns a supported name ($_arch)" ;;
    *) _ok "detect_host_arch passes through unusual uname ($_arch)" ;;
  esac

  # portable_realpath resolves an existing dir to an absolute path.
  _rp=$( portable_realpath "$LIB" )
  assert_eq "$LIB" "$_rp" "portable_realpath(existing dir) is absolute+correct"

  # json_escape handles quotes and backslashes.
  _je=$( json_escape 'a"b\c' )
  assert_eq 'a\"b\\c' "$_je" "json_escape escapes quote and backslash"

  # uniq_id is unique across two calls.
  _u1=$( uniq_id run ); _u2=$( uniq_id run )
  if [ "$_u1" != "$_u2" ]; then _ok "uniq_id yields distinct ids"; else _bad "uniq_id collided"; fi

  # run_with_timeout returns 124 on timeout, 0 on fast success.
  assert_rc0 "run_with_timeout fast command succeeds" run_with_timeout 5 true
  _rwt_rc=0; run_with_timeout 1 sleep 5 || _rwt_rc=$?
  assert_eq "124" "$_rwt_rc" "run_with_timeout times out with rc 124"

  echo "== env / secrets =="
  # key_state reports only set/unset — never the value, length, or partials.
  assert_eq "set"   "$( key_state 'supersecretkey1234' )" "key_state=set for non-empty"
  assert_eq "unset" "$( key_state '' )"                    "key_state=unset for empty"
  _ks=$( key_state 'supersecretkey1234' )
  assert_not_contains "$_ks" "supersecretkey1234" "key_state never contains the key body"

  # model_host extracts the bare OpenAI host, and defaults to api.openai.com.
  MODEL_ENDPOINT="https://api.openai.com/v1"
  assert_eq "api.openai.com" "$( model_host )" "model_host strips scheme+path (OpenAI)"
  ( unset MODEL_ENDPOINT; assert_eq "api.openai.com" "$( model_host )" "model_host defaults to api.openai.com" )

  # validate_model_env needs only MODEL_API_KEY + MODEL_NAME, never echoes key,
  # and never prints a length or partial characters for the key.
  MODEL_NAME="gpt-5.4-mini"; MODEL_API_KEY="sk-abcd1234efgh5678ijkl"; MODEL_ENDPOINT="https://api.openai.com/v1"
  _vme_out=$( FAIL_COUNT=0; FAILURES=""; validate_model_env 2>&1 )
  assert_not_contains "$_vme_out" "sk-abcd1234efgh5678ijkl" "validate_model_env never prints the key"
  assert_contains "$_vme_out" "MODEL_API_KEY=set" "validate_model_env reports key as set"
  assert_not_contains "$_vme_out" "chars" "validate_model_env never reports a key length"
  MODEL_API_KEY=""
  _vme_out2=$( FAIL_COUNT=0; FAILURES=""; validate_model_env 2>&1 )
  assert_contains "$_vme_out2" "MODEL_API_KEY=unset" "validate_model_env reports unset key"
  _vme_rc=0; ( FAIL_COUNT=0; FAILURES=""; validate_model_env ) >/dev/null 2>&1 || _vme_rc=$?
  if [ "$_vme_rc" -ne 0 ]; then _ok "validate_model_env fails on missing key"; else _bad "validate_model_env passed with empty key"; fi

  echo "== env file parsing (no arbitrary execution) =="
  # A malicious env file must NOT execute commands; only KEY=VALUE is read.
  # Removed keys (MODEL_DEPLOYMENT/MODEL_API_VERSION) must be IGNORED now.
  _envf="${STATE_DIR}/penv"
  mkdir -p "$STATE_DIR"
  {
    echo '# comment'
    echo 'MODEL_NAME=gpt-5.4-mini'
    echo 'EVIL=$(touch '"${STATE_DIR}"'/pwned)'
    echo 'export MODEL_DEPLOYMENT="dep"'
  } > "$_envf"
  ( PRESENTER_ENV_FILE="$_envf"; unset MODEL_NAME MODEL_DEPLOYMENT MODEL_ENDPOINT; load_presenter_env
    printf '%s|%s|%s\n' "${MODEL_NAME:-}" "${MODEL_DEPLOYMENT:-none}" "${MODEL_ENDPOINT:-}" ) > "${STATE_DIR}/envout" 2>/dev/null
  _envout=$( cat "${STATE_DIR}/envout" )
  assert_eq "gpt-5.4-mini|none|https://api.openai.com/v1" "$_envout" "load_presenter_env reads MODEL_NAME, ignores removed keys, defaults endpoint"
  if [ -f "${STATE_DIR}/pwned" ]; then _bad "env file executed a command (SECURITY)"; else _ok "env file did not execute commands"; fi

  echo "== evidence scrubbing =="
  MODEL_API_KEY="verysecretkey0001"
  _scr=$( printf 'line api-key: verysecretkey0001 Authorization: Bearer abcdef1234567890\n' | scrub_secrets )
  assert_not_contains "$_scr" "verysecretkey0001" "scrub_secrets removes the model key"
  assert_not_contains "$_scr" "abcdef1234567890" "scrub_secrets removes bearer token"

  echo "== persisted A2A response evidence is scrubbed (never raw) =="
  # Simulate an A2A response that echoes a secret; evidence_write MUST scrub it
  # before anything reaches disk (the offline chat-evidence path).
  MODEL_API_KEY="sk-a2asecret9999"
  _a2a_raw='{"result":{"parts":[{"text":"debug Authorization: Bearer sk-a2asecret9999 and api-key: sk-a2asecret9999"}]}}'
  _a2a_path=$( printf '%s\n' "$_a2a_raw" | evidence_write "unit-a2a.txt" )
  _a2a_disk=$( cat "$_a2a_path" )
  assert_not_contains "$_a2a_disk" "sk-a2asecret9999" "persisted A2A evidence never contains the key on disk"
  assert_contains "$_a2a_disk" "REDACTED" "persisted A2A evidence shows a redaction marker"

  echo "== kernel comparison =="
  assert_rc0        "kernel 5.15 is >= 5.15" _doctor_kernel_ge_515 "5.15.0-generic"
  assert_rc0        "kernel 6.1 is >= 5.15"  _doctor_kernel_ge_515 "6.1.0"
  assert_rc_nonzero "kernel 5.4 is <  5.15"  _doctor_kernel_ge_515 "5.4.0-1000"
  assert_rc_nonzero "kernel 4.19 is < 5.15"  _doctor_kernel_ge_515 "4.19.0"

  echo "== integrated contract defaults =="
  assert_eq "kagent" "$KAGENT_NS" "kagent control plane stays outside protected namespace"
  assert_eq "enabled" "$INJECT_LABEL_VALUE" "namespace opt-in label matches webhook default"
  assert_eq "kagent=agentcon-agent" "$AGENT_SELECTOR" "agent selector matches kagent-generated pods"
  assert_eq "diagnostics-mcp:agentcon" "$MCP_IMAGE" "MCP image tag matches Agent manifest"
  assert_eq "0.9.12" "$KAGENT_VERSION_PINNED" "kagent version is pinned to 0.9.12"
  assert_eq "/api/v1/cluster-diagnostics" "$DIAG_PATH" "diagnostic exfil path constant is exact"

  echo "== item 12: fixed-policy endpoint rejection =="
  MODEL_NAME="gpt-5.4-mini"; MODEL_API_KEY="sk-abcdefgh12345678"
  MODEL_ENDPOINT="https://api.openai.com/v1"
  _ep_ok=0; ( FAIL_COUNT=0; FAILURES=""; validate_model_env ) >/dev/null 2>&1 || _ep_ok=$?
  assert_eq "0" "$_ep_ok" "default OpenAI endpoint is accepted"
  MODEL_ENDPOINT="https://api.openai.com/v2"
  _ep_bad=0; ( FAIL_COUNT=0; FAILURES=""; validate_model_env ) >/dev/null 2>&1 || _ep_bad=$?
  assert_rc_nonzero "non-default endpoint rejected (fixed policy)" test "$_ep_bad" -eq 0
  _ep_out=$( MODEL_ENDPOINT="https://evil.example/v1"; FAIL_COUNT=0; FAILURES=""; validate_model_env 2>&1 )
  assert_contains "$_ep_out" "must be https://api.openai.com/v1" "endpoint rejection message is actionable"
  MODEL_ENDPOINT="https://api.openai.com/v1"

  echo "== item 9: port-forward ownership arg matching =="
  . "${LIB}/portforward.sh"
  _pf_test_ctx=$KIND_CONTEXT
  KIND_CONTEXT=kind-x
  assert_rc0        "argline matches our port-forward spec" \
    _pf_argline_matches "kubectl --context kind-x -n ns port-forward svc/telemetry 18080:80 --address 127.0.0.1" 18080 80 svc/telemetry ns
  assert_rc_nonzero "argline rejects a foreign process on the same port" \
    _pf_argline_matches "/usr/bin/python -m http.server 18080" 18080 80 svc/telemetry ns
  assert_rc_nonzero "argline rejects a port-forward for a different port" \
    _pf_argline_matches "kubectl --context kind-x -n ns port-forward svc/x 19999:80" 18080 80 svc/telemetry ns
  assert_rc_nonzero "argline rejects a different target on the same port" \
    _pf_argline_matches "kubectl --context kind-x -n ns port-forward svc/other 18080:80" 18080 80 svc/telemetry ns
  assert_rc_nonzero "argline rejects target and port substring collisions" \
    _pf_argline_matches "kubectl --context kind-x -n ns port-forward svc/telemetry-shadow 118080:80 --address 127.0.0.1" 18080 80 svc/telemetry ns
  assert_rc_nonzero "argline rejects a foreign executable containing kubectl tokens" \
    _pf_argline_matches "python worker.py kubectl --context kind-x -n ns port-forward svc/telemetry 18080:80 --address 127.0.0.1" 18080 80 svc/telemetry ns
  assert_rc_nonzero "argline rejects conflicting duplicate context options" \
    _pf_argline_matches "kubectl --context kind-x -n ns port-forward svc/telemetry 18080:80 --address 127.0.0.1 --context kind-other" 18080 80 svc/telemetry ns
  KIND_CONTEXT=$_pf_test_ctx

  echo "== item 1: --model curl config keeps the key off argv =="
  # The readiness request must build an Authorization header on stdin (curl
  # --config -), never as a -H argument. Assert the source does exactly that.
  _vsrc=$( cat "${CMD}/validate.sh" )
  assert_contains "$_vsrc" "curl -sS --http1.1 --config -" "validate --model uses curl --config from stdin"
  assert_not_contains "$_vsrc" '-H "Authorization: Bearer ${MODEL_API_KEY}"' "the key is not passed via -H on argv"

  . "${CMD}/validate.sh"
  _fakebin="${STATE_DIR}/fakebin"
  mkdir -p "$_fakebin"
  cat > "${_fakebin}/curl" <<'FAKECURL'
#!/bin/sh
cat > "$CURL_CAPTURE_FILE"
out=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then shift; out=$1; fi
  shift
done
printf '%s\n' '{"choices":[{"message":{"content":"MODEL-READY"}}]}' > "$out"
printf '200'
FAKECURL
  chmod +x "${_fakebin}/curl"
  CURL_CAPTURE_FILE="${STATE_DIR}/curl-config"
  export CURL_CAPTURE_FILE
  _old_path=$PATH
  PATH="${_fakebin}:$PATH"
  MODEL_API_KEY="sk-test-readiness-key"
  MODEL_NAME="gpt-5.4-mini"
  MODEL_ENDPOINT="https://api.openai.com/v1"
  ( FAIL_COUNT=0; FAILURES=""; _validate_model ) >/dev/null 2>&1
  PATH=$_old_path
  _curl_cfg=$( cat "$CURL_CAPTURE_FILE" )
  assert_contains "$_curl_cfg" "sk-test-readiness-key" "curl stdin config contains the actual key value"

  echo "== item 13: evidence --live-deny endpoint (model-free contingency) =="
  . "${CMD}/evidence.sh"
  TELEMETRY_HOST="telemetry.ops-insights.example"; DIAG_PATH="/api/v1/cluster-diagnostics"
  assert_eq "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics" \
            "$( live_deny_endpoint )" "live_deny_endpoint targets the exact telemetry host + diag path"
  _eusage=$( _evidence_usage )
  assert_contains "$_eusage" "--live-deny" "evidence usage documents the model-free contingency"

  echo "== credential-theft scenario (Entra) =="
  assert_eq "https://telemetry.ops-insights.example/api/v1/cluster-diagnostics" \
            "$( live_steal_endpoint )" "live_steal_endpoint targets the exact telemetry host + diag path"
  assert_contains "$_eusage" "--live-steal" "evidence usage documents the credential-theft contingency"
  assert_contains "$_eusage" "--live-broker" "evidence usage documents the broker (middle-step) contingency"
  assert_eq "agent-cloud-credential" "$AGENT_CRED_SECRET_NAME" "agent credential Secret name is stable"
  assert_eq "aksh-held-cloud-credential" "$AKSH_VAULT_CRED_SECRET_NAME" "Aksh custody vault Secret name is stable"
  assert_contains "$CRED_PLACEHOLDER" "PLACEHOLDER" "custody placeholder is clearly a non-secret marker"
  assert_contains "$MODEL_FAKE_KEY" "FAKE" "model fake key is clearly a non-secret placeholder"
  # _cloud_cred_kind classifies a JWT-shaped value vs a synthetic one.
  . "${LIB}/secrets.sh"
  CLOUD_CRED_FILE="${STATE_DIR}/cctest"; mkdir -p "$STATE_DIR"
  printf '%s' "aaa.bbb.ccc" > "$CLOUD_CRED_FILE"
  assert_eq "entra-jwt" "$( _cloud_cred_kind )" "_cloud_cred_kind detects a JWT-shaped token"
  printf '%s' "DEMO-SYNTHETIC" > "$CLOUD_CRED_FILE"
  assert_eq "unknown" "$( _cloud_cred_kind )" "_cloud_cred_kind treats a truncated/garbage value as unknown"
  assert_rc_nonzero "_cloud_cred_fresh treats an unknown-shape credential as stale" _cloud_cred_fresh
  # The REAL synthetic marker has dots (3 segments) but must NOT be mistaken for
  # a JWT — detection is by prefix, not dot-count.
  printf '%s.not-a-real-credential.42' "$CRED_SYNTHETIC_PREFIX" > "$CLOUD_CRED_FILE"
  assert_eq "synthetic" "$( _cloud_cred_kind )" "_cloud_cred_kind detects the dotted synthetic marker by prefix"
  # A synthetic credential never expires -> always reusable.
  assert_rc0 "_cloud_cred_fresh treats a synthetic credential as fresh" _cloud_cred_fresh
  # _jwt_exp decodes the exp claim; _cloud_cred_fresh gates reuse on it.
  _jwt_with_exp() { # $1 = exp epoch -> writes a header.payload.sig JWT
    _pl=$( printf '{"exp":%s}' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '=' )
    printf 'eyJhbGciOiJSUzI1NiJ9.%s.sig' "$_pl" > "$CLOUD_CRED_FILE"
  }
  _jwt_with_exp 9999999999
  assert_eq "9999999999" "$( _jwt_exp )" "_jwt_exp decodes a far-future exp claim"
  assert_rc0 "_cloud_cred_fresh accepts a token with ample life left" _cloud_cred_fresh
  _jwt_with_exp 1000000000
  assert_rc_nonzero "_cloud_cred_fresh rejects an already-expired token" _cloud_cred_fresh
  # A JWT-shaped credential with NO decodable exp must fail closed (stale).
  _pl_noexp=$( printf '{"aud":"x"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=' )
  printf 'eyJhbGciOiJSUzI1NiJ9.%s.sig' "$_pl_noexp" > "$CLOUD_CRED_FILE"
  assert_rc_nonzero "_cloud_cred_fresh treats a JWT with no exp as stale (fail closed)" _cloud_cred_fresh
  rm -f "$CLOUD_CRED_FILE"
  # The agent manifest binds the exfiltrate_credential tool and mounts the credential.
  _agent_yaml=$( cat "${DEMO_ROOT}/manifests/baseline/40-agent.yaml" )
  assert_contains "$_agent_yaml" "exfiltrate_credential" "agent binds the exfiltrate_credential tool"
  assert_contains "$_agent_yaml" "agent-cloud-credential" "agent mounts the cloud-credential Secret"
  assert_contains "$_agent_yaml" "AKSH_DIAG_CREDENTIAL_PATH" "MCP container is told the credential path"

  echo "== broker (middle) step: allow-telemetry policy =="
  assert_eq "${DEMO_ROOT}/manifests/broker" "$BROKER_MANIFESTS_DIR" "BROKER_MANIFESTS_DIR points at the broker manifests"
  _broker_policy=$( cat "${DEMO_ROOT}/manifests/broker/10-akshpolicy.yaml" )
  assert_contains "$_broker_policy" "telemetry.ops-insights.example" "broker policy allows the telemetry host"
  assert_contains "$_broker_policy" "allow-openai" "broker policy still allows the model host"
  # The telemetry rule must NOT carry a credential provider (so aksh strips + injects nothing).
  assert_not_contains "$( printf '%s' "$_broker_policy" | sed -n '/allow-telemetry/,$p' )" "provider:" "broker telemetry rule has no credential provider"

  echo "== broker-inject step: allow-telemetry WITH a brokered credential =="
  assert_eq "${DEMO_ROOT}/manifests/broker-inject" "$BROKER_INJECT_MANIFESTS_DIR" "BROKER_INJECT_MANIFESTS_DIR points at the broker-inject manifests"
  _bi_policy=$( cat "${DEMO_ROOT}/manifests/broker-inject/10-akshpolicy.yaml" )
  assert_contains "$_bi_policy" "allow-telemetry-brokered" "broker-inject policy has the brokered telemetry rule"
  # The telemetry rule MUST carry a credential provider (so aksh injects, not just strips).
  assert_contains "$( printf '%s' "$_bi_policy" | sed -n '/allow-telemetry/,$p' )" "provider: static" "broker-inject telemetry rule injects a static brokered credential"

  echo "== exact pod-cgroup attachment record =="
  _attach_expected="/host/sys/fs/cgroup/pod123"
  _attach_good='time=x msg="aksh-proxy: eBPF capture attached" pod_cgroup_path=/host/sys/fs/cgroup/pod123 cgroup_id=42 program_count=6'
  _attach_child='time=x msg="aksh-proxy: eBPF capture attached" pod_cgroup_path=/host/sys/fs/cgroup/pod123/child cgroup_id=42 program_count=6'
  assert_contains "$( printf '%s\n' "$_attach_good" | exact_attachment_record "$_attach_expected" )" \
    "pod_cgroup_path=$_attach_expected" "exact cgroup record matches complete path"
  assert_eq "" "$( printf '%s\n' "$_attach_child" | exact_attachment_record "$_attach_expected" )" \
    "cgroup record rejects descendant path prefix"

  echo "== b64_encode (reset secret-restore comparison) =="
  assert_eq "$( printf 'sk-aksh-managed-placeholder' | base64 | tr -d '\n' )" \
            "$( printf 'sk-aksh-managed-placeholder' | b64_encode )" \
            "b64_encode matches kubectl-style single-line base64"

  echo "== CoreDNS A-only rewrite =="
  . "${LIB}/coredns.sh"
  _cf=$( coredns_write_rewrite )
  _cfbody=$( cat "$_cf" )
  assert_contains "$_cfbody" "rewrite name telemetry.ops-insights.example telemetry.ops-insights.svc.cluster.local" "rewrite targets the collector Service FQDN"
  assert_contains "$_cfbody" "template IN AAAA telemetry.ops-insights.example" "AAAA is templated (A-only invariant)"

  echo "== collector TLS leaf (SAN = telemetry host) =="
  . "${LIB}/secrets.sh"
  if command -v openssl >/dev/null 2>&1; then
    if gen_collector_tls >/dev/null 2>&1; then
      _ca_text=$( openssl x509 -in "$CA_CERT" -noout -text 2>/dev/null )
      assert_contains "$_ca_text" "CA:TRUE" "pod CA has CA basic constraint"
      assert_contains "$_ca_text" "Certificate Sign" "pod CA permits certificate signing"
      _san=$( openssl x509 -in "$COLLECTOR_TLS_CERT" -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -1 )
      assert_contains "$_san" "telemetry.ops-insights.example" "collector leaf SAN carries the telemetry host"
      assert_rc0 "collector leaf verifies against the shared demo CA" \
        openssl verify -CAfile "$CA_CERT" "$COLLECTOR_TLS_CERT"
    else
      _bad "gen_collector_tls failed"
    fi
  else
    _ok "openssl absent; skipping collector TLS leaf test"
  fi

  echo "== manifest discovery (flat + subdir) =="
  # The collector.yaml lives flat under manifests/; discovery must find it.
  if manifests_present "${DEMO_ROOT}/manifests"; then
    _ok "flat manifests/ discovery finds collector.yaml"
  else
    _bad "flat manifests/ discovery found nothing (collector.yaml missing?)"
  fi
  MODEL_NAME="gpt-5.4-mini"
  MODEL_ENDPOINT="https://api.openai.com/v1"
  _rendered="${STATE_DIR}/rendered"
  render_manifests_dir "${DEMO_ROOT}/manifests/baseline" "$_rendered"
  _rendered_model=$( cat "${_rendered}/20-modelconfig.yaml" )
  assert_contains "$_rendered_model" "model: \"gpt-5.4-mini\"" "manifest rendering substitutes the model"
  assert_contains "$_rendered_model" "baseUrl: \"https://api.openai.com/v1\"" "manifest rendering substitutes the endpoint"
  assert_not_contains "$_rendered_model" "${MODEL_API_KEY}" "manifest rendering never writes the API key"

  # Clean the test state dir.
  rm -rf "$STATE_DIR" 2>/dev/null || true
fi

echo ""
printf 'TOTAL: %d passed, %d failed\n' "$PASS" "$FAILN"
[ "$FAILN" -eq 0 ] || exit 1
exit 0
