#!/usr/bin/env bash
# env.sh — load and validate the presenter's model credentials.
#
# The demo drives a real OpenAI model. Baseline kagent holds the key; protection
# replaces it with a dummy and mounts the real key only into Aksh. The presenter
# credential lives in
# presenter.env.local, which is gitignored and never committed. This module:
#
#   * parses presenter.env.local WITHOUT ever echoing MODEL_API_KEY,
#   * validates the required inputs are present and well-formed,
#   * reports the key only as set/unset — never the value, a fingerprint, a
#     length, or any partial characters.
#
# Presenter inputs:
#   REQUIRED : MODEL_API_KEY (an OpenAI API key), MODEL_NAME (e.g. gpt-5.4-mini)
#   OPTIONAL : MODEL_ENDPOINT (defaults to https://api.openai.com/v1)
#
# A real OpenAI key spends real quota. Keep validation lean: nothing here makes
# a network call, and `validate --full` drives only a small, bounded number of
# real completions. Use free-tier / low-cost keys judiciously.
#
# Bash 3.2 safe. No `source`d file is allowed to run arbitrary side effects we
# do not expect: we parse KEY=VALUE lines ourselves rather than `. file`, so a
# malformed env file cannot execute commands.

if [ -n "${_AKSH_ENV_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_ENV_SOURCED=1

# The presenter must supply these two; MODEL_ENDPOINT is optional (defaulted).
# MODEL_API_KEY is secret and is only ever reported as set/unset.
MODEL_REQUIRED_VARS="MODEL_API_KEY MODEL_NAME"
MODEL_SECRET_VARS="MODEL_API_KEY"

# The OpenAI API base the agent's ModelConfig (provider OpenAI / openAI.baseUrl)
# points at, and the host the AkshPolicy allows. Overridable, but defaults to
# the public OpenAI endpoint.
MODEL_ENDPOINT_DEFAULT="https://api.openai.com/v1"

: "${PRESENTER_ENV_FILE:=${DEMO_DIR}/presenter.env.local}"

# is_secret_var NAME -> 0 if the variable must never be printed.
is_secret_var() {
  for _isv in $MODEL_SECRET_VARS; do
    [ "$1" = "$_isv" ] && return 0
  done
  return 1
}

# key_state VALUE -> "set" if non-empty, else "unset". This is the ONLY thing
# the CLI ever reports about MODEL_API_KEY: no value, no length, no partial
# characters, anywhere (status, doctor, evidence, docs).
key_state() {
  if [ -n "${1:-}" ]; then printf 'set\n'; else printf 'unset\n'; fi
}

# load_presenter_env — parse KEY=VALUE from presenter.env.local into the env.
#   Only assigns MODEL_* and a small allow-list of demo overrides; ignores
#   comments/blank lines; strips optional surrounding quotes. Never prints the
#   value it assigns. Existing environment values win (so `MODEL_X=… demo.sh`
#   works and CI secrets are honoured) — the file only fills the gaps.
load_presenter_env() {
  if [ ! -f "$PRESENTER_ENV_FILE" ]; then
    return 0
  fi
  # Refuse a world-readable secret file with a warning (not fatal on shared
  # laptops, but the presenter should know).
  _lpe_perm=$( ls -l "$PRESENTER_ENV_FILE" 2>/dev/null | cut -c1-10 )
  case "$_lpe_perm" in
    *r--r--*|*rw-rw*|*rwxrwx*) warn "$PRESENTER_ENV_FILE is group/world readable; chmod 600 it" ;;
  esac

  while IFS= read -r _lpe_line || [ -n "$_lpe_line" ]; do
    # Strip leading whitespace.
    case "$_lpe_line" in
      ''|'#'*) continue ;;
    esac
    # Only KEY=VALUE forms with a valid identifier key.
    case "$_lpe_line" in
      *=*) : ;;
      *) continue ;;
    esac
    _lpe_key=${_lpe_line%%=*}
    _lpe_val=${_lpe_line#*=}
    # Drop an optional leading "export ".
    _lpe_key=${_lpe_key#export }
    _lpe_key=${_lpe_key# }
    _lpe_key=${_lpe_key% }
    # Validate identifier.
    case "$_lpe_key" in
      *[!A-Za-z0-9_]*|'') continue ;;
    esac
    # Only accept known-safe keys.
    case "$_lpe_key" in
      MODEL_ENDPOINT|MODEL_NAME|MODEL_API_KEY|\
      CLUSTER|DEMO_NS|TELEMETRY_HOST|COLLECTOR_SVC|COLLECTOR_NS|\
      COLLECTOR_PORT|COLLECTOR_LOCAL_PORT|AGENT_PORT|KAGENT_UI_LOCAL_PORT|\
      PROXY_IMAGE|INJECTOR_IMAGE|INJECT_LABEL_KEY|INJECT_LABEL_VALUE|\
      KAGENT_NS|KAGENT_UI_SVC|AGENT_SELECTOR|PROTECT_TARGET_SELECTOR) : ;;
      *) continue ;;
    esac
    # Strip surrounding single or double quotes.
    _lpe_val=${_lpe_val%$'\r'}
    case "$_lpe_val" in
      \"*\") _lpe_val=${_lpe_val#\"}; _lpe_val=${_lpe_val%\"} ;;
      \'*\') _lpe_val=${_lpe_val#\'}; _lpe_val=${_lpe_val%\'} ;;
    esac
    # Do not overwrite a value already set in the environment.
    eval "_lpe_cur=\${$_lpe_key:-}"
    if [ -z "${_lpe_cur:-}" ]; then
      eval "$_lpe_key=\$_lpe_val"
      eval "export $_lpe_key"
    fi
  done < "$PRESENTER_ENV_FILE"
  # Default the OpenAI endpoint AFTER reading the file, so a presenter-supplied
  # value wins but the common case needs no configuration.
  : "${MODEL_ENDPOINT:=$MODEL_ENDPOINT_DEFAULT}"
  export MODEL_ENDPOINT
  return 0
}

# validate_model_env — assert the required OpenAI inputs are present and shaped
# right. Emits [ok]/[FAIL] lines. MODEL_API_KEY is reported ONLY as set/unset —
# never the value, a length, or any partial characters. No network call is made
# (validation must never spend the presenter's OpenAI quota). Returns non-zero
# if anything is missing/malformed.
validate_model_env() {
  _vme_rc=0
  # Ensure the endpoint default is applied even if validate is called before
  # load_presenter_env for some reason.
  : "${MODEL_ENDPOINT:=$MODEL_ENDPOINT_DEFAULT}"
  for _vme_v in $MODEL_REQUIRED_VARS; do
    eval "_vme_val=\${$_vme_v:-}"
    if is_secret_var "$_vme_v"; then
      # Never print the key or anything derived from it — only set/unset.
      if [ -z "${_vme_val:-}" ]; then
        fail "model env: MODEL_API_KEY=unset (required; put it in presenter.env.local)"
        _vme_rc=1
      else
        ok "model env: MODEL_API_KEY=set"
      fi
      continue
    fi
    if [ -z "${_vme_val:-}" ]; then
      fail "model env: $_vme_v is not set"
      _vme_rc=1
      continue
    fi
    ok "model env: $_vme_v=$_vme_val"
  done
  # Endpoint is optional/defaulted. This demo's AkshPolicy allows ONLY
  # api.openai.com over POST /v1/, the CoreDNS rewrite and ModelConfig baseUrl
  # are all fixed around that host, so a non-default endpoint would silently
  # break capture/policy. Refuse anything but the pinned default.
  if [ "${MODEL_ENDPOINT:-}" = "$MODEL_ENDPOINT_DEFAULT" ]; then
    ok "model env: MODEL_ENDPOINT=$MODEL_ENDPOINT"
  else
    fail "model env: MODEL_ENDPOINT must be ${MODEL_ENDPOINT_DEFAULT} for this fixed-policy demo (got ${MODEL_ENDPOINT:-empty}); unset MODEL_ENDPOINT to use the default"
    _vme_rc=1
  fi
  return $_vme_rc
}

# model_host — the bare host of MODEL_ENDPOINT (e.g. api.openai.com), used for
# the AkshPolicy allow rule and CoreDNS reasoning. Portable (no grep -P).
model_host() {
  _mh=${MODEL_ENDPOINT:-$MODEL_ENDPOINT_DEFAULT}
  _mh=${_mh#http://}
  _mh=${_mh#https://}
  _mh=${_mh%%/*}
  printf '%s\n' "$_mh"
}
