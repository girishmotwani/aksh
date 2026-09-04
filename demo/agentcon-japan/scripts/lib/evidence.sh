#!/usr/bin/env bash
# evidence.sh — write sanitized, structured evidence under .state/evidence.
#
# Evidence must be safe to attach to a talk repo or a slide: it can contain
# audit dispositions, request IDs, resolved IPs, arch and cgroup facts — but
# NEVER the model API key or any Authorization header value. Every writer here
# runs its inputs through scrub_secrets first.

if [ -n "${_AKSH_EVIDENCE_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_EVIDENCE_SOURCED=1

# scrub_secrets — redact the model key and bearer tokens from arbitrary text.
#   Portable sed (BSD/GNU): every s/// command carries its trailing delimiter
#   and flag, no -E/-r, no -i. Works identically on macOS and Linux.
scrub_secrets() {
  _ss_in=$( cat )
  if [ -n "${MODEL_API_KEY:-}" ]; then
    _ss_key_esc=$( printf '%s' "$MODEL_API_KEY" | sed 's/[][\/.*^$&]/\\&/g' )
    _ss_in=$( printf '%s' "$_ss_in" | sed "s/${_ss_key_esc}/<REDACTED_MODEL_KEY>/g" )
  fi
  _ss_in=$( printf '%s' "$_ss_in" \
    | sed 's/[Bb]earer [A-Za-z0-9._~+\/-]\{8,\}=*/Bearer <REDACTED>/g' \
    | sed 's/"[Aa]uthorization":[[:space:]]*"[^"]*"/"authorization":"<REDACTED>"/g' \
    | sed 's/sk-[A-Za-z0-9._-]\{8,\}/<REDACTED_OPENAI_KEY>/g' \
    | sed 's/api-key:[[:space:]]*[A-Za-z0-9._-]\{8,\}/api-key: <REDACTED>/g' )
  printf '%s' "$_ss_in"
}

evidence_write() {
  ensure_state_dirs
  _ew_name=$1
  _ew_ts=$( date -u +%Y%m%dT%H%M%SZ )
  _ew_path="${EVIDENCE_DIR}/${_ew_ts}-${_ew_name}"
  scrub_secrets > "$_ew_path"
  printf '%s\n' "$_ew_path"
}

evidence_kv() {
  _ekv_file=$1; _ekv_key=$2; _ekv_val=$3
  _ekv_clean=$( printf '%s' "$_ekv_val" | scrub_secrets )
  printf '%s=%s\n' "$_ekv_key" "$_ekv_clean" >> "$_ekv_file"
}

evidence_json_begin() {
  ensure_state_dirs
  printf '{\n' > "$1"
  : > "${1}.firstflag"
}
evidence_json_field() {
  _ejf_file=$1; _ejf_key=$2; _ejf_val=$3
  _ejf_val=$( printf '%s' "$_ejf_val" | scrub_secrets )
  _ejf_val=$( json_escape "$_ejf_val" )
  _ejf_key=$( json_escape "$_ejf_key" )
  if [ -s "${_ejf_file}.firstflag" ]; then
    printf ',\n' >> "$_ejf_file"
  else
    printf 'x' > "${_ejf_file}.firstflag"
  fi
  printf '  "%s": "%s"' "$_ejf_key" "$_ejf_val" >> "$_ejf_file"
}
evidence_json_end() {
  printf '\n}\n' >> "$1"
  rm -f "${1}.firstflag"
}
