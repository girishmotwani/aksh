#!/usr/bin/env bash
# manifests.sh — discover and apply the YAML that sibling workstreams own.
#
# The presenter does NOT author the kagent/collector/injector manifests; those
# land in demo/agentcon-japan/manifests/{baseline,protect}. This module applies
# whatever is present, in sorted order, and degrades to a clear, actionable TODO
# when a stage's manifests have not been committed yet — so the CLI is runnable
# end-to-end as the other workstreams fill in.

if [ -n "${_AKSH_MANIFESTS_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_MANIFESTS_SOURCED=1

# list_manifests DIR — print sorted *.yaml/*.yml paths, one per line. No
# mapfile; shell globs are used because BSD find has no -maxdepth.
list_manifests() {
  _lm_dir=$1
  [ -d "$_lm_dir" ] || return 0
  for _lm_file in "$_lm_dir"/*.yaml "$_lm_dir"/*.yml; do
    [ -f "$_lm_file" ] && printf '%s\n' "$_lm_file"
  done | LC_ALL=C sort
}

# manifests_present DIR — 0 if at least one manifest exists.
manifests_present() {
  _mp_first=$( list_manifests "$1" | head -1 )
  [ -n "$_mp_first" ]
}

# apply_manifests_dir DIR LABEL — apply every manifest in DIR (sorted). Returns
# 0 if applied, 2 if the directory is empty/missing (a soft, reported skip).
apply_manifests_dir() {
  _amd_dir=$1
  _amd_label=$2
  if ! manifests_present "$_amd_dir"; then
    warn "no ${_amd_label} manifests found under ${_amd_dir}"
    warn "INTEGRATION TODO: the ${_amd_label} workstream must land YAML here; skipping apply"
    return 2
  fi
  _amd_rc=0
  while IFS= read -r _amd_f; do
    [ -z "$_amd_f" ] && continue
    info "apply $( basename "$_amd_f" )"
    if ! kc apply -f "$_amd_f"; then
      fail "kubectl apply failed for $_amd_f"
      _amd_rc=1
    fi
  done <<EOF
$( list_manifests "$_amd_dir" )
EOF
  return $_amd_rc
}

# apply_manifest_if_present FILE LABEL — apply a single optional manifest.
apply_manifest_if_present() {
  if [ -f "$1" ]; then
    info "apply $( basename "$1" )"
    kc apply -f "$1"
  else
    warn "optional ${2} manifest not present ($1); skipping"
    return 2
  fi
}

sed_replacement() {
  printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
}

# render_manifests_dir INPUT OUTPUT — substitute only the two non-secret model
# fields. The API key is never a template value and never enters rendered YAML.
render_manifests_dir() {
  _rmd_in=$1
  _rmd_out=$2
  mkdir -p "$_rmd_out"
  _rmd_model=$( sed_replacement "$MODEL_NAME" )
  _rmd_endpoint=$( sed_replacement "$MODEL_ENDPOINT" )
  while IFS= read -r _rmd_file; do
    [ -z "$_rmd_file" ] && continue
    _rmd_target="${_rmd_out}/$( basename "$_rmd_file" )"
    sed \
      -e "s|\${MODEL_NAME}|${_rmd_model}|g" \
      -e "s|\${MODEL_ENDPOINT}|${_rmd_endpoint}|g" \
      "$_rmd_file" > "$_rmd_target"
  done <<EOF
$( list_manifests "$_rmd_in" )
EOF
}

apply_rendered_manifests_dir() {
  _armd_source=$1
  _armd_name=$2
  _armd_output="${RENDER_DIR}/${_armd_name}"
  rm -rf "$_armd_output"
  render_manifests_dir "$_armd_source" "$_armd_output"
  apply_manifests_dir "$_armd_output" "$_armd_name"
}
