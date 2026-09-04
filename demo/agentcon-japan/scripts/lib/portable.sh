#!/usr/bin/env bash
# portable.sh — POSIX/Bash 3.2-safe shims used across the presenter CLI.
#
# The presenter must run identically on:
#   * WSL / Linux (GNU coreutils)
#   * Apple Silicon macOS with Docker Desktop (BSD coreutils, Bash 3.2)
#
# So NOTHING in this codebase may rely on: GNU `sed -i`, `grep -P`,
# `readlink -f`, `mapfile`/`readarray`, `timeout(1)`, `xargs -r`, Bash 4
# associative arrays, or GNU `date -d`. Every construct below is verified to
# behave the same on both toolchains. Keep it that way.

# Guard against double-sourcing.
if [ -n "${_AKSH_PORTABLE_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_PORTABLE_SOURCED=1

# ---------------------------------------------------------------------------
# portable_realpath PATH
#   readlink -f is GNU-only (macOS readlink has no -f). Resolve to an absolute
#   path using cd/pwd, which is identical everywhere. Does not resolve symlink
#   chains beyond the final component, which the CLI never needs.
# ---------------------------------------------------------------------------
portable_realpath() {
  _prp_target=$1
  if [ -d "$_prp_target" ]; then
    ( cd "$_prp_target" 2>/dev/null && pwd )
  else
    _prp_dir=$( dirname "$_prp_target" )
    _prp_base=$( basename "$_prp_target" )
    _prp_abs=$( cd "$_prp_dir" 2>/dev/null && pwd )
    [ -n "$_prp_abs" ] && printf '%s/%s\n' "$_prp_abs" "$_prp_base"
  fi
}

# ---------------------------------------------------------------------------
# run_with_timeout SECONDS CMD [ARGS...]
#   timeout(1) is not on macOS by default (it is `gtimeout` if coreutils is
#   brewed). This implements the same contract with a watchdog subshell and an
#   explicit `kill <pid>` (never pkill/killall). Returns 124 on timeout, else
#   the command's own exit status.
# ---------------------------------------------------------------------------
run_with_timeout() {
  _rwt_secs=$1
  shift
  "$@" &
  _rwt_cmd_pid=$!
  (
    sleep "$_rwt_secs"
    kill "$_rwt_cmd_pid" 2>/dev/null
  ) &
  _rwt_watch_pid=$!
  wait "$_rwt_cmd_pid" 2>/dev/null
  _rwt_rc=$?
  # Stop the watchdog if the command finished first.
  if kill -0 "$_rwt_watch_pid" 2>/dev/null; then
    kill "$_rwt_watch_pid" 2>/dev/null
    wait "$_rwt_watch_pid" 2>/dev/null || true
    return "$_rwt_rc"
  fi
  # Watchdog already fired: the command was killed by us -> treat as timeout.
  wait "$_rwt_watch_pid" 2>/dev/null || true
  if [ "$_rwt_rc" -ge 128 ]; then
    return 124
  fi
  return "$_rwt_rc"
}

# ---------------------------------------------------------------------------
# wait_for SECONDS INTERVAL CMD [ARGS...]
#   Poll CMD until it succeeds or the deadline passes. Uses `date +%s`, which
#   is identical on GNU and BSD (no `date -d` anywhere). Returns 0 on success,
#   124 on timeout.
# ---------------------------------------------------------------------------
wait_for() {
  _wf_deadline_secs=$1
  _wf_interval=$2
  shift 2
  _wf_start=$( date +%s )
  while :; do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    _wf_now=$( date +%s )
    if [ $(( _wf_now - _wf_start )) -ge "$_wf_deadline_secs" ]; then
      return 124
    fi
    sleep "$_wf_interval"
  done
}

# ---------------------------------------------------------------------------
# now_epoch / iso_utc — timestamps that work on both toolchains.
#   `date -u +%Y-%m-%dT%H:%M:%SZ` is portable; `date -Iseconds` is GNU-only.
# ---------------------------------------------------------------------------
now_epoch() { date +%s; }
iso_utc()   { date -u +%Y-%m-%dT%H:%M:%SZ; }

# ---------------------------------------------------------------------------
# read_lines_into VAR < input
#   mapfile/readarray replacement. Reads stdin into a newline list; callers
#   iterate with a `while read` loop or `for x in $var` after setting IFS.
#   Prefer feeding a command's output through `while IFS= read -r line` instead;
#   this helper exists for the few places a captured list is genuinely simpler.
# ---------------------------------------------------------------------------
count_lines() {
  # Portable line count that does not depend on `wc -l` whitespace quirks.
  _cl_n=0
  while IFS= read -r _cl_line; do
    _cl_n=$(( _cl_n + 1 ))
  done
  # Handle a final line with no trailing newline.
  [ -n "${_cl_line:-}" ] && _cl_n=$(( _cl_n + 1 ))
  printf '%s\n' "$_cl_n"
}

# One-level regular files, sorted. BSD find on macOS has no -maxdepth, so use
# shell globbing instead.
list_regular_files() {
  _lrf_dir=$1
  [ -d "$_lrf_dir" ] || return 0
  for _lrf_file in "$_lrf_dir"/*; do
    [ -f "$_lrf_file" ] && printf '%s\n' "$_lrf_file"
  done | LC_ALL=C sort
}

# ---------------------------------------------------------------------------
# json_escape STRING — minimal JSON string escaper (no jq dependency).
#   Escapes backslash, double-quote, newline, tab, carriage return. Sufficient
#   for the sanitized evidence records the CLI emits.
# ---------------------------------------------------------------------------
json_escape() {
  _je_s=$1
  # Order matters: backslash first.
  _je_s=$( printf '%s' "$_je_s" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' )
  # Convert real newlines/tabs to escaped forms via awk for portability.
  printf '%s' "$_je_s" | awk 'BEGIN{ORS=""} {gsub(/\t/,"\\t"); if(NR>1) printf "\\n"; printf "%s", $0}'
}

# ---------------------------------------------------------------------------
# uniq_id PREFIX — collision-resistant request/run id without GNU-only tools.
#   Combines epoch seconds, the PID and a shell RANDOM draw. Good enough to
#   correlate a single presenter run's requests in audit logs.
# ---------------------------------------------------------------------------
uniq_id() {
  _ui_prefix=${1:-id}
  printf '%s-%s-%s-%s\n' "$_ui_prefix" "$( date +%s )" "$$" "${RANDOM:-0}${RANDOM:-0}"
}

# ---------------------------------------------------------------------------
# detect_host_arch — normalise `uname -m` to Docker/Go arch names.
#   Emits: amd64 | arm64  (the only two the demo supports). Anything else is
#   returned verbatim so callers can produce an actionable error.
# ---------------------------------------------------------------------------
detect_host_arch() {
  _dha_m=$( uname -m 2>/dev/null || echo unknown )
  case "$_dha_m" in
    x86_64|amd64)          printf 'amd64\n' ;;
    aarch64|arm64)         printf 'arm64\n' ;;
    *)                     printf '%s\n' "$_dha_m" ;;
  esac
}

# ---------------------------------------------------------------------------
# b64_encode < input  — base64 of stdin with no line wrapping or trailing
#   newline artefacts, portable across GNU coreutils and BSD/macOS `base64`.
#   Used to compare a Kubernetes Secret's stored (base64) value against an
#   expected literal WITHOUT ever decoding/printing the real secret.
# ---------------------------------------------------------------------------
b64_encode() {
  # `tr -d '\n'` folds GNU's 76-col wrapping and any trailing newline so the
  # result matches kubectl's single-line `.data` encoding on both toolchains.
  base64 2>/dev/null | tr -d '\n'
}

atomic_write() {
  _aw_file=$1
  _aw_tmp="${_aw_file}.tmp.$$"
  cat > "$_aw_tmp"
  mv -f "$_aw_tmp" "$_aw_file"
}
