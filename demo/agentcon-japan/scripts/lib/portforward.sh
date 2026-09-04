#!/usr/bin/env bash
# portforward.sh — manage the two kubectl port-forwards the demo exposes, each
# tracked by a PID file so `open` is idempotent, `status` can report health,
# and `reset`/`cleanup` can stop them by exact PID (never pkill/killall).

if [ -n "${_AKSH_PF_SOURCED:-}" ]; then return 0 2>/dev/null || true; fi
_AKSH_PF_SOURCED=1

# _pf_pidfile NAME -> path of the PID file for a named forward.
_pf_pidfile() { printf '%s/pf-%s.pid\n' "$PIDS_DIR" "$1"; }

# The pidfile stores two lines: the PID, then the "LOCAL REMOTE TARGET" spec, so
# ownership can be re-verified later (a bare PID can be recycled by the OS onto
# an unrelated process).
_pf_read_pid()  { sed -n '1p' "$1" 2>/dev/null; }
_pf_read_spec() { sed -n '2p' "$1" 2>/dev/null; }

# _pf_ps_args PID -> the process's full argument line, portably (GNU + BSD).
_pf_ps_args() {
  ps -p "$1" -o args= 2>/dev/null || ps -p "$1" -o command= 2>/dev/null
}

# _pf_argline_matches ARGLINE LOCAL REMOTE TARGET NAMESPACE -> 0 if ARGLINE is
# the exact class of kubectl port-forward recorded in our pidfile.
_pf_argline_matches() {
  printf '%s\n' "$1" | awk \
    -v context="$KIND_CONTEXT" -v ns_want="$5" \
    -v target="$4" -v mapping="$2:$3" '
    {
      n = split($1, exe, "/")
      exit !(NF == 10 &&
        exe[n] == "kubectl" &&
        $2 == "--context" && $3 == context &&
        $4 == "-n" && $5 == ns_want &&
        $6 == "port-forward" &&
        $7 == target &&
        $8 == mapping &&
        $9 == "--address" && $10 == "127.0.0.1")
    }'
}

# _pf_pid_is_ours PID LOCAL REMOTE -> 0 if PID is live AND its args match one of
# our kubectl port-forwards for LOCAL:REMOTE (guards against recycled PIDs).
_pf_pid_is_ours() {
  [ -n "$1" ] || return 1
  kill -0 "$1" 2>/dev/null || return 1
  _pfio_args=$( _pf_ps_args "$1" )
  # If ps is unavailable we cannot prove ownership: fail closed (treat as not
  # ours) so we never kill or trust a process we cannot identify.
  [ -n "$_pfio_args" ] || return 1
  _pf_argline_matches "$_pfio_args" "$2" "$3" "$4" "$5"
}

# _pf_alive PIDFILE -> 0 if the recorded PID is a live process WE own.
_pf_alive() {
  _pfa_file=$1
  [ -f "$_pfa_file" ] || return 1
  _pfa_pid=$( _pf_read_pid "$_pfa_file" )
  _pfa_spec=$( _pf_read_spec "$_pfa_file" )
  [ -n "$_pfa_pid" ] || return 1
  # spec = "LOCAL REMOTE TARGET NAMESPACE".
  _pfa_local=$( printf '%s' "$_pfa_spec" | awk '{print $1}' )
  _pfa_remote=$( printf '%s' "$_pfa_spec" | awk '{print $2}' )
  _pfa_target=$( printf '%s' "$_pfa_spec" | awk '{print $3}' )
  _pfa_ns=$( printf '%s' "$_pfa_spec" | awk '{print $4}' )
  [ -n "$_pfa_local" ] && [ -n "$_pfa_remote" ] && [ -n "$_pfa_target" ] && [ -n "$_pfa_ns" ] || return 1
  _pf_pid_is_ours "$_pfa_pid" "$_pfa_local" "$_pfa_remote" "$_pfa_target" "$_pfa_ns"
}

# port_is_listening PORT -> 0 if something accepts on 127.0.0.1:PORT. Tries a
# few tools so it works on both macOS and Linux without lsof guaranteed.
port_is_listening() {
  _pil_port=$1
  if have nc; then
    nc -z 127.0.0.1 "$_pil_port" >/dev/null 2>&1 && return 0
  fi
  if have curl; then
    # A refused connection returns quickly; a listening socket returns some
    # HTTP status (even an error page) which curl treats as success to connect.
    curl -s -o /dev/null -m 2 "http://127.0.0.1:${_pil_port}/" >/dev/null 2>&1 && return 0
  fi
  # Last resort: /dev/tcp (bash builtin, present on both platforms' bash).
  ( exec 3<>"/dev/tcp/127.0.0.1/${_pil_port}" ) >/dev/null 2>&1 && return 0
  return 1
}

# start_port_forward NAME NAMESPACE SVC_OR_POD REMOTE_PORT LOCAL_PORT
#   Idempotent: if a healthy forward already runs, reuse it. Otherwise start a
#   detached kubectl port-forward, record its PID, and wait for the local port
#   to accept connections.
start_port_forward() {
  _spf_name=$1; _spf_ns=$2; _spf_target=$3; _spf_remote=$4; _spf_local=$5
  ensure_state_dirs
  _spf_pidfile=$( _pf_pidfile "$_spf_name" )
  if _pf_alive "$_spf_pidfile" && port_is_listening "$_spf_local"; then
    ok "port-forward '$_spf_name' already healthy on 127.0.0.1:${_spf_local}"
    return 0
  fi
  # Refuse to start if 127.0.0.1:LOCAL is already occupied by something that is
  # NOT one of our forwards — starting a second forward would silently fail or
  # collide, and we must never assume ownership of a foreign listener.
  if port_is_listening "$_spf_local" && ! _pf_alive "$_spf_pidfile"; then
    err "local port 127.0.0.1:${_spf_local} is occupied by another process; refusing to start '$_spf_name'"
    err "free the port or set a different *_LOCAL_PORT, then retry"
    return 1
  fi
  # Clean up a stale pidfile before starting fresh.
  stop_port_forward "$_spf_name" >/dev/null 2>&1 || true
  step "Starting port-forward '$_spf_name': 127.0.0.1:${_spf_local} -> ${_spf_target}:${_spf_remote}"
  # Log to the state dir so failures are diagnosable after the fact.
  _spf_log="${PIDS_DIR}/pf-${_spf_name}.log"
  kubectl --context "$KIND_CONTEXT" -n "$_spf_ns" port-forward \
    "$_spf_target" "${_spf_local}:${_spf_remote}" \
    --address 127.0.0.1 >"$_spf_log" 2>&1 &
  _spf_pid=$!
  # Record PID + the ownership spec (LOCAL REMOTE TARGET).
  printf '%s\n%s %s %s %s\n' "$_spf_pid" "$_spf_local" "$_spf_remote" "$_spf_target" "$_spf_ns" > "$_spf_pidfile"
  # Health wait: up to 30s for the local port to accept AND the process to stay
  # ours (a forward that dies immediately must not be reported healthy).
  if wait_for 30 1 port_is_listening "$_spf_local" && _pf_alive "$_spf_pidfile"; then
    ok "port-forward '$_spf_name' healthy on 127.0.0.1:${_spf_local}"
    return 0
  fi
  err "port-forward '$_spf_name' did not become healthy; see $_spf_log"
  stop_port_forward "$_spf_name" >/dev/null 2>&1 || true
  return 1
}

# stop_port_forward NAME — kill the recorded PID, but ONLY if it is still one of
# our port-forwards (ownership-checked) so a recycled PID is never killed.
stop_port_forward() {
  _stp_name=$1
  _stp_pidfile=$( _pf_pidfile "$_stp_name" )
  if [ -f "$_stp_pidfile" ]; then
    _stp_pid=$( _pf_read_pid "$_stp_pidfile" )
    _stp_spec=$( _pf_read_spec "$_stp_pidfile" )
    _stp_local=$( printf '%s' "$_stp_spec" | awk '{print $1}' )
    _stp_remote=$( printf '%s' "$_stp_spec" | awk '{print $2}' )
    _stp_target=$( printf '%s' "$_stp_spec" | awk '{print $3}' )
    _stp_ns=$( printf '%s' "$_stp_spec" | awk '{print $4}' )
    if [ -n "$_stp_pid" ] && _pf_pid_is_ours "$_stp_pid" "$_stp_local" "$_stp_remote" "$_stp_target" "$_stp_ns"; then
      kill "$_stp_pid" 2>/dev/null || true
      # Give it a moment, then confirm it is gone.
      wait_for 5 1 sh -c "! kill -0 $_stp_pid 2>/dev/null" >/dev/null 2>&1 || true
      info "stopped port-forward '$_stp_name' (pid $_stp_pid)"
    elif [ -n "$_stp_pid" ] && kill -0 "$_stp_pid" 2>/dev/null; then
      warn "pid $_stp_pid for '$_stp_name' is not our port-forward (recycled?); NOT killing it"
    fi
    rm -f "$_stp_pidfile"
  fi
}

# stop_all_port_forwards — stop every named forward we know about.
stop_all_port_forwards() {
  for _sapf_f in "$PIDS_DIR"/pf-*.pid; do
    [ -f "$_sapf_f" ] || continue
    _sapf_name=$( basename "$_sapf_f" )
    _sapf_name=${_sapf_name#pf-}
    _sapf_name=${_sapf_name%.pid}
    stop_port_forward "$_sapf_name"
  done
}

# port_forward_status — print a health line per known forward.
port_forward_status() {
  _pfs_any=1
  for _pfs_f in "$PIDS_DIR"/pf-*.pid; do
    [ -f "$_pfs_f" ] || continue
    _pfs_any=0
    _pfs_name=$( basename "$_pfs_f" ); _pfs_name=${_pfs_name#pf-}; _pfs_name=${_pfs_name%.pid}
    _pfs_pid=$( _pf_read_pid "$_pfs_f" )
    if _pf_alive "$_pfs_f"; then
      info "port-forward '$_pfs_name': pid $_pfs_pid (running, ours)"
    elif [ -n "$_pfs_pid" ] && kill -0 "$_pfs_pid" 2>/dev/null; then
      info "port-forward '$_pfs_name': pid $_pfs_pid (alive but NOT ours; recycled)"
    else
      info "port-forward '$_pfs_name': pid $_pfs_pid (dead; stale pidfile)"
    fi
  done
  [ "$_pfs_any" -eq 1 ] && info "no port-forwards recorded"
  return 0
}

# open_browser URL — best-effort, OPTIONAL. macOS `open`, Linux `xdg-open`; if
# neither exists (headless/WSL without a browser bridge) just print the URL.
open_browser() {
  _ob_url=$1
  if have open; then
    open "$_ob_url" >/dev/null 2>&1 && return 0
  fi
  if have xdg-open; then
    xdg-open "$_ob_url" >/dev/null 2>&1 && return 0
  fi
  info "open this in a browser: $_ob_url"
  return 0
}
