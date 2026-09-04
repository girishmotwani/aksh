#!/usr/bin/env bash
# demo.sh — the AgentCon Japan presenter CLI.
#
# A single, portable entrypoint for running the aksh "before/after" demo on
# stage. It works identically on a WSL/Linux amd64 laptop and on an Apple
# Silicon macOS laptop with Docker Desktop. It is deliberately Bash 3.2-safe
# (macOS ships Bash 3.2): no associative arrays, no `mapfile`, no GNU-only
# `sed -i` / `grep -P` / `readlink -f` / `timeout` / `date -d`. There is NO
# PowerShell anywhere in this workstream — that is the point of it.
#
# Subcommands:
#   doctor [--deep]   preflight the laptop (+ cluster kernel/cgroup/BPF, smoke)
#   setup             stand up the BASELINE (real agent + collector, no aksh)
#   open [--browser]  two kubectl port-forwards with PID files + health waits
#   protect           insert aksh (injector, policy, label, roll, invariants)
#   status            fast, read-only "where is the demo right now"
#   validate --model  one bounded OpenAI credential/quota check
#   validate --full   drive baseline+protected flows and assert every invariant
#   validate --mac    fresh native Apple-Silicon end-to-end acceptance
#   evidence [--list] collect/print sanitized evidence under .state/evidence
#   evidence --live-deny  model-free protected-deny trigger (offline contingency)
#   reset             back to BASELINE, keep the cluster (safe mid-talk)
#   cleanup           delete the named kind cluster + shred local secrets
#
# Exit status is non-zero if a subcommand reports any failed check.

set -u
set -o pipefail

# Resolve our own directory portably (no readlink -f) so the CLI runs from any
# cwd, including a double-clicked shortcut on macOS.
_demo_self=${BASH_SOURCE[0]}
_demo_dir=$( cd "$( dirname "$_demo_self" )" && pwd )
LIB="${_demo_dir}/scripts/lib"
CMD="${_demo_dir}/scripts/cmd"

# --- library (order matters: portable -> common -> the rest) ----------------
# shellcheck source=scripts/lib/portable.sh
. "${LIB}/portable.sh"
# shellcheck source=scripts/lib/common.sh
. "${LIB}/common.sh"
# shellcheck source=scripts/lib/env.sh
. "${LIB}/env.sh"
# shellcheck source=scripts/lib/cluster.sh
. "${LIB}/cluster.sh"
# shellcheck source=scripts/lib/images.sh
. "${LIB}/images.sh"
# shellcheck source=scripts/lib/k8s.sh
. "${LIB}/k8s.sh"
# shellcheck source=scripts/lib/coredns.sh
. "${LIB}/coredns.sh"
# shellcheck source=scripts/lib/secrets.sh
. "${LIB}/secrets.sh"
# shellcheck source=scripts/lib/manifests.sh
. "${LIB}/manifests.sh"
# shellcheck source=scripts/lib/install.sh
. "${LIB}/install.sh"
# shellcheck source=scripts/lib/portforward.sh
. "${LIB}/portforward.sh"
# shellcheck source=scripts/lib/evidence.sh
. "${LIB}/evidence.sh"

# --- subcommands ------------------------------------------------------------
# shellcheck source=scripts/cmd/doctor.sh
. "${CMD}/doctor.sh"
# shellcheck source=scripts/cmd/setup.sh
. "${CMD}/setup.sh"
# shellcheck source=scripts/cmd/open.sh
. "${CMD}/open.sh"
# shellcheck source=scripts/cmd/protect.sh
. "${CMD}/protect.sh"
# shellcheck source=scripts/cmd/status.sh
. "${CMD}/status.sh"
# shellcheck source=scripts/cmd/validate.sh
. "${CMD}/validate.sh"
# shellcheck source=scripts/cmd/evidence.sh
. "${CMD}/evidence.sh"
# shellcheck source=scripts/cmd/reset.sh
. "${CMD}/reset.sh"
# shellcheck source=scripts/cmd/cleanup.sh
. "${CMD}/cleanup.sh"

usage() {
  cat <<EOF
AgentCon Japan — aksh presenter CLI

Usage: demo.sh <command> [flags]

Commands:
  doctor [--deep]     preflight the laptop; --deep adds kernel/cgroup/BPF and
                      image build/load prerequisite checks
  setup               stand up the BASELINE (real agent + collector, no aksh)
  open [--browser]    two port-forwards (collector, agent) with health waits
  protect             insert aksh: injector, AkshPolicy, label the demo
                      workload, roll it, and check the invariants
  status              read-only summary of host + cluster + forwards + evidence
  validate --full     drive baseline+protected agent interactions and assert
                      exfil-blocked / OpenAI-still-works / audited-deny /
                      pod-cgroup / idempotency+recovery. Drives a few real agent
                      turns; the number of OpenAI API calls is the agent's, not
                      a fixed count.
  validate --model    a guaranteed single tiny OpenAI call to verify key, model,
                      network and available quota before rehearsal/stage
  validate --mac      Apple-Silicon macOS Docker Desktop only: fresh cleanup +
                      native setup + full end-to-end acceptance with evidence
  evidence [--list]   collect/print sanitized evidence (.state/evidence)
  evidence --live-deny  MODEL-FREE offline contingency: drive the diagnostics
                      exfil via the diagnostics-mcp 'send' CLI (no LLM/key) and
                      prove aksh blocks it (HTTP 403 + new policy_no_match audit)
  evidence --live-steal MODEL-FREE credential-theft contingency: drive the
                      diagnostics-mcp 'steal' CLI (reads the pod's mounted cloud
                      credential) and prove aksh blocks the leak (no new leaked
                      credential at the collector, HTTP 403, policy_no_match)
  reset               return to BASELINE but keep the cluster (safe mid-talk)
  cleanup             delete the named kind cluster and shred local secrets

Environment:
  presenter.env.local   MODEL_API_KEY (required) and MODEL_NAME (required, e.g.
                        gpt-5.4-mini); MODEL_ENDPOINT optional, defaults to
                        https://api.openai.com/v1. Gitignored; the key is never
                        echoed (reported only as set/unset). Copy
                        presenter.env.example to start. A real OpenAI key spends
                        real quota — run validation judiciously.

Portability: runs on WSL/Linux (amd64) and Apple Silicon macOS Docker Desktop
(arm64). Bash 3.2-safe. No PowerShell.
EOF
}

main() {
  if [ "$#" -eq 0 ]; then usage; exit 2; fi
  _main_cmd=$1; shift
  case "$_main_cmd" in
    doctor)   cmd_doctor "$@" ;;
    setup)    cmd_setup "$@" ;;
    open)     cmd_open "$@" ;;
    protect)  cmd_protect "$@" ;;
    status)   cmd_status "$@" ;;
    validate) cmd_validate "$@" ;;
    evidence) cmd_evidence "$@" ;;
    reset)    cmd_reset "$@" ;;
    cleanup)  cmd_cleanup "$@" ;;
    -h|--help|help) usage; exit 0 ;;
    *) err "unknown command: ${_main_cmd}"; usage; exit 2 ;;
  esac
}

main "$@"
