#!/usr/bin/env bash
# PreToolUse hook of the rust-refactor agent. Every Bash call must be made of
# allowlisted programs: cargo (build, test, lint, docs), read-only git and
# text tools. Exit code 2 blocks the call and shows the reason to the agent.
#
# Tests: .claude/hooks/test-rust-refactor-guard.sh
set -u

GUARD_NAME=rust-refactor
GUARD_ALLOWED="cargo build/check/test/clippy/fmt/doc/bench/tree/metadata/run, read-only git, and text tools"
# shellcheck source=guard-lib.sh
. "$(dirname "$0")/guard-lib.sh"

check_program() {
  local program=$1
  shift
  case $program in
    cargo) check_cargo "$@" ;;
    git) check_git "$@" ;;
    *) is_text_tool "$program" || block "'$program' is not on the allowlist" ;;
  esac
}

run_guard
