#!/usr/bin/env bash
# Shared by the agent guards (PreToolUse hooks), sourced, never run. A guard
# sets GUARD_NAME and GUARD_ALLOWED, sources this file, defines
# check_program <program> <args…> (which calls block, or returns to allow),
# then calls run_guard.
#
# This is a guardrail against habits (committing, pushing, adding a
# dependency, reaching a production cluster), not a sandbox. It fails
# closed: anything it cannot classify is blocked. See ADR 0009.

# Fail closed: any exit other than 0 (allowed) or 2 (blocked), such as a
# crash, becomes a block. Claude Code would otherwise let the command run.
trap 'status=$?; [ "$status" -eq 0 ] || [ "$status" -eq 2 ] || { echo "Blocked by the ${GUARD_NAME:-agent} guard: internal error ($status)." >&2; exit 2; }' EXIT

# The guard sets GUARD_NAME and GUARD_ALLOWED before sourcing this file.
block() {
  echo "Blocked by the $GUARD_NAME guard: $1. Allowed: $GUARD_ALLOWED. Leave the change in the working tree for the caller." >&2
  exit 2
}

command -v jq >/dev/null || block "jq is missing, so the command cannot be checked"
command=$(jq -r '.tool_input.command // empty')

# Command substitution can hide any command.
case $command in
  *'$('* | *'`'*) block "command substitution" ;;
esac

# Allowed cargo subcommands; `+toolchain` and flags may come first.
# --config and -Z can set a rustc wrapper or a linker, anywhere in the line.
check_cargo() {
  local word
  for word in "$@"; do
    case $word in
      --config* | -Z*) block "cargo $word" ;;
    esac
  done
  for word in "$@"; do
    case $word in
      +* | -*) continue ;;
      build | check | test | clippy | fmt | doc | bench | tree | metadata | run) return ;;
      *) block "cargo $word" ;;
    esac
  done
  block "cargo without a subcommand"
}

# Allowed git subcommands, read-only. Only -C <dir>, --no-pager and -P may
# precede them: -c and other global options can run arbitrary programs.
check_git() {
  while [ $# -gt 0 ]; do
    case $1 in
      -C)
        [ $# -ge 2 ] || block "git -C without a directory"
        shift 2
        ;;
      --no-pager | -P) shift ;;
      -*) block "git option $1" ;;
      status | diff | log | show | blame | ls-files | rev-parse | shortlog | describe)
        shift
        local arg
        for arg in "$@"; do
          case $arg in
            # Prefixes, since git accepts unambiguous abbreviations (--ext).
            -O* | --open* | --ext* | --out*) block "git $arg" ;;
          esac
        done
        return
        ;;
      branch)
        shift
        local arg
        for arg in "$@"; do
          case $arg in
            --list | -l | --show-current | -a | --all | -r | --remotes | -v | -vv) ;;
            *) block "git branch $arg" ;;
          esac
        done
        return
        ;;
      *) block "git $1" ;;
    esac
  done
  block "git without a subcommand"
}

# Programs every guard allows: they only read, or print. Not rg (--pre)
# nor sort (--compress-program): they run programs; agents have Grep.
is_text_tool() {
  case $1 in
    cd | pwd | ls | cat | head | tail | wc | uniq | diff | grep | jq | echo | printf | true | test | '[') return 0 ;;
    *) return 1 ;;
  esac
}

run_guard() {
  # Split on control operators. Separators inside quotes split too: that can
  # block a harmless command, never let one through.
  while IFS= read -r segment; do
    read -ra words <<<"$segment"
    i=0
    # Leading VAR=value assignments: only harmless ones. Others (GIT_PAGER,
    # GIT_CONFIG_*, RUSTC_WRAPPER, LD_PRELOAD…) can make git or cargo run
    # arbitrary programs.
    while [ "$i" -lt "${#words[@]}" ] && [[ ${words[$i]} =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; do
      case ${words[$i]%%=*} in
        RUST_LOG | RUST_BACKTRACE) i=$((i + 1)) ;;
        *) block "environment assignment ${words[$i]%%=*}" ;;
      esac
    done
    [ "$i" -lt "${#words[@]}" ] || continue
    program=${words[$i]}
    rest=("${words[@]:$((i + 1))}")
    # ${a[@]+"${a[@]}"}: an empty array is "unbound" for bash 3.2 under set -u.
    check_program "$program" ${rest[@]+"${rest[@]}"}
  done < <(
    # Drop fd redirections (2>&1, &>file) first, so their `&` is not a separator.
    printf '%s\n' "$command" | sed -E 's/[0-9]*>&[0-9-]*/ /g; s/&>/>/g' | tr ';&|()' '\n\n\n\n\n'
  )
  exit 0
}
