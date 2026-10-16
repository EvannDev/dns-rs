#!/usr/bin/env bash
# Tests for rust-refactor-guard.sh: each case is "<expected exit> <command>".
# Run: .claude/hooks/test-rust-refactor-guard.sh
set -u
guard="$(dirname "$0")/rust-refactor-guard.sh"
failures=0

check() {
  local expected=$1 command=$2 actual
  jq -n --arg c "$command" '{tool_name: "Bash", tool_input: {command: $c}}' \
    | "$guard" >/dev/null 2>&1
  actual=$?
  if [ "$actual" != "$expected" ]; then
    echo "FAIL: expected exit $expected, got $actual: $command"
    failures=$((failures + 1))
  fi
}

# Allowed: building, testing, reading history and the working tree.
check 0 'cargo test -q'
check 0 'cargo clippy --all-targets -- -D warnings'
check 0 'cargo fmt --all --check'
check 0 'git status --short'
check 0 'git diff HEAD -- crates/dns-rs/src/filter.rs'
check 0 'git log --oneline -5'
check 0 'git branch --list'
check 0 'grep -rn "fn check" crates/'
check 0 'cargo test --test server && git diff --stat'

# Blocked: writing history or remote state.
check 2 'git commit -m "refactor"'
check 2 'git push origin HEAD'
check 2 'cargo test && git commit -am wip'
check 2 'git reset --hard HEAD~1'
check 2 'git clean -fdx'
check 2 'git checkout -- crates/dns-rs/src/lib.rs'
check 2 'git restore crates/dns-rs/src/lib.rs'
check 2 'git stash'
check 2 'git rebase main'
check 2 'git branch -D feature'
check 2 'gh pr create --fill'
# Blocked: dependency changes need authorization.
check 2 'cargo add serde'
check 2 'cargo remove regex'
check 2 'cargo update'
check 2 'cargo publish'
# Blocked: no web access.
check 2 'curl -s https://example.org'
check 2 'wget https://example.org/list'

if [ "$failures" -eq 0 ]; then echo "all guard tests passed"; else exit 1; fi
