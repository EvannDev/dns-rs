#!/usr/bin/env bash
# Tests for rust-refactor-guard.sh.
#   allowed '<command>'            must exit 0
#   blocked '<command>' '<reason>' must exit 2 with <reason> in the message,
#                                  and never through an internal error
# Run: .claude/hooks/test-rust-refactor-guard.sh
set -u
guard="$(dirname "$0")/rust-refactor-guard.sh"
failures=0

run() {
  # A hook killed by a timeout lets the command run, so hanging is a failure
  # (exit 142) like any other. The guard runs in its own process group, all
  # of it killed: a looping subshell would otherwise keep the pipe open.
  jq -n --arg c "$1" '{tool_name: "Bash", tool_input: {command: $c}}' \
    | perl -e '$pid = fork // die; if (!$pid) { setpgrp; exec @ARGV }
        $SIG{ALRM} = sub { kill "KILL", -$pid; exit 142 }; alarm 5;
        waitpid $pid, 0; exit($? >> 8)' "$guard" 2>&1 >/dev/null
}

fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

allowed() {
  local message status
  message=$(run "$1")
  status=$?
  [ "$status" -eq 0 ] || fail "expected allowed, got exit $status ($message): $1"
}

blocked() {
  local message status
  message=$(run "$1")
  status=$?
  if [ "$status" -ne 2 ]; then
    fail "expected blocked, got exit $status: $1"
  elif [[ $message == *"internal error"* ]]; then
    fail "blocked by a crash, not by a rule ($message): $1"
  elif [[ $message != *"$2"* ]]; then
    fail "blocked for another reason, expected '$2' ($message): $1"
  fi
}

# Allowed: building, testing, reading history and the working tree.
allowed 'cargo test -q'
allowed 'cargo clippy --all-targets -- -D warnings'
allowed 'cargo fmt --all --check'
allowed 'cargo test --release -- --nocapture'
allowed 'cargo +1.99.1 clippy --all-targets -- -D warnings'
allowed 'RUST_LOG=debug cargo test -q'
allowed 'RUST_BACKTRACE=1 cargo test'
allowed 'cd crates/dns-rs && cargo test'
allowed 'cargo test --test server && git diff --stat'
allowed 'cargo test -q 2>&1 | grep "test result" | head -3'
allowed 'git status --short'
allowed 'git diff HEAD -- crates/dns-rs/src/filter.rs'
allowed 'git log --oneline -5'
allowed 'git branch --list'
allowed 'git --no-pager diff --stat'
allowed 'git -C crates/dns-rs log --oneline -3'
allowed 'git show HEAD:crates/dns-rs/src/lib.rs | head -20'
allowed 'grep -rn "fn check" crates/'
allowed 'ls'

# Git commands that write history, discard work or reach remotes.
blocked 'git commit -m "refactor"' 'git commit'
blocked 'git push origin HEAD' 'git push'
blocked 'cargo test && git commit -am wip' 'git commit'
blocked 'git reset --hard HEAD~1' 'git reset'
blocked 'git clean -fdx' 'git clean'
blocked 'git checkout -- crates/dns-rs/src/lib.rs' 'git checkout'
blocked 'git restore crates/dns-rs/src/lib.rs' 'git restore'
blocked 'git stash' 'git stash'
blocked 'git rebase main' 'git rebase'
blocked 'git rm crates/dns-rs/src/wire.rs' 'git rm'
blocked 'git mv a b' 'git mv'
blocked 'git apply patch.diff' 'git apply'
blocked 'git switch -c other' 'git switch'
blocked 'git worktree add ../x' 'git worktree'
blocked 'git config user.name x' 'git config'
blocked 'git fetch origin' 'git fetch'
blocked 'git branch -D feature' 'git branch -D'
# Global options before the subcommand.
blocked 'git -C . commit -m x' 'git commit'
blocked 'git --no-pager push' 'git push'
blocked 'git -c user.name=a commit -m x' 'git option -c'
blocked 'git -c core.pager="sh -c x" log' 'git option -c'
# Git options that run a program or write a file, and their abbreviations.
blocked 'git diff --ext-diff' 'git --ext-diff'
blocked 'git diff --ext' 'git --ext'
blocked 'git log --output=/tmp/x' 'git --output'
blocked 'git log --out=/tmp/x' 'git --out'
blocked 'git diff -O/tmp/orderfile' 'git -O/tmp/orderfile'
blocked 'git show --open-files-in-pager=x' 'git --open'
blocked 'git grep -O"sh -c x" pattern' 'git grep'
# A dangling -C must block, not loop forever.
blocked 'git -C' 'git -C without a directory'
blocked 'git -C; git push' 'git -C without a directory'
blocked 'git -C crates' 'git without a subcommand'
blocked 'git' 'git without a subcommand'

# Cargo: dependencies, publishing, options that set a wrapper or linker.
blocked 'cargo add serde' 'cargo add'
blocked 'cargo remove regex' 'cargo remove'
blocked 'cargo update' 'cargo update'
blocked 'cargo publish' 'cargo publish'
blocked 'cargo +nightly add serde' 'cargo add'
blocked 'cargo --locked update' 'cargo update'
blocked 'cargo --config=build.rustc-wrapper="/tmp/x.sh" build' 'cargo --config'
blocked 'cargo build --config build.rustc-wrapper=/tmp/x.sh' 'cargo --config'
blocked 'cargo -Zunstable-options test' 'cargo -Z'
blocked 'cargo' 'cargo without a subcommand'

# Environment assignments that make git or cargo run programs.
blocked 'GIT_EXTERNAL_DIFF=/tmp/x.sh git diff' 'environment assignment GIT_EXTERNAL_DIFF'
blocked 'GIT_PAGER=/tmp/x.sh git log' 'environment assignment GIT_PAGER'
blocked 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0=x git log' 'environment assignment GIT_CONFIG_COUNT'
blocked 'RUSTC_WRAPPER=/tmp/x.sh cargo build' 'environment assignment RUSTC_WRAPPER'
blocked 'LD_PRELOAD=/tmp/x.so cargo test' 'environment assignment LD_PRELOAD'

# Programs outside the allowlist, however they are reached.
blocked 'gh pr create --fill' "'gh' is not on the allowlist"
blocked 'curl -s https://example.org' "'curl' is not on the allowlist"
blocked 'wget https://example.org/list' "'wget' is not on the allowlist"
blocked 'bash -c "git push"' "'bash' is not on the allowlist"
blocked 'sh -c "git commit"' "'sh' is not on the allowlist"
blocked 'env git push' "'env' is not on the allowlist"
blocked 'find . -name x -exec git commit \;' "'find' is not on the allowlist"
blocked 'rg --pre=/tmp/x.sh pattern' "'rg' is not on the allowlist"
blocked 'sort --compress-program=/tmp/x.sh file' "'sort' is not on the allowlist"
# Separators without spaces, subshells, command substitution.
blocked 'cargo test;git push' 'git push'
blocked 'cargo test&&git commit -am x' 'git commit'
blocked '(git commit -m x)' 'git commit'
blocked 'echo $(git push)' 'command substitution'
blocked 'echo `git push`' 'command substitution'

if [ "$failures" -eq 0 ]; then echo "all guard tests passed"; else exit 1; fi
