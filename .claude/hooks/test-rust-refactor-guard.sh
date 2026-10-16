#!/usr/bin/env bash
# Tests for rust-refactor-guard.sh: each case is "<expected exit> <command>".
# Run: .claude/hooks/test-rust-refactor-guard.sh
set -u
guard="$(dirname "$0")/rust-refactor-guard.sh"
failures=0

check() {
  local expected=$1 command=$2 actual
  # perl's alarm stops a hanging guard: a hook killed by a timeout lets the
  # command run, so hanging is a failure (exit 142) like any other.
  jq -n --arg c "$command" '{tool_name: "Bash", tool_input: {command: $c}}' \
    | perl -e 'alarm 5; exec @ARGV' "$guard" >/dev/null 2>&1
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

# Bypasses found in review: global options before the subcommand.
check 2 'git -C . commit -m x'
check 2 'git -c user.name=a commit -m x'
check 2 'git --no-pager push'
check 2 'cargo +nightly add serde'
check 2 'cargo --locked update'
# Bypasses: subcommands missing from a deny list.
check 2 'git rm crates/dns-rs/src/wire.rs'
check 2 'git mv a b'
check 2 'git apply patch.diff'
check 2 'git switch -c other'
check 2 'git worktree add ../x'
check 2 'git config user.name x'
check 2 'git fetch origin'
# Bypasses: separators without spaces, subshells, command substitution.
check 2 'cargo test;git push'
check 2 'cargo test&&git commit -am x'
check 2 '(git commit -m x)'
check 2 'echo $(git push)'
check 2 'echo `git push`'
check 2 'bash -c "git push"'
check 2 'sh -c "git commit"'
check 2 'env git push'
check 2 'find . -name x -exec git commit \;'
# Git options that run arbitrary commands.
check 2 'git -c core.pager="sh -c x" log'
check 2 'git grep -O"sh -c x" pattern'
# Bare programs: empty argument lists must not crash the guard (bash 3.2,
# the macOS default, treats an empty array as unbound under `set -u`), and
# a crash must block rather than let the command through.
check 2 'cargo'
check 2 'git'
check 0 'ls'
# Environment assignments can run programs through git and cargo.
check 2 'GIT_EXTERNAL_DIFF=/tmp/x.sh git diff'
check 2 'GIT_PAGER=/tmp/x.sh git log'
check 2 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0=x git log'
check 2 'RUSTC_WRAPPER=/tmp/x.sh cargo build'
check 2 'LD_PRELOAD=/tmp/x.so cargo test'
check 0 'RUST_BACKTRACE=1 cargo test'
# Options that make cargo or text tools run programs.
check 2 'cargo --config=build.rustc-wrapper="/tmp/x.sh" build'
check 2 'cargo build --config build.rustc-wrapper=/tmp/x.sh'
check 2 'cargo -Zunstable-options test'
check 2 'rg --pre=/tmp/x.sh pattern'
check 2 'sort --compress-program=/tmp/x.sh file'
# A dangling -C must block, not loop forever.
check 2 'git -C'
check 2 'git -C; git push'
check 2 'git -C crates'
# Still allowed: common read-only and build forms.
check 0 'RUST_LOG=debug cargo test -q'
check 0 'cd crates/dns-rs && cargo test'
check 0 'git --no-pager diff --stat'
check 0 'git -C crates/dns-rs log --oneline -3'
check 0 'cargo +1.99.1 clippy --all-targets -- -D warnings'
check 0 'cargo test -q 2>&1 | grep "test result" | head -3'
check 0 'cargo test --release -- --nocapture'
check 0 'git show HEAD:crates/dns-rs/src/lib.rs | head -20'

if [ "$failures" -eq 0 ]; then echo "all guard tests passed"; else exit 1; fi
