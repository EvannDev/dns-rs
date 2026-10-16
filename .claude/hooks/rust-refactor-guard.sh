#!/usr/bin/env bash
# PreToolUse hook of the rust-refactor agent: enforces, outside the prompt,
# that it never writes Git history or remote state, never changes
# dependencies and never reaches the network. Exit code 2 blocks the call.
# Tests: .claude/hooks/test-rust-refactor-guard.sh
set -u

command=$(jq -r '.tool_input.command // empty')

block() {
  echo "Blocked by the rust-refactor guard: $1. Leave the change in the working tree for the caller." >&2
  exit 2
}

# Word boundaries: match `git commit` anywhere in a compound command.
pattern() { printf '(^|[;&|[:space:]])%s([[:space:]]|$)' "$1"; }

for sub in commit push reset clean checkout restore stash rebase merge cherry-pick tag am revert; do
  grep -qE "$(pattern "git $sub")" <<<"$command" && block "git $sub rewrites history or discards work"
done
grep -qE '(^|[;&|[:space:]])git branch[[:space:]](.*[[:space:]])?-[dDmM]' <<<"$command" && block "git branch deletion or rename"
grep -qE "$(pattern gh)" <<<"$command" && block "gh acts on GitHub"
for sub in add remove rm update publish install yank; do
  grep -qE "$(pattern "cargo $sub")" <<<"$command" && block "cargo $sub changes dependencies or publishes"
done
for tool in curl wget; do
  grep -qE "$(pattern "$tool")" <<<"$command" && block "$tool reaches the network"
done
exit 0
