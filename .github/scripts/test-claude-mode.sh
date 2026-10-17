#!/usr/bin/env bash
# Tests for claude-mode.sh, on throwaway git repositories.
# Run: .github/scripts/test-claude-mode.sh
set -u
mode_script="$(cd "$(dirname "$0")" && pwd)/claude-mode.sh"
failures=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

# expect <name> <action> <before> <expected output>
expect() {
  local output
  output=$("$mode_script" "$2" "$3" origin/main 2>&1)
  [ "$output" = "$4" ] || fail "$1: expected '$4', got '$output'"
}

commit() {
  echo "$1" >>"$1"
  git add "$1" && git commit -qm "$1"
}

cd "$work" || exit 1
git init -q -b main origin-repo && cd origin-repo || exit 1
git config user.email t@example.com && git config user.name t
commit base
git clone -q . ../pr && cd ../pr || exit 1
git config user.email t@example.com && git config user.name t
git switch -qc feature
commit feature-1
first=$(git rev-parse HEAD)

expect "opened PR" opened "" "mode=full"
expect "ready for review" ready_for_review "" "mode=full"
expect "reopened PR" reopened "$first" "mode=full"

commit feature-2
expect "new commit" synchronize "$first" "mode=incremental
range=$first..HEAD"

# The base moves on and is merged into the PR: nothing new to review.
(cd ../origin-repo && commit main-2)
git fetch -q origin
before=$(git rev-parse HEAD)
git merge -q --no-edit origin/main
expect "merge of the base" synchronize "$before" "mode=skip"

# A merge of the base plus a commit of the PR's own: review the commit.
commit feature-3
expect "merge then commit" synchronize "$before" "mode=incremental
range=$before..HEAD"

# Force-push: the old head is not an ancestor any more.
old=$(git rev-parse HEAD)
git reset -q --hard "$first"
commit rewritten
expect "force-push" synchronize "$old" "mode=full"
expect "unknown reviewed head" synchronize 0123456789abcdef0123456789abcdef01234567 "mode=full"
expect "no review yet" synchronize "" "mode=full"

if [ "$failures" -eq 0 ]; then echo "all claude-mode tests passed"; else exit 1; fi
