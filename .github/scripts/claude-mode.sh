#!/usr/bin/env bash
# How much of a pull request the Claude agents look at, printed as
# `key=value` lines for $GITHUB_OUTPUT:
#   mode=full                    the whole PR: opened, ready, reopened, no
#                                review yet, or history rewritten since
#   mode=incremental, range=…    only the commits since the last review
#   mode=skip                    since then, the PR only merged its base
#
# The last reviewed SHA comes from the review's own marker, not from the
# push event: GitHub drops superseded pending runs, so the previous push
# is not always the last one reviewed.
#
# Usage: claude-mode.sh <event action> <last reviewed SHA or ""> <base ref>
# Tests: .github/scripts/test-claude-mode.sh
set -u
action=$1 reviewed=$2 base=$3

if [ "$action" != synchronize ] ||
  ! git cat-file -e "$reviewed^{commit}" 2>/dev/null ||
  ! git merge-base --is-ancestor "$reviewed" HEAD; then
  echo "mode=full"
elif [ -z "$(git rev-list --no-merges "$reviewed..HEAD" "^$base")" ]; then
  echo "mode=skip"
else
  echo "mode=incremental"
  echo "range=$reviewed..HEAD"
fi
