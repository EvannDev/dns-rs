#!/usr/bin/env bash
# Prints the CHANGELOG.md section of <version>, without its heading, as the
# GitHub release notes. Run from the repository root.
#
# Usage: release-notes.sh <version>
# Tests: .github/scripts/test-release.sh
set -euo pipefail
version=$1

grep -qF "## [$version]" CHANGELOG.md || {
  echo "CHANGELOG.md has no section [$version]" >&2
  exit 1
}
# From the heading to the next section or the link references, then
# without the blank lines around it.
awk -v heading="## [$version]" '
  index($0, heading) == 1 { inside = 1; next }
  inside && (/^## \[/ || /^\[[^]]*\]: /) { exit }
  inside { print }
' CHANGELOG.md | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'
