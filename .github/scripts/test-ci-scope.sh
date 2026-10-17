#!/usr/bin/env bash
# Tests for ci-scope.sh: which changed files let CI skip the build checks.
# Run: .github/scripts/test-ci-scope.sh
set -u
scope_script="$(cd "$(dirname "$0")" && pwd)/ci-scope.sh"
failures=0

# expect <name> <expected output> <changed files, one per line>
expect() {
  local output
  output=$(printf '%s' "$3" | "$scope_script" 2>&1)
  [ "$output" = "$2" ] || { echo "FAIL: $1: expected '$2', got '$output'"; failures=$((failures + 1)); }
}

expect "docs pages" "code=false" $'docs/configuration.md\ndocs/adr/0018-x.md\n'
expect "root markdown" "code=false" $'README.md\nCHANGELOG.md\nCLAUDE.md\n'
expect "site config" "code=false" $'book.toml\ndocs/SUMMARY.md\n'
expect "agent definitions" "code=false" $'.claude/agents/docs.md\n'
expect "rust code" "code=true" $'docs/configuration.md\ncrates/dns-rs/src/config.rs\n'
# A test parses it.
expect "example config" "code=true" $'dns-rs.example.toml\n'
# Packaged with the chart: chart checks must run.
expect "chart readme" "code=true" $'charts/dns-rs/README.md\n'
expect "markdown under the crate" "code=true" $'crates/dns-rs/README.md\n'
# Run by agent-guards, and they guard the agents.
expect "agent hooks" "code=true" $'.claude/hooks/devops-guard.sh\n'
expect "workflow" "code=true" $'.github/workflows/ci.yml\n'
expect "docs-like name outside docs" "code=true" $'scripts/docs/build.sh\n'
# Nothing to compare (or a failed diff): run everything.
expect "no files" "code=true" ""

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "all ci-scope tests passed"
