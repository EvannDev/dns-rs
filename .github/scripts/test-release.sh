#!/usr/bin/env bash
# Tests for check-release.sh and release-notes.sh, on throwaway copies of
# the files they read.
# Run: .github/scripts/test-release.sh
set -u
scripts="$(cd "$(dirname "$0")" && pwd)"
failures=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

# A repository at version <crate> / <chart> / <appVersion>.
fixture() {
  rm -rf "$work/repo" && mkdir -p "$work/repo/crates/dns-rs" "$work/repo/charts/dns-rs"
  printf '[package]\nname = "dns-rs"\nversion = "%s"\n\n[dependencies]\nfoo = { version = "9.9.9" }\n' "$1" \
    >"$work/repo/crates/dns-rs/Cargo.toml"
  printf 'apiVersion: v2\nname: dns-rs\nversion: %s\nappVersion: "%s"\n' "$2" "$3" \
    >"$work/repo/charts/dns-rs/Chart.yaml"
  cat >"$work/repo/CHANGELOG.md" <<'MD'
# Changelog

## [Unreleased]

### Added

- Something not released yet.

## [0.2.0] - 2026-11-02

### Added

- Feature two.

### Fixed

- Bug two.

## [0.1.0] - 2026-10-17

- Feature one.

[0.2.0]: https://example.com/compare/v0.1.0...v0.2.0
MD
}

# passes <name> <command…>: exits 0
passes() {
  local name=$1 output
  shift
  output=$(cd "$work/repo" && "$@" 2>&1) || fail "$name: expected success, got: $output"
}

# fails <name> <reason> <command…>: exits non-zero, with <reason> in the message
fails() {
  local name=$1 reason=$2 output
  shift 2
  if output=$(cd "$work/repo" && "$@" 2>&1); then
    fail "$name: expected failure"
  elif [[ $output != *"$reason"* ]]; then
    fail "$name: failed for another reason, expected '$reason': $output"
  fi
}

# Versions agree: on every PR (no tag) and for a matching tag.
fixture 0.2.0 0.2.0 0.2.0
passes "versions agree" "$scripts/check-release.sh"
passes "tag matches" "$scripts/check-release.sh" v0.2.0
fails "tag differs" "tag v0.3.0 is version 0.3.0, but crates/dns-rs/Cargo.toml says 0.2.0" "$scripts/check-release.sh" v0.3.0
fails "tag without v" "not a release tag" "$scripts/check-release.sh" 0.2.0
fails "tag not semver" "not a release tag" "$scripts/check-release.sh" v0.2
fails "tag with junk" "not a release tag" "$scripts/check-release.sh" 'v0.2.0;rm'
fails "unreleased version tagged" "CHANGELOG.md has no section [0.3.0]" sh -c "sed -i.bak 's/0.2.0/0.3.0/' crates/dns-rs/Cargo.toml charts/dns-rs/Chart.yaml && $scripts/check-release.sh v0.3.0"

fixture 0.2.0 0.2.1 0.2.0
fails "chart version drifts" "charts/dns-rs/Chart.yaml version is 0.2.1" "$scripts/check-release.sh"
fixture 0.2.0 0.2.0 0.1.0
fails "appVersion drifts" "charts/dns-rs/Chart.yaml appVersion is 0.1.0" "$scripts/check-release.sh"

# Pre-releases are versions too.
fixture 1.0.0-rc.1 1.0.0-rc.1 1.0.0-rc.1
fails "pre-release needs its changelog section" "CHANGELOG.md has no section [1.0.0-rc.1]" "$scripts/check-release.sh" v1.0.0-rc.1
printf '\n## [1.0.0-rc.1] - 2026-12-01\n\n- Release candidate.\n' >>"$work/repo/CHANGELOG.md"
passes "pre-release tag" "$scripts/check-release.sh" v1.0.0-rc.1
notes=$(cd "$work/repo" && "$scripts/release-notes.sh" 1.0.0-rc.1)
[ "$notes" = "- Release candidate." ] || fail "notes of a pre-release: got '$notes'"

# Release notes: the version's section, without its heading.
fixture 0.2.0 0.2.0 0.2.0
notes=$(cd "$work/repo" && "$scripts/release-notes.sh" 0.2.0)
expected='### Added

- Feature two.

### Fixed

- Bug two.'
[ "$notes" = "$expected" ] || fail "notes of 0.2.0: got '$notes'"
notes=$(cd "$work/repo" && "$scripts/release-notes.sh" 0.1.0)
[ "$notes" = "- Feature one." ] || fail "notes of the last section: got '$notes'"
fails "notes of a missing version" "CHANGELOG.md has no section [9.9.9]" "$scripts/release-notes.sh" 9.9.9

if [ "$failures" -eq 0 ]; then echo "all release tests passed"; else exit 1; fi
