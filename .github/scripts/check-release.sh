#!/usr/bin/env bash
# The crate, the chart and its appVersion carry one version. Given a tag
# (vMAJOR.MINOR.PATCH[-pre]), also checks that it names that version and
# that CHANGELOG.md has its section. Run from the repository root.
#
# Usage: check-release.sh [tag]
# Tests: .github/scripts/test-release.sh
set -euo pipefail

die() {
  echo "$*" >&2
  exit 1
}

crate=$(sed -n 's/^version = "\(.*\)"$/\1/p' crates/dns-rs/Cargo.toml | head -1)
chart=$(sed -n 's/^version: *//p' charts/dns-rs/Chart.yaml | head -1)
app=$(sed -n 's/^appVersion: *"\{0,1\}\([^"]*\)"\{0,1\} *$/\1/p' charts/dns-rs/Chart.yaml | head -1)
[ -n "$crate" ] || die "crates/dns-rs/Cargo.toml has no version"
[ "$chart" = "$crate" ] ||
  die "charts/dns-rs/Chart.yaml version is $chart, but crates/dns-rs/Cargo.toml says $crate"
[ "$app" = "$crate" ] ||
  die "charts/dns-rs/Chart.yaml appVersion is $app, but crates/dns-rs/Cargo.toml says $crate"

if [ $# -ge 1 ]; then
  tag=$1
  [[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?)$ ]] ||
    die "$tag is not a release tag (vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-pre)"
  version=${BASH_REMATCH[1]}
  [ "$version" = "$crate" ] ||
    die "tag $tag is version $version, but crates/dns-rs/Cargo.toml says $crate"
  grep -qF "## [$version]" CHANGELOG.md || die "CHANGELOG.md has no section [$version]"
fi
echo "version $crate"
