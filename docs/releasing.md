# Releasing

A tag named `v*` pushed to the repository starts the `Release` workflow
(`.github/workflows/release.yml`). Jobs run in this order, and a failure stops
the following ones:

| Job | What it does |
|---|---|
| `verify` | Checks that the tagged commit is on `main`, that the tag is `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-pre`, that the tag, the crate version (`crates/dns-rs/Cargo.toml`) and the chart `version` and `appVersion` (`charts/dns-rs/Chart.yaml`) name the same version, and that `CHANGELOG.md` has a `## [X.Y.Z]` section |
| `image` | Runs the `Image` workflow: publishes `ghcr.io/evanndev/dns-rs` with the tags `X.Y.Z` and `X.Y`; a pre-release gets only `X.Y.Z-pre`, so `X.Y` keeps pointing to the last stable release (see [Container image](container.md)) |
| `chart` | Packages the chart, pushes it to `oci://ghcr.io/evanndev/charts`, then renders what a user would pull. It waits for `image`, so a published chart never points to a missing image |
| `release` | Creates the GitHub release with the changelog section, the install commands and the chart `.tgz`. A version with a `-suffix` is marked as a pre-release |

## Cutting a release

1. In one pull request, set the same version in `crates/dns-rs/Cargo.toml`
   and in the `version` and `appVersion` of `charts/dns-rs/Chart.yaml`, and
   turn `## [Unreleased]` in `CHANGELOG.md` into `## [X.Y.Z]`.
2. After it is merged, tag the merge commit on `main` and push the tag:

   ```sh
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

## If a release fails partway

Jobs that succeeded stay published. Fix the cause and use **Re-run failed
jobs** on the same run: pushing the image and the chart again under the same
version replaces them with the same content. Never move or reuse a tag that
was published, even partly: users may already have pulled it. If the fix
needs a code change, release it as the next patch version.

## Version checks

CI runs `.github/scripts/check-release.sh` on every pull request, so the
three versions cannot drift apart before the tag. The first time a package is
published, GHCR may create it as private; make it public once in the package
settings.
