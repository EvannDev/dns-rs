# 0014. The Helm chart takes the configuration as TOML text

- Status: Accepted
- Date: 2026-10-17

## Context

The chart needs to put `dns-rs.toml` in a ConfigMap. The natural Helm way is a
YAML map in `values.yaml` rendered with `toToml`. Helm parses numbers in
values as floats, so `toToml` writes `cache.size = 20000.0`, which dns-rs
rejects (checked with the binary, PR #22).

## Decision

- `values.config` is a string holding the TOML file, copied into the
  ConfigMap as is.
- `values.schema.json` declares `config` as a string, so a YAML map fails at
  `helm install`.
- The chart does not add a `checksum/config` annotation: dns-rs reloads
  `[blocking]` changes by itself
  ([ADR 0010](0010-hot-reload-by-polling-and-sighup.md)), so a configuration
  change does not restart pods.

## Consequences

- Operators write the same TOML as in [Configuration](../configuration.md);
  the example file can be pasted.
- Helm cannot override single keys with `--set`; override the whole text.
- Changes to restart-only settings are not applied until pods are restarted
  by hand.
