# 0003. Declarative TOML configuration

- Status: Accepted
- Date: 2026-10-16

## Context

Pi-hole is configured through its web UI and stores the result in a local
database, which fits one instance but not several replicas, nor GitOps.
dns-rs needs one configuration that every replica reads, which can live in
version control and later in a Kubernetes ConfigMap or custom resources.

## Decision

- The configuration is one TOML file, named by `DNS_RS_CONFIG`. Without
  it, defaults apply.
- A few `DNS_RS_*` environment variables override single values, which is
  convenient in containers.
- Validation is strict: unknown keys, invalid regexes, malformed domain
  patterns and unsupported list sources stop startup with a message naming
  the field. A typo must never silently fall back to a default.
- `dns-rs.example.toml` documents every option, and a test checks that it
  stays valid.

TOML was preferred to YAML for the quality of its Rust tooling.

## Consequences

- There is no write API for the configuration yet; changes go through the
  file. A write API may come later on top of the same model.
- Hot reload must keep the last valid configuration when the file becomes
  invalid (planned).
