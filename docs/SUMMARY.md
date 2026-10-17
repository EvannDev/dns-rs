# Summary

[Introduction](README.md)

# User guide

- [Getting started](getting-started.md)
- [Migrating from Pi-hole](migrating-from-pihole.md)
- [Configuration](configuration.md)
- [Blocklists](blocklists.md)

# Deployment

- [Container image](container.md)
- [Kubernetes](kubernetes.md)

# Operations

- [Metrics and probes](metrics.md)
- [Logging](logging.md)

# Project

- [Releasing](releasing.md)
- [Architecture decisions](adr/README.md)
  - [0001. Rust, with hickory-proto and our own server loop](adr/0001-rust-and-own-dns-server-loop.md)
  - [0002. Replicas are stateless](adr/0002-stateless-replicas.md)
  - [0003. Declarative TOML configuration](adr/0003-declarative-toml-configuration.md)
  - [0004. No DHCP server](adr/0004-no-dhcp-server.md)
  - [0005. Blocking runs before the cache, on an atomically swapped policy](adr/0005-blocking-before-cache-with-atomic-policy.md)
  - [0006. Blocklist matching semantics](adr/0006-blocklist-matching-semantics.md)
  - [0007. Bounded, fail-soft blocklist downloads](adr/0007-bounded-fail-soft-blocklist-downloads.md)
  - [0008. Test-driven development, enforced by CI and agents](adr/0008-test-driven-development-and-agent-review.md)
  - [0009. Agent permissions are enforced outside prompts](adr/0009-agent-permissions-enforced-outside-prompts.md)
  - [0010. Hot reload by polling and SIGHUP, blocking settings only](adr/0010-hot-reload-by-polling-and-sighup.md)
  - [0011. Per-replica metrics with bounded labels](adr/0011-per-replica-bounded-metrics.md)
  - [0012. The API requires a bearer token](adr/0012-api-requires-a-bearer-token.md)
  - [0013. The container listens on an unprivileged port](adr/0013-container-listens-on-an-unprivileged-port.md)
  - [0014. The Helm chart takes the configuration as TOML text](adr/0014-helm-config-as-toml-text.md)
  - [0015. The API token file is reloaded](adr/0015-api-token-file-is-reloaded.md)
  - [0016. Local records](adr/0016-local-records.md)
  - [0017. Conditional forwarding](adr/0017-conditional-forwarding.md)
