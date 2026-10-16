# Architecture decision records

Decisions that shape dns-rs and would be hard to reverse, with the reasons
behind them. Accepted records are never rewritten; a new record supersedes
an old one.

| # | Decision | Status |
|---|---|---|
| [0001](0001-rust-and-own-dns-server-loop.md) | Rust, with hickory-proto and our own server loop | Accepted |
| [0002](0002-stateless-replicas.md) | Replicas are stateless | Accepted |
| [0003](0003-declarative-toml-configuration.md) | Declarative TOML configuration | Accepted |
| [0004](0004-no-dhcp-server.md) | No DHCP server | Accepted |
| [0005](0005-blocking-before-cache-with-atomic-policy.md) | Blocking runs before the cache, on an atomically swapped policy | Accepted |
| [0006](0006-blocklist-matching-semantics.md) | Blocklist matching semantics | Accepted |
| [0007](0007-bounded-fail-soft-blocklist-downloads.md) | Bounded, fail-soft blocklist downloads | Accepted |
| [0008](0008-test-driven-development-and-agent-review.md) | Test-driven development, enforced by CI and agents | Accepted |
| [0009](0009-agent-permissions-enforced-outside-prompts.md) | Agent permissions are enforced outside prompts | Accepted |
| [0010](0010-hot-reload-by-polling-and-sighup.md) | Hot reload by polling and SIGHUP, blocking settings only | Accepted |
| [0011](0011-per-replica-bounded-metrics.md) | Per-replica metrics with bounded labels | Accepted |
| [0012](0012-api-requires-a-bearer-token.md) | The API requires a bearer token | Accepted |
