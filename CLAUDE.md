# dns-rs

A network-wide DNS sinkhole (Pi-hole alternative) in Rust, designed to run in a
container and, later, as multiple stateless replicas on Kubernetes.

## Non-negotiable rules

- **Test-driven development.** Every behaviour change starts with a failing test.
  Cycle: write the test, see it fail for the expected reason, make it pass with the
  simplest code, then refactor with the tests green. A PR that adds behaviour
  without a test that covers it is incomplete.
- **A test written after the code must be proven to bite**: break the code on
  purpose, watch the test fail, restore.
- **Tests describe behaviour, not implementation.** Name them after what the
  system does (`repeated_query_is_served_from_cache`), cite the RFC when a test
  encodes protocol rules.
- **No network in tests** except loopback sockets owned by the test itself.
- **Time is injected** (e.g. `now: Instant` parameters) so TTL logic is
  deterministic; no `sleep` in unit tests.
- The CI gate is: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
  (pedantic is on), `cargo test`. Run all three before proposing a change.
- Tests that capture `tracing` output go in their own test binary (one test):
  callsite interest is cached globally and makes them flaky next to others.
- No `unsafe`. No `unwrap()`/`expect()` outside tests: errors become DNS response
  codes (SERVFAIL, FORMERR…) or are logged; the server never panics on input.
- Code, comments and commit messages in English (Conventional Commits).

## Architecture

Single crate for now (`crates/dns-rs`), split into crates only when needed.

| Module | Role |
|---|---|
| `server` | UDP/TCP listeners, UDP truncation, malformed-input handling |
| `handler` | Request validation, blocking policy (`ArcSwap`), cache, upstream; reports the `Source` |
| `blocking` | Blocking modes and synthesized answers for blocked names |
| `cache` | TTL-aware response cache, negative caching (RFC 2308) |
| `filter` | Pure allow/deny engine: exact, subtree (`*.domain`), regex; allow wins |
| `lists` | Blocklist parsing: hosts, plain domains, ABP `\|\|domain^` / `@@` |
| `upstream` | `Upstream` trait; `DnsUpstream` = UDP with TCP fallback, anti-spoofing |
| `wire` | DNS over TCP length-prefix framing |
| `config` | TOML file (`DNS_RS_CONFIG`) with `DNS_RS_*` overrides; validation; builds the `Policy` |
| `sources` | Loads the configured blocklists (`file://`; `https://` to come) |
| `query_log` | One log line per query, target `dns_rs::query` |

Design constraint for every feature: a replica must stay **stateless** (config
and rules come from a shared source, cache is local, logs/metrics are exported)
so that N replicas can run behind one service.

## Roadmap

0. Forwarder with cache — done
1. Blocking: adlists, allow/deny (exact, suffix, regex), blocking modes — done
   for local lists; remaining: HTTP lists, hot reload, periodic refresh
2. Observability: query log, Prometheus metrics, REST API
3. Groups/clients, local records, conditional forwarding, DoH/DoT upstream, DNSSEC
4. Container image, control plane / data plane split, multi-replica
5. Kubernetes manifests, then CRDs
