# dns-rs

A network-wide DNS sinkhole written in Rust — a modern take on Pi-hole, built to
run in a container and scale as stateless replicas.

> Status: phase 0 — caching DNS forwarder (UDP/TCP). Blocking comes next.

## Run

```sh
DNS_RS_LISTEN=127.0.0.1:15353 cargo run
dig @127.0.0.1 -p 15353 example.com
```

| Variable | Default | |
|---|---|---|
| `DNS_RS_LISTEN` | `0.0.0.0:53` | UDP and TCP listen address |
| `DNS_RS_UPSTREAM` | `1.1.1.1:53` | Upstream resolver (port defaults to 53) |
| `DNS_RS_UPSTREAM_TIMEOUT_MS` | `2000` | Upstream timeout |
| `DNS_RS_CACHE_SIZE` | `10000` | Maximum cached responses |
| `RUST_LOG` | `info` | Log filter |

## Develop

The project is test-driven: see [CLAUDE.md](CLAUDE.md) for the rules.

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```
