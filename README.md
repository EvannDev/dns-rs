# dns-rs

A network-wide DNS sinkhole written in Rust — a modern take on Pi-hole, built to
run in a container and scale as stateless replicas.

> Status: caching DNS forwarder with blocking (local blocklists, allow/deny
> rules, regexes). Next: HTTP blocklists and hot reload.

## Run

```sh
cp dns-rs.example.toml dns-rs.toml   # then edit it
DNS_RS_CONFIG=dns-rs.toml DNS_RS_LISTEN=127.0.0.1:15353 cargo run --release
dig @127.0.0.1 -p 15353 example.com
```

All settings live in the TOML file; see [`dns-rs.example.toml`](dns-rs.example.toml).
A few can be overridden by environment variables, handy in containers:

| Variable | Overrides |
|---|---|
| `DNS_RS_CONFIG` | Path of the TOML file (defaults apply without it) |
| `DNS_RS_LISTEN` | `server.listen` |
| `DNS_RS_UPSTREAM` | `upstream.server` |
| `DNS_RS_UPSTREAM_TIMEOUT_MS` | `upstream.timeout` |
| `DNS_RS_CACHE_SIZE` | `cache.size` |
| `RUST_LOG` | Log filter, default `info`; `dns_rs::query=off` silences the query log |

## Develop

The project is test-driven: see [CLAUDE.md](CLAUDE.md) for the rules.

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
