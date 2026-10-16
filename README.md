# dns-rs

A network-wide DNS sinkhole written in Rust — a modern take on Pi-hole, built to
run in a container and scale as stateless replicas.

> Status: caching DNS forwarder with blocking (blocklists over HTTPS or from
> files, allow/deny rules, regexes) that reloads its configuration and
> refreshes blocklists while running. It serves Prometheus metrics and Kubernetes probes over HTTP.
> Next: more metrics, a REST API.

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
| `DNS_RS_HTTP_LISTEN` | `http.listen` |
| `DNS_RS_UPSTREAM` | `upstream.server` |
| `DNS_RS_UPSTREAM_TIMEOUT_MS` | `upstream.timeout` |
| `DNS_RS_CACHE_SIZE` | `cache.size` |
| `RUST_LOG` | Log filter, default `info`; `dns_rs::query=off` silences the query log |

## Reload without restart

dns-rs reads the configuration file every 10 seconds (by content, so a
Kubernetes ConfigMap update counts as an edit) and immediately on `SIGHUP`.
Changes to `[blocking]` apply at once. `server.listen`, `http.listen`, `http.api_token_file`, `upstream.server`,
`upstream.timeout` and `cache.size` need a restart: dns-rs logs
"configuration changes need a restart to apply" once and keeps the running
values. An invalid or missing file is rejected (logged once) and the previous
configuration keeps working.

Blocklists are downloaded again every `blocking.refresh` (default `24h`,
minimum `1m`). A list that fails keeps its last valid version. On a
configuration reload only new lists are downloaded; removed lists stop
blocking.

See the [documentation](docs/README.md) for the configuration reference,
blocklist formats, metrics and the log format.

## Develop

The project is test-driven: see [CLAUDE.md](CLAUDE.md) for the rules.

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
