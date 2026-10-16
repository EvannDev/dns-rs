# Changelog

All notable changes to dns-rs are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Caching DNS forwarder over UDP and TCP, a query log (target
  `dns_rs::query`), blocking with allow/deny rules, regexes and the blocking
  modes `null`, `nxdomain`, `nodata` and `refused`, local blocklists, and
  declarative TOML configuration with `DNS_RS_*` overrides (#2).
- Blocklists downloaded over HTTPS (or HTTP, with a warning), with a 30 s
  timeout, a 64 MiB size limit and four downloads at a time. A list that
  fails is skipped (#7).
- Wildcard lists: `{ url = "...", wildcard = true }` makes the bare domains of
  a list also block their subdomains (#8).
- Hot reload: the configuration file is read every 10 seconds (compared by
  content) and on `SIGHUP`. `[blocking]` changes apply without a restart;
  changes to `server.listen`, `upstream.*` and `cache.size` are logged once as
  needing a restart. An invalid or missing file is rejected and the previous
  configuration keeps working (#13).
- `blocking.refresh` (default `24h`, at least `1m`): blocklists are downloaded
  again on this schedule. A list that fails keeps its last valid version (#13).
- HTTP endpoint on `http.listen` (default `0.0.0.0:8080`, override
  `DNS_RS_HTTP_LISTEN`, restart-only): `/healthz`, `/readyz` and `/metrics`
  in the OpenMetrics text format, with `dns_rs_queries_total{source,rcode,type}`,
  the `dns_rs_query_duration_seconds{source}` histogram and
  `dns_rs_build_info{version}`. Label values are bounded (#15).
- State metrics: `dns_rs_blocking_rules`, `dns_rs_blocklist_rules{list}`,
  `dns_rs_blocklist_last_success_timestamp_seconds{list}`,
  `dns_rs_blocklist_failures_total{list,reason}`,
  `dns_rs_config_reloads_total{result}`, `dns_rs_config_valid` and
  `dns_rs_cache_entries`. The `list` label drops credentials, query string
  and fragment from list URLs (#17).

### Changed

- Configuration parse errors are one line with their position, for example
  `line 4, column 1: unknown field ...` (#13).
- `blocking.deny_regex` and `blocking.allow_regex` are also validated as a
  whole: a list whose patterns compile alone but are too large together is
  rejected at startup or on reload, naming the key (#13).
