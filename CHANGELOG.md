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
  and fragment from list URLs and then ends with a fingerprint of the full
  URL, so lists differing only by query string stay apart (#17).
- List URLs that do not parse (for example `https://exa mple.org`) are
  rejected when the configuration is validated (#17).
- `GET /api/v1/check/{domain}` on the HTTP endpoint explains a blocking
  decision as JSON: `blocked`, `mode`, and the deny and allow rules that
  matched, each with its kind, text and origin (`config:deny`, `config:allow`,
  `config:deny_regex`, `config:allow_regex` or the list label). Invalid names
  get `400` (#18).
- The API (`/api/*`) requires `Authorization: Bearer <token>` (scheme
  case-insensitive). The token comes from `DNS_RS_API_TOKEN` or from the file
  named by `http.api_token_file` (restart-only); the variable wins. It must
  have at least 16 characters and is validated at startup. Without a token
  the API is disabled and answers `403`; a missing or wrong token gets `401`.
  `/healthz`, `/readyz` and `/metrics` stay open (#19).
- `GET /api/v1/status` reports the replica state as JSON: version, blocking
  mode and rule count, configuration validity, cache entries and, for each
  configured list, its label, rules, last success and last failure. A failure
  shows its reason (and HTTP status) but never the error message, which may
  contain a list URL token. Requires the API token (#20).
- Container image `ghcr.io/evanndev/dns-rs` for amd64 and arm64, on a
  distroless base running as `nonroot`. DNS listens on 5353 and HTTP on 8080
  inside the container (`DNS_RS_LISTEN`, `DNS_RS_HTTP_LISTEN`). Published from
  `main` (`edge`, `sha-<commit>`) and `v*` tags (`X.Y.Z`, `X.Y`) (#21).
- Helm chart `charts/dns-rs`: a Deployment of stateless replicas (2 by
  default), a ConfigMap from `config` (TOML text), a DNS Service (53, UDP and
  TCP), an HTTP Service (8080), hardened pods and `values.schema.json`.
  `[blocking]` changes reach running pods through hot reload, without a
  restart; upstream and cache settings are values passed as environment
  variables, so a change rolls every replica. Not published to a chart repository yet (#22).

- Helm chart production features: an API token from `api.token` or
  `api.existingSecret` (mounted as a file), a PodDisruptionBudget, topology
  spread across nodes, an optional ServiceMonitor and an optional ingress
  NetworkPolicy (#23).
- `DNS_RS_API_TOKEN_FILE` sets `http.api_token_file` from the environment (#23).
- Helm chart: `helm test` queries the DNS Service over UDP and TCP; configure
  it with `tests.enabled`, `tests.image` and `tests.query` (#26).

- Releases: a `v*` tag on `main` publishes the image (`X.Y.Z` and `X.Y`),
  the Helm chart as an OCI artifact (`oci://ghcr.io/evanndev/charts/dns-rs`)
  and a GitHub release with the changelog section and the chart package.
  Tags with a suffix (`v1.0.0-rc.1`) become pre-releases. CI checks that the
  crate, chart and `appVersion` versions stay equal (#27).

### Changed

- The API token file is read again on each configuration poll and on `SIGHUP`:
  rotating the token no longer needs a restart. An invalid or missing file
  keeps the previous token (#23).
- dns-rs binds its HTTP server before loading blocklists: `/healthz` answers
  while lists load and `/readyz` stays `503` until the first policy is
  installed (#22).
- The container image declares `USER 65532:65532` instead of the name
  `nonroot`, so Kubernetes can verify `runAsNonRoot` (#22).

- Configuration parse errors are one line with their position, for example
  `line 4, column 1: unknown field ...` (#13).
- `blocking.deny_regex` and `blocking.allow_regex` are also validated as a
  whole: a list whose patterns compile alone but are too large together is
  rejected at startup or on reload, naming the key (#13).
