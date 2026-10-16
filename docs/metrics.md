# Metrics and probes

dns-rs serves a small HTTP endpoint on `http.listen` (default
`0.0.0.0:8080`, override `DNS_RS_HTTP_LISTEN`). Changing the address needs a
restart. If the address cannot be bound, dns-rs exits at startup.

`/healthz`, `/readyz` and `/metrics` have no authentication. Metrics reveal
traffic volumes and the version, so on a shared network bind the endpoint to
loopback (`127.0.0.1:8080`) or, on Kubernetes, allow only the kubelet and
Prometheus to reach it with a NetworkPolicy. The API under `/api/` reveals
your blocking rules and requires a token (see [Authentication](#authentication)).

| Path | Response |
|---|---|
| `/healthz` | `200` with `ok` while the process runs (liveness) |
| `/readyz` | `200` with `ready` once the DNS sockets are bound and the first blocking policy is installed; `503` with `starting` before that (readiness) |
| `/metrics` | Metrics in the OpenMetrics text format (`application/openmetrics-text; version=1.0.0; charset=utf-8`) |
| `/api/v1/check/{domain}` | JSON explanation of the blocking decision for a domain (see [Check API](#check-api)) |

## Authentication

Requests under `/api/` must carry `Authorization: Bearer <token>`. The scheme
is case-insensitive. A missing or wrong token gets `401` with
`WWW-Authenticate: Bearer` and `{"error":"missing or invalid API token"}`.

The token comes from the `DNS_RS_API_TOKEN` environment variable or from the
file named by `http.api_token_file` (surrounding whitespace is trimmed, so a
mounted Secret works); the variable wins. It must have at least 16
characters, otherwise dns-rs exits at startup without printing the token. It
is not a TOML key, because the configuration file often ends up in a
ConfigMap. Changing `http.api_token_file` needs a restart.

Without a token the API is disabled: every request under `/api/` gets `403`,
and dns-rs logs `API disabled: set DNS_RS_API_TOKEN or http.api_token_file to
enable it` at startup. See [ADR 0012](adr/0012-api-requires-a-bearer-token.md).

```
curl -H "Authorization: Bearer $DNS_RS_API_TOKEN" http://localhost:8080/api/v1/check/example.com
```

## Metrics

| Metric | Type | Labels |
|---|---|---|
| `dns_rs_queries_total` | counter | `source`, `rcode`, `type` |
| `dns_rs_query_duration_seconds` | histogram | `source` |
| `dns_rs_build_info` | info | `version` |
| `dns_rs_blocking_rules` | gauge | none |
| `dns_rs_blocklist_rules` | gauge | `list` |
| `dns_rs_blocklist_last_success_timestamp_seconds` | gauge | `list` |
| `dns_rs_blocklist_failures_total` | counter | `list`, `reason` |
| `dns_rs_config_reloads_total` | counter | `result` |
| `dns_rs_config_valid` | gauge | none |
| `dns_rs_cache_entries` | gauge | none |

The histogram has 16 buckets from 50 µs, doubling up to about 1.6 s.

Label values:

- `source`: `cache`, `upstream`, `blocked`, `rejected` or `failed` (the same
  values as in the [query log](logging.md#query-log)).
- `rcode`: `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`,
  `REFUSED`, or `other`.
- `type`: `A`, `AAAA`, `ANY`, `CAA`, `CNAME`, `DNSKEY`, `DS`, `HTTPS`, `MX`,
  `NS`, `PTR`, `SOA`, `SRV`, `SVCB`, `TXT`, or `other`. A request without a
  question has `type="none"`.

- `list`: the blocklist as configured, as a `file://` path or a URL. For
  URLs, credentials, query string and fragment are removed, because the
  endpoint has no authentication and private list URLs may carry a token.
  When something was removed, the label ends with `#` and an 8-digit
  hexadecimal fingerprint of the full URL (for example
  `https://lists.example/hosts#1a2b3c4d`), so lists that differ only by
  their query string keep separate series. The fingerprint is the low 32
  bits of FNV-1a 64 of the full URL, so it is the same on every replica and
  build, and it does not reveal the removed part.
  Series of a list removed from the configuration are dropped on reload.
- `reason` (blocklist failures): `timeout`, `too_large`, `status` or
  `failed`.
- `result` (config reloads): `applied` or `rejected`.

The label sets are fixed or come from the configuration, so a client cannot
create new series. See
[ADR 0011](adr/0011-per-replica-bounded-metrics.md).

## State metrics

| Metric | Meaning |
|---|---|
| `dns_rs_blocking_rules` | Deny rules in the blocking policy in force |
| `dns_rs_blocklist_rules` | Deny rules from each list, as last loaded. A list that fails to refresh keeps its last valid rules |
| `dns_rs_blocklist_last_success_timestamp_seconds` | Unix time of the last successful load of each list; alert when it gets old |
| `dns_rs_blocklist_failures_total` | Failed list loads, by reason |
| `dns_rs_config_reloads_total` | Configuration changes `applied` or `rejected`. Unchanged files are not counted, and the same rejection is counted once |
| `dns_rs_config_valid` | `1` while the configuration file, as last read, is valid; `0` after an invalid or missing file. It returns to `1` as soon as a valid file is read, even one identical to the applied configuration |
| `dns_rs_cache_entries` | Responses held in the cache, read at each scrape |

## Check API

`GET /api/v1/check/{domain}` (token required) answers "why is this domain blocked, or not?"
using the blocking policy in force, including after a reload. Nothing is
queried upstream.

```
GET /api/v1/check/ad.doubleclick.net
{"domain":"ad.doubleclick.net","blocked":false,"mode":"null",
 "denied_by":{"kind":"exact","rule":"ad.doubleclick.net","origin":"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts#f2b086a8"},
 "allowed_by":{"kind":"exact","rule":"ad.doubleclick.net","origin":"config:allow"}}
```

| Field | Meaning |
|---|---|
| `domain` | The name as sent in the path |
| `blocked` | `true` when a deny rule matches and no allow rule does (allow wins) |
| `mode` | The configured `blocking.mode`: `null`, `nxdomain`, `nodata` or `refused` |
| `denied_by` | The deny rule that matched, or `null` |
| `allowed_by` | The allow rule that matched, or `null` |

A rule is an object with three fields:

- `kind`: `exact`, `subtree` or `regex`.
- `rule`: the rule as written, for example `ads.example.com`,
  `*.example.com` or a regular expression.
- `origin`: where the rule comes from: `config:deny`, `config:allow`,
  `config:deny_regex`, `config:allow_regex`, or the label of the blocklist
  (the same label as the `list` metric label, without credentials, query
  string or fragment).

When several rules match, the most specific one is reported: an exact rule,
then the closest subtree rule, then the first regex. Configuration rules are
loaded before lists, so a rule found both in the configuration and in a list
is attributed to the configuration; a rule present in several lists keeps its
first origin.

The name is lowercased and a trailing dot is ignored. A name that a client
could not query (characters other than letters, digits, `-` and `_`, an empty
label, a label over 63 bytes, or a name over 253 bytes) gets `400` with
`{"error":"..."}`.

## Prometheus and Kubernetes

Each replica exposes its own counters; scrape every replica and let
Prometheus aggregate them (for example with `sum by (source)`). dns-rs keeps
no statistics such as top domains.

For Kubernetes, point the liveness probe at `/healthz` and the readiness
probe at `/readyz`, both on the `http.listen` port.
