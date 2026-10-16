# Metrics and probes

dns-rs serves a small HTTP endpoint on `http.listen` (default
`0.0.0.0:8080`, override `DNS_RS_HTTP_LISTEN`). Changing the address needs a
restart. If the address cannot be bound, dns-rs exits at startup.

The endpoint has no authentication. Everything it serves is read-only, but
metrics reveal traffic volumes and the version. On a shared network, bind it
to loopback (`127.0.0.1:8080`) or, on Kubernetes, allow only the kubelet and
Prometheus to reach it with a NetworkPolicy.

| Path | Response |
|---|---|
| `/healthz` | `200` with `ok` while the process runs (liveness) |
| `/readyz` | `200` with `ready` once the DNS sockets are bound and the first blocking policy is installed; `503` with `starting` before that (readiness) |
| `/metrics` | Metrics in the OpenMetrics text format (`application/openmetrics-text; version=1.0.0; charset=utf-8`) |

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

## Prometheus and Kubernetes

Each replica exposes its own counters; scrape every replica and let
Prometheus aggregate them (for example with `sum by (source)`). dns-rs keeps
no statistics such as top domains.

For Kubernetes, point the liveness probe at `/healthz` and the readiness
probe at `/readyz`, both on the `http.listen` port.
