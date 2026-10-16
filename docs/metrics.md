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

The histogram has 16 buckets from 50 µs, doubling up to about 1.6 s.

Label values:

- `source`: `cache`, `upstream`, `blocked`, `rejected` or `failed` (the same
  values as in the [query log](logging.md#query-log)).
- `rcode`: `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`,
  `REFUSED`, or `other`.
- `type`: `A`, `AAAA`, `ANY`, `CAA`, `CNAME`, `DNSKEY`, `DS`, `HTTPS`, `MX`,
  `NS`, `PTR`, `SOA`, `SRV`, `SVCB`, `TXT`, or `other`. A request without a
  question has `type="none"`.

The label sets are fixed, so a client cannot create new series. See
[ADR 0011](adr/0011-per-replica-bounded-metrics.md).

## Prometheus and Kubernetes

Each replica exposes its own counters; scrape every replica and let
Prometheus aggregate them (for example with `sum by (source)`). dns-rs keeps
no statistics such as top domains.

For Kubernetes, point the liveness probe at `/healthz` and the readiness
probe at `/readyz`, both on the `http.listen` port.
