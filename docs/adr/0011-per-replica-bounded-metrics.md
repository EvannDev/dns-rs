# 0011. Per-replica metrics with bounded labels

- Status: Accepted
- Date: 2026-10-16

## Context

Replicas are stateless ([0002](0002-stateless-replicas.md)), so no replica
can hold the statistics of the others. Operators need query counts and
latency, and Kubernetes needs liveness and readiness probes. Record types
and response codes come from the network, so labels built from them could
grow without bound.

## Decision

- No in-process statistics such as top domains. Each replica exposes
  counters and Prometheus aggregates them.
- Metrics are served in the OpenMetrics text format at `/metrics` on an HTTP
  endpoint (`http.listen`, default `0.0.0.0:8080`) that also serves
  `/healthz` and `/readyz`.
- Label values come from fixed lists. Record types outside a list of common
  ones and unusual response codes share the value `other`; a request without
  a question has `type="none"`. A client cannot create series.
- `/readyz` returns `503` until the DNS sockets are bound and the first
  policy is installed, so Kubernetes routes no traffic too early.

## Consequences

- Per-domain or per-client views are not available from metrics; the query
  log carries them.
- Record types outside the list cannot be told apart in metrics.
- Changing `http.listen` needs a restart.
- The endpoint listens on all interfaces by default and has no
  authentication.
