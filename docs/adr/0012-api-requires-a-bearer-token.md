# 0012. The API requires a bearer token

- Status: Accepted
- Date: 2026-10-17

## Context

The HTTP endpoint serves Kubernetes probes, Prometheus metrics and, since
`/api/v1/check`, an API that reveals the blocking policy: rules, regexes,
list labels and file paths. It listens on `0.0.0.0:8080` by default, which
the probes need (the kubelet connects to the pod IP), so the API was open to
anyone who could reach the port. `/api/v1/status` will reveal more.

Three options were weighed: keep the API open and document how to restrict
the port; make the API opt-in; protect it with a token.

## Decision

- Requests under `/api/` must carry `Authorization: Bearer <token>`. The
  scheme is case-insensitive; the token is compared in constant time for a
  given length.
- The token comes from `DNS_RS_API_TOKEN`, or from the file named by
  `http.api_token_file` (a mounted Kubernetes Secret); the variable wins.
  It never goes in the TOML file, which often ends up in a widely readable
  ConfigMap. It is at least 16 characters, read at startup, and never
  logged or printed.
- Without a token, the API is disabled (`403`): secure by default.
- `/healthz`, `/readyz` and `/metrics` stay open for probes and scrapes.

## Consequences

- Using the API requires setting a token first.
- Rotating the token needs a restart, like every `[http]` setting.
- `/metrics` remains readable without a token: it reveals traffic volumes
  and list labels, not the rules themselves.
