# 0013. The container listens on an unprivileged port

- Status: Accepted
- Date: 2026-10-17

## Context

dns-rs defaults to port 53, which a non-root process cannot bind without
`CAP_NET_BIND_SERVICE` or a sysctl. The image runs as the `nonroot` user on a
distroless base (no shell, no package manager).

## Decision

- The image sets `DNS_RS_LISTEN=0.0.0.0:5353` and
  `DNS_RS_HTTP_LISTEN=0.0.0.0:8080`, so it runs without capabilities or
  sysctls.
- The port is published as 53: `docker run -p 53:5353/udp -p 53:5353/tcp`, or
  a Kubernetes Service with `port: 53` and `targetPort: 5353`.
- The binary's own default stays `0.0.0.0:53`; only the image changes it.

## Consequences

- Operators get port 53 from the runtime, not from extra privileges in the
  container.
- Environment variables override the configuration file, so `server.listen`
  and `http.listen` in a file mounted into the image are ignored unless the
  variables are overridden too.
