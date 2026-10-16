# 0007. Bounded, fail-soft blocklist downloads

- Status: Accepted
- Date: 2026-10-16

## Context

Blocklists are downloaded from third-party servers. DNS resolution must not
depend on their availability, and their content is untrusted: a list can be
huge, slow, or tampered with in transit.

## Decision

- Lists are loaded concurrently, at most 4 at a time, each within 30
  seconds and 64 MiB. The size limit applies to the bytes received, not
  only to `Content-Length`, and to `file://` lists too.
- Any failure (HTTP status, timeout, network error, size) skips that list
  only and is logged with its cause; DNS starts regardless.
- Redirects are followed at most 5 times and never from HTTPS down to
  plain HTTP. Plain `http://` lists log a warning: a tampered list could
  inject `@@` exceptions and unblock domains.
- HTTP uses `reqwest` with `rustls` (no OpenSSL). A TLS stack that cannot
  start is a fatal startup error, since it means a broken environment.

## Consequences

- Peak memory while loading stays bounded by the concurrency and size
  limits.
- On a list failure, the last valid version of that list should be kept
  across refreshes (planned with periodic refresh).
