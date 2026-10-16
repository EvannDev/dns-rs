# 0001. Rust, with hickory-proto and our own server loop

- Status: Accepted
- Date: 2026-10-15

## Context

dns-rs replaces Pi-hole, whose core is a fork of dnsmasq written in C,
surrounded by Bash scripts. That stack is hard to evolve, to test and to
secure. The replacement must be memory-safe, fast enough to answer from
cache in microseconds, and easy to ship as a small static binary.

## Decision

- Write dns-rs in Rust on the tokio runtime, with `unsafe` code forbidden.
- Use `hickory-proto` only to parse and serialize DNS messages, and write
  our own UDP/TCP server loop, request handler and upstream client, so the
  pipeline (validation, blocking, cache, forwarding, logging) stays fully
  under our control and testable.

## Consequences

- Protocol details are our responsibility and are covered by tests that
  cite the RFCs: truncation (RFC 1035), EDNS (RFC 6891), TCP framing and
  pipelining (RFC 7766), negative caching (RFC 2308).
- The upstream client checks message IDs and questions itself, to resist
  spoofed responses.
- Encrypted upstreams (DoH, DoT) can come later from `hickory-resolver` or
  our own client, behind the same `Upstream` trait.
