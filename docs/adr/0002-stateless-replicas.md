# 0002. Replicas are stateless

- Status: Accepted
- Date: 2026-10-15

## Context

Pi-hole keeps everything in each instance: configuration, compiled lists,
query history. Running several instances means running several unrelated
Pi-holes. dns-rs targets containers and Kubernetes, where a DNS service
should run as several identical replicas behind one service.

## Decision

A replica keeps no state another replica would need:

- configuration and rules come from a shared, declarative source
  ([0003](0003-declarative-toml-configuration.md));
- the DNS cache is local to each replica and only an optimization;
- query logs and, later, metrics are exported (stdout, Prometheus) rather
  than stored in the replica.

The planned evolution is a split between a data plane (stateless
resolvers) and a control plane (API, list downloads, aggregated
statistics), both from the same binary.

## Consequences

- Every feature is reviewed against this constraint.
- Features that need per-node state, such as DHCP, are out of scope
  ([0004](0004-no-dhcp-server.md)).
- Per-client rules depend on the client IP: behind a load balancer it must
  be preserved (for example `externalTrafficPolicy: Local` on Kubernetes).
- Rate limiting, when added, will be approximate per replica.
