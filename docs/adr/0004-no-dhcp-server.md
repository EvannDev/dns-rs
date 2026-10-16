# 0004. No DHCP server

- Status: Accepted
- Date: 2026-10-15

## Context

Pi-hole ships a DHCP server, inherited from dnsmasq, mostly for routers
that cannot announce another DNS server.

## Decision

dns-rs does not implement DHCP.

## Consequences

- DHCP leases are per-node state and need broadcast access to the local
  network, which conflicts with stateless replicas
  ([0002](0002-stateless-replicas.md)) and with running in Kubernetes.
- Users whose router cannot announce dns-rs as DNS server need a separate
  DHCP server.
