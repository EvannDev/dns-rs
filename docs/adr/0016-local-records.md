# 0016. Local records

- Status: Accepted (amends 0010: `[local]` also applies live)
- Date: 2026-10-17

## Context

A home network has machines with fixed addresses (a NAS, a printer) that no
public resolver knows. Pi-hole answers such names from a "local DNS" list.
dns-rs replicas share no state (ADR 0002), so these records must come from
the same configuration as the blocking rules.

## Decision

- A `[local]` section lists records as name and address pairs:

  ```toml
  [local]
  ttl = 300 # seconds, the default
  records = [
    { name = "nas.home.arpa", ip = "192.168.1.10" },
    { name = "nas.home.arpa", ip = "fd00::10" },
  ]
  ```

  The address family gives the type: A for IPv4, AAAA for IPv6. Several
  records may share a name. Names are matched exactly and without regard
  to case; subdomains of a local name are not local. A name must have at
  least two labels, as blocklist domains do; `home.arpa` (RFC 8375) is
  the suffix meant for this.
- Local records are answered before blocking: a name the operator gave an
  address on purpose is not blocked by a list. The answer is authoritative
  (AA set), comes from dns-rs alone and is not cached.
- For a local name, A and AAAA queries get the addresses of that family,
  ANY gets all of them, and any other type gets an empty NOERROR (the name
  exists). A family with no record also gets an empty NOERROR, never
  NXDOMAIN, so clients do not conclude the name is gone.
- Queries answered locally are reported with the source `local` in the
  query log and metrics.
- `[local]` applies live, like `[blocking]` (ADR 0010): a reload replaces
  the records atomically; an invalid name or address rejects the whole
  configuration and the previous records stay in force.

## Consequences

- Reverse lookups (PTR for the addresses) and aliases (CNAME) are not
  answered yet; they can be built on the same records later.
- Single-label names (`nas`) are refused; clients usually append their
  search domain, so `nas` reaches dns-rs as `nas.home.arpa` when the DHCP
  server announces that domain.
