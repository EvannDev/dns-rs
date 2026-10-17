# 0017. Conditional forwarding

- Status: Accepted
- Date: 2026-10-17

## Context

Home and office networks have names that only a local server knows: the
router's DHCP leases under `home.arpa` or `lan`, an Active Directory domain,
the reverse zone of the LAN (`1.168.192.in-addr.arpa`). Public resolvers
answer NXDOMAIN for them. Pi-hole calls the fix "conditional forwarding":
queries for a domain go to a given server instead of the upstream.

Local records (ADR 0016) cover a few fixed names; they cannot follow DHCP
leases, which only the router knows.

## Decision

A `[[forward]]` table sends a domain to its own server:

```toml
[[forward]]
domain = "home.arpa"
server = "192.168.1.1"   # port 53 unless given
```

- **Matching.** A rule covers its domain and every name under it,
  label by label and without case. When rules nest, the longest domain
  wins (`lab.home.arpa` over `home.arpa`). A domain may have one label
  (`lan`); the root may not (that is `upstream.server`).
- **Order.** Local records, then blocking, then the cache, then the
  forward server or the upstream. Forwarding chooses where a query goes;
  it does not exempt a name from blocking.
- **Transport.** The same client as the upstream: UDP with TCP
  fallback, the same anti-spoofing checks and `upstream.timeout`.
- **Cache.** Forwarded answers are cached like others. When the rules
  change, the cache is emptied: an NXDOMAIN cached from the public
  upstream before a rule was added would otherwise hide the new rule for
  as long as its negative TTL.
- **Hot reload.** `[[forward]]` applies live, like `[blocking]` and
  `[local]` (ADR 0010); an invalid table rejects the whole configuration
  and the previous rules stay in force.
- **Validation.** A domain given twice (case-insensitive) is an error, so
  which server wins is never a matter of order.
- **Observability.** Answers from a forward server are reported with the
  source `forwarded` in the query log and in metrics.

## Consequences

- One server per domain, no failover between several. A list of servers
  can be added later without changing the matching rules.
- Emptying the cache on a rule change costs a burst of upstream queries
  on that replica; rules change rarely, and only on reload. A query in
  flight during the change may still cache an answer from the previous
  server, for its TTL at most.
- A forward server that fails gives SERVFAIL; the query is not retried
  on the upstream, which must not learn private names.
- Replicas stay stateless (ADR 0002): rules come from the shared
  configuration, and each replica's cache is its own.
- The forward server must be reachable from every replica. The chart's
  NetworkPolicy filters ingress only, so it needs no change.
- Chart users set `[[forward]]` in the TOML configuration, as they do
  `[blocking]` and `[local]` (ADR 0014).
