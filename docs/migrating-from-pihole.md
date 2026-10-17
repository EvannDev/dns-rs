# Migrating from Pi-hole

dns-rs covers the DNS side of Pi-hole: blocking, local records and
conditional forwarding. There is no import tool: you translate your settings
into `dns-rs.toml` by hand. This page maps the concepts and lists what is
missing.

## Concept map

| Pi-hole | dns-rs | Notes |
|---|---|---|
| Adlists | `blocking.lists` | Hosts files, plain domain lists, `*.domain` and Adblock `\|\|domain^` rules from `https://`, `http://` or `file://`. See [Blocklists](blocklists.md) |
| Gravity update | `blocking.refresh` | Downloads again every `24h` by default, minimum `1m`; no command to run |
| Allowlist (exact) | `blocking.allow` | `example.com` is that name only, `*.example.com` includes subdomains. Allow always wins |
| Denylist (exact) | `blocking.deny` | Same syntax |
| Regex allowlist and denylist | `blocking.allow_regex`, `blocking.deny_regex` | Matched against the lowercase name without the trailing dot |
| Blocking mode | `blocking.mode` | `null` (default), `nxdomain`, `nodata`, `refused` |
| Local DNS records | `[local]` `records` | A and AAAA only; see [Configuration](configuration.md#local-records) |
| Conditional forwarding | `[[forward]]` | One table per domain; see [Configuration](configuration.md#conditional-forwarding) |
| Upstream DNS servers | `upstream.server` | A single plain DNS server, UDP with TCP fallback |
| Cache size | `cache.size` | Restart needed to change |
| Query log | One log line per query | Written to the process log, target `dns_rs::query`; see [Logging](logging.md) |
| Statistics | Prometheus metrics, `/api/v1/status` | See [Metrics and probes](metrics.md) |
| Testing a domain | `/api/v1/check/{domain}` | Needs the API token |

## Differences to know about

- **Bare domains block that name only**, as in Pi-hole. Lists written for
  wildcard blocking (OISD `domainswild2`, HaGeZi "wildcard domains") need
  `{ url = "...", wildcard = true }`. See
  [ADR 0006](adr/0006-blocklist-matching-semantics.md).
- **Regexes use the Rust `regex` syntax.** Look through your Pi-hole regexes
  and test them: a pattern that does not compile is a configuration error
  that names the key. dns-rs does not check compatibility with the regex
  flavor Pi-hole uses.
- **Local names are never blocked.** Local records are answered before
  blocking, and subdomains of a local name are not local.
- **Forwarded domains do not fall back to the upstream.** If the server of a
  `[[forward]]` fails, the client gets SERVFAIL, so private names do not
  leak ([ADR 0017](adr/0017-conditional-forwarding.md)).
- **Configuration is a file, not a database.** Edit `dns-rs.toml`: `[blocking]`,
  `[local]` and `[[forward]]` apply within 10 seconds or on `SIGHUP`. There
  is no admin UI that writes it
  ([ADR 0003](adr/0003-declarative-toml-configuration.md)).
- **Replicas are stateless.** There is no query database, so history and
  long-term statistics come from your log and metrics pipeline
  ([ADR 0002](adr/0002-stateless-replicas.md)).

## A translation example

```toml
[blocking]
mode = "null"
lists = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]
allow = ["analytics.example.com"]
deny = ["*.tracker.example"]
deny_regex = ['^ad[0-9]+\.']

[local]
records = [{ name = "nas.home.arpa", ip = "192.168.1.10" }]

[[forward]]
domain = "home.arpa"
server = "192.168.1.1"
```

Then follow [Getting started](getting-started.md) to run it, and check
queries with `dig` before switching your DHCP server over.

## What dns-rs does not do

Checked against the code and the decision records:

- **DHCP server.** Not implemented, by decision
  ([ADR 0004](adr/0004-no-dhcp-server.md)). Announce dns-rs as DNS server
  from your router or a separate DHCP server.
- **Web admin interface.** There is none. The HTTP port serves probes,
  metrics and a small read-only API (`/api/v1/check`, `/api/v1/status`).
- **Groups and per-client rules.** All clients get the same policy.
- **Encrypted upstreams.** `upstream.server` is plain DNS over UDP and TCP.
  DNS over HTTPS and DNS over TLS are not supported.
- **Several upstream servers.** `upstream.server` takes one address.
- **DNSSEC.** Not validated by dns-rs.
- **Reverse lookups and CNAMEs for local records.** Only A and AAAA records
  are supported in `[local]`.
- **Query history in the application.** Queries go to the log; there is no
  stored history or per-domain statistics beyond the metrics.

Several of these are on the roadmap in
[`CLAUDE.md`](https://github.com/EvannDev/dns-rs/blob/main/CLAUDE.md), but
planned work is not available.
