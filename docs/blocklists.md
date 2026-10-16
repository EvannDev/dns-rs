# Blocklists

## Sources

`blocking.lists` takes entries of two forms:

```toml
[blocking]
lists = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  { url = "https://big.oisd.nl/domainswild2", wildcard = true },
  "file:///etc/dns-rs/lists/mine.txt",
]
```

Accepted schemes are `https://`, `http://` and `file://` with an absolute
path. Plain `http://` works but logs a warning: a tampered list could add
exceptions and unblock domains. A redirect from HTTPS to HTTP is refused.

Lists are loaded at startup and again every `blocking.refresh`, four at a
time. Each download has a 30 second timeout and a 64 MiB size limit. A list
that fails is skipped and logged, and DNS keeps working. A list that loaded
before and fails on refresh keeps blocking with its last valid version. See
[ADR 0007](adr/0007-bounded-fail-soft-blocklist-downloads.md).

## Formats

Each line may be a hosts entry, a plain domain, a `*.domain` wildcard or an
Adblock Plus rule. Comments and lines dns-rs does not understand are
ignored; the number of ignored lines is logged per list.

| Line | Blocks |
|---|---|
| `0.0.0.0 ads.example.com` (hosts) | `ads.example.com` only |
| `ads.example.com` | `ads.example.com` only |
| `*.example.com` | `example.com` and its subdomains |
| `\|\|example.com^` | `example.com` and its subdomains |
| `@@\|\|example.com^` | Allows `example.com` and its subdomains, overriding blocks |

Hosts boilerplate such as `localhost` is not treated as an entry.

Bare domains block that name only, as in Pi-hole. Lists meant to cover
subdomains too (OISD `domainswild2`, HaGeZi "wildcard domains") need
`wildcard = true` in the table form, which makes bare domains match their
subdomains as well. See [ADR 0006](adr/0006-blocklist-matching-semantics.md).

## Your own rules

`blocking.deny` and `blocking.allow` use the same `example.com` and
`*.example.com` syntax. `blocking.deny_regex` and `blocking.allow_regex` are
matched against the lowercase name without the trailing dot. Allow rules
always win over deny rules and lists.

## Blocking modes

`blocking.mode` sets what a blocked name receives. Synthesized answers have a
2 second TTL, so unblocking takes effect quickly.

| Mode | Answer |
|---|---|
| `null` (default) | `0.0.0.0` for A, `::` for AAAA, empty NOERROR for other types |
| `nxdomain` | NXDOMAIN |
| `nodata` | Empty NOERROR for every type |
| `refused` | REFUSED |
