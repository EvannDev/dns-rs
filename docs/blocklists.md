# Blocklists

Blocklists are listed under `blocking.lists` and loaded once at startup.

```toml
[blocking]
lists = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  { url = "https://big.oisd.nl/domainswild2", wildcard = true },
  "file:///etc/dns-rs/lists/mine.txt",
]
```

## Sources

| Form | Notes |
|---|---|
| `https://…` | Preferred |
| `http://…` | Accepted, but logs a warning: a tampered list could add `@@` exceptions and unblock domains |
| `file:///absolute/path` | The path must be absolute |

Any other scheme is a configuration error.

Downloads are limited so that a bad list cannot take dns-rs down:

| Limit | Value |
|---|---|
| Timeout per list | 30 seconds |
| Maximum size | 64 MiB |
| Lists loaded at once | 4 |
| Redirects followed | 5 at most; a redirect from HTTPS to HTTP is refused |

A list that fails any of these, or returns an HTTP error status, is skipped
with a warning (`cannot load blocklist, skipped`). DNS keeps working with the
other lists.

## Syntaxes

| Line | Blocks |
|---|---|
| `0.0.0.0 ads.example.com` (hosts) | `ads.example.com` only |
| `ads.example.com` (plain) | `ads.example.com` only, unless the list is marked `wildcard = true` |
| `*.example.com` | `example.com` and its subdomains |
| `\|\|example.com^` (Adblock) | `example.com` and its subdomains |
| `@@\|\|example.com^` | Allows `example.com` and its subdomains |

Lines that are not domain rules, such as Adblock cosmetic filters, are
skipped; the `skipped` field of the `blocklist loaded` log line counts them.
For lists that name a domain once and mean its subdomains too (OISD
`domainswild2`, HaGeZi "wildcard domains"), use the table form with
`wildcard = true`.

## Allow and deny rules

`blocking.deny` and `blocking.allow` take `example.com` (that name only) or
`*.example.com` (the name and its subdomains). `deny_regex` and `allow_regex`
are matched against the lowercase name without the trailing dot.

A name that matches an allow rule, from the configuration or from a list, is
never blocked.
