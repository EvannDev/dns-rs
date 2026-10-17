# Configuration

dns-rs reads one TOML file, named by the `DNS_RS_CONFIG` environment
variable. Without it, the defaults below apply. Every section and key is
optional, and an unknown key is an error. The commented reference is
[`dns-rs.example.toml`](../dns-rs.example.toml).

Durations use the humantime format (`2s`, `500ms`, `24h`).

## Settings

| Key | Default | Meaning |
|---|---|---|
| `server.listen` | `0.0.0.0:53` | Address of the UDP and TCP listeners |
| `http.listen` | `0.0.0.0:8080` | Address of the HTTP endpoint for probes and metrics (see [Metrics and probes](metrics.md)) |
| `http.api_token_file` | none | File holding the API token, for example a mounted Secret; `DNS_RS_API_TOKEN` wins over it. Without a token the API is disabled (see [Authentication](metrics.md#authentication)) |
| `upstream.server` | `1.1.1.1:53` | Resolver queries are forwarded to; the port defaults to 53 |
| `upstream.timeout` | `2s` | Upstream timeout; must be greater than zero |
| `cache.size` | `10000` | Maximum number of cached responses |
| `blocking.mode` | `null` | `null`, `nxdomain`, `nodata` or `refused` (see [Blocklists](blocklists.md#blocking-modes)) |
| `blocking.refresh` | `24h` | How often blocklists are downloaded again; at least `1m` |
| `blocking.lists` | none | Blocklist URLs, or `{ url = "...", wildcard = true }` tables |
| `blocking.deny` | none | Domains to block: `example.com` or `*.example.com` |
| `blocking.allow` | none | Same syntax; always wins over `deny`, regexes and lists |
| `blocking.deny_regex` | none | Regexes of names to block |
| `blocking.allow_regex` | none | Regexes of names to allow |
| `local.ttl` | `300` | TTL of local answers, in seconds |
| `local.records` | none | `{ name = "nas.home.arpa", ip = "192.168.1.10" }` tables answered by dns-rs itself (see [Local records](#local-records)) |

## Local records

`local.records` lists names dns-rs answers itself, as Pi-hole's local DNS
does ([ADR 0016](adr/0016-local-records.md)):

```toml
[local]
ttl = 300
records = [
  { name = "nas.home.arpa", ip = "192.168.1.10" },
  { name = "nas.home.arpa", ip = "fd00::10" },
]
```

- The address family gives the type: A for IPv4, AAAA for IPv6. A name may
  have several records; ANY returns all of them.
- Names match exactly and without regard to case, and the answer keeps the
  name as the client wrote it. Subdomains of a local name are not local.
- Local records are answered before blocking, so a list never blocks them.
  The answer is authoritative (AA) and uses neither the upstream nor the
  cache.
- For a local name, other types (MX, TXT...) and a family with no record get
  an empty NOERROR, never NXDOMAIN.
- These queries have the source `local` in the [query log](logging.md#query-log)
  and the [metrics](metrics.md).
- Not supported yet: PTR (reverse lookups) and CNAME.

## Environment variables

| Variable | Overrides |
|---|---|
| `DNS_RS_CONFIG` | Path of the TOML file |
| `DNS_RS_LISTEN` | `server.listen` |
| `DNS_RS_HTTP_LISTEN` | `http.listen` |
| `DNS_RS_API_TOKEN` | API token, at least 16 characters; wins over `http.api_token_file`. Not a TOML key: keep the token out of the file |
| `DNS_RS_API_TOKEN_FILE` | `http.api_token_file`. The Helm chart uses it because it refuses `[http]` in the reloaded configuration |
| `DNS_RS_UPSTREAM` | `upstream.server` |
| `DNS_RS_UPSTREAM_TIMEOUT_MS` | `upstream.timeout`, in milliseconds |
| `DNS_RS_CACHE_SIZE` | `cache.size` |
| `RUST_LOG` | Log filter, default `info` (see [Logging](logging.md)) |

Overrides are applied after the file is read, at startup and on every reload.

## Validation

dns-rs refuses to start on an invalid configuration. The error is one line
naming the problem, with its position for TOML syntax errors, for example
`invalid config file: line 4, column 1: unknown field ...`.

Beyond syntax, these are rejected:

- `upstream.timeout` of zero.
- `blocking.refresh` under one minute.
- A `local.records` name that is not a domain of at least two labels (the
  error names `local.records`), or an address that does not parse.
- A `deny` or `allow` entry that is not a domain or `*.domain`.
- A regex that does not compile, or a regex list whose patterns are too
  large together (each list is compiled as one set). The error names the key.
- A list source that is not `file:///absolute/path`, `https://` or `http://`, or an
  `http(s)://` URL that does not parse (for example `https://exa mple.org`).

## Reload without restart

The file is read every 10 seconds, compared by content, and immediately on
`SIGHUP`. Changes to `[blocking]` and `[local]` apply at once. Changes to `server.listen`,
`http.listen`, `http.api_token_file`, `upstream.server`, `upstream.timeout` and `cache.size` need a restart: dns-rs
logs `configuration changes need a restart to apply` once, listing the
settings, and keeps the running values. An invalid or missing file is
rejected (logged once as `configuration rejected, keeping the previous one`)
and the previous configuration keeps working.

The API token file is read again at the same moments, so a rotated token
applies without a restart (see [Authentication](metrics.md#authentication)).

Blocklists are downloaded again every `blocking.refresh`. On a configuration
reload only lists that are new are downloaded; lists that were removed stop
blocking. An invalid `[local]` rejects the whole file, so the previous
records stay in force. See [ADR 0010](adr/0010-hot-reload-by-polling-and-sighup.md).
