# Configuration

dns-rs reads a TOML file whose path is given by `DNS_RS_CONFIG`. Without it,
the defaults below apply. Every section and key is optional, and unknown keys
are rejected. See [`dns-rs.example.toml`](../dns-rs.example.toml) for a
commented file.

An invalid file or environment value stops dns-rs at startup with an error
naming the setting.

## Settings

| Key | Default | Environment override | Notes |
|---|---|---|---|
| `server.listen` | `0.0.0.0:53` | `DNS_RS_LISTEN` | UDP and TCP listen address |
| `upstream.server` | `1.1.1.1:53` | `DNS_RS_UPSTREAM` | Resolver to forward to; the port defaults to 53 |
| `upstream.timeout` | `2s` | `DNS_RS_UPSTREAM_TIMEOUT_MS` | Duration such as `500ms` or `2s` in the file, milliseconds in the variable; must be greater than zero |
| `cache.size` | `10000` | `DNS_RS_CACHE_SIZE` | Maximum number of cached responses |
| `blocking.mode` | `null` | none | `null`, `nxdomain`, `nodata` or `refused` |
| `blocking.lists` | `[]` | none | See [Blocklists](blocklists.md) |
| `blocking.deny` | `[]` | none | `example.com` or `*.example.com` |
| `blocking.allow` | `[]` | none | Same syntax; wins over deny rules and lists |
| `blocking.deny_regex` | `[]` | none | Regexes |
| `blocking.allow_regex` | `[]` | none | Regexes |

`RUST_LOG` sets the log filter (default `info`); see [Logging](logging.md).

## Blocking modes

| Mode | Answer for a blocked name |
|---|---|
| `null` | `0.0.0.0` for `A`, `::` for `AAAA`, an empty `NOERROR` for other types |
| `nxdomain` | `NXDOMAIN` |
| `nodata` | An empty `NOERROR` for every type |
| `refused` | `REFUSED` |

Synthesized answers have a TTL of 2 seconds, so a change of policy takes
effect quickly on clients.

## Behaviour notes

- Blocking is checked before the cache.
- Responses are cached for their record TTL, and negative answers are cached
  too. When the cache is full, expired entries are purged first, and a new
  response is dropped if the cache is still full.
- A request with a non-query opcode gets `NOTIMP`; one that does not carry
  exactly one question gets `FORMERR`. An upstream that cannot answer gives
  `SERVFAIL`.
- TCP connections idle for 10 seconds are closed.
- Rules are read once at startup. Restart dns-rs to apply changes; hot
  reload and periodic refresh are planned.
