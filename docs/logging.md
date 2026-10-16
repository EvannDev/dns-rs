# Logging

dns-rs logs through `tracing`. `RUST_LOG` sets the filter; the default is
`info`.

## Query log

Each answered query produces one `info` line with the target
`dns_rs::query`:

| Field | Content |
|---|---|
| `client` | Client IP address |
| `name` | Queried name, or `-` if the request had no question |
| `type` | Record type, or `-` if the request had no question |
| `rcode` | Response code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, `FORMERR`, `NOTIMP`, or `RCODEn`) |
| `source` | `cache`, `upstream`, `blocked`, `rejected` (invalid or unsupported request) or `failed` (upstream could not answer) |
| `duration_us` | Time to answer, in microseconds |

To silence it: `RUST_LOG=info,dns_rs::query=off`.

## Other messages

| Level | Message | Meaning |
|---|---|---|
| info | `blocklist loaded` | Fields `list`, `deny`, `allow`, `skipped` |
| warn | `blocklist fetched over plain HTTP, prefer HTTPS` | An `http://` list is configured |
| warn | `cannot load blocklist, skipped` | The list failed; see the `error` field |
| warn | `upstream query failed` | The client gets `SERVFAIL` |
| info | `blocking policy loaded` | Fields `rules` (deny rules) and `mode` |
| info | `dns-rs started` | Fields `listen` and `upstream` |
| info | `shutting down` | Ctrl-C or SIGTERM received |
