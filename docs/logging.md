# Logging

dns-rs logs through `tracing` to standard output. `RUST_LOG` sets the filter
and defaults to `info`.

## Query log

Each answered query produces one `INFO` line under the target
`dns_rs::query`, with these fields:

| Field | Value |
|---|---|
| `client` | Client IP address |
| `name` | Queried name, with the trailing dot |
| `type` | Record type, for example `A` |
| `rcode` | `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`, or `RCODE<n>` |
| `source` | `cache`, `upstream`, `blocked`, `local` (a [local record](configuration.md#local-records)), `forwarded` (answered by a [forward server](configuration.md#conditional-forwarding)), `rejected` (FORMERR or NOTIMP) or `failed` (upstream or forward server could not answer, SERVFAIL) |
| `duration_us` | Time to answer, in microseconds |

Turn it off without silencing the rest: `RUST_LOG=info,dns_rs::query=off`.

## Operational messages

| Level | Message | Meaning |
|---|---|---|
| info | `dns-rs started` | Listening; shows `listen`, `http_listen` and `upstream` |
| info | `blocking policy loaded` | A policy is in force; shows the rule count and mode |
| info | `local records loaded` | At startup and when `[local]` changed; `names` is the number of local names |
| info | `forwarded domains loaded` | At startup and when `[[forward]]` changed; `domains` is the number of forwarded domains |
| info | `blocklist loaded` | Per list: `deny`, `allow` and `skipped` counts |
| warn | `cannot load blocklist, skipped` | A list failed; the cause is in `error` |
| warn | `keeping the previous version of the blocklist` | A refresh failed, the old content stays |
| warn | `blocklist fetched over plain HTTP, prefer HTTPS` | An `http://` list |
| info | `reload requested` | `SIGHUP` received |
| info | `refreshing blocklists` | The `blocking.refresh` schedule fired |
| info | `configuration reloaded` | A changed configuration was applied |
| warn | `configuration changes need a restart to apply` | Lists the restart-only settings that changed |
| error | `configuration rejected, keeping the previous one` | Invalid or unreadable file |
| warn | `upstream query failed` | The client receives SERVFAIL |
| info | `shutting down` | Ctrl-C or SIGTERM received |

Malformed queries and connection errors are logged at `debug`.
