# 0010. Hot reload by polling and SIGHUP, blocking settings only

- Status: Accepted; amended by [0016](0016-local-records.md) (`[local]` also applies live)
- Date: 2026-10-16

## Context

Rules must change without restarting dns-rs, including in containers where
the configuration is a mounted Kubernetes ConfigMap. Sockets, the upstream
client and the cache are created at startup. See also
[0007](0007-bounded-fail-soft-blocklist-downloads.md), which planned keeping
the last valid version of a list across refreshes.

## Decision

- The configuration file is read every 10 seconds and compared by content,
  so a ConfigMap swap counts as an edit. `SIGHUP` triggers an immediate
  reload; signals arriving while a reload is pending merge into it.
- Only `[blocking]` changes apply live. `server.listen`, `upstream.server`,
  `upstream.timeout` and `cache.size` are reported once as needing a restart
  and are not applied.
- An invalid or missing file is rejected, logged once, and the previous
  configuration stays in force.
- All lists are downloaded again every `blocking.refresh` (default `24h`,
  minimum `1m`, so providers do not see every replica download every few
  seconds). A list that fails keeps its last valid version. A configuration
  reload downloads only lists that are new; removed lists stop blocking.
- Lists are parsed and the policy is compiled on a blocking thread, and
  lists are shared through `Arc`, so building a policy copies no rules and
  does not delay queries.

## Consequences

- A change takes up to 10 seconds to apply unless `SIGHUP` is sent.
- Changing the listen address, upstream or cache size still requires a
  restart.
- Each replica downloads lists independently; a shared source is not
  implemented.
