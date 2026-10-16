# 0005. Blocking runs before the cache, on an atomically swapped policy

- Status: Accepted
- Date: 2026-10-16

## Context

The blocking rules change at runtime: list refreshes, configuration
reloads. A change must apply at once, without restarting and without
slowing down queries.

## Decision

- The handler checks the blocking policy before the cache, so a new rule
  applies to the very next query, including names cached moments ago.
- The policy (compiled filter and blocking mode) is held in an `ArcSwap`:
  readers never lock, and a new policy replaces the old one atomically.
- Blocked answers are synthesized locally with a 2-second TTL, so that
  unblocking takes effect quickly on clients. The default mode, `null`,
  answers `0.0.0.0` / `::` to A / AAAA queries and an empty NOERROR to
  other types, so HTTPS/SVCB records cannot leak address hints. Other
  modes: `nxdomain`, `nodata`, `refused`.

## Consequences

- Each query pays one filter lookup before the cache: a hash lookup per
  label of the name, plus the regex set.
- Building a new policy happens off the query path and may take time on
  large lists; only the swap is instantaneous.
