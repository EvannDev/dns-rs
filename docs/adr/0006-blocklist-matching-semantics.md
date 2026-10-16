# 0006. Blocklist matching semantics

- Status: Accepted
- Date: 2026-10-16

## Context

Public blocklists come in several formats with different meanings: hosts
files list exact names, Adblock-style lists use `||domain^` for a domain
and its subdomains, and "wildcard" domain lists such as OISD
`domainswild2` mean "this domain and its subdomains" without saying so in
each line.

## Decision

- A bare domain or hosts entry matches that exact name, as in Pi-hole.
- `*.example.com` (in lists and in the configuration) and `||example.com^`
  match the domain and all its subdomains.
- A list entry in the configuration can be a table with `wildcard = true`
  to make its bare and hosts domains cover their subdomains.
- Allow rules always win over deny rules. Lists may ship `@@||domain^`
  exceptions, which become allow rules.
- Adblock rules with options (`$third-party`…) are skipped: applying them
  without their options would block more than the author meant. Cosmetic
  filters are skipped too.
- Names with a single label (`com`, `*.com`, `||net^`) are rejected, so a
  typo can never block a whole top-level domain.
- Matching is case-insensitive and ignores the trailing dot; regexes are
  matched against the lowercase name without trailing dot.

## Consequences

- Operators must mark wildcard lists explicitly; otherwise such lists block
  less than intended. The example configuration shows how.
- Skipped lines are counted and logged per list, to help diagnose formats.
