# 0008. Test-driven development, enforced by CI and agents

- Status: Accepted
- Date: 2026-10-15

## Context

dns-rs is developed with AI agents writing, reviewing and documenting code.
Without a strict discipline, behaviour drifts and tests stop proving
anything.

## Decision

- Every behaviour change starts with a failing test. A test written after
  the code must be proven to bite by breaking the code on purpose.
- Tests assert the reason of a failure, not just that it fails; time is
  injected; tests use no network except loopback.
- Tests that capture `tracing` output live alone in their own test binary,
  because tracing caches callsite interest globally.
- `main` is protected: changes go through pull requests that must pass
  formatting, clippy (pedantic, warnings as errors) and tests on Linux and
  macOS. The Rust toolchain is pinned in `rust-toolchain.toml`.
- A Claude agent reviews every pull request against `CLAUDE.md`, and a
  documentation agent (`.claude/agents/docs.md`) keeps the documentation
  true to the code.

## Consequences

- The rules live in `CLAUDE.md`, read by both humans and agents.
- Agent reviews are advisory; the required checks are the CI jobs.
