# 0009. Agent permissions are enforced outside prompts

- Status: Accepted
- Date: 2026-10-17

## Context

Agents work on this repository with real permissions: the review and docs
agents run in GitHub Actions with a token that can push, and the
`rust-refactor` agent runs locally with a shell. A prompt rule such as
"never push" is an instruction, not a control: a model can misread it, and
untrusted input (a PR body, a downloaded file) can try to override it. The
first version of the refactor agent's guard used a deny list, which review
showed could be bypassed in 19 ways (`git -C . commit`, `cargo +nightly
add`, subshells…).

## Decision

Every limit that matters is enforced by something the agent cannot talk
its way around; prompts only explain the limits.

- `main` is protected by a ruleset with no bypass actor: no agent or person
  can push to it, only merge a pull request whose required checks pass.
- Agents that act in CI run only for people with write access; forks,
  drafts and Dependabot are skipped, and the docs agent ignores its own
  pushes.
- Local agents restricted beyond tool names use `PreToolUse` hooks with an
  allowlist that fails closed: `rust-refactor-guard.sh` allows cargo build,
  test and lint commands, read-only git and text tools, and blocks
  everything else, including when the hook itself fails. Its cases are
  tested in CI.
- Third-party agent prompts are read in full and adapted before adoption,
  with their tools narrowed, and credited in `THIRD_PARTY_NOTICES.md`.

## Consequences

- A hook is a guardrail, not a sandbox: an agent allowed to edit code and
  run `cargo test` executes that code. Containment against a hostile agent
  would need an isolated environment.
- Allowlists block some harmless commands (a `;` inside quotes splits the
  command); agents then ask, or use their file tools instead.
