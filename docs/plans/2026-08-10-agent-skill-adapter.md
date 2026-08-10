# Agent Skill adapter implementation plan

Status: implemented locally; offline verification is recorded by the test suite.
Live-provider validation and external publication are outside this plan.

## Goal

Add a generic Agent entry point for Git Evidence while preserving the CLI and
Schema 0.3 as the sole evidence authority. Incorporate only the two accepted
future ideas found in the private weekly-report branch audit; do not implement
their core schemas in this slice.

## Delivery slices

1. Add `integrations/agent-skill/git-evidence/` with a concise Skill, UI
   metadata, a CLI contract reference, and a standard-library runner.
2. Add JSON diagnostics to `doctor` and `render`, and make structured error
   outcomes parseable without changing exit codes or artifact streams.
3. Have the runner create a private independent run directory, stop at the
   first failed stage, and emit a bounded receipt containing artifact identity,
   counts, coverage state, warnings, and retrieval modes.
4. Add transcript/eval fixtures and offline tests for collection, replay,
   warning visibility, failure closure, diagnostic stream routing, and private
   file modes.
5. Record the Agent boundary, future Work item relation boundary, and future
   Narrative Source Pack boundary in the domain language and ADRs.

## Accepted operational policy

- A generated TOML config is independent, temporary, mode `0600`, and never
  mutates a user's config. Saving it requires explicit authorization.
- The default run directory is independent and mode `0700`; Bundle, report, and
  receipt are mode `0600`. An explicit output directory must not already exist.
- `doctor` and `validate` put JSON diagnostics on stdout. `collect` and `render`
  keep artifacts in files/stdout and put JSON diagnostics on stderr.
- No direct provider access, enrichment, Bundle mutation, publication, commit,
  push, or live canary is part of the Agent adapter.

## Acceptance

- Existing text CLI behavior and exit meanings remain compatible.
- Every orchestrated outcome exposes one parseable `{status, issues, ...}` JSON
  document on the documented diagnostic stream.
- A failed doctor, collect, or validate stage prevents later stages.
- Receipts do not retain raw command output or credential values.
- Skill validation, unit tests, package checks, and isolated offline forward
  tests pass.
