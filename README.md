# Git Evidence

Evidence-first engineering activity reports across GitHub, GitLab, and Gitee.

Git Evidence is a provider-neutral engine that collects, normalizes, validates,
and renders reproducible engineering activity reports with source-linked
evidence and explicit coverage boundaries.

It is not an engineering productivity scoring system or a generic AI
summarizer: every render-eligible activity claim must remain tied to source evidence and an
explicit coverage boundary.

This project is in the implementation and contract-hardening stage. Its
product is a standalone CLI/library that collects platform data, normalizes it
into a versioned JSON evidence bundle, validates coverage, and renders
reproducible Markdown reports. Agent skills and scheduled jobs are optional
adapters around that core, not the source of truth.

## Why it exists

The useful distinction is not “AI-generated weekly summary”. It is whether a
report can answer:

- Which source objects support each claim?
- Which projects, users, and time ranges were actually covered?
- Did pagination, permissions, rate limits, or platform limits leave gaps?
- Is a commit associated with a change request, or is that association merely
  unknown?

The project therefore fails closed when core resource evidence is incomplete or
unverifiable. It may leave an evidence bundle and diagnostics for repair, while
an otherwise complete core report may remain render-eligible with explicit
warnings for optional activity/ref gaps. Render eligibility is not permission
to disclose the sensitive Bundle or its report; visibility approval is an
external operator decision.

## Current decisions

- The public project lives independently from the private weekly-report
  workspace.
- GitLab, GitHub, and Gitee are first-class provider targets behind one
  provider-neutral contract.
- No private organization workflow or compatibility profile is part of the
  public project.
- A provider may use a platform CLI internally, but the public core contract is
  provider-based and does not require `glab`.
- The default `project-first` report profile is accompanied by selectable
  `timeline`, `release-focused`, and opt-in `actor-summary` profiles.
- The public baseline is Apache-2.0 with synthetic or anonymous fixtures only.
- Comment bodies and private organization data are excluded by default.
- The default model has no productivity score, ranking, or performance claim.
- Provider descriptors and instance factories are registered together and
  unknown provider kinds fail closed.
- Collection and report configuration are independently validated; the legacy
  single-file loader remains available for compatibility.
- Actors are anonymous by default, credentials are environment-only, and
  source URLs are retained only after auth material is redacted.

See [CONTEXT.md](CONTEXT.md), the [accepted ADRs](docs/adr/), and the current
[MVP plan](docs/plans/2026-08-01-open-source-mvp.md).

## Quick start

The current slice can replay a bundle offline or collect an explicitly scoped
bundle from configured providers:

```bash
python -m pip install .
git-evidence --version
git-evidence providers
git-evidence doctor --config config.example.yml
git-evidence collect --config config.example.yml \
  --output evidence/bundle.json
git-evidence validate fixtures/example_bundle.json
git-evidence migrate fixtures/example_bundle.json \
  --output evidence/bundle-0.2.json
git-evidence render fixtures/example_bundle.json \
  --config config.example.yml --profile project-first --output report.md
```

`validate` and `collect` accept `--diagnostics-format json` for structured
automation output. JSON mode emits one document per diagnostic stream with a
stable `status`, an `issues` array, and collection summary counts; it never
mixes prose into that document. Exit statuses are stable: `0` success (possibly with
non-blocking warnings), `1` validation/render-eligibility failure, `2`
configuration/input/I/O failure, and `3` a core provider-group collection
failure. Bundle, report, and cache files use atomic replacement and mode
`0600`; stdout remains available when no output path is supplied.

`collect` emits the strict Schema 0.2 contract directly, including its retained
plan, unique invocation, response-level Retrieval records, typed Assertions,
and recomputable Bundle digest. Schema 0.1 remains readable for one
compatibility window; converting a stored 0.1 artifact is always an explicit
migration that records the source artifact digest. See the
[0.1 to 0.2 migration guide](docs/migration/0.1-to-0.2.md).

The v0.1 CLI status word `publishable` is legacy wording for render eligibility
only. A successful collect, validate, or render command does not approve
disclosure of the sensitive Bundle or its report.

The example configuration names `GITHUB_TOKEN`; set that environment variable
before `collect`, or remove `token_env` for an intentionally anonymous public
run.

Actor names remain anonymous by default. To render a name, set
`report.display_actor_names: true` and provide its full canonical actor ID in
`report.actor_labels`; pass the same configuration to `render --config`.

GitLab, GitHub, and Gitee each have an experimental resource-API collector in
this slice. They are exercised with recorded responses and emit explicit
coverage for the optional activity/ref surface; live provider behavior is not
advertised as production-complete yet. A collection with incomplete core
resources still writes its bundle when `--output` is provided, but exits
non-zero so diagnostics can be repaired before rendering. Ordinary optional
activity/ref malformed, typed, transport, and capability failures remain
render-eligible and appear in `coverage.warnings` and the rendered coverage
section; an optional `privacy_violation` remains fail-closed with a fatal
ledger entry.

The public replay inputs live under
[`fixtures/provider_contract/`](fixtures/provider_contract/). They contain
synthetic responses only and are the minimum contract examples for all three
adapters; they are not claims that the live APIs behave identically across
instances or versions.

The live replay boundary and offline verification checklist are documented in
[`docs/testing/live-e2e.md`](docs/testing/live-e2e.md) and the
[`offline/CI/live-canary contract`](docs/runbook/offline-ci-live-canary.md).
Live bundles are kept outside the public fixture set.

With `include_activity_api: true`, GitLab and GitHub may add bounded push/ref
observations marked `incomplete`; Gitee remains explicitly `unsupported` for
that optional surface. No provider is allowed to turn these observations into
a complete push/ref claim, and every non-supported optional observation carries
an `optional_coverage_warning` entry. Ordinary optional warnings do not close a
complete core gate; a privacy violation is the explicit security exception and
does close render eligibility.

## Status

The P2 contract slice includes the provider registry, collection/report config
split, fail-closed privacy render gate, provenance-linked coverage
failures, private cache replay, strict cache status/header handling, duplicate
record diagnostics, and bounded transport budgets. No provider is advertised
as production-complete: this checkout's offline fixtures and renderer tests do
not constitute a live-provider canary, and no current live canary is claimed.
A provider becomes supported only when its capability declaration, contract
fixtures, coverage behavior, live replay gates, and report replay tests pass.
