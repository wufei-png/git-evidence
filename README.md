# Git Evidence

Evidence-first engineering activity reports across GitHub, GitLab, and Gitee.

Git Evidence is a provider-neutral engine that collects, normalizes, validates,
and renders reproducible engineering activity reports with source-linked
evidence and explicit coverage boundaries.

It is not an engineering productivity scoring system or a generic AI
summarizer: every publishable claim must remain tied to source evidence and an
explicit coverage boundary.

This project is in the implementation and contract-hardening stage. Its
product is a standalone CLI/library that collects platform data, normalizes it
into a versioned evidence bundle, validates coverage, and renders reproducible
Markdown or JSON reports. Agent skills and scheduled jobs are optional
adapters around that core, not the source of truth.

## Why it exists

The useful distinction is not “AI-generated weekly summary”. It is whether a
report can answer:

- Which source objects support each claim?
- Which projects, users, and time ranges were actually covered?
- Did pagination, permissions, rate limits, or platform limits leave gaps?
- Is a commit associated with a change request, or is that association merely
  unknown?

The project therefore fails closed for publishable output. It may leave an
evidence bundle and diagnostics for repair, but it must not turn incomplete
collection into a confident report.

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
PYTHONPATH=src python3 -m git_evidence providers
PYTHONPATH=src python3 -m git_evidence doctor --config config.example.yml
PYTHONPATH=src python3 -m git_evidence collect --config config.example.yml \
  --output evidence/bundle.json
PYTHONPATH=src python3 -m git_evidence validate fixtures/example_bundle.json
PYTHONPATH=src python3 -m git_evidence render fixtures/example_bundle.json \
  --config config.example.yml --profile project-first --output report.md
```

The example configuration names `GITHUB_TOKEN`; set that environment variable
before `collect`, or remove `token_env` for an intentionally anonymous public
run.

Actor names remain anonymous by default. To render a name, set
`report.display_actor_names: true` and provide its full canonical actor ID in
`report.actor_labels`; pass the same configuration to `render --config`.

GitLab, GitHub, and Gitee each have an experimental resource-API collector in
this slice. They are exercised with recorded responses and emit explicit
coverage for the optional activity/ref surface; live provider behavior is not
advertised as production-complete yet. A blocked collection still writes its
bundle when `--output` is provided, but exits non-zero so diagnostics can be
repaired before rendering.

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
a complete push/ref claim.

## Status

The P2 contract slice includes the provider registry, collection/report config
split, fail-closed privacy publication gate, provenance-linked coverage
failures, private cache replay, and bounded transport budgets. No provider is
advertised as production-complete: this checkout's offline fixtures and
renderer tests do not constitute a live-provider canary, and no current live
canary is claimed.
A provider becomes supported only when its capability declaration, contract
fixtures, coverage behavior, live replay gates, and report replay tests pass.
