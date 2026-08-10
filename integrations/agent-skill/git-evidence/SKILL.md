---
name: git-evidence
description: Collect, validate, and render evidence-backed engineering activity reports with the Git Evidence CLI. Use for a natural-language request to report GitHub, GitLab, or Gitee activity; to replay or diagnose a Schema 0.3 evidence bundle; or to explain collection coverage, warnings, retrieval mode, and report artifacts without inventing provider facts.
---

# Git Evidence

Translate reporting intent into an explicit Git Evidence run, delegate evidence
semantics to the core CLI, and return a bounded receipt. Keep disclosure and
provider access under the operator's control.

Read [references/cli-contract.md](references/cli-contract.md) before executing
the runner or interpreting its receipt.

## Choose the workflow

Use exactly one input mode:

- Use `--bundle` for an existing Schema 0.3 Bundle. This is offline replay and
  performs `validate → render`; do not require provider credentials.
- Use `--collection-config` for a new or cached collection. This performs
  `doctor → collect → validate → render`.

When the desired mode is unclear, ask the user to choose offline Bundle replay
or a new/cache-enabled collection first. Never request a Bundle and collection
scope as simultaneous requirements.

Do not treat “last week,” “my work,” a provider name, or the current repository
as sufficient authority for live collection. If required scope is absent, ask
for it before creating a collection configuration.

## Resolve collection intent

Before a new collection, resolve and repeat back:

- the exact start and end instants plus IANA timezone;
- provider instance and repository allowlist;
- actor allowlist, including an explicit empty allowlist when all actors are in
  scope;
- live versus cache-enabled retrieval expectations;
- report profile, language, identity display, and source-URL policy.

Use natural-language dates only to propose exact instants for confirmation.
Never broaden repository or actor scope implicitly.

## Prepare private inputs and outputs

For collection, create an independent temporary TOML file with mode `0600`.
Never edit a user's existing configuration. Put credential **environment
variable names** in `token_env`; never copy credential values into the
configuration, command, Bundle, receipt, or report. Show the normalized
non-secret scope before running. Remove the generated configuration after the
receipt is available; save it only when the user explicitly asks.

Let the runner create its default private run directory (`0700`). Use
`--run-dir` only for an explicit output location; it must name a path that does
not already exist. Bundle, report, and receipt files remain private (`0600`). Do
not copy, commit, publish, upload, or disclose any artifact as part of this
workflow.

## Execute the core workflow

Run the standard-library orchestrator relative to this Skill:

```bash
python scripts/run_git_evidence.py \
  --collection-config /private/path/run.toml
```

For offline replay:

```bash
python scripts/run_git_evidence.py \
  --bundle /private/path/bundle.json \
  --profile project-first --language zh-CN
```

Use `--report-config` only when offline rendering needs explicit report privacy
or actor-label settings. The runner invokes the installed `git-evidence`
executable without a shell. `--executable` exists for an explicit local binary
or test environment, not for a compound command.

## Interpret and report

Fail closed at the first non-zero stage. Do not render after a failed doctor,
collect, or validate stage. Do not suppress warnings or equate an empty result
with complete coverage.

Return only the receipt's:

- artifact paths;
- plan, invocation, and Bundle identities;
- Assertion and Evidence counts;
- render eligibility, bounded Coverage warning and group-failure projections
  with total/blocking counts and truncation state;
- retrieval modes and per-stage statuses.

Explain that `render_eligible` means the Bundle can be deterministically
rendered; it does not authorize disclosure. Obtain separate authorization for
any external write or audience-visible publication.

## Preserve the core boundary

Do not call provider APIs directly, scrape additional issue or change-request
bodies, infer provider completeness, rewrite a Bundle, create unsupported
Issue-to-Change Request relationships, or synthesize a Narrative Source Pack.
Those semantics belong to future evidence-bound core contracts. The runner may
only sequence CLI commands, check structured diagnostics, and summarize bounded
artifact metadata.
