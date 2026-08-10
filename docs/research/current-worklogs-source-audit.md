# Private weekly-report source audit

This note records what is being extracted from the private weekly-report
workflow without copying its organization-specific data.

## Reusable behavior

The tracked Skill implementation contains separate fetchers for user events,
Issues and notes, merge requests, shared GitLab access, report scaffolding,
and report validation. The combined runner emits `events.json`, `issues.json`,
`mrs.json`, and `manifest.json` in an independent run directory.

The most valuable behavior to preserve is not the Chinese prose. It is the
relationship between collection and validation:

- events are a discovery source, with object-level backfill;
- Issues seen in event targets are included even when outside the topic Issue
  project;
- merge-request-associated pushes are separated before no-association output;
- pagination and retry limits become manifest state;
- report links must come from fetched object URLs;
- report generation refuses incomplete manifests;
- the final report is checked against the fetched MR, Issue, commit, branch,
  and section evidence.

## Coupling that must not cross the public boundary

The private implementation currently embeds two self-hosted GitLab instances,
a fixed team roster, a fixed topic/support project, a Chinese report template,
Asia/Shanghai Friday windows, and `glab` subprocess authentication. These are
valuable compatibility requirements for the private adapter, but they are not
the public engine's domain model.

The current branch partition also labels a branch “no MR” when its
`(host, project, source_branch)` key is absent from the current-window MR set.
The public extraction maps that observation to `change_association` and keeps
the stronger wording out of the canonical contract.

## Evidence boundary

Existing tests exercise window calculation, pagination cutoffs, cross-project
Issue backfill, push partitioning, report structure, link coverage, duplicate
prevention, and incomplete-manifest rejection. They are a behavior inventory,
not a public fixture set. Public tests must replace internal names and live
URLs with synthetic provider responses and explicit capability failures.

## Post-extraction branch audit (2026-08-10)

The audit compared the private extraction baseline with a bounded
post-extraction range on 2026-08-10. Seven later Skill changes were inspected.
Exact private branch names, paths, and commit coordinates are intentionally not
retained in the public tree.

Only two new ideas cross the public design boundary:

- evidence-bound Work item-to-Change request relations, with bare short
  references rejected and provider/repository scope preserved (ADR-0024);
- an optional separate Narrative Source Pack with an explicit source hierarchy
  and calibrated bounds (ADR-0025).

The other changes are not adopted as new public work. Duplicate summary-line
rejection is an Agent-output concern rather than an evidence contract. Private
MR/direct-push partitioning and merge/squash metadata overlap the public
core's existing Change association and resource/merge Assertion semantics;
copying their algorithms would import different event assumptions. User
deduplication is already enforced through provider-qualified actor identity and
does not justify another identity path. The private targeted-diff constants
remain research data, not public limits.
