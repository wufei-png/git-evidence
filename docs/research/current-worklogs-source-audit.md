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
