# Open-source MVP plan

Status: P2 contract gates implemented locally; live canary remains unverified.

The first collection slice is now implemented: canonical bundle loading,
fail-closed validation, four deterministic offline report profiles, a
three-provider registry, and experimental resource-API collectors exercised by
public synthetic replay fixtures. The P2 contract also separates collection
and report config validation and makes anonymous actor display, credential
redaction, and auth-safe evidence URLs publication gates. No live provider
canary is claimed by offline replay.

The configuration-driven `collect` command now groups explicit repository
targets by provider/instance and merges them into one canonical bundle. A
collection with a required-source failure remains available as diagnostics but
cannot be rendered as a publishable report.

The optional activity slice is also wired: GitLab and GitHub can emit bounded
push/ref observations with conservative association states; Gitee remains
explicitly unsupported for activity/ref collection.

The offline/CI versus live-canary acceptance boundary is recorded in
[`docs/runbook/offline-ci-live-canary.md`](../runbook/offline-ci-live-canary.md).

## Product promise

Build a provider-neutral, evidence-first engineering activity report engine
that can collect from GitLab, GitHub, and Gitee, preserve provenance, expose
coverage limits, and render a report only when deterministic validation allows
publication.

The differentiator is multi-platform evidence correctness, not the number of
summary templates or the presence of an LLM.

## Accepted direction

- Standalone project: `git-evidence`.
- First-class provider targets: GitLab, GitHub, and Gitee.
- Public core boundary: provider contract plus adapters; no private
  organization profile or compatibility infrastructure is shipped.
- Broad compatibility is the chosen product ambition, but “supported” means a
  provider passes its capability matrix, contract fixtures, coverage tests,
  and offline report replay. It does not mean every platform exposes every
  native feature.
- Public semantics use canonical facts, evidence, coverage manifests, and
  conservative change association.
- Resource APIs are the primary source for repository objects. Activity APIs
  are optional supplements; without them, push/ref-change completeness is
  explicitly unavailable.
- The public window is a configurable half-open interval `[start, end)` with a
  timezone. The private Friday convention is not a public default.
- The default report profile is project/topic-first. Common alternatives are
  selectable and language-neutral at the canonical contract level.
- Apache-2.0 working license; synthetic or anonymous fixtures only.

## Challenge to the broad-scope choice

Supporting three platforms can differentiate the project only if the common
contract refuses false equivalence. GitHub Issues may represent pull
requests, GitLab activity can omit details for discussion notes and bulk
pushes, and Gitee's review and issue APIs have their own object and pagination
semantics. Therefore each provider must expose capabilities and unknowns;
the renderer may not fill a missing platform feature with an empty list or a
guessed equivalence.

The first implementation should still be broad in architecture and test
fixtures, but narrow in claims: three adapters can exist before all three are
called production-complete.

## Extraction baseline

The private weekly-report Skill is only a behavioral reference for extraction;
no private compatibility profile or organization-specific adapter is shipped.
Its reusable behavior inventory includes:

- time-window resolution with an explicit closed/open interval;
- bounded pagination and retry behavior;
- normalized events, Issues, merge requests, commits, and URLs;
- separate change-request-associated push candidates from other ref activity;
- issue-note preloading and cross-project Issue backfill;
- an independent manifest with errors and truncation;
- offline Markdown scaffolding and deterministic report validation.

The following must not be copied into the public project:

- private GitLab instances and credentials;
- team roster, aliases, and ordering;
- the fixed topic/support project;
- Chinese section names and organization-specific wording;
- the private Friday/Asia-Shanghai scheduling convention;
- the private `glab` executable boundary;
- the current `direct push` label.

## Proposed public layers

```text
CLI / agent adapters
        |
collect -> normalize -> reconcile -> validate -> render
        |          |          |          |
      providers  canonical  association  profiles
```

The canonical intermediate artifact must be sufficient for `validate` and
`render` to run without network access. An optional summarizer may consume
validated fact cards later; it cannot collect, classify completeness, invent
links, or decide publication.

## Initial acceptance gates

1. A versioned canonical JSON contract exists for actors, repositories, work
   items, change requests, interactions, commits, ref changes, releases,
   evidence, facts, capabilities, and coverage observations.
2. GitLab, GitHub, and Gitee each have contract fixtures for the shared minimum
   surface and explicit fixtures for unsupported or ambiguous behavior.
3. Each provider records pagination, rate-limit, permission, endpoint, and
   capability outcomes in the coverage manifest.
4. A fatal coverage or evidence error prevents a successful Markdown report,
   while diagnostics remain available.
5. The same evidence bundle renders reproducibly in JSON and Markdown without
   another platform request.
6. Synthetic fixtures cover merged/open change requests, Issues and comments,
   commits, ref changes, multiple pages, empty results, and truncated/failure
   cases.
7. A generic report profile can express project/topic/release/code sections
   without importing private hosts, members, project names, or credentials.
8. Built-in profiles include `project-first`, `timeline`, `release-focused`,
   and opt-in `actor-summary`; profiles cannot change evidence or coverage
   decisions.

## Explicit non-goals for this slice

- productivity or performance scoring;
- a hosted SaaS, dashboard, webhook collector, or data warehouse;
- automatic writes back to any platform;
- a required LLM or cloud data transfer;
- pretending that GitHub, GitLab, and Gitee have identical review, event, or
  push semantics;
- copying the private repository's report archive or real evidence.

## Remaining implementation gates

- keep the public synthetic fixtures aligned with the canonical contract as
  adapters evolve;
- keep live GitLab, GitHub, and Gitee replays reproducible without adding real
  private data to the repository;
- capture more provider/version-specific responses and decide whether Gitee
  has a stable activity/ref contract worth implementing;
- add provider-specific permission, rate-limit, retention, and malformed
  response fixtures from those live replays;
- define a release process and compatibility policy before changing an
  adapter from `experimental` to `stable`.
