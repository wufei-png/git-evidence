# Canonical evidence contract

The canonical bundle is the stable boundary between provider collection,
reconciliation, validation, and rendering. It is versioned, serializable, and
usable offline. A renderer must not make another provider request.

The machine-readable Schemas have one package authority under
[`src/git_evidence/schemas`](../../src/git_evidence/schemas);
the executable validator additionally checks cross-record references,
canonical identities and digests, and allowlist/coverage invariants that JSON
Schema alone cannot express. Schema 0.1 is read-only compatibility; Schema 0.2
is strict, contains unknown provider data only under namespaced `extensions`,
and is both the direct collection format and the explicit legacy-migration
target.

## Schema 0.2 identity envelope

Schema 0.2 removes `run_id`. `plan_id` is the RFC 8785 plus Unicode-NFC digest
of the retained plan, `invocation.id` identifies one actual execution or
migration, and `bundle_digest` covers the complete canonical Bundle except its
own field. The validator recomputes both digests. The plan and Bundle digest
domains are separated as specified by ADR-0018.

`facts` are replaced by typed `assertions`, Evidence references a Retrieval,
and `coverage.render_eligible` replaces the misleading v0.1
`coverage.allow_publish` name. An explicit legacy migration uses
`Retrieval.mode: legacy_import`; it does not invent a fetch timestamp or source
API version that the 0.1 artifact never recorded. Migrated Evidence likewise
marks native identity unavailable instead of copying a canonical subject ID
into a native-ID field.

## Top-level shape

```json
{
  "schema_version": "0.2",
  "canonicalization": {
    "algorithm": "RFC8785",
    "version": "v1",
    "unicode_normalization": "NFC"
  },
  "plan_id": "plan:sha256:<digest>",
  "plan": {
    "origin": "collection",
    "window": {
      "start": "2026-07-27T00:00:00Z",
      "end": "2026-08-03T00:00:00Z",
      "timezone": "UTC"
    },
    "scope": {
      "repositories": ["repo:github:github.com:example/project"],
      "actors": []
    },
    "providers": [{
      "kind": "github",
      "instance": "github.com",
      "selected_sources": ["repositories", "work_items", "change_requests", "interactions", "commits", "releases"]
    }]
  },
  "invocation": {
    "id": "invocation:<uuid>",
    "started_at": "2026-08-03T00:00:00Z",
    "finished_at": "2026-08-03T00:00:01Z",
    "generator": {"name": "git-evidence", "version": "0.2.0"}
  },
  "bundle_digest": "bundle:sha256:<digest>",
  "providers": [],
  "repositories": [],
  "actors": [],
  "work_items": [],
  "change_requests": [],
  "interactions": [],
  "commits": [],
  "ref_changes": [],
  "releases": [],
  "retrievals": [],
  "evidence": [],
  "assertions": [],
  "collection": {},
  "privacy": {
    "actor_display": "anonymous",
    "source_urls": "sanitized",
    "auth_redaction": true
  },
  "coverage": {
    "required_sources": ["repositories", "work_items", "change_requests", "interactions", "commits", "releases"],
    "observations": [],
    "fatal": [],
    "warnings": [],
    "group_failures": [],
    "render_eligible": true
  }
}
```

## Invariants

- Every entity ID is unique within its collection and is namespaced by
  provider/instance where the source requires it.
- Every `assertion` has at least one `evidence_id`; every evidence ID resolves
  to Evidence with a Retrieval, honest native identity state, and a source URL
  or explicit non-URL source reference.
- An Assertion or Entity outside the repository allowlist is invalid for the
  retained plan.
- Every repository-scoped entity has a non-empty `repository_id` that belongs
  to the plan allowlist; repository entities themselves must also belong to that
  allowlist.
- When `plan.scope.actors` is non-empty, every actor entity and every non-empty
  `actor_id` reference belongs to that allowlist. Every reference must also
  resolve to an actor entity; actor-neutral records remain valid.
- `coverage.required_sources` is a non-empty, duplicate-free list of known
  resource or activity source names. An unknown or empty required-source list
  is invalid.
- Every required source has a coverage observation for every in-scope
  provider/repository combination.
- `render_eligible` is a derived field, never caller authority. The
  validator computes render eligibility from all intrinsic schema, provenance,
  privacy, coverage, and reference checks; collectors overwrite the field with
  that result. A contradictory caller-supplied value is invalid.
- `coverage.fatal` contains only typed blockers with `code`, provider and
  instance identity, repository, source, and non-supported status. Operational
  blockers also carry a bounded `failure_class`; ad-hoc fatal strings are not
  part of the contract.
- Activity/ref sources are optional supplements. Their `unsupported`,
  `unavailable`, or `incomplete` observations do not close the core gate, but
  each such observation must have a machine-readable entry in
  `coverage.warnings` with matching source, provider, repository, and status.
- `coverage.warnings` uses `code: optional_coverage_warning` and may carry a
  safe operational `failure_class` or `failure_classes`; renderers must show
  these warnings rather than silently omitting the coverage limitation.
- `change_association` is one of `linked`, `unlinked`, `ambiguous`, or
  `unknown`.
- `capability_state` is one of `supported`, `unsupported`, `unavailable`, or
  `incomplete`. Provider capability summaries are a deterministic conservative
  fold of repository observations, so a later success cannot overwrite an
  earlier incomplete or unavailable observation.
- A coverage diagnostic may carry a `failure_class` such as
  `permission_denied`, `rate_limited`, `service_error`, `not_found`,
  `request_rejected`, `malformed_response`, or `network_error`. The class is
  an operational explanation and does not expand the capability-state enum.
  When one logical source aggregates child requests with different causes, it
  carries `failure_classes` instead of pretending that the last child error is
  the only cause.
- A transport diagnostic may carry only the safe rate-limit headers
  `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset`, and
  `retry-after`; authentication headers and other response headers are not
  propagated.
- A resource-observed commit cannot imply a complete push/ref-change claim.
- A malformed item inside an otherwise valid provider page is omitted from
  canonical entities, while valid siblings remain; that source is marked
  `incomplete` with `failure_class: malformed_response`.
- A `ref_change` may carry `commit_ids` for commits observed in the same bundle
  and `commit_shas` when the activity source exposes a SHA that is not yet a
  resource entity. Neither field makes an incomplete activity source complete.
- When a provider successfully resolves commit-to-change-request candidates,
  `change_request_ids` records the in-bundle candidates that support the
  association state; unresolved or out-of-scope candidates do not get guessed
  into this list.
- A ref/change association is `linked` only when the available native SHA
  evidence resolves to one change request; multiple candidates are
  `ambiguous`, and any unresolved SHA keeps the result `unknown`.
- Every interaction carries `subject_type` (`work_item` or `change_request`)
  and a canonical `subject_id` that resolves to a parent in the same repository.
- A canonical commit must preserve one full hexadecimal Git object ID in its
  native identity, canonical ID, and `sha` field, plus a matching
  `hash_algorithm` of `sha1` or `sha256`. Abbreviated and sentinel revisions are
  unverifiable. A mismatch is a malformed core resource and blocks rendering.
  Per ADR-0017, this field expresses render eligibility and never authorizes
  disclosure.
- Each executable validation issue exposes stable `code`, `severity`, JSON
  `path`, `scope`, safe `message`, and `remediation` fields for automation.

## Minimum entity vocabulary

Providers normalize native objects into `Repository`, `Actor`, `WorkItem`,
`ChangeRequest`, `Interaction`, `Commit`, `RefChange`, and `Release`. Native
fields that do not have a safe common meaning remain under provider-specific
metadata and do not silently change the common semantics.

## Rendering profiles

The initial built-ins are:

- `project-first` — default; projects/topics, releases, changes, then other
  verified activity.
- `timeline` — chronological facts grouped by date.
- `release-focused` — releases and change requests first, then supporting
  evidence.
- `actor-summary` — explicit opt-in actor view with no ranking or score.

Profiles may change grouping, language, and display redaction. They may not
change the evidence set or turn an unavailable capability into an asserted
fact.
