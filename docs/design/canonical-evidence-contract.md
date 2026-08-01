# Canonical evidence contract

The canonical bundle is the stable boundary between provider collection,
reconciliation, validation, and rendering. It is versioned, serializable, and
usable offline. A renderer must not make another provider request.

The machine-readable draft is
[`schemas/evidence-bundle-0.1.schema.json`](../../schemas/evidence-bundle-0.1.schema.json);
the executable validator additionally checks cross-record references and
allowlist/coverage invariants that JSON Schema alone cannot express.

## Top-level shape

```json
{
  "schema_version": "0.1",
  "run": {
    "run_id": "run:example",
    "window": {
      "start": "2026-07-27T00:00:00Z",
      "end": "2026-08-03T00:00:00Z",
      "timezone": "UTC"
    },
    "scope": {
      "repositories": ["repo:github:github.com:example/project"],
      "actors": []
    }
  },
  "providers": [],
  "repositories": [],
  "actors": [],
  "work_items": [],
  "change_requests": [],
  "interactions": [],
  "commits": [],
  "ref_changes": [],
  "releases": [],
  "evidence": [],
  "facts": [],
  "coverage": {
    "required_sources": ["repositories", "work_items", "change_requests", "commits", "releases"],
    "observations": [],
    "fatal": [],
    "allow_publish": true
  }
}
```

## Invariants

- Every entity ID is unique within its collection and is namespaced by
  provider/instance where the source requires it.
- Every `fact` has at least one `evidence_id`; every evidence ID resolves to an
  evidence record with a source URL or an explicit non-URL source reference.
- A fact or entity outside the repository allowlist is invalid for the run.
- Every repository-scoped entity has a non-empty `repository_id` that belongs
  to the run allowlist; repository entities themselves must also belong to that
  allowlist.
- When `run.scope.actors` is non-empty, every actor entity and every
  `actor_id` reference belongs to that actor allowlist. Every non-empty
  `actor_id` reference must also resolve to an actor entity; actor-neutral
  records remain valid.
- `coverage.required_sources` is a non-empty, duplicate-free list of known
  resource or activity source names. An unknown or empty required-source list
  is invalid.
- Every required source has a coverage observation for every in-scope
  provider/repository combination.
- `allow_publish` is false when a required source is fatal, incomplete, or
  missing, or when an evidence reference cannot be resolved.
- `change_association` is one of `linked`, `unlinked`, `ambiguous`, or
  `unknown`.
- `capability_state` is one of `supported`, `unsupported`, `unavailable`, or
  `incomplete`.
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
