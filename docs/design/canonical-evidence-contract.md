# Canonical evidence contract

Schema 0.3 is the sole Bundle format and the stable boundary between
collection, validation, and offline rendering. Earlier formats are not read,
recognized, migrated, or coordinated. The single machine-readable authority is
[`src/git_evidence/schemas/evidence-bundle-0.3.schema.json`](../../src/git_evidence/schemas/evidence-bundle-0.3.schema.json).

JSON Schema defines the closed serialized shape. The executable validator also
checks digests, identity, scope, provenance, cross-record references, coverage,
privacy, and render eligibility.

## Identity envelope

- `plan_id` is the RFC 8785 plus Unicode-NFC digest of the normalized,
  non-secret collection plan.
- `invocation.id` identifies one execution. Repeating a plan creates a new
  invocation.
- `bundle_digest` identifies the exact canonical Bundle except for its own
  field. It detects changes when compared with a trusted digest; it is not a
  signature or proof of collector authenticity.

## Direct write model

Providers write Schema 0.3 fragments containing normalized entities,
Retrievals, Evidence, typed Assertions, collection diagnostics, and Coverage.
Aggregation merges those same records. Finalization adds only the canonical
plan, invocation, privacy envelope, and Bundle digest; it does not translate a
second internal schema or reconstruct Assertions from an older representation.

The top-level collections are `providers`, `repositories`, `actors`,
`work_items`, `change_requests`, `interactions`, `commits`, `ref_changes`,
`releases`, `retrievals`, `evidence`, and `assertions`. Unknown generic
extension objects are not part of the contract.

## Required coverage

Every in-scope provider/repository pair requires supported observations for:

- `repositories`
- `work_items`
- `change_request_observations`
- `change_request_merges`
- `interactions`
- `commits`
- `releases`

Change-request observation and merge are different events. Every normalized
change request with `occurred_at` has a `change_request.observed.v1` Assertion.
When `merged_at` is present, the same subject also has a separate
`change_request.merged.v1` Assertion whose event time is `merged_at`. A merged
subject or either coverage surface cannot silently stand in for the other.

`activities` and `ref_changes` are optional supplements. A non-supported
optional observation requires a matching `optional_coverage_warning`. A
privacy violation remains fail-closed.

## Invariants

- IDs are non-empty and unique within every collection. Provider and repository
  identities bind to their canonical kind, instance, owner, and name.
- All timestamps are offset-aware at input and normalized to UTC in canonical
  output. The plan window is half-open `[start, end)`; the declared IANA
  timezone controls report calendar grouping, not the instant boundaries.
- Every Assertion resolves to a subject in the same repository, uses a
  predicate valid for that subject type, and references at least one Evidence
  record for that exact subject.
- Every Evidence record resolves to a Retrieval from the same provider and
  repository and carries a known native identity plus a sanitized URL or an
  explicit source reference.
- Every repository-scoped entity and Assertion is inside the retained plan
  allowlist. Actor references resolve and obey a non-empty actor allowlist.
- Coverage is scoped by provider and repository. Required observations cannot
  be replaced by a success for another repository or provider instance.
- `coverage.render_eligible` is derived from intrinsic validation and core
  coverage. A contradictory value is invalid. It is never disclosure approval.
- `coverage.fatal`, `coverage.group_failures`, and `coverage.warnings` use
  typed, bounded records. Operational causes do not expand capability states.
- Provider capability summaries use the conservative order `supported` <
  `unsupported` < `unavailable` < `incomplete`; later success cannot erase an
  earlier limitation.
- Canonical commits carry one full SHA-1 or SHA-256 object ID consistently in
  native identity, canonical ID, `sha`, and `hash_algorithm`.
- `change_association` is `linked`, `unlinked`, `ambiguous`, or `unknown`.
  Partial association checks remain `unknown`; multiple candidates are
  `ambiguous`.
- Validation issues expose stable `code`, `severity`, JSON `path`, `scope`,
  safe `message`, and `remediation` fields.

## Rendering

The built-in profiles are `project-first`, `timeline`, `release-focused`, and
opt-in `actor-summary`. Timeline ordering uses parsed instants and groups dates
after projection into `plan.window.timezone`. Profiles may change presentation,
language, and display redaction; they cannot change evidence or coverage.

Rendering is offline. The renderer makes no provider request and rejects any
Bundle that is not render eligible.
