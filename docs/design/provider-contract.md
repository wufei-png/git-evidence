# Provider contract

Providers are responsible for translating native platform resources into the
canonical bundle. They do not render prose and they do not decide whether an
incomplete run is render-eligible by themselves.

## Required resource operations

For each repository in the explicit allowlist and each `[start, end)` window,
the provider contract has these logical operations:

```text
probe() -> provider metadata and adapter implementation state
get_repository(repository_ref) -> Repository
list_work_items(repository_ref, window) -> Page[WorkItem]
list_change_requests(repository_ref, window) -> Page[ChangeRequest]
list_interactions(subject_ref, window) -> Page[Interaction]
list_commits(repository_ref, window) -> Page[Commit]
list_releases(repository_ref, window) -> Page[Release]
```

The provider may use different native endpoints, multiple requests, or
compensation queries. The canonical collector records each logical operation
and its underlying observations in the coverage manifest.

## Optional activity operations

```text
list_activities(scope, window) -> Page[Activity]
list_ref_changes(repository_ref, window) -> Page[RefChange]
associate_commit(repository_ref, commit_ref) -> ChangeAssociation
```

These operations can improve push/ref attribution and candidate discovery, but
they are not required to collect resource-backed Issues, change requests,
interactions, commits, or releases. If they are disabled or unavailable, the
provider must emit `unavailable`, `unsupported`, or `incomplete` coverage and
the report must not claim complete push/ref coverage. Each non-supported
activity/ref observation must also emit a matching `coverage.warnings[]`
entry; this warning does not close the render gate when the core resource
sources are complete.

## Pagination and failure rules

- A page is complete only when the provider has followed its documented next
  page/cursor signal. GitHub and Gitee follow the HTTP `Link` next relation
  until it is absent; GitLab follows `X-Next-Page` until it is absent or zero.
  The generic short-page strategy is retained only for endpoints whose native
  contract explicitly documents that proof; provider adapters do not silently
  fall back to it.
- Every terminal page records a typed pagination outcome. `link_exhausted`,
  `cursor_exhausted`, and an explicitly documented `documented_short_page`
  prove completeness. `max_pages_reached` and `cycle_detected` are incomplete
  outcomes and close the publication gate. A required paginated source cannot
  be `supported` when this proof is missing, incomplete, or inconsistent with
  the known provider strategy.
- A cached or replayed response is data only when its status is a non-boolean
  2xx value. Cached pagination and rate-limit headers are allowlisted, format
  checked, and credential-checked before replay; unsafe headers cause a cache
  miss.
- A successful HTTP response with only the first page is incomplete, not
  empty.
- A `401`/`403`, exhausted retry, malformed response, or missing required
  object reference is recorded as a fatal observation when the source is
  required by the report plan.
- Coverage keeps the capability state separate from the operational
  `failure_class`: `permission_denied` covers `401`/`403`, `rate_limited`
  covers `429`, `service_error` covers `5xx`, and malformed/network/not-found
  outcomes retain their own classes.
- When a logical source fans out to multiple child requests, distinct causes
  are preserved in `diagnostics.failure_classes`; a single unambiguous cause
  remains available as `diagnostics.failure_class`.
- Retriable `429` and transient `5xx` responses honor bounded retry and
  `Retry-After` behavior. Attempts, status, retryability, and rate-limit
  headers remain in coverage diagnostics without exposing credentials.
- Provider-specific rate-limit and API-version details stay in diagnostics and
  capability metadata; they do not change canonical entity meaning.
- Interaction normalization must retain the canonical parent `subject_id` and
  its `work_item` or `change_request` type. Pagination task identity uses that
  same canonical subject, not a provider-local number.
- When actor scoping removes an interaction parent but retains an in-scope
  interaction, the shared builder emits only a minimal, unattributed structural
  parent. It does not emit a fact or evidence claim for the filtered parent.
- Commit normalization accepts only full SHA-1 or SHA-256 object IDs and emits
  the matching `hash_algorithm`; short display revisions are not evidence IDs.
- Capability summaries fold all repository observations conservatively and
  independently of collection order. Provider implementations return evidence
  and coverage, while the shared validator derives publication eligibility.
- Native fields without a safe common mapping remain provider-specific rather
  than being guessed into a common field.
- Every coverage observation is keyed by a syntactically valid provider kind,
  canonical instance, allowlisted repository, and source. Offline validation
  deliberately does not require that provider adapter to be installed in the
  validating process, so a canonical bundle remains independently verifiable.
  Collection still requires a registered adapter. Repeated canonical IDs are
  not silently accepted:
  valid siblings remain, while the source becomes `incomplete` with
  `malformed_response` diagnostics and the render gate remains closed.

## Three provider targets

| Provider | Resource target | Activity target | Current code status |
| --- | --- | --- | --- |
| GitLab | projects, issues, merge requests, notes/discussions, commits, releases | events/ref changes | experimental |
| GitHub | repositories, issues, pulls, comments/reviews, commits, releases | events/ref changes | experimental |
| Gitee | repositories, issues, pull requests, comments, commits, releases | activity/ref changes | experimental |

`experimental` means the adapter has a recorded-response contract test and
emits the canonical coverage shape; it is not a production-completeness or
cross-version compatibility promise.

The current optional activity behavior is intentionally asymmetric:

- GitLab uses project Events API push observations and emits `incomplete`
  activity/ref coverage because bulk pushes can omit ref and commit detail.
- GitHub uses repository events and emits `incomplete` activity/ref coverage
  because the event feed is bounded and latency-limited.
- Gitee emits `unsupported` activity/ref coverage until a stable public event
  contract is captured in fixtures.

The targets are intentionally phrased as logical resources. Their native
endpoints are not assumed equivalent; GitHub issues can represent pull
requests, GitLab events can omit bulk-push detail, and Gitee requires its own
object mapping.
