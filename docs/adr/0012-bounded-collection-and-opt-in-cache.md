---
status: accepted
date: 2026-08-02
---

# Bounded collection and opt-in cache

Terminology note: per ADR-0017, “publication” and the v0.1
`coverage.allow_publish` field in this ADR mean render eligibility, not approval
to disclose an artifact.

Each provider/instance collection group is isolated: successful groups remain
available as diagnostics while a failed core resource group contributes
explicit coverage failure and prevents rendering. Ordinary failed optional
activity/ref collection—including malformed responses, typed provider errors,
and transport/capability failures—contributes `coverage.group_failures` and a
visible `coverage.warnings` entry, but does not close an otherwise complete
core gate. An optional `privacy_violation` remains fail-closed, with a fatal
ledger entry and `allow_publish: false`. Requests use bounded retries and
budgets.
Response caching is disabled by default and may be enabled explicitly with a
bounded local cache; cache hits never upgrade capability or publication state,
and authentication headers/tokens are never persisted.

## Implementation boundary

The default per-group request envelope is a 30-second timeout, 2 idempotent
GET retries, 100 pages per logical list, 1000 total HTTP requests, 0.5-second
exponential backoff, at most 0.25 seconds of jitter, and a 60-second
`Retry-After` cap. Request/page/retry counts, budget exhaustion, and cache-hit
signals are exposed as safe collection metrics and, when relevant, coverage
diagnostics.

The hard caps are 300 seconds for timeout, 10 retries, 1000 pages, 10000
requests, 60 seconds for backoff and jitter, 300 seconds for the retry-after
cap, 86400 seconds for cache TTL, and 10000 cache entries. Non-finite values
and unbounded request budgets are rejected. A retryable remote failure remains
the primary failure if a later retry is stopped by the request budget; the
ledger may additionally record `budget_exhausted`.

Every resource and activity/ref item is normalized independently. Missing or
ill-typed native identity, repository identity, or required occurrence time is
dropped, while valid siblings remain. The affected source becomes
`incomplete`, carries `failure_class: malformed_response`, and records
`dropped_count`; no placeholder `None` identity is emitted.

Collection configuration and token presence are preflight checks. Once
collection starts, a failed `(provider, instance)` group produces structured
coverage observations and `coverage.group_failures` for every affected
repository/source. Successful groups remain in the merged diagnostic bundle,
but any failed core resource source keeps `allow_publish: false`; ordinary
optional activity/ref failures remain render-eligible with warnings, while
optional privacy violations remain fail-closed. The CLI reserves
status 3 for a partial core-group failure, status 2 for preflight config
failure, and status 1 for ordinary validation/render-gate failure.

Coverage observations are provenance-qualified: every observation declares a
registered `provider_id` and an allowlisted `repository_id`, and the
provider/instance/repository tuple must agree with the provider registry.
Required-source matching uses `(provider_id, repository_id, source)`; an
observation with missing, unknown, or mismatched provenance cannot satisfy the
required coverage contract.

The cache is enabled only when `enabled: true` and explicit `path`,
`ttl_seconds`, and `max_entries` are present. Its key contains provider,
instance, request path, parameters, and a digest of token scope. Entries store
only a redacted URL, status, safe JSON body, and allowlisted pagination/
rate-limit headers. Only non-boolean 2xx statuses are cacheable. Pagination
and rate-limit header values are format-checked and passed through the shared
credential detector; invalid or sensitive values reject the entry. Cache
files and temporary files are mode `0600`; missing headers in an old entry,
unreadable, expired, unredacted, non-2xx, or credential-bearing entries behave
as misses so replay cannot claim complete pagination.

The normalizer keeps valid siblings when a source repeats a canonical ID, but
records the collision as `incomplete` with `malformed_response` diagnostics
and blocks rendering for required resource sources. Direct library calls to
`collect_config` run the same collection validator as the CLI before any
provider factory is invoked.
