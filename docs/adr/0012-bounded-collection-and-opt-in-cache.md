---
status: accepted
date: 2026-08-02
---

# Bounded collection and opt-in cache

Each provider/instance collection group is isolated: successful groups remain
available as diagnostics while a failed group contributes explicit coverage
failure and prevents publication. Requests use bounded retries and budgets.
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

Every resource and activity/ref item is normalized independently. Missing or
ill-typed native identity, repository identity, or required occurrence time is
dropped, while valid siblings remain. The affected source becomes
`incomplete`, carries `failure_class: malformed_response`, and records
`dropped_count`; no placeholder `None` identity is emitted.

Collection configuration and token presence are preflight checks. Once
collection starts, a failed `(provider, instance)` group produces structured
coverage observations and `coverage.group_failures` for every affected
repository/source. Successful groups remain in the merged diagnostic bundle,
but any failed required source keeps `allow_publish: false`. The CLI reserves
status 3 for this partial group-failure result, status 2 for preflight config
failure, and status 1 for ordinary validation/publication failure.

The cache is enabled only when `enabled: true` and explicit `path`,
`ttl_seconds`, and `max_entries` are present. Its key contains provider,
instance, request path, parameters, and a digest of token scope. Entries store
only a redacted URL, status, and safe JSON body; unreadable, expired, or
credential-bearing entries behave as misses.
