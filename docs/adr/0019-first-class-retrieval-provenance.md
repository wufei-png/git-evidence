---
status: superseded
superseded_by: 0022
date: 2026-08-08
---

# Retrieval provenance is separate from evidence and coverage

The v0.2 bundle introduces first-class `Retrieval` records for individual
provider responses and cache replays. A live Retrieval records `fetched_at`;
a replay additionally records `replayed_at`, the original cache `stored_at`,
and derived cache age so stale source data cannot appear freshly fetched. It
also records provider, safe endpoint kind and target reference, cache status,
pagination position/completion signal, and available safe response validators
such as ETag or Last-Modified. Cached provenance is invalid when the original
fetch/store time is missing, later than replay time, or inconsistent with TTL.
Evidence references the Retrieval and the native source object identity;
coverage observations continue to answer whether the planned source was
completely covered.

Response-level metadata is not copied onto every Evidence record. A payload
digest is recorded only when the payload is retained for replay or has a
specified deterministic canonicalization, because an unverifiable decorative
hash adds no audit value. Provider API version metadata is likewise recorded
only when the provider exposes a meaningful version rather than being guessed
from adapter code or URL shape.
