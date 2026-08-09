---
status: accepted
date: 2026-08-10
supersedes: [0018, 0019, 0020]
---

# Schema 0.3 is the sole direct evidence contract

Git Evidence accepts and emits only Schema 0.3. It does not read, identify,
migrate, or coordinate any earlier Bundle shape. Provider and aggregate
fragments use the same Entity, Retrieval, Evidence, Assertion, and Coverage
vocabulary as the final Bundle; finalization adds the identity/privacy envelope
without translating another internal schema.

Generic extension containers are excluded. Provider-native values enter the
contract only through fields with defined common semantics.

Change-request observation and merge are independent core events. Coverage
therefore requires both `change_request_observations` and
`change_request_merges`. A merged change request carries both an observation
Assertion and a separate merge Assertion.

Canonical timestamps are UTC. Rendering parses instants and projects calendar
dates through the plan's IANA timezone. Validation and CLI language use
`render_eligible`, `coverage.render_blocked`, and `coverage.render_mismatch`;
render eligibility remains distinct from disclosure authorization.
