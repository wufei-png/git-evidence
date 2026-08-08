---
status: accepted
date: 2026-08-08
---

# Typed assertions drive narrative activity claims

The v0.2 bundle replaces free-text `Fact` records with typed `Assertion`
records for every narrative engineering-activity claim. An Assertion names
`subject_type`, `subject_id`, a versioned typed predicate, `occurred_at`, and
one or more `evidence_ids`. Entities represent observed objects; an
application-level Assertion Builder derives reportable activity claims from
those entities and provider-neutral semantics. A single Entity may support
multiple Assertions when the evidence establishes distinct events.

Providers no longer emit `_summary`, `_section`, localized prose, or profile
placement. Renderers and profiles map Assertions to grouping, language, and
wording without changing their meaning or evidence. Reusing the old `Fact`
name with weaker `kind` strings was rejected because it would retain an
implicit subject/predicate protocol; deriving report lines directly from
Entities was rejected because it would make stable claim identity and evidence
binding an undocumented Renderer behavior.

Scope, window, invocation metadata, Retrieval provenance, Coverage observations,
warnings, and render-policy results are rendered directly from their validated
authoritative records. They are not duplicated as activity Assertions, and a
renderer must not transform them into claims about engineering activity.
