---
status: accepted
date: 2026-08-08
---

# Evidence bundles are sensitive; report publication is explicit

Schema-specific names in this historical decision are superseded by ADR-0022;
the disclosure boundary remains accepted.

The canonical Evidence Bundle is a provenance-preserving audit artifact and is
sensitive by default. Removing credentials and hiding actor names in a renderer
does not make the bundle anonymous: stable actor and repository identities,
titles, source references, and URLs may still disclose private engineering
data. The supported public boundary is therefore an explicitly configured and
operator-approved rendered report, not the canonical bundle.

The v0.1 `coverage.allow_publish` field is interpreted as render eligibility:
it says that evidence and coverage are sufficient for deterministic rendering,
not that either artifact is safe to disclose. The v0.1 CLI word “publishable”
is legacy terminology with the same limited meaning. Successful collection,
validation, or rendering never grants disclosure approval; approval is an
external operator/workflow action and is intentionally not represented as a
Bundle Boolean. This interpretation supersedes only the publication wording in
ADR-0002, ADR-0012, and ADR-0013, not their evidence, coverage, or privacy
gates.

A future schema uses the term `render_eligible`. If a machine-readable public
artifact becomes a real requirement, it will be a separate sanitized export
with its own schema and reference-preserving transformation rather than a mode
that silently weakens the canonical bundle's provenance.
