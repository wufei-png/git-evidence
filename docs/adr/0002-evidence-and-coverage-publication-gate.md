---
status: accepted
date: 2026-08-01
---

# Evidence and coverage are render gates

Terminology note: ADR-0017 supersedes this ADR's use of “publication” with
“render eligibility.” Passing this gate permits deterministic rendering; it
does not approve disclosure of a Bundle or report.

Collection success is not the same as report completeness. A render-eligible
report requires every presented activity assertion to have evidence and every core
resource operation to have a complete, verifiable coverage result. Pagination
gaps, permission failures, provider capability limits, invalid links, commit
SHA inconsistencies, and unresolved fatal observations block rendering; the
run may still emit diagnostics and a replayable evidence bundle for repair.

Activity and ref APIs are optional supplements. An `unsupported`, `unavailable`,
or `incomplete` activity/ref observation does not block a complete core
resource report, but it must be copied into `coverage.warnings` with its
provenance, capability status, and any safe operational failure class. The
renderer exposes these warnings so optional gaps cannot be mistaken for
complete push/ref coverage.

This decision keeps deterministic integrity checks outside the renderer and
outside any optional language model. It also gives GitLab, GitHub, and Gitee a
common quality bar without pretending their APIs have identical semantics.
