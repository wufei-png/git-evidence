---
status: accepted
date: 2026-08-01
---

# Evidence and coverage are publication gates

Collection success is not the same as report completeness. A publishable
report requires every presented canonical fact to have evidence and every
required provider operation to have a coverage result. Pagination gaps,
permission failures, provider capability limits, invalid links, and unresolved
fatal observations block publication; the run may still emit diagnostics and a
replayable evidence bundle for repair.

This decision keeps deterministic integrity checks outside the renderer and
outside any optional language model. It also gives GitLab, GitHub, and Gitee a
common quality bar without pretending their APIs have identical semantics.
