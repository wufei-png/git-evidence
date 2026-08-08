---
status: accepted
date: 2026-08-08
---

# Request scheduling is core-first and fair across repositories

The existing `max_requests` limit remains scoped to one provider-instance
collection group. Repositories are ordered by canonical repository ID, never
configuration position. Preflight requires at least five requests per
repository—one root plus the first work-item, change-request, commit, and
release page—so an infeasible plan fails before sending a request with a typed
`plan_budget_infeasible` configuration error.

The runtime fairness unit is one physical HTTP attempt; retry attempts re-enter
the queue instead of running invisibly inside one repository's turn. Cache hits
consume no request budget and may therefore complete without an HTTP attempt.
After roots, top-level sources are queued by page depth, canonical repository
ID, and the fixed source order `work_items`, `change_requests`, `commits`,
`releases`. Interaction requests discovered from those lists are queued by
canonical repository ID, subject type, subject ID, and endpoint kind, with one
request per repository per round. Optional activity/ref work is admitted only
after every required source is complete; it may use the remaining budget but
has no reservation of its own. At runtime, an exhausted required queue marks
its affected observations `incomplete` with `budget_exhausted` and adds typed
fatal blockers; an exhausted optional queue produces scoped warnings instead.

Interactions remain required core coverage: there is no fixed preflight
reserve because their size is unknowable until parent lists are read, but
optional work cannot consume the remainder until interactions complete. We
defer global, per-repository, and user-configurable per-source budgets until
real collection measurements justify their additional configuration and
schema surface. Merely reordering the current per-repository pipeline is
insufficient because a large first repository could still starve later ones.
