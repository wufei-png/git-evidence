---
status: accepted
date: 2026-08-01
---

# Bounded activity supplements

Opt-in activity collection remains a supplement rather than a publication
requirement. The GitLab and GitHub adapters may emit provider-native push/ref
observations, but mark the activity and ref coverage `incomplete` because
retention, latency, bulk-event, or payload-size limits prevent a completeness
claim. Gitee remains `unsupported` until its activity/ref semantics have a
stable, replayable public contract. This preserves useful candidates without
turning an event stream into proof of complete push coverage.
