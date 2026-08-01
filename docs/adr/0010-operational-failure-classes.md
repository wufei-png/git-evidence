---
status: accepted
date: 2026-08-01
---

# Operational failure classes

Keep the v0.1 capability-state enum (`supported`, `unsupported`, `unavailable`,
`incomplete`) and add a machine-readable `failure_class` inside coverage
diagnostics. Expanding the capability enum would make publication and renderer
compatibility depend on transport details; a separate class preserves the
meaning of coverage while distinguishing permission denial, rate limiting,
service errors, not-found responses, malformed responses, and network errors.
