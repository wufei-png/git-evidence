---
status: accepted
date: 2026-08-01
---

# Capability and identity disclosure

Provider features report one of `supported`, `unsupported`, `unavailable`, or
`incomplete`. Operational causes are carried separately as a diagnostic
`failure_class` so permission denial, rate limiting, service failure, malformed
responses, and network errors cannot collapse into the same explanation while
the capability-state contract remains stable. Canonical evidence keeps
provider-qualified actor identities for provenance, while rendered display
names require explicit configuration. A resource-observed commit may be
rendered as an observed change without being promoted to a push/ref-change
claim when ref evidence is unavailable.
