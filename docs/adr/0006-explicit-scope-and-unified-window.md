---
status: accepted
date: 2026-08-01
---

# Explicit scope and unified window

Every run has an explicit repository/project allowlist and a provider-neutral
half-open time interval `[start, end)` with a configured timezone. Resource
queries are evaluated within that scope and interval; actor filters are
optional narrowing filters, not the source of scope. The private weekly
Friday convention is not carried into the public product. This makes
cross-platform runs reproducible and prevents an empty actor or activity
stream from being mistaken for an empty repository.
