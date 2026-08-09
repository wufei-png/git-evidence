---
status: accepted
date: 2026-08-10
---

# TOML provider-instance configuration without legacy compatibility

Configuration uses TOML exclusively and models each provider instance as a
named authority referenced by repositories. Each canonical `(kind, instance)`
pair is unique and owns its credential reference, transport policy, cache, and
request budget; unused or unknown references fail validation. Historical YAML
and kind-keyed shapes are not read, detected, migrated, or coordinated because
compatibility would preserve the ambiguity this boundary is intended to remove.
