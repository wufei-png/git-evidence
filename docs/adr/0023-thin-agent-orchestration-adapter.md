---
status: accepted
date: 2026-08-10
---

# Agent integration remains a thin orchestration adapter

The in-repository Agent Skill resolves explicit user intent and sequences
`doctor → collect → validate → render` (or offline `validate → render`) through
structured CLI diagnostics. It does not call providers, decide coverage,
rewrite Bundles, or authorize disclosure; those responsibilities remain in the
core and external operator workflow. This preserves a useful natural-language
entry point without creating a second evidence engine.
