---
status: accepted
date: 2026-08-02
---

# Independent runtime and thin-protocol boundary

Git Evidence remains independently versioned and owns its own Python dependency
boundary. We do not extract a cross-repository shared runtime from similarly
shaped redaction, retry, or diagnostic code: Git Evidence's
repository/provider/capability/coverage/publication/privacy semantics are
distinct from other systems' project/change-request/SHA, effect-receipt, and
worker-lease semantics, so code-shape overlap is not a safe domain boundary.

The current sharing surface is documentation only: domain vocabulary candidates
or thin protocols may be documented when they preserve each system's meaning and
ownership; they are not Python runtime dependencies. Reconsider extraction only
when all of these are true: at least two real consumers exist, the semantic
contract is versioned and stable, shared tests demonstrate no domain-semantic
change, and independent release and rollback plans exist.
