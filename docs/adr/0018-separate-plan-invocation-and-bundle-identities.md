---
status: accepted
date: 2026-08-08
---

# Separate collection plan, invocation, and bundle identities

The v0.2 evidence contract replaces the overloaded `run_id` with three
independent identities. `plan_id` is a stable digest of the normalized,
non-secret collection configuration that can affect scope, selected sources,
or collection semantics. `invocation_id` is an opaque random identifier for
one actual execution and is accompanied by start/end timestamps and generator
version. `bundle_digest` identifies the exact canonical Bundle content and is
computed with the digest field itself excluded.

The current aggregate hash cannot identify repeated executions, and the fixed
provider-group IDs cannot identify either intent or execution. Keeping a
fourth compatibility `run_id` would preserve that ambiguity, so v0.2 removes
it rather than assigning it another meaning. Secrets and credential values are
never inputs to `plan_id`; a separately safe token-scope discriminator may
remain runtime/cache metadata but is not plan identity.

## Canonicalization v1

Both digests use SHA-256 over RFC 8785 JSON Canonicalization Scheme bytes after
all strings and object keys are normalized to Unicode NFC. Non-finite numbers
and non-canonical timestamps are invalid. Digest inputs are domain-separated
with the UTF-8 prefix `git-evidence:plan:v1\n` or
`git-evidence:bundle:v1\n`; identifiers are lowercase
`plan:sha256:<64-hex>` and `bundle:sha256:<64-hex>`.

The plan input expands declared defaults, uses canonical provider-instance and
repository identities, sorts semantically unordered repository/actor sets,
and includes every non-secret option that can change selected sources,
coverage, limits, cache semantics, or transport policy. Credential values,
environment variable names, local cache/output paths, and report configuration
are excluded. The Bundle input excludes only its own `bundle_digest`; canonical
collections are ordered by ID, while order-bearing provider extension arrays
retain their declared order. Timestamps use RFC 3339 UTC `Z`. The validator
recomputes both digests and rejects an unknown canonicalization version.
