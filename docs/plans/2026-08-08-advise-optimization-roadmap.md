# Optimization roadmap after the external advice review

Status: superseded by ADR-0021, ADR-0022, and the current implementation. This
document records the earlier design sequence; it is not a current contract.

This roadmap challenges `/tmp/git-evidence/advise.md` against the current code,
tests, glossary, and accepted ADRs. It separates credential safety and core
correctness from v0.2 contract work so an architectural rewrite cannot delay
closing concrete transport and scheduling defects.

## Verified baseline

- `uv run --with pytest python -m pytest -q`: 106 tests passed with 88 subtests.
- Source and wheel/sdist builds succeed; packaging emits a deprecation warning
  for the table form of `project.license`.
- Ruff currently reports 81 issues, Ruff format would change 16 files, and
  Pyright reports 48 errors and 3 warnings. These are existing debt, not a
  green CI baseline.
- No live-provider canary was run in this review. Offline results do not prove
  current GitHub, GitLab, Gitee, proxy, redirect, or rate-limit behavior.

## Dependency and delivery order

The advice used one P0 label for several different kinds of work. Delivery
follows this dependency graph rather than treating P1 and v0.2 as independent
linear buckets:

1. **P0 Safety and core correctness** — prevent credential disclosure and
   request-target abuse, bound hostile inputs, make core budget allocation fair,
   and establish a real green CI gate.
2. **P1 v0.1-compatible hardening** — strict current-shape configuration,
   deterministic capability and failure models, repository isolation, privacy
   scanning, atomic I/O, packaging, and maintainable tests.
3. **v0.2 contract and migration** — plan/invocation/artifact identities, Retrieval,
   Assertion, `render_eligible`, typed entities, and an explicit migration.
4. **Post-v0.2 integration hardening** — provider-instance references, Assertion
   report traceability, invocation metadata, and v0.1 compatibility removal at
   the documented boundary.
5. **Deferred scale features** — incremental checkpoints, concurrency, plugin
   SPI, attestation/signing, and broad fuzz/mutation infrastructure.

## Accepted domain and architecture decisions

- Authenticated requests require HTTPS and TLS verification. Follow-up targets
  stay inside the canonical API origin and path boundary; see ADR-0015.
- Request scheduling remains bounded per provider-instance group and becomes
  core-first and fair across repositories; see ADR-0016.
- Evidence Bundles are sensitive audit artifacts. Render eligibility is not
  disclosure approval; see ADR-0017.
- v0.2 separates `plan_id`, `invocation_id`, and `bundle_digest`; see ADR-0018.
- Response/cache provenance is represented by Retrieval records rather than
  duplicated across Evidence records; see ADR-0019.
- Typed Assertions replace free-text Facts for narrative engineering-activity
  claims; scope, coverage, and provenance retain their own authority; see
  ADR-0020.

The “evidence compiler” analogy remains a useful reasoning aid, not a mandate
to reproduce the proposed target directory. Modules should be extracted only
when a tested behavior boundary is being changed.

## P0 implementation slices

### P0-A: trusted request targets and bounded input

Implement this independently of Schema v0.2 and directory restructuring.

- Derive a canonical API authority from the actual transport base, including
  effective port and API path prefix. Do not compare follow-up URLs to the web
  instance name (`github.com` and `api.github.com` are intentionally distinct).
- Validate the initial request, every pagination target, and every redirect.
  Reject userinfo, an unexpected authentication query, cross-origin targets,
  path-boundary escape, HTTPS downgrade, repeated targets, and regressing
  pagination cursors.
- Do not rely on urllib's default redirect behavior as a security policy.
- Reject authenticated HTTP and authenticated `verify_tls: false` at preflight.
  Credentialless insecure transport is explicit, loopback-only, diagnostic, and
  never render-eligible.
- Bound bytes while reading the response rather than after an unbounded read.
  Also bound JSON nesting, per-page item count, normalized entity count, string
  size, and final Bundle size. Limit failures become typed coverage diagnostics;
  a required-source limit failure blocks rendering.

Acceptance requires regression tests for all three authentication styles,
including external/loopback/link-local targets, scheme downgrade, API-prefix
escape, redirects, cycles, cursor regression, compressed/oversized responses,
deep JSON, and valid siblings near each limit.

### P0-B: core-first fair scheduling

- Canonically sort repositories by repository ID. Reject a group before network
  I/O when `max_requests < 5 * repository_count`, the minimum root plus first
  top-level page attempt for every required non-interaction source.
- Establish every repository root, then queue top-level pages by page depth,
  repository ID, and the fixed source order work items, change requests,
  commits, releases.
- Queue discovered N+1 interactions by repository ID, subject type/ID, and
  endpoint kind, issuing at most one request per repository per round.
- Interactions remain required core coverage. Their size is not guessed during
  preflight; optional activity/ref starts only after all required queues finish.
- Required runtime exhaustion produces scoped `incomplete` observations,
  `budget_exhausted`, and typed blockers. Optional exhaustion produces scoped
  warnings and never changes completed core coverage.
- Keep the existing provider-instance `max_requests` meaning. Do not add global,
  per-repository, or user-configurable source budgets without runtime evidence.
- Isolate unexpected failures at `(provider, instance, repository)` while
  retaining safe sibling diagnostics. A privacy violation still closes the
  aggregate render gate.

Acceptance requires permutation tests proving that repository configuration
order cannot change core coverage, plus infeasible preflight, deterministic
tie-breaking, large-first-repository, interaction N+1, optional exhaustion, and
partial repository failure cases.

### P0-C: real CI with debt lanes

Create a network-free pull-request workflow for the declared Python support
matrix. Blocking gates are:

- pytest and compileall;
- source/package Schema single-authority consistency;
- `git diff --check`;
- sdist and wheel build;
- install the wheel into a clean environment, load its packaged Schema, and run
  CLI provider/doctor/validate/render smoke tests.

Ruff, Ruff format, and Pyright begin as visible non-blocking debt lanes with
their baselines recorded. Clean them in cohesive follow-up changes, then make
each lane blocking only after it reaches zero. Dependency audit and CodeQL may
be added as visible security lanes before their failure policy is calibrated.
Live canaries remain manual/protected and are never part of ordinary PR CI.

## P1 hardening decisions

These are high-confidence corrections and do not need new product choices.

### Configuration and instance identity

- Reject unknown keys by default at every mapping level; no separate lenient
  default or `config check --strict` opt-in.
- Reject duplicate canonical repositories during preflight.
- Validate IANA timezone names. Offset timestamps define the collection window;
  the timezone defines rendering/calendar interpretation and must not silently
  move the instant boundaries.
- Normalize scheme, IDNA host, case, effective port, base path, and trailing
  separators before building provider/repository IDs.

### Integrity, coverage, and validation

- Aggregate provider capability summaries with a deterministic conservative
  order; never use last-write-wins. Repository-scoped observations remain the
  render-gate authority.
- Replace mixed strings/dicts in the fatal ledger with one typed blocker shape.
- Give every Interaction an explicit typed `subject_id` and `subject_type`.
- Validate revision identifiers according to the provider/algorithm contract;
  rename any merely non-sentinel helper so its name does not promise SHA
  verification.
- Split validation by responsibility—schema, references/integrity, privacy,
  coverage assessment, and render policy—behind one stable public validator.
  Do this incrementally, not through a directory rewrite.
- Return structured issues with code, severity, JSON path, scope, and safe
  remediation. Recompute render eligibility from blockers; never trust a
  caller-supplied Boolean as authority.

### Pagination and provider behavior

- Each provider owns its pagination strategy and documented termination proofs.
  Record `cursor_exhausted`, `link_exhausted`, documented short-page,
  date-boundary, limit, and cycle outcomes explicitly.
- Permit historical early termination only when a provider-specific contract
  proves stable ordering for that endpoint.
- Separate collector availability from offline Bundle validity. A historical
  Bundle embeds the provider descriptor/namespace needed for validation; an
  installed collector registry is not required merely to read it.

### Privacy and security

- Keep canonical Bundles sensitive; do not implement HMAC actor modes until a
  machine-readable public export is an accepted requirement.
- Scan all strings for configured secret values, URL-encoded variants,
  authorization assignments, private-key markers, and high-confidence token
  forms. Malformed values in URL-typed fields fail closed.
- Treat low-confidence entropy/token-like matches as warnings so ordinary IDs
  do not become false-positive blockers.
- Replace broad key-name bans gradually with typed allowed structures, keeping
  secret-bearing transport context separate from public cryptographic metadata.
- Expand SECURITY.md with supported versions, a private reporting channel,
  response expectations, threat actors, untrusted inputs, protected assets,
  and explicit non-guarantees.

### CLI, I/O, and packaging

- Complete localization, escape Unicode bidi/zero-width controls, avoid repeated
  actor labels, and keep all profile behavior deterministic.
- Add `--version`, structured diagnostics, stable exit-code documentation,
  verbosity controls, normalized config/plan preview, and endpoint/budget dry
  run. Treat stdin/stdout support as convenience, not a safety prerequisite.
- Use one atomic, permission-aware writer for Bundles, reports, and cache.
- Establish one package version source, derive User-Agent from it, ship
  `py.typed`, use one Schema source, test installed artifacts, and replace the
  deprecated license table. Add release/community metadata when publication is
  actually prepared.

### Test maintenance

- Split the giant tests by behavior boundary without changing coverage first.
- Add targeted property tests for URL redaction, ID round-trips, pagination
  termination, blocker monotonicity, warning merge order, and corrupt cache.
- Build a provider conformance helper from repeated fixture assertions after
  the provider-specific pagination contracts stabilize.
- Defer broad fuzzing and mutation testing until the deterministic P0/P1 lanes
  are green and owned; they are useful assurance tools, not prerequisites for
  fixing known defects.

## v0.2 contract migration

The v0.2 Schema is strict and typed per entity, with unknown extension data
contained under provider-namespaced `extensions`. It adds Retrieval and
Assertion collections, the three explicit identities, typed blockers, scoped
coverage, and `render_eligible`; it removes free-text Facts and `run_id`.

The canonicalization and hash envelope are defined by ADR-0018 and are part of
Schema acceptance, not a later signing feature.

Migration policy:

- collectors emit only the latest Schema;
- validator and renderer read v0.1 and v0.2 for one documented compatibility
  window;
- migration is explicit and records the source artifact digest—loading never
  silently rewrites an audit artifact;
- schema-generated or packaged copies come from one authority;
- breaking predicate or entity meaning requires another Schema version, not an
  unversioned provider extension.

## Post-v0.2 integration hardening

- Configuration uses named provider-instance entries referenced by
  repositories, allowing different credentials and limits for multiple
  instances of one provider kind.
- Every rendered activity Assertion carries a stable Evidence marker even when
  source URLs are hidden. Scope-qualified Coverage and Retrieval provenance are
  rendered directly from their authoritative records, not copied into
  Assertions.
- Reports show invocation, Bundle digest, generator, profile, language, and
  policy version metadata. Bundle JSON remains distinct from rendered report
  formats; no JSON report backend is advertised until one exists.

## Explicitly rejected or deferred advice

- Do not combine P0 transport work with Schema v0.2 or a full package move.
- Do not claim that anonymized rendering makes the canonical Bundle anonymous.
- Do not add public pseudonym modes before a public JSON artifact is required.
- Do not create field digests or API versions that cannot be independently
  established.
- Do not introduce incremental checkpoints, bounded concurrency, plugin entry
  points, in-toto/SLSA envelopes, signing, SBOM, or signed releases as substitutes
  for the current transport, coverage, and CI gaps.
- Do not use a proposed directory tree as acceptance evidence. Behavior,
  contracts, replay fixtures, and failure-path tests are the acceptance units.

## Validation boundary

This roadmap is based on current source, docs, ADRs, synthetic fixtures, and
offline test/build probes. It does not include live-provider, proxy/redirect,
private-CA, GitHub Actions, package-index installation, or disclosure review.
Those remain explicit runtime/release evidence gates during implementation.
