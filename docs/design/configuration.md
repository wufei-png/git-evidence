# Configuration boundary

Configuration describes what a run is authorized and expected to inspect. It
does not contain secrets or report facts.

```toml
[window]
start = 2026-07-27T00:00:00Z
end = 2026-08-03T00:00:00Z
timezone = "UTC"

[scope]
actors = []

[[scope.repositories]]
provider_ref = "public-github"
owner = "example"
name = "project"

[providers.public-github]
kind = "github"
instance = "github.com"
token_env = "GITHUB_TOKEN"
include_activity_api = false

[providers.public-github.transport]
verify_tls = true
allow_insecure_loopback = false
timeout_seconds = 30
max_retries = 2
max_pages = 100
max_requests = 1000
retry_backoff_seconds = 0.5
retry_jitter_seconds = 0.25
retry_after_max_seconds = 60

[providers.public-github.cache]
enabled = false
path = ".git-evidence-cache.json"
ttl_seconds = 300
max_entries = 256

[report]
profile = "project-first"
language = "en"
display_actor_names = false

[report.actor_labels]

[report.privacy]
actor_display = "anonymous"
allow_source_urls = true
auth_redaction = true
```

Rules:

- TOML is the only accepted configuration syntax. YAML and other historical
  shapes are rejected rather than detected or migrated.
- Configuration files are limited to 1 MiB, 16 nested levels, and 16 Ki
  characters per key or string value before semantic validation.
- `scope.repositories` is required and is the allowlist authority. Each entry
  names a provider instance through `provider_ref`; provider kind and instance
  are declared once under `[providers.<ref>]`.
- `scope.actors` is an optional narrowing allowlist of canonical actor IDs. It
  filters records that carry an actor; repository and other actor-neutral
  entities remain in scope. Bundle validation also rejects actor references
  that do not resolve to an actor entity or fall outside a non-empty allowlist.
- `window` is a timezone-aware half-open interval `[start, end)`.
- Tokens come from environment variables, a keyring, or a CI secret; they are
  never stored in this file or passed as a command-line value.
- Authenticated collection requires HTTPS with `verify_tls: true` and has no
  bypass. Credentialless HTTP or disabled TLS verification is accepted only
  with `allow_insecure_loopback: true` on a loopback instance; its output is
  diagnostic and cannot pass the render gate.
- `include_activity_api: false` is honest: resource-backed facts remain
  available, but push/ref completeness is unavailable.
- `display_actor_names` defaults to false. Names are rendered only when it is
  true and `report.actor_labels` contains an explicit mapping from the full
  canonical actor ID to a non-empty display label. Bundle-provided names are
  never trusted by the renderer.
- Collection and report settings materialize frozen typed configuration
  objects. `load_collection_config` performs validation once at the file
  boundary; `collect_config` accepts only that validated type.
- `report.privacy.actor_display` defaults to `anonymous`; `explicit-labels`
  displays only labels supplied in `report.actor_labels`. `auth_redaction` is
  mandatory and source URLs remain allowed evidence after auth query/userinfo
  sanitization. Inline credentials are rejected; use `token_env` instead.
- Report profile and language change presentation only; they cannot relax
  required coverage or evidence validation.
- Provider request limits are bounded per `(kind, instance)` group. The
  defaults are a 30-second timeout, 2 retries, 100 pages per logical list,
  1000 total HTTP requests, 0.5-second exponential backoff with at most
  0.25 seconds of jitter, and a 60-second `Retry-After` cap. GET retries are
  idempotent; exhausted limits remain visible in collection metrics and block
  rendering for affected required sources.
- The hard caps are 300 seconds for timeout, 10 retries, 1000 pages, 10000
  requests, 60 seconds each for backoff/jitter, 300 seconds for the
  `Retry-After` cap, 86400 seconds for cache TTL, and 10000 cache entries.
  Non-finite values and unbounded `None` request budgets are rejected. If a
  retryable 429/5xx response is followed by budget exhaustion, the original
  `rate_limited`/`service_error` remains the primary failure and
  `budget_exhausted` is recorded as an additional cause.
- Cache is disabled unless `[providers.<ref>.cache]` has `enabled = true` and
  `path`, `ttl_seconds`,
  and `max_entries` are explicitly supplied. Cache keys include provider,
  instance, path, parameters, and a token-scope digest. Only redacted URL,
  status, safe JSON body data, and allowlisted `Link`/next-page/rate-limit
  headers may be stored; only non-boolean 2xx statuses and validated,
  credential-free header values are accepted. Authorization headers and
  tokens are never written. Invalid or sensitive pagination headers make the
  entry a cache miss.
  Cache files and temporary files are mode `0600`; expired, unreadable,
  unredacted, unsafe, or old entries without headers are cache misses. A cache
  hit follows the same normalizer and coverage gate and never upgrades
  capability.
- A collection plan must reserve at least five requests per repository in each
  `(provider, instance)` group: one repository root and the first work-item,
  change-request, commit, and release page attempts. An infeasible group raises
  the typed `plan_budget_infeasible` configuration error before provider
  construction or network I/O. Repository targets are canonically ordered by
  provider, instance, owner, and name; configuration position is not an
  execution priority.

`git-evidence collect` groups the allowlist by `(kind, instance)`, invokes
each provider adapter, and merges the results into one canonical bundle. The
provider instance config is shared only by repositories using its `provider_ref`.
Canonical `(kind, instance)` pairs must be unique, unused provider definitions
are rejected, and separate instances have separate credentials and transport
budgets. If `token_env` is set,
the runtime reads that environment variable and never accepts a token on the
command line. A missing environment variable is treated as a collection
configuration error rather than silently lowering authorization.

A provider-group `ProviderNotReady`, API, transport, budget, malformed, typed,
or unexpected collection failure is recorded in `coverage.group_failures` with
provider, instance, repository, source, and `failure_class`, and is linked to
the matching observation (and to a structured fatal entry for required
sources). Other groups remain in the bundle for diagnosis. A core resource
group failure forces `allow_publish: false`; ordinary optional activity/ref
malformed, typed, transport, or capability failures remain render-eligible with a
structured coverage warning. An optional `privacy_violation` is the security
exception: it requires a fatal ledger entry and keeps `allow_publish: false`.
Configuration and missing-token errors are preflight failures and return CLI
status 2; a bundle with one or more failed core provider groups returns status
3, while an optional-only non-privacy failure returns status 0 with coverage
warnings; ordinary schema or semantic render-gate failures return status 1.

`git-evidence render --config config.toml bundle.json` applies the report
profile, language, actor display flag, and explicit `actor_labels` map without
making any provider request.

For an intentionally anonymous public run, omit `token_env` explicitly and
accept the provider's anonymous rate and visibility limits.

The first public collector slice treats activity/ref collection as an optional
supplement. `include_activity_api: true` records a provider-specific
`incomplete` or `unsupported` capability; it does not upgrade a commit into a
push claim. Resource-backed Issues, change requests, comments, commits, and
releases remain the primary collection surface.

The transport retries bounded transient `429` and `5xx` failures and records
safe rate-limit diagnostics in coverage observations. Required resource
failures still block rendering after retries are exhausted. Every normalized
resource and activity/ref source rejects missing native identity, repository
identity, or required timestamp fields item-by-item; valid siblings are kept,
while the source is marked `incomplete` with `malformed_response` and a
`dropped_count`. The same source-level status applies to duplicate canonical
IDs: the first valid record and other valid siblings remain, but the collision
is recorded and required rendering is blocked. Coverage matching includes
the registered provider identity as well as repository and source.

Every initial, pagination, and redirect target is validated against the actual
transport API base rather than the web instance label. Follow-ups must retain
scheme, canonical host, effective port, and API path prefix; userinfo,
fragments, supplied authentication query fields, downgrade, path escape,
redirect cycles, repeated pagination targets, and regressing page numbers are
rejected before another request can carry credentials.

Untrusted provider input is bounded independently of runtime configuration.
One response may contain at most 8 MiB of identity-encoded JSON, with at most
64 nesting levels and 256 Ki characters in any key or string value. Compressed
responses are rejected because the client requests identity encoding. A page
may contain at most 1000 items, a logical paginated source at most 100000
items and 32 MiB of decoded JSON, a provider or aggregate bundle at most
100000 normalized entities, and the final indented UTF-8 bundle at most
64 MiB. Cache files are also limited to 64 MiB, while each replayed response
must independently remain within the 8 MiB response bound. `limit_exceeded` is a typed
operational failure: it makes an affected required source incomplete and
blocks rendering. Aggregate overflow is replaced by a bounded diagnostic
bundle that preserves prior provider/privacy failures rather than writing the
oversized artifact or fabricating provider-source failures.
