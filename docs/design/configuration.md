# Configuration boundary

Configuration describes what a run is authorized and expected to inspect. It
does not contain secrets or report facts.

```yaml
window:
  start: 2026-07-27T00:00:00Z
  end: 2026-08-03T00:00:00Z
  timezone: UTC

scope:
  repositories:
    - provider: github
      instance: github.com
      owner: example
      name: project
  actors: []

providers:
  github:
    token_env: GITHUB_TOKEN
    include_activity_api: false
    verify_tls: true
    timeout_seconds: 30
    max_retries: 2
    max_pages: 100
    max_requests: 1000
    retry_backoff_seconds: 0.5
    retry_jitter_seconds: 0.25
    retry_after_max_seconds: 60
    cache:
      enabled: false
      path: .git-evidence-cache.json
      ttl_seconds: 300
      max_entries: 256

report:
  profile: project-first
  language: en
  display_actor_names: false
  actor_labels: {}
  privacy:
    actor_display: anonymous
    allow_source_urls: true
    auth_redaction: true
```

Rules:

- `scope.repositories` is required and is the allowlist authority.
- `scope.actors` is an optional narrowing allowlist of canonical actor IDs. It
  filters records that carry an actor; repository and other actor-neutral
  entities remain in scope. Bundle validation also rejects actor references
  that do not resolve to an actor entity or fall outside a non-empty allowlist.
- `window` is a timezone-aware half-open interval `[start, end)`.
- Tokens come from environment variables, a keyring, or a CI secret; they are
  never stored in this file or passed as a command-line value.
- `include_activity_api: false` is honest: resource-backed facts remain
  available, but push/ref completeness is unavailable.
- `display_actor_names` defaults to false. Names are rendered only when it is
  true and `report.actor_labels` contains an explicit mapping from the full
  canonical actor ID to a non-empty display label. Bundle-provided names are
  never trusted by the renderer.
- Collection and report settings have separate validators. `collect` uses
  `load_collection_config` and ignores invalid report settings; `render` uses
  `load_report_config` and ignores collection settings. `load_config` remains
  the strict legacy single-file compatibility loader.
- `report.privacy.actor_display` defaults to `anonymous`; `explicit-labels`
  displays only labels supplied in `report.actor_labels`. `auth_redaction` is
  mandatory and source URLs remain allowed evidence after auth query/userinfo
  sanitization. Inline credentials are rejected; use `token_env` instead.
- Report profile and language change presentation only; they cannot relax
  required coverage or evidence validation.
- Provider request limits are bounded per `(provider, instance)` group. The
  defaults are a 30-second timeout, 2 retries, 100 pages per logical list,
  1000 total HTTP requests, 0.5-second exponential backoff with at most
  0.25 seconds of jitter, and a 60-second `Retry-After` cap. GET retries are
  idempotent; exhausted limits remain visible in collection metrics and block
  publication for affected required sources.
- Cache is disabled unless `cache.enabled: true` and `path`, `ttl_seconds`,
  and `max_entries` are explicitly supplied. Cache keys include provider,
  instance, path, parameters, and a token-scope digest. Only redacted URL,
  status, and safe JSON body data may be stored; authorization headers and
  tokens are never written. Expired, unreadable, or unsafe entries are cache
  misses. A cache hit follows the same normalizer and coverage gate and never
  upgrades capability.

`git-evidence collect` groups the allowlist by `(provider, instance)`, invokes
each provider adapter, and merges the results into one canonical bundle. The
provider config is shared by all repositories for that provider kind; separate
instances are collected as separate provider groups. If `token_env` is set,
the runtime reads that environment variable and never accepts a token on the
command line. A missing environment variable is treated as a collection
configuration error rather than silently lowering authorization.

A provider-group `ProviderNotReady`, API, or unexpected collection failure is
recorded in `coverage.group_failures` with provider, instance, repository,
source, and `failure_class`. Other groups remain in the bundle for diagnosis,
but any failed required source sets `allow_publish: false`. Configuration and
missing-token errors are preflight failures and return CLI status 2; a bundle
with one or more failed provider groups returns status 3; ordinary schema or
semantic publication failures return status 1.

`git-evidence render --config config.yml bundle.json` applies the report
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
failures still block publication after retries are exhausted. Every normalized
resource and activity/ref source rejects missing native identity, repository
identity, or required timestamp fields item-by-item; valid siblings are kept,
while the source is marked `incomplete` with `malformed_response` and a
`dropped_count`.
