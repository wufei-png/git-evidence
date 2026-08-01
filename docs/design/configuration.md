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

report:
  profile: project-first
  language: en
  display_actor_names: false
  actor_labels: {}
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
- Report profile and language change presentation only; they cannot relax
  required coverage or evidence validation.

`git-evidence collect` groups the allowlist by `(provider, instance)`, invokes
each provider adapter, and merges the results into one canonical bundle. The
provider config is shared by all repositories for that provider kind; separate
instances are collected as separate provider groups. If `token_env` is set,
the runtime reads that environment variable and never accepts a token on the
command line. A missing environment variable is treated as a collection
configuration error rather than silently lowering authorization.

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
failures still block publication after retries are exhausted.
