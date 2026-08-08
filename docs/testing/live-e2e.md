# Live CLI and API replay

This runbook is for smoke-testing the public adapters against repositories that
are explicitly allowlisted for the run. It is not a production certification:
the result is bounded by the selected window, the provider account, API
retention, pagination limits, and the current adapter version.

## Safety boundary

- Use a newly created or otherwise non-company repository where the operator is
  authorized to read the data. Do not use private company repositories in this
  project.
- Keep tokens in environment variables or the provider CLI credential store.
  Do not put tokens in YAML, shell history, fixtures, or committed bundles.
- Write live bundles and rendered reports under `/tmp` or the ignored
  `evidence/` and `reports/` directories. Live bundles are not public
  contract fixtures.
- The repository allowlist is authoritative. An empty result is not evidence
  that another project, actor, or time range was covered.

## CLI checks

Use the native CLI for its own login and project discovery checks:

```bash
gh auth status --hostname github.com
glab auth status --hostname jihulab.com
gitee user search <public-user>
```

`gh` is the GitHub CLI; it is not a substitute for `glab` when the target is a
Jihulab/GitLab instance. The current Gitee CLI exposes issue and pull-request
commands, but not the complete repository/commit/release read surface used by
this adapter. The Gitee provider therefore uses the Gitee v5 API for the
canonical collection and uses the CLI only as an additional operator check.

## Collection checks

Create an uncommitted live configuration with an explicit allowlist and a
provider token environment variable where required:

```yaml
window:
  start: 2026-07-26T00:00:00Z
  end: 2026-08-02T00:00:00Z
  timezone: UTC

scope:
  repositories:
    - provider: github
      instance: github.com
      owner: <owner>
      name: <repository>

providers:
  github:
    token_env: GITHUB_TOKEN
    include_activity_api: true
```

Run the same flow for each provider with a provider-specific target and token
environment variable:

```bash
PYTHONPATH=src python3 -m git_evidence collect \
  --config /tmp/live-config.yml \
  --output /tmp/live-bundle.json
PYTHONPATH=src python3 -m git_evidence validate /tmp/live-bundle.json
PYTHONPATH=src python3 -m git_evidence render \
  /tmp/live-bundle.json --profile timeline --output /tmp/live-report.md
```

The acceptance checks are:

1. `collect` writes a bundle even when rendering is blocked, so the failure
   can be inspected.
2. `validate` returns `VALIDATION: none` for a render-eligible replay. This is
   not approval to disclose the Bundle or report.
3. `render` succeeds offline and makes no provider request.
4. Every allowlisted resource has a coverage observation.
5. Activity/ref coverage is reported as `incomplete` or `unsupported` unless a
   provider-specific completeness proof exists, and each non-supported
   observation has a matching `coverage.warnings[]` entry.
6. A ref association is `linked` only after all commit-to-change-request
   checks needed for that ref complete successfully. Partial or failed checks
   remain `unknown`; multiple candidates are `ambiguous`; an empty result is
   `unlinked` only after a complete check.

## Failure and association inspection

Inspect coverage without printing credentials or response bodies containing
secrets:

```bash
jq '.coverage.observations | map({source,status,note,diagnostics})' \
  /tmp/live-bundle.json
jq '.coverage.warnings' /tmp/live-bundle.json
jq '.ref_changes | group_by(.change_association) |
  map({state: .[0].change_association, count: length})' \
  /tmp/live-bundle.json
```

Capability state and operational cause are separate fields. For example,
`status: incomplete` with `diagnostics.failure_class: rate_limited` means the
source was attempted but a bounded retry budget was exhausted; it does not
mean the source is unsupported. The current stable failure classes include
`permission_denied`, `rate_limited`, `service_error`, `not_found`,
`request_rejected`, `malformed_response`, `network_error`, and
`fixture_missing`. A fan-out source that encountered more than one distinct
cause uses `diagnostics.failure_classes` so the last child request cannot hide
an earlier permission, throttling, or service error.

## Recorded smoke evidence

On 2026-08-01, a non-company Jihulab project and the public GitHub `cli/cli`
repository both completed live collection and offline validation/rendering.
The Jihulab replay observed 10 ref changes with 11 complete commit-association
attempts; the GitHub replay observed 29 complete association attempts and
produced `linked`, `unlinked`, and `ambiguous` states. Both activity surfaces
remained `incomplete`, as expected for bounded event supplements.

A public Gitee replay completed the resource surface after the collector
removed an unsupported `sort=updated_at` query parameter. Its resource
coverage was supported for the selected repository/window; activity/ref
coverage remained explicitly `unsupported`. This is evidence of a working
smoke path, not a claim that Gitee's activity API has been implemented.
