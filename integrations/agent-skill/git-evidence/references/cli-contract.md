# CLI orchestration contract

The Skill is an optional adapter. The Git Evidence CLI remains authoritative
for configuration validation, provider collection, Bundle validation, coverage,
render eligibility, privacy checks, and report rendering.

## Diagnostic streams

Every orchestrated command uses `--diagnostics-format json`. JSON diagnostics
always contain `status` and `issues`.

| Command | Artifact stream | JSON diagnostic stream |
| --- | --- | --- |
| `doctor` | none | stdout |
| `collect` | `--output` file | stderr |
| `validate` | none | stdout |
| `render` | `--output` file | stderr |

The runner spools these streams outside memory, reads at most 1 MiB of the
selected diagnostic stream, and never stores raw stdout or stderr in its
receipt. It retains bounded structured issues and a small allowlist of summary
fields. Oversized or malformed diagnostics fail as a protocol error.
Successful `validate` diagnostics carry the core-owned Coverage projection used
to populate offline receipts, including the blocking provider-group count.

## Exit codes and sequencing

- `0`: success, possibly with non-blocking warnings.
- `1`: validation or render-eligibility failure.
- `2`: configuration, input, collection setup, or output I/O failure.
- `3`: required provider-group collection failure.
- `70`: redacted internal failure or an invalid CLI/runner protocol response.

Stop after any non-zero stage. A failed collection may still leave a diagnostic
Bundle; its existence does not authorize validation, rendering, or disclosure.

## Receipt contract

`git-evidence-agent-receipt-1` contains the run mode, private artifact paths,
ordered stage results, and—when a readable Bundle exists—a bounded summary:

- `plan_id`, `invocation_id`, and `bundle_digest`;
- Assertion and Evidence counts;
- declared `render_eligible` state;
- Coverage warning and provider-group failure counts;
- bounded Coverage warning and group-failure projections plus truncation counts;
- total and blocking provider-group failure counts remain distinct;
- distinct Retrieval modes such as `live`, `cache_replay`, or `recorded_replay`.

The receipt is an operational handoff, not an Evidence Bundle, validation
authority, privacy attestation, or disclosure approval.

## Collection configuration boundary

Generate a separate private TOML configuration only after resolving exact
window, timezone, provider instance, repository allowlist, actor scope,
retrieval expectations, profile, language, and report privacy. Credentials are
environment references only. Do not mutate an existing user configuration and
do not retain the generated file unless explicitly requested.
