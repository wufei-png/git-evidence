#!/usr/bin/env bash
set -euo pipefail

umask 077
canary_root="${RUNNER_TEMP:?}/git-evidence-live-canary"
mkdir -p "$canary_root"
trap 'rm -f "$canary_root/config.toml" "$canary_root/bundle.json" "$canary_root/report.md" "$canary_root/doctor.log" "$canary_root/collect.log" "$canary_root/validate.log" "$canary_root/render.log"' EXIT
printf '%s' "${LIVE_CANARY_CONFIG_CONTENT:?}" > "$canary_root/config.toml"

run_quietly() {
  local label="$1"
  local log="$2"
  shift 2
  set +e
  "$@" > "$log" 2>&1
  local status=$?
  set -e
  if (( status != 0 )); then
    printf '%s: failed (exit %s)\n' "$label" "$status" >&2
    return "$status"
  fi
  printf '%s: ok\n' "$label"
}

run_quietly CANARY_DOCTOR "$canary_root/doctor.log" \
  git-evidence doctor --config "$canary_root/config.toml"
python - \
  "$canary_root/config.toml" \
  "${LIVE_EXPECTED_PROVIDER:?}" \
  "${LIVE_ALLOWED_INSTANCES:?}" <<'PY'
import sys

from git_evidence.config import load_collection_config
from git_evidence.providers.base import validate_instance

config = load_collection_config(sys.argv[1])
expected = sys.argv[2]
allowed_instances = {
    validate_instance(value.strip())
    for value in sys.argv[3].split(",")
    if value.strip()
}
if not allowed_instances:
    raise SystemExit("canary instance allowlist is empty")
repositories = config.repositories
if not repositories or {item.target.provider_kind for item in repositories} != {expected}:
    raise SystemExit("canary repository allowlist does not match selected provider")
configured_instances = {
    validate_instance(item.target.instance)
    for item in repositories
}
if not configured_instances <= allowed_instances:
    raise SystemExit("canary repository instance is not independently allowlisted")
providers = config.providers
if {provider.kind for provider in providers} != {expected}:
    raise SystemExit("canary provider config does not match selected provider")
if len(providers) != 1 or providers[0].token_env != "LIVE_PROVIDER_TOKEN":
    raise SystemExit("canary config must use token_env: LIVE_PROVIDER_TOKEN")
print(
    "CANARY_SCOPE: "
    f"provider={expected} "
    f"window_start={config.window_start} "
    f"window_end={config.window_end} "
    f"timezone={config.timezone} "
    f"repository_count={len(repositories)}"
)
PY
run_quietly CANARY_COLLECT "$canary_root/collect.log" \
  git-evidence collect --config "$canary_root/config.toml" \
    --output "$canary_root/bundle.json" \
    --diagnostics-format json
run_quietly CANARY_VALIDATE "$canary_root/validate.log" \
  git-evidence validate "$canary_root/bundle.json" \
    --diagnostics-format json
run_quietly CANARY_RENDER "$canary_root/render.log" \
  git-evidence render "$canary_root/bundle.json" \
    --config "$canary_root/config.toml" \
    --output "$canary_root/report.md"
test -s "$canary_root/report.md"
