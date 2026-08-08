#!/usr/bin/env bash
set -euo pipefail

umask 077
canary_root="${RUNNER_TEMP:?}/git-evidence-live-canary"
mkdir -p "$canary_root"
trap 'rm -f "$canary_root/config.yml" "$canary_root/bundle.json" "$canary_root/report.md" "$canary_root/doctor.log" "$canary_root/collect.log" "$canary_root/validate.log" "$canary_root/render.log"' EXIT
printf '%s' "${LIVE_CANARY_CONFIG_CONTENT:?}" > "$canary_root/config.yml"

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
  git-evidence doctor --config "$canary_root/config.yml"
python - \
  "$canary_root/config.yml" \
  "${LIVE_EXPECTED_PROVIDER:?}" \
  "${LIVE_ALLOWED_INSTANCES:?}" <<'PY'
from pathlib import Path
import sys

import yaml
from git_evidence.providers.base import validate_instance

config = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = sys.argv[2]
allowed_instances = {
    validate_instance(value.strip())
    for value in sys.argv[3].split(",")
    if value.strip()
}
if not allowed_instances:
    raise SystemExit("canary instance allowlist is empty")
repositories = config["scope"]["repositories"]
if not repositories or {item["provider"] for item in repositories} != {expected}:
    raise SystemExit("canary repository allowlist does not match selected provider")
configured_instances = {
    validate_instance(item["instance"])
    for item in repositories
}
if not configured_instances <= allowed_instances:
    raise SystemExit("canary repository instance is not independently allowlisted")
providers = config["providers"]
if set(providers) != {expected}:
    raise SystemExit("canary provider config does not match selected provider")
if providers[expected].get("token_env") != "LIVE_PROVIDER_TOKEN":
    raise SystemExit("canary config must use token_env: LIVE_PROVIDER_TOKEN")
window = config["window"]
print(
    "CANARY_SCOPE: "
    f"provider={expected} "
    f"window_start={window['start']} "
    f"window_end={window['end']} "
    f"timezone={window['timezone']} "
    f"repository_count={len(repositories)}"
)
PY
run_quietly CANARY_COLLECT "$canary_root/collect.log" \
  git-evidence collect --config "$canary_root/config.yml" \
    --output "$canary_root/bundle.json" \
    --diagnostics-format json
run_quietly CANARY_VALIDATE "$canary_root/validate.log" \
  git-evidence validate "$canary_root/bundle.json" \
    --diagnostics-format json
run_quietly CANARY_RENDER "$canary_root/render.log" \
  git-evidence render "$canary_root/bundle.json" \
    --config "$canary_root/config.yml" \
    --output "$canary_root/report.md"
test -s "$canary_root/report.md"
