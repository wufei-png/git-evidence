from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

MAX_ERRORS = 68
MAX_WARNINGS = 0
COMMAND = ("pyright", "src/git_evidence", "--outputjson")


def _summary(payload: Any) -> dict[str, int]:
    if not isinstance(payload, dict) or not isinstance(payload.get("summary"), dict):
        raise TypeError("Pyright output did not contain a summary object")
    summary = payload["summary"]
    counts: dict[str, int] = {}
    for key in ("errorCount", "warningCount"):
        value = summary.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Pyright summary.{key} must be a non-negative integer")
        counts[key] = value
    return counts


def main() -> int:
    completed = subprocess.run(
        COMMAND,
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        counts = _summary(json.loads(completed.stdout))
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"pyright baseline check failed: {exc}", file=sys.stderr)
        if completed.stderr:
            print(completed.stderr.rstrip(), file=sys.stderr)
        return 2
    errors = counts["errorCount"]
    warnings = counts["warningCount"]
    print(
        "Pyright production-source baseline: "
        f"errors={errors}/{MAX_ERRORS}, warnings={warnings}/{MAX_WARNINGS}"
    )
    if errors > MAX_ERRORS or warnings > MAX_WARNINGS:
        print("Pyright diagnostics exceeded the committed baseline", file=sys.stderr)
        return 1
    if completed.returncode not in {0, 1}:
        print(
            f"Pyright exited unexpectedly with status {completed.returncode}",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
