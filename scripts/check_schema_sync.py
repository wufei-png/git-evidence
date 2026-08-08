from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "src" / "git_evidence" / "schemas"
LEGACY_DUPLICATE_ROOT = ROOT / "schemas"


def main() -> int:
    schema_paths = sorted(SCHEMA_ROOT.glob("evidence-bundle-*.schema.json"))
    if {path.name for path in schema_paths} != {
        "evidence-bundle-0.1.schema.json",
        "evidence-bundle-0.2.schema.json",
    }:
        raise SystemExit("authoritative package must contain exactly the 0.1 and 0.2 Schemas")
    duplicate_paths = list(LEGACY_DUPLICATE_ROOT.glob("evidence-bundle-*.schema.json"))
    if duplicate_paths:
        raise SystemExit("Schema copies outside src/git_evidence/schemas are forbidden")
    for path in schema_paths:
        parsed = json.loads(path.read_text(encoding="utf-8"))
        if parsed.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise SystemExit(f"{path.name} does not declare draft 2020-12")
    print("SCHEMA: package resources are the single authority for 0.1 and 0.2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
