from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUTHORITATIVE_SCHEMA = ROOT / "schemas" / "evidence-bundle-0.1.schema.json"
PACKAGED_SCHEMA = (
    ROOT / "src" / "git_evidence" / "schemas" / "evidence-bundle-0.1.schema.json"
)


def main() -> int:
    authoritative = AUTHORITATIVE_SCHEMA.read_bytes()
    packaged = PACKAGED_SCHEMA.read_bytes()
    if authoritative != packaged:
        raise SystemExit(
            "packaged Schema differs from schemas/evidence-bundle-0.1.schema.json"
        )
    parsed = json.loads(authoritative)
    if parsed.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise SystemExit("authoritative Schema does not declare draft 2020-12")
    print("SCHEMA: authoritative and packaged copies are identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
