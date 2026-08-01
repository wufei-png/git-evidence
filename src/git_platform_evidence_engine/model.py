from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO


COLLECTION_KEYS = (
    "providers",
    "repositories",
    "actors",
    "work_items",
    "change_requests",
    "interactions",
    "commits",
    "ref_changes",
    "releases",
    "evidence",
    "facts",
)


class BundleLoadError(ValueError):
    """The evidence bundle cannot be read as a JSON object."""


def load_bundle(source: str | Path | TextIO) -> dict[str, Any]:
    """Load a canonical bundle from a path or an open text stream."""
    try:
        if hasattr(source, "read"):
            value = json.load(source)  # type: ignore[arg-type]
        else:
            value = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleLoadError(str(exc)) from exc
    if not isinstance(value, dict):
        raise BundleLoadError("evidence bundle root must be a JSON object")
    return value


def collection(bundle: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return a collection while leaving shape errors to the validator."""
    value = bundle.get(key, [])
    return value if isinstance(value, list) else []
