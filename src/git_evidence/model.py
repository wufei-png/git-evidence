from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO

from .bounds import (
    InputLimitError,
    read_bounded_bytes,
    read_bounded_text,
    validate_json_value_limits,
)
from .limits import (
    MAX_BUNDLE_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_STRING_CHARS,
    MAX_NORMALIZED_ENTITIES,
)

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
ALL_COLLECTION_KEYS = (*COLLECTION_KEYS, "retrievals", "assertions")


class BundleLoadError(ValueError):
    """The evidence bundle cannot be read as a JSON object."""


def load_bundle(source: str | Path | TextIO) -> dict[str, Any]:
    """Load a canonical bundle from a path or an open text stream."""
    try:
        if hasattr(source, "read"):
            text = read_bounded_text(source, max_bytes=MAX_BUNDLE_BYTES)  # type: ignore[arg-type]
            value = json.loads(text)
        else:
            value = json.loads(read_bounded_bytes(source, max_bytes=MAX_BUNDLE_BYTES))
        validate_json_value_limits(
            value,
            max_depth=MAX_JSON_DEPTH,
            max_string_chars=MAX_JSON_STRING_CHARS,
        )
    except (
        InputLimitError,
        OSError,
        RecursionError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise BundleLoadError(str(exc)) from exc
    if not isinstance(value, dict):
        raise BundleLoadError("evidence bundle root must be a JSON object")
    entity_count = sum(
        len(value.get(key, []))
        for key in ALL_COLLECTION_KEYS
        if isinstance(value.get(key, []), list)
    )
    if entity_count > MAX_NORMALIZED_ENTITIES:
        raise BundleLoadError(
            f"evidence bundle exceeds {MAX_NORMALIZED_ENTITIES} normalized entities"
        )
    return value


def collection(bundle: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return a collection while leaving shape errors to the validator."""
    value = bundle.get(key, [])
    return value if isinstance(value, list) else []
