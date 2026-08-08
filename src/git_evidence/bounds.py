"""Shared guards for untrusted JSON and bounded artifact input."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO


class InputLimitError(ValueError):
    """An input crossed a deterministic memory or artifact boundary."""


def read_bounded_bytes(path: str | Path, *, max_bytes: int) -> bytes:
    with Path(path).open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise InputLimitError(f"input exceeds {max_bytes} bytes")
    return raw


def read_bounded_text(stream: TextIO, *, max_bytes: int) -> str:
    chunks: list[str] = []
    size = 0
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        if not isinstance(chunk, str):
            raise InputLimitError("text input returned a non-text chunk")
        size += len(chunk.encode("utf-8"))
        if size > max_bytes:
            raise InputLimitError(f"input exceeds {max_bytes} bytes")
        chunks.append(chunk)
    return "".join(chunks)


def json_size_with_limit(
    value: Any,
    *,
    max_bytes: int,
    ensure_ascii: bool = False,
    indent: int | None = 2,
) -> int:
    size = 0
    encoder = json.JSONEncoder(
        ensure_ascii=ensure_ascii,
        indent=indent,
        allow_nan=False,
        separators=None if indent is not None else (",", ":"),
    )
    for chunk in encoder.iterencode(value):
        size += len(chunk.encode("utf-8"))
        if size > max_bytes:
            raise InputLimitError(f"serialized JSON exceeds {max_bytes} bytes")
    return size


def indented_json_growth_upper_bound(value: Any, *, base_indent: int) -> int:
    encoded = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
    return len(encoded.encode("utf-8")) + base_indent * (encoded.count("\n") + 1) + 32


def validate_json_value_limits(
    value: Any,
    *,
    max_depth: int,
    max_string_chars: int,
) -> None:
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > max_depth:
            raise InputLimitError(f"JSON nesting exceeds {max_depth}")
        if isinstance(current, str):
            if len(current) > max_string_chars:
                raise InputLimitError(
                    f"JSON string exceeds {max_string_chars} characters"
                )
            continue
        if isinstance(current, dict):
            for key, child in current.items():
                if len(str(key)) > max_string_chars:
                    raise InputLimitError(
                        f"JSON key exceeds {max_string_chars} characters"
                    )
                pending.append((child, depth + 1))
        elif isinstance(current, (list, tuple)):
            pending.extend((child, depth + 1) for child in current)
