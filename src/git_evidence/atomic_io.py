from __future__ import annotations

import os
import tempfile
from pathlib import Path


class AtomicWriteError(OSError):
    """A sensitive artifact could not be durably replaced."""


def atomic_write_text(
    path: str | Path,
    text: str,
    *,
    mode: int = 0o600,
) -> None:
    """Durably replace one text artifact without exposing a partial file."""
    target = Path(path)
    temporary: Path | None = None
    file_descriptor: int | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=str(target.parent),
        )
        temporary = Path(temporary_name)
        os.fchmod(file_descriptor, mode)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="") as handle:
            file_descriptor = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = None
        os.chmod(target, mode)
        try:
            directory_descriptor = os.open(
                target.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
        except OSError:
            directory_descriptor = None
        if directory_descriptor is not None:
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except (OSError, TypeError, ValueError) as exc:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise AtomicWriteError(f"cannot atomically write {target}") from exc
