from __future__ import annotations

from datetime import UTC, date, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class TimeValueError(ValueError):
    """A timestamp or timezone cannot be interpreted canonically."""


def parse_instant(value: str) -> datetime:
    """Parse one offset-aware ISO/RFC3339 instant."""
    if not isinstance(value, str) or not value:
        raise TimeValueError("timestamp must be a non-empty string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TimeValueError("timestamp must be valid ISO/RFC3339") from exc
    if parsed.tzinfo is None:
        raise TimeValueError("timestamp must include a timezone offset")
    return parsed


def normalize_utc(value: str | datetime) -> str:
    """Return the canonical microsecond UTC representation of an instant."""
    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is None:
            raise TimeValueError("timestamp must include a timezone offset")
    else:
        parsed = parse_instant(value)
    return (
        parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def local_date(value: str, timezone: str) -> date:
    """Project an instant onto the declared IANA timezone's calendar date."""
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise TimeValueError(f"unknown IANA timezone: {timezone}") from exc
    return parse_instant(value).astimezone(zone).date()
