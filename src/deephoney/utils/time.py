"""UTC-first timestamp helpers.

All internal timestamps are timezone-aware UTC values.  Source logs are
documented to use UTC; if a source emits a naive timestamp we attach UTC
rather than pretending the value came from an unknown local timezone.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)


def utcnow() -> datetime:
    """Return the current timezone-aware UTC time."""

    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as timezone-aware UTC.

    A naive datetime is interpreted as UTC because both supported honeypot
    sources are configured to log in UTC.  No other timezone is guessed.
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_timestamp(value: Any) -> datetime | None:
    """Parse the timestamp formats commonly emitted by Cowrie and Dionaea.

    The function never raises.  Unparseable input returns ``None`` so the
    caller can preserve an event without inventing a timestamp.
    """

    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        return ensure_utc(value)

    if isinstance(value, int | float):
        try:
            number = float(value)
            if abs(number) > 1_000_000_000_000:
                number /= 1000.0
            return datetime.fromtimestamp(number, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    try:
        if text.lstrip("-").replace(".", "", 1).isdigit():
            number = float(text)
            if abs(number) >= 1_000_000_000:
                return parse_timestamp(number)
    except ValueError:
        pass

    try:
        return ensure_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        pass

    for fmt in _ISO_FORMATS:
        try:
            return ensure_utc(datetime.strptime(text, fmt))
        except ValueError:
            continue
    return None


def format_utc(value: datetime | None) -> str | None:
    """Format a timestamp as a stable UTC string for JSON exports."""

    if value is None:
        return None
    return ensure_utc(value).isoformat().replace("+00:00", "Z")


def get_timezone(name: str) -> ZoneInfo:
    """Resolve a display timezone, falling back to UTC when invalid."""

    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def to_display_timezone(value: datetime | None, timezone_name: str = "UTC") -> datetime | None:
    """Convert a UTC timestamp to the configured display timezone."""

    if value is None:
        return None
    return ensure_utc(value).astimezone(get_timezone(timezone_name))


def format_display(
    value: datetime | None,
    timezone_name: str = "UTC",
    *,
    pattern: str = "%Y-%m-%d %H:%M:%S",
) -> str:
    """Return a human-readable timestamp, with an explicit empty fallback."""

    if value is None:
        return "unknown"
    return to_display_timezone(value, timezone_name).strftime(pattern)


def duration_seconds(first: datetime | None, last: datetime | None) -> float:
    """Return a non-negative duration in seconds, or 0 when unavailable."""

    if first is None or last is None:
        return 0.0
    return max(0.0, (ensure_utc(last) - ensure_utc(first)).total_seconds())


def seconds_ago(seconds: int) -> datetime:
    """Return a UTC datetime ``seconds`` in the past."""

    return utcnow() - timedelta(seconds=seconds)


def parse_range(
    start: str | None,
    end: str | None,
) -> tuple[datetime | None, datetime | None]:
    """Parse optional CLI date strings as UTC datetimes.

    Accepted values are ISO dates/datetimes and the special token ``now``.
    """

    def _one(raw: str | None) -> datetime | None:
        if raw is None or raw == "":
            return None
        if raw.lower() == "now":
            return utcnow()
        parsed = parse_timestamp(raw)
        if parsed is None:
            raise ValueError(f"Invalid timestamp: {raw!r}")
        return parsed

    return _one(start), _one(end)


def timezone_label(name: str) -> str:
    """Return a short, display-safe timezone label."""

    return name if name else "UTC"


__all__ = [
    "UTC",
    "duration_seconds",
    "ensure_utc",
    "format_display",
    "format_utc",
    "get_timezone",
    "parse_range",
    "parse_timestamp",
    "seconds_ago",
    "timezone_label",
    "to_display_timezone",
    "utcnow",
]
