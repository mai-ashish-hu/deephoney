"""Unit tests for UTC timestamp handling."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from deephoney.utils.time import (
    duration_seconds,
    ensure_utc,
    format_display,
    format_utc,
    get_timezone,
    parse_range,
    parse_timestamp,
    timezone_label,
    to_display_timezone,
    utcnow,
)


def test_parse_timestamp_accepts_iso_variants() -> None:
    expected = datetime(2024, 8, 15, 10, 30, tzinfo=UTC)
    assert parse_timestamp("2024-08-15T10:30:00Z") == expected
    assert parse_timestamp("2024-08-15T10:30:00+00:00") == expected
    assert parse_timestamp("2024-08-15 10:30:00") == expected
    assert parse_timestamp(datetime(2024, 8, 15, 10, 30)) == expected


def test_parse_timestamp_accepts_epoch_seconds_and_milliseconds() -> None:
    expected = datetime(2024, 8, 15, 10, 30, tzinfo=UTC)
    seconds = expected.timestamp()
    assert parse_timestamp(seconds) == expected
    assert parse_timestamp(int(seconds)) == expected
    assert parse_timestamp(str(seconds)) == expected
    assert parse_timestamp(int(seconds * 1000)) == expected


def test_numeric_strings_are_not_mistaken_for_small_epochs() -> None:
    assert parse_timestamp("2024.08") is None
    assert parse_timestamp("20240815") == datetime(2024, 8, 15, tzinfo=UTC)


@pytest.mark.parametrize("value", [None, "", "not-a-date", [], {}, True])
def test_parse_timestamp_never_raises(value: object) -> None:
    if isinstance(value, bool):
        assert parse_timestamp(value) is not None
    else:
        assert parse_timestamp(value) is None


def test_ensure_utc_treats_naive_as_utc_and_converts_offsets() -> None:
    assert ensure_utc(datetime(2024, 1, 1, 12)) == datetime(2024, 1, 1, 12, tzinfo=UTC)
    offset = timezone(timedelta(hours=2))
    assert ensure_utc(datetime(2024, 1, 1, 12, tzinfo=offset)) == datetime(
        2024, 1, 1, 10, tzinfo=UTC
    )


def test_duration_seconds_is_non_negative_and_missing_safe() -> None:
    first = datetime(2024, 1, 1, tzinfo=UTC)
    assert duration_seconds(first, first + timedelta(seconds=12)) == 12.0
    assert duration_seconds(first + timedelta(seconds=12), first) == 0.0
    assert duration_seconds(None, first) == 0.0


def test_format_utc_uses_z_suffix() -> None:
    assert format_utc(datetime(2024, 1, 1, 12, 0, tzinfo=UTC)) == "2024-01-01T12:00:00Z"
    assert format_utc(None) is None


def test_display_timezone_helpers() -> None:
    moment = datetime(2024, 8, 15, 10, 0, tzinfo=UTC)
    assert to_display_timezone(moment, "UTC") == moment
    assert get_timezone("not/a-zone").key == "UTC"
    assert format_display(None) == "unknown"
    assert format_display(moment, "UTC") == "2024-08-15 10:00:00"
    assert timezone_label("") == "UTC"


def test_parse_range_supports_now_and_rejects_garbage() -> None:
    before = utcnow()
    start, end = parse_range("2024-08-01", None)
    assert start == datetime(2024, 8, 1, tzinfo=UTC)
    assert end is None
    now_start, _ = parse_range("now", None)
    assert now_start is not None and now_start >= before
    with pytest.raises(ValueError):
        parse_range("yesterday-ish", None)
