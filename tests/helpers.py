"""Test-only builders for normalized events and sessions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from deephoney.schemas.events import EventType, NormalizedEvent, SourceEngine
from deephoney.utils.hashing import event_identity

BASE_TIME = datetime(2024, 8, 15, 10, 0, 0, tzinfo=UTC)
_UNSET = object()


def make_event(
    *,
    index: int = 0,
    engine: SourceEngine | str = SourceEngine.COWRIE,
    event_type: EventType | str = EventType.CONNECTION,
    session_id: str | None = "test-session-1",
    timestamp: datetime | None | object = _UNSET,
    ingested_at: datetime | None | object = _UNSET,
    **overrides: Any,
) -> NormalizedEvent:
    """Build a deterministic event for unit tests.

    The raw payload contains the index so event hashes stay unique unless a
    test deliberately reuses the same raw payload.
    """

    engine_value = engine.value if isinstance(engine, SourceEngine) else engine
    event_type_value = event_type.value if isinstance(event_type, EventType) else event_type
    raw: dict[str, Any] = {
        "test_index": index,
        "session": session_id,
        "eventid": f"test.{event_type_value}",
    }
    raw.update(overrides.pop("raw_event", {}))
    source_event_id = overrides.pop("source_event_id", f"test-{index}")
    event_id, event_hash = event_identity(engine_value, raw, source_event_id=source_event_id)
    values: dict[str, Any] = {
        "event_id": event_id,
        "event_hash": event_hash,
        "source_engine": engine_value,
        "source_event_id": source_event_id,
        "event_type": event_type_value,
        "timestamp": (BASE_TIME + timedelta(seconds=index) if timestamp is _UNSET else timestamp),
        "src_ip": "203.0.113.50",
        "src_port": 50000 + index,
        "dst_ip": "192.0.2.10",
        "dst_port": 2222,
        "protocol": "ssh",
        "session_id": session_id,
        "username": None,
        "command": None,
        "artifact_sha256": None,
        "raw_event": raw,
        "source_file": "fixture.log",
        "source_line": index + 1,
        "ingested_at": (
            BASE_TIME + timedelta(seconds=index) if ingested_at is _UNSET else ingested_at
        ),
        "parser_version": "test-parser-1",
        "details": {},
    }
    values.update(overrides)
    return NormalizedEvent(**values)


def make_sequence(*event_types: EventType, **overrides: Any) -> list[NormalizedEvent]:
    return [
        make_event(index=index, event_type=event_type, **overrides)
        for index, event_type in enumerate(event_types)
    ]
