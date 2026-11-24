"""Unit tests for session reconstruction rules."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from tests.helpers import make_event

from deephoney.schemas.events import EventType, SourceEngine
from deephoney.sessions.reconstruction import (
    reconstruct_session,
    reconstruct_sessions,
    session_sort_key,
)
from deephoney.utils.hashing import session_uuid

BASE = datetime(2024, 8, 15, 10, 0, tzinfo=UTC)


def test_groups_by_engine_and_session_id() -> None:
    events = [
        make_event(index=1, session_id="s1", engine="cowrie"),
        make_event(index=2, session_id="s1", engine="cowrie"),
        make_event(index=3, session_id="s1", engine="dionaea"),
        make_event(index=4, session_id="s2", engine="cowrie"),
        make_event(index=5, session_id=None),
    ]
    records = reconstruct_sessions(events)
    assert len(records) == 3
    assert {(r.source_engine, r.source_session_id) for r in records} == {
        ("cowrie", "s1"),
        ("cowrie", "s2"),
        ("dionaea", "s1"),
    }
    for record in records:
        assert record.id == str(session_uuid(record.source_engine, record.source_session_id))


def test_engine_filter_and_session_filter() -> None:
    events = [
        make_event(index=1, session_id="s1", engine="cowrie"),
        make_event(index=2, session_id="s2", engine="cowrie"),
        make_event(index=3, session_id="d1", engine="dionaea"),
    ]
    assert len(reconstruct_sessions(events, engine=SourceEngine.COWRIE)) == 2
    filtered = reconstruct_sessions(events, session_ids={"s2", "d1"})
    assert {(r.source_engine, r.source_session_id) for r in filtered} == {
        ("cowrie", "s2"),
        ("dionaea", "d1"),
    }


def test_events_without_timestamps_sort_last_but_are_retained() -> None:
    events = [
        make_event(index=1, timestamp=BASE + timedelta(seconds=5)),
        make_event(index=2, timestamp=None),
        make_event(index=3, timestamp=BASE),
    ]
    record = reconstruct_session(source_engine="cowrie", source_session_id="s1", events=events)
    assert record.events[0].event_id == events[2].event_id
    assert record.events[1].event_id == events[0].event_id
    assert record.events[2].event_id == events[1].event_id
    assert record.metadata["events_without_timestamp"] == 1
    assert record.first_seen_at == BASE
    assert record.last_seen_at == BASE + timedelta(seconds=5)


def test_session_with_only_missing_timestamps_uses_ingestion_time() -> None:
    event = make_event(index=1, timestamp=None, ingested_at=BASE)
    record = reconstruct_session(source_engine="cowrie", source_session_id="s1", events=[event])
    assert record.first_seen_at == BASE
    assert record.last_seen_at == BASE
    assert record.duration_seconds == 0.0


def test_session_metadata_counts_and_artifacts() -> None:
    digest = "c" * 64
    events = [
        make_event(
            index=0, event_type=EventType.AUTH_FAILURE, username="a", raw_event={"password": "x"}
        ),
        make_event(
            index=1, event_type=EventType.AUTH_FAILURE, username="b", raw_event={"password": "y"}
        ),
        make_event(index=2, event_type=EventType.AUTH_SUCCESS, username="a"),
        make_event(index=3, event_type=EventType.COMMAND, command="uname -a"),
        make_event(
            index=4,
            event_type=EventType.FILE_DOWNLOAD,
            artifact_sha256=digest,
            details={"download": {"size": 100, "filename": "x.bin"}},
        ),
        make_event(index=5, event_type=EventType.CONNECTION, dst_port=22),
        make_event(index=6, event_type=EventType.CONNECTION, dst_port=80),
    ]
    record = reconstruct_session(source_engine="cowrie", source_session_id="s1", events=events)
    meta = record.metadata
    assert record.event_count == 7
    assert meta["auth_failures"] == 2
    assert meta["auth_successes"] == 1
    assert meta["auth_attempts"] == 3
    assert meta["command_count"] == 1
    assert meta["command_sequence"] == ["uname -a"]
    assert meta["download_count"] == 1
    assert meta["distinct_usernames"] == 2
    assert meta["distinct_password_hashes"] == 2
    assert meta["artifact_hashes"] == [digest]
    assert meta["artifact_sizes"] == {digest: 100}
    assert meta["dst_ports"] == [22, 80, 2222]
    assert set(meta["protocols"]) == {"ssh"}


def test_sort_key_places_missing_timestamps_last() -> None:
    timed = make_event(index=1, timestamp=BASE)
    missing = make_event(index=2, timestamp=None)
    assert sorted([missing, timed], key=session_sort_key)[0] is timed


def test_reconstruct_session_requires_events() -> None:
    with pytest.raises(ValueError):
        reconstruct_session(source_engine="cowrie", source_session_id="s1", events=[])
