"""Unit tests for redaction at the ORM serialization boundary."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from deephoney.storage.models import Detection, Event, HoneypotSession, ParserFailure
from deephoney.storage.serializers import (
    detection_to_dict,
    event_to_dict,
    parser_failure_to_dict,
    session_to_dict,
)
from deephoney.utils.redaction import REDACTED

_NOW = datetime.now(UTC)


def _event() -> Event:
    return Event(
        id=uuid.uuid4(),
        event_hash="hash",
        source_engine="cowrie",
        event_type="command",
        command="echo password=hunter2",
        raw_payload={"password": "hunter2"},
        details={
            "message": "login attempt [root/hunter2] failed",
            "nested": {"token": "abc"},
        },
        source_file="sample.log",
        parser_version="v1",
        ingested_at=_NOW,
    )


def test_event_serialization_redacts_command_details_and_raw_payload() -> None:
    row = event_to_dict(_event())
    assert row["command"] == "echo password=[REDACTED]"
    assert row["details"]["message"] == "login attempt [root/[REDACTED]] failed"
    assert row["details"]["nested"]["token"] == REDACTED
    assert row["raw_payload"]["password"] == REDACTED


def test_session_serialization_redacts_command_sequence_and_metadata() -> None:
    session = HoneypotSession(
        id=uuid.uuid4(),
        source_engine="cowrie",
        source_session_id="session-1",
        first_seen_at=_NOW,
        last_seen_at=_NOW,
        session_metadata={
            "command_sequence": ["echo password=hunter2"],
            "api_key": "secret",
        },
    )
    row = session_to_dict(session)
    assert row["commands"] == ["echo password=[REDACTED]"]
    assert row["metadata"]["api_key"] == REDACTED


def test_parser_failure_excerpt_redacts_json_credentials() -> None:
    failure = ParserFailure(
        id=uuid.uuid4(),
        source_engine="cowrie",
        source_file="sample.log",
        line_number=1,
        error="invalid JSON",
        raw_excerpt='{"password": "hunter2", "username": "root"}',
        created_at=_NOW,
    )
    row = parser_failure_to_dict(failure)
    assert row["raw_excerpt"] == '{"password": "[REDACTED]", "username": "root"}'


def test_detection_serialization_redacts_evidence_and_explanation() -> None:
    detection = Detection(
        id=uuid.uuid4(),
        detection_method="rule",
        risk_score=80,
        risk_level="high",
        model_version="v1",
        evidence={"rules": [{"observed": {"password": "hunter2"}}]},
        explanation={"text": "password=hunter2"},
        created_at=_NOW,
    )
    row = detection_to_dict(detection)
    assert row["evidence"]["rules"][0]["observed"]["password"] == REDACTED
    assert row["explanation"]["text"] == "password=[REDACTED]"
