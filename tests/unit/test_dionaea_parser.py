"""Unit tests for the Dionaea JSON and plaintext parser paths."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from deephoney.parsers.base import ParseSuccess
from deephoney.parsers.dionaea.parser import DionaeaParser
from deephoney.schemas.events import EventType


@pytest.fixture
def parser() -> DionaeaParser:
    return DionaeaParser()


def _parse(parser: DionaeaParser, record: object) -> ParseSuccess:
    outcome = parser.parse_record(record, source_file="dionaea.json", line_number=1)
    assert isinstance(outcome, ParseSuccess)
    return outcome


def test_real_log_json_shape_is_supported(parser: DionaeaParser) -> None:
    record = {
        "connection": {
            "protocol": "ftpctrl",
            "transport": "tcp",
            "type": "accept",
        },
        "dst_ip": "192.0.2.10",
        "dst_port": 21,
        "src_hostname": None,
        "src_ip": "203.0.113.88",
        "src_port": 50222,
        "timestamp": "2024-08-15T11:20:00.000000",
        "credentials": [
            {"username": "anonymous", "password": "DEMO_PASSWORD_NOT_REAL_20"},
        ],
        "ftp": {
            "commands": [
                {"command": "USER", "arguments": "anonymous"},
                {"command": "PASS", "arguments": "DEMO_PASSWORD_NOT_REAL_20"},
            ]
        },
    }
    event = _parse(parser, record).event
    assert event.event_type is EventType.CONNECTION
    assert event.src_ip == "203.0.113.88"
    assert event.src_port == 50222
    assert event.dst_ip == "192.0.2.10"
    assert event.dst_port == 21
    assert event.protocol == "ftp"
    assert event.username == "anonymous"
    assert event.command == "USER"
    assert event.timestamp == datetime(2024, 8, 15, 11, 20, tzinfo=UTC)
    assert event.details["session_id_provenance"] == (
        "derived_from_single_dionaea_log_json_connection_record"
    )
    assert event.details["credential_count"] == 1
    assert event.details["ftp_command_count"] == 2
    assert event.session_id is not None and event.session_id.startswith("dionaea-log-")
    assert "DEMO_PASSWORD_NOT_REAL_20" not in str(event.details)


def test_messages_are_redacted_in_both_parser_paths(parser: DionaeaParser) -> None:
    json_event = _parse(
        parser,
        {
            "message": "login attempt [root/hunter2] failed password=secret123",
            "connection": {"type": "accept"},
            "src_ip": "203.0.113.5",
            "dst_ip": "192.0.2.10",
        },
    ).event
    assert json_event.details["message"] == (
        "login attempt [root/[REDACTED]] failed password=[REDACTED]"
    )

    plain_event = _parse(
        parser,
        "2024-08-15 11:30:00 [dionaea.connection.accept] password=secret123",
    ).event
    assert (
        plain_event.details["message"]
        == "2024-08-15 11:30:00 [dionaea.connection.accept] password=[REDACTED]"
    )


def test_derived_session_id_is_deterministic(parser: DionaeaParser) -> None:
    record = {
        "connection": {"protocol": "httpd", "transport": "tcp", "type": "accept"},
        "dst_ip": "192.0.2.10",
        "dst_port": 80,
        "src_ip": "198.51.100.61",
        "src_port": 51110,
        "timestamp": "2024-08-15T11:22:00.000000",
    }
    first = _parse(parser, record).event
    second = _parse(parser, record).event
    assert first.session_id == second.session_id
    changed = _parse(parser, {**record, "src_port": 51111}).event
    assert changed.session_id != first.session_id


def test_source_connection_id_is_preserved_as_provenance(parser: DionaeaParser) -> None:
    record = {
        "type": "dionaea.connection.accepted",
        "connection": {
            "connection_unique_id": "demo-dionaea-0001",
            "protocol": "tcp",
            "remote": {"host": "203.0.113.77", "port": 49152},
            "local": {"host": "192.0.2.10", "port": 2121},
        },
    }
    event = _parse(parser, record).event
    assert event.session_id == "demo-dionaea-0001"
    assert event.details["session_id_provenance"] == "source"
    assert event.details["connection_unique_id"] == "demo-dionaea-0001"


def test_binary_payloads_are_removed_from_details(parser: DionaeaParser) -> None:
    record = {
        "type": "dionaea.modules.python.httpd.capture",
        "connection": {"type": "accept", "protocol": "httpd"},
        "src_ip": "203.0.113.5",
        "dst_ip": "192.0.2.10",
        "capture": {
            "filename": "sample.bin",
            "size": 10,
            "data": "obviously-not-real-binary",
        },
        "payload": "DEADBEEF",
    }
    event = _parse(parser, record).event
    assert event.event_type is EventType.CAPTURE
    assert "obviously-not-real-binary" not in str(event.details)
    assert "DEADBEEF" not in str(event.details)
    assert event.details["capture"]["filename"] == "sample.bin"


def test_download_sha256_is_extracted(parser: DionaeaParser) -> None:
    digest = "b" * 64
    event = _parse(
        parser,
        {
            "type": "dionaea.modules.python.ftp.download",
            "connection": {"type": "accept", "protocol": "tcp"},
            "src_ip": "203.0.113.7",
            "dst_ip": "192.0.2.10",
            "download": {"filename": "x.bin", "size": 2, "sha256": digest},
        },
    ).event
    assert event.artifact_sha256 == digest
    assert event.details["filename"] == "x.bin"
    assert event.details["size"] == 2


def test_plaintext_fallback_uses_only_labelled_remote_address(parser: DionaeaParser) -> None:
    line = (
        "2024-08-15 11:30:00,123 [dionaea.connection.accept] "
        "remote 203.0.113.90:50000 connected to 192.0.2.10:21"
    )
    event = _parse(parser, line).event
    assert event.timestamp == datetime(2024, 8, 15, 11, 30, 0, 123000, tzinfo=UTC)
    assert event.src_ip == "203.0.113.90"
    assert event.details["raw_format"] == "plaintext"
    assert "labelled remote" in event.details["address_inference"]


def test_plaintext_without_label_does_not_invent_address(parser: DionaeaParser) -> None:
    event = _parse(
        parser,
        "2024-08-15 11:30:00 [dionaea.connection.accept] connection from somewhere",
    ).event
    assert event.src_ip is None
    assert "no labelled remote" in event.details["address_inference"]


def test_unknown_json_without_connection_fields_fabricates_nothing(parser: DionaeaParser) -> None:
    event = _parse(parser, {"event": "dionaea.future.event"}).event
    assert event.event_type is EventType.UNKNOWN
    assert event.src_ip is None
    assert event.dst_ip is None
    assert event.session_id is None


def test_parse_string_record_returns_plaintext_failure_for_empty(parser: DionaeaParser) -> None:
    outcome = parser.parse_record("   ", source_file="dionaea.log", line_number=4)
    from deephoney.parsers.base import ParseFailure

    assert isinstance(outcome, ParseFailure)
    assert outcome.line_number == 4
