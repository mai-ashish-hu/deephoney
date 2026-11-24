"""Unit tests for the Cowrie JSON parser."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from deephoney.parsers.base import ParseFailure, ParseSuccess
from deephoney.parsers.cowrie.parser import CowrieParser
from deephoney.schemas.events import EventType


@pytest.fixture
def parser() -> CowrieParser:
    return CowrieParser()


def _parse(parser: CowrieParser, record: dict) -> ParseSuccess:
    outcome = parser.parse_record(record, source_file="cowrie.json", line_number=1)
    assert isinstance(outcome, ParseSuccess)
    return outcome


def test_session_connect_is_normalized(parser: CowrieParser) -> None:
    event = _parse(
        parser,
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2024-08-15T10:00:00.000000Z",
            "src_ip": "203.0.113.44",
            "src_port": 51514,
            "dst_ip": "192.0.2.10",
            "dst_port": 2222,
            "session": "demo-1",
            "protocol": "ssh",
            "message": "New connection",
        },
    ).event
    assert event.source_engine.value == "cowrie"
    assert event.event_type is EventType.CONNECTION
    assert event.timestamp == datetime(2024, 8, 15, 10, 0, tzinfo=UTC)
    assert event.src_ip == "203.0.113.44"
    assert event.dst_port == 2222
    assert event.session_id == "demo-1"
    assert event.details["cowrie_eventid"] == "cowrie.session.connect"
    assert event.details["message"] == "New connection"


def test_login_failure_never_copies_password_into_details(parser: CowrieParser) -> None:
    event = _parse(
        parser,
        {
            "eventid": "cowrie.login.failed",
            "timestamp": "2024-08-15T10:00:05Z",
            "src_ip": "203.0.113.44",
            "session": "demo-1",
            "username": "root",
            "password": "DEMO_PASSWORD_NOT_REAL_01",
        },
    ).event
    assert event.event_type is EventType.AUTH_FAILURE
    assert event.username == "root"
    assert event.details["password_present"] is True
    assert "password" not in event.details
    assert event.raw_event["password"] == "DEMO_PASSWORD_NOT_REAL_01"


def test_command_input_maps_to_command(parser: CowrieParser) -> None:
    event = _parse(
        parser,
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2024-08-15T10:00:10Z",
            "session": "demo-1",
            "input": "uname -a",
        },
    ).event
    assert event.event_type is EventType.COMMAND
    assert event.command == "uname -a"


def test_command_success_falls_back_to_command_field(parser: CowrieParser) -> None:
    event = _parse(
        parser,
        {
            "eventid": "cowrie.command.success",
            "command": "whoami",
        },
    ).event
    assert event.command == "whoami"


def test_unknown_event_id_is_retained_as_unknown(parser: CowrieParser) -> None:
    event = _parse(parser, {"eventid": "cowrie.future.event"}).event
    assert event.event_type is EventType.UNKNOWN
    assert event.details["cowrie_eventid"] == "cowrie.future.event"


def test_file_download_sha256_is_validated(parser: CowrieParser) -> None:
    good = "a" * 64
    event = _parse(
        parser,
        {
            "eventid": "cowrie.session.file_download",
            "shasum": good.upper(),
            "outfile": "payload.bin",
            "url": "http://example.invalid/payload.bin",
            "size": 1234,
        },
    ).event
    assert event.artifact_sha256 == good
    assert event.details["outfile"] == "payload.bin"
    assert event.details["size"] == 1234

    invalid = _parse(
        parser,
        {"eventid": "cowrie.session.file_download", "shasum": "not-a-sha256"},
    ).event
    assert invalid.artifact_sha256 is None


def test_missing_fields_are_not_invented(parser: CowrieParser) -> None:
    event = _parse(parser, {"eventid": "cowrie.login.failed"}).event
    assert event.timestamp is None
    assert event.src_ip is None
    assert event.src_port is None
    assert event.dst_ip is None
    assert event.dst_port is None
    assert event.session_id is None


def test_parse_line_returns_failure_for_malformed_json(parser: CowrieParser) -> None:
    outcome = parser.parse_line('{"eventid": ', source_file="cowrie.json", line_number=3)
    assert isinstance(outcome, ParseFailure)
    assert outcome.line_number == 3
    assert "invalid JSON" in outcome.error


def test_parse_line_returns_failure_for_blank_and_array(parser: CowrieParser) -> None:
    blank = parser.parse_line("   ", source_file="x")
    assert isinstance(blank, ParseFailure)
    array = parser.parse_line('[{"a": 1}]', source_file="x")
    assert isinstance(array, ParseFailure)
    assert "array" in array.error.lower()


def test_build_event_sanitizes_and_bounds_fields(parser: CowrieParser) -> None:
    event = _parse(
        parser,
        {
            "eventid": "cowrie.command.input",
            "input": "echo\x00 hi",
            "src_ip": "not-an-ip",
            "src_port": 99999,
            "session": "s1\x01",
        },
    ).event
    assert event.command == "echo hi"
    assert event.src_ip is None
    assert event.src_port is None
    assert event.session_id == "s1"
