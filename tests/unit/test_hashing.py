"""Unit tests for deterministic hashing and event identity."""

from __future__ import annotations

from deephoney.utils.hashing import (
    canonical_json,
    event_identity,
    file_sha256,
    session_uuid,
    sha256_bytes,
    sha256_json,
    sha256_text,
)


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})
    assert canonical_json({"a": 1}) == '{"a":1}'


def test_sha_helpers() -> None:
    assert sha256_text("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert sha256_bytes(b"abc") == sha256_text("abc")
    assert sha256_json({"a": 1}) == sha256_text('{"a":1}')


def test_file_sha256(tmp_path) -> None:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"deephoney")
    assert file_sha256(path) == sha256_bytes(b"deephoney")


def test_event_identity_is_stable_and_filename_independent() -> None:
    raw = {"eventid": "cowrie.session.connect", "session": "s1"}
    first = event_identity("cowrie", raw, source_event_id="cowrie.session.connect")
    second = event_identity("cowrie", raw, source_event_id="cowrie.session.connect")
    assert first == second
    reordered = {"session": "s1", "eventid": "cowrie.session.connect"}
    assert event_identity("cowrie", reordered, source_event_id="cowrie.session.connect") == first


def test_event_identity_changes_with_engine_raw_or_source_id() -> None:
    raw = {"eventid": "x"}
    base = event_identity("cowrie", raw, source_event_id="x")
    assert event_identity("dionaea", raw, source_event_id="x") != base
    assert event_identity("cowrie", {"eventid": "y"}, source_event_id="x") != base
    assert event_identity("cowrie", raw, source_event_id="y") != base


def test_session_uuid_is_engine_scoped() -> None:
    assert session_uuid("cowrie", "abc") == session_uuid("cowrie", "abc")
    assert session_uuid("cowrie", "abc") != session_uuid("dionaea", "abc")
    assert session_uuid("cowrie", "abc") != session_uuid("cowrie", "abd")
