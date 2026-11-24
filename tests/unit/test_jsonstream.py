"""Unit tests for tolerant JSON/JSONL streaming."""

from __future__ import annotations

from pathlib import Path

from deephoney.utils.jsonstream import iter_json_records, iter_record_candidates


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_json_lines_with_one_malformed_record(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mixed.json",
        '{"a": 1}\n' '{"broken": \n' '{"a": 2}\n',
    )
    candidates = list(iter_record_candidates(path))
    assert [c.ok for c in candidates] == [True, False, True]
    assert candidates[0].line_number == 1
    assert candidates[2].line_number == 3
    assert list(iter_json_records(path)) == [{"a": 1}, {"a": 2}]


def test_pretty_printed_object_is_assembled(tmp_path: Path) -> None:
    path = _write(tmp_path / "pretty.json", '{\n  "a": 1,\n  "b": {"c": 2}\n}\n')
    candidates = list(iter_record_candidates(path))
    assert len(candidates) == 1
    assert candidates[0].ok
    assert candidates[0].record == {"a": 1, "b": {"c": 2}}


def test_json_array_is_flattened(tmp_path: Path) -> None:
    path = _write(tmp_path / "array.json", '[{"a": 1}, 5, {"a": 2}]')
    candidates = list(iter_record_candidates(path))
    assert [c.ok for c in candidates] == [True, False, True]
    assert candidates[1].error == "JSON array item is not an object"


def test_plaintext_lines_are_passed_through(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "plain.log", "2024-08-15 [dionaea.connection.accept] remote 203.0.113.5\n"
    )
    candidates = list(iter_record_candidates(path))
    assert len(candidates) == 1
    assert candidates[0].ok
    assert isinstance(candidates[0].record, str)


def test_incomplete_trailing_record_is_reported(tmp_path: Path) -> None:
    path = _write(tmp_path / "partial.json", '{"a": 1}\n{"b": 2')
    candidates = list(iter_record_candidates(path))
    assert candidates[0].ok
    assert not candidates[1].ok
    assert "JSON" in (candidates[1].error or "")


def test_oversized_record_is_rejected_without_stopping(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "large.json",
        '{"payload": "' + "x" * 100 + '"}\n{"ok": 1}\n',
    )
    candidates = list(iter_record_candidates(path, max_record_bytes=50))
    errors = [c.error for c in candidates if c.error]
    assert any("exceeds" in error for error in errors)
    assert any(c.ok for c in candidates)


def test_oversized_line_is_reported_once(tmp_path: Path) -> None:
    path = _write(tmp_path / "large-once.json", '{"payload": "' + "x" * 100 + '"}\n')
    candidates = list(iter_record_candidates(path, max_record_bytes=50))
    assert len(candidates) == 1
    assert candidates[0].error and "exceeds" in candidates[0].error


def test_blank_lines_are_skipped(tmp_path: Path) -> None:
    path = _write(tmp_path / "blanks.json", '\n\n{"a": 1}\n\n')
    candidates = list(iter_record_candidates(path))
    assert len(candidates) == 1
    assert candidates[0].record == {"a": 1}
