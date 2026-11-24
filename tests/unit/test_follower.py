"""Unit tests for partial-line-safe log tailing."""

from __future__ import annotations

from pathlib import Path

from deephoney.collectors.follower import FileTailer


def test_tailer_returns_only_complete_lines(tmp_path: Path) -> None:
    path = tmp_path / "cowrie.json"
    path.write_text('{"a": 1}\n{"b": 2}\n{"partial":', encoding="utf-8")
    tailer = FileTailer(path)
    assert tailer.read_complete_lines() == ['{"a": 1}', '{"b": 2}']
    assert tailer.buffer == b'{"partial":'
    assert tailer.committed_offset == len(b'{"a": 1}\n{"b": 2}\n')


def test_tailer_resumes_after_partial_line_is_completed(tmp_path: Path) -> None:
    path = tmp_path / "cowrie.json"
    path.write_text('{"a": 1}\n{"part', encoding="utf-8")
    tailer = FileTailer(path)
    assert tailer.read_complete_lines() == ['{"a": 1}']
    with path.open("a", encoding="utf-8") as handle:
        handle.write('ial": 2}\n')
    assert tailer.read_complete_lines() == ['{"partial": 2}']


def test_tailer_resets_after_truncation(tmp_path: Path) -> None:
    path = tmp_path / "cowrie.json"
    path.write_text("one\ntwo\n", encoding="utf-8")
    tailer = FileTailer(path)
    assert tailer.read_complete_lines() == ["one", "two"]
    path.write_text("new\n", encoding="utf-8")
    assert tailer.read_complete_lines() == ["new"]
    assert tailer.reset_count == 1


def test_tailer_drain_and_missing_file(tmp_path: Path) -> None:
    missing = FileTailer(tmp_path / "missing.log")
    assert missing.read_complete_lines() == []
    path = tmp_path / "partial.log"
    path.write_text("unterminated", encoding="utf-8")
    tailer = FileTailer(path)
    assert tailer.read_complete_lines() == []
    assert tailer.drain() == ["unterminated"]
    assert tailer.drain() == []


def test_tailer_preserves_invalid_and_multibyte_bytes(tmp_path: Path) -> None:
    path = tmp_path / "mixed.log"
    path.write_bytes(b'{"a": 1}\n\xff\xfe\n{"b": 2}\n')
    tailer = FileTailer(path)
    assert tailer.read_complete_lines() == ['{"a": 1}', "\ufffd\ufffd", '{"b": 2}']
    assert tailer.committed_offset == path.stat().st_size


def test_tailer_reassembles_a_split_multibyte_character(tmp_path: Path) -> None:
    path = tmp_path / "utf8.log"
    payload = '{"msg":"café"}\n'.encode()
    cut = payload.index(b"\xc3") + 1
    path.write_bytes(payload)
    tailer = FileTailer(path)
    assert tailer.read_complete_lines(max_bytes=cut) == []
    assert tailer.committed_offset == 0
    assert tailer.read_complete_lines() == ['{"msg":"café"}']
    assert tailer.committed_offset == len(payload)
