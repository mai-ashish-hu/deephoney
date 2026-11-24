"""Unit tests for bounded, metadata-only PCAP import."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephoney.pcap.importer import (
    PcapImportError,
    import_pcap_file,
    parse_capture,
    validate_capture,
)


def test_validate_capture_accepts_sample(sample_paths: dict[str, Path], settings) -> None:
    path, fmt = validate_capture(sample_paths["pcap"], max_file_bytes=settings.pcap.max_file_bytes)
    assert path.is_file()
    assert fmt in {"pcap-little", "pcap-big", "pcap-ns-little", "pcap-ns-big", "pcapng"}


def test_validate_capture_rejects_bad_inputs(tmp_path: Path, settings) -> None:
    with pytest.raises(PcapImportError, match="not found"):
        validate_capture(tmp_path / "missing.pcap", max_file_bytes=1000)
    wrong_suffix = tmp_path / "capture.txt"
    wrong_suffix.write_bytes(b"\xd4\xc3\xb2\xa1")
    with pytest.raises(PcapImportError, match="Only"):
        validate_capture(wrong_suffix, max_file_bytes=1000)
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(PcapImportError, match="empty"):
        validate_capture(empty, max_file_bytes=1000)
    malformed = tmp_path / "bad.pcap"
    malformed.write_bytes(b"nope")
    with pytest.raises(PcapImportError, match="header"):
        validate_capture(malformed, max_file_bytes=1000)


def test_size_limit_is_enforced(sample_paths: dict[str, Path], settings) -> None:
    with pytest.raises(PcapImportError, match="exceeding"):
        validate_capture(sample_paths["pcap"], max_file_bytes=10)


def test_sample_capture_parses_to_metadata_flows(sample_paths: dict[str, Path], settings) -> None:
    parsed = parse_capture(sample_paths["pcap"], settings)
    assert parsed.packet_count == 14
    assert len(parsed.flows) >= 1
    assert parsed.metadata["payload_retained"] is False
    assert parsed.metadata["flow_count"] == len(parsed.flows)
    for flow in parsed.flows:
        assert flow["src_ip"].startswith(("203.0.113.", "192.0.2.", "198.51.100."))
        assert flow["packet_count"] >= 0
        assert flow["metadata"]["payload_retained"] is False
        assert "payload" not in flow


def test_packet_limit_marks_capture_truncated(sample_paths: dict[str, Path], settings) -> None:
    settings.pcap.max_packets = 2
    parsed = parse_capture(sample_paths["pcap"], settings)
    assert parsed.packet_count == 2
    assert parsed.truncated is True


def test_import_is_idempotent_by_sha256(repository, sample_paths, settings) -> None:
    first = import_pcap_file(repository, sample_paths["pcap"], settings)
    second = import_pcap_file(repository, sample_paths["pcap"], settings)
    assert first["imported"] is True
    assert second["imported"] is False
    assert first["capture_id"] == second["capture_id"]
    captures = repository.get_pcap_captures()
    assert len(captures) == 1
    flows, total = repository.get_pcap_flows(first["capture_id"])
    assert total == first["flow_count"]
    assert all(flow["metadata"]["payload_retained"] is False for flow in flows)
