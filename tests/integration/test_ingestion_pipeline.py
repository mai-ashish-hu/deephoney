"""Integration tests for ingestion, deduplication, and follow mode."""

from __future__ import annotations

from pathlib import Path

from deephoney.ingestion.pipeline import IngestionPipeline
from deephoney.schemas.events import SourceEngine


def _pipeline(repository, settings) -> IngestionPipeline:
    return IngestionPipeline(repository, settings)


def test_sample_logs_ingest_and_rebuild_sessions(repository, settings, sample_paths) -> None:
    pipeline = _pipeline(repository, settings)
    cowrie = pipeline.ingest_file(sample_paths["cowrie"], SourceEngine.COWRIE.value, archive=False)
    dionaea = pipeline.ingest_file(
        sample_paths["dionaea"], SourceEngine.DIONAEA.value, archive=False
    )
    dionaea_json = pipeline.ingest_file(
        sample_paths["dionaea_json"], SourceEngine.DIONAEA.value, archive=False
    )
    assert (cowrie.records_read, cowrie.records_created, cowrie.records_failed) == (26, 26, 0)
    assert (dionaea.records_read, dionaea.records_created, dionaea.records_failed) == (7, 7, 0)
    assert (dionaea_json.records_created, dionaea_json.records_failed) == (2, 0)
    assert cowrie.status == dionaea.status == dionaea_json.status == "success"

    overview = repository.overview_stats()
    assert overview["total_events"] == 35
    assert overview["by_engine"] == {"cowrie": 26, "dionaea": 9}
    assert overview["session_count"] >= 5
    assert overview["unique_source_ips"] >= 5
    assert overview["risk_distribution"]


def test_reingestion_is_idempotent(repository, settings, sample_paths) -> None:
    pipeline = _pipeline(repository, settings)
    first = pipeline.ingest_file(sample_paths["cowrie"], "cowrie", archive=False)
    second = pipeline.ingest_file(sample_paths["cowrie"], "cowrie", archive=False)
    assert first.records_created == 26
    assert second.records_created == 0
    assert second.records_skipped == 26
    assert repository.overview_stats()["total_events"] == 26


def test_malformed_records_are_quarantined_and_ingestion_continues(
    repository, settings, tmp_path: Path
) -> None:
    log = tmp_path / "cowrie-malformed.json"
    log.write_text(
        '{"eventid": "cowrie.session.connect", "timestamp": "2024-08-15T10:00:00Z", '
        '"session": "bad-1", "src_ip": "203.0.113.30", "dst_port": 2222}\n'
        '{"eventid": "cowrie.login.failed", "session": "bad-1"\n'
        "not-json-at-all\n"
        '{"eventid": "cowrie.command.input", "timestamp": "2024-08-15T10:00:05Z", '
        '"session": "bad-1", "input": "id"}\n',
        encoding="utf-8",
    )
    result = _pipeline(repository, settings).ingest_file(log, "cowrie", archive=False)
    assert result.status == "partial"
    assert result.records_read == 3
    assert result.records_created == 2
    assert result.records_failed == 1
    assert len(repository.get_parser_failures()) == 1
    stored = repository.export_events()
    assert {row["source_event_id"] for row in stored} == {
        "cowrie.session.connect",
        "cowrie.command.input",
    }
    sessions = repository.overview_stats()["session_count"]
    assert sessions == 1


def test_archive_path_is_not_reported_as_an_error(repository, settings, sample_paths) -> None:
    result = _pipeline(repository, settings).ingest_file(
        sample_paths["cowrie"], "cowrie", archive=True, run_detection=False
    )
    assert result.archive_path
    assert all("archived" not in error for error in result.errors)
    assert result.as_dict()["archive_path"] == result.archive_path


def test_result_errors_are_bounded(repository, settings, tmp_path: Path, monkeypatch) -> None:
    import deephoney.ingestion.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "MAX_RESULT_ERRORS", 2)
    log = tmp_path / "cowrie-errors.json"
    log.write_text("bad\nbad\nbad\n", encoding="utf-8")
    result = _pipeline(repository, settings).ingest_file(log, "cowrie", archive=False)
    assert len(result.errors) == 2
    assert result.errors_omitted == 1
    summary = repository.get_ingestion_runs(limit=1)[0]["error_summary"]
    assert "1 additional error(s) omitted" in summary


def test_follow_mode_uses_persisted_offsets(repository, settings, tmp_path: Path) -> None:
    log = tmp_path / "cowrie-follow.json"
    log.write_text(
        '{"eventid": "cowrie.session.connect", "session": "follow-1", "src_ip": "203.0.113.20"}\n'
        '{"eventid": "cowrie.command.input", "session": "follow-1", "input": "id"}\n',
        encoding="utf-8",
    )
    pipeline = _pipeline(repository, settings)
    pipeline.follow([("cowrie", str(log))], once=True)
    assert repository.overview_stats()["total_events"] == 2
    offset = repository.get_offset(str(log))
    assert offset is not None and offset.byte_offset == log.stat().st_size

    with log.open("a", encoding="utf-8") as handle:
        handle.write(
            '{"eventid": "cowrie.command.input", "session": "follow-1", "input": "uname -a"}\n'
        )
    _pipeline(repository, settings).follow([("cowrie", str(log))], once=True)
    assert repository.overview_stats()["total_events"] == 3


def test_follow_mode_does_not_process_partial_line(repository, settings, tmp_path: Path) -> None:
    log = tmp_path / "cowrie-partial.json"
    log.write_text(
        '{"eventid": "cowrie.session.connect", "session": "partial-1"}\n'
        '{"eventid": "cowrie.command.input", "session": "partial-1", "input": "id"',
        encoding="utf-8",
    )
    _pipeline(repository, settings).follow([("cowrie", str(log))], once=True)
    events = repository.export_events()
    assert len(events) == 1
    assert events[0]["event_type"] == "connection"
    failures = repository.get_parser_failures()
    assert len(failures) == 1
    assert "invalid JSON" in failures[0]["error"]
