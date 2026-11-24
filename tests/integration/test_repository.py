"""Integration tests for repository queries, migrations, and reports."""

from __future__ import annotations

from datetime import UTC, datetime

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from deephoney.ingestion.pipeline import IngestionPipeline
from deephoney.reporting.summary import build_summary
from deephoney.storage.models import Base
from deephoney.storage.repository import (
    DetectionFilters,
    EventFilters,
    SessionFilters,
)


def _seed(repository, settings, sample_paths) -> None:
    pipeline = IngestionPipeline(repository, settings)
    pipeline.ingest_file(sample_paths["cowrie"], "cowrie", archive=False)
    pipeline.ingest_file(sample_paths["dionaea"], "dionaea", archive=False)
    pipeline.ingest_file(sample_paths["dionaea_json"], "dionaea", archive=False)


def test_migrations_create_all_tables(database) -> None:
    tables = set(inspect(database.engine).get_table_names())
    assert {
        "events",
        "sessions",
        "artifacts",
        "detections",
        "ingestion_runs",
        "parser_failures",
        "ingestion_offsets",
        "pcap_captures",
        "pcap_flows",
    } <= tables


def test_migrated_schema_matches_orm_metadata(database) -> None:
    with database.engine.connect() as connection:
        context = MigrationContext.configure(connection)
        assert compare_metadata(context, Base.metadata) == []


def test_event_filters_search_and_pagination(repository, settings, sample_paths) -> None:
    _seed(repository, settings, sample_paths)
    rows, total = repository.query_events(EventFilters(), page=1, page_size=10)
    assert total == 35
    assert len(rows) == 10

    cowrie_rows, cowrie_total = repository.query_events(EventFilters(engines=("cowrie",)))
    assert cowrie_total == 26
    assert all(row["source_engine"] == "cowrie" for row in cowrie_rows)

    failures, failure_total = repository.query_events(EventFilters(event_types=("auth_failure",)))
    assert failure_total == 12
    assert all(row["event_type"] == "auth_failure" for row in failures)

    ssh_rows, ssh_total = repository.query_events(EventFilters(protocol="SSH"))
    assert ssh_total == 26

    ip_rows, ip_total = repository.query_events(EventFilters(src_ip="203.0.113.44"))
    assert ip_total > 0
    assert {row["src_ip"] for row in ip_rows} == {"203.0.113.44"}

    matches, match_total = repository.query_events(EventFilters(search="uname"))
    assert match_total == 1
    assert matches[0]["command"] == "uname -a"

    wildcard, wildcard_total = repository.query_events(EventFilters(search="%"))
    assert wildcard_total == 0


def test_paginated_queries_have_stable_ordering(repository, settings, sample_paths) -> None:
    _seed(repository, settings, sample_paths)
    seen: set[str] = set()
    for page in range(1, 6):
        rows, total = repository.query_events(EventFilters(), page=page, page_size=7)
        assert total == 35
        assert len(rows) == 7
        seen.update(row["event_id"] for row in rows)
    assert len(seen) == 35

    session_ids: set[str] = set()
    page = 1
    while True:
        rows, total = repository.query_sessions(SessionFilters(), page=page, page_size=2)
        session_ids.update(row["session_uuid"] for row in rows)
        if len(session_ids) >= total:
            break
        page += 1
    assert len(session_ids) == total


def test_session_and_detection_filters(repository, settings, sample_paths) -> None:
    _seed(repository, settings, sample_paths)
    all_sessions, session_total = repository.query_sessions(SessionFilters())
    assert session_total >= 5
    assert all("risk_score" in row for row in all_sessions)

    high_sessions, high_total = repository.query_sessions(SessionFilters(risk_levels=("high",)))
    assert high_total >= 1
    assert all(row["risk_level"] == "high" for row in high_sessions)

    detections, detection_total = repository.query_detections(DetectionFilters())
    assert detection_total >= 1
    method_rows, method_total = repository.query_detections(DetectionFilters(methods=("rule",)))
    assert method_total == detection_total
    assert all(row["detection_method"] == "rule" for row in method_rows)

    filtered, filtered_total = repository.query_detections(DetectionFilters(min_risk_score=100))
    assert all(row["risk_score"] >= 100 for row in filtered)


def test_export_helpers_are_bounded(repository, settings, sample_paths) -> None:
    _seed(repository, settings, sample_paths)
    assert len(repository.export_events(limit=5)) == 5
    assert len(repository.export_sessions(limit=2)) == 2
    assert len(repository.export_detections(limit=1)) == 1


def test_artifacts_and_run_history_are_recorded(repository, settings, sample_paths) -> None:
    _seed(repository, settings, sample_paths)
    artifacts = repository.get_artifacts()
    assert artifacts
    digest = artifacts[0]["sha256"]
    assert len(digest) == 64
    assert artifacts[0]["metadata"]["note"].startswith("metadata only")
    runs = repository.get_ingestion_runs()
    assert len(runs) >= 2
    assert all(run["records_read"] > 0 for run in runs)


def test_summary_report_is_descriptive(repository, settings, sample_paths) -> None:
    _seed(repository, settings, sample_paths)
    summary = build_summary(repository)
    assert summary["event_counts"]["total"] == 35
    assert summary["event_counts"]["by_engine"] == {"cowrie": 26, "dionaea": 9}
    assert summary["session_count"] >= 6
    assert summary["top_source_ips"]
    assert "not proof" in summary["disclaimer"]
    assert summary["range"] == {"start": None, "end": None}

    start = datetime(2024, 8, 15, 10, 0, tzinfo=UTC)
    end = datetime(2024, 8, 15, 10, 1, tzinfo=UTC)
    ranged = build_summary(repository, start=start, end=end)
    assert ranged["event_counts"]["total"] < summary["event_counts"]["total"]
