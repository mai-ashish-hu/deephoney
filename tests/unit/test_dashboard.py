"""Unit tests for dashboard-only data helpers.

The Streamlit renderers are intentionally thin.  These tests cover the pure
logic underneath them (date windows, relative timestamps, model registry
summaries, bounded text, and non-intrusive health probes) without starting a
Streamlit server.
"""

from __future__ import annotations

import json
import socket
from datetime import UTC, date, datetime, timedelta

from deephoney.dashboard.data import (
    bounded_text,
    day_bounds,
    default_start_date,
    honeypot_health,
    model_registry_summary,
    relative_time,
)
from deephoney.utils.net import tcp_probe


def test_day_bounds_is_inclusive_and_ordered() -> None:
    start, end = day_bounds(date(2024, 8, 15), date(2024, 8, 17))
    assert start == datetime(2024, 8, 15, 0, 0, 0, tzinfo=UTC)
    assert end.date() == date(2024, 8, 17)
    assert end.hour == 23 and end.minute == 59 and end.second == 59
    assert end.tzinfo is UTC


def test_day_bounds_swaps_reversed_input() -> None:
    start, end = day_bounds(date(2024, 8, 17), date(2024, 8, 15))
    assert start.date() == date(2024, 8, 15)
    assert end.date() == date(2024, 8, 17)


def test_default_start_date_is_in_the_past() -> None:
    today = datetime.now(UTC).date()
    assert default_start_date(30) < today
    assert default_start_date(0) == today


def test_relative_time_is_human_readable() -> None:
    now = datetime(2024, 8, 15, 12, 0, tzinfo=UTC)
    assert relative_time(None, now=now) == "never"
    assert relative_time(now - timedelta(seconds=5), now=now) == "5s ago"
    assert relative_time(now - timedelta(minutes=3), now=now) == "3m ago"
    assert relative_time(now - timedelta(hours=2), now=now) == "2h ago"
    assert relative_time(now - timedelta(days=9), now=now) == "9d ago"


def test_relative_time_handles_naive_and_future_values() -> None:
    now = datetime(2024, 8, 15, 12, 0, tzinfo=UTC)
    naive = datetime(2024, 8, 15, 11, 59, 30)
    assert relative_time(naive, now=now) == "30s ago"
    future = now + timedelta(minutes=5)
    assert relative_time(future, now=now) == "2024-08-15 12:05 UTC"


def test_bounded_text_strips_controls_and_truncates() -> None:
    assert bounded_text("hello\x00world") == "helloworld"
    assert bounded_text(None) == ""
    text = bounded_text("x" * 50, max_length=10)
    assert len(text) <= 10
    assert text.endswith("...")


def test_model_registry_summary_handles_missing_and_corrupt_files(settings) -> None:
    assert model_registry_summary(settings) == []
    settings.model_dir.mkdir(parents=True, exist_ok=True)
    (settings.model_dir / "registry.json").write_text("{not json", encoding="utf-8")
    assert model_registry_summary(settings) == []
    (settings.model_dir / "registry.json").write_text("[]", encoding="utf-8")
    assert model_registry_summary(settings) == []


def test_model_registry_summary_joins_metadata(settings) -> None:
    settings.model_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "model_version": "rf-2024.1",
        "model_type": "random_forest",
        "feature_version": "2024.1.0",
        "metrics": {"f1": 0.91},
        "dataset": {"synthetic": True},
        "disclaimer": "Synthetic demo model; not proof of malicious intent.",
    }
    (settings.model_dir / "classical.metadata.json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )
    (settings.model_dir / "registry.json").write_text(
        json.dumps(
            {
                "classical": {
                    "model_version": "rf-2024.1",
                    "updated_at": "2024-08-31T12:00:00Z",
                    "metadata_path": "classical.metadata.json",
                },
                "broken": {"metadata_path": "missing.json"},
                "not-a-record": "ignored",
            }
        ),
        encoding="utf-8",
    )
    rows = {row["slot"]: row for row in model_registry_summary(settings)}
    assert set(rows) == {"classical", "broken"}
    classical = rows["classical"]
    assert classical["model_type"] == "random_forest"
    assert classical["feature_version"] == "2024.1.0"
    assert classical["metrics"] == {"f1": 0.91}
    assert classical["synthetic_dataset"] is True
    assert classical["disclaimer"].startswith("Synthetic demo model")
    assert rows["broken"]["model_type"] == "unknown"


def test_model_registry_summary_handles_malformed_dataset(settings) -> None:
    settings.model_dir.mkdir(parents=True, exist_ok=True)
    (settings.model_dir / "metadata.json").write_text(
        json.dumps({"model_version": "v1", "dataset": "not-an-object"}), encoding="utf-8"
    )
    (settings.model_dir / "registry.json").write_text(
        json.dumps({"bad": {"metadata_path": "metadata.json"}}), encoding="utf-8"
    )
    rows = model_registry_summary(settings)
    assert len(rows) == 1
    assert rows[0]["synthetic_dataset"] is None
    assert rows[0]["model_version"] == "v1"


def test_tcp_probe_reports_open_and_closed_ports() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        result = tcp_probe("127.0.0.1", port, timeout=1.0)
        assert result.open is True
        assert result.latency_ms is not None
        assert result.error is None

    closed = tcp_probe("127.0.0.1", port, timeout=0.5)
    assert closed.open is False
    assert closed.error


def test_honeypot_health_is_a_bounded_probe(monkeypatch, settings) -> None:
    calls: list[tuple[str, int, float]] = []

    def fake_probe(host: str, port: int, timeout: float = 2.0):
        calls.append((host, port, timeout))
        from deephoney.utils.net import ProbeResult

        return ProbeResult(host=host, port=port, open=False, latency_ms=None, error="refused")

    monkeypatch.setenv("DEEPHONEY_COWRIE_HOST", "127.0.0.1")
    monkeypatch.setenv("DEEPHONEY_COWRIE_SSH_PORT", "2222")
    monkeypatch.setenv("DEEPHONEY_DIONAEA_HOST", "127.0.0.1")
    monkeypatch.setenv("DEEPHONEY_DIONAEA_HTTP_PORT", "8080")
    monkeypatch.setattr("deephoney.dashboard.data.tcp_probe", fake_probe)
    results = honeypot_health()
    assert len(results) == 4
    assert {result["service"] for result in results} == {
        "Cowrie SSH",
        "Cowrie Telnet",
        "Dionaea FTP",
        "Dionaea HTTP",
    }
    assert all(result["open"] is False for result in results)
    assert all(":" in result["endpoint"] for result in results)
    assert calls and all(call[2] == 1.5 for call in calls)


def test_dashboard_pages_are_importable_and_renderable() -> None:
    from deephoney.dashboard.pages import cowrie, dionaea, events, overview, reports, status, threat

    for module in (overview, events, cowrie, dionaea, threat, reports, status):
        assert callable(module.render)
