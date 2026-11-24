"""Aggregate report construction for the dashboard and CLI."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from deephoney.storage.repository import Repository
from deephoney.utils.time import format_utc


def build_summary(
    repository: Repository,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    top_limit: int = 10,
) -> dict[str, Any]:
    """Build a JSON-safe summary for a time range.

    The summary is descriptive.  It does not assert that every honeypot
    connection is an attack or that IP counts imply attribution.
    """

    counts = repository.summary_counts(start, end)
    overview = repository.overview_stats()
    return {
        "generated_at": format_utc(datetime.now().astimezone()),
        "range": {
            "start": format_utc(start),
            "end": format_utc(end),
        },
        "event_counts": {
            "total": sum(counts["by_engine"].values()),
            "by_engine": counts["by_engine"],
            "by_event_type": counts["by_event_type"],
            "by_protocol": counts["by_protocol"],
        },
        "session_count": overview["session_count"],
        "artifact_count": overview["artifact_count"],
        "unique_source_ips": overview["unique_source_ips"],
        "risk_distribution": overview["risk_distribution"],
        "detection_methods": repository.detection_counts_by_method(),
        "top_source_ips": repository.top_source_ips(start, end, limit=top_limit),
        "daily_events": repository.event_counts_by_day(start, end),
        "daily_sessions": repository.sessions_by_day(start, end),
        "pcap_captures": repository.get_pcap_captures(limit=top_limit),
        "disclaimer": (
            "Counts describe observed honeypot telemetry. They are prioritisation "
            "and reporting aids, not proof of malicious intent or attribution."
        ),
    }


__all__ = ["build_summary"]
