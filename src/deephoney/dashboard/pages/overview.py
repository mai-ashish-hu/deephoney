"""Overview dashboard page."""

from __future__ import annotations

import streamlit as st

from deephoney.config.settings import Settings
from deephoney.dashboard.components import (
    daily_activity_chart,
    empty_state,
    events_frame,
    metric_row,
    page_header,
    risk_distribution_chart,
    safety_banner,
    sessions_frame,
    show_dataframe,
    source_ip_chart,
)
from deephoney.storage.repository import Repository, SessionFilters


def render(repository: Repository, settings: Settings, *, timezone_name: str) -> None:
    page_header(
        "Overview",
        "Observed Cowrie and Dionaea telemetry, session activity, and risk distribution.",
    )
    safety_banner()
    overview = repository.overview_stats()
    by_engine = overview["by_engine"]
    risk = overview["risk_distribution"]
    metric_row(
        [
            ("Total events", overview["total_events"], "Normalized events from both honeypots"),
            ("Cowrie", by_engine.get("cowrie", 0), "SSH/Telnet interaction telemetry"),
            ("Dionaea", by_engine.get("dionaea", 0), "Service interactions and capture metadata"),
            ("Source IPs", overview["unique_source_ips"], "Distinct observed source addresses"),
            ("Sessions", overview["session_count"], "Reconstructed engine-local sessions"),
            ("Artifacts", overview["artifact_count"], "Metadata-only artifact records"),
            (
                "High-risk detections",
                risk.get("high", 0),
                "Detections with a score at or above the high threshold",
            ),
        ]
    )
    st.caption(
        "Last event: "
        f"{overview['last_event_at'].strftime('%Y-%m-%d %H:%M UTC') if overview['last_event_at'] else 'none'} · "
        "Last ingestion: "
        f"{overview['last_ingested_at'].strftime('%Y-%m-%d %H:%M UTC') if overview['last_ingested_at'] else 'none'}"
    )

    left, right = st.columns([1.35, 1])
    with left:
        st.subheader("Events over time")
        try:
            daily_activity_chart(repository.event_counts_by_day(), label="Events")
        except Exception as exc:
            st.warning("Daily event aggregation is unavailable.")
            st.code(type(exc).__name__)
    with right:
        st.subheader("Risk distribution")
        risk_distribution_chart(risk)

    left, right = st.columns([1, 1.35])
    with left:
        st.subheader("Most active source IPs")
        try:
            source_ip_chart(repository.top_source_ips(limit=10))
        except Exception as exc:
            st.warning("Source IP aggregation is unavailable.")
            st.code(type(exc).__name__)
    with right:
        st.subheader("Recent high-risk sessions")
        try:
            sessions, _total = repository.query_sessions(
                SessionFilters(risk_levels=("high",)),
                page=1,
                page_size=8,
                timezone_name=timezone_name,
            )
        except Exception as exc:
            st.warning("Session query failed.")
            st.code(type(exc).__name__)
            sessions = []
        if sessions:
            show_dataframe(sessions_frame(sessions))
        else:
            empty_state(
                "No high-risk sessions have been scored yet.",
                "Stage A rules run automatically after ingestion.",
            )

    st.subheader("Recent events")
    recent = overview.get("recent_events") or []
    if recent:
        show_dataframe(events_frame(recent), height=360)
    else:
        empty_state(
            "No telemetry has been ingested.",
            "Run `make seed` for a sanitized demonstration dataset.",
        )


__all__ = ["render"]
