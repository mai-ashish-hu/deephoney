"""Reports and safe export page."""

from __future__ import annotations

import json

import streamlit as st

from deephoney.config.settings import Settings
from deephoney.dashboard.components import (
    daily_activity_chart,
    empty_state,
    metric_row,
    page_header,
    risk_distribution_chart,
    source_ip_chart,
)
from deephoney.reporting import (
    build_summary,
    export_filename,
    export_payload,
    rows_to_json,
)
from deephoney.storage.repository import Repository

EXPORT_LIMIT = 20_000


def _download(
    rows: list[dict],
    *,
    label: str,
    prefix: str,
    fmt: str,
    key: str,
    columns: list[str] | None = None,
) -> None:
    try:
        content, media_type = export_payload(rows, fmt, columns=columns)
    except Exception as exc:
        st.warning(f"{label} export could not be prepared.")
        st.code(type(exc).__name__)
        return
    st.download_button(
        f"Download {label} ({fmt.upper()})",
        data=content,
        file_name=export_filename(prefix, fmt),
        mime=media_type,
        key=key,
    )


def render(repository: Repository, settings: Settings, *, timezone_name: str) -> None:
    page_header(
        "Reports",
        "Range summaries, trends, and sanitized CSV/JSON exports for events, sessions, and detections.",
    )
    with st.expander("Report range", expanded=True):
        from deephoney.dashboard.components import date_range_filter

        start, end = date_range_filter("reports")
    try:
        summary = build_summary(repository, start=start, end=end)
    except Exception as exc:
        from deephoney.dashboard.components import render_error

        render_error(exc)
        return

    counts = summary["event_counts"]
    metric_row(
        [
            ("Events in range", counts["total"], None),
            ("Sessions (all time)", summary["session_count"], None),
            ("Artifacts (all time)", summary["artifact_count"], None),
            ("Unique IPs (all time)", summary["unique_source_ips"], None),
        ]
    )
    tabs = st.tabs(["Summary", "Events", "Sessions", "Detections", "Raw summary"])

    with tabs[0]:
        left, right = st.columns(2)
        with left:
            st.subheader("Daily events")
            daily_activity_chart(summary["daily_events"], label="Events")
        with right:
            st.subheader("Risk distribution")
            risk_distribution_chart(summary["risk_distribution"])
        st.subheader("Top source IPs")
        source_ip_chart(summary["top_source_ips"])
        _download(
            [summary],
            label="summary",
            prefix="deephoney-summary",
            fmt="json",
            key="reports_summary_json",
        )

    with tabs[1]:
        try:
            rows = repository.export_events(start=start, end=end, limit=EXPORT_LIMIT)
        except Exception as exc:
            st.warning("Event export could not be prepared.")
            st.code(type(exc).__name__)
            rows = []
        st.caption(
            f"{len(rows)} event(s) prepared (maximum {EXPORT_LIMIT}). Raw payloads are redacted "
            "and CSV formula prefixes are neutralised."
        )
        if rows:
            _download(
                rows, label="events", prefix="deephoney-events", fmt="csv", key="reports_events_csv"
            )
            _download(
                rows,
                label="events",
                prefix="deephoney-events",
                fmt="json",
                key="reports_events_json",
            )
        else:
            empty_state("No events exist in this range.")

    with tabs[2]:
        try:
            rows = repository.export_sessions(start=start, end=end, limit=EXPORT_LIMIT)
        except Exception as exc:
            st.warning("Session export could not be prepared.")
            st.code(type(exc).__name__)
            rows = []
        st.caption(f"{len(rows)} session(s) prepared (maximum {EXPORT_LIMIT}).")
        if rows:
            _download(
                rows,
                label="sessions",
                prefix="deephoney-sessions",
                fmt="csv",
                key="reports_sessions_csv",
            )
            _download(
                rows,
                label="sessions",
                prefix="deephoney-sessions",
                fmt="json",
                key="reports_sessions_json",
            )
        else:
            empty_state("No sessions exist in this range.")

    with tabs[3]:
        try:
            rows = repository.export_detections(start=start, end=end, limit=EXPORT_LIMIT)
        except Exception as exc:
            st.warning("Detection export could not be prepared.")
            st.code(type(exc).__name__)
            rows = []
        st.caption(f"{len(rows)} detection(s) prepared (maximum {EXPORT_LIMIT}).")
        if rows:
            _download(
                rows,
                label="detections",
                prefix="deephoney-detections",
                fmt="csv",
                key="reports_detections_csv",
            )
            _download(
                rows,
                label="detections",
                prefix="deephoney-detections",
                fmt="json",
                key="reports_detections_json",
            )
        else:
            empty_state("No detections exist in this range.")

    with tabs[4]:
        st.caption("Sanitized JSON summary for inclusion in a report appendix.")
        try:
            st.code(rows_to_json([summary]), language="json")
        except Exception as exc:
            st.warning("Summary rendering failed.")
            st.code(type(exc).__name__)
        st.caption(
            "Interpretation: event counts describe observed honeypot telemetry. "
            "They are not an attribution or compromise assessment."
        )
        if rows_to_json([summary]):
            st.download_button(
                "Download summary JSON",
                data=json.dumps(summary, indent=2, default=str, ensure_ascii=False).encode("utf-8"),
                file_name=export_filename("deephoney-summary", "json"),
                mime="application/json",
                key="reports_raw_summary_json",
            )


__all__ = ["render"]
