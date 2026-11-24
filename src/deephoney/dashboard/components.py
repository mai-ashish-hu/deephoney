"""Reusable, security-conscious dashboard components."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from datetime import date, datetime
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from deephoney.dashboard.data import day_bounds, default_start_date
from deephoney.schemas.detections import RiskLevel
from deephoney.storage.repository import Repository
from deephoney.utils.redaction import sanitize_text

PANEL_CSS = """
<style>
.block-container {padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1500px;}
.dh-banner {
  border: 1px solid #8a6d2f; background: rgba(217,164,65,0.10);
  border-radius: 0.55rem; padding: 0.75rem 1rem; margin-bottom: 1rem;
  color: #E8EDF2; font-size: 0.9rem;
}
.dh-muted {color: #9AA7B4; font-size: 0.85rem;}
div[data-testid="stMetric"] {
  background: #17202A; border: 1px solid #243241;
  padding: 0.7rem 0.9rem; border-radius: 0.55rem;
}
</style>
"""


def page_header(title: str, subtitle: str) -> None:
    st.title(title)
    st.caption(subtitle)


def safety_banner() -> None:
    st.markdown(
        '<div class="dh-banner">'
        "<strong>Defensive lab system.</strong> Risk scores are prioritisation aids, "
        "not proof of malicious intent or attribution. Captured credentials are "
        "redacted and exported cells are formula-neutralised."
        "</div>",
        unsafe_allow_html=True,
    )


def render_error(exc: Exception) -> None:
    """Show a safe error without leaking DSNs, credentials, or attacker data."""

    st.error(
        "The data request failed. Check that PostgreSQL is running and migrations "
        "are applied (`alembic upgrade head`)."
    )
    with st.expander("Technical detail"):
        st.code(type(exc).__name__)
    st.caption("Server-side logs contain the full traceback; database URLs are never shown.")


def empty_state(message: str, hint: str | None = None) -> None:
    st.info(message)
    if hint:
        st.caption(hint)


def metric_row(items: Iterable[tuple[str, Any, str | None]]) -> None:
    entries = list(items)
    if not entries:
        return
    columns = st.columns(len(entries))
    for column, (label, value, help_text) in zip(columns, entries, strict=True):
        column.metric(label, value, help=help_text)


def _truncate(value: Any, limit: int = 220) -> str:
    if value is None:
        return ""
    text = sanitize_text(value, max_length=limit + 80)
    return text[:limit] + ("..." if len(text) > limit else "")


def events_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    display: list[dict[str, Any]] = []
    for row in rows:
        display.append(
            {
                "Time (UTC)": row.get("timestamp") or "unknown",
                "Engine": row.get("source_engine"),
                "Event type": row.get("event_type"),
                "Source": row.get("src_ip"),
                "Src port": row.get("src_port"),
                "Destination port": row.get("dst_port"),
                "Protocol": row.get("protocol"),
                "Username": _truncate(row.get("username"), 80),
                "Command": _truncate(row.get("command"), 180),
            }
        )
    return pd.DataFrame(display)


def sessions_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    display: list[dict[str, Any]] = []
    for row in rows:
        display.append(
            {
                "First seen (UTC)": row.get("first_seen_at") or "unknown",
                "Engine": row.get("source_engine"),
                "Source IP": row.get("src_ip"),
                "Risk": row.get("risk_score") if row.get("risk_score") is not None else "-",
                "Level": row.get("risk_level") or "unscored",
                "Events": row.get("event_count"),
                "Duration (s)": round(float(row.get("duration_seconds") or 0), 1),
                "Auth fail": row.get("auth_failures"),
                "Auth ok": row.get("auth_successes"),
                "Commands": row.get("command_count"),
                "Downloads": row.get("download_count"),
                "Protocols": ", ".join(str(item) for item in (row.get("protocols") or [])),
            }
        )
    return pd.DataFrame(display)


def detections_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    display: list[dict[str, Any]] = []
    for row in rows:
        display.append(
            {
                "Created (UTC)": row.get("created_at") or "unknown",
                "Engine": row.get("source_engine"),
                "Source IP": row.get("src_ip"),
                "Session": row.get("source_session_id"),
                "Score": row.get("risk_score"),
                "Level": row.get("risk_level"),
                "Method": row.get("detection_method"),
                "Model version": row.get("model_version"),
                "Confidence": (
                    round(float(row["confidence"]), 3)
                    if row.get("confidence") is not None
                    else "n/a"
                ),
            }
        )
    return pd.DataFrame(display)


def show_dataframe(frame: pd.DataFrame, *, height: int | None = None) -> None:
    if frame.empty:
        empty_state("No records match the current filters.")
        return
    st.dataframe(
        frame,
        hide_index=True,
        use_container_width=True,
        height=height,
    )


def risk_distribution_chart(distribution: dict[str, int]) -> None:
    labels = [level.value for level in RiskLevel]
    counts = [int(distribution.get(label, 0)) for label in labels]
    if not any(counts):
        empty_state(
            "No detections have been scored yet.", "Run `make seed` to import sample telemetry."
        )
        return
    frame = pd.DataFrame({"Risk level": labels, "Detections": counts})
    figure = px.bar(
        frame,
        x="Risk level",
        y="Detections",
        color="Risk level",
        color_discrete_map={"low": "#3B8C6E", "medium": "#D9A441", "high": "#C0392B"},
    )
    figure.update_layout(
        template="plotly_dark",
        height=330,
        margin=dict(l=10, r=10, t=20, b=10),
        showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(figure, use_container_width=True)


def daily_activity_chart(rows: list[dict[str, Any]], *, label: str) -> None:
    if not rows:
        empty_state(f"No {label.lower()} data is available for this range.")
        return
    frame = pd.DataFrame(rows)
    if frame.empty or "day" not in frame.columns:
        empty_state(f"No {label.lower()} data is available for this range.")
        return
    figure = px.bar(
        frame,
        x="day",
        y="count",
        color="source_engine",
        barmode="stack",
        labels={"day": "Day (UTC)", "count": label, "source_engine": "Engine"},
    )
    figure.update_layout(
        template="plotly_dark",
        height=340,
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h"),
    )
    st.plotly_chart(figure, use_container_width=True)


def source_ip_chart(rows: list[dict[str, Any]]) -> None:
    if not rows:
        empty_state("No source IP observations are available.")
        return
    frame = pd.DataFrame(rows).head(10).iloc[::-1]
    figure = px.bar(
        frame,
        x="events",
        y="src_ip",
        orientation="h",
        labels={"events": "Events", "src_ip": "Source IP"},
    )
    figure.update_layout(
        template="plotly_dark",
        height=320,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(figure, use_container_width=True)


def page_size_selector(key: str, default: int = 50) -> int:
    size_key = f"{key}_page_size"
    last_key = f"{key}_last_page_size"
    size = st.selectbox(
        "Rows per page",
        options=[25, 50, 100],
        index=[25, 50, 100].index(default) if default in {25, 50, 100} else 1,
        key=size_key,
    )
    if st.session_state.get(last_key) != size:
        st.session_state[last_key] = size
        st.session_state[f"{key}_page"] = 1
    return int(size)


def current_page(key: str) -> int:
    return max(1, int(st.session_state.get(f"{key}_page", 1)))


def reset_page_on_filter_change(key: str, signature: object) -> None:
    """Return to page one when the active filter values change."""

    last_key = f"{key}_last_filters"
    if st.session_state.get(last_key) != signature:
        st.session_state[last_key] = signature
        st.session_state[f"{key}_page"] = 1


def pagination_controls(total: int, page: int, page_size: int, key: str) -> None:
    pages = max(1, math.ceil(total / max(1, page_size)))
    page = min(max(1, page), pages)
    st.session_state[f"{key}_page"] = page
    left, middle, right = st.columns([1, 3, 1])
    if left.button("Previous", disabled=page <= 1, key=f"{key}_prev", use_container_width=True):
        st.session_state[f"{key}_page"] = page - 1
        st.rerun()
    middle.caption(f"Page {page} of {pages} · {total} record(s)")
    if right.button("Next", disabled=page >= pages, key=f"{key}_next", use_container_width=True):
        st.session_state[f"{key}_page"] = page + 1
        st.rerun()


def date_range_filter(key: str) -> tuple[datetime | None, datetime | None]:
    """Render an optional inclusive date range; default is all time."""

    all_time = st.checkbox("All time", value=True, key=f"{key}_all_time")
    if all_time:
        return None, None
    selected = st.date_input(
        "Date range (UTC)",
        value=(default_start_date(), date.today()),
        key=f"{key}_dates",
    )
    if isinstance(selected, tuple | list) and len(selected) == 2:
        start_date, end_date = selected
        return day_bounds(start_date, end_date)
    return None, None


def show_json(title: str, value: Any, *, expanded: bool = False) -> None:
    with st.expander(title, expanded=expanded):
        st.json(value if value is not None else {})


def _event_commands(events: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for event in events:
        command = event.get("command")
        if not command:
            continue
        rows.append(
            {
                "Time (UTC)": event.get("timestamp") or "unknown",
                "Event": event.get("event_type"),
                "Username": _truncate(event.get("username"), 80),
                "Command": sanitize_text(command, max_length=1000),
            }
        )
    return pd.DataFrame(rows)


def render_detection(detection: dict[str, Any]) -> None:
    evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
    score = detection.get("risk_score")
    level = str(detection.get("risk_level", "unknown")).upper()
    st.subheader("Detection evidence")
    columns = st.columns(4)
    columns[0].metric("Risk score", f"{score}/100")
    columns[1].metric("Risk level", level)
    columns[2].metric("Method", str(detection.get("detection_method", "unknown")))
    columns[3].metric("Model version", str(detection.get("model_version", "unknown")))
    if isinstance(score, int):
        st.progress(min(max(score, 0), 100))
    summary = evidence.get("summary")
    if summary:
        st.write(sanitize_text(summary, max_length=2000))
    rules = evidence.get("rules")
    if isinstance(rules, list) and rules:
        rows = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rows.append(
                {
                    "Rule": rule.get("rule_id"),
                    "Title": rule.get("title"),
                    "Weight": rule.get("weight"),
                    "What was observed": json.dumps(
                        rule.get("observed", {}), ensure_ascii=False, sort_keys=True
                    )[:500],
                    "Description": rule.get("description"),
                }
            )
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    top_features = evidence.get("top_features")
    if isinstance(top_features, list) and top_features:
        st.markdown("**Approximate feature contributions**")
        st.dataframe(pd.DataFrame(top_features), hide_index=True, use_container_width=True)
    explanation = detection.get("explanation")
    if explanation:
        show_json("Approximate explanation payload", explanation)
    if evidence.get("observed_facts"):
        show_json("Observed facts", evidence["observed_facts"])
    if evidence.get("metrics"):
        show_json("Model evaluation context", evidence["metrics"])
    disclaimer = evidence.get("disclaimer") or (
        "A risk score is a prioritisation aid, not proof of malicious intent."
    )
    st.caption(sanitize_text(disclaimer, max_length=1000))


def render_session_detail(
    repository: Repository,
    session: dict[str, Any],
    *,
    timezone_name: str,
) -> None:
    session_uuid = session.get("session_uuid")
    if not session_uuid:
        empty_state("This session has no internal identifier.")
        return
    risk = session.get("risk_score")
    metric_row(
        [
            ("Source IP", session.get("src_ip") or "unknown", None),
            ("Risk", f"{risk}/100" if risk is not None else "unscored", None),
            ("Events", session.get("event_count", 0), None),
            (
                "Duration",
                f"{float(session.get('duration_seconds') or 0):.1f}s",
                None,
            ),
        ]
    )
    st.caption(
        f"Engine: {session.get('source_engine')} · first seen "
        f"{session.get('first_seen_display') or 'unknown'} · source session id shown below."
    )
    st.code(str(session.get("source_session_id") or "unknown"), language=None)

    try:
        events = repository.get_serialized_session_events(session_uuid, timezone_name=timezone_name)
        detections = repository.get_detections_for_session(
            session_uuid, timezone_name=timezone_name
        )
    except Exception as exc:
        render_error(exc)
        return

    tabs = st.tabs(
        ["Timeline", "Commands", "Authentication", "Artifacts", "Detections", "Metadata"]
    )
    with tabs[0]:
        show_dataframe(events_frame(events), height=420)
    with tabs[1]:
        commands = _event_commands(events)
        show_dataframe(commands, height=360)
    with tabs[2]:
        auth_rows = [
            {
                "Time (UTC)": event.get("timestamp") or "unknown",
                "Event": event.get("event_type"),
                "Username": _truncate(event.get("username"), 120),
            }
            for event in events
            if event.get("event_type") in {"auth_attempt", "auth_success", "auth_failure"}
        ]
        show_dataframe(pd.DataFrame(auth_rows), height=320)
    with tabs[3]:
        artifacts = [
            {
                "Time (UTC)": event.get("timestamp") or "unknown",
                "Event": event.get("event_type"),
                "SHA-256": event.get("artifact_sha256") or "",
                "Details": json.dumps(event.get("details") or {}, ensure_ascii=False)[:600],
            }
            for event in events
            if event.get("event_type") in {"file_download", "file_upload", "capture"}
            or event.get("artifact_sha256")
        ]
        show_dataframe(pd.DataFrame(artifacts), height=320)
        st.caption("Only hashes and metadata are displayed. Captured binaries are never served.")
    with tabs[4]:
        if not detections:
            empty_state("No detection is stored for this session.")
        for detection in detections:
            with st.expander(
                f"{str(detection.get('detection_method')).title()} · "
                f"score {detection.get('risk_score')}/100",
                expanded=False,
            ):
                render_detection(detection)
    with tabs[5]:
        show_json("Reconstructed session metadata", session.get("metadata"), expanded=True)


__all__ = [
    "PANEL_CSS",
    "current_page",
    "daily_activity_chart",
    "date_range_filter",
    "detections_frame",
    "empty_state",
    "events_frame",
    "metric_row",
    "page_header",
    "page_size_selector",
    "pagination_controls",
    "render_detection",
    "render_error",
    "render_session_detail",
    "reset_page_on_filter_change",
    "risk_distribution_chart",
    "safety_banner",
    "sessions_frame",
    "show_dataframe",
    "show_json",
    "source_ip_chart",
]
