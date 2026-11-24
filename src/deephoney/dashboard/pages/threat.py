"""Threat analysis page."""

from __future__ import annotations

import streamlit as st

from deephoney.config.settings import Settings
from deephoney.dashboard.components import (
    current_page,
    date_range_filter,
    detections_frame,
    empty_state,
    metric_row,
    page_header,
    page_size_selector,
    pagination_controls,
    render_detection,
    render_session_detail,
    reset_page_on_filter_change,
    safety_banner,
    show_dataframe,
)
from deephoney.storage.repository import DetectionFilters, Repository


def render(repository: Repository, settings: Settings, *, timezone_name: str) -> None:
    page_header(
        "Threat Analysis",
        "Inspect risk scores, detection methods, contributing evidence, and approximate explanations.",
    )
    safety_banner()
    with st.expander("Filters", expanded=True):
        start, end = date_range_filter("threat")
        first, second, third = st.columns(3)
        engines = first.multiselect(
            "Engine", options=["cowrie", "dionaea"], default=[], key="threat_engines"
        )
        methods = second.multiselect(
            "Method",
            options=["rule", "supervised_model", "anomaly_model", "sequence_model", "statistical"],
            default=[],
            key="threat_methods",
        )
        levels = third.multiselect(
            "Risk level", options=["high", "medium", "low"], default=[], key="threat_levels"
        )
        min_score = st.slider("Minimum score", 0, 100, 0, key="threat_min_score")

    filters = DetectionFilters(
        start=start,
        end=end,
        engines=tuple(engines),
        methods=tuple(methods),
        risk_levels=tuple(levels),
        min_risk_score=min_score or None,
    )
    reset_page_on_filter_change(
        "threat",
        (
            filters.start,
            filters.end,
            filters.engines,
            filters.methods,
            filters.risk_levels,
            filters.min_risk_score,
        ),
    )
    page_size = page_size_selector("threat", default=25)
    page = current_page("threat")
    try:
        rows, total = repository.query_detections(
            filters,
            page=page,
            page_size=page_size,
            timezone_name=timezone_name,
        )
        methods_count = repository.detection_counts_by_method()
    except Exception as exc:
        from deephoney.dashboard.components import render_error

        render_error(exc)
        return

    metric_row(
        [
            ("Matching detections", total, None),
            ("Rule detections", methods_count.get("rule", 0), "Stage A transparent heuristics"),
            (
                "Classical model",
                methods_count.get("supervised_model", 0) + methods_count.get("anomaly_model", 0),
                "Stage B, when a model is registered",
            ),
            ("Sequence model", methods_count.get("sequence_model", 0), "Stage C experimental"),
        ]
    )
    if not rows:
        empty_state(
            "No detections match the current filters.",
            "Run ingestion and detection, or train a model with `make` targets.",
        )
        return
    show_dataframe(detections_frame(rows), height=420)
    pagination_controls(total, page, page_size, "threat")

    st.subheader("Detection detail")
    index = st.selectbox(
        "Select a detection",
        options=list(range(len(rows))),
        format_func=lambda item: (
            f"score {rows[item].get('risk_score')} · {rows[item].get('detection_method')} · "
            f"{rows[item].get('source_engine')} · {rows[item].get('src_ip') or 'unknown'}"
        ),
        key="threat_selected",
    )
    selected = rows[index]
    render_detection(selected)
    st.caption(
        f"Session `{selected.get('source_session_id') or 'unknown'}` · "
        f"first seen {selected.get('first_seen_display') or 'unknown'} · "
        f"events {selected.get('event_count')}"
    )
    with st.expander("Session context", expanded=False):
        try:
            session = repository.get_session_row(selected.get("session_uuid"))
            if session is None:
                empty_state("The source session is no longer available.")
            else:
                session_dict = {
                    "session_uuid": str(session.id),
                    "source_engine": session.source_engine,
                    "source_session_id": session.source_session_id,
                    "src_ip": session.src_ip,
                    "first_seen_display": session.first_seen_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "event_count": session.event_count,
                    "risk_score": selected.get("risk_score"),
                    "duration_seconds": (session.session_metadata or {}).get("duration_seconds"),
                    "metadata": session.session_metadata,
                }
                render_session_detail(repository, session_dict, timezone_name=timezone_name)
        except Exception as exc:
            st.warning("Session context could not be loaded.")
            st.code(type(exc).__name__)


__all__ = ["render"]
