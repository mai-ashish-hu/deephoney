"""Event explorer page."""

from __future__ import annotations

import streamlit as st

from deephoney.config.settings import Settings
from deephoney.dashboard.components import (
    current_page,
    date_range_filter,
    empty_state,
    events_frame,
    metric_row,
    page_header,
    page_size_selector,
    pagination_controls,
    reset_page_on_filter_change,
    show_dataframe,
    show_json,
)
from deephoney.storage.repository import EventFilters, Repository
from deephoney.utils.redaction import sanitize_text

DISPLAY_FIELDS = (
    "event_id",
    "event_hash",
    "source_engine",
    "source_event_id",
    "event_type",
    "timestamp",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "session_id",
    "username",
    "command",
    "artifact_sha256",
    "source_file",
    "source_line",
    "parser_version",
    "ingested_at",
)


def render(repository: Repository, settings: Settings, *, timezone_name: str) -> None:
    page_header(
        "Live / Recent Events",
        "Filter normalized events, inspect source metadata, and review redacted raw payloads.",
    )
    with st.expander("Filters", expanded=True):
        start, end = date_range_filter("events")
        first, second, third = st.columns([1, 1.4, 1])
        engines = first.multiselect(
            "Engine",
            options=["cowrie", "dionaea"],
            default=[],
            key="events_engines",
        )
        try:
            event_type_options = repository.distinct_event_types()
            protocol_options = repository.distinct_protocols()
        except Exception as exc:
            st.error("Filter metadata could not be loaded without a migrated database.")
            st.code(type(exc).__name__)
            event_type_options = []
            protocol_options = []
        event_types = second.multiselect(
            "Event type", options=event_type_options, default=[], key="events_types"
        )
        protocol = third.selectbox(
            "Protocol", options=["any", *protocol_options], key="events_protocol"
        )
        first, second = st.columns(2)
        src_ip = first.text_input("Source IP (exact)", key="events_src_ip")
        search = second.text_input("Search command, username, or event id", key="events_search")

    filters = EventFilters(
        start=start,
        end=end,
        engines=tuple(engines),
        event_types=tuple(event_types),
        protocol=None if protocol == "any" else protocol,
        src_ip=src_ip.strip() or None,
        search=search.strip() or None,
    )
    reset_page_on_filter_change(
        "events",
        (
            filters.start,
            filters.end,
            filters.engines,
            filters.event_types,
            filters.protocol,
            filters.src_ip,
            filters.search,
        ),
    )
    page_size = page_size_selector("events", default=settings.dashboard.page_size)
    page = current_page("events")
    try:
        rows, total = repository.query_events(
            filters, page=page, page_size=page_size, timezone_name=timezone_name
        )
    except Exception as exc:
        from deephoney.dashboard.components import render_error

        render_error(exc)
        return

    metric_row(
        [
            ("Matching events", total, None),
            (
                "Cowrie on page",
                sum(1 for row in rows if row["source_engine"] == "cowrie"),
                None,
            ),
            (
                "Dionaea on page",
                sum(1 for row in rows if row["source_engine"] == "dionaea"),
                None,
            ),
        ]
    )
    show_dataframe(events_frame(rows), height=450)
    pagination_controls(total, page, page_size, "events")

    if not rows:
        empty_state(
            "No events match the selected filters.",
            "Try selecting the all-time range or clearing the search box.",
        )
        return
    st.subheader("Event detail")
    index = st.selectbox(
        "Select a row from this page",
        options=list(range(len(rows))),
        format_func=lambda item: (
            f"{rows[item].get('timestamp_display') or 'unknown'} · "
            f"{rows[item].get('source_engine')} · {rows[item].get('event_type')}"
        ),
        key="events_selected",
    )
    selected = rows[index]
    values = {
        field: (
            sanitize_text(selected.get(field), max_length=1000)
            if isinstance(selected.get(field), str)
            else selected.get(field)
        )
        for field in DISPLAY_FIELDS
    }
    st.json(values)
    st.caption(
        "Password-like values are redacted from raw payloads. Timestamps are stored in UTC "
        f"and displayed in {timezone_name}."
    )
    show_json("Raw source event (redacted)", selected.get("raw_payload"), expanded=False)


__all__ = ["render"]
