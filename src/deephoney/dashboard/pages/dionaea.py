"""Dionaea analysis page."""

from __future__ import annotations

import json

import pandas as pd
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
    render_session_detail,
    reset_page_on_filter_change,
    sessions_frame,
    show_dataframe,
)
from deephoney.storage.repository import EventFilters, Repository, SessionFilters


def _artifact_frame(rows: list[dict]) -> pd.DataFrame:
    records = []
    for row in rows:
        metadata = row.get("metadata") or {}
        records.append(
            {
                "First seen (UTC)": row.get("first_seen_at") or "unknown",
                "SHA-256": row.get("sha256"),
                "Size (bytes)": row.get("file_size"),
                "Detected type": row.get("detected_type"),
                "Filenames": ", ".join(str(item) for item in metadata.get("filenames", [])[:5]),
                "URLs": ", ".join(str(item) for item in metadata.get("urls", [])[:5]),
            }
        )
    return pd.DataFrame(records)


def _render_pcap(repository: Repository) -> None:
    captures = repository.get_pcap_captures(limit=50)
    if not captures:
        empty_state(
            "No PCAP captures have been imported.",
            "Use `python scripts/import_pcap.py data/samples/pcap/sample-ssh-scan.pcap`.",
        )
        return
    frame = pd.DataFrame(
        [
            {
                "Imported (UTC)": row.get("imported_at_display"),
                "Filename": row.get("filename"),
                "SHA-256": row.get("sha256"),
                "Packets": row.get("packet_count"),
                "Flows": row.get("flow_count"),
                "Truncated": row.get("truncated"),
            }
            for row in captures
        ]
    )
    show_dataframe(frame)
    index = st.selectbox(
        "Inspect capture flows",
        options=list(range(len(captures))),
        format_func=lambda item: str(captures[item].get("filename")),
        key="pcap_selected_capture",
    )
    flows, total = repository.get_pcap_flows(captures[index].get("capture_id"), limit=500)
    st.caption(f"{total} flow record(s); showing at most 500. Payload bytes are not stored.")
    if flows:
        show_dataframe(
            pd.DataFrame(
                [
                    {
                        "First seen (UTC)": flow.get("first_seen_display"),
                        "Source": f"{flow.get('src_ip')}:{flow.get('src_port') or ''}",
                        "Destination": f"{flow.get('dst_ip')}:{flow.get('dst_port') or ''}",
                        "Protocol": flow.get("protocol"),
                        "Packets": flow.get("packet_count"),
                        "Bytes": flow.get("byte_count"),
                        "Service": (flow.get("metadata") or {}).get("dst_port_service"),
                    }
                    for flow in flows
                ]
            ),
            height=420,
        )
    else:
        empty_state("No flow rows are stored for this capture.")


def render(repository: Repository, settings: Settings, *, timezone_name: str) -> None:
    page_header(
        "Dionaea Analysis",
        "Service interactions, connection metadata, artifact hashes, and bounded PCAP flow analysis.",
    )
    tabs = st.tabs(["Sessions", "Artifacts", "Events", "PCAP flows"])

    with tabs[0]:
        with st.expander("Session filters", expanded=True):
            start, end = date_range_filter("dionaea")
            first, second = st.columns(2)
            src_ip = first.text_input("Source IP (exact)", key="dionaea_src_ip")
            levels = second.multiselect(
                "Risk level", options=["high", "medium", "low"], default=[], key="dionaea_levels"
            )
        filters = SessionFilters(
            start=start,
            end=end,
            engines=("dionaea",),
            src_ip=src_ip.strip() or None,
            risk_levels=tuple(levels),
        )
        reset_page_on_filter_change(
            "dionaea", (filters.start, filters.end, filters.src_ip, filters.risk_levels)
        )
        page_size = page_size_selector("dionaea", default=25)
        page = current_page("dionaea")
        try:
            rows, total = repository.query_sessions(
                filters,
                page=page,
                page_size=page_size,
                timezone_name=timezone_name,
            )
        except Exception as exc:
            from deephoney.dashboard.components import render_error

            render_error(exc)
            rows, total = [], 0
        metric_row(
            [
                ("Dionaea sessions", total, None),
                (
                    "Protocols on page",
                    len({protocol for row in rows for protocol in (row.get("protocols") or [])}),
                    None,
                ),
                (
                    "High risk on page",
                    sum(1 for row in rows if row.get("risk_level") == "high"),
                    None,
                ),
            ]
        )
        if rows:
            show_dataframe(sessions_frame(rows), height=380)
            pagination_controls(total, page, page_size, "dionaea")
            st.subheader("Session inspector")
            index = st.selectbox(
                "Select a Dionaea session",
                options=list(range(len(rows))),
                format_func=lambda item: (
                    f"{rows[item].get('first_seen_display') or 'unknown'} · "
                    f"{rows[item].get('src_ip') or 'unknown source'} · "
                    f"{', '.join(str(p) for p in (rows[item].get('protocols') or [])) or 'unknown protocol'}"
                ),
                key="dionaea_selected",
            )
            render_session_detail(repository, rows[index], timezone_name=timezone_name)
        else:
            empty_state("No Dionaea sessions match the filters.")

    with tabs[1]:
        try:
            artifacts = repository.get_artifacts(
                engine="dionaea", limit=200, timezone_name=timezone_name
            )
        except Exception as exc:
            from deephoney.dashboard.components import render_error

            render_error(exc)
            artifacts = []
        st.caption(
            "Metadata only. DeepHoney never serves, executes, or links directly to captured binaries."
        )
        if artifacts:
            show_dataframe(_artifact_frame(artifacts))
            selected = st.selectbox(
                "Inspect artifact metadata",
                options=list(range(len(artifacts))),
                format_func=lambda item: str(artifacts[item].get("sha256")),
                key="dionaea_artifact_selected",
            )
            st.json(json.loads(json.dumps(artifacts[selected], ensure_ascii=False, default=str)))
        else:
            empty_state("No Dionaea artifact metadata has been recorded.")

    with tabs[2]:
        with st.expander("Event filters", expanded=True):
            start, end = date_range_filter("dionaea_events")
            try:
                event_type_options = repository.distinct_event_types()
            except Exception as exc:
                from deephoney.dashboard.components import render_error

                render_error(exc)
                event_type_options = []
            event_types = st.multiselect(
                "Event type",
                options=event_type_options,
                default=[],
                key="dionaea_event_types",
            )
        filters = EventFilters(
            start=start,
            end=end,
            engines=("dionaea",),
            event_types=tuple(event_types),
        )
        reset_page_on_filter_change(
            "dionaea_events", (filters.start, filters.end, filters.event_types)
        )
        page_size = page_size_selector("dionaea_events", default=25)
        page = current_page("dionaea_events")
        try:
            events, total = repository.query_events(
                filters,
                page=page,
                page_size=page_size,
                timezone_name=timezone_name,
            )
        except Exception as exc:
            from deephoney.dashboard.components import render_error

            render_error(exc)
            events, total = [], 0
        metric_row([("Matching events", total, None)])
        show_dataframe(events_frame(events), height=420)
        pagination_controls(total, page, page_size, "dionaea_events")
        if events:
            index = st.selectbox(
                "Inspect event detail",
                options=list(range(len(events))),
                format_func=lambda item: (
                    f"{events[item].get('timestamp_display') or 'unknown'} · "
                    f"{events[item].get('event_type')}"
                ),
                key="dionaea_event_selected",
            )
            st.json(events[index].get("details") or {})
            with st.expander("Raw source event (redacted)"):
                st.json(events[index].get("raw_payload") or {})

    with tabs[3]:
        try:
            _render_pcap(repository)
        except Exception as exc:
            from deephoney.dashboard.components import render_error

            render_error(exc)


__all__ = ["render"]
