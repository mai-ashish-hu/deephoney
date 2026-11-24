"""Cowrie analysis page."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from deephoney.config.settings import Settings
from deephoney.dashboard.components import (
    current_page,
    date_range_filter,
    empty_state,
    metric_row,
    page_header,
    page_size_selector,
    pagination_controls,
    render_session_detail,
    reset_page_on_filter_change,
    sessions_frame,
    show_dataframe,
)
from deephoney.storage.repository import Repository, SessionFilters


def render(repository: Repository, settings: Settings, *, timezone_name: str) -> None:
    page_header(
        "Cowrie Analysis",
        "SSH/Telnet sessions: authentication activity, command timelines, downloads, and risk evidence.",
    )
    with st.expander("Filters", expanded=True):
        start, end = date_range_filter("cowrie")
        first, second = st.columns(2)
        src_ip = first.text_input("Source IP (exact)", key="cowrie_src_ip")
        levels = second.multiselect(
            "Risk level",
            options=["high", "medium", "low"],
            default=[],
            key="cowrie_levels",
        )

    filters = SessionFilters(
        start=start,
        end=end,
        engines=("cowrie",),
        src_ip=src_ip.strip() or None,
        risk_levels=tuple(levels),
    )
    reset_page_on_filter_change(
        "cowrie", (filters.start, filters.end, filters.src_ip, filters.risk_levels)
    )
    page_size = page_size_selector("cowrie", default=25)
    page = current_page("cowrie")
    try:
        rows, total = repository.query_sessions(
            filters, page=page, page_size=page_size, timezone_name=timezone_name
        )
    except Exception as exc:
        from deephoney.dashboard.components import render_error

        render_error(exc)
        return

    metric_row(
        [
            ("Sessions", total, None),
            (
                "High risk on page",
                sum(1 for row in rows if row.get("risk_level") == "high"),
                None,
            ),
            (
                "Commands on page",
                sum(int(row.get("command_count") or 0) for row in rows),
                None,
            ),
            (
                "Downloads on page",
                sum(int(row.get("download_count") or 0) for row in rows),
                None,
            ),
        ]
    )
    if not rows:
        empty_state(
            "No Cowrie sessions match the filters.",
            "Cowrie session events require a source session identifier and ingested telemetry.",
        )
        return

    show_dataframe(sessions_frame(rows), height=380)
    pagination_controls(total, page, page_size, "cowrie")
    st.subheader("Session inspector")
    index = st.selectbox(
        "Select a Cowrie session",
        options=list(range(len(rows))),
        format_func=lambda item: (
            f"{rows[item].get('first_seen_display') or 'unknown'} · "
            f"{rows[item].get('src_ip') or 'unknown source'} · "
            f"risk {rows[item].get('risk_score') if rows[item].get('risk_score') is not None else '-'}"
        ),
        key="cowrie_selected",
    )
    render_session_detail(repository, rows[index], timezone_name=timezone_name)

    st.subheader("Authentication overview")
    try:
        auth_rows = []
        for row in rows:
            auth_rows.append(
                {
                    "First seen (UTC)": row.get("first_seen_display") or "unknown",
                    "Source IP": row.get("src_ip"),
                    "Failures": row.get("auth_failures"),
                    "Successes": row.get("auth_successes"),
                    "Distinct usernames": (row.get("metadata") or {}).get("distinct_usernames"),
                    "Distinct password hashes": (row.get("metadata") or {}).get(
                        "distinct_password_hashes"
                    ),
                }
            )
        show_dataframe(pd.DataFrame(auth_rows))
    except Exception as exc:
        st.warning("Authentication summary could not be rendered.")
        st.code(type(exc).__name__)
    st.caption(
        "Passwords are never displayed. Distinct password counts are derived from one-way "
        "SHA-256 hashes of captured credentials for behavioural comparison only."
    )


__all__ = ["render"]
