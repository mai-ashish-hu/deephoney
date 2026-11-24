"""System status page: health, ingestion freshness, failures, and models."""

from __future__ import annotations

from datetime import UTC, datetime

import pandas as pd
import streamlit as st

from deephoney.config.settings import Settings
from deephoney.dashboard.components import (
    empty_state,
    metric_row,
    page_header,
    render_error,
    show_dataframe,
    show_json,
)
from deephoney.dashboard.data import honeypot_health, model_registry_summary, relative_time
from deephoney.storage.repository import Repository
from deephoney.utils.redaction import sanitize_text


def _render_services() -> None:
    st.subheader("Honeypot service health")
    st.caption(
        "These are TCP connection probes from the dashboard host. They do not send "
        "credentials, commands, or payloads. A closed port in Docker may mean the lab "
        "is not running locally, not that the honeypot is misconfigured."
    )
    try:
        rows = honeypot_health()
    except Exception as exc:
        st.warning("Service probes could not be completed.")
        st.code(type(exc).__name__)
        return
    frame = pd.DataFrame(
        [
            {
                "Service": row["service"],
                "Endpoint": row["endpoint"],
                "Open": row["open"],
                "Latency (ms)": row["latency_ms"],
                "Error": row["error"] or "",
            }
            for row in rows
        ]
    )
    show_dataframe(frame)


def _render_ingestion(repository: Repository) -> None:
    st.subheader("Ingestion freshness")
    try:
        runs = repository.get_ingestion_runs(limit=25)
        last_by_engine = repository.last_ingestion_by_engine()
    except Exception as exc:
        render_error(exc)
        return

    last_rows = []
    now = datetime.now(UTC)
    for engine in ("cowrie", "dionaea"):
        last = last_by_engine.get(engine)
        last_rows.append(
            {
                "Engine": engine,
                "Last started": last.get("started_at_display") if last else "never",
                "Ago": (
                    relative_time(datetime.fromisoformat(last["started_at"]), now=now)
                    if last and last.get("started_at")
                    else "never"
                ),
                "Status": last.get("status") if last else "no runs",
                "Created": last.get("records_created") if last else None,
                "Failed": last.get("records_failed") if last else None,
            }
        )
    metric_row(
        [
            (
                "Ingestion runs recorded",
                len(runs),
                "Most recent runs, bounded to 25 in this view",
            ),
            (
                "Cowrie last run",
                last_rows[0]["Ago"],
                "Relative to the dashboard clock (UTC)",
            ),
            (
                "Dionaea last run",
                last_rows[1]["Ago"],
                "Relative to the dashboard clock (UTC)",
            ),
        ]
    )
    show_dataframe(pd.DataFrame(last_rows))

    if runs:
        st.markdown("**Recent ingestion runs**")
        show_dataframe(
            pd.DataFrame(
                [
                    {
                        "Started (UTC)": row.get("started_at_display"),
                        "Engine": row.get("source_engine"),
                        "File": sanitize_text(row.get("source_file"), max_length=120),
                        "Read": row.get("records_read"),
                        "Created": row.get("records_created"),
                        "Skipped": row.get("records_skipped"),
                        "Failed": row.get("records_failed"),
                        "Status": row.get("status"),
                    }
                    for row in runs
                ]
            )
        )
        with st.expander("Run error summaries"):
            for row in runs:
                if row.get("error_summary"):
                    st.text(
                        f"{row.get('run_id')} [{row.get('source_engine')}]: "
                        f"{sanitize_text(row['error_summary'], max_length=1000)}"
                    )
    else:
        empty_state(
            "No ingestion runs have been recorded.",
            "Import a sanitized sample with `python scripts/import_logs.py --sample`.",
        )


def _render_failures(repository: Repository) -> None:
    st.subheader("Parser failures")
    try:
        failures = repository.get_parser_failures(limit=50)
    except Exception as exc:
        render_error(exc)
        return
    if not failures:
        st.success("No parser failures are recorded in the current retention window.")
        return
    show_dataframe(
        pd.DataFrame(
            [
                {
                    "Created (UTC)": row.get("created_at_display"),
                    "Engine": row.get("source_engine"),
                    "File": sanitize_text(row.get("source_file"), max_length=100),
                    "Line": row.get("line_number"),
                    "Error": sanitize_text(row.get("error"), max_length=220),
                }
                for row in failures
            ]
        )
    )
    index = st.selectbox(
        "Inspect a failure",
        options=list(range(len(failures))),
        format_func=lambda item: (
            f"{failures[item].get('created_at_display')} · "
            f"{failures[item].get('source_engine')} · line {failures[item].get('line_number')}"
        ),
        key="status_failure_selected",
    )
    show_json(
        "Bounded raw excerpt",
        {"error": failures[index].get("error"), "excerpt": failures[index].get("raw_excerpt")},
        expanded=True,
    )


def _render_models(settings: Settings) -> None:
    st.subheader("Model availability")
    st.caption(
        "The rules pipeline is the supported baseline. A model is optional and is "
        "only shown when a registry entry exists in the configured model directory."
    )
    try:
        registry = model_registry_summary(settings)
    except Exception as exc:
        st.warning("The model registry could not be read.")
        st.code(type(exc).__name__)
        return
    if not registry:
        empty_state(
            "No model is registered.",
            "Rules and transparent risk scores remain fully functional without a model.",
        )
        return
    show_dataframe(
        pd.DataFrame(
            [
                {
                    "Slot": entry.get("slot"),
                    "Model version": entry.get("model_version"),
                    "Type": entry.get("model_type"),
                    "Feature version": entry.get("feature_version"),
                    "Updated": entry.get("updated_at"),
                    "Synthetic data": entry.get("synthetic_dataset"),
                }
                for entry in registry
            ]
        )
    )
    st.json(registry)


def render(repository: Repository, settings: Settings, *, timezone_name: str) -> None:
    page_header(
        "System Status",
        "Database connectivity, honeypot reachability, ingestion freshness, parser failures, and models.",
    )
    st.caption(f"Dashboard display timezone: {timezone_name}. Storage is always UTC.")
    try:
        online = repository.database.ping()
    except Exception:
        online = False
    metric_row(
        [
            ("Database", "online" if online else "offline", "A lightweight SELECT 1 probe"),
            ("Environment", settings.app.environment, "From configs/app.yaml or DEEPHONEY_ENV"),
            ("Rules version", settings.detection.rules_version, "Stage A rule contract"),
            (
                "ML enabled",
                "yes" if settings.detection.ml_enabled else "no",
                "Classical model stage toggle",
            ),
        ]
    )
    if not online:
        st.error(
            "The database is not reachable. Start PostgreSQL, apply migrations, and "
            "check DATABASE_URL. The dashboard does not display connection strings."
        )
        return
    _render_services()
    _render_ingestion(repository)
    _render_failures(repository)
    _render_models(settings)


__all__ = ["render"]
