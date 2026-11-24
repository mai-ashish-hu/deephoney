"""Dashboard data access and health helpers.

All unbounded or expensive reads are wrapped by the repository's paginated
queries.  The dashboard never imports vendor-specific honeypot code and never
reads files from the honeypot containers; it only reads normalized records and
selected read-only health state.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any

import streamlit as st

from deephoney.config.settings import Settings, get_settings
from deephoney.storage.database import Database
from deephoney.storage.repository import Repository
from deephoney.utils.net import tcp_probe
from deephoney.utils.redaction import sanitize_text


@dataclass(frozen=True, slots=True)
class DashboardContext:
    settings: Settings
    repository: Repository


@st.cache_resource(show_spinner=False)
def get_context() -> DashboardContext:
    settings = get_settings()
    database = Database(
        settings.database.url,
        echo=settings.database.echo,
        pool_size=settings.database.pool_size,
        pool_max_overflow=settings.database.pool_max_overflow,
    )
    return DashboardContext(settings=settings, repository=Repository(database))


def database_online(context: DashboardContext) -> bool:
    return context.repository.database.ping()


def day_bounds(start: date, end: date) -> tuple[datetime, datetime]:
    """Convert inclusive calendar dates to an inclusive UTC instant range."""

    if end < start:
        start, end = end, start
    return (
        datetime.combine(start, time.min, tzinfo=UTC),
        datetime.combine(end, time.max, tzinfo=UTC),
    )


def default_start_date(days: int = 30) -> date:
    return (datetime.now(UTC) - timedelta(days=days)).date()


def relative_time(value: datetime | None, *, now: datetime | None = None) -> str:
    if value is None:
        return "never"
    reference = now or datetime.now(UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    seconds = int((reference - value).total_seconds())
    if seconds < 0:
        return value.strftime("%Y-%m-%d %H:%M UTC")
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _registry_path(model_dir: Path) -> Path:
    return model_dir / "registry.json"


def model_registry_summary(settings: Settings) -> list[dict[str, Any]]:
    """Read model registry/metadata without importing heavy ML libraries."""

    registry_path = _registry_path(settings.model_dir)
    if not registry_path.is_file():
        return []
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(registry, dict):
        return []
    rows: list[dict[str, Any]] = []
    for key, entry in registry.items():
        if not isinstance(entry, dict):
            continue
        metadata_path = entry.get("metadata_path")
        metadata: dict[str, Any] = {}
        if isinstance(metadata_path, str):
            path = Path(metadata_path)
            if not path.is_absolute():
                path = settings.model_dir / path
            if path.is_file():
                try:
                    parsed = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(parsed, dict):
                        metadata = parsed
                except (OSError, json.JSONDecodeError):
                    metadata = {}
        dataset = metadata.get("dataset")
        synthetic = dataset.get("synthetic") if isinstance(dataset, dict) else None
        rows.append(
            {
                "slot": key,
                "model_version": entry.get("model_version") or metadata.get("model_version"),
                "model_type": metadata.get("model_type", "unknown"),
                "updated_at": entry.get("updated_at"),
                "feature_version": metadata.get("feature_version"),
                "metrics": metadata.get("metrics", {}),
                "synthetic_dataset": synthetic,
                "disclaimer": metadata.get("disclaimer"),
            }
        )
    return rows


def honeypot_health() -> list[dict[str, Any]]:
    """Probe the local/isolated honeypot endpoints for a status page.

    This is a TCP connect only.  It does not send credentials, commands,
    payloads, or exploit traffic.  Hostnames resolve only inside the Compose
    network in the default deployment.
    """

    targets = [
        {
            "name": "Cowrie SSH",
            "host": os.getenv("DEEPHONEY_COWRIE_HOST", "127.0.0.1"),
            "port": int(os.getenv("DEEPHONEY_COWRIE_SSH_PORT", "2222")),
        },
        {
            "name": "Cowrie Telnet",
            "host": os.getenv("DEEPHONEY_COWRIE_HOST", "127.0.0.1"),
            "port": int(os.getenv("DEEPHONEY_COWRIE_TELNET_PORT", "2223")),
        },
        {
            "name": "Dionaea FTP",
            "host": os.getenv("DEEPHONEY_DIONAEA_HOST", "127.0.0.1"),
            "port": int(os.getenv("DEEPHONEY_DIONAEA_FTP_PORT", "2121")),
        },
        {
            "name": "Dionaea HTTP",
            "host": os.getenv("DEEPHONEY_DIONAEA_HOST", "127.0.0.1"),
            "port": int(os.getenv("DEEPHONEY_DIONAEA_HTTP_PORT", "8080")),
        },
    ]
    results: list[dict[str, Any]] = []
    for target in targets:
        probe = tcp_probe(target["host"], target["port"], timeout=1.5)
        results.append(
            {
                "service": target["name"],
                "endpoint": f"{target['host']}:{target['port']}",
                "open": probe.open,
                "latency_ms": probe.latency_ms,
                "error": sanitize_text(probe.error, max_length=180) if probe.error else None,
            }
        )
    return results


def bounded_text(value: Any, max_length: int = 300) -> str:
    return sanitize_text(value, max_length=max_length)


__all__ = [
    "DashboardContext",
    "bounded_text",
    "database_online",
    "day_bounds",
    "default_start_date",
    "get_context",
    "honeypot_health",
    "model_registry_summary",
    "relative_time",
]
