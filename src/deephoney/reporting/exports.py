"""Safe CSV/JSON exports for analyst reports.

Every cell passes through :func:`deephoney.utils.redaction.csv_safe`, which
neutralises spreadsheet formula injection and strips control characters.
Raw attacker-controlled text is never interpreted as a formula.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deephoney.utils.redaction import csv_safe, safe_json_value


def _flatten_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict | list | tuple):
        return json.dumps(safe_json_value(value), ensure_ascii=False, sort_keys=True)
    return csv_safe(value)


def _columns(rows: Sequence[Mapping[str, Any]], columns: Iterable[str] | None) -> list[str]:
    if columns is not None:
        return list(columns)
    ordered: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                ordered.append(str(key))
    return ordered


def rows_to_csv(
    rows: Sequence[Mapping[str, Any]],
    *,
    columns: Iterable[str] | None = None,
) -> str:
    """Serialize rows to CSV text with formula-injection protection."""

    fieldnames = _columns(rows, columns)
    buffer = io.StringIO()
    if not fieldnames:
        return ""
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _flatten_value(row.get(key)) for key in fieldnames})
    return buffer.getvalue()


def rows_to_json(rows: Sequence[Mapping[str, Any]], *, indent: int = 2) -> str:
    """Serialize rows to sanitized, pretty-printed JSON."""

    return json.dumps(
        [safe_json_value(dict(row)) for row in rows],
        ensure_ascii=False,
        indent=indent,
        sort_keys=True,
    )


def export_payload(
    rows: Sequence[Mapping[str, Any]],
    fmt: str,
    *,
    columns: Iterable[str] | None = None,
) -> tuple[bytes, str]:
    """Return ``(content, media_type)`` for a CSV or JSON export."""

    normalised = fmt.strip().lower()
    if normalised == "csv":
        return rows_to_csv(rows, columns=columns).encode("utf-8"), "text/csv; charset=utf-8"
    if normalised == "json":
        text = rows_to_json(rows) + "\n"
        return text.encode("utf-8"), "application/json; charset=utf-8"
    raise ValueError("Export format must be 'csv' or 'json'")


def write_export(
    rows: Sequence[Mapping[str, Any]],
    path: str | Path,
    fmt: str,
    *,
    columns: Iterable[str] | None = None,
) -> Path:
    """Write an export to disk and return the resolved path."""

    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    content, _media_type = export_payload(rows, fmt, columns=columns)
    target.write_bytes(content)
    return target


def export_filename(prefix: str, fmt: str, *, now: datetime | None = None) -> str:
    """Return a filesystem-safe, UTC-stamped export filename."""

    safe_prefix = (
        "".join(character for character in prefix if character.isalnum() or character in {"-", "_"})
        or "deephoney"
    )
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    extension = "csv" if fmt.strip().lower() == "csv" else "json"
    return f"{safe_prefix}-{stamp}.{extension}"


__all__ = [
    "export_filename",
    "export_payload",
    "rows_to_csv",
    "rows_to_json",
    "write_export",
]
