"""Unit tests for safe CSV/JSON exports."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

import pytest

from deephoney.reporting.exports import (
    export_filename,
    export_payload,
    rows_to_csv,
    rows_to_json,
    write_export,
)


def test_csv_export_neutralises_formulas_and_controls() -> None:
    rows = [
        {"command": '=HYPERLINK("http://evil")', "username": "@attacker"},
        {"command": "ok", "username": "normal\x00user"},
    ]
    text = rows_to_csv(rows)
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert parsed[0]["command"].startswith("'=")
    assert parsed[0]["username"].startswith("'@")
    assert parsed[1]["username"] == "normaluser"


def test_csv_columns_can_be_selected() -> None:
    text = rows_to_csv([{"a": 1, "b": 2}], columns=["b"])
    assert text.splitlines()[0] == "b"
    assert "a" not in text


def test_json_export_is_sanitised() -> None:
    rows = [{"command": "a\x00b", "nested": {"value": "x\x01"}}]
    data = json.loads(rows_to_json(rows))
    assert data == [{"command": "ab", "nested": {"value": "x"}}]


def test_export_payload_formats() -> None:
    content, media = export_payload([{"a": 1}], "csv")
    assert media.startswith("text/csv")
    assert content.startswith(b"a")
    content, media = export_payload([{"a": 1}], "json")
    assert media.startswith("application/json")
    assert json.loads(content) == [{"a": 1}]
    with pytest.raises(ValueError):
        export_payload([], "xml")


def test_export_filename_is_safe_and_stamped() -> None:
    name = export_filename("../../evil name", "csv", now=datetime(2024, 8, 31, tzinfo=UTC))
    assert name == "evilname-20240831T000000Z.csv"
    assert export_filename("", "json").startswith("deephoney-")


def test_write_export_creates_parent_directories(tmp_path) -> None:
    target = tmp_path / "nested" / "report.csv"
    result = write_export([{"=cmd": "=1"}], target, "csv")
    assert result == target.resolve()
    assert "'=" in target.read_text(encoding="utf-8")
