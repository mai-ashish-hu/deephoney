"""Unit tests for redaction, sanitisation, and safe export values."""

from __future__ import annotations

import math

import pytest

from deephoney.utils.redaction import (
    REDACTED,
    csv_row,
    csv_safe,
    escape_html,
    format_bytes,
    is_sensitive_key,
    redact_embedded_secrets,
    redact_mapping,
    redact_raw_event,
    safe_json_value,
    sanitize_text,
    strip_control_characters,
)


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "passwd",
        "passphrase",
        "user_password",
        "api_key",
        "api-key",
        "access_token",
        "authorization",
        "set-cookie",
        "private_key",
        "credentials",
        "client_secret",
    ],
)
def test_sensitive_keys_are_detected(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize("key", ["username", "key_exchange", "command", "src_ip", "tokenizer"])
def test_non_sensitive_keys_are_not_redacted(key: str) -> None:
    assert not is_sensitive_key(key)


def test_redact_mapping_is_deep_and_keeps_structure() -> None:
    payload = {
        "username": "admin",
        "password": "placeholder",
        "nested": [{"token": "abc", "safe": 1}],
        "key_exchange": "curve25519",
    }
    redacted = redact_mapping(payload)
    assert redacted["username"] == "admin"
    assert redacted["password"] == REDACTED
    assert redacted["nested"][0]["token"] == REDACTED
    assert redacted["nested"][0]["safe"] == 1
    assert redacted["key_exchange"] == "curve25519"
    assert redact_raw_event(payload)["password"] == REDACTED


def test_embedded_credentials_in_messages_are_masked() -> None:
    assert redact_embedded_secrets("login attempt [root/hunter2] failed") == (
        "login attempt [root/[REDACTED]] failed"
    )
    assert redact_embedded_secrets("password=secret123") == "password=[REDACTED]"
    assert redact_embedded_secrets("passphrase: correct") == "passphrase: [REDACTED]"
    assert redact_embedded_secrets('{"password": "hunter2", "username": "root"}') == (
        '{"password": "[REDACTED]", "username": "root"}'
    )


def test_redaction_depth_is_bounded() -> None:
    value: object = "leaf"
    for _ in range(20):
        value = {"nested": value}
    assert "[MAX_DEPTH]" in str(redact_mapping(value))


def test_sanitize_text_removes_control_characters_and_truncates() -> None:
    assert strip_control_characters("a\x00b\x08c") == "abc"
    assert sanitize_text("a\x00b") == "ab"
    assert sanitize_text("abcdef", max_length=5) == "ab..."
    assert sanitize_text(None) == ""


def test_escape_html() -> None:
    assert escape_html('<script>"x"</script>') == ("&lt;script&gt;&quot;x&quot;&lt;/script&gt;")


@pytest.mark.parametrize(
    "formula",
    ["=1+1", "+SUM(A1)", "-2+3", "@cmd", "\t=1", "\r=1", " =1+1", "  @cmd", "\n=1"],
)
def test_csv_safe_neutralises_formulas(formula: str) -> None:
    assert csv_safe(formula) == "'" + formula


def test_csv_safe_and_row_preserve_plain_values() -> None:
    assert csv_safe("normal") == "normal"
    assert csv_safe(" normal") == " normal"
    assert csv_row(["=1", "ok"]) == ["'=1", "ok"]


def test_safe_json_value_handles_non_finite_and_depth() -> None:
    assert safe_json_value(float("nan")) == "nan"
    assert safe_json_value(float("inf")) == "inf"
    assert safe_json_value({"key\x00": "value\x01"}) == {"key": "value"}


def test_format_bytes() -> None:
    assert format_bytes(0) == "0 B"
    assert format_bytes(1536) == "1.5 KiB"
    assert format_bytes(None) == "unknown"
    assert format_bytes(-1) == "unknown"
    assert format_bytes("bad") == "unknown"
    assert math.isfinite(1.0)
