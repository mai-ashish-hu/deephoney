"""Redaction, display sanitisation, and safe export helpers.

Attacker-controlled values must be treated as untrusted strings.  The
dashboard never injects them as HTML, exports neutralise spreadsheet
formulas, and captured passwords are hidden unless a future, explicitly
authorised analyst view is added.
"""

from __future__ import annotations

import html
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"(^|[._-])("
    r"pass(word|wd|phrase)?|"
    r"secret|"
    r"token|"
    r"authorization|"
    r"cookie|"
    r"set-cookie|"
    r"private[_-]?key|"
    r"api[_-]?key|"
    r"access[_-]?key|"
    r"credential(s)?"
    r")($|[._-])",
    re.IGNORECASE,
)

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_LOGIN_ATTEMPT = re.compile(r"(?i)(login attempt\s*\[[^/\]]+/)([^\]]+)(\])")
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|passphrase)\b(\s*[=:]\s*)([^\s,;\"'}]+)"
)
_JSON_CREDENTIAL = re.compile(
    r'(?i)("(?:password|passwd|passphrase|secret|token|api[_-]?key|authorization|cookie)"'
    r"\s*:\s*)\"[^\"]*\""
)


def redact_embedded_secrets(value: str) -> str:
    """Mask credential values embedded in an untrusted free-text string."""

    redacted = _LOGIN_ATTEMPT.sub(rf"\1{REDACTED}\3", value)
    redacted = _CREDENTIAL_ASSIGNMENT.sub(rf"\1\2{REDACTED}", redacted)
    return _JSON_CREDENTIAL.sub(rf'\1"{REDACTED}"', redacted)


def is_sensitive_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    normalised = key.strip().replace(" ", "_")
    return bool(_SENSITIVE_KEY.search(normalised))


def redact_mapping(value: Any, *, max_depth: int = 12, _depth: int = 0) -> Any:
    """Return a deep copy with sensitive values replaced.

    ``raw_event`` JSON can be nested and attacker-controlled.  The function
    has a depth limit so a malicious payload cannot cause unbounded work.
    """

    if _depth >= max_depth:
        return "[MAX_DEPTH]"
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED
            if is_sensitive_key(key)
            else redact_mapping(item, max_depth=max_depth, _depth=_depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact_mapping(item, max_depth=max_depth, _depth=_depth + 1) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, str):
        return redact_embedded_secrets(value)
    return value


def redact_raw_event(raw_event: Any) -> Any:
    """Redact credentials and secrets from a stored raw source event."""

    return redact_mapping(raw_event)


def strip_control_characters(value: str) -> str:
    return _CONTROL_CHARS.sub("", value)


def sanitize_text(value: Any, *, max_length: int = 8192) -> str:
    """Normalise an untrusted value for safe plain-text display/storage."""

    if value is None:
        return ""
    text = strip_control_characters(str(value))
    if len(text) > max_length:
        return text[: max(0, max_length - 3)] + "..."
    return text


def escape_html(value: Any, *, max_length: int = 8192) -> str:
    """Escape an untrusted value before optional HTML embedding."""

    return html.escape(sanitize_text(value, max_length=max_length), quote=True)


def safe_json_value(value: Any, *, max_depth: int = 12, _depth: int = 0) -> Any:
    """Return a JSON-serialisable, control-character-free copy."""

    if _depth >= max_depth:
        return "[MAX_DEPTH]"
    if isinstance(value, Mapping):
        return {
            sanitize_text(key, max_length=256): safe_json_value(
                item, max_depth=max_depth, _depth=_depth + 1
            )
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [safe_json_value(item, max_depth=max_depth, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    return value


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection while preserving text.

    Leading whitespace is ignored by several spreadsheet applications when
    deciding whether a cell is a formula, so it must not hide a formula prefix.
    """

    text = sanitize_text(value, max_length=32767)
    candidate = text.lstrip(" \t\r\n")
    if text[:1] in {"\t", "\r", "\n"} or candidate[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


def csv_row(values: Sequence[Any]) -> list[str]:
    return [csv_safe(value) for value in values]


def format_bytes(size: int | float | None) -> str:
    """Format a byte count for dashboards; never raises on bad input."""

    try:
        number = float(size)
    except (TypeError, ValueError):
        return "unknown"
    if number < 0:
        return "unknown"
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    if index == 0:
        return f"{int(number)} {units[index]}"
    return f"{number:.1f} {units[index]}"


__all__ = [
    "REDACTED",
    "csv_row",
    "csv_safe",
    "escape_html",
    "format_bytes",
    "is_sensitive_key",
    "redact_embedded_secrets",
    "redact_mapping",
    "redact_raw_event",
    "safe_json_value",
    "sanitize_text",
    "strip_control_characters",
]
