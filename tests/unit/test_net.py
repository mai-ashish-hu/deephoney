"""Unit tests for network helpers and live-target safety."""

from __future__ import annotations

import pytest

from deephoney.utils.net import (
    is_loopback_host,
    is_private_lab_host,
    is_valid_ip,
    normalize_ip,
    protocol_from_port,
    protocol_from_text,
    safe_port,
    validate_live_target,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (" 203.0.113.7 ", "203.0.113.7"),
        ("2001:0db8::1", "2001:db8::1"),
        ("not-an-ip", None),
        ("", None),
        (None, None),
        (123, None),
    ],
)
def test_normalize_ip(value: object, expected: str | None) -> None:
    assert normalize_ip(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, 0), (22, 22), ("443", 443), (-1, None), (70000, None), (True, None), ("x", None)],
)
def test_safe_port(value: object, expected: int | None) -> None:
    assert safe_port(value) == expected


def test_protocol_helpers() -> None:
    assert protocol_from_port(22) == "ssh"
    assert protocol_from_port(9999) is None
    assert protocol_from_port(None, default="tcp") == "tcp"
    assert protocol_from_text("dionaea.modules.python.ftp.login") == "ftp"
    assert protocol_from_text("unknown") is None


def test_ip_classification_helpers() -> None:
    assert is_valid_ip("127.0.0.1")
    assert not is_valid_ip("localhost")
    assert is_loopback_host("localhost")
    assert is_loopback_host("::1")
    assert not is_loopback_host("192.0.2.10")
    assert is_private_lab_host("192.168.1.10")
    assert is_private_lab_host("127.0.0.1")
    assert not is_private_lab_host("8.8.8.8")


def test_live_target_allows_loopback_and_rejects_public() -> None:
    assert validate_live_target("localhost") == "127.0.0.1"
    assert validate_live_target("127.0.0.1") == "127.0.0.1"
    with pytest.raises(ValueError, match="Refusing"):
        validate_live_target("8.8.8.8")
    with pytest.raises(ValueError, match="Refusing"):
        validate_live_target("192.168.1.10")


def test_live_target_requires_opt_in_for_private_lab() -> None:
    assert validate_live_target("192.168.1.10", allow_private_lab=True) == "192.168.1.10"
    assert validate_live_target("169.254.1.5", allow_private_lab=True) == "169.254.1.5"
    with pytest.raises(ValueError, match="IP literal"):
        validate_live_target("honeypot.internal", allow_private_lab=True)
