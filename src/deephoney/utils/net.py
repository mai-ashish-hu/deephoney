"""Network helpers used by parsers, health checks, and the safe simulator."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

SERVICE_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    42: "wins",
    53: "dns",
    69: "tftp",
    80: "http",
    135: "msrpc",
    139: "netbios",
    443: "https",
    445: "smb",
    1433: "mssql",
    1723: "pptp",
    1883: "mqtt",
    1900: "upnp",
    3306: "mysql",
    5060: "sip",
    5061: "sips",
    11211: "memcache",
}

SERVICE_HINTS: dict[str, str] = {
    "http": "http",
    "https": "https",
    "smb": "smb",
    "ftp": "ftp",
    "tftp": "tftp",
    "mysql": "mysql",
    "mssql": "mssql",
    "sip": "sip",
    "mqtt": "mqtt",
    "memcache": "memcache",
    "upnp": "upnp",
    "pptp": "pptp",
    "printer": "printer",
}


def protocol_from_port(port: int | None, default: str | None = None) -> str | None:
    if port is None:
        return default
    return SERVICE_PORTS.get(port, default)


def protocol_from_text(text: str) -> str | None:
    lowered = text.lower()
    for hint, name in SERVICE_HINTS.items():
        if hint in lowered:
            return name
    return None


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_ip(value: object) -> str | None:
    """Return a canonical IP string or ``None``.

    Hostnames are not resolved here: logs are expected to contain addresses,
    and avoiding DNS keeps ingestion deterministic and offline.
    """

    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def safe_port(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        port = int(str(value), 10)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def is_loopback_host(host: str) -> bool:
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_private_lab_host(host: str) -> bool:
    if is_loopback_host(host):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_link_local


def validate_live_target(host: str, *, allow_private_lab: bool = False) -> str:
    """Validate a target for the *safe* attack emulator.

    Only loopback is allowed by default.  A private lab address requires an
    explicit opt-in, and public addresses are always refused.  DNS names are
    not accepted, preventing accidental external targeting through a typo or
    a poisoned resolver.
    """

    text = host.strip()
    if text.lower() == "localhost":
        text = "127.0.0.1"
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(
            "Live simulation target must be an IP literal or localhost; "
            "hostnames are refused to prevent accidental external targeting."
        ) from exc
    if address.is_loopback:
        return str(address)
    if allow_private_lab and (address.is_private or address.is_link_local):
        return str(address)
    raise ValueError(
        f"Refusing live simulation target {address}. Use loopback, or explicitly "
        "allow a private lab address; public targets are never permitted."
    )


@dataclass(frozen=True, slots=True)
class ProbeResult:
    host: str
    port: int
    open: bool
    latency_ms: float | None
    error: str | None = None


def tcp_probe(host: str, port: int, timeout: float = 2.0) -> ProbeResult:
    """Perform a non-intrusive TCP connect check for health reporting."""

    import time

    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.monotonic() - started) * 1000.0
            return ProbeResult(host=host, port=port, open=True, latency_ms=round(elapsed, 1))
    except OSError as exc:
        return ProbeResult(
            host=host,
            port=port,
            open=False,
            latency_ms=None,
            error=str(exc)[:200],
        )


__all__ = [
    "SERVICE_PORTS",
    "ProbeResult",
    "is_loopback_host",
    "is_private_lab_host",
    "is_valid_ip",
    "normalize_ip",
    "protocol_from_port",
    "protocol_from_text",
    "safe_port",
    "tcp_probe",
    "validate_live_target",
]
