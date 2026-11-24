"""Metadata-only PCAP flow extraction.

DeepHoney never executes or stores packet payloads from an imported capture.
Only addresses, ports, transport metadata, timestamps, packet counts and byte
counts are persisted.  Parsing is bounded by file size, packet count and
capture duration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deephoney.config.logging import get_logger
from deephoney.config.settings import Settings
from deephoney.storage.repository import Repository
from deephoney.utils.hashing import file_sha256
from deephoney.utils.net import protocol_from_port, safe_port

logger = get_logger(__name__)

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "pcap-little",
    b"\xa1\xb2\xc3\xd4": "pcap-big",
    b"\x4d\x3c\xb2\xa1": "pcap-ns-little",
    b"\xa1\xb2\x3c\x4d": "pcap-ns-big",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}
SUPPORTED_SUFFIXES = {".pcap", ".pcapng"}


class PcapImportError(ValueError):
    """Raised when a capture is unsupported, malformed, or too large."""


@dataclass(slots=True)
class FlowAggregate:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    service: str | None = None

    def add(self, *, timestamp: datetime, length: int) -> None:
        self.packet_count += 1
        self.byte_count += max(0, int(length))
        if self.first_seen_at is None or timestamp < self.first_seen_at:
            self.first_seen_at = timestamp
        if self.last_seen_at is None or timestamp > self.last_seen_at:
            self.last_seen_at = timestamp

    def as_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "metadata": {
                "dst_port_service": self.service,
                "payload_retained": False,
                "source": "pcap_flow_metadata_only",
            },
        }


@dataclass(slots=True)
class PcapParseResult:
    flows: list[dict[str, Any]]
    packet_count: int
    truncated: bool
    started_at: datetime | None
    ended_at: datetime | None
    metadata: dict[str, Any] = field(default_factory=dict)


def validate_capture(path: str | Path, *, max_file_bytes: int) -> tuple[Path, str]:
    """Validate a capture file's size, suffix, and magic bytes."""

    file_path = Path(path)
    if not file_path.is_file():
        raise PcapImportError(f"Capture not found: {file_path}")
    suffix = file_path.suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        raise PcapImportError("Only .pcap and .pcapng captures are accepted")
    size = file_path.stat().st_size
    if size <= 0:
        raise PcapImportError("Capture file is empty")
    if size > max_file_bytes:
        raise PcapImportError(
            f"Capture is {size} bytes, exceeding the configured limit of {max_file_bytes} bytes"
        )
    with file_path.open("rb") as handle:
        header = handle.read(4)
    format_name = _PCAP_MAGICS.get(header)
    if format_name is None:
        raise PcapImportError("Unsupported or malformed capture header")
    return file_path, format_name


def parse_capture(path: str | Path, settings: Settings) -> PcapParseResult:
    """Parse a bounded PCAP into flow metadata."""

    file_path, format_name = validate_capture(path, max_file_bytes=settings.pcap.max_file_bytes)
    try:
        from scapy.all import IP, TCP, UDP, IPv6, PcapReader
    except ImportError as exc:
        raise PcapImportError("Scapy is not installed; PCAP import is unavailable") from exc

    flows: dict[tuple[Any, ...], FlowAggregate] = {}
    packet_count = 0
    skipped = 0
    truncated = False
    started_at: datetime | None = None
    ended_at: datetime | None = None
    first_epoch: float | None = None

    try:
        with PcapReader(str(file_path)) as reader:
            for packet in reader:
                if packet_count >= settings.pcap.max_packets:
                    truncated = True
                    break
                packet_count += 1
                timestamp_epoch = float(getattr(packet, "time", 0.0) or 0.0)
                timestamp = datetime.fromtimestamp(timestamp_epoch, tz=UTC)
                if first_epoch is None:
                    first_epoch = timestamp_epoch
                if timestamp_epoch - first_epoch > settings.pcap.max_seconds:
                    truncated = True
                    break

                ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
                if ip_layer is None:
                    skipped += 1
                    continue
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                src_port: int | None = None
                dst_port: int | None = None
                protocol = "ip"
                if packet.haslayer(TCP):
                    protocol = "tcp"
                    src_port = safe_port(packet[TCP].sport)
                    dst_port = safe_port(packet[TCP].dport)
                elif packet.haslayer(UDP):
                    protocol = "udp"
                    src_port = safe_port(packet[UDP].sport)
                    dst_port = safe_port(packet[UDP].dport)
                elif str(getattr(ip_layer, "proto", "")) == "1":
                    protocol = "icmp"

                key = (src_ip, dst_ip, src_port, dst_port, protocol)
                flow = flows.get(key)
                if flow is None:
                    flow = FlowAggregate(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        service=protocol_from_port(dst_port),
                    )
                    flows[key] = flow
                flow.add(timestamp=timestamp, length=len(packet))
                started_at = timestamp if started_at is None else min(started_at, timestamp)
                ended_at = timestamp if ended_at is None else max(ended_at, timestamp)
    except PcapImportError:
        raise
    except Exception as exc:
        raise PcapImportError(
            f"Malformed or unreadable capture: {type(exc).__name__}: {exc}"
        ) from exc

    if packet_count == 0:
        raise PcapImportError("Capture contains no readable packets")

    flow_rows = [
        flow.as_dict()
        for flow in sorted(
            flows.values(),
            key=lambda item: (item.first_seen_at or datetime.min.replace(tzinfo=UTC), item.src_ip),
        )
    ]
    metadata = {
        "format": format_name,
        "payload_retained": False,
        "analyser": "scapy-flow-metadata",
        "scapy_version": _scapy_version(),
        "packet_limit": settings.pcap.max_packets,
        "seconds_limit": settings.pcap.max_seconds,
        "skipped_non_ip_packets": skipped,
        "flow_count": len(flow_rows),
    }
    return PcapParseResult(
        flows=flow_rows,
        packet_count=packet_count,
        truncated=truncated,
        started_at=started_at,
        ended_at=ended_at,
        metadata=metadata,
    )


def import_pcap_file(
    repository: Repository,
    path: str | Path,
    settings: Settings,
) -> dict[str, Any]:
    """Validate, parse, and persist one capture's flow metadata."""

    file_path, _format_name = validate_capture(path, max_file_bytes=settings.pcap.max_file_bytes)
    digest = file_sha256(file_path)
    parsed = parse_capture(file_path, settings)
    capture_id, created = repository.save_pcap_import(
        filename=file_path.name,
        sha256=digest,
        file_size=file_path.stat().st_size,
        packet_count=parsed.packet_count,
        truncated=parsed.truncated,
        metadata={
            **parsed.metadata,
            "started_at": parsed.started_at.isoformat() if parsed.started_at else None,
            "ended_at": parsed.ended_at.isoformat() if parsed.ended_at else None,
            "filename": file_path.name,
        },
        flows=parsed.flows,
    )
    if not created:
        logger.info("capture %s already imported as %s", file_path.name, capture_id)
    return {
        "capture_id": capture_id,
        "sha256": digest,
        "filename": file_path.name,
        "imported": created,
        "packet_count": parsed.packet_count,
        "flow_count": len(parsed.flows),
        "truncated": parsed.truncated,
    }


def _scapy_version() -> str | None:
    try:
        from scapy import __version__ as scapy_version

        return str(scapy_version)
    except ImportError:
        return None


__all__ = [
    "FlowAggregate",
    "PcapImportError",
    "PcapParseResult",
    "SUPPORTED_SUFFIXES",
    "import_pcap_file",
    "parse_capture",
    "validate_capture",
]
