"""Deterministic, versioned session features.

The same stored raw events must always produce the same features.  No random
values, wall-clock time, or external lookups are used here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from deephoney.features.commands import (
    HIGH_RISK_CATEGORIES,
    classify_commands,
)
from deephoney.schemas.events import EventType
from deephoney.sessions.reconstruction import SessionRecord
from deephoney.utils.time import duration_seconds

FEATURE_VERSION = "2024.1.0"

FEATURE_NAMES: tuple[str, ...] = (
    "engine_is_cowrie",
    "engine_is_dionaea",
    "event_count",
    "duration_seconds",
    "events_per_minute",
    "auth_attempts",
    "auth_failures",
    "auth_successes",
    "auth_failure_ratio",
    "distinct_usernames",
    "distinct_password_hashes",
    "command_count",
    "distinct_commands",
    "unique_command_ratio",
    "recon_command_count",
    "file_transfer_command_count",
    "persistence_command_count",
    "destructive_command_count",
    "crypto_command_count",
    "lateral_command_count",
    "privilege_command_count",
    "shell_utility_count",
    "high_risk_command_count",
    "download_count",
    "artifact_count",
    "has_artifact",
    "total_artifact_size",
    "has_executable_artifact",
    "distinct_src_ports",
    "distinct_dst_ports",
    "distinct_protocols",
    "connection_count",
    "has_successful_login",
    "src_ip_session_count",
)

_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".elf",
    ".bin",
    ".sh",
    ".pl",
    ".py",
    ".ps1",
    ".jar",
    ".msi",
}
_EXECUTABLE_HINTS = (
    "executable",
    "pe32",
    "elf",
    "mach-o",
    "ms-dos",
    "application/x-dosexec",
    "application/x-elf",
)


@dataclass(slots=True)
class SessionFeatures:
    """Feature row for one reconstructed session."""

    source_engine: str
    session_id: str
    src_ip: str | None
    feature_version: str = FEATURE_VERSION
    event_count: int = 0
    duration_seconds: float = 0.0
    events_per_minute: float = 0.0
    auth_attempts: int = 0
    auth_failures: int = 0
    auth_successes: int = 0
    auth_failure_ratio: float = 0.0
    distinct_usernames: int = 0
    distinct_password_hashes: int = 0
    command_count: int = 0
    distinct_commands: int = 0
    unique_command_ratio: float = 0.0
    recon_command_count: int = 0
    file_transfer_command_count: int = 0
    persistence_command_count: int = 0
    destructive_command_count: int = 0
    crypto_command_count: int = 0
    lateral_command_count: int = 0
    privilege_command_count: int = 0
    shell_utility_count: int = 0
    high_risk_command_count: int = 0
    download_count: int = 0
    artifact_count: int = 0
    has_artifact: int = 0
    total_artifact_size: float = 0.0
    has_executable_artifact: int = 0
    distinct_src_ports: int = 0
    distinct_dst_ports: int = 0
    distinct_protocols: int = 0
    connection_count: int = 0
    has_successful_login: int = 0
    src_ip_session_count: int = 1
    command_sequence: list[str] = field(default_factory=list, repr=False)

    def to_vector(self) -> list[float]:
        """Return a model-safe numeric vector in ``FEATURE_NAMES`` order."""

        return [float(self.as_dict()[name]) for name in FEATURE_NAMES]

    def as_dict(self) -> dict[str, float | int | str | None]:
        return {
            "engine_is_cowrie": 1 if self.source_engine == "cowrie" else 0,
            "engine_is_dionaea": 1 if self.source_engine == "dionaea" else 0,
            "event_count": self.event_count,
            "duration_seconds": self.duration_seconds,
            "events_per_minute": self.events_per_minute,
            "auth_attempts": self.auth_attempts,
            "auth_failures": self.auth_failures,
            "auth_successes": self.auth_successes,
            "auth_failure_ratio": self.auth_failure_ratio,
            "distinct_usernames": self.distinct_usernames,
            "distinct_password_hashes": self.distinct_password_hashes,
            "command_count": self.command_count,
            "distinct_commands": self.distinct_commands,
            "unique_command_ratio": self.unique_command_ratio,
            "recon_command_count": self.recon_command_count,
            "file_transfer_command_count": self.file_transfer_command_count,
            "persistence_command_count": self.persistence_command_count,
            "destructive_command_count": self.destructive_command_count,
            "crypto_command_count": self.crypto_command_count,
            "lateral_command_count": self.lateral_command_count,
            "privilege_command_count": self.privilege_command_count,
            "shell_utility_count": self.shell_utility_count,
            "high_risk_command_count": self.high_risk_command_count,
            "download_count": self.download_count,
            "artifact_count": self.artifact_count,
            "has_artifact": self.has_artifact,
            "total_artifact_size": self.total_artifact_size,
            "has_executable_artifact": self.has_executable_artifact,
            "distinct_src_ports": self.distinct_src_ports,
            "distinct_dst_ports": self.distinct_dst_ports,
            "distinct_protocols": self.distinct_protocols,
            "connection_count": self.connection_count,
            "has_successful_login": self.has_successful_login,
            "src_ip_session_count": self.src_ip_session_count,
        }

    def dataset_row(self) -> dict[str, Any]:
        """Return a CSV/JSON-serialisable row including identifiers."""

        row: dict[str, Any] = {
            "source_engine": self.source_engine,
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "feature_version": self.feature_version,
        }
        row.update(self.as_dict())
        return row


def _artifact_details(event: Any) -> dict[str, Any]:
    details = event.details if isinstance(event.details, dict) else {}
    result: dict[str, Any] = {}
    for key in ("download", "capture", "file"):
        value = details.get(key)
        if isinstance(value, dict):
            result.update(value)
    for key in ("filename", "outfile", "file_type", "mime_type", "size", "file_size"):
        if key in details and details[key] is not None:
            result[key] = details[key]
    return result


def _is_executable_artifact(event: Any) -> bool:
    details = _artifact_details(event)
    names = [details.get("filename"), details.get("outfile"), event.command]
    for name in names:
        if not isinstance(name, str):
            continue
        if Path(name.strip()).suffix.lower() in _EXECUTABLE_EXTENSIONS:
            return True
    hints = " ".join(str(details.get(key) or "") for key in ("file_type", "mime_type")).lower()
    return any(hint in hints for hint in _EXECUTABLE_HINTS)


def _artifact_size(event: Any) -> int | None:
    details = _artifact_details(event)
    for key in ("size", "file_size"):
        value = details.get(key)
        try:
            number = int(str(value), 10)
        except (TypeError, ValueError):
            continue
        if number >= 0:
            return number
    return None


def _password_hash_count(record: SessionRecord) -> int:
    import hashlib

    hashes: set[str] = set()
    for event in record.events:
        if not isinstance(event.raw_event, dict):
            continue
        for key in ("password", "passwd", "passphrase"):
            value = event.raw_event.get(key)
            if value not in (None, ""):
                hashes.add(hashlib.sha256(str(value).encode("utf-8")).hexdigest())
    return len(hashes)


def extract_features(record: SessionRecord) -> SessionFeatures:
    """Extract deterministic features from a reconstructed session."""

    events = record.events
    commands = [event.command for event in events if event.command]
    command_counts = classify_commands(commands)
    command_count = len(commands)
    distinct_commands = len(set(commands))
    auth_failures = sum(1 for event in events if event.event_type is EventType.AUTH_FAILURE)
    auth_successes = sum(1 for event in events if event.event_type is EventType.AUTH_SUCCESS)
    auth_attempts = auth_failures + auth_successes
    duration = duration_seconds(record.first_seen_at, record.last_seen_at)
    event_count = len(events)
    events_per_minute = 0.0
    if event_count:
        events_per_minute = min(10000.0, (event_count / max(duration, 1.0)) * 60.0)

    artifact_hashes = {event.artifact_sha256 for event in events if event.artifact_sha256}
    has_executable = any(_is_executable_artifact(event) for event in events)
    sizes: dict[str, int] = {}
    for event in events:
        if event.artifact_sha256:
            size = _artifact_size(event)
            if size is not None:
                sizes[event.artifact_sha256] = max(size, sizes.get(event.artifact_sha256, 0))

    high_risk_count = sum(command_counts[category] for category in HIGH_RISK_CATEGORIES)

    return SessionFeatures(
        source_engine=record.source_engine,
        session_id=record.source_session_id,
        src_ip=record.src_ip,
        event_count=event_count,
        duration_seconds=round(duration, 3),
        events_per_minute=round(events_per_minute, 3),
        auth_attempts=auth_attempts,
        auth_failures=auth_failures,
        auth_successes=auth_successes,
        auth_failure_ratio=round(auth_failures / auth_attempts, 4) if auth_attempts else 0.0,
        distinct_usernames=len({event.username for event in events if event.username}),
        distinct_password_hashes=_password_hash_count(record),
        command_count=command_count,
        distinct_commands=distinct_commands,
        unique_command_ratio=round(distinct_commands / command_count, 4) if command_count else 0.0,
        recon_command_count=command_counts["recon"],
        file_transfer_command_count=command_counts["file_transfer"],
        persistence_command_count=command_counts["persistence"],
        destructive_command_count=command_counts["destructive"],
        crypto_command_count=command_counts["crypto"],
        lateral_command_count=command_counts["lateral"],
        privilege_command_count=command_counts["privilege"],
        shell_utility_count=command_counts["shell_utility"],
        high_risk_command_count=high_risk_count,
        download_count=sum(1 for event in events if event.event_type is EventType.FILE_DOWNLOAD),
        artifact_count=len(artifact_hashes),
        has_artifact=1 if artifact_hashes else 0,
        total_artifact_size=float(sum(sizes.values())),
        has_executable_artifact=1 if has_executable else 0,
        distinct_src_ports=len({event.src_port for event in events if event.src_port is not None}),
        distinct_dst_ports=len({event.dst_port for event in events if event.dst_port is not None}),
        distinct_protocols=len({event.protocol for event in events if event.protocol}),
        connection_count=sum(1 for event in events if event.event_type is EventType.CONNECTION),
        has_successful_login=1 if auth_successes else 0,
        command_sequence=commands[:500],
    )


def features_as_dict(features: SessionFeatures) -> dict[str, Any]:
    return asdict(features)


__all__ = [
    "FEATURE_NAMES",
    "FEATURE_VERSION",
    "SessionFeatures",
    "extract_features",
    "features_as_dict",
]
