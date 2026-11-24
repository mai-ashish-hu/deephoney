"""Reconstruct sessions from normalized source events.

Cowrie provides a strong session identifier.  Dionaea exposes a connection
unique id.  DeepHoney groups only within one engine and only when a source
session/connection id exists; it never merges Cowrie and Dionaea activity
based on a shared IP address.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from deephoney.schemas.events import EventType, NormalizedEvent, SourceEngine
from deephoney.utils.hashing import session_uuid, sha256_text
from deephoney.utils.redaction import safe_json_value, sanitize_text
from deephoney.utils.time import duration_seconds, ensure_utc

MAX_COMMANDS_IN_METADATA = 500
MAX_USERS_IN_METADATA = 200
MAX_SOURCE_IPS_IN_METADATA = 200
MAX_HASHES_IN_METADATA = 200


@dataclass(slots=True)
class SessionRecord:
    """A reconstructed source session and the events supporting it."""

    id: str
    source_engine: str
    source_session_id: str
    src_ip: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int
    metadata: dict[str, Any]
    events: list[NormalizedEvent] = field(default_factory=list, repr=False)

    @property
    def duration_seconds(self) -> float:
        return duration_seconds(self.first_seen_at, self.last_seen_at)


def session_sort_key(event: NormalizedEvent) -> tuple[Any, ...]:
    """Sort by event time, then source line, then ingestion time.

    Events without a source timestamp sort after timestamped events so they
    are visible rather than silently reordered into a misleading position.
    """

    return (
        event.timestamp is None,
        event.timestamp or event.ingested_at,
        event.source_line if event.source_line is not None else 0,
        event.event_id,
    )


def _password_hashes(events: Iterable[NormalizedEvent]) -> set[str]:
    hashes: set[str] = set()
    for event in events:
        raw = event.raw_event
        if not isinstance(raw, dict):
            continue
        for key in ("password", "passwd", "passphrase"):
            value = raw.get(key)
            if value not in (None, ""):
                hashes.add(sha256_text(str(value)))
    return hashes


def _artifact_size(event: NormalizedEvent) -> int | None:
    details = event.details if isinstance(event.details, dict) else {}
    candidates = [
        details.get("size"),
        details.get("file_size"),
        details.get("bytes"),
    ]
    download = details.get("download")
    if isinstance(download, dict):
        candidates.append(download.get("size"))
    capture = details.get("capture")
    if isinstance(capture, dict):
        candidates.append(capture.get("size"))
    file_meta = details.get("file")
    if isinstance(file_meta, dict):
        candidates.append(file_meta.get("size"))
    for value in candidates:
        try:
            number = int(str(value), 10)
        except (TypeError, ValueError):
            continue
        if number >= 0:
            return number
    return None


def reconstruct_session(
    *,
    source_engine: str,
    source_session_id: str,
    events: Iterable[NormalizedEvent],
) -> SessionRecord:
    """Reconstruct one session from its events."""

    ordered = sorted(events, key=session_sort_key)
    if not ordered:
        raise ValueError("Cannot reconstruct a session without events")

    timestamps = [event.timestamp for event in ordered if event.timestamp is not None]
    all_times = timestamps or [event.ingested_at for event in ordered]
    first_seen = min(all_times)
    last_seen = max(all_times)

    event_types = Counter(event.event_type.value for event in ordered)
    protocols = sorted({event.protocol for event in ordered if event.protocol})
    dst_ports = sorted({event.dst_port for event in ordered if event.dst_port is not None})
    src_ports = sorted({event.src_port for event in ordered if event.src_port is not None})
    src_ips = sorted({event.src_ip for event in ordered if event.src_ip})
    usernames = sorted({event.username for event in ordered if event.username})
    artifact_hashes = sorted({event.artifact_sha256 for event in ordered if event.artifact_sha256})
    command_sequence = [
        sanitize_text(event.command, max_length=2048) for event in ordered if event.command
    ][:MAX_COMMANDS_IN_METADATA]

    auth_failures = sum(1 for event in ordered if event.event_type is EventType.AUTH_FAILURE)
    auth_successes = sum(1 for event in ordered if event.event_type is EventType.AUTH_SUCCESS)
    download_count = sum(1 for event in ordered if event.event_type is EventType.FILE_DOWNLOAD)
    upload_count = sum(1 for event in ordered if event.event_type is EventType.FILE_UPLOAD)
    command_count = sum(1 for event in ordered if event.event_type is EventType.COMMAND)

    artifact_sizes: dict[str, int] = {}
    for event in ordered:
        if event.artifact_sha256:
            size = _artifact_size(event)
            if size is not None:
                artifact_sizes[event.artifact_sha256] = max(
                    size, artifact_sizes.get(event.artifact_sha256, 0)
                )

    src_ip = next((event.src_ip for event in ordered if event.src_ip), None)
    password_hashes = _password_hashes(ordered)

    metadata = {
        "event_types": dict(sorted(event_types.items())),
        "protocols": protocols,
        "dst_ports": dst_ports,
        "src_ports": src_ports,
        "src_ips": src_ips[:MAX_SOURCE_IPS_IN_METADATA],
        "usernames": [
            sanitize_text(user, max_length=255) for user in usernames[:MAX_USERS_IN_METADATA]
        ],
        "command_count": command_count,
        "command_sequence": command_sequence,
        "auth_failures": auth_failures,
        "auth_successes": auth_successes,
        "auth_attempts": auth_failures + auth_successes,
        "download_count": download_count,
        "upload_count": upload_count,
        "distinct_usernames": len(usernames),
        "distinct_password_hashes": len(password_hashes),
        "artifact_hashes": artifact_hashes[:MAX_HASHES_IN_METADATA],
        "artifact_sizes": artifact_sizes,
        "first_seen_at": first_seen.isoformat(),
        "last_seen_at": last_seen.isoformat(),
        "duration_seconds": duration_seconds(first_seen, last_seen),
        "events_without_timestamp": sum(1 for event in ordered if event.timestamp is None),
        "reconstruction_version": "2024.1.0",
    }
    metadata = safe_json_value(metadata)

    return SessionRecord(
        id=str(session_uuid(source_engine, source_session_id)),
        source_engine=source_engine,
        source_session_id=source_session_id,
        src_ip=src_ip,
        first_seen_at=ensure_utc(first_seen),
        last_seen_at=ensure_utc(last_seen),
        event_count=len(ordered),
        metadata=metadata,
        events=ordered,
    )


def reconstruct_sessions(
    events: Iterable[NormalizedEvent],
    *,
    engine: SourceEngine | str | None = None,
    session_ids: set[str] | None = None,
) -> list[SessionRecord]:
    """Group events by ``(engine, session_id)`` and reconstruct each group.

    Events without a session identifier are returned separately by the
    caller's normal event queries; they are not assigned to an invented
    session.  Cross-engine grouping never happens here.
    """

    allowed_engine = engine.value if isinstance(engine, SourceEngine) else engine
    grouped: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if not event.session_id:
            continue
        if allowed_engine and event.source_engine.value != allowed_engine:
            continue
        if session_ids is not None and event.session_id not in session_ids:
            continue
        grouped[(event.source_engine.value, event.session_id)].append(event)

    records = [
        reconstruct_session(
            source_engine=source_engine,
            source_session_id=session_id,
            events=group_events,
        )
        for (source_engine, session_id), group_events in grouped.items()
    ]
    records.sort(
        key=lambda record: (record.first_seen_at, record.source_engine, record.source_session_id)
    )
    return records


__all__ = [
    "MAX_COMMANDS_IN_METADATA",
    "MAX_SOURCE_IPS_IN_METADATA",
    "MAX_USERS_IN_METADATA",
    "SessionRecord",
    "reconstruct_session",
    "reconstruct_sessions",
    "session_sort_key",
]
