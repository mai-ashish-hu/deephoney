"""Shared normalized event model.

Every source-specific event is mapped into this schema while the original
payload is retained.  Missing source fields stay ``None``: parsers do not
invent addresses, ports, usernames, or timestamps.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from deephoney.utils.time import ensure_utc


class SourceEngine(str, Enum):
    COWRIE = "cowrie"
    DIONAEA = "dionaea"


class EventType(str, Enum):
    CONNECTION = "connection"
    DISCONNECT = "disconnect"
    AUTH_ATTEMPT = "auth_attempt"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    COMMAND = "command"
    FILE_DOWNLOAD = "file_download"
    FILE_UPLOAD = "file_upload"
    CAPTURE = "capture"
    PAYLOAD = "payload"
    SERVICE_INTERACTION = "service_interaction"
    CLIENT_VERSION = "client_version"
    CLIENT_FINGERPRINT = "client_fingerprint"
    SESSION_PARAMS = "session_params"
    LOG_CLOSED = "log_closed"
    UNKNOWN = "unknown"


class NormalizedEvent(BaseModel):
    """One normalized honeypot observation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    event_hash: str
    source_engine: SourceEngine
    source_event_id: str | None = None
    event_type: EventType
    timestamp: datetime | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    session_id: str | None = None
    username: str | None = None
    command: str | None = None
    artifact_sha256: str | None = None
    raw_event: dict[str, Any] | str
    source_file: str
    source_line: int | None = None
    ingested_at: datetime
    parser_version: str
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else None

    @field_validator("artifact_sha256")
    @classmethod
    def _sha256(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip().lower()
        if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
            return None
        return candidate

    @field_validator("src_port", "dst_port")
    @classmethod
    def _port(cls, value: int | None) -> int | None:
        if value is None:
            return None
        return value if 0 <= value <= 65535 else None

    def to_record(self) -> dict[str, Any]:
        """Return a plain dictionary suitable for serializers and tests."""

        return self.model_dump(mode="python")


__all__ = ["EventType", "NormalizedEvent", "SourceEngine"]
