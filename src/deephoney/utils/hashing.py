"""Deterministic hashing and stable event identifiers."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

EVENT_NAMESPACE = uuid.UUID("7ab98f50-1d9e-4f2b-9b36-f8c9a4b63e04")


def canonical_json(value: Any) -> str:
    """Serialize a value deterministically for hashing.

    The raw event is attacker-controlled, so serialization must never raise.
    Fallback values are represented by ``str(value)``.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


def file_sha256(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def event_identity(
    source_engine: str,
    raw_event: Any,
    *,
    source_event_id: str | None = None,
) -> tuple[str, str]:
    """Return ``(event_id, event_hash)`` for a source event.

    The content hash deliberately excludes the source filename so that the
    same event imported from a rotated/copied log is deduplicated.  The
    downstream pipeline handles a duplicate within the same file as well.
    """

    material = {
        "engine": source_engine,
        "source_event_id": source_event_id,
        "raw": raw_event,
    }
    event_hash = sha256_json(material)
    event_id = str(uuid.uuid5(EVENT_NAMESPACE, f"deephoney:{event_hash}"))
    return event_id, event_hash


def session_uuid(source_engine: str, source_session_id: str) -> uuid.UUID:
    """Create a deterministic internal UUID for an engine session."""

    return uuid.uuid5(EVENT_NAMESPACE, f"session:{source_engine}:{source_session_id}")


def detection_uuid(session_id: str, method: str, model_version: str) -> uuid.UUID:
    """Create a deterministic detection identifier."""

    return uuid.uuid5(
        EVENT_NAMESPACE,
        f"detection:{session_id}:{method}:{model_version}",
    )


__all__ = [
    "EVENT_NAMESPACE",
    "canonical_json",
    "detection_uuid",
    "event_identity",
    "file_sha256",
    "session_uuid",
    "sha256_bytes",
    "sha256_json",
    "sha256_text",
]
