"""Deterministic deduplication helpers."""

from __future__ import annotations

from deephoney.schemas.events import NormalizedEvent


def dedupe_key(event: NormalizedEvent) -> str:
    """Return the canonical idempotency key for an event.

    The event hash is derived from the source engine, source event id, and
    retained raw payload.  Source filename and ingestion time are excluded so
    copied/rotated logs remain idempotent.
    """

    return event.event_hash


def event_is_duplicate(event: NormalizedEvent, existing_hashes: set[str]) -> bool:
    return dedupe_key(event) in existing_hashes


__all__ = ["dedupe_key", "event_is_duplicate"]
