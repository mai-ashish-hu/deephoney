"""Parser contracts and shared normalization helpers."""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from deephoney.schemas.events import EventType, NormalizedEvent, SourceEngine
from deephoney.utils.hashing import event_identity
from deephoney.utils.net import normalize_ip, safe_port
from deephoney.utils.redaction import safe_json_value, sanitize_text
from deephoney.utils.time import ensure_utc, parse_timestamp, utcnow

MAX_SOURCE_EVENT_ID = 255
MAX_USERNAME = 255
MAX_COMMAND = 8192
MAX_DETAIL_TEXT = 8192


@dataclass(frozen=True, slots=True)
class ParseSuccess:
    event: NormalizedEvent


@dataclass(frozen=True, slots=True)
class ParseFailure:
    source_engine: str
    source_file: str
    line_number: int | None
    error: str
    raw_excerpt: str


ParseOutcome = ParseSuccess | ParseFailure


def _as_text(value: Any, limit: int = MAX_DETAIL_TEXT) -> str | None:
    if value is None:
        return None
    text = sanitize_text(value, max_length=limit)
    return text or None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class BaseParser(abc.ABC):
    """Base class for tolerant, non-throwing source parsers."""

    engine: SourceEngine
    parser_version: str

    def parse_line(
        self,
        raw_line: str,
        *,
        source_file: str,
        line_number: int | None = None,
        ingested_at: datetime | None = None,
    ) -> ParseOutcome:
        """Parse one raw line, returning a failure instead of raising."""

        text = raw_line.strip()
        if not text:
            return ParseFailure(
                source_engine=self.engine.value,
                source_file=source_file,
                line_number=line_number,
                error="empty record",
                raw_excerpt="",
            )
        try:
            record: dict[str, Any] | str
            if text[0] in "{[":
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return ParseFailure(
                        source_engine=self.engine.value,
                        source_file=source_file,
                        line_number=line_number,
                        error="JSON array where an object was expected",
                        raw_excerpt=sanitize_text(text, max_length=2000),
                    )
                if not isinstance(parsed, dict):
                    return ParseFailure(
                        source_engine=self.engine.value,
                        source_file=source_file,
                        line_number=line_number,
                        error=f"unsupported JSON type: {type(parsed).__name__}",
                        raw_excerpt=sanitize_text(text, max_length=2000),
                    )
                record = parsed
            else:
                record = text
            return self.parse_record(
                record,
                source_file=source_file,
                line_number=line_number,
                ingested_at=ingested_at,
            )
        except (json.JSONDecodeError, RecursionError) as exc:
            return ParseFailure(
                source_engine=self.engine.value,
                source_file=source_file,
                line_number=line_number,
                error=f"invalid JSON: {exc}",
                raw_excerpt=sanitize_text(text, max_length=2000),
            )
        except Exception as exc:
            return ParseFailure(
                source_engine=self.engine.value,
                source_file=source_file,
                line_number=line_number,
                error=f"parser error: {type(exc).__name__}: {exc}",
                raw_excerpt=sanitize_text(text, max_length=2000),
            )

    @abc.abstractmethod
    def parse_record(
        self,
        record: dict[str, Any] | str,
        *,
        source_file: str,
        line_number: int | None = None,
        ingested_at: datetime | None = None,
    ) -> ParseOutcome:
        """Normalize one already-decoded record."""

    def build_event(
        self,
        *,
        raw_event: dict[str, Any] | str,
        event_type: EventType,
        source_file: str,
        source_event_id: Any = None,
        timestamp: Any = None,
        src_ip: Any = None,
        src_port: Any = None,
        dst_ip: Any = None,
        dst_port: Any = None,
        protocol: Any = None,
        session_id: Any = None,
        username: Any = None,
        command: Any = None,
        artifact_sha256: Any = None,
        details: dict[str, Any] | None = None,
        line_number: int | None = None,
        ingested_at: datetime | None = None,
    ) -> NormalizedEvent:
        source_event_id_text = _as_text(source_event_id, MAX_SOURCE_EVENT_ID)
        event_id, event_hash = event_identity(
            self.engine.value,
            raw_event,
            source_event_id=source_event_id_text,
        )
        safe_details = safe_json_value(details or {})
        if not isinstance(safe_details, dict):
            safe_details = {"value": safe_details}

        sha = artifact_sha256 if isinstance(artifact_sha256, str) else None
        parsed_sha = sha.strip().lower() if sha else None
        if parsed_sha is not None and (
            len(parsed_sha) != 64 or any(char not in "0123456789abcdef" for char in parsed_sha)
        ):
            parsed_sha = None

        return NormalizedEvent(
            event_id=event_id,
            event_hash=event_hash,
            source_engine=self.engine,
            source_event_id=source_event_id_text,
            event_type=event_type,
            timestamp=parse_timestamp(timestamp),
            src_ip=normalize_ip(src_ip),
            src_port=safe_port(src_port),
            dst_ip=normalize_ip(dst_ip),
            dst_port=safe_port(dst_port),
            protocol=_as_text(protocol, 32),
            session_id=_as_text(session_id, 255),
            username=_as_text(username, MAX_USERNAME),
            command=_as_text(command, MAX_COMMAND),
            artifact_sha256=parsed_sha,
            raw_event=raw_event,
            source_file=source_file,
            source_line=line_number,
            ingested_at=ensure_utc(ingested_at or utcnow()),
            parser_version=self.parser_version,
            details=safe_details,
        )

    @staticmethod
    def failure(
        *,
        engine: SourceEngine,
        source_file: str,
        line_number: int | None,
        error: str,
        raw_text: str,
        excerpt_bytes: int = 2000,
    ) -> ParseFailure:
        return ParseFailure(
            source_engine=engine.value,
            source_file=source_file,
            line_number=line_number,
            error=sanitize_text(error, max_length=500),
            raw_excerpt=sanitize_text(raw_text, max_length=excerpt_bytes),
        )


__all__ = [
    "BaseParser",
    "ParseFailure",
    "ParseOutcome",
    "ParseSuccess",
    "_as_dict",
    "_as_text",
]
