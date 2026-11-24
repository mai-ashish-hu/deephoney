"""Cowrie JSON event parser.

Cowrie emits one JSON object per line.  The event IDs are stable names such
as ``cowrie.login.failed`` but they are not globally unique; DeepHoney builds
an idempotent identifier from the retained raw event.
"""

from __future__ import annotations

from typing import Any

from deephoney.parsers.base import BaseParser, ParseOutcome, ParseSuccess
from deephoney.schemas.events import EventType, SourceEngine
from deephoney.utils.net import protocol_from_port
from deephoney.utils.redaction import redact_embedded_secrets, safe_json_value, sanitize_text

COWRIE_PARSER_VERSION = "cowrie-parser-2024.1.0"

_EVENT_TYPE_MAP: dict[str, EventType] = {
    "cowrie.session.connect": EventType.CONNECTION,
    "cowrie.session.closed": EventType.DISCONNECT,
    "cowrie.login.success": EventType.AUTH_SUCCESS,
    "cowrie.login.failed": EventType.AUTH_FAILURE,
    "cowrie.auth.success": EventType.AUTH_SUCCESS,
    "cowrie.auth.failed": EventType.AUTH_FAILURE,
    "cowrie.command.input": EventType.COMMAND,
    "cowrie.command.success": EventType.COMMAND,
    "cowrie.command.failed": EventType.COMMAND,
    "cowrie.session.file_download": EventType.FILE_DOWNLOAD,
    "cowrie.session.file_download.failed": EventType.FILE_DOWNLOAD,
    "cowrie.session.file_upload": EventType.FILE_UPLOAD,
    "cowrie.client.version": EventType.CLIENT_VERSION,
    "cowrie.client.fingerprint": EventType.CLIENT_FINGERPRINT,
    "cowrie.client.kex": EventType.SERVICE_INTERACTION,
    "cowrie.client.size": EventType.SERVICE_INTERACTION,
    "cowrie.client.var": EventType.SERVICE_INTERACTION,
    "cowrie.session.params": EventType.SESSION_PARAMS,
    "cowrie.log.closed": EventType.LOG_CLOSED,
    "cowrie.direct-tcpip.request": EventType.CONNECTION,
    "cowrie.direct-tcpip.data": EventType.SERVICE_INTERACTION,
    "cowrie.direct-tcpip.failed": EventType.SERVICE_INTERACTION,
    "cowrie.payload": EventType.PAYLOAD,
}


def _detail_pick(record: dict[str, Any], *keys: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in keys:
        if key in record and record[key] is not None:
            result[key] = safe_json_value(record[key])
    return result


class CowrieParser(BaseParser):
    engine = SourceEngine.COWRIE
    parser_version = COWRIE_PARSER_VERSION

    def parse_record(
        self,
        record: dict[str, Any] | str,
        *,
        source_file: str,
        line_number: int | None = None,
        ingested_at: Any = None,
    ) -> ParseOutcome:
        if not isinstance(record, dict):
            return self.failure(
                engine=self.engine,
                source_file=source_file,
                line_number=line_number,
                error="Cowrie record is not a JSON object",
                raw_text=str(record),
            )

        eventid = str(record.get("eventid") or "").strip()
        event_type = _EVENT_TYPE_MAP.get(eventid, EventType.UNKNOWN)

        src_port = record.get("src_port")
        dst_port = record.get("dst_port")
        protocol = record.get("protocol") or protocol_from_port(dst_port)

        command = record.get("input")
        if command is None and event_type is EventType.COMMAND:
            command = record.get("command")
        if command is None:
            command = record.get("command")

        details = {
            "cowrie_eventid": eventid or None,
            "message": redact_embedded_secrets(
                sanitize_text(record.get("message"), max_length=4096)
            )
            or None,
            "password_present": bool(record.get("password")),
            "sensor": sanitize_text(record.get("sensor"), max_length=256) or None,
        }
        details.update(
            _detail_pick(
                record,
                "url",
                "outfile",
                "filename",
                "size",
                "shasum",
                "duration",
                "version",
                "mac",
                "kex",
                "hassh",
                "hasshAlgorithms",
                "client",
                "ttylog",
                "realm",
                "cwd",
            )
        )
        details = {key: value for key, value in details.items() if value is not None}

        shasum = record.get("shasum")
        artifact_sha256 = shasum if isinstance(shasum, str) else None

        return ParseSuccess(
            event=self.build_event(
                raw_event=record,
                event_type=event_type,
                source_file=source_file,
                source_event_id=eventid or None,
                timestamp=record.get("timestamp") or record.get("time"),
                src_ip=record.get("src_ip"),
                src_port=src_port,
                dst_ip=record.get("dst_ip"),
                dst_port=dst_port,
                protocol=protocol,
                session_id=record.get("session") or record.get("session_id"),
                username=record.get("username"),
                command=command,
                artifact_sha256=artifact_sha256,
                details=details,
                line_number=line_number,
                ingested_at=ingested_at,
            )
        )


__all__ = ["COWRIE_PARSER_VERSION", "CowrieParser"]
