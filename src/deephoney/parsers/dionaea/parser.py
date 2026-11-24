"""Dionaea event parser.

The pinned Dionaea image can emit JSON through its ``log_json`` ihandler and
a human-readable ``dionaea.log``.  The JSON path is preferred; the plaintext
fallback intentionally extracts only facts that are unambiguous.
"""

from __future__ import annotations

import json
import re
from typing import Any

from deephoney.parsers.base import BaseParser, ParseOutcome, ParseSuccess, _as_dict
from deephoney.schemas.events import EventType, SourceEngine
from deephoney.utils.hashing import sha256_text
from deephoney.utils.net import protocol_from_port, protocol_from_text
from deephoney.utils.redaction import redact_embedded_secrets, safe_json_value, sanitize_text

DIONAEA_PARSER_VERSION = "dionaea-parser-2024.1.0"

_TS_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REMOTE_RE = re.compile(
    r"(?:remote|from|client|source)[^0-9]{0,30}(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
_TYPE_RE = re.compile(r"\[(?P<type>[A-Za-z0-9_.-]+)\]")
_BINARY_KEYS = {
    "data",
    "payload",
    "raw",
    "binary",
    "content",
    "body",
    "packet",
    "bytes",
    "base64",
}


def _strip_binary(value: Any, depth: int = 0) -> Any:
    """Keep metadata only; never store captured payload bytes."""

    if depth > 8:
        return "[MAX_DEPTH]"
    if isinstance(value, dict):
        return {
            str(key): _strip_binary(item, depth + 1)
            for key, item in value.items()
            if str(key).lower() not in _BINARY_KEYS
        }
    if isinstance(value, list):
        return [_strip_binary(item, depth + 1) for item in value[:50]]
    if isinstance(value, bytes | bytearray):
        return "[BINARY OMITTED]"
    return safe_json_value(value)


def _extract_sha256(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str):
            candidate = value.strip().lower()
            if len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate):
                return candidate
    return None


def _map_event_type(event_type: str) -> EventType:
    lowered = event_type.lower()
    if "connection.close" in lowered or lowered.endswith(".close"):
        return EventType.DISCONNECT
    if "connection." in lowered and (
        lowered.endswith(".accept")
        or lowered.endswith(".link")
        or lowered.endswith(".reject")
        or "accept" in lowered
    ):
        return EventType.CONNECTION
    if ".download." in lowered or lowered.endswith(".download"):
        return EventType.FILE_DOWNLOAD
    if lowered.endswith(".capture") or ".capture." in lowered:
        return EventType.CAPTURE
    if ".modules." in lowered:
        return EventType.SERVICE_INTERACTION
    return EventType.UNKNOWN


def _protocol_for_event(event_type: str, connection: dict[str, Any], dst_port: Any) -> str | None:
    lower_type = event_type.lower()
    for hint in (
        "smb",
        "http",
        "https",
        "ftp",
        "tftp",
        "mysql",
        "mssql",
        "sip",
        "mqtt",
        "memcache",
        "upnp",
        "pptp",
        "printer",
    ):
        if hint in lower_type:
            return hint
    transport = connection.get("protocol")
    mapped = protocol_from_port(dst_port)
    if mapped and mapped not in {"tcp", "udp"}:
        return mapped
    return str(transport).lower() if transport else mapped


class DionaeaParser(BaseParser):
    engine = SourceEngine.DIONAEA
    parser_version = DIONAEA_PARSER_VERSION

    def parse_record(
        self,
        record: dict[str, Any] | str,
        *,
        source_file: str,
        line_number: int | None = None,
        ingested_at: Any = None,
    ) -> ParseOutcome:
        if isinstance(record, str):
            return self._parse_plaintext(
                record,
                source_file=source_file,
                line_number=line_number,
                ingested_at=ingested_at,
            )
        return self._parse_json(
            record,
            source_file=source_file,
            line_number=line_number,
            ingested_at=ingested_at,
        )

    def _parse_json(
        self,
        record: dict[str, Any],
        *,
        source_file: str,
        line_number: int | None,
        ingested_at: Any,
    ) -> ParseOutcome:
        event_type_text = str(
            record.get("type") or record.get("event") or record.get("event_type") or ""
        ).strip()
        connection = _as_dict(record.get("connection"))
        connection_type = str(connection.get("type") or "").strip().lower()
        if not event_type_text:
            if connection_type in {"accept", "listen", "connect", "reject"}:
                event_type_text = f"dionaea.connection.{connection_type}"
            elif record.get("capture") or record.get("download"):
                event_type_text = "dionaea.modules.python.file.capture"
        event_type = _map_event_type(event_type_text)
        remote = _as_dict(connection.get("remote") or record.get("remote"))
        local = _as_dict(connection.get("local") or record.get("local"))
        download = _as_dict(record.get("download"))
        capture = _as_dict(record.get("capture"))
        file_meta = download or capture or _as_dict(record.get("file"))

        src_ip = (
            remote.get("host")
            or remote.get("address")
            or remote.get("ip")
            or record.get("src_ip")
            or record.get("remote_ip")
        )
        src_port = remote.get("port") or record.get("src_port") or record.get("remote_port")
        dst_ip = (
            local.get("host")
            or local.get("address")
            or local.get("ip")
            or record.get("dst_ip")
            or record.get("local_ip")
        )
        dst_port = local.get("port") or record.get("dst_port") or record.get("local_port")
        protocol = _protocol_for_event(event_type_text, connection, dst_port)

        session_id = (
            connection.get("connection_unique_id")
            or connection.get("id")
            or record.get("connection_unique_id")
            or record.get("session_id")
        )
        session_id_provenance = "source" if session_id else None
        if not session_id and connection_type and (src_ip or dst_ip):
            seed = json.dumps(
                {
                    "connection": connection,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "timestamp": record.get("timestamp"),
                },
                sort_keys=True,
                default=str,
            )
            session_id = f"dionaea-log-{sha256_text(seed)[:16]}"
            session_id_provenance = "derived_from_single_dionaea_log_json_connection_record"
        source_event_id = record.get("id") or record.get("uuid") or record.get("event_id")

        username = record.get("username")
        if username is None:
            login = _as_dict(record.get("login") or record.get("auth"))
            username = login.get("username")
        credentials = record.get("credentials")
        if username is None and isinstance(credentials, list):
            for entry in credentials:
                if isinstance(entry, dict) and entry.get("username") is not None:
                    username = entry.get("username")
                    break
        command = record.get("command") or record.get("input")
        if command is None:
            ftp = _as_dict(record.get("ftp"))
            commands = ftp.get("commands")
            if isinstance(commands, list) and commands:
                first = commands[0]
                if isinstance(first, dict):
                    command = first.get("command")

        sha256 = _extract_sha256(
            file_meta.get("sha256"),
            file_meta.get("sha256_hash"),
            record.get("sha256"),
            capture.get("sha256"),
        )

        metadata = {
            "dionaea_event_type": event_type_text or None,
            "connection_unique_id": session_id if session_id_provenance == "source" else None,
            "session_id_provenance": session_id_provenance,
            "connection_type": connection_type or None,
            "transport": connection.get("protocol"),
            "remote": _strip_binary(remote) or None,
            "local": _strip_binary(local) or None,
            "download": _strip_binary(download) or None,
            "capture": _strip_binary(capture) or None,
            "file": _strip_binary(file_meta) or None,
            "message": redact_embedded_secrets(
                sanitize_text(record.get("message"), max_length=4096)
            )
            or None,
        }
        if isinstance(credentials, list):
            metadata["credential_count"] = min(len(credentials), 100)
            metadata["credentials_retained_in_raw_event"] = True
        ftp = _as_dict(record.get("ftp"))
        ftp_commands = ftp.get("commands")
        if isinstance(ftp_commands, list):
            metadata["ftp_command_count"] = min(len(ftp_commands), 100)
        for key in ("url", "filename", "size", "file_type", "mime_type", "md5", "sha1"):
            if key in file_meta:
                metadata[key] = safe_json_value(file_meta[key])
        metadata = {key: value for key, value in metadata.items() if value is not None}

        return ParseSuccess(
            event=self.build_event(
                raw_event=record,
                event_type=event_type,
                source_file=source_file,
                source_event_id=source_event_id,
                timestamp=record.get("timestamp") or record.get("time"),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                session_id=session_id,
                username=username,
                command=command,
                artifact_sha256=sha256,
                details=metadata,
                line_number=line_number,
                ingested_at=ingested_at,
            )
        )

    def _parse_plaintext(
        self,
        text: str,
        *,
        source_file: str,
        line_number: int | None,
        ingested_at: Any,
    ) -> ParseOutcome:
        """Best-effort fallback for human-readable dionaea.log lines.

        This path only assigns a source IP when the line explicitly labels a
        remote/client address.  Ports are not guessed from unlabelled text.
        """

        stripped = sanitize_text(text, max_length=8192).strip()
        if not stripped:
            return self.failure(
                engine=self.engine,
                source_file=source_file,
                line_number=line_number,
                error="empty plaintext record",
                raw_text=text,
            )

        ts_match = _TS_RE.search(stripped)
        timestamp = ts_match.group("timestamp") if ts_match else None
        type_match = _TYPE_RE.search(stripped)
        event_type_text = type_match.group("type") if type_match else ""
        event_type = _map_event_type(event_type_text)

        remote_match = _REMOTE_RE.search(stripped)
        src_ip = remote_match.group("ip") if remote_match else None
        if src_ip and not _IPV4_RE.fullmatch(src_ip):
            src_ip = None

        protocol = protocol_from_text(event_type_text) or protocol_from_text(stripped)
        details = {
            "raw_format": "plaintext",
            "dionaea_event_type": event_type_text or None,
            "message": redact_embedded_secrets(stripped[:4096]),
            "address_inference": (
                "src_ip taken from an explicitly labelled remote/client field"
                if src_ip
                else "no labelled remote address in plaintext line"
            ),
        }
        details = {key: value for key, value in details.items() if value is not None}

        return ParseSuccess(
            event=self.build_event(
                raw_event=stripped,
                event_type=event_type,
                source_file=source_file,
                timestamp=timestamp,
                src_ip=src_ip,
                protocol=protocol,
                details=details,
                line_number=line_number,
                ingested_at=ingested_at,
            )
        )


__all__ = ["DIONAEA_PARSER_VERSION", "DionaeaParser"]
