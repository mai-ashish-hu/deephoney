"""ORM-to-dictionary serialization with consistent redaction."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from deephoney.storage.models import (
    Artifact,
    Detection,
    Event,
    HoneypotSession,
    IngestionRun,
    ParserFailure,
    PcapCapture,
    PcapFlow,
)
from deephoney.utils.redaction import (
    redact_embedded_secrets,
    redact_mapping,
    redact_raw_event,
    safe_json_value,
)
from deephoney.utils.time import format_display, format_utc


def _display(value: datetime | None, timezone_name: str) -> str:
    return format_display(value, timezone_name)


def event_to_dict(
    event: Event,
    *,
    timezone_name: str = "UTC",
    redact: bool = True,
    include_raw: bool = True,
) -> dict[str, Any]:
    raw = redact_raw_event(event.raw_payload) if redact else event.raw_payload
    row: dict[str, Any] = {
        "event_id": str(event.id),
        "event_hash": event.event_hash,
        "source_engine": event.source_engine,
        "source_event_id": event.source_event_id,
        "event_type": event.event_type,
        "timestamp": format_utc(event.timestamp),
        "timestamp_display": _display(event.timestamp, timezone_name),
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "dst_ip": event.dst_ip,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "session_id": event.session_id,
        "username": event.username,
        "command": redact_embedded_secrets(event.command) if event.command else None,
        "artifact_sha256": event.artifact_sha256,
        "source_file": event.source_file,
        "source_line": event.source_line,
        "parser_version": event.parser_version,
        "ingested_at": format_utc(event.ingested_at),
        "ingested_at_display": _display(event.ingested_at, timezone_name),
        "details": safe_json_value(redact_mapping(event.details or {})),
    }
    if include_raw:
        row["raw_payload"] = safe_json_value(raw)
    return row


def session_to_dict(
    session: HoneypotSession,
    *,
    timezone_name: str = "UTC",
    risk: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = safe_json_value(redact_mapping(session.session_metadata or {}))
    row: dict[str, Any] = {
        "session_uuid": str(session.id),
        "source_engine": session.source_engine,
        "source_session_id": session.source_session_id,
        "src_ip": session.src_ip,
        "first_seen_at": format_utc(session.first_seen_at),
        "first_seen_display": _display(session.first_seen_at, timezone_name),
        "last_seen_at": format_utc(session.last_seen_at),
        "last_seen_display": _display(session.last_seen_at, timezone_name),
        "event_count": session.event_count,
        "metadata": metadata,
        "duration_seconds": metadata.get("duration_seconds", 0),
        "command_count": metadata.get("command_count", 0),
        "auth_failures": metadata.get("auth_failures", 0),
        "auth_successes": metadata.get("auth_successes", 0),
        "download_count": metadata.get("download_count", 0),
        "protocols": metadata.get("protocols", []),
        "dst_ports": metadata.get("dst_ports", []),
        "commands": metadata.get("command_sequence", []),
    }
    if risk is not None:
        row.update(
            {
                "risk_score": risk.get("risk_score"),
                "risk_level": risk.get("risk_level"),
                "detection_method": risk.get("detection_method"),
                "model_version": risk.get("model_version"),
            }
        )
    return row


def detection_to_dict(
    detection: Detection,
    *,
    timezone_name: str = "UTC",
    session: HoneypotSession | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "detection_id": str(detection.id),
        "session_uuid": str(detection.session_id) if detection.session_id else None,
        "event_id": str(detection.event_id) if detection.event_id else None,
        "detection_method": detection.detection_method,
        "risk_score": detection.risk_score,
        "risk_level": detection.risk_level,
        "model_version": detection.model_version,
        "confidence": detection.confidence,
        "evidence": safe_json_value(redact_mapping(detection.evidence or {})),
        "explanation": (
            safe_json_value(redact_mapping(detection.explanation))
            if detection.explanation
            else None
        ),
        "created_at": format_utc(detection.created_at),
        "created_at_display": _display(detection.created_at, timezone_name),
    }
    if session is not None:
        row.update(
            {
                "source_engine": session.source_engine,
                "source_session_id": session.source_session_id,
                "src_ip": session.src_ip,
                "first_seen_at": format_utc(session.first_seen_at),
                "first_seen_display": _display(session.first_seen_at, timezone_name),
                "event_count": session.event_count,
            }
        )
    return row


def artifact_to_dict(artifact: Artifact, *, timezone_name: str = "UTC") -> dict[str, Any]:
    return {
        "artifact_id": str(artifact.id),
        "source_engine": artifact.source_engine,
        "sha256": artifact.sha256,
        "file_size": artifact.file_size,
        "detected_type": artifact.detected_type,
        "storage_path": artifact.storage_path,
        "first_seen_at": format_utc(artifact.first_seen_at),
        "first_seen_display": _display(artifact.first_seen_at, timezone_name),
        "metadata": safe_json_value(redact_mapping(artifact.artifact_metadata or {})),
    }


def ingestion_run_to_dict(run: IngestionRun, *, timezone_name: str = "UTC") -> dict[str, Any]:
    return {
        "run_id": str(run.id),
        "source_engine": run.source_engine,
        "source_file": run.source_file,
        "started_at": format_utc(run.started_at),
        "started_at_display": _display(run.started_at, timezone_name),
        "finished_at": format_utc(run.finished_at),
        "finished_at_display": _display(run.finished_at, timezone_name),
        "records_read": run.records_read,
        "records_created": run.records_created,
        "records_skipped": run.records_skipped,
        "records_failed": run.records_failed,
        "status": run.status,
        "error_summary": (
            redact_embedded_secrets(run.error_summary) if run.error_summary else None
        ),
    }


def parser_failure_to_dict(failure: ParserFailure, *, timezone_name: str = "UTC") -> dict[str, Any]:
    return {
        "failure_id": str(failure.id),
        "source_engine": failure.source_engine,
        "source_file": failure.source_file,
        "line_number": failure.line_number,
        "error": redact_embedded_secrets(failure.error),
        "raw_excerpt": redact_embedded_secrets(failure.raw_excerpt),
        "created_at": format_utc(failure.created_at),
        "created_at_display": _display(failure.created_at, timezone_name),
    }


def pcap_capture_to_dict(capture: PcapCapture, *, timezone_name: str = "UTC") -> dict[str, Any]:
    return {
        "capture_id": str(capture.id),
        "filename": capture.filename,
        "sha256": capture.sha256,
        "file_size": capture.file_size,
        "packet_count": capture.packet_count,
        "flow_count": capture.flow_count,
        "truncated": capture.truncated,
        "imported_at": format_utc(capture.imported_at),
        "imported_at_display": _display(capture.imported_at, timezone_name),
        "metadata": safe_json_value(redact_mapping(capture.capture_metadata or {})),
    }


def pcap_flow_to_dict(flow: PcapFlow, *, timezone_name: str = "UTC") -> dict[str, Any]:
    return {
        "flow_id": str(flow.id),
        "capture_id": str(flow.capture_id),
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "first_seen_at": format_utc(flow.first_seen_at),
        "first_seen_display": _display(flow.first_seen_at, timezone_name),
        "last_seen_at": format_utc(flow.last_seen_at),
        "last_seen_display": _display(flow.last_seen_at, timezone_name),
        "metadata": safe_json_value(redact_mapping(flow.flow_metadata or {})),
    }


__all__ = [
    "artifact_to_dict",
    "detection_to_dict",
    "event_to_dict",
    "ingestion_run_to_dict",
    "parser_failure_to_dict",
    "pcap_capture_to_dict",
    "pcap_flow_to_dict",
    "session_to_dict",
]
