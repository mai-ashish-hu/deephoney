"""Database repository.

The repository is deliberately explicit: every query is bounded, filters are
parameterized through SQLAlchemy, and raw payloads are redacted at the
serialization boundary.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from deephoney.schemas.detections import DetectionResult
from deephoney.schemas.events import EventType, NormalizedEvent, SourceEngine
from deephoney.sessions.reconstruction import SessionRecord, reconstruct_sessions
from deephoney.storage.database import Database
from deephoney.storage.models import (
    Artifact,
    Detection,
    Event,
    HoneypotSession,
    IngestionOffset,
    IngestionRun,
    ParserFailure,
    PcapCapture,
    PcapFlow,
)
from deephoney.storage.serializers import (
    artifact_to_dict,
    detection_to_dict,
    event_to_dict,
    ingestion_run_to_dict,
    parser_failure_to_dict,
    pcap_capture_to_dict,
    pcap_flow_to_dict,
    session_to_dict,
)
from deephoney.utils.hashing import sha256_json
from deephoney.utils.redaction import safe_json_value
from deephoney.utils.time import utcnow

MAX_PAGE_SIZE = 500
MAX_EXPORT_ROWS = 100_000


@dataclass(slots=True)
class EventFilters:
    start: datetime | None = None
    end: datetime | None = None
    engines: tuple[str, ...] = ()
    event_types: tuple[str, ...] = ()
    protocol: str | None = None
    src_ip: str | None = None
    session_id: str | None = None
    search: str | None = None


@dataclass(slots=True)
class SessionFilters:
    start: datetime | None = None
    end: datetime | None = None
    engines: tuple[str, ...] = ()
    src_ip: str | None = None
    risk_levels: tuple[str, ...] = ()
    min_risk_score: int | None = None


@dataclass(slots=True)
class DetectionFilters:
    start: datetime | None = None
    end: datetime | None = None
    engines: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    risk_levels: tuple[str, ...] = ()
    min_risk_score: int | None = None


@dataclass(slots=True)
class ArtifactMetadata:
    sha256: str
    file_size: int | None = None
    detected_type: str | None = None
    filenames: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _event_conditions(filters: EventFilters) -> list[Any]:
    conditions: list[Any] = []
    if filters.start is not None:
        conditions.append(Event.timestamp >= filters.start)
    if filters.end is not None:
        conditions.append(Event.timestamp <= filters.end)
    if filters.engines:
        conditions.append(Event.source_engine.in_(filters.engines))
    if filters.event_types:
        conditions.append(Event.event_type.in_(filters.event_types))
    if filters.protocol:
        conditions.append(Event.protocol == filters.protocol.lower())
    if filters.src_ip:
        conditions.append(Event.src_ip == filters.src_ip.strip())
    if filters.session_id:
        conditions.append(Event.session_id == filters.session_id.strip())
    if filters.search:
        pattern = f"%{_escape_like(filters.search.strip())}%"
        conditions.append(
            or_(
                Event.command.ilike(pattern, escape="\\"),
                Event.username.ilike(pattern, escape="\\"),
                Event.src_ip.ilike(pattern, escape="\\"),
                Event.source_event_id.ilike(pattern, escape="\\"),
            )
        )
    return conditions


def _session_conditions(filters: SessionFilters) -> list[Any]:
    conditions: list[Any] = []
    if filters.start is not None:
        conditions.append(HoneypotSession.last_seen_at >= filters.start)
    if filters.end is not None:
        conditions.append(HoneypotSession.last_seen_at <= filters.end)
    if filters.engines:
        conditions.append(HoneypotSession.source_engine.in_(filters.engines))
    if filters.src_ip:
        conditions.append(HoneypotSession.src_ip == filters.src_ip.strip())
    if filters.risk_levels:
        subquery = (
            select(Detection.session_id)
            .where(Detection.risk_level.in_(filters.risk_levels))
            .distinct()
        )
        conditions.append(HoneypotSession.id.in_(subquery))
    if filters.min_risk_score is not None:
        subquery = (
            select(Detection.session_id)
            .where(Detection.risk_score >= filters.min_risk_score)
            .distinct()
        )
        conditions.append(HoneypotSession.id.in_(subquery))
    return conditions


def _artifact_metadata_from_event(event: NormalizedEvent) -> ArtifactMetadata | None:
    if not event.artifact_sha256:
        return None
    details = event.details if isinstance(event.details, dict) else {}
    file_meta: dict[str, Any] = {}
    for key in ("download", "capture", "file"):
        value = details.get(key)
        if isinstance(value, dict):
            file_meta.update(value)
    for key in ("filename", "outfile", "size", "file_size", "file_type", "mime_type", "url"):
        if details.get(key) is not None and key not in file_meta:
            file_meta[key] = details[key]

    size: int | None = None
    for key in ("size", "file_size"):
        try:
            candidate = int(str(file_meta.get(key)), 10)
        except (TypeError, ValueError):
            continue
        if candidate >= 0:
            size = candidate
            break

    detected_type = file_meta.get("file_type") or file_meta.get("mime_type")
    metadata = ArtifactMetadata(
        sha256=event.artifact_sha256,
        file_size=size,
        detected_type=str(detected_type)[:128] if detected_type else None,
    )
    for key in ("filename", "outfile"):
        if file_meta.get(key):
            metadata.filenames.add(str(file_meta[key])[:512])
    if file_meta.get("url"):
        metadata.urls.add(str(file_meta["url"])[:2048])
    return metadata


class Repository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add_event(self, event: NormalizedEvent) -> bool:
        """Insert one normalized event; return False for a duplicate."""

        try:
            with self.database.session() as db:
                exists = db.scalar(select(Event.id).where(Event.event_hash == event.event_hash))
                if exists is not None:
                    return False
                db.add(
                    Event(
                        id=uuid.UUID(event.event_id),
                        event_hash=event.event_hash,
                        source_engine=event.source_engine.value,
                        source_event_id=event.source_event_id,
                        event_type=event.event_type.value,
                        timestamp=event.timestamp,
                        src_ip=event.src_ip,
                        src_port=event.src_port,
                        dst_ip=event.dst_ip,
                        dst_port=event.dst_port,
                        protocol=event.protocol,
                        session_id=event.session_id,
                        username=event.username,
                        command=event.command,
                        artifact_sha256=event.artifact_sha256,
                        raw_payload=event.raw_event,
                        details=event.details,
                        source_file=event.source_file,
                        source_line=event.source_line,
                        parser_version=event.parser_version,
                        ingested_at=event.ingested_at,
                    )
                )
        except IntegrityError:
            return False
        artifact = _artifact_metadata_from_event(event)
        if artifact is not None:
            self._upsert_artifact(event.source_engine.value, artifact)
        return True

    def stream_event_hashes(self, limit: int = 100_000) -> set[str]:
        """Small helper used by tests and maintenance scripts."""

        with self.database.session() as db:
            rows = db.scalars(select(Event.event_hash).limit(limit)).all()
        return set(rows)

    def _upsert_artifact(self, engine: str, metadata: ArtifactMetadata) -> None:
        for attempt in range(2):
            try:
                with self.database.session() as db:
                    existing = db.scalar(
                        select(Artifact).where(
                            Artifact.source_engine == engine,
                            Artifact.sha256 == metadata.sha256,
                        )
                    )
                    if existing is None:
                        db.add(
                            Artifact(
                                id=uuid.uuid4(),
                                source_engine=engine,
                                sha256=metadata.sha256,
                                file_size=metadata.file_size,
                                detected_type=metadata.detected_type,
                                storage_path=None,
                                first_seen_at=utcnow(),
                                artifact_metadata={
                                    "filenames": sorted(metadata.filenames)[:20],
                                    "urls": sorted(metadata.urls)[:20],
                                    "note": (
                                        "metadata only; binary content stays in the "
                                        "honeypot artifact store"
                                    ),
                                },
                            )
                        )
                        return

                    if metadata.file_size is not None:
                        existing.file_size = max(existing.file_size or 0, metadata.file_size)
                    if metadata.detected_type:
                        existing.detected_type = metadata.detected_type[:128]
                    meta = dict(existing.artifact_metadata or {})
                    filenames = set(meta.get("filenames", [])) | metadata.filenames
                    urls = set(meta.get("urls", [])) | metadata.urls
                    meta["filenames"] = sorted(filenames)[:20]
                    meta["urls"] = sorted(urls)[:20]
                    existing.artifact_metadata = meta
                    return
            except IntegrityError:
                if attempt:
                    raise

    def start_ingestion_run(self, source_engine: str, source_file: str) -> str:
        run_id = uuid.uuid4()
        with self.database.session() as db:
            db.add(
                IngestionRun(
                    id=run_id,
                    source_engine=source_engine,
                    source_file=str(source_file),
                    started_at=utcnow(),
                    status="running",
                )
            )
        return str(run_id)

    def finish_ingestion_run(
        self,
        run_id: str,
        *,
        records_read: int,
        records_created: int,
        records_skipped: int,
        records_failed: int,
        status: str,
        error_summary: str | None = None,
    ) -> None:
        with self.database.session() as db:
            row = db.get(IngestionRun, uuid.UUID(run_id))
            if row is None:
                return
            row.finished_at = utcnow()
            row.records_read = records_read
            row.records_created = records_created
            row.records_skipped = records_skipped
            row.records_failed = records_failed
            row.status = status
            row.error_summary = error_summary

    def record_parser_failure(
        self,
        *,
        source_engine: str,
        source_file: str,
        line_number: int | None,
        error: str,
        raw_excerpt: str,
    ) -> None:
        with self.database.session() as db:
            db.add(
                ParserFailure(
                    id=uuid.uuid4(),
                    source_engine=source_engine,
                    source_file=str(source_file),
                    line_number=line_number,
                    error=error[:4000],
                    raw_excerpt=raw_excerpt[:20_000],
                    created_at=utcnow(),
                )
            )

    def get_offset(self, source_file: str) -> IngestionOffset | None:
        with self.database.session() as db:
            return db.get(IngestionOffset, str(source_file))

    def set_offset(
        self, source_file: str, engine: str, offset: int, size: int, mtime: float
    ) -> None:
        with self.database.session() as db:
            row = db.get(IngestionOffset, str(source_file))
            if row is None:
                db.add(
                    IngestionOffset(
                        source_file=str(source_file),
                        source_engine=engine,
                        byte_offset=offset,
                        file_size=size,
                        mtime=mtime,
                    )
                )
            else:
                row.byte_offset = offset
                row.file_size = size
                row.mtime = mtime
                row.updated_at = utcnow()

    def _save_session(self, db: Session, record: SessionRecord) -> uuid.UUID:
        session_uuid = uuid.UUID(record.id)
        row = db.get(HoneypotSession, session_uuid)
        if row is None:
            row = HoneypotSession(
                id=session_uuid,
                source_engine=record.source_engine,
                source_session_id=record.source_session_id,
                src_ip=record.src_ip,
                first_seen_at=record.first_seen_at,
                last_seen_at=record.last_seen_at,
                event_count=record.event_count,
                session_metadata=record.metadata,
            )
            db.add(row)
        else:
            row.src_ip = record.src_ip
            row.first_seen_at = record.first_seen_at
            row.last_seen_at = record.last_seen_at
            row.event_count = record.event_count
            row.session_metadata = record.metadata
            row.updated_at = utcnow()
        return session_uuid

    def save_session(self, record: SessionRecord) -> str:
        with self.database.session() as db:
            return str(self._save_session(db, record))

    def rebuild_sessions(
        self,
        *,
        engine: str | None = None,
        session_ids: set[str] | None = None,
        prune: bool = False,
    ) -> int:
        with self.database.session() as db:
            stmt = select(Event).where(Event.session_id.is_not(None))
            if engine:
                stmt = stmt.where(Event.source_engine == engine)
            if session_ids is not None:
                stmt = stmt.where(Event.session_id.in_(session_ids))
            rows = db.scalars(stmt.execution_options(yield_per=1000)).all()
        records = reconstruct_sessions(
            [self._row_to_event(row) for row in rows],
            engine=engine,
            session_ids=session_ids,
        )
        with self.database.session() as db:
            for index, record in enumerate(records, start=1):
                self._save_session(db, record)
                if index % 500 == 0:
                    db.flush()
        if prune and engine:
            keep = {uuid.UUID(record.id) for record in records}
            with self.database.session() as db:
                statement = select(HoneypotSession.id).where(
                    HoneypotSession.source_engine == engine
                )
                if keep:
                    statement = statement.where(HoneypotSession.id.not_in(keep))
                stale = db.scalars(statement).all()
                if stale:
                    db.execute(delete(Detection).where(Detection.session_id.in_(stale)))
                    db.execute(delete(HoneypotSession).where(HoneypotSession.id.in_(stale)))
        return len(records)

    def _row_to_event(self, row: Event) -> NormalizedEvent:
        try:
            engine = SourceEngine(row.source_engine)
        except ValueError:
            engine = SourceEngine.COWRIE
        try:
            event_type = EventType(row.event_type)
        except ValueError:
            event_type = EventType.UNKNOWN
        return NormalizedEvent(
            event_id=str(row.id),
            event_hash=row.event_hash,
            source_engine=engine,
            source_event_id=row.source_event_id,
            event_type=event_type,
            timestamp=row.timestamp,
            src_ip=row.src_ip,
            src_port=row.src_port,
            dst_ip=row.dst_ip,
            dst_port=row.dst_port,
            protocol=row.protocol,
            session_id=row.session_id,
            username=row.username,
            command=row.command,
            artifact_sha256=row.artifact_sha256,
            raw_event=row.raw_payload,
            source_file=row.source_file,
            source_line=row.source_line,
            ingested_at=row.ingested_at,
            parser_version=row.parser_version,
            details=row.details or {},
        )

    def save_detection(self, detection: DetectionResult) -> str | None:
        with self.database.session() as db:
            session_row = db.scalar(
                select(HoneypotSession).where(
                    HoneypotSession.source_engine == detection.source_engine,
                    HoneypotSession.source_session_id == detection.session_id,
                )
            )
            if session_row is None:
                return None
            existing = db.scalar(
                select(Detection).where(
                    Detection.session_id == session_row.id,
                    Detection.detection_method == detection.detection_method.value,
                    Detection.model_version == detection.model_version,
                )
            )
            evidence = safe_json_value(detection.evidence)
            explanation = safe_json_value(detection.explanation) if detection.explanation else None
            if existing is None:
                existing = Detection(
                    id=uuid.uuid4(),
                    session_id=session_row.id,
                    detection_method=detection.detection_method.value,
                    risk_score=detection.risk_score,
                    risk_level=detection.risk_level.value,
                    model_version=detection.model_version,
                    confidence=detection.confidence,
                    evidence=evidence,
                    explanation=explanation,
                    created_at=utcnow(),
                )
                db.add(existing)
            else:
                existing.risk_score = detection.risk_score
                existing.risk_level = detection.risk_level.value
                existing.confidence = detection.confidence
                existing.evidence = evidence
                existing.explanation = explanation
                existing.created_at = utcnow()
        return str(existing.id)

    def get_session_row(self, session_id: str | uuid.UUID) -> HoneypotSession | None:
        try:
            key = session_id if isinstance(session_id, uuid.UUID) else uuid.UUID(str(session_id))
        except ValueError:
            return None
        with self.database.session() as db:
            return db.get(HoneypotSession, key)

    def get_session_row_by_source(
        self, source_engine: str, source_session_id: str
    ) -> HoneypotSession | None:
        with self.database.session() as db:
            return db.scalar(
                select(HoneypotSession).where(
                    HoneypotSession.source_engine == source_engine,
                    HoneypotSession.source_session_id == source_session_id,
                )
            )

    def get_session_events(
        self, session_uuid: str | uuid.UUID, *, limit: int = MAX_EXPORT_ROWS
    ) -> list[Event]:
        row = self.get_session_row(session_uuid)
        if row is None:
            return []
        with self.database.session() as db:
            return list(
                db.scalars(
                    select(Event)
                    .where(
                        Event.source_engine == row.source_engine,
                        Event.session_id == row.source_session_id,
                    )
                    .order_by(
                        Event.timestamp.asc().nullslast(),
                        Event.source_line.asc().nullslast(),
                        Event.ingested_at.asc(),
                        Event.id.asc(),
                    )
                    .limit(min(max(1, limit), MAX_EXPORT_ROWS))
                ).all()
            )

    def get_serialized_session_events(
        self,
        session_uuid: str | uuid.UUID,
        *,
        timezone_name: str = "UTC",
    ) -> list[dict[str, Any]]:
        return [
            event_to_dict(row, timezone_name=timezone_name)
            for row in self.get_session_events(session_uuid)
        ]

    def get_detections_for_session(
        self,
        session_uuid: str | uuid.UUID,
        *,
        timezone_name: str = "UTC",
    ) -> list[dict[str, Any]]:
        try:
            key = uuid.UUID(str(session_uuid))
        except ValueError:
            return []
        with self.database.session() as db:
            session_row = db.get(HoneypotSession, key)
            rows = db.scalars(
                select(Detection)
                .where(Detection.session_id == key)
                .order_by(
                    Detection.risk_score.desc(), Detection.created_at.desc(), Detection.id.asc()
                )
            ).all()
            return [
                detection_to_dict(row, session=session_row, timezone_name=timezone_name)
                for row in rows
            ]

    def distinct_event_types(self) -> list[str]:
        with self.database.session() as db:
            rows = db.scalars(select(Event.event_type).distinct().order_by(Event.event_type)).all()
        return [str(row) for row in rows]

    def distinct_protocols(self) -> list[str]:
        with self.database.session() as db:
            rows = db.scalars(
                select(Event.protocol)
                .where(Event.protocol.is_not(None))
                .distinct()
                .order_by(Event.protocol)
            ).all()
        return [str(row) for row in rows]

    def get_session_records(
        self,
        *,
        engine: str | None = None,
        session_ids: set[str] | None = None,
    ) -> list[SessionRecord]:
        with self.database.session() as db:
            stmt = select(Event).where(Event.session_id.is_not(None))
            if engine:
                stmt = stmt.where(Event.source_engine == engine)
            if session_ids is not None:
                stmt = stmt.where(Event.session_id.in_(session_ids))
            rows = db.scalars(stmt.execution_options(yield_per=1000)).all()
        return reconstruct_sessions(
            [self._row_to_event(row) for row in rows],
            engine=engine,
            session_ids=session_ids,
        )

    def count_sessions_for_ip(
        self, src_ip: str, *, since: datetime, until: datetime | None = None
    ) -> int:
        conditions = [
            HoneypotSession.src_ip == src_ip,
            HoneypotSession.last_seen_at >= since,
        ]
        if until is not None:
            conditions.append(HoneypotSession.first_seen_at <= until)
        with self.database.session() as db:
            return int(db.scalar(select(func.count(HoneypotSession.id)).where(*conditions)) or 0)

    def get_best_detection_map(
        self, session_ids: Sequence[uuid.UUID | str]
    ) -> dict[str, Detection]:
        keys = [uuid.UUID(str(item)) for item in session_ids]
        if not keys:
            return {}
        with self.database.session() as db:
            rows = db.scalars(
                select(Detection)
                .where(Detection.session_id.in_(keys))
                .order_by(
                    Detection.risk_score.desc(), Detection.created_at.desc(), Detection.id.asc()
                )
            ).all()
        best: dict[str, Detection] = {}
        for row in rows:
            key = str(row.session_id)
            best.setdefault(key, row)
        return best

    def query_events(
        self,
        filters: EventFilters,
        *,
        page: int = 1,
        page_size: int = 50,
        timezone_name: str = "UTC",
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, page)
        page_size = min(max(1, page_size), MAX_PAGE_SIZE)
        conditions = _event_conditions(filters)
        with self.database.session() as db:
            total = int(db.scalar(select(func.count(Event.id)).where(*conditions)) or 0)
            rows = db.scalars(
                select(Event)
                .where(*conditions)
                .order_by(
                    Event.timestamp.desc().nullslast(), Event.ingested_at.desc(), Event.id.asc()
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
            data = [event_to_dict(row, timezone_name=timezone_name) for row in rows]
        return data, total

    def query_sessions(
        self,
        filters: SessionFilters,
        *,
        page: int = 1,
        page_size: int = 50,
        timezone_name: str = "UTC",
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, page)
        page_size = min(max(1, page_size), MAX_PAGE_SIZE)
        conditions = _session_conditions(filters)
        with self.database.session() as db:
            total = int(db.scalar(select(func.count(HoneypotSession.id)).where(*conditions)) or 0)
            rows = db.scalars(
                select(HoneypotSession)
                .where(*conditions)
                .order_by(HoneypotSession.first_seen_at.desc(), HoneypotSession.id.asc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
        best = self.get_best_detection_map([row.id for row in rows])
        data = [
            session_to_dict(
                row,
                timezone_name=timezone_name,
                risk=(
                    {
                        "risk_score": best[str(row.id)].risk_score,
                        "risk_level": best[str(row.id)].risk_level,
                        "detection_method": best[str(row.id)].detection_method,
                        "model_version": best[str(row.id)].model_version,
                    }
                    if str(row.id) in best
                    else None
                ),
            )
            for row in rows
        ]
        return data, total

    def query_detections(
        self,
        filters: DetectionFilters,
        *,
        page: int = 1,
        page_size: int = 50,
        timezone_name: str = "UTC",
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, page)
        page_size = min(max(1, page_size), MAX_PAGE_SIZE)
        conditions: list[Any] = []
        if filters.start is not None:
            conditions.append(Detection.created_at >= filters.start)
        if filters.end is not None:
            conditions.append(Detection.created_at <= filters.end)
        if filters.engines:
            conditions.append(HoneypotSession.source_engine.in_(filters.engines))
        if filters.methods:
            conditions.append(Detection.detection_method.in_(filters.methods))
        if filters.risk_levels:
            conditions.append(Detection.risk_level.in_(filters.risk_levels))
        if filters.min_risk_score is not None:
            conditions.append(Detection.risk_score >= filters.min_risk_score)

        with self.database.session() as db:
            total = int(
                db.scalar(
                    select(func.count(Detection.id))
                    .select_from(Detection)
                    .join(HoneypotSession, Detection.session_id == HoneypotSession.id)
                    .where(*conditions)
                )
                or 0
            )
            rows = db.execute(
                select(Detection, HoneypotSession)
                .join(HoneypotSession, Detection.session_id == HoneypotSession.id)
                .where(*conditions)
                .order_by(
                    Detection.risk_score.desc(), Detection.created_at.desc(), Detection.id.asc()
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
            data = [
                detection_to_dict(detection, session=session, timezone_name=timezone_name)
                for detection, session in rows
            ]
        return data, total

    def overview_stats(self) -> dict[str, Any]:
        with self.database.session() as db:
            total_events = int(db.scalar(select(func.count(Event.id))) or 0)
            by_engine_rows = db.execute(
                select(Event.source_engine, func.count(Event.id))
                .group_by(Event.source_engine)
                .order_by(Event.source_engine)
            ).all()
            unique_sources = int(db.scalar(select(func.count(func.distinct(Event.src_ip)))) or 0)
            session_count = int(db.scalar(select(func.count(HoneypotSession.id))) or 0)
            artifact_count = int(db.scalar(select(func.count(Artifact.id))) or 0)
            risk_rows = db.execute(
                select(Detection.risk_level, func.count(Detection.id))
                .group_by(Detection.risk_level)
                .order_by(Detection.risk_level)
            ).all()
            last_event = db.scalar(select(func.max(Event.timestamp)))
            last_ingested = db.scalar(select(func.max(Event.ingested_at)))
            recent = db.scalars(
                select(Event)
                .order_by(
                    Event.timestamp.desc().nullslast(), Event.ingested_at.desc(), Event.id.asc()
                )
                .limit(10)
            ).all()
        return {
            "total_events": total_events,
            "by_engine": {engine: count for engine, count in by_engine_rows},
            "unique_source_ips": unique_sources,
            "session_count": session_count,
            "artifact_count": artifact_count,
            "risk_distribution": {level: count for level, count in risk_rows},
            "last_event_at": last_event,
            "last_ingested_at": last_ingested,
            "recent_events": [event_to_dict(row) for row in recent],
        }

    def event_counts_by_day(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> list[dict[str, Any]]:
        conditions: list[Any] = [Event.timestamp.is_not(None)]
        if start is not None:
            conditions.append(Event.timestamp >= start)
        if end is not None:
            conditions.append(Event.timestamp <= end)
        day = func.date(Event.timestamp)
        with self.database.session() as db:
            rows = db.execute(
                select(day.label("day"), Event.source_engine, func.count(Event.id))
                .where(*conditions)
                .group_by(day, Event.source_engine)
                .order_by(day, Event.source_engine)
            ).all()
        return [
            {"day": str(day_value), "source_engine": engine, "count": count}
            for day_value, engine, count in rows
        ]

    def sessions_by_day(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> list[dict[str, Any]]:
        conditions: list[Any] = []
        if start is not None:
            conditions.append(HoneypotSession.first_seen_at >= start)
        if end is not None:
            conditions.append(HoneypotSession.first_seen_at <= end)
        day = func.date(HoneypotSession.first_seen_at)
        with self.database.session() as db:
            rows = db.execute(
                select(
                    day.label("day"), HoneypotSession.source_engine, func.count(HoneypotSession.id)
                )
                .where(*conditions)
                .group_by(day, HoneypotSession.source_engine)
                .order_by(day, HoneypotSession.source_engine)
            ).all()
        return [
            {"day": str(day_value), "source_engine": engine, "count": count}
            for day_value, engine, count in rows
        ]

    def top_source_ips(
        self, start: datetime | None = None, end: datetime | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        conditions: list[Any] = [Event.src_ip.is_not(None)]
        if start is not None:
            conditions.append(Event.timestamp >= start)
        if end is not None:
            conditions.append(Event.timestamp <= end)
        with self.database.session() as db:
            rows = db.execute(
                select(Event.src_ip, func.count(Event.id).label("events"))
                .where(*conditions)
                .group_by(Event.src_ip)
                .order_by(func.count(Event.id).desc(), Event.src_ip.asc())
                .limit(min(max(1, limit), 100))
            ).all()
        return [{"src_ip": src_ip, "events": count} for src_ip, count in rows]

    def get_artifacts(
        self, *, engine: str | None = None, limit: int = 100, timezone_name: str = "UTC"
    ) -> list[dict[str, Any]]:
        with self.database.session() as db:
            stmt = select(Artifact)
            if engine:
                stmt = stmt.where(Artifact.source_engine == engine)
            rows = db.scalars(
                stmt.order_by(Artifact.first_seen_at.desc(), Artifact.id.asc()).limit(
                    min(max(1, limit), 1000)
                )
            ).all()
            return [artifact_to_dict(row, timezone_name=timezone_name) for row in rows]

    def get_ingestion_runs(
        self, *, limit: int = 50, engine: str | None = None, timezone_name: str = "UTC"
    ) -> list[dict[str, Any]]:
        with self.database.session() as db:
            stmt = select(IngestionRun)
            if engine:
                stmt = stmt.where(IngestionRun.source_engine == engine)
            rows = db.scalars(
                stmt.order_by(IngestionRun.started_at.desc(), IngestionRun.id.asc()).limit(
                    min(max(1, limit), 500)
                )
            ).all()
            return [ingestion_run_to_dict(row, timezone_name=timezone_name) for row in rows]

    def get_parser_failures(
        self, *, limit: int = 50, timezone_name: str = "UTC"
    ) -> list[dict[str, Any]]:
        with self.database.session() as db:
            rows = db.scalars(
                select(ParserFailure)
                .order_by(ParserFailure.created_at.desc(), ParserFailure.id.asc())
                .limit(min(max(1, limit), 500))
            ).all()
            return [parser_failure_to_dict(row, timezone_name=timezone_name) for row in rows]

    def last_event_by_engine(self) -> dict[str, datetime | None]:
        with self.database.session() as db:
            rows = db.execute(
                select(Event.source_engine, func.max(Event.timestamp))
                .group_by(Event.source_engine)
                .order_by(Event.source_engine)
            ).all()
        return {engine: timestamp for engine, timestamp in rows}

    def last_ingestion_by_engine(self) -> dict[str, dict[str, Any] | None]:
        result: dict[str, dict[str, Any] | None] = {}
        for engine in ("cowrie", "dionaea"):
            with self.database.session() as db:
                row = db.scalar(
                    select(IngestionRun)
                    .where(IngestionRun.source_engine == engine)
                    .order_by(IngestionRun.started_at.desc(), IngestionRun.id.asc())
                    .limit(1)
                )
            result[engine] = ingestion_run_to_dict(row) if row else None
        return result

    def get_pcap_captures(
        self, *, limit: int = 50, timezone_name: str = "UTC"
    ) -> list[dict[str, Any]]:
        with self.database.session() as db:
            rows = db.scalars(
                select(PcapCapture)
                .order_by(PcapCapture.imported_at.desc(), PcapCapture.id.asc())
                .limit(min(max(1, limit), 200))
            ).all()
            return [pcap_capture_to_dict(row, timezone_name=timezone_name) for row in rows]

    def get_pcap_flows(
        self, capture_id: str | uuid.UUID | None = None, *, limit: int = 500
    ) -> tuple[list[dict[str, Any]], int]:
        conditions: list[Any] = []
        if capture_id is not None:
            conditions.append(PcapFlow.capture_id == uuid.UUID(str(capture_id)))
        with self.database.session() as db:
            total = int(db.scalar(select(func.count(PcapFlow.id)).where(*conditions)) or 0)
            rows = db.scalars(
                select(PcapFlow)
                .where(*conditions)
                .order_by(PcapFlow.first_seen_at.asc(), PcapFlow.id.asc())
                .limit(min(max(1, limit), 5000))
            ).all()
            return [pcap_flow_to_dict(row) for row in rows], total

    def save_pcap_import(
        self,
        *,
        filename: str,
        sha256: str,
        file_size: int,
        packet_count: int,
        truncated: bool,
        metadata: dict[str, Any],
        flows: Iterable[dict[str, Any]],
    ) -> tuple[str, bool]:
        with self.database.session() as db:
            existing = db.scalar(select(PcapCapture).where(PcapCapture.sha256 == sha256))
            if existing is not None:
                return str(existing.id), False
            capture_id = uuid.uuid4()
            flow_list = list(flows)
            capture = PcapCapture(
                id=capture_id,
                filename=filename,
                sha256=sha256,
                file_size=file_size,
                packet_count=packet_count,
                flow_count=len(flow_list),
                truncated=truncated,
                capture_metadata=safe_json_value(metadata),
            )
            db.add(capture)
            for flow in flow_list:
                db.add(
                    PcapFlow(
                        id=uuid.uuid4(),
                        capture_id=capture_id,
                        src_ip=flow["src_ip"],
                        src_port=flow.get("src_port"),
                        dst_ip=flow["dst_ip"],
                        dst_port=flow.get("dst_port"),
                        protocol=flow.get("protocol", "ip"),
                        packet_count=flow.get("packet_count", 0),
                        byte_count=flow.get("byte_count", 0),
                        first_seen_at=flow["first_seen_at"],
                        last_seen_at=flow["last_seen_at"],
                        flow_metadata=safe_json_value(flow.get("metadata", {})),
                    )
                )
        return str(capture_id), True

    def export_events(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        engines: tuple[str, ...] = (),
        limit: int = MAX_EXPORT_ROWS,
    ) -> list[dict[str, Any]]:
        bounded = min(max(1, limit), MAX_EXPORT_ROWS)
        collected: list[dict[str, Any]] = []
        page = 1
        while len(collected) < bounded:
            rows, total = self.query_events(
                EventFilters(start=start, end=end, engines=engines),
                page=page,
                page_size=min(MAX_PAGE_SIZE, bounded - len(collected)),
            )
            collected.extend(rows)
            if not rows or len(collected) >= total:
                break
            page += 1
        return collected[:bounded]

    def export_sessions(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        engines: tuple[str, ...] = (),
        limit: int = MAX_EXPORT_ROWS,
    ) -> list[dict[str, Any]]:
        bounded = min(max(1, limit), MAX_EXPORT_ROWS)
        collected: list[dict[str, Any]] = []
        page = 1
        while len(collected) < bounded:
            rows, total = self.query_sessions(
                SessionFilters(start=start, end=end, engines=engines),
                page=page,
                page_size=min(MAX_PAGE_SIZE, bounded - len(collected)),
            )
            collected.extend(rows)
            if not rows or len(collected) >= total:
                break
            page += 1
        return collected[:bounded]

    def export_detections(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        engines: tuple[str, ...] = (),
        limit: int = MAX_EXPORT_ROWS,
    ) -> list[dict[str, Any]]:
        bounded = min(max(1, limit), MAX_EXPORT_ROWS)
        collected: list[dict[str, Any]] = []
        page = 1
        while len(collected) < bounded:
            rows, total = self.query_detections(
                DetectionFilters(start=start, end=end, engines=engines),
                page=page,
                page_size=min(MAX_PAGE_SIZE, bounded - len(collected)),
            )
            collected.extend(rows)
            if not rows or len(collected) >= total:
                break
            page += 1
        return collected[:bounded]

    def summary_counts(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> dict[str, Any]:
        conditions: list[Any] = []
        if start is not None:
            conditions.append(Event.timestamp >= start)
        if end is not None:
            conditions.append(Event.timestamp <= end)
        with self.database.session() as db:
            by_engine = db.execute(
                select(Event.source_engine, func.count(Event.id))
                .where(*conditions)
                .group_by(Event.source_engine)
                .order_by(Event.source_engine)
            ).all()
            by_type = db.execute(
                select(Event.event_type, func.count(Event.id))
                .where(*conditions)
                .group_by(Event.event_type)
                .order_by(func.count(Event.id).desc(), Event.event_type.asc())
            ).all()
            by_protocol = db.execute(
                select(Event.protocol, func.count(Event.id))
                .where(*conditions, Event.protocol.is_not(None))
                .group_by(Event.protocol)
                .order_by(func.count(Event.id).desc(), Event.protocol.asc())
            ).all()
        return {
            "by_engine": {engine: count for engine, count in by_engine},
            "by_event_type": {event_type: count for event_type, count in by_type},
            "by_protocol": {protocol: count for protocol, count in by_protocol},
        }

    def detection_counts_by_method(self) -> dict[str, int]:
        with self.database.session() as db:
            rows = db.execute(
                select(Detection.detection_method, func.count(Detection.id))
                .group_by(Detection.detection_method)
                .order_by(Detection.detection_method)
            ).all()
        return {method: count for method, count in rows}

    def get_detection(self, detection_id: str | uuid.UUID) -> Detection | None:
        try:
            key = uuid.UUID(str(detection_id))
        except ValueError:
            return None
        with self.database.session() as db:
            return db.get(Detection, key)

    def delete_event(self, event_id: str | uuid.UUID) -> bool:
        try:
            key = uuid.UUID(str(event_id))
        except ValueError:
            return False
        with self.database.session() as db:
            row = db.get(Event, key)
            if row is None:
                return False
            db.delete(row)
        return True

    def raw_event_fingerprint(self) -> str:
        with self.database.session() as db:
            rows = db.scalars(select(Event.event_hash).order_by(Event.event_hash)).all()
        return sha256_json(rows)


__all__ = [
    "ArtifactMetadata",
    "DetectionFilters",
    "EventFilters",
    "MAX_EXPORT_ROWS",
    "MAX_PAGE_SIZE",
    "Repository",
    "SessionFilters",
]
