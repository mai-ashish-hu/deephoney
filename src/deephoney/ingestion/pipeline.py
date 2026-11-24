"""File and follow-mode ingestion pipeline.

The pipeline is intentionally conservative:

* one malformed record never stops the file;
* parser failures are persisted with a bounded raw excerpt;
* events are idempotent through a deterministic source content hash;
* sessions and Stage A detections are rebuilt only for affected identifiers.
"""

from __future__ import annotations

import shutil
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from deephoney.collectors.follower import FileTailer
from deephoney.config.logging import get_logger
from deephoney.config.settings import Settings
from deephoney.parsers import get_parser
from deephoney.parsers.base import ParseFailure, ParseSuccess
from deephoney.schemas.events import SourceEngine
from deephoney.storage.repository import Repository
from deephoney.utils.jsonstream import iter_record_candidates
from deephoney.utils.time import utcnow

logger = get_logger(__name__)

MAX_RESULT_ERRORS = 100


class IngestionError(RuntimeError):
    """Raised for a fatal ingestion input problem (for example, missing file)."""


@dataclass(slots=True)
class IngestionResult:
    run_id: str
    source_engine: str
    source_file: str
    records_read: int = 0
    records_created: int = 0
    records_skipped: int = 0
    records_failed: int = 0
    status: str = "running"
    errors: list[str] = field(default_factory=list)
    errors_omitted: int = 0
    archive_path: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None

    @property
    def ok(self) -> bool:
        return self.status == "success"

    def add_error(self, message: str) -> None:
        """Record a run error without letting attacker input grow without bound."""

        if len(self.errors) < MAX_RESULT_ERRORS:
            self.errors.append(message)
        else:
            self.errors_omitted += 1

    def as_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "source_engine": self.source_engine,
            "source_file": self.source_file,
            "records_read": self.records_read,
            "records_created": self.records_created,
            "records_skipped": self.records_skipped,
            "records_failed": self.records_failed,
            "status": self.status,
            "errors": self.errors,
            "errors_omitted": self.errors_omitted,
            "archive_path": self.archive_path,
        }


class IngestionPipeline:
    def __init__(self, repository: Repository, settings: Settings) -> None:
        self.repository = repository
        self.settings = settings

    def ingest_file(
        self,
        path: str | Path,
        engine: str,
        *,
        archive: bool | None = None,
        rebuild_sessions: bool = True,
        run_detection: bool = True,
    ) -> IngestionResult:
        file_path = Path(path)
        engine_value = SourceEngine(engine).value
        if not file_path.is_file():
            raise IngestionError(f"Log file not found: {file_path}")

        should_archive = self.settings.ingestion.archive_raw if archive is None else archive
        archive_path: Path | None = None
        if should_archive:
            try:
                archive_path = self._archive_file(file_path, engine_value)
            except OSError as exc:
                raise IngestionError(f"Could not archive {file_path}: {exc}") from exc

        parser = get_parser(engine_value)
        result = IngestionResult(
            run_id=self.repository.start_ingestion_run(engine_value, str(file_path)),
            source_engine=engine_value,
            source_file=str(file_path),
            started_at=utcnow(),
            archive_path=str(archive_path) if archive_path else None,
        )
        session_ids: set[str] = set()

        try:
            for candidate in iter_record_candidates(
                file_path,
                max_record_bytes=self.settings.ingestion.max_line_bytes,
            ):
                result.records_read += 1
                if candidate.error or candidate.record is None:
                    result.records_failed += 1
                    error = candidate.error or "empty record"
                    result.add_error(f"line {candidate.line_number}: {error}")
                    self.repository.record_parser_failure(
                        source_engine=engine_value,
                        source_file=str(file_path),
                        line_number=candidate.line_number,
                        error=error,
                        raw_excerpt=candidate.raw_text[
                            : self.settings.ingestion.parser_failure_excerpt_bytes
                        ],
                    )
                    continue

                outcome = parser.parse_record(
                    candidate.record,
                    source_file=str(file_path),
                    line_number=candidate.line_number,
                    ingested_at=utcnow(),
                )
                if isinstance(outcome, ParseFailure):
                    result.records_failed += 1
                    result.add_error(f"line {outcome.line_number}: {outcome.error}")
                    self.repository.record_parser_failure(
                        source_engine=outcome.source_engine,
                        source_file=outcome.source_file,
                        line_number=outcome.line_number,
                        error=outcome.error,
                        raw_excerpt=outcome.raw_excerpt[
                            : self.settings.ingestion.parser_failure_excerpt_bytes
                        ],
                    )
                    continue

                assert isinstance(outcome, ParseSuccess)
                created = self.repository.add_event(outcome.event)
                if created:
                    result.records_created += 1
                    if outcome.event.session_id:
                        session_ids.add(outcome.event.session_id)
                else:
                    result.records_skipped += 1

            result.status = self._status(result)
            result.finished_at = utcnow()
            self.repository.finish_ingestion_run(
                result.run_id,
                records_read=result.records_read,
                records_created=result.records_created,
                records_skipped=result.records_skipped,
                records_failed=result.records_failed,
                status=result.status,
                error_summary=self._error_summary(result),
            )
        except Exception as exc:
            result.status = "failed"
            result.add_error(f"fatal: {type(exc).__name__}: {exc}")
            result.finished_at = utcnow()
            self.repository.finish_ingestion_run(
                result.run_id,
                records_read=result.records_read,
                records_created=result.records_created,
                records_skipped=result.records_skipped,
                records_failed=result.records_failed,
                status="failed",
                error_summary=self._error_summary(result),
            )
            logger.exception(
                "ingestion failed",
                extra={"engine": engine_value, "source_file": str(file_path)},
            )

        if session_ids and rebuild_sessions:
            self.repository.rebuild_sessions(engine=engine_value, session_ids=session_ids)
            if run_detection:
                self._run_detection(engine_value, session_ids)
        if archive_path is not None:
            logger.info("archived raw log at %s", archive_path)
        logger.info(
            "ingested %s records from %s: created=%s skipped=%s failed=%s status=%s",
            result.records_read,
            file_path,
            result.records_created,
            result.records_skipped,
            result.records_failed,
            result.status,
            extra={
                "engine": engine_value,
                "source_file": str(file_path),
                "records_read": result.records_read,
                "records_created": result.records_created,
                "records_failed": result.records_failed,
            },
        )
        return result

    def ingest_glob(
        self,
        pattern: str,
        engine: str,
        *,
        archive: bool | None = None,
        run_detection: bool = True,
    ) -> list[IngestionResult]:
        from glob import glob

        results = [
            self.ingest_file(path, engine, archive=archive, run_detection=run_detection)
            for path in sorted(glob(pattern))
            if Path(path).is_file()
        ]
        return results

    def follow(
        self,
        sources: Iterable[tuple[str, str]],
        *,
        once: bool = False,
    ) -> None:
        """Tail log globs continuously.

        Offsets are persisted in ``ingestion_offsets``.  On restart, a file
        that has grown since the last offset is resumed; deduplication makes
        re-reading safe even if offsets are lost.
        """

        tailers: dict[tuple[str, str], FileTailer] = {}
        logger.info("starting follow mode; Ctrl-C to stop")
        try:
            while True:
                did_work = False
                for engine, pattern in sources:
                    from glob import glob

                    for raw_path in sorted(glob(pattern)):
                        path = Path(raw_path)
                        if not path.is_file():
                            continue
                        key = (engine, str(path))
                        tailer = tailers.get(key)
                        if tailer is None:
                            stored = self.repository.get_offset(str(path))
                            start_offset = (
                                stored.byte_offset
                                if stored and stored.byte_offset <= path.stat().st_size
                                else 0
                            )
                            tailer = FileTailer(path, offset=start_offset)
                            tailers[key] = tailer
                        lines = tailer.read_complete_lines()
                        if lines:
                            did_work = True
                            self._process_tail_batch(engine, path, lines)
                            stat = path.stat()
                            self.repository.set_offset(
                                str(path),
                                SourceEngine(engine).value,
                                tailer.committed_offset,
                                stat.st_size,
                                stat.st_mtime,
                            )
                if once:
                    break
                if not did_work:
                    time.sleep(self.settings.ingestion.follow_interval_seconds)
        except KeyboardInterrupt:
            logger.info("follow mode stopped")
        finally:
            for (engine, source), tailer in tailers.items():
                remaining = tailer.drain()
                if remaining:
                    self._process_tail_batch(engine, Path(source), remaining)

    def _process_tail_batch(self, engine: str, path: Path, lines: list[str]) -> None:
        engine_value = SourceEngine(engine).value
        parser = get_parser(engine_value)
        result = IngestionResult(
            run_id=self.repository.start_ingestion_run(engine_value, str(path)),
            source_engine=engine_value,
            source_file=str(path),
            started_at=utcnow(),
        )
        session_ids: set[str] = set()
        for line in lines:
            result.records_read += 1
            outcome = parser.parse_line(
                line,
                source_file=str(path),
                line_number=None,
                ingested_at=utcnow(),
            )
            if isinstance(outcome, ParseFailure):
                result.records_failed += 1
                result.add_error(f"line {outcome.line_number}: {outcome.error}")
                self.repository.record_parser_failure(
                    source_engine=outcome.source_engine,
                    source_file=outcome.source_file,
                    line_number=outcome.line_number,
                    error=outcome.error,
                    raw_excerpt=outcome.raw_excerpt[
                        : self.settings.ingestion.parser_failure_excerpt_bytes
                    ],
                )
                continue
            created = self.repository.add_event(outcome.event)
            if created:
                result.records_created += 1
                if outcome.event.session_id:
                    session_ids.add(outcome.event.session_id)
            else:
                result.records_skipped += 1
        result.status = self._status(result)
        result.finished_at = utcnow()
        self.repository.finish_ingestion_run(
            result.run_id,
            records_read=result.records_read,
            records_created=result.records_created,
            records_skipped=result.records_skipped,
            records_failed=result.records_failed,
            status=result.status,
            error_summary=self._error_summary(result),
        )
        if session_ids:
            self.repository.rebuild_sessions(engine=engine_value, session_ids=session_ids)
            self._run_detection(engine_value, session_ids)
        logger.info(
            "tail batch %s: read=%s created=%s skipped=%s failed=%s",
            path,
            result.records_read,
            result.records_created,
            result.records_skipped,
            result.records_failed,
        )

    def _run_detection(self, engine: str, session_ids: set[str]) -> None:
        try:
            from deephoney.detection.service import run_rules_for_sessions

            run_rules_for_sessions(
                self.repository,
                self.settings,
                engine=engine,
                session_ids=session_ids,
            )
        except Exception:
            logger.exception("post-ingestion rule detection failed")

    def _archive_file(self, path: Path, engine: str) -> Path:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        target_dir = self.settings.raw_dir / engine / datetime.now(UTC).strftime("%Y-%m-%d")
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / f"{stamp}-{path.name}"
        counter = 1
        while target.exists():
            target = target_dir / f"{stamp}-{counter}-{path.name}"
            counter += 1
        shutil.copy2(path, target)
        return target

    @staticmethod
    def _status(result: IngestionResult) -> str:
        if result.records_read == 0:
            return "empty"
        if result.records_failed == 0:
            return "success"
        if result.records_created or result.records_skipped:
            return "partial"
        return "failed"

    @staticmethod
    def _error_summary(result: IngestionResult) -> str | None:
        parts = list(result.errors[:20])
        if result.errors_omitted:
            parts.append(f"... {result.errors_omitted} additional error(s) omitted")
        if not parts:
            return None
        return "\n".join(parts)[:8000]


__all__ = ["IngestionError", "IngestionPipeline", "IngestionResult"]
