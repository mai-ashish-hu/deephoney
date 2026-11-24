"""Detection orchestration against stored sessions."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from deephoney.config.logging import get_logger
from deephoney.config.settings import Settings
from deephoney.detection.rules.engine import evaluate_rules
from deephoney.features.extractor import SessionFeatures, extract_features
from deephoney.sessions.reconstruction import SessionRecord
from deephoney.storage.repository import Repository

logger = get_logger(__name__)

RECENT_SOURCE_WINDOW = timedelta(hours=24)


def features_for_record(repository: Repository, record: SessionRecord) -> SessionFeatures:
    features = extract_features(record)
    if record.src_ip:
        features.src_ip_session_count = repository.count_sessions_for_ip(
            record.src_ip,
            since=record.first_seen_at - RECENT_SOURCE_WINDOW,
            until=record.last_seen_at,
        )
    return features


def run_rules_for_sessions(
    repository: Repository,
    settings: Settings,
    *,
    engine: str | None = None,
    session_ids: set[str] | None = None,
) -> int:
    """Evaluate Stage A rules for selected (or all) sessions."""

    if session_ids is not None and not session_ids:
        return 0
    records = repository.get_session_records(engine=engine, session_ids=session_ids)
    saved = 0
    for record in records:
        features = features_for_record(repository, record)
        result = evaluate_rules(
            features,
            medium_threshold=settings.detection.medium_threshold,
            high_threshold=settings.detection.high_threshold,
            rules_version=settings.detection.rules_version,
            max_evidence_items=settings.detection.max_evidence_items,
        )
        if repository.save_detection(result):
            saved += 1
    logger.info("rule detection evaluated %s sessions (%s saved)", len(records), saved)
    return saved


def run_ml_for_sessions(
    repository: Repository,
    settings: Settings,
    *,
    engine: str | None = None,
    session_ids: set[str] | None = None,
    model_path: str | Path | None = None,
) -> int:
    """Run a trained classical model, if one is available."""

    if session_ids is not None and not session_ids:
        return 0
    from deephoney.detection.classical.model import load_detector

    detector = load_detector(model_path or settings.model_dir)
    if detector is None:
        logger.warning("no classical model found in %s", settings.model_dir)
        return 0
    records = repository.get_session_records(engine=engine, session_ids=session_ids)
    saved = 0
    for record in records:
        features = features_for_record(repository, record)
        try:
            result = detector.score(
                features,
                medium_threshold=settings.detection.medium_threshold,
                high_threshold=settings.detection.high_threshold,
            )
        except ValueError as exc:
            logger.warning("model skipped session %s: %s", record.source_session_id, exc)
            continue
        if repository.save_detection(result):
            saved += 1
    logger.info("classical model evaluated %s sessions (%s saved)", len(records), saved)
    return saved


def run_sequence_for_sessions(
    repository: Repository,
    settings: Settings,
    *,
    engine: str | None = None,
    session_ids: set[str] | None = None,
    model_path: str | Path | None = None,
) -> int:
    """Run the optional experimental command-sequence model.

    The model is only attempted when PyTorch and a registered checkpoint are
    available.  Absence of either is an observable, non-fatal condition: the
    rules and classical stages remain the supported baseline.
    """

    if session_ids is not None and not session_ids:
        return 0
    try:
        from deephoney.detection.sequence.model import load_sequence_detector
    except ImportError:
        logger.warning("sequence model unavailable: PyTorch is not installed")
        return 0

    detector = load_sequence_detector(model_path or settings.model_dir)
    if detector is None:
        logger.warning("no sequence model found in %s", settings.model_dir)
        return 0
    records = repository.get_session_records(engine=engine, session_ids=session_ids)
    saved = 0
    for record in records:
        features = features_for_record(repository, record)
        if not features.command_sequence:
            continue
        try:
            result = detector.score(
                features,
                medium_threshold=settings.detection.medium_threshold,
                high_threshold=settings.detection.high_threshold,
            )
        except (ValueError, RuntimeError) as exc:
            logger.warning("sequence model skipped session %s: %s", record.source_session_id, exc)
            continue
        if repository.save_detection(result):
            saved += 1
    logger.info("sequence model evaluated %s sessions (%s saved)", len(records), saved)
    return saved


def run_detection(
    repository: Repository,
    settings: Settings,
    *,
    include_ml: bool | None = None,
    include_sequence: bool | None = None,
    engine: str | None = None,
    session_ids: set[str] | None = None,
) -> dict[str, int]:
    """Run rules and, when configured, the classical and sequence models."""

    results = {
        "rules": run_rules_for_sessions(
            repository, settings, engine=engine, session_ids=session_ids
        ),
        "ml": 0,
        "sequence": 0,
    }
    use_ml = settings.detection.ml_enabled if include_ml is None else include_ml
    if use_ml:
        results["ml"] = run_ml_for_sessions(
            repository, settings, engine=engine, session_ids=session_ids
        )
    use_sequence = (
        settings.detection.sequence_enabled if include_sequence is None else include_sequence
    )
    if use_sequence:
        results["sequence"] = run_sequence_for_sessions(
            repository, settings, engine=engine, session_ids=session_ids
        )
    return results


__all__ = [
    "RECENT_SOURCE_WINDOW",
    "features_for_record",
    "run_detection",
    "run_ml_for_sessions",
    "run_rules_for_sessions",
    "run_sequence_for_sessions",
]
