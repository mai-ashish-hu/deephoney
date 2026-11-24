"""Integration tests for detection orchestration and model training."""

from __future__ import annotations

import pytest

from deephoney.detection.classical.model import load_detector
from deephoney.detection.classical.train import train_classical
from deephoney.detection.service import (
    features_for_record,
    run_detection,
    run_rules_for_sessions,
)
from deephoney.ingestion.pipeline import IngestionPipeline
from deephoney.storage.repository import DetectionFilters


def test_rules_run_against_stored_sessions(repository, settings, sample_paths) -> None:
    IngestionPipeline(repository, settings).ingest_file(
        sample_paths["cowrie"], "cowrie", archive=False, run_detection=False
    )
    saved = run_rules_for_sessions(repository, settings)
    assert saved >= 1
    detections, total = repository.query_detections(DetectionFilters(methods=("rule",)))
    assert total == saved
    assert all(row["evidence"]["rules_version"] == "2024.1.0" for row in detections)
    assert any(row["risk_score"] >= 60 for row in detections)


def test_source_ip_session_count_uses_session_window(repository, settings, sample_paths) -> None:
    IngestionPipeline(repository, settings).ingest_file(
        sample_paths["cowrie"], "cowrie", archive=False, run_detection=False
    )
    records = repository.get_session_records(engine="cowrie")
    assert records
    first = features_for_record(repository, records[0])
    second = features_for_record(repository, records[0])
    assert first.src_ip_session_count == 1
    assert second.src_ip_session_count == first.src_ip_session_count


def test_training_rejects_unknown_mode(settings, sample_paths, tmp_path) -> None:
    with pytest.raises(ValueError, match="mode must be"):
        train_classical(sample_paths["synthetic"], tmp_path, mode="bogus")


def test_group_split_requires_src_ip(settings, sample_paths, tmp_path) -> None:
    import pandas as pd

    dataset = tmp_path / "no-src-ip.csv"
    pd.read_csv(sample_paths["synthetic"]).drop(columns=["src_ip"]).to_csv(dataset, index=False)
    with pytest.raises(ValueError, match="group split requires"):
        train_classical(dataset, tmp_path / "models", mode="supervised", split_strategy="group")


@pytest.mark.slow
def test_supervised_training_and_detector_round_trip(repository, settings, sample_paths) -> None:
    summary = train_classical(
        sample_paths["synthetic"], settings.model_dir, mode="supervised", split_strategy="group"
    )
    assert summary["mode"] == "supervised"
    assert summary["model_type"] == "random_forest"
    assert summary["dataset"]["synthetic"] is True
    assert summary["metrics"]["split_strategy"] == "group_by_src_ip"
    assert summary["metrics"]["test_size"] > 0
    assert 0.0 <= summary["metrics"]["f1"] <= 1.0

    detector = load_detector(settings.model_dir)
    assert detector is not None
    assert detector.model_version == summary["model_version"]

    IngestionPipeline(repository, settings).ingest_file(
        sample_paths["cowrie"], "cowrie", archive=False, run_detection=False
    )
    runs = run_detection(
        repository, settings, include_ml=True, include_sequence=False, engine="cowrie"
    )
    assert runs["rules"] >= 1
    assert runs["ml"] >= 1
    assert runs["sequence"] == 0
    detections, total = repository.query_detections(DetectionFilters(methods=("supervised_model",)))
    assert total == runs["ml"]
    assert detections[0]["confidence"] is not None
    assert detections[0]["explanation"]["method"] == "occlusion_replacement"


def test_sequence_training_requires_torch(settings, sample_paths) -> None:
    from deephoney.detection.sequence.model import TORCH_AVAILABLE, train_sequence_model

    if TORCH_AVAILABLE:
        pytest.skip("PyTorch is installed; optional sequence training is available")
    with pytest.raises(RuntimeError, match="PyTorch is not installed"):
        train_sequence_model(sample_paths["sequences"], settings.model_dir)
