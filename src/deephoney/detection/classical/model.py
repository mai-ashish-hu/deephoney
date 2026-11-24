"""Persisted classical model loading and inference."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from deephoney.explainability.classical import occlusion_explanations
from deephoney.features.extractor import FEATURE_NAMES, SessionFeatures
from deephoney.schemas.detections import (
    DetectionMethod,
    DetectionResult,
    risk_level_for_score,
)

REGISTRY_NAME = "registry.json"


def _read_registry(model_dir: Path) -> dict[str, Any]:
    registry_path = model_dir / REGISTRY_NAME
    if not registry_path.is_file():
        return {}
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _resolve(model_dir: Path, value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = model_dir / path
    return path if path.is_file() else None


def load_detector(model_dir: str | Path, *, kind: str | None = None) -> ClassicalDetector | None:
    """Load a registered supervised or anomaly model.

    Preference order: requested ``kind``, then supervised, then anomaly.  A
    missing model returns ``None`` so ingestion/demo flows continue.
    """

    base = Path(model_dir)
    registry = _read_registry(base)
    order = [kind] if kind else ["supervised", "anomaly"]
    for candidate in order:
        if not candidate:
            continue
        entry = registry.get(candidate)
        if not isinstance(entry, dict):
            continue
        model_path = _resolve(base, entry.get("model_path"))
        metadata_path = _resolve(base, entry.get("metadata_path"))
        if model_path is None or metadata_path is None:
            continue
        try:
            model = joblib.load(model_path)
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(metadata, dict):
            continue
        if tuple(metadata.get("feature_names", [])) != FEATURE_NAMES:
            raise ValueError("Model feature contract does not match this DeepHoney version")
        return ClassicalDetector(model=model, metadata=metadata, model_path=model_path)
    return None


class ClassicalDetector:
    def __init__(self, *, model: Any, metadata: dict[str, Any], model_path: Path) -> None:
        self.model = model
        self.metadata = metadata
        self.model_path = model_path
        self.model_type = str(metadata.get("model_type", "unknown"))
        self.model_version = str(metadata.get("model_version", "unknown"))
        self.feature_version = str(metadata.get("feature_version", ""))
        self.feature_names = tuple(metadata.get("feature_names", FEATURE_NAMES))
        if self.feature_names != FEATURE_NAMES:
            raise ValueError("Persisted feature names do not match FEATURE_NAMES")
        self.background_medians = {
            str(key): float(value)
            for key, value in (metadata.get("background_medians") or {}).items()
            if isinstance(value, int | float)
        }

    def _check(self, features: SessionFeatures) -> None:
        if features.feature_version != self.feature_version:
            raise ValueError(
                f"Feature version mismatch: session={features.feature_version}, "
                f"model={self.feature_version}"
            )

    def score(
        self,
        features: SessionFeatures,
        *,
        medium_threshold: int = 25,
        high_threshold: int = 60,
    ) -> DetectionResult:
        self._check(features)
        vector = features.to_vector()
        if self.model_type == "isolation_forest":
            raw = float(self.model.decision_function(np.asarray([vector], dtype=float))[0])
            score_min = float(self.metadata.get("score_min", -0.1))
            score_max = float(self.metadata.get("score_max", 0.1))
            span = max(score_max - score_min, 1e-9)
            risk_score = int(round(max(0.0, min(100.0, (score_max - raw) / span * 100.0))))
            method = DetectionMethod.ANOMALY
            confidence = None
            summary = "Anomaly model output mapped to a 0-100 prioritisation score."
            anomaly_model = True
        else:
            probabilities = self.model.predict_proba(np.asarray([vector], dtype=float))[0]
            classes = list(getattr(self.model, "classes_", [0, 1]))
            try:
                probability = float(probabilities[classes.index(1)]) if 1 in classes else 0.0
            except (ValueError, IndexError):
                probability = 0.0
            risk_score = int(round(max(0.0, min(1.0, probability)) * 100))
            method = DetectionMethod.SUPERVISED
            confidence = round(probability, 6)
            summary = "Supervised model probability mapped to a 0-100 prioritisation score."
            anomaly_model = False

        explanation = occlusion_explanations(
            self.model,
            vector,
            FEATURE_NAMES,
            self.background_medians,
            anomaly_model=anomaly_model,
        )
        evidence = {
            "summary": summary,
            "model_type": self.model_type,
            "model_version": self.model_version,
            "feature_version": self.feature_version,
            "metrics": self.metadata.get("metrics", {}),
            "training": self.metadata.get("training", {}),
            "dataset": self.metadata.get("dataset", {}),
            "top_features": explanation.get("top_contributions", [])[:5],
            "thresholds": {"medium": medium_threshold, "high": high_threshold},
            "disclaimer": self.metadata.get(
                "disclaimer",
                "Model output is a prioritisation aid, not proof of malicious intent.",
            ),
        }
        return DetectionResult(
            session_id=features.session_id,
            source_engine=features.source_engine,
            detection_method=method,
            model_version=self.model_version,
            risk_score=risk_score,
            risk_level=risk_level_for_score(risk_score, medium_threshold, high_threshold),
            confidence=confidence,
            evidence=evidence,
            explanation=explanation,
        )


__all__ = ["ClassicalDetector", "REGISTRY_NAME", "load_detector"]
