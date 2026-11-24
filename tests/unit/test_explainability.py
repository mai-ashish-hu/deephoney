"""Unit tests for approximate model explanations and evidence text."""

from __future__ import annotations

import numpy as np

from deephoney.detection.rules.engine import evaluate_rules
from deephoney.explainability.classical import occlusion_explanations
from deephoney.explainability.rules import explain_detection, rule_evidence_rows
from deephoney.features.extractor import FEATURE_NAMES, SessionFeatures


class _LinearModel:
    """Small deterministic stand-in for a scikit-learn classifier."""

    def predict_proba(self, values: np.ndarray) -> np.ndarray:
        positive = np.clip(values.sum(axis=1) / 100.0, 0.001, 0.999)
        return np.column_stack([1.0 - positive, positive])


def test_occlusion_explanations_are_bounded_and_labelled() -> None:
    vector = [0.0] * len(FEATURE_NAMES)
    vector[FEATURE_NAMES.index("event_count")] = 50.0
    medians = {name: 0.0 for name in FEATURE_NAMES}
    explanation = occlusion_explanations(_LinearModel(), vector, FEATURE_NAMES, medians, top_k=3)
    assert explanation["method"] == "occlusion_replacement"
    assert explanation["approximate"] is True
    assert len(explanation["top_contributions"]) == 3
    assert "not proof" in explanation["disclaimer"]
    top = explanation["top_contributions"][0]
    assert set(top) == {
        "feature",
        "value",
        "replacement_median",
        "contribution",
        "direction",
    }
    assert top["feature"] == "event_count"


def test_anomaly_explanations_use_decision_function() -> None:
    class Anomaly:
        def decision_function(self, values: np.ndarray) -> np.ndarray:
            return values.sum(axis=1) * -0.01

    vector = [1.0] * len(FEATURE_NAMES)
    medians = {name: 0.5 for name in FEATURE_NAMES}
    explanation = occlusion_explanations(
        Anomaly(), vector, FEATURE_NAMES, medians, anomaly_model=True
    )
    assert explanation["baseline_output"] < 0
    assert len(explanation["top_contributions"]) == 8


def test_rule_evidence_helpers() -> None:
    features = SessionFeatures(
        source_engine="cowrie",
        session_id="s1",
        src_ip="203.0.113.1",
        recon_command_count=1,
        auth_failures=10,
    )
    detection = evaluate_rules(features)
    rows = rule_evidence_rows(detection)
    assert {row["rule_id"] for row in rows} == {"DH-R001", "DH-R003"}
    text = explain_detection(detection)
    assert "Risk" in text
    assert "not proof" in text
    assert explain_detection({"risk_score": 10, "detection_method": "rule"}).startswith(
        "Risk 10/100"
    )
