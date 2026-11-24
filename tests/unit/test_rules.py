"""Unit tests for Stage A rules and risk bands."""

from __future__ import annotations

import pytest

from deephoney.detection.rules.engine import evaluate_rules
from deephoney.features.extractor import SessionFeatures
from deephoney.schemas.detections import DetectionMethod, RiskLevel, risk_level_for_score


def _features(**overrides: object) -> SessionFeatures:
    values: dict[str, object] = {
        "source_engine": "cowrie",
        "session_id": "rule-session",
        "src_ip": "203.0.113.50",
    }
    values.update(overrides)
    return SessionFeatures(**values)


def _ids(result) -> set[str]:
    return {item["rule_id"] for item in result.evidence["rules"]}


def test_no_rules_produces_low_risk_with_disclaimer() -> None:
    result = evaluate_rules(_features())
    assert result.risk_score == 0
    assert result.risk_level is RiskLevel.LOW
    assert result.detection_method is DetectionMethod.RULE
    assert result.confidence is None
    assert _ids(result) == set()
    assert "not evidence of benign intent" in result.evidence["summary"]
    assert "do not prove" in result.evidence["disclaimer"]


def test_repeated_authentication_failures() -> None:
    result = evaluate_rules(_features(auth_failures=10))
    assert _ids(result) == {"DH-R001"}
    assert result.risk_score == 25
    assert result.risk_level is RiskLevel.MEDIUM


def test_success_after_failures_and_interactive_activity() -> None:
    result = evaluate_rules(_features(auth_successes=1, auth_failures=3, command_count=1))
    assert {"DH-R002", "DH-R016"} <= _ids(result)
    assert result.risk_score == 30


RULE_CASES = [
    ({"recon_command_count": 1}, "DH-R003"),
    ({"file_transfer_command_count": 1}, "DH-R004"),
    ({"persistence_command_count": 1}, "DH-R005"),
    ({"destructive_command_count": 1}, "DH-R006"),
    ({"crypto_command_count": 1}, "DH-R007"),
    ({"download_count": 1}, "DH-R008"),
    ({"event_count": 50}, "DH-R009"),
    ({"distinct_dst_ports": 3}, "DH-R010"),
    ({"has_executable_artifact": 1}, "DH-R011"),
    ({"events_per_minute": 10}, "DH-R012"),
    ({"distinct_usernames": 5}, "DH-R013"),
    ({"lateral_command_count": 1}, "DH-R014"),
    ({"src_ip_session_count": 3}, "DH-R015"),
    ({"auth_successes": 1, "command_count": 1}, "DH-R016"),
]


@pytest.mark.parametrize(("overrides", "rule_id"), RULE_CASES)
def test_each_rule_fires_at_its_documented_threshold(
    overrides: dict[str, object], rule_id: str
) -> None:
    result = evaluate_rules(_features(**overrides))
    assert rule_id in _ids(result)


def test_score_is_capped_and_flagged() -> None:
    result = evaluate_rules(
        _features(
            auth_failures=20,
            auth_successes=1,
            recon_command_count=5,
            file_transfer_command_count=2,
            persistence_command_count=2,
            destructive_command_count=2,
            crypto_command_count=2,
            download_count=2,
            artifact_count=2,
            event_count=100,
            distinct_dst_ports=5,
            has_executable_artifact=1,
            events_per_minute=500,
            distinct_usernames=9,
            lateral_command_count=2,
            src_ip_session_count=9,
            command_count=10,
        )
    )
    assert result.risk_score == 100
    assert result.evidence["raw_weight_sum"] > 100
    assert result.evidence["score_capped"] is True
    assert result.risk_level is RiskLevel.HIGH


def test_custom_thresholds_are_applied() -> None:
    result = evaluate_rules(_features(recon_command_count=1), medium_threshold=5, high_threshold=8)
    assert result.risk_score == 10
    assert result.risk_level is RiskLevel.HIGH
    assert result.evidence["thresholds"] == {"medium": 5, "high": 8}


def test_evidence_item_limit_is_enforced() -> None:
    result = evaluate_rules(
        _features(
            auth_failures=20,
            auth_successes=1,
            recon_command_count=1,
            command_count=1,
            crypto_command_count=1,
        ),
        max_evidence_items=2,
    )
    assert len(result.evidence["rules"]) == 2
    assert result.evidence["evidence_truncated"] is True
    assert result.evidence["raw_weight_sum"] == 95
    assert result.risk_score == 95


def test_risk_level_boundaries() -> None:
    assert risk_level_for_score(0) is RiskLevel.LOW
    assert risk_level_for_score(24) is RiskLevel.LOW
    assert risk_level_for_score(25) is RiskLevel.MEDIUM
    assert risk_level_for_score(59) is RiskLevel.MEDIUM
    assert risk_level_for_score(60) is RiskLevel.HIGH
    assert risk_level_for_score(100) is RiskLevel.HIGH
