"""Human-readable evidence extraction for detections."""

from __future__ import annotations

from typing import Any

from deephoney.schemas.detections import DetectionResult


def rule_evidence_rows(detection: DetectionResult | dict[str, Any]) -> list[dict[str, Any]]:
    """Return rule evidence rows suitable for a dataframe."""

    if isinstance(detection, DetectionResult):
        evidence = detection.evidence
    else:
        evidence = detection.get("evidence", {})
    if not isinstance(evidence, dict):
        return []
    rules = evidence.get("rules", [])
    if not isinstance(rules, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in rules:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "rule_id": item.get("rule_id"),
                "title": item.get("title"),
                "weight": item.get("weight"),
                "description": item.get("description"),
                "observed": item.get("observed"),
            }
        )
    return rows


def explain_detection(detection: DetectionResult | dict[str, Any]) -> str:
    """Return a concise, non-causal explanation string."""

    if isinstance(detection, DetectionResult):
        evidence = detection.evidence
        method = detection.detection_method.value
        score = detection.risk_score
    else:
        evidence = detection.get("evidence", {})
        method = str(detection.get("detection_method", "unknown"))
        score = detection.get("risk_score")

    if not isinstance(evidence, dict):
        return f"Risk {score}/100 via {method}. No evidence payload is available."

    rules = evidence.get("rules")
    if isinstance(rules, list) and rules:
        titles = [str(item.get("title")) for item in rules if isinstance(item, dict)]
        return (
            f"Risk {score}/100 via {method}. "
            f"Contributing evidence: {'; '.join(titles)}. "
            "This prioritisation is not proof of malicious intent."
        )
    summary = evidence.get("summary")
    if summary:
        return f"Risk {score}/100 via {method}. {summary}"
    return f"Risk {score}/100 via {method}. Evidence is limited to the stored feature summary."


__all__ = ["explain_detection", "rule_evidence_rows"]
