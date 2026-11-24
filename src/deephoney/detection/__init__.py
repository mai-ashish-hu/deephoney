"""Detection pipeline: rules first, classical ML second, sequence models last."""

from __future__ import annotations

from deephoney.detection.rules.engine import RULE_WEIGHTS, evaluate_rules
from deephoney.schemas.detections import DetectionResult

__all__ = ["RULE_WEIGHTS", "DetectionResult", "evaluate_rules"]
