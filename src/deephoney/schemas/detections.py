"""Detection result contracts and risk-level helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DetectionMethod(str, Enum):
    RULE = "rule"
    STATISTICAL = "statistical"
    SUPERVISED = "supervised_model"
    ANOMALY = "anomaly_model"
    SEQUENCE = "sequence_model"


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    rule_id: str
    title: str
    weight: int = Field(ge=0, le=100)
    description: str
    observed: Any = None


class DetectionResult(BaseModel):
    """A transparent prioritisation result.

    ``confidence`` is only populated by a model that supplies a calibrated or
    otherwise defensible probability.  Rule detections deliberately leave it
    unset.
    """

    model_config = ConfigDict(extra="ignore", protected_namespaces=())

    session_id: str
    source_engine: str
    detection_method: DetectionMethod
    model_version: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    explanation: dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("created_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def risk_level_for_score(score: int | float, medium: int = 25, high: int = 60) -> RiskLevel:
    """Map a documented 0-100 score to a configurable risk band."""

    if score >= high:
        return RiskLevel.HIGH
    if score >= medium:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


__all__ = [
    "DetectionMethod",
    "DetectionResult",
    "EvidenceItem",
    "RiskLevel",
    "risk_level_for_score",
]
