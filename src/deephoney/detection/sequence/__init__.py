"""Optional compact sequence model for Cowrie command sequences."""

from __future__ import annotations

from deephoney.detection.sequence.model import (
    SEQUENCE_VERSION,
    TORCH_AVAILABLE,
    CommandGRU,
    SequenceDetector,
    load_sequence_detector,
)

__all__ = [
    "SEQUENCE_VERSION",
    "TORCH_AVAILABLE",
    "CommandGRU",
    "SequenceDetector",
    "load_sequence_detector",
]
