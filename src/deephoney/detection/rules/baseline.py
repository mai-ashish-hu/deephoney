"""Descriptive baseline summaries.

These numbers describe the observed dataset.  They are intentionally not
called "normal behaviour" and are not used as an automatic threshold without
documentation.
"""

from __future__ import annotations

from collections.abc import Iterable
from statistics import mean, median

from deephoney.features.extractor import FEATURE_NAMES, SessionFeatures

_INTERESTING = (
    "event_count",
    "auth_failures",
    "command_count",
    "download_count",
    "distinct_dst_ports",
    "events_per_minute",
)


def summarize_features(rows: Iterable[SessionFeatures]) -> dict[str, dict[str, float]]:
    """Return count/min/median/mean/max summaries for selected features."""

    feature_rows = list(rows)
    summary: dict[str, dict[str, float]] = {}
    for name in _INTERESTING:
        values = [float(row.as_dict()[name]) for row in feature_rows]
        if not values:
            summary[name] = {"count": 0, "min": 0, "median": 0, "mean": 0, "max": 0}
            continue
        summary[name] = {
            "count": len(values),
            "min": min(values),
            "median": median(values),
            "mean": round(mean(values), 4),
            "max": max(values),
        }
    return summary


def feature_coverage(rows: Iterable[SessionFeatures]) -> dict[str, int]:
    """Count how many sessions populate each numeric feature."""

    feature_rows = list(rows)
    coverage: dict[str, int] = {}
    for name in FEATURE_NAMES:
        coverage[name] = sum(1 for row in feature_rows if row.as_dict().get(name) is not None)
    return coverage


__all__ = ["feature_coverage", "summarize_features"]
