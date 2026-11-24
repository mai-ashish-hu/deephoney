"""Approximate model explanations by feature occlusion.

No SHAP dependency is required.  For each feature we replace its value with
the training median and measure the change in model output.  This is an
approximate, model-agnostic local explanation; it is not causal evidence.
"""

from __future__ import annotations

from typing import Any

import numpy as np


def occlusion_explanations(
    model: Any,
    vector: list[float],
    feature_names: tuple[str, ...],
    background_medians: dict[str, float],
    *,
    top_k: int = 8,
    anomaly_model: bool = False,
) -> dict[str, Any]:
    base = np.asarray([vector], dtype=float)

    def positive_class_probability(values: Any) -> float:
        return float(values[1] if len(values) > 1 else values[0])

    if anomaly_model:
        base_output = float(model.decision_function(base)[0])
    else:
        base_output = positive_class_probability(model.predict_proba(base)[0])

    contributions: list[dict[str, Any]] = []
    for index, name in enumerate(feature_names):
        replacement = float(background_medians.get(name, 0.0))
        perturbed = base.copy()
        perturbed[0, index] = replacement
        if anomaly_model:
            new_output = float(model.decision_function(perturbed)[0])
            contribution = base_output - new_output
        else:
            new_output = positive_class_probability(model.predict_proba(perturbed)[0])
            contribution = base_output - new_output
        contributions.append(
            {
                "feature": name,
                "value": round(float(vector[index]), 6),
                "replacement_median": round(replacement, 6),
                "contribution": round(contribution, 6),
                "direction": "increases_risk" if contribution > 0 else "decreases_or_neutral",
            }
        )

    contributions.sort(key=lambda item: abs(item["contribution"]), reverse=True)
    return {
        "method": "occlusion_replacement",
        "approximate": True,
        "baseline_output": round(base_output, 6),
        "top_contributions": contributions[:top_k],
        "disclaimer": (
            "Approximate feature occlusion compares the model output after replacing "
            "one feature with its training median. Feature importance is not proof of "
            "causation, intent, or attribution."
        ),
    }


__all__ = ["occlusion_explanations"]
