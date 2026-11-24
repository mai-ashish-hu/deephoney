"""Reproducible classical model training.

The project only claims supervised performance when a documented labelled
dataset and a leakage-aware split are supplied.  Group-aware splitting keeps
all sessions from one source IP on one side of the evaluation boundary.
"""

from __future__ import annotations

import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from deephoney.features.extractor import FEATURE_NAMES, FEATURE_VERSION
from deephoney.utils.hashing import file_sha256

REGISTRY_NAME = "registry.json"
DEFAULT_SEED = 42

_LABEL_MAP = {
    "1": 1,
    "malicious": 1,
    "attack": 1,
    "suspicious": 1,
    "true": 1,
    "0": 0,
    "benign": 0,
    "normal": 0,
    "false": 0,
}


def _normalise_label(value: Any) -> int:
    text = str(value).strip().lower()
    if text in _LABEL_MAP:
        return _LABEL_MAP[text]
    try:
        number = int(text)
    except ValueError as exc:
        raise ValueError(f"Unsupported label value: {value!r}") from exc
    if number in (0, 1):
        return number
    raise ValueError(f"Unsupported label value: {value!r}")


def _load_dataset(path: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"Dataset not found: {path}")
    frame = pd.read_csv(path)
    required = {"label", *FEATURE_NAMES}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {', '.join(missing)}")

    original_rows = len(frame)
    if "feature_version" in frame.columns:
        versions = set(frame["feature_version"].dropna().astype(str))
        if versions and versions != {FEATURE_VERSION}:
            raise ValueError(
                f"Dataset feature_version(s) {sorted(versions)} do not match {FEATURE_VERSION}"
            )

    frame = frame.dropna(subset=["label"]).copy()
    frame["label"] = frame["label"].map(_normalise_label)
    for name in FEATURE_NAMES:
        frame[name] = pd.to_numeric(frame[name], errors="coerce")
    frame = frame.dropna(subset=["label", *FEATURE_NAMES]).copy()
    dropped = original_rows - len(frame)
    if frame.empty:
        raise ValueError("Dataset has no usable rows after validation")
    return frame, {
        "original_rows": original_rows,
        "usable_rows": len(frame),
        "dropped_rows": dropped,
    }


def _split_indices(
    frame: pd.DataFrame,
    *,
    strategy: str,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, str]:
    y = frame["label"].to_numpy(dtype=int)
    if strategy == "group":
        if "src_ip" not in frame.columns or frame["src_ip"].nunique() < 2:
            raise ValueError("group split requires a src_ip column with two distinct values")
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
        train_idx, test_idx = next(splitter.split(frame, y, groups=frame["src_ip"].astype(str)))
        return np.asarray(train_idx), np.asarray(test_idx), "group_by_src_ip"
    if strategy == "time":
        if "timestamp" not in frame.columns:
            raise ValueError("time split requires a timestamp column")
        timestamps = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
        if not timestamps.notna().all() or len(frame) < 4:
            raise ValueError("time split requires parseable timestamps and at least four rows")
        order = np.argsort(timestamps.to_numpy())
        split_at = max(1, int(len(order) * 0.75))
        return order[:split_at], order[split_at:], "chronological"
    if strategy != "stratified":
        raise ValueError("split_strategy must be group, time, or stratified")
    train_idx, test_idx = train_test_split(
        np.arange(len(frame)),
        test_size=0.25,
        random_state=seed,
        stratify=y if len(set(y)) > 1 else None,
    )
    return np.asarray(train_idx), np.asarray(test_idx), "stratified_random"


def _supervised_metrics(
    model: RandomForestClassifier,
    x_test: np.ndarray,
    y_test: np.ndarray,
    *,
    train_size: int,
    split_strategy: str,
) -> dict[str, Any]:
    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1] if hasattr(model, "predict_proba") else None
    metrics: dict[str, Any] = {
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 6),
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
        "test_size": int(len(y_test)),
        "train_size": int(train_size),
        "split_strategy": split_strategy,
        "class_distribution_test": {
            "benign": int((y_test == 0).sum()),
            "malicious": int((y_test == 1).sum()),
        },
    }
    if probabilities is not None and len(set(y_test)) == 2:
        try:
            metrics["roc_auc"] = round(float(roc_auc_score(y_test, probabilities)), 6)
        except ValueError:
            metrics["roc_auc"] = None
    return metrics


def _write_registry(model_dir: Path, key: str, entry: dict[str, Any]) -> None:
    registry_path = model_dir / REGISTRY_NAME
    existing: dict[str, Any] = {}
    if registry_path.is_file():
        try:
            parsed = json.loads(registry_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                existing = parsed
        except (OSError, json.JSONDecodeError):
            existing = {}
    existing[key] = entry
    registry_path.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")


def train_classical(
    dataset_path: str | Path,
    model_dir: str | Path,
    *,
    mode: str = "auto",
    split_strategy: str = "group",
    seed: int = DEFAULT_SEED,
    contamination: float = 0.1,
) -> dict[str, Any]:
    """Train and persist a model, returning a JSON-safe summary."""

    if mode not in {"auto", "supervised", "anomaly"}:
        raise ValueError("mode must be auto, supervised, or anomaly")
    if split_strategy not in {"group", "time", "stratified"}:
        raise ValueError("split_strategy must be group, time, or stratified")
    if not 0 < contamination <= 0.5:
        raise ValueError("contamination must be greater than 0 and at most 0.5")

    dataset = Path(dataset_path).resolve()
    target_dir = Path(model_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    frame, dataset_info = _load_dataset(dataset)
    labels_present = frame["label"].nunique() > 1

    selected_mode = mode
    if mode == "auto":
        selected_mode = "supervised" if labels_present else "anomaly"
    if selected_mode == "supervised" and not labels_present:
        raise ValueError("Supervised training requires two label classes")

    created = datetime.now(UTC)
    stamp = created.strftime("%Y%m%dT%H%M%SZ")
    x = frame[list(FEATURE_NAMES)].to_numpy(dtype=float)
    y = frame["label"].to_numpy(dtype=int)
    dataset_hash = file_sha256(dataset)
    background_medians = {
        name: float(np.nanmedian(x[:, index])) for index, name in enumerate(FEATURE_NAMES)
    }
    dataset_meta = {
        "path": dataset.name,
        "sha256": dataset_hash,
        "synthetic": "synthetic" in dataset.name.lower(),
        **dataset_info,
        "label_source": "CSV label column" if labels_present else "unlabelled",
        "feature_version": FEATURE_VERSION,
    }
    common_training = {
        "seed": seed,
        "trained_at": created.isoformat(),
        "python": platform.python_version(),
        "sklearn": sklearn.__version__,
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "feature_version": FEATURE_VERSION,
    }

    if selected_mode == "supervised":
        train_idx, test_idx, actual_split = _split_indices(
            frame, strategy=split_strategy, seed=seed
        )
        x_train, x_test = x[train_idx], x[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        if len(set(y_train)) < 2:
            raise ValueError("Training split contains a single class; change the split or dataset")
        model = RandomForestClassifier(
            n_estimators=300,
            max_depth=10,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
        )
        model.fit(x_train, y_train)
        metrics = _supervised_metrics(
            model, x_test, y_test, train_size=len(train_idx), split_strategy=actual_split
        )
        model.fit(x, y)
        model_version = f"rf-{FEATURE_VERSION}-{stamp}"
        model_type = "random_forest"
        registry_key = "supervised"
        model_file = "random_forest_v1.joblib"
        metadata_file = "random_forest_v1.metadata.json"
        metadata = {
            "model_type": model_type,
            "model_version": model_version,
            "feature_names": list(FEATURE_NAMES),
            "feature_version": FEATURE_VERSION,
            "classes": [0, 1],
            "background_medians": background_medians,
            "metrics": metrics,
            "training": common_training,
            "dataset": dataset_meta,
            "disclaimer": (
                "Supervised metrics are valid only for the documented dataset and split. "
                "The bundled dataset is synthetic and is not evidence of real-world accuracy."
            ),
        }
        joblib.dump(model, target_dir / model_file)
    else:
        model = IsolationForest(
            n_estimators=300,
            contamination=contamination,
            random_state=seed,
            n_jobs=-1,
        )
        model.fit(x)
        scores = model.decision_function(x)
        score_min = float(np.min(scores))
        score_max = float(np.max(scores))
        metrics = {
            "contamination": contamination,
            "score_min": score_min,
            "score_max": score_max,
            "score_median": float(np.median(scores)),
            "train_size": int(len(frame)),
            "note": "Anomaly scores are not calibrated probabilities.",
        }
        model_version = f"iforest-{FEATURE_VERSION}-{stamp}"
        model_type = "isolation_forest"
        registry_key = "anomaly"
        model_file = "isolation_forest_v1.joblib"
        metadata_file = "isolation_forest_v1.metadata.json"
        metadata = {
            "model_type": model_type,
            "model_version": model_version,
            "feature_names": list(FEATURE_NAMES),
            "feature_version": FEATURE_VERSION,
            "background_medians": background_medians,
            "score_min": score_min,
            "score_max": score_max,
            "metrics": metrics,
            "training": common_training,
            "dataset": dataset_meta,
            "disclaimer": (
                "Anomaly detection flags deviations from the training distribution. "
                "It does not establish malicious intent or attribution."
            ),
        }
        joblib.dump(model, target_dir / model_file)

    (target_dir / metadata_file).write_text(
        json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8"
    )
    _write_registry(
        target_dir,
        registry_key,
        {
            "model_path": model_file,
            "metadata_path": metadata_file,
            "model_version": model_version,
            "updated_at": created.isoformat(),
        },
    )
    return {
        "mode": selected_mode,
        "model_type": model_type,
        "model_version": model_version,
        "model_path": str(target_dir / model_file),
        "metadata_path": str(target_dir / metadata_file),
        "metrics": metadata["metrics"],
        "dataset": dataset_meta,
        "warning": (
            "Synthetic dataset: do not present these metrics as real-world performance."
            if dataset_meta["synthetic"]
            else "Validate labels and provenance before presenting metrics."
        ),
        "python": sys.version.split()[0],
    }


__all__ = ["DEFAULT_SEED", "REGISTRY_NAME", "train_classical"]
