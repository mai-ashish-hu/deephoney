"""Compact GRU command-sequence model (experimental Stage C).

This module is optional.  PyTorch is deliberately not part of the core
runtime; import failures are handled so the rules/classical pipeline remains
fully usable on a CPU-only student laptop without a multi-gigabyte install.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

import numpy as np

from deephoney.features.extractor import SessionFeatures
from deephoney.schemas.detections import DetectionMethod, DetectionResult, risk_level_for_score

SEQUENCE_VERSION = "2024.1.0"
REGISTRY_NAME = "registry.json"
PAD = "<pad>"
UNK = "<unk>"

try:
    import torch
    from torch import nn

    TORCH_AVAILABLE = True
except ImportError:
    torch = None
    nn = None
    TORCH_AVAILABLE = False


def tokenize_commands(commands: list[str], *, max_len: int = 64) -> list[str]:
    tokens: list[str] = []
    for command in commands:
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        tokens.extend(part.lower()[:64] for part in parts if part.strip())
        if len(tokens) >= max_len:
            break
    return tokens[:max_len]


def build_vocabulary(command_lists: list[list[str]], *, max_len: int = 64) -> dict[str, int]:
    vocab: dict[str, int] = {PAD: 0, UNK: 1}
    for commands in command_lists:
        for token in tokenize_commands(commands, max_len=max_len):
            if token not in vocab:
                vocab[token] = len(vocab)
    return vocab


def encode_tokens(tokens: list[str], vocab: dict[str, int], *, max_len: int = 64) -> list[int]:
    encoded = [vocab.get(token, vocab[UNK]) for token in tokens[:max_len]]
    return encoded + [vocab[PAD]] * (max_len - len(encoded))


if TORCH_AVAILABLE:

    class CommandGRU(nn.Module):
        def __init__(
            self, vocab_size: int, *, embedding_dim: int = 32, hidden_dim: int = 64
        ) -> None:
            super().__init__()
            self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
            self.gru = nn.GRU(embedding_dim, hidden_dim, batch_first=True, bidirectional=True)
            self.dropout = nn.Dropout(0.2)
            self.classifier = nn.Linear(hidden_dim * 2, 1)

        def forward(self, tokens: Any) -> Any:
            embedded = self.embedding(tokens)
            _output, hidden = self.gru(embedded)
            combined = torch.cat((hidden[-2], hidden[-1]), dim=1)
            return self.classifier(self.dropout(combined)).squeeze(-1)

else:

    class CommandGRU:
        """Placeholder that gives a clear error when torch is absent."""

        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise ImportError(
                "PyTorch is optional. Install requirements-ml.lock to use the sequence model."
            )


def _read_registry(model_dir: Path) -> dict[str, Any]:
    path = model_dir / REGISTRY_NAME
    if not path.is_file():
        return {}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def load_sequence_detector(model_dir: str | Path) -> SequenceDetector | None:
    if not TORCH_AVAILABLE:
        return None
    base = Path(model_dir)
    registry = _read_registry(base)
    entry = registry.get("sequence")
    if not isinstance(entry, dict):
        return None
    model_path = entry.get("model_path")
    metadata_path = entry.get("metadata_path")
    if not model_path or not metadata_path:
        return None
    model_file = Path(model_path) if Path(model_path).is_absolute() else base / model_path
    meta_file = Path(metadata_path) if Path(metadata_path).is_absolute() else base / metadata_path
    if not model_file.is_file() or not meta_file.is_file():
        return None
    try:
        checkpoint = torch.load(model_file, map_location="cpu", weights_only=False)
        metadata = json.loads(meta_file.read_text(encoding="utf-8"))
    except (OSError, RuntimeError, ValueError):
        return None
    vocab = checkpoint.get("vocab")
    max_len = int(checkpoint.get("max_len", 64))
    if not isinstance(vocab, dict):
        return None
    model = CommandGRU(len(vocab), **metadata.get("architecture", {}))
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    return SequenceDetector(model=model, vocab=vocab, max_len=max_len, metadata=metadata)


class SequenceDetector:
    def __init__(
        self,
        *,
        model: Any,
        vocab: dict[str, int],
        max_len: int,
        metadata: dict[str, Any],
    ) -> None:
        self.model = model
        self.vocab = vocab
        self.max_len = max_len
        self.metadata = metadata
        self.model_version = str(metadata.get("model_version", "unknown"))

    def _probability(self, tokens: list[str]) -> float:
        encoded = encode_tokens(tokens, self.vocab, max_len=self.max_len)
        tensor = torch.tensor([encoded], dtype=torch.long)
        with torch.no_grad():
            logits = self.model(tensor)
            probability = torch.sigmoid(logits).item()
        return float(probability)

    def score(
        self,
        features: SessionFeatures,
        *,
        medium_threshold: int = 25,
        high_threshold: int = 60,
    ) -> DetectionResult:
        tokens = tokenize_commands(features.command_sequence, max_len=self.max_len)
        if not tokens:
            raise ValueError("Sequence model requires at least one command token")
        probability = self._probability(tokens)
        risk_score = int(round(probability * 100))
        base = probability
        contributions: list[dict[str, Any]] = []
        for index, token in enumerate(tokens[: min(len(tokens), 20)]):
            reduced = tokens[:index] + tokens[index + 1 :]
            without = self._probability(reduced)
            contributions.append(
                {
                    "token": token,
                    "position": index,
                    "contribution": round(base - without, 6),
                    "direction": "increases_risk" if base - without > 0 else "decreases_or_neutral",
                }
            )
        contributions.sort(key=lambda item: abs(item["contribution"]), reverse=True)
        explanation = {
            "method": "token_occlusion",
            "approximate": True,
            "top_tokens": contributions[:10],
            "disclaimer": (
                "Token occlusion is an approximate sensitivity check, not a causal explanation. "
                "Command tokens are attacker-controlled and may be truncated."
            ),
        }
        evidence = {
            "summary": "Experimental command-sequence model probability mapped to 0-100.",
            "model_version": self.model_version,
            "sequence_version": SEQUENCE_VERSION,
            "model_metrics": self.metadata.get("metrics", {}),
            "dataset": self.metadata.get("dataset", {}),
            "thresholds": {"medium": medium_threshold, "high": high_threshold},
            "disclaimer": (
                "The sequence model is an academic experiment. It is not a prerequisite "
                "for the DeepHoney baseline and has not been validated on production traffic."
            ),
        }
        return DetectionResult(
            session_id=features.session_id,
            source_engine=features.source_engine,
            detection_method=DetectionMethod.SEQUENCE,
            model_version=self.model_version,
            risk_score=risk_score,
            risk_level=risk_level_for_score(risk_score, medium_threshold, high_threshold),
            confidence=round(probability, 6),
            evidence=evidence,
            explanation=explanation,
        )


def train_sequence_model(
    dataset_path: str | Path,
    model_dir: str | Path,
    *,
    epochs: int = 12,
    batch_size: int = 16,
    learning_rate: float = 1e-3,
    max_len: int = 64,
    seed: int = 42,
) -> dict[str, Any]:
    """Train the optional GRU and persist a checkpoint plus metadata."""

    if not TORCH_AVAILABLE:
        raise RuntimeError("PyTorch is not installed; install requirements-ml.lock")
    from datetime import UTC, datetime

    import sklearn
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )
    from sklearn.model_selection import GroupShuffleSplit, train_test_split

    path = Path(dataset_path)
    base = Path(model_dir)
    base.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict) or "commands" not in item or "label" not in item:
            continue
        rows.append(item)
    if len(rows) < 10:
        raise ValueError("Sequence dataset needs at least 10 valid JSONL rows")

    command_lists = [list(item.get("commands") or []) for item in rows]
    labels = np.asarray(
        [1 if str(item["label"]).lower() in {"1", "malicious", "attack"} else 0 for item in rows]
    )
    groups = np.asarray(
        [str(item.get("src_ip", f"row-{index}")) for index, item in enumerate(rows)]
    )
    indices = np.arange(len(rows))
    if len(set(groups)) >= 2:
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
        train_idx, test_idx = next(splitter.split(indices, labels, groups=groups))
        split_strategy = "group_by_src_ip"
    else:
        train_idx, test_idx = train_test_split(
            indices,
            test_size=0.25,
            random_state=seed,
            stratify=labels if len(set(labels)) > 1 else None,
        )
        split_strategy = "stratified_random"

    vocab = build_vocabulary(command_lists, max_len=max_len)
    torch.manual_seed(seed)
    model = CommandGRU(len(vocab))
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    positives = max(1, int(labels[train_idx].sum()))
    negatives = max(1, int(len(train_idx) - positives))
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([negatives / positives]))

    def _batch(indices_subset: np.ndarray) -> tuple[Any, Any]:
        encoded = torch.tensor(
            [
                encode_tokens(
                    tokenize_commands(command_lists[i], max_len=max_len), vocab, max_len=max_len
                )
                for i in indices_subset
            ],
            dtype=torch.long,
        )
        target = torch.tensor(labels[indices_subset], dtype=torch.float32)
        return encoded, target

    model.train()
    for _epoch in range(epochs):
        permutation = np.random.default_rng(seed + _epoch).permutation(train_idx)
        for start in range(0, len(permutation), batch_size):
            batch_indices = permutation[start : start + batch_size]
            encoded, target = _batch(batch_indices)
            optimizer.zero_grad()
            loss = loss_fn(model(encoded), target)
            loss.backward()
            optimizer.step()

    model.eval()
    with torch.no_grad():
        encoded_test, target_test = _batch(test_idx)
        probabilities = torch.sigmoid(model(encoded_test)).numpy()
    predictions = (probabilities >= 0.5).astype(int)
    metrics: dict[str, Any] = {
        "accuracy": round(float(accuracy_score(labels[test_idx], predictions)), 6),
        "precision": round(
            float(precision_score(labels[test_idx], predictions, zero_division=0)), 6
        ),
        "recall": round(float(recall_score(labels[test_idx], predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(labels[test_idx], predictions, zero_division=0)), 6),
        "confusion_matrix": confusion_matrix(labels[test_idx], predictions, labels=[0, 1]).tolist(),
        "test_size": int(len(test_idx)),
        "train_size": int(len(train_idx)),
        "split_strategy": split_strategy,
    }
    if len(set(labels[test_idx])) == 2:
        metrics["roc_auc"] = round(float(roc_auc_score(labels[test_idx], probabilities)), 6)

    created = datetime.now(UTC)
    model_version = f"gru-{SEQUENCE_VERSION}-{created.strftime('%Y%m%dT%H%M%SZ')}"
    checkpoint_path = base / "command_gru_v1.pt"
    metadata_path = base / "command_gru_v1.metadata.json"
    torch.save(
        {"state_dict": model.state_dict(), "vocab": vocab, "max_len": max_len},
        checkpoint_path,
    )
    metadata = {
        "model_type": "command_gru",
        "model_version": model_version,
        "feature_names": ["command_tokens"],
        "sequence_version": SEQUENCE_VERSION,
        "architecture": {"embedding_dim": 32, "hidden_dim": 64},
        "max_len": max_len,
        "metrics": metrics,
        "training": {
            "epochs": epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "seed": seed,
            "trained_at": created.isoformat(),
            "torch": torch.__version__,
            "sklearn": sklearn.__version__,
        },
        "dataset": {
            "path": path.name,
            "rows": len(rows),
            "synthetic": "synthetic" in path.name.lower(),
        },
        "disclaimer": (
            "Experimental sequence model trained on a small synthetic dataset. "
            "Metrics are not evidence of production accuracy."
        ),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    registry_path = base / REGISTRY_NAME
    registry: dict[str, Any] = {}
    if registry_path.is_file():
        try:
            parsed = json.loads(registry_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                registry = parsed
        except (OSError, json.JSONDecodeError):
            registry = {}
    registry["sequence"] = {
        "model_path": checkpoint_path.name,
        "metadata_path": metadata_path.name,
        "model_version": model_version,
        "updated_at": created.isoformat(),
    }
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")
    return {
        "model_version": model_version,
        "model_path": str(checkpoint_path),
        "metadata_path": str(metadata_path),
        "metrics": metrics,
        "warning": "Synthetic sequence dataset; not a production accuracy claim.",
    }


__all__ = [
    "CommandGRU",
    "PAD",
    "REGISTRY_NAME",
    "SEQUENCE_VERSION",
    "TORCH_AVAILABLE",
    "UNK",
    "SequenceDetector",
    "build_vocabulary",
    "encode_tokens",
    "load_sequence_detector",
    "tokenize_commands",
    "train_sequence_model",
]
