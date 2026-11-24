#!/usr/bin/env python3
"""Train the optional GRU command-sequence experiment (requires PyTorch)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _bootstrap import ROOT, settings_for
from deephoney.detection.sequence.model import TORCH_AVAILABLE, train_sequence_model


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        default=str(ROOT / "data/samples/synthetic/command_sequences.jsonl"),
        help="JSONL rows with commands, label, and optional src_ip",
    )
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--max-len", type=int, default=64)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model-dir", default=None)
    parser.add_argument("--config", default=None)
    args = parser.parse_args()

    if not TORCH_AVAILABLE:
        print(
            "error: PyTorch is not installed. Install the optional ML lock:\n"
            "  uv pip install --python .venv/bin/python -r requirements-ml.lock\n"
            "The rules and classical pipeline do not require PyTorch.",
            file=sys.stderr,
        )
        return 2
    dataset = Path(args.dataset).expanduser().resolve()
    if not dataset.is_file():
        print(
            f"error: dataset not found: {dataset}\n"
            "Generate it with scripts/generate_synthetic_dataset.py",
            file=sys.stderr,
        )
        return 2
    settings = settings_for(args.config)
    model_dir = Path(args.model_dir).expanduser() if args.model_dir else settings.model_dir
    try:
        summary = train_sequence_model(
            dataset,
            model_dir,
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            max_len=args.max_len,
            seed=args.seed,
        )
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, default=str))
    print(
        "\nCAUTION: the sequence model is an academic experiment on a small "
        "synthetic dataset; it is not a production classifier.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
