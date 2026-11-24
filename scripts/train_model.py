#!/usr/bin/env python3
"""Train and register a classical baseline model on a documented dataset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _bootstrap import ROOT, settings_for
from deephoney.detection.classical.train import train_classical


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        default=str(ROOT / "data/samples/synthetic/synthetic_sessions.csv"),
        help="CSV containing FEATURE_NAMES plus a label column",
    )
    parser.add_argument("--mode", choices=["auto", "supervised", "anomaly"], default="auto")
    parser.add_argument("--split", choices=["group", "time", "stratified"], default="group")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--contamination", type=float, default=0.1)
    parser.add_argument("--model-dir", default=None)
    parser.add_argument("--config", default=None)
    args = parser.parse_args()

    dataset = Path(args.dataset).expanduser().resolve()
    if not dataset.is_file():
        print(
            f"error: dataset not found: {dataset}\n"
            "Generate the synthetic dataset with scripts/generate_synthetic_dataset.py",
            file=sys.stderr,
        )
        return 2
    settings = settings_for(args.config)
    model_dir = Path(args.model_dir).expanduser() if args.model_dir else settings.model_dir
    try:
        summary = train_classical(
            dataset,
            model_dir,
            mode=args.mode,
            split_strategy=args.split,
            seed=args.seed,
            contamination=args.contamination,
        )
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, default=str))
    print(
        "\nCAUTION: metrics describe this documented dataset and split only. "
        "The bundled dataset is synthetic and is not evidence of real-world accuracy.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
