#!/usr/bin/env python3
"""Replay stored normalized events through session rebuild and detection."""

from __future__ import annotations

import argparse
import json
import sys

from _bootstrap import repository_for, settings_for
from deephoney.detection.service import run_detection


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["cowrie", "dionaea"])
    parser.add_argument("--session-id", action="append", default=[])
    parser.add_argument("--ml", action="store_true", help="Include a registered classical model")
    parser.add_argument(
        "--sequence", action="store_true", help="Include the optional sequence model"
    )
    parser.add_argument(
        "--prune", action="store_true", help="Remove sessions for the selected engine"
    )
    parser.add_argument("--config", default=None)
    parser.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = settings_for(args.config)
    repository = repository_for(settings)
    session_ids = set(args.session_id) or None

    if not repository.database.ping():
        print("error: database is not reachable", file=sys.stderr)
        return 1
    sessions = repository.rebuild_sessions(
        engine=args.engine, session_ids=session_ids, prune=args.prune
    )
    results = run_detection(
        repository,
        settings,
        include_ml=args.ml,
        include_sequence=args.sequence,
        engine=args.engine,
        session_ids=session_ids,
    )
    payload = {
        "rebuilt_sessions": sessions,
        "detections": results,
        "engine": args.engine,
        "pruned": args.prune,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"Replayed stored events: rebuilt={sessions} rules={results['rules']} "
            f"ml={results['ml']} sequence={results['sequence']}"
        )
        if args.ml and results["ml"] == 0:
            print("No classical model scored any session; train one with scripts/train_model.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
