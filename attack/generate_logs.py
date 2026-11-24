#!/usr/bin/env python3
"""Generate synthetic Cowrie/Dionaea JSONL logs without any network traffic."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    "all",
    "ssh-bruteforce",
    "ssh-post-exploit",
    "http-probe",
    "ftp-probe",
)


def _generator():
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    from attack_simulator import generate_scenario_logs

    return generate_scenario_logs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, default="all")
    parser.add_argument("--out", default=str(ROOT / "data/samples/generated"))
    parser.add_argument("--base-time", default="2024-08-15T12:00:00Z")
    args = parser.parse_args()
    try:
        paths = _generator()(
            args.out,
            scenario=args.scenario,
            base_time=args.base_time,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for path in paths:
        print(f"Wrote synthetic log: {path}")
    print("No network traffic was sent. Ingest with attack/ingest_simulated.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
