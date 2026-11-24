#!/usr/bin/env python3
"""Send bounded, benign traffic to a honeypot you own (loopback by default)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("all", "ssh-bruteforce", "ssh-post-exploit", "http-probe", "ftp-probe", "tcp-probe")


def _simulator():
    for candidate in (ROOT / "src", ROOT / "scripts"):
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    from attack_simulator import run_live_simulation
    from deephoney.utils.net import validate_live_target

    return run_live_simulation, validate_live_target


def _confirm(host: str, port: int, *, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("Refusing non-interactive live probing without --yes.", file=sys.stderr)
        return False
    answer = input(f"Send limited lab traffic to {host}:{port} (a honeypot you own)? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--scenario", choices=SCENARIOS, default="all")
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--allow-private-lab", action="store_true")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535 or not 1 <= args.http_port <= 65535:
        print("error: ports must be between 1 and 65535", file=sys.stderr)
        return 2

    run_simulation, validate_target = _simulator()
    try:
        target = validate_target(args.host, allow_private_lab=args.allow_private_lab)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not _confirm(target, args.port, assume_yes=args.yes):
        print("cancelled", file=sys.stderr)
        return 1

    scenario = "tcp-probe" if args.scenario == "ftp-probe" else args.scenario
    summary = run_simulation(
        target,
        scenario=scenario,
        port=args.port,
        http_port=args.http_port,
        allow_private_lab=args.allow_private_lab,
        max_attempts=max(1, min(args.max_attempts, 10)),
        timeout=max(0.5, min(args.timeout, 10.0)),
    )
    print(json.dumps(summary, indent=2, default=str))
    print("No exploits, downloads, persistence, or arbitrary commands were used.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
