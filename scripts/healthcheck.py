#!/usr/bin/env python3
"""Database, ingestion, model, and optional service health check."""

from __future__ import annotations

import argparse

from _bootstrap import ROOT
from deephoney.cli import main as cli_main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--probe", action="store_true", help="TCP-probe local honeypot ports")
    args = parser.parse_args()
    argv = ["--project-root", str(ROOT)]
    if args.config:
        argv.extend(["--config", args.config])
    argv.append("healthcheck")
    if args.json:
        argv.append("--json")
    if args.probe:
        argv.append("--probe")
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
