#!/usr/bin/env python3
"""Generate synthetic lab logs and ingest them into the configured database."""

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


def _components():
    for candidate in (ROOT / "src", ROOT / "scripts"):
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    from attack_simulator import generate_scenario_logs
    from deephoney.config.settings import load_settings
    from deephoney.ingestion.pipeline import IngestionPipeline
    from deephoney.storage.database import Database
    from deephoney.storage.repository import Repository

    return generate_scenario_logs, load_settings, IngestionPipeline, Database, Repository


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, default="all")
    parser.add_argument("--out", default=str(ROOT / "data/samples/generated"))
    parser.add_argument("--base-time", default="2024-08-15T12:00:00Z")
    parser.add_argument("--config", default=None)
    parser.add_argument("--no-detect", action="store_true")
    args = parser.parse_args()

    generate, load_settings, pipeline_cls, database_cls, repository_cls = _components()
    try:
        paths = generate(args.out, scenario=args.scenario, base_time=args.base_time)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    settings = load_settings(config_path=args.config, project_root=ROOT)
    settings.ensure_directories()
    repository = repository_cls(database_cls(settings.database.url))
    pipeline = pipeline_cls(repository, settings)
    for path in paths:
        engine = "cowrie" if "cowrie" in path.name else "dionaea"
        result = pipeline.ingest_file(path, engine, archive=False, run_detection=not args.no_detect)
        print(
            f"Ingested {path.name}: read={result.records_read} created={result.records_created} "
            f"skipped={result.records_skipped} failed={result.records_failed} status={result.status}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
