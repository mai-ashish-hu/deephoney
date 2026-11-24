#!/usr/bin/env python3
"""Seed a demonstration database with sanitized samples.

The script is idempotent: re-running it reuses deterministic event hashes,
reuses the imported PCAP by SHA-256, upserts sessions/detections, and refreshes
the model when ``--with-model`` is supplied.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _bootstrap import ensure_schema, repository_for, settings_for
from deephoney.detection.classical.train import train_classical
from deephoney.detection.service import run_detection
from deephoney.ingestion.pipeline import IngestionPipeline
from deephoney.pcap.importer import PcapImportError, import_pcap_file


def _sample_paths(settings) -> list[tuple[Path, str]]:
    candidates = [
        (settings.sample_dir / "cowrie" / "cowrie-sample.json", "cowrie"),
        (settings.sample_dir / "dionaea" / "dionaea-sample.json", "dionaea"),
        (settings.sample_dir / "dionaea" / "dionaea-log-json-sample.json", "dionaea"),
    ]
    missing = [str(path) for path, _engine in candidates if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing sample file(s): " + ", ".join(missing))
    return candidates


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None)
    parser.add_argument(
        "--with-model",
        action="store_true",
        help="Train/register a classical model on the bundled synthetic dataset",
    )
    parser.add_argument("--no-pcap", action="store_true", help="Skip the sample PCAP")
    parser.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = settings_for(args.config)
    try:
        ensure_schema(settings)
    except Exception as exc:
        print(
            "error: schema is unavailable. Start PostgreSQL and run "
            f"`alembic upgrade head`. Detail: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1

    repository = repository_for(settings)
    pipeline = IngestionPipeline(repository, settings)
    results = []
    for path, engine in _sample_paths(settings):
        result = pipeline.ingest_file(path, engine, archive=False)
        results.append(result.as_dict())

    pcap_result = None
    pcap_path = settings.sample_dir / "pcap" / "sample-ssh-scan.pcap"
    if not args.no_pcap and pcap_path.is_file():
        try:
            pcap_result = import_pcap_file(repository, pcap_path, settings)
        except PcapImportError as exc:
            print(f"warning: sample PCAP skipped: {exc}", file=sys.stderr)

    model_summary = None
    if args.with_model:
        dataset = settings.sample_dir / "synthetic" / "synthetic_sessions.csv"
        if not dataset.is_file():
            print(
                "error: synthetic dataset missing; run scripts/generate_synthetic_dataset.py",
                file=sys.stderr,
            )
            return 1
        model_summary = train_classical(
            dataset, settings.model_dir, mode="supervised", split_strategy="group"
        )

    detections = run_detection(
        repository,
        settings,
        include_ml=args.with_model,
    )
    overview = repository.overview_stats()
    summary = {
        "imports": results,
        "pcap": pcap_result,
        "model": model_summary,
        "detections": detections,
        "overview": {
            "events": overview["total_events"],
            "sessions": overview["session_count"],
            "artifacts": overview["artifact_count"],
            "unique_source_ips": overview["unique_source_ips"],
            "risk_distribution": overview["risk_distribution"],
        },
        "disclaimer": (
            "Bundled telemetry is synthetic. Risk scores demonstrate the pipeline; "
            "they are not a real-world accuracy claim."
        ),
    }
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print("DeepHoney demo seed complete")
        print(f"  events:    {overview['total_events']}")
        print(f"  sessions:  {overview['session_count']}")
        print(f"  artifacts: {overview['artifact_count']}")
        print(f"  risks:     {overview['risk_distribution']}")
        print(
            "  detections: "
            f"rules={detections['rules']} ml={detections['ml']} sequence={detections['sequence']}"
        )
        if pcap_result:
            print(
                f"  PCAP:      {pcap_result['filename']} "
                f"({pcap_result['packet_count']} packets, {pcap_result['flow_count']} flows)"
            )
        if model_summary:
            print(
                f"  model:     {model_summary['model_version']} "
                f"({model_summary['model_type']}, synthetic data)"
            )
        print("\nStart the dashboard with: make run")
        print("All sample activity is synthetic and must be labelled as such in reports.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
