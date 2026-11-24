#!/usr/bin/env python3
"""Import archived Cowrie/Dionaea logs with a tolerant, idempotent pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _bootstrap import ensure_schema, repository_for, settings_for
from deephoney.ingestion.pipeline import IngestionError, IngestionPipeline


def _detect_engine(path: Path) -> str:
    name = path.name.lower()
    if "cowrie" in name:
        return "cowrie"
    if "dionaea" in name:
        return "dionaea"
    if path.suffix.lower() == ".log":
        return "dionaea"
    try:
        first = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise ValueError(f"Cannot read {path}: {exc}") from exc
    for line in first:
        text = line.strip()
        if not text:
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            return "dionaea" if "dionaea" in text.lower() else "cowrie"
        if not isinstance(record, dict):
            continue
        if "eventid" in record:
            return "cowrie"
        if "type" in record or "connection" in record or "download" in record:
            return "dionaea"
        break
    raise ValueError(f"Cannot infer engine for {path}; pass --engine explicitly")


def _sample_files(settings, engine: str | None) -> list[tuple[Path, str]]:
    base = settings.sample_dir
    candidates = [
        (base / "cowrie" / "cowrie-sample.json", "cowrie"),
        (base / "dionaea" / "dionaea-sample.json", "dionaea"),
        (base / "dionaea" / "dionaea-log-json-sample.json", "dionaea"),
    ]
    selected = [
        (path, name)
        for path, name in candidates
        if path.is_file() and (engine is None or engine == name)
    ]
    if not selected:
        raise FileNotFoundError(
            f"No bundled samples found under {base}; run from a complete checkout."
        )
    return selected


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Archived log file(s)")
    parser.add_argument(
        "--engine",
        choices=["cowrie", "dionaea"],
        default=None,
        help="Force one parser; by default the engine is inferred",
    )
    parser.add_argument("--sample", action="store_true", help="Import bundled sanitized samples")
    parser.add_argument("--init-db", action="store_true", help="Apply migrations if needed")
    parser.add_argument("--no-detect", action="store_true", help="Skip Stage A detection")
    parser.add_argument("--no-archive", action="store_true", help="Do not copy raw input")
    parser.add_argument("--config", default=None, help="Alternative app YAML")
    parser.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = settings_for(args.config)
    if args.init_db:
        ensure_schema(settings)
    repository = repository_for(settings)
    pipeline = IngestionPipeline(repository, settings)

    try:
        targets: list[tuple[Path, str]] = (
            _sample_files(settings, args.engine) if args.sample else []
        )
        for raw in args.paths:
            path = Path(raw).expanduser().resolve()
            engine = args.engine or _detect_engine(path)
            targets.append((path, engine))
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print("error: pass log paths or --sample", file=sys.stderr)
        return 2

    results = []
    exit_code = 0
    for path, engine in targets:
        try:
            result = pipeline.ingest_file(
                path,
                engine,
                archive=False if args.no_archive else None,
                run_detection=not args.no_detect,
            )
        except IngestionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        results.append(result.as_dict())
        if not args.json:
            print(
                f"{engine:8} {path.name}: read={result.records_read} "
                f"created={result.records_created} skipped={result.records_skipped} "
                f"failed={result.records_failed} status={result.status}"
            )
            for error in result.errors[:5]:
                print(f"  {error}")
        if result.status == "failed":
            exit_code = 1

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        overview = repository.overview_stats()
        print(
            f"\nStored: {overview['total_events']} events, "
            f"{overview['session_count']} sessions, {overview['artifact_count']} artifacts"
        )
        print("Tip: run `deephoney detect` to rescore existing sessions without re-importing.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
