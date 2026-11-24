"""DeepHoney command line interface.

The CLI covers the operational path: database setup, offline ingestion,
follow-mode collection, session rebuilds, detection, PCAP import, safe
exports, model training, health checks, and launching the dashboard.

Examples::

    deephoney init-db
    deephoney ingest data/samples/cowrie/cowrie-sample.json --engine cowrie
    deephoney detect --ml
    deephoney import-pcap data/samples/pcap/sample-ssh-scan.pcap
    deephoney report --kind summary --format json
    deephoney healthcheck --json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from deephoney import __version__
from deephoney.config.logging import configure_logging, get_logger
from deephoney.config.settings import Settings, load_settings
from deephoney.detection.service import run_detection
from deephoney.ingestion.pipeline import IngestionError, IngestionPipeline
from deephoney.pcap.importer import PcapImportError, import_pcap_file
from deephoney.reporting import build_summary, export_payload, write_export
from deephoney.storage.database import Database
from deephoney.storage.repository import Repository
from deephoney.utils.net import tcp_probe
from deephoney.utils.time import parse_range, parse_timestamp, utcnow

logger = get_logger(__name__)

DASHBOARD_APP = Path(__file__).resolve().parent / "dashboard" / "app.py"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deephoney",
        description=(
            "DeepHoney: defensive multi-honeypot monitoring. "
            "Operate only on honeypots you own in an isolated lab."
        ),
    )
    parser.add_argument("--version", action="version", version=f"deephoney {__version__}")
    parser.add_argument("--project-root", default=None, help="Repository/project root")
    parser.add_argument("--config", default=None, help="Path to app YAML config")
    parser.add_argument("--log-level", default=None, help="DEBUG, INFO, WARNING, ERROR")
    sub = parser.add_subparsers(dest="command", required=True)

    init_db = sub.add_parser("init-db", help="Apply Alembic migrations")
    init_db.add_argument(
        "--create-all",
        action="store_true",
        help="Create tables directly (development convenience; migrations are preferred)",
    )
    init_db.set_defaults(func=_cmd_init_db)

    ingest = sub.add_parser("ingest", help="Import one or more archived log files")
    ingest.add_argument("paths", nargs="+", help="Log file(s) to import")
    ingest.add_argument("--engine", required=True, choices=["cowrie", "dionaea"])
    ingest.add_argument("--no-detect", action="store_true", help="Skip Stage A detection")
    ingest.add_argument("--no-archive", action="store_true", help="Do not copy the raw log")
    ingest.add_argument("--json", action="store_true", help="Print machine-readable results")
    ingest.set_defaults(func=_cmd_ingest)

    follow = sub.add_parser("follow", help="Tail honeypot logs continuously")
    follow.add_argument(
        "--cowrie-glob",
        default=os.getenv("COWRIE_LOG_GLOB", "data/raw/cowrie/*.json"),
        help="Glob for Cowrie JSON logs",
    )
    follow.add_argument(
        "--dionaea-glob",
        default=os.getenv("DIONAEA_LOG_GLOB", "data/raw/dionaea/*.json"),
        help="Glob for Dionaea log_json records",
    )
    follow.add_argument(
        "--dionaea-plain-glob",
        default=os.getenv("DIONAEA_PLAIN_LOG_GLOB", ""),
        help="Optional glob for Dionaea's human-readable log (capture metadata fallback)",
    )
    follow.add_argument("--once", action="store_true", help="Process available data once")
    follow.set_defaults(func=_cmd_follow)

    rebuild = sub.add_parser("rebuild-sessions", help="Rebuild sessions from stored events")
    rebuild.add_argument("--engine", choices=["cowrie", "dionaea"])
    rebuild.add_argument(
        "--prune", action="store_true", help="Remove stale sessions for the engine"
    )
    rebuild.set_defaults(func=_cmd_rebuild_sessions)

    detect = sub.add_parser("detect", help="Run detection against stored sessions")
    detect.add_argument("--engine", choices=["cowrie", "dionaea"])
    detect.add_argument(
        "--session-id", action="append", default=[], help="Limit to source session id"
    )
    detect.add_argument("--ml", action="store_true", help="Also run a registered classical model")
    detect.add_argument(
        "--sequence", action="store_true", help="Also run the optional sequence model"
    )
    detect.add_argument("--json", action="store_true")
    detect.set_defaults(func=_cmd_detect)

    pcap = sub.add_parser("import-pcap", help="Import bounded, metadata-only PCAP flows")
    pcap.add_argument("paths", nargs="+", help=".pcap or .pcapng file(s)")
    pcap.add_argument("--json", action="store_true")
    pcap.set_defaults(func=_cmd_import_pcap)

    report = sub.add_parser("report", help="Build a sanitized JSON/CSV export")
    report.add_argument(
        "--kind",
        choices=[
            "summary",
            "events",
            "sessions",
            "detections",
            "pcap-flows",
            "ingestion-runs",
            "parser-failures",
        ],
        default="summary",
    )
    report.add_argument("--format", choices=["json", "csv"], default="json")
    report.add_argument("--out", default=None, help="Output path; stdout when omitted")
    report.add_argument("--start", default=None, help="Inclusive ISO start (UTC)")
    report.add_argument("--end", default=None, help="Inclusive ISO end (UTC)")
    report.add_argument("--limit", type=int, default=20_000)
    report.add_argument("--capture-id", default=None, help="For PCAP flows (optional)")
    report.set_defaults(func=_cmd_report)

    train = sub.add_parser("train", help="Train a classical Random Forest / Isolation Forest")
    train.add_argument("--dataset", required=True, help="CSV with FEATURE_NAMES and label")
    train.add_argument("--mode", choices=["auto", "supervised", "anomaly"], default="auto")
    train.add_argument("--split", choices=["group", "time", "stratified"], default="group")
    train.add_argument("--seed", type=int, default=42)
    train.add_argument("--contamination", type=float, default=0.1)
    train.add_argument("--model-dir", default=None)
    train.set_defaults(func=_cmd_train)

    train_seq = sub.add_parser(
        "train-sequence", help="Train the optional GRU command-sequence model"
    )
    train_seq.add_argument("--dataset", required=True, help="JSONL with commands and label")
    train_seq.add_argument("--epochs", type=int, default=12)
    train_seq.add_argument("--batch-size", type=int, default=16)
    train_seq.add_argument("--learning-rate", type=float, default=1e-3)
    train_seq.add_argument("--max-len", type=int, default=64)
    train_seq.add_argument("--seed", type=int, default=42)
    train_seq.add_argument("--model-dir", default=None)
    train_seq.set_defaults(func=_cmd_train_sequence)

    health = sub.add_parser("healthcheck", help="Check database, ingestion, models, and services")
    health.add_argument("--json", action="store_true")
    health.add_argument(
        "--probe", action="store_true", help="TCP-probe configured honeypot endpoints"
    )
    health.set_defaults(func=_cmd_healthcheck)

    dashboard = sub.add_parser("dashboard", help="Launch the Streamlit dashboard")
    dashboard.add_argument("--address", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8501)
    dashboard.set_defaults(func=_cmd_dashboard)

    return parser


def _settings(args: argparse.Namespace) -> Settings:
    if args.project_root:
        os.environ["DEEPHONEY_PROJECT_ROOT"] = str(Path(args.project_root).expanduser().resolve())
    settings = load_settings(config_path=args.config, project_root=args.project_root)
    if args.log_level:
        settings.app.log_level = args.log_level.upper()
    configure_logging(settings.app.log_level)
    return settings


def _database(settings: Settings) -> Database:
    return Database(
        settings.database.url,
        echo=settings.database.echo,
        pool_size=settings.database.pool_size,
        pool_max_overflow=settings.database.pool_max_overflow,
    )


def _repository(settings: Settings) -> Repository:
    settings.ensure_directories()
    return Repository(_database(settings))


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def _cmd_init_db(args: argparse.Namespace) -> int:
    settings = _settings(args)
    if args.create_all:
        database = _database(settings)
        database.create_all()
        print(f"Created schema directly in {database.dialect_name}.")
        print("For a real deployment use `alembic upgrade head` instead.")
        return 0

    root = settings.project_root
    os.environ["DATABASE_URL"] = settings.database.url
    try:
        from alembic import command
        from alembic.config import Config
    except ImportError:
        print("Alembic is not installed. Install requirements-dev.lock.", file=sys.stderr)
        return 2

    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database.url)
    command.upgrade(config, "head")
    print(f"Database migrated to head using {settings.database.url.split('@')[-1]}")
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    settings = _settings(args)
    repository = _repository(settings)
    pipeline = IngestionPipeline(repository, settings)
    results = []
    exit_code = 0
    for path in args.paths:
        try:
            result = pipeline.ingest_file(
                path,
                args.engine,
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
                f"{path}: read={result.records_read} created={result.records_created} "
                f"skipped={result.records_skipped} failed={result.records_failed} "
                f"status={result.status}"
            )
            for error in result.errors[:10]:
                print(f"  {error}")
        if result.status == "failed":
            exit_code = 1
    if args.json:
        _print_json(results)
    return exit_code


def _cmd_follow(args: argparse.Namespace) -> int:
    settings = _settings(args)
    pipeline = IngestionPipeline(_repository(settings), settings)
    sources = [
        ("cowrie", args.cowrie_glob),
        ("dionaea", args.dionaea_glob),
    ]
    if args.dionaea_plain_glob:
        sources.append(("dionaea", args.dionaea_plain_glob))
    pipeline.follow(sources, once=args.once)
    return 0


def _cmd_rebuild_sessions(args: argparse.Namespace) -> int:
    settings = _settings(args)
    repository = _repository(settings)
    count = repository.rebuild_sessions(engine=args.engine, prune=args.prune)
    print(f"Rebuilt {count} session(s){' for ' + args.engine if args.engine else ''}.")
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    settings = _settings(args)
    repository = _repository(settings)
    session_ids = set(args.session_id) or None
    results = run_detection(
        repository,
        settings,
        include_ml=args.ml,
        include_sequence=args.sequence,
        engine=args.engine,
        session_ids=session_ids,
    )
    if args.json:
        _print_json(results)
    else:
        print(
            "Detection complete: "
            f"rules={results['rules']} ml={results['ml']} sequence={results['sequence']}"
        )
        if not args.ml and not settings.detection.ml_enabled:
            print("Classical ML was not requested (use --ml after training a model).")
    return 0


def _cmd_import_pcap(args: argparse.Namespace) -> int:
    settings = _settings(args)
    repository = _repository(settings)
    results = []
    exit_code = 0
    for path in args.paths:
        try:
            outcome = import_pcap_file(repository, path, settings)
        except PcapImportError as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        results.append(outcome)
        if not args.json:
            print(
                f"{outcome['filename']}: imported={outcome['imported']} "
                f"packets={outcome['packet_count']} flows={outcome['flow_count']} "
                f"truncated={outcome['truncated']} sha256={outcome['sha256']}"
            )
    if args.json:
        _print_json(results)
    return exit_code


def _cmd_report(args: argparse.Namespace) -> int:
    settings = _settings(args)
    repository = _repository(settings)
    try:
        start, end = parse_range(args.start, args.end)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.kind == "summary":
        summary = build_summary(repository, start=start, end=end)
        columns = None
        rows: list[dict[str, Any]] = [summary]
    elif args.kind == "events":
        rows = repository.export_events(start=start, end=end, limit=args.limit)
        columns = None
    elif args.kind == "sessions":
        rows = repository.export_sessions(start=start, end=end, limit=args.limit)
        columns = None
    elif args.kind == "detections":
        rows = repository.export_detections(start=start, end=end, limit=args.limit)
        columns = None
    elif args.kind == "pcap-flows":
        rows, _total = repository.get_pcap_flows(args.capture_id, limit=min(args.limit, 5000))
        columns = None
    elif args.kind == "ingestion-runs":
        rows = repository.get_ingestion_runs(limit=min(args.limit, 500))
        columns = [
            "run_id",
            "source_engine",
            "source_file",
            "started_at",
            "status",
            "records_read",
            "records_created",
            "records_skipped",
            "records_failed",
        ]
    else:
        rows = repository.get_parser_failures(limit=min(args.limit, 500))
        columns = [
            "failure_id",
            "source_engine",
            "source_file",
            "line_number",
            "error",
            "created_at",
        ]

    if args.out:
        target = write_export(rows, args.out, args.format, columns=columns)
        print(f"Wrote {len(rows)} row(s) to {target}")
    else:
        content, _media_type = export_payload(rows, args.format, columns=columns)
        sys.stdout.write(content.decode("utf-8"))
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    settings = _settings(args)
    from deephoney.detection.classical.train import train_classical

    model_dir = Path(args.model_dir).expanduser() if args.model_dir else settings.model_dir
    summary = train_classical(
        args.dataset,
        model_dir,
        mode=args.mode,
        split_strategy=args.split,
        seed=args.seed,
        contamination=args.contamination,
    )
    _print_json(summary)
    print(
        "\nReminder: metrics describe the documented dataset and split only. "
        "A synthetic training set is not evidence of real-world accuracy.",
        file=sys.stderr,
    )
    return 0


def _cmd_train_sequence(args: argparse.Namespace) -> int:
    settings = _settings(args)
    from deephoney.detection.sequence.model import train_sequence_model

    model_dir = Path(args.model_dir).expanduser() if args.model_dir else settings.model_dir
    summary = train_sequence_model(
        args.dataset,
        model_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        max_len=args.max_len,
        seed=args.seed,
    )
    _print_json(summary)
    return 0


def _probe_services() -> list[dict[str, Any]]:
    targets = [
        (
            "Cowrie SSH",
            os.getenv("DEEPHONEY_COWRIE_HOST", "127.0.0.1"),
            int(os.getenv("DEEPHONEY_COWRIE_SSH_PORT", "2222")),
        ),
        (
            "Cowrie Telnet",
            os.getenv("DEEPHONEY_COWRIE_HOST", "127.0.0.1"),
            int(os.getenv("DEEPHONEY_COWRIE_TELNET_PORT", "2223")),
        ),
        (
            "Dionaea FTP",
            os.getenv("DEEPHONEY_DIONAEA_HOST", "127.0.0.1"),
            int(os.getenv("DEEPHONEY_DIONAEA_FTP_PORT", "2121")),
        ),
        (
            "Dionaea HTTP",
            os.getenv("DEEPHONEY_DIONAEA_HOST", "127.0.0.1"),
            int(os.getenv("DEEPHONEY_DIONAEA_HTTP_PORT", "8080")),
        ),
    ]
    rows = []
    for name, host, port in targets:
        result = tcp_probe(host, port, timeout=1.5)
        rows.append(
            {
                "service": name,
                "endpoint": f"{host}:{port}",
                "open": result.open,
                "latency_ms": result.latency_ms,
                "error": result.error,
            }
        )
    return rows


def _cmd_healthcheck(args: argparse.Namespace) -> int:
    settings = _settings(args)
    repository = _repository(settings)
    database = repository.database
    online = database.ping()
    failures = repository.get_parser_failures(limit=500) if online else []
    recent_cutoff = utcnow().timestamp() - 24 * 3600
    recent_failures = 0
    for failure in failures:
        created = parse_timestamp(failure.get("created_at"))
        if created is not None and created.timestamp() >= recent_cutoff:
            recent_failures += 1
    from deephoney.dashboard.data import model_registry_summary

    report: dict[str, Any] = {
        "checked_at": utcnow().isoformat(),
        "database": {
            "online": online,
            "dialect": database.dialect_name,
            "url_configured": bool(settings.database.url),
        },
        "ingestion": repository.last_ingestion_by_engine() if online else {},
        "parser_failures_24h": recent_failures,
        "models": (
            [
                {
                    "slot": row.get("slot"),
                    "model_version": row.get("model_version"),
                    "model_type": row.get("model_type"),
                }
                for row in model_registry_summary(settings)
            ]
            if online
            else []
        ),
    }
    if args.probe:
        report["services"] = _probe_services()
    if args.json:
        _print_json(report)
    else:
        print(f"Database: {'online' if online else 'OFFLINE'} ({database.dialect_name})")
        if online:
            for engine, last in (report["ingestion"] or {}).items():
                status = last.get("status") if last else "no runs"
                started = last.get("started_at") if last else "never"
                print(f"  {engine}: last={started} status={status}")
            print(f"Parser failures (24h): {recent_failures}")
            models = report["models"]
            print(f"Models registered: {len(models) if models else 0}")
        if args.probe:
            for row in report.get("services", []):
                state = "open" if row["open"] else "closed"
                print(f"  {row['service']} {row['endpoint']}: {state}")
    return 0 if online else 1


def _cmd_dashboard(args: argparse.Namespace) -> int:
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(DASHBOARD_APP),
        "--server.address",
        args.address,
        "--server.port",
        str(args.port),
    ]
    try:
        return subprocess.call(command)
    except FileNotFoundError:
        print("Streamlit is not installed. Install requirements-dev.lock.", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        logger.error("%s", exc)
        print(f"error: {exc}", file=sys.stderr)
        return 1


__all__ = ["main"]

if __name__ == "__main__":
    raise SystemExit(main())
