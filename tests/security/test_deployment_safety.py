"""Security regression tests for deployment and display boundaries."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _compose() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_honeypots_have_no_host_mounts_or_docker_socket() -> None:
    compose = _compose()
    named_volumes = set(compose["volumes"])
    for service_name in ("cowrie", "dionaea"):
        service = compose["services"][service_name]
        for volume in service.get("volumes", []):
            source = volume.split(":", 1)[0]
            assert source in named_volumes, (service_name, volume)
            assert not source.startswith((".", "/", "~")), (service_name, volume)
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "docker.sock" not in text
    assert "network_mode: host" not in text
    assert "privileged: true" not in text


def test_published_ports_default_to_loopback() -> None:
    compose = _compose()
    for service_name, service in compose["services"].items():
        for mapping in service.get("ports", []):
            assert mapping.startswith("${LAB_BIND_ADDRESS"), (service_name, mapping)


def test_management_database_is_not_published() -> None:
    compose = _compose()
    assert "ports" not in compose["services"]["postgres"]


def test_honeypot_hardening_options() -> None:
    compose = _compose()
    for service_name in ("cowrie", "dionaea"):
        service = compose["services"][service_name]
        assert "ALL" in service["cap_drop"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service.get("pids_limit")
        assert service.get("mem_limit")


def test_networks_are_internal() -> None:
    compose = _compose()
    assert compose["networks"]["backend"]["internal"] is True
    assert compose["networks"]["honeypot_ingress"]["internal"] is True


def test_gitignore_excludes_secrets_runtime_data_and_models() -> None:
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".env", "data/raw/*", "models/*", "*.pcap"):
        assert pattern in ignored
    assert not (ROOT / ".env").exists()


def test_no_committed_private_keys_or_cloud_tokens() -> None:
    patterns = {
        "private-key": re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
        "aws-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    }
    skip_dirs = {".git", ".venv", "__pycache__", ".ruff_cache", ".pytest_cache", "models"}
    offenses: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix.lower() in {".joblib", ".pcap", ".png", ".jpg", ".gif", ".zip", ".gz"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for label, pattern in patterns.items():
            if pattern.search(text):
                offenses.append(f"{label}: {path.relative_to(ROOT)}")
    assert offenses == []


def test_raw_events_and_exports_redact_passwords(repository, settings, sample_paths) -> None:
    from deephoney.ingestion.pipeline import IngestionPipeline

    IngestionPipeline(repository, settings).ingest_file(
        sample_paths["cowrie"], "cowrie", archive=False
    )
    rows = repository.export_events()
    serialised = str(rows)
    assert "DEMO_PASSWORD_NOT_REAL_01" not in serialised
    assert "[REDACTED]" in serialised

    row = next(item for item in rows if item["event_type"] == "auth_failure")
    assert row["raw_payload"]["password"] == "[REDACTED]"


def test_csv_exports_neutralise_attacker_controlled_cells() -> None:
    from deephoney.reporting.exports import rows_to_csv

    text = rows_to_csv([{"command": "=cmd|' /C calc'!A0", "src_ip": "@SUM(1+1)"}])
    assert "'=cmd" in text
    assert "'@SUM" in text
