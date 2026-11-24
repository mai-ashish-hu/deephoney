# DeepHoney

Multi-honeypot threat monitoring for isolated defensive labs. DeepHoney ingests Cowrie and Dionaea telemetry, reconstructs sessions, extracts deterministic features, applies transparent risk rules and optional models, and presents redacted findings in a Streamlit dashboard.

> [!WARNING]
> Use this project only on honeypots you own inside an isolated lab. Never point the live simulator at public systems. Risk scores are prioritisation aids, not proof of malicious intent or attribution.

## Features

- Tolerant, idempotent ingestion of Cowrie and Dionaea JSON/JSONL logs, plus a bounded plaintext Dionaea fallback.
- Session reconstruction with provenance, no cross-engine merging by IP, and evidence-preserving ordering.
- Versioned, deterministic feature extraction with explainable rule scoring and optional classical/sequence models.
- Redaction at every display/export boundary: credentials, commands, details, evidence, and parser failure excerpts are sanitised.
- CSV exports neutralise spreadsheet formula injection; PCAP import stores metadata only, never payloads.
- Paginated Streamlit dashboard with events, sessions, detections, artifacts, threat analysis, reports, and health checks.
- Safe attack-simulation scripts for generating lab activity without exploits or payloads.

## Quick start

The Docker Compose lab is the recommended path. It keeps honeypot traffic on internal networks and publishes management ports to loopback only.

```bash
cp .env.example .env
make docker-up
make docker-seed
make docker-smoke
```

Open <http://127.0.0.1:8501>.

> [!IMPORTANT]
> Edit `.env` before starting the lab. Replace the placeholder PostgreSQL password and keep `LAB_BIND_ADDRESS=127.0.0.1` unless you have explicitly secured the host.

## Local development

Python 3.12.5 is required. PostgreSQL is used in deployment; tests use temporary SQLite databases via the real Alembic migrations.

```bash
make prepare
make install-dev
source .venv/bin/activate
make migrate
make seed
make run
```

## Command line

Run any command with `python -m deephoney <command>` or `deephoney <command>` after activation.

| Command | Purpose |
| --- | --- |
| `init-db` | Apply Alembic migrations (`--create-all` for a quick local schema) |
| `ingest <path> --engine cowrie|dionaea` | Import archived logs with deduplication |
| `follow --once` | Tail log globs once, or continuously without `--once` |
| `rebuild-sessions --engine ...` | Rebuild sessions from stored events (`--prune` removes stale rows) |
| `detect [--ml] [--sequence]` | Run rules and optionally registered models |
| `import-pcap <path>` | Import bounded, metadata-only PCAP flows |
| `report --kind summary|events|sessions|detections --format json|csv` | Produce sanitised exports |
| `train --dataset ... --mode supervised` | Train and register a classical model |
| `healthcheck --probe` | Check database, ingestion, models, and local endpoints |
| `dashboard` | Launch the Streamlit app |

Use `--json` on most commands for machine-readable output.

## Safe attack simulation

The `attack/` directory contains lab-only simulators. They use placeholder credentials and allowlisted commands, never send exploits, never download files, and refuse public targets.

```bash
# Generate synthetic Cowrie/Dionaea JSONL logs only; no network traffic.
python attack/generate_logs.py --scenario all --out data/samples/generated

# Generate logs and ingest them into the configured database.
python attack/ingest_simulated.py --scenario all

# Send bounded, benign traffic to a honeypot on loopback.
python attack/lab_probe.py --host 127.0.0.1 --yes
```

> [!WARNING]
> Live probing accepts only loopback by default. A private lab address requires `--allow-private-lab`; public addresses are always refused. You must still obtain written authorization for any system you do not own.

## Project layout

```text
src/deephoney/     parsers, ingestion, storage, detection, dashboard, CLI
attack/            safe lab-only activity generators and probes
configs/           application YAML configuration
deployments/       Cowrie and Dionaea container definitions
migrations/        Alembic schema history
scripts/           seeding, dataset generation, replay, utilities
tests/             unit, integration, and security tests
```

## Safety and data handling

> [!IMPORTANT]
> Passwords and secrets are replaced with `[REDACTED]` at the serialization boundary. Raw events are retained only for deterministic hashing and reconstruction, and are redacted before display or export. Exported cells are formula-neutralised. Captured binary payloads are never stored or served.

The dashboard is bound to loopback and the Compose networks are internal. There are no host mounts or Docker socket mounts for honeypot services.

## Quality checks

```bash
make test
make lint
make format
make check-versions
```

The suite covers parsing, redaction, ingestion, persistence, detection, PCAP metadata, exports, dashboard helpers, and deployment safety.

## Version baseline

This project reconstructs the March–August 2024 academic release. Dependency versions are frozen as of 2024-08-31; the requirement documents were rebuilt on 14 November 2026 to keep that original baseline reproducible.

## Resources

- [Cowrie](https://github.com/cowrie/cowrie)
- [Dionaea](https://github.com/DinoTools/dionaea)
- [Streamlit](https://docs.streamlit.io/)
- [SQLAlchemy](https://docs.sqlalchemy.org/)
