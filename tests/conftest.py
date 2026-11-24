"""Shared test configuration.

Tests use a temporary SQLite database created by the real Alembic
migrations, so the migration path is exercised rather than bypassed with
``metadata.create_all``.  Every test gets its own database file.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from deephoney.config.settings import Settings, load_settings, reset_settings_cache
from deephoney.storage.database import Database
from deephoney.storage.repository import Repository

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def project_root() -> Path:
    return ROOT


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    database_url = f"sqlite:///{tmp_path / 'deephoney-test.db'}"
    data_dir = tmp_path / "data"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("DEEPHONEY_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DEEPHONEY_MODEL_DIR", str(tmp_path / "models"))
    monkeypatch.delenv("DEEPHONEY_CONFIG", raising=False)
    monkeypatch.delenv("DEEPHONEY_ML_ENABLED", raising=False)
    monkeypatch.delenv("DEEPHONEY_TORCH_ENABLED", raising=False)
    reset_settings_cache()
    loaded = load_settings(project_root=ROOT, load_dotenv=False)
    loaded.ensure_directories()
    try:
        yield loaded
    finally:
        reset_settings_cache()


@pytest.fixture
def database(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Iterator[Database]:
    monkeypatch.setenv("DATABASE_URL", settings.database.url)
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(config, "head")
    db = Database(settings.database.url)
    try:
        yield db
    finally:
        db.dispose()


@pytest.fixture
def repository(database: Database) -> Repository:
    return Repository(database)


@pytest.fixture
def sample_dir(project_root: Path) -> Path:
    return project_root / "data" / "samples"


@pytest.fixture
def sample_paths(sample_dir: Path) -> dict[str, Path]:
    return {
        "cowrie": sample_dir / "cowrie" / "cowrie-sample.json",
        "dionaea": sample_dir / "dionaea" / "dionaea-sample.json",
        "dionaea_json": sample_dir / "dionaea" / "dionaea-log-json-sample.json",
        "pcap": sample_dir / "pcap" / "sample-ssh-scan.pcap",
        "synthetic": sample_dir / "synthetic" / "synthetic_sessions.csv",
        "sequences": sample_dir / "synthetic" / "command_sequences.jsonl",
    }


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent a developer's shell from changing test meaning."""

    for name in (
        "DEEPHONEY_RULES_VERSION",
        "DEEPHONEY_ARCHIVE_RAW",
        "DEEPHONEY_REQUIRE_LOOPBACK",
        "DEEPHONEY_ALLOW_PRIVATE_LAB_TARGETS",
        "DEEPHONEY_ALLOW_PUBLIC_ATTACK_TARGETS",
        "DEEPHONEY_DATABASE_URL",
        "DEEPHONEY_CACHE_TTL_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)


def pytest_configure() -> None:
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
