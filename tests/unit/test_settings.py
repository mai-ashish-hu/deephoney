"""Unit tests for configuration loading and safety validation."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from deephoney.config.settings import (
    DetectionConfig,
    SafetyConfig,
    Settings,
    _apply_environment,
    load_settings,
)
from deephoney.storage.database import normalize_database_url

ROOT = Path(__file__).resolve().parents[2]


def test_defaults_are_lab_safe() -> None:
    settings = Settings()
    assert settings.app.environment == "lab"
    assert settings.dashboard.reveal_passwords is False
    assert settings.safety.allow_public_attack_targets is False
    assert settings.detection.medium_threshold < settings.detection.high_threshold


def test_load_settings_reads_yaml_and_environment(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "app.yaml"
    config.write_text(
        "app:\n  environment: test\ndatabase:\n  url: sqlite:///x.db\n"
        "detection:\n  medium_threshold: 20\n  high_threshold: 70\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DEEPHONEY_DISPLAY_TIMEZONE", "Europe/Berlin")
    settings = load_settings(config, project_root=ROOT, load_dotenv=False)
    assert settings.app.environment == "test"
    assert settings.app.display_timezone == "Europe/Berlin"
    assert settings.detection.medium_threshold == 20
    assert settings.database.url == "sqlite:///x.db"


def test_environment_overrides_yaml(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "app.yaml"
    config.write_text("database:\n  url: sqlite:///from-yaml.db\n", encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///from-env.db")
    settings = load_settings(config, project_root=ROOT, load_dotenv=False)
    assert settings.database.url == "sqlite:///from-env.db"


def test_invalid_thresholds_are_rejected() -> None:
    with pytest.raises(ValidationError, match="medium_threshold"):
        DetectionConfig(medium_threshold=70, high_threshold=60)


def test_unknown_timezone_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Unknown display timezone"):
        Settings.model_validate({"app": {"display_timezone": "Mars/Olympus"}})


def test_public_attack_targets_can_never_be_enabled(monkeypatch) -> None:
    monkeypatch.setenv("DEEPHONEY_ALLOW_PUBLIC_ATTACK_TARGETS", "1")
    merged = _apply_environment({"safety": {}})
    assert merged["safety"]["allow_public_attack_targets"] is False
    with pytest.raises(ValidationError, match="Public attack targets"):
        SafetyConfig(allow_public_attack_targets=True)


def test_reveal_passwords_is_forced_off() -> None:
    settings = Settings.model_validate({"dashboard": {"reveal_passwords": True}})
    assert settings.dashboard.reveal_passwords is False


def test_database_url_normalisation() -> None:
    assert normalize_database_url("postgresql://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_database_url("postgres://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert normalize_database_url("sqlite:///x.db") == "sqlite:///x.db"


def test_paths_resolve_against_project_root(tmp_path: Path) -> None:
    settings = Settings.model_validate(
        {"paths": {"data_dir": "custom-data"}, "project_root": tmp_path}
    )
    assert settings.data_dir == (tmp_path / "custom-data").resolve()
    settings.ensure_directories()
    assert settings.data_dir.is_dir()
