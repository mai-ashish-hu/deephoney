"""Typed application settings loaded from YAML and environment variables.

The project deliberately avoids a settings framework dependency.  Pydantic
validates the merged configuration, and a tiny ``.env`` reader keeps local
development convenient without adding python-dotenv.
"""

from __future__ import annotations

import contextlib
import os
from functools import lru_cache
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DEFAULT_CONFIG_RELATIVE = Path("configs/app.yaml")


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = "DeepHoney"
    environment: str = "lab"
    display_timezone: str = "UTC"
    log_level: str = "INFO"

    @field_validator("display_timezone")
    @classmethod
    def _valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"Unknown display timezone: {value}") from exc
        return value

    @field_validator("log_level")
    @classmethod
    def _upper_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        level = value.upper()
        return level if level in allowed else "INFO"


class DatabaseConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    url: str = "postgresql+psycopg://deephoney:deephoney@127.0.0.1:5432/deephoney"
    echo: bool = False
    pool_size: int = Field(default=5, ge=1, le=50)
    pool_max_overflow: int = Field(default=5, ge=0, le=100)


class PathConfig(BaseModel):
    model_config = ConfigDict(extra="ignore", protected_namespaces=())
    data_dir: str = "data"
    raw_dir: str = "data/raw"
    processed_dir: str = "data/processed"
    artifact_dir: str = "data/artifacts"
    sample_dir: str = "data/samples"
    model_dir: str = "models"


class IngestionConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    max_line_bytes: int = Field(default=1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    archive_raw: bool = False
    follow_interval_seconds: float = Field(default=5.0, ge=0.25, le=300.0)
    parser_failure_excerpt_bytes: int = Field(default=2000, ge=128, le=20000)


class DetectionConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    rules_version: str = "2024.1.0"
    medium_threshold: int = Field(default=25, ge=0, le=100)
    high_threshold: int = Field(default=60, ge=0, le=100)
    max_evidence_items: int = Field(default=30, ge=1, le=200)
    ml_enabled: bool = False
    sequence_enabled: bool = False

    @model_validator(mode="after")
    def _ordered_thresholds(self) -> DetectionConfig:
        if self.medium_threshold >= self.high_threshold:
            raise ValueError("detection.medium_threshold must be smaller than high_threshold")
        return self


class PcapConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    max_file_bytes: int = Field(default=50 * 1024 * 1024, ge=1024)
    max_packets: int = Field(default=100_000, ge=1)
    max_seconds: int = Field(default=60, ge=1, le=3600)


class DashboardConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    page_size: int = Field(default=50, ge=5, le=500)
    cache_ttl_seconds: int = Field(default=15, ge=0, le=600)
    show_raw_events: bool = True
    reveal_passwords: bool = False

    @field_validator("reveal_passwords")
    @classmethod
    def _never_reveal_by_default(cls, value: bool) -> bool:
        return False if value else value


class SafetyConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    require_loopback_for_live_attacks: bool = True
    allow_private_lab_targets: bool = False
    allow_public_attack_targets: bool = False

    @field_validator("allow_public_attack_targets")
    @classmethod
    def _no_public_targets(cls, value: bool) -> bool:
        if value:
            raise ValueError("Public attack targets are not permitted by this project")
        return value


class Settings(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        arbitrary_types_allowed=True,
        protected_namespaces=(),
    )
    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    paths: PathConfig = Field(default_factory=PathConfig)
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    pcap: PcapConfig = Field(default_factory=PcapConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    project_root: Path = Field(default_factory=lambda: Path.cwd(), exclude=True)
    config_path: Path | None = Field(default=None, exclude=True)

    def resolve_path(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        if path.is_absolute():
            return path
        return (self.project_root / path).resolve()

    @property
    def data_dir(self) -> Path:
        return self.resolve_path(self.paths.data_dir)

    @property
    def raw_dir(self) -> Path:
        return self.resolve_path(self.paths.raw_dir)

    @property
    def processed_dir(self) -> Path:
        return self.resolve_path(self.paths.processed_dir)

    @property
    def artifact_dir(self) -> Path:
        return self.resolve_path(self.paths.artifact_dir)

    @property
    def sample_dir(self) -> Path:
        return self.resolve_path(self.paths.sample_dir)

    @property
    def model_dir(self) -> Path:
        return self.resolve_path(self.paths.model_dir)

    def ensure_directories(self) -> None:
        for directory in (
            self.data_dir,
            self.raw_dir,
            self.processed_dir,
            self.artifact_dir,
            self.sample_dir,
            self.model_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


def _read_dotenv(path: Path) -> None:
    """Populate ``os.environ`` from a simple KEY=VALUE file if present.

    Existing environment variables always win.  This intentionally supports
    only the simple syntax used by the repository's ``.env.example``.
    """

    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def _apply_environment(data: dict[str, Any]) -> dict[str, Any]:
    result = dict(data)
    result.setdefault("app", {})
    result.setdefault("database", {})
    result.setdefault("paths", {})
    result.setdefault("detection", {})
    result.setdefault("dashboard", {})
    result.setdefault("safety", {})

    database_url = os.getenv("DEEPHONEY_DATABASE_URL") or os.getenv("DATABASE_URL")
    if database_url:
        result["database"]["url"] = database_url
    if os.getenv("DEEPHONEY_DISPLAY_TIMEZONE"):
        result["app"]["display_timezone"] = os.environ["DEEPHONEY_DISPLAY_TIMEZONE"]
    if os.getenv("DEEPHONEY_ENV"):
        result["app"]["environment"] = os.environ["DEEPHONEY_ENV"]
    if os.getenv("DEEPHONEY_LOG_LEVEL"):
        result["app"]["log_level"] = os.environ["DEEPHONEY_LOG_LEVEL"]

    data_dir = os.getenv("DEEPHONEY_DATA_DIR")
    if data_dir:
        result["paths"]["data_dir"] = data_dir
        result["paths"]["raw_dir"] = str(Path(data_dir) / "raw")
        result["paths"]["processed_dir"] = str(Path(data_dir) / "processed")
        result["paths"]["artifact_dir"] = str(Path(data_dir) / "artifacts")
        result["paths"]["sample_dir"] = str(Path(data_dir) / "samples")

    if os.getenv("DEEPHONEY_RAW_DIR"):
        result["paths"]["raw_dir"] = os.environ["DEEPHONEY_RAW_DIR"]
    if os.getenv("DEEPHONEY_MODEL_DIR"):
        result["paths"]["model_dir"] = os.environ["DEEPHONEY_MODEL_DIR"]
    if os.getenv("DEEPHONEY_RULES_VERSION"):
        result["detection"]["rules_version"] = os.environ["DEEPHONEY_RULES_VERSION"]
    if os.getenv("DEEPHONEY_ML_ENABLED") is not None:
        result["detection"]["ml_enabled"] = _as_bool(os.getenv("DEEPHONEY_ML_ENABLED"))
    if os.getenv("DEEPHONEY_TORCH_ENABLED") is not None:
        result["detection"]["sequence_enabled"] = _as_bool(os.getenv("DEEPHONEY_TORCH_ENABLED"))
    if os.getenv("DEEPHONEY_CACHE_TTL_SECONDS"):
        with contextlib.suppress(ValueError):
            result["dashboard"]["cache_ttl_seconds"] = int(
                os.environ["DEEPHONEY_CACHE_TTL_SECONDS"]
            )
    if os.getenv("DEEPHONEY_ARCHIVE_RAW") is not None:
        result["ingestion"] = result.get("ingestion", {})
        result["ingestion"]["archive_raw"] = _as_bool(os.getenv("DEEPHONEY_ARCHIVE_RAW"))
    if os.getenv("DEEPHONEY_ALLOW_PRIVATE_LAB_TARGETS") is not None:
        result["safety"]["allow_private_lab_targets"] = _as_bool(
            os.getenv("DEEPHONEY_ALLOW_PRIVATE_LAB_TARGETS")
        )
    result["safety"]["allow_public_attack_targets"] = False
    if os.getenv("DEEPHONEY_REQUIRE_LOOPBACK") is not None:
        result["safety"]["require_loopback_for_live_attacks"] = _as_bool(
            os.getenv("DEEPHONEY_REQUIRE_LOOPBACK"), default=True
        )
    return result


def load_settings(
    config_path: str | Path | None = None,
    *,
    project_root: str | Path | None = None,
    load_dotenv: bool = True,
) -> Settings:
    """Load, merge, and validate DeepHoney settings.

    An explicit ``config_path`` selects which YAML file is read; it does not
    outrank environment variables.  Precedence is environment variables >
    YAML > built-in defaults.
    """

    root = (
        Path(project_root or os.getenv("DEEPHONEY_PROJECT_ROOT") or Path.cwd())
        .expanduser()
        .resolve()
    )
    if load_dotenv:
        _read_dotenv(root / ".env")

    selected = config_path or os.getenv("DEEPHONEY_CONFIG")
    candidate = Path(selected).expanduser() if selected else root / DEFAULT_CONFIG_RELATIVE
    if not candidate.is_absolute():
        candidate = root / candidate
    data = _load_yaml(candidate)
    data = _apply_environment(data)
    data["project_root"] = root
    data["config_path"] = candidate if candidate.is_file() else None
    settings = Settings.model_validate(data)
    return settings


@lru_cache(maxsize=8)
def get_settings() -> Settings:
    """Return cached settings for the current process."""

    return load_settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()


__all__ = [
    "AppConfig",
    "DashboardConfig",
    "DatabaseConfig",
    "DetectionConfig",
    "IngestionConfig",
    "PathConfig",
    "PcapConfig",
    "SafetyConfig",
    "Settings",
    "get_settings",
    "load_settings",
    "reset_settings_cache",
]
