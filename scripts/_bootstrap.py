"""Shared bootstrap helpers for repository scripts.

Scripts are expected to run with the project virtual environment.  The
``sys.path`` insertion is a convenience for a source checkout that has not
been installed editable; it does not install or execute anything.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sqlalchemy import inspect

from deephoney.config.settings import Settings, load_settings
from deephoney.storage.database import Database
from deephoney.storage.repository import Repository


def settings_for(config: str | None = None) -> Settings:
    if config:
        os.environ["DEEPHONEY_CONFIG"] = str(Path(config).expanduser())
    return load_settings(project_root=ROOT)


def database_for(settings: Settings) -> Database:
    return Database(
        settings.database.url,
        echo=settings.database.echo,
        pool_size=settings.database.pool_size,
        pool_max_overflow=settings.database.pool_max_overflow,
    )


def repository_for(settings: Settings) -> Repository:
    settings.ensure_directories()
    return Repository(database_for(settings))


def ensure_schema(settings: Settings) -> None:
    """Apply Alembic migrations when the expected tables are absent."""

    database = database_for(settings)
    try:
        tables = inspect(database.engine).get_table_names()
    finally:
        database.dispose()
    if "events" in tables:
        return

    os.environ["DATABASE_URL"] = settings.database.url
    from alembic import command
    from alembic.config import Config

    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database.url)
    command.upgrade(config, "head")


def samples_dir(settings: Settings) -> Path:
    return settings.sample_dir


__all__ = [
    "ROOT",
    "SRC",
    "database_for",
    "ensure_schema",
    "repository_for",
    "samples_dir",
    "settings_for",
]
