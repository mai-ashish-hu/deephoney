"""Version-policy tests for the March-August 2024 dependency baseline.

The PRD's published version table describes a newer baseline.  The project
deliberately reconstructs the 2024 academic release, so these tests pin the
approved versions and reject floating ranges or moving image tags.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

APPROVED = {
    "alembic": "1.13.2",
    "joblib": "1.4.2",
    "numpy": "1.26.4",
    "pandas": "2.2.2",
    "plotly": "5.24.0",
    "psycopg": "3.2.1",
    "pydantic": "2.8.2",
    "PyYAML": "6.0.2",
    "scapy": "2.5.0",
    "scikit-learn": "1.5.1",
    "SQLAlchemy": "2.0.32",
    "streamlit": "1.38.0",
}

FORBIDDEN_TAGS = re.compile(r"(?i)(?<![\w.-])(latest|nightly|edge|master|main)(?![\w.-])")


def _requirement_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith(("#", "-", "    "))
    ]


@pytest.mark.parametrize(("name", "version"), APPROVED.items())
def test_requirements_in_pins_approved_version(name: str, version: str) -> None:
    lines = _requirement_lines(ROOT / "requirements.in")
    expected = f"{name}=={version}"
    normalised = [re.sub(r"\[[^\]]*\]", "", line.split(";")[0]) for line in lines]
    assert any(line == expected for line in normalised), expected


def test_pyproject_dependencies_match_requirements() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for name, version in APPROVED.items():
        expected = f"{name}=={version}"
        assert expected in pyproject or f"{name}[binary]=={version}" in pyproject


def test_python_version_is_pinned_to_2024_release() -> None:
    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.12.5"
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.12.5,<3.13"' in pyproject


def test_lock_files_are_frozen_and_hash_checked() -> None:
    for name in (
        "requirements.lock",
        "requirements-dev.lock",
        "requirements-simulator.lock",
        "requirements-ml.lock",
        "deployments/cowrie/requirements.lock",
    ):
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        assert "--hash=sha256:" in text, name
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("--hash"):
                continue
            if "==" not in stripped:
                continue
            assert ">=" not in stripped and "~=" not in stripped and "!=" not in stripped, (
                name,
                stripped,
            )


def test_no_floating_or_moving_image_tags() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    dockerfiles = [
        ROOT / "Dockerfile",
        ROOT / "deployments" / "cowrie" / "Dockerfile",
        ROOT / "deployments" / "dionaea" / "Dockerfile",
    ]
    for path in dockerfiles:
        text = path.read_text(encoding="utf-8")
        assert FORBIDDEN_TAGS.search(text) is None, path
        for line in text.splitlines():
            if line.startswith("FROM "):
                assert "@sha256:" in line, (path, line)
    assert "image: postgres:16.4-bookworm@sha256:" in compose
    assert "FROM dinotools/dionaea:0.11.0@sha256:" in (
        ROOT / "deployments" / "dionaea" / "Dockerfile"
    ).read_text(encoding="utf-8")


def test_cowrie_is_pinned_to_verified_upstream_tarball() -> None:
    text = (ROOT / "deployments" / "cowrie" / "Dockerfile").read_text(encoding="utf-8")
    assert "v2.5.0.tar.gz" in text
    assert "9db15102675729783a4d65617fb4355e366a7fdcd8f5705f6d41541eb1f5919b" in text


def test_base_image_digests_are_exact() -> None:
    app = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    cowrie = (ROOT / "deployments" / "cowrie" / "Dockerfile").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert (
        "python:3.12.5-slim-bookworm@sha256:c24c34b502635f1f7c4e99dc09a2cbd85d480b7dcfd077198c6b5af138906390"
        in app
    )
    assert (
        "python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317"
        in cowrie
    )
    assert (
        "postgres:16.4-bookworm@sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412"
        in compose
    )
