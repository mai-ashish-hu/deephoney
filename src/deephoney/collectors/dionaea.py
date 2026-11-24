"""Dionaea log discovery helper (JSON preferred, plaintext fallback)."""

from __future__ import annotations

from collections.abc import Iterator
from glob import glob
from pathlib import Path

from deephoney.collectors.follower import FileTailer
from deephoney.schemas.events import SourceEngine


class DionaeaCollector:
    engine = SourceEngine.DIONAEA

    def __init__(self, *globs: str) -> None:
        self.globs = tuple(glob_pattern for glob_pattern in globs if glob_pattern)

    def files(self) -> list[Path]:
        paths: set[Path] = set()
        for pattern in self.globs:
            paths.update(Path(path) for path in glob(pattern) if Path(path).is_file())
        return sorted(paths)

    def tailers(self) -> Iterator[FileTailer]:
        for path in self.files():
            yield FileTailer(path)


__all__ = ["DionaeaCollector"]
