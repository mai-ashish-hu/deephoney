"""Cowrie log discovery helper."""

from __future__ import annotations

from collections.abc import Iterator
from glob import glob
from pathlib import Path

from deephoney.collectors.follower import FileTailer
from deephoney.schemas.events import SourceEngine


class CowrieCollector:
    engine = SourceEngine.COWRIE

    def __init__(self, log_glob: str) -> None:
        self.log_glob = log_glob

    def files(self) -> list[Path]:
        return sorted({Path(path) for path in glob(self.log_glob) if Path(path).is_file()})

    def tailers(self) -> Iterator[FileTailer]:
        for path in self.files():
            yield FileTailer(path)


__all__ = ["CowrieCollector"]
