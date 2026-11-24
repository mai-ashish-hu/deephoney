"""Incremental, partial-line-safe log tailing."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class FileTailer:
    """Read only complete lines from a file that may still be written."""

    path: Path
    offset: int = 0
    buffer: bytes = field(default=b"", repr=False)
    reset_count: int = 0

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    @property
    def committed_offset(self) -> int:
        """Byte offset up to the last complete line.

        ``offset`` may include an unterminated line held in ``buffer``.  Only
        the committed offset is safe to persist across process restarts.
        """

        return max(0, self.offset - len(self.buffer))

    def read_complete_lines(self, max_bytes: int = 8 * 1024 * 1024) -> list[str]:
        if not self.path.is_file():
            return []
        stat = self.path.stat()
        if stat.st_size < self.offset:
            self.offset = 0
            self.buffer = b""
            self.reset_count += 1
        try:
            with self.path.open("rb") as handle:
                handle.seek(self.offset)
                chunk = handle.read(max(1, max_bytes))
        except OSError:
            return []
        self.offset += len(chunk)
        data = self.buffer + chunk
        if b"\n" not in data:
            self.buffer = data
            return []
        *parts, self.buffer = data.split(b"\n")
        return [
            line.decode("utf-8", errors="replace").rstrip("\r") for line in parts if line.strip()
        ]

    def drain(self) -> list[str]:
        """Return an unterminated final line (batch import at EOF only)."""

        data = self.buffer
        self.buffer = b""
        if not data.strip():
            return []
        return [data.decode("utf-8", errors="replace").rstrip("\r")]


__all__ = ["FileTailer"]
