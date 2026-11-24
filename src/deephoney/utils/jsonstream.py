"""Tolerant JSON/JSONL streaming.

Honeypot logs may be JSON Lines, a pretty-printed JSON object, or a JSON
array.  A malformed record must not stop the rest of the file from being
processed.  This module returns record candidates (including failures)
rather than raising.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_MAX_RECORD_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class RecordCandidate:
    """One candidate source record plus its origin."""

    record: dict[str, Any] | str | None
    line_number: int
    raw_text: str
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.record is not None


def iter_record_candidates(
    path: str | Path,
    *,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
) -> Iterator[RecordCandidate]:
    """Yield candidate records from a log file.

    JSON Lines is parsed line by line.  If a line starts a pretty-printed
    JSON value, subsequent lines are buffered until the value parses or the
    byte limit is reached.  A JSON array is flattened into its elements.
    """

    file_path = Path(path)
    buffer: list[str] = []
    buffer_bytes = 0
    buffer_start_line = 0

    def _try_json(text: str) -> tuple[bool, Any, str | None]:
        try:
            return True, json.loads(text), None
        except (json.JSONDecodeError, RecursionError) as exc:
            return (
                False,
                None,
                f"invalid JSON: {exc.msg}" if isinstance(exc, json.JSONDecodeError) else str(exc),
            )

    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            line_bytes = len(line.encode("utf-8", errors="replace"))
            if buffer_bytes + line_bytes > max_record_bytes:
                yield RecordCandidate(
                    record=None,
                    line_number=buffer_start_line or line_number,
                    raw_text="".join(buffer)[:max_record_bytes],
                    error=f"record exceeds {max_record_bytes} bytes",
                )
                buffer = []
                buffer_bytes = 0
                continue

            stripped = line.strip()
            if not buffer:
                if not stripped:
                    continue
                if stripped[0] not in "{[":
                    yield RecordCandidate(
                        record=line.rstrip("\n"),
                        line_number=line_number,
                        raw_text=line.rstrip("\n"),
                    )
                    continue
                buffer_start_line = line_number

            buffer.append(line)
            buffer_bytes += line_bytes
            candidate_text = "".join(buffer).strip()
            parsed_ok, parsed, error = _try_json(candidate_text)
            if parsed_ok:
                if isinstance(parsed, list):
                    for item in parsed:
                        if isinstance(item, dict):
                            yield RecordCandidate(
                                record=item,
                                line_number=buffer_start_line,
                                raw_text=json.dumps(item, ensure_ascii=False),
                            )
                        else:
                            yield RecordCandidate(
                                record=None,
                                line_number=buffer_start_line,
                                raw_text=str(item)[:max_record_bytes],
                                error="JSON array item is not an object",
                            )
                elif isinstance(parsed, dict):
                    yield RecordCandidate(
                        record=parsed,
                        line_number=buffer_start_line,
                        raw_text=candidate_text,
                    )
                else:
                    yield RecordCandidate(
                        record=None,
                        line_number=buffer_start_line,
                        raw_text=candidate_text[:max_record_bytes],
                        error=f"unsupported JSON type: {type(parsed).__name__}",
                    )
                buffer = []
                buffer_bytes = 0
                continue

            if len(buffer) > 1:
                standalone_ok, standalone, standalone_error = _try_json(stripped)
                if standalone_ok and isinstance(standalone, dict | list):
                    prefix = "".join(buffer[:-1]).strip()
                    yield RecordCandidate(
                        record=None,
                        line_number=buffer_start_line,
                        raw_text=prefix[:max_record_bytes],
                        error=error or "invalid JSON",
                    )
                    buffer = []
                    buffer_bytes = 0
                    if isinstance(standalone, dict):
                        yield RecordCandidate(
                            record=standalone,
                            line_number=line_number,
                            raw_text=stripped,
                        )
                    else:
                        for item in standalone:
                            if isinstance(item, dict):
                                yield RecordCandidate(
                                    record=item,
                                    line_number=line_number,
                                    raw_text=json.dumps(item, ensure_ascii=False),
                                )
                            else:
                                yield RecordCandidate(
                                    record=None,
                                    line_number=line_number,
                                    raw_text=str(item)[:max_record_bytes],
                                    error="JSON array item is not an object",
                                )
                    continue

            if (
                len(buffer) == 1
                and line.endswith("\n")
                and candidate_text.rstrip().endswith(("}", "]"))
            ):
                yield RecordCandidate(
                    record=None,
                    line_number=buffer_start_line,
                    raw_text=candidate_text[:max_record_bytes],
                    error=error or "invalid JSON",
                )
                buffer = []
                buffer_bytes = 0

    if buffer:
        text = "".join(buffer).strip()
        parsed_ok, parsed, error = _try_json(text)
        if parsed_ok:
            if isinstance(parsed, dict):
                yield RecordCandidate(record=parsed, line_number=buffer_start_line, raw_text=text)
            elif isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        yield RecordCandidate(
                            record=item,
                            line_number=buffer_start_line,
                            raw_text=json.dumps(item, ensure_ascii=False),
                        )
                    else:
                        yield RecordCandidate(
                            record=None,
                            line_number=buffer_start_line,
                            raw_text=str(item)[:max_record_bytes],
                            error="JSON array item is not an object",
                        )
            else:
                yield RecordCandidate(
                    record=None,
                    line_number=buffer_start_line,
                    raw_text=text[:max_record_bytes],
                    error=f"unsupported JSON type: {type(parsed).__name__}",
                )
        else:
            yield RecordCandidate(
                record=None,
                line_number=buffer_start_line,
                raw_text=text[:max_record_bytes],
                error=error or "incomplete JSON record at end of file",
            )


def iter_json_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield only successfully parsed JSON objects (convenience helper)."""

    for candidate in iter_record_candidates(path):
        if candidate.ok and isinstance(candidate.record, dict):
            yield candidate.record


__all__ = [
    "DEFAULT_MAX_RECORD_BYTES",
    "RecordCandidate",
    "iter_json_records",
    "iter_record_candidates",
]
