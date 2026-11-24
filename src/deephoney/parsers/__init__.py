"""Source-specific parsers."""

from __future__ import annotations

from deephoney.parsers.base import BaseParser, ParseFailure, ParseOutcome, ParseSuccess
from deephoney.parsers.cowrie.parser import CowrieParser
from deephoney.parsers.dionaea.parser import DionaeaParser
from deephoney.schemas.events import SourceEngine

PARSERS: dict[str, type[BaseParser]] = {
    SourceEngine.COWRIE.value: CowrieParser,
    SourceEngine.DIONAEA.value: DionaeaParser,
}


def get_parser(engine: str) -> BaseParser:
    try:
        parser_class = PARSERS[engine.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported honeypot engine: {engine!r}") from exc
    return parser_class()


__all__ = [
    "BaseParser",
    "CowrieParser",
    "DionaeaParser",
    "ParseFailure",
    "ParseOutcome",
    "ParseSuccess",
    "get_parser",
]
