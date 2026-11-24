"""Explainable command categorisation.

The patterns are intentionally documented heuristics, not a claim that a
command is malicious.  A command such as ``ls`` is common in legitimate
administration and in reconnaissance; the dashboard presents the category as
an observation, not as proof of intent.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

COMMAND_CATEGORIES: dict[str, tuple[str, ...]] = {
    "recon": (
        r"\buname\b",
        r"\bwhoami\b",
        r"\bid\b",
        r"\bhostname\b",
        r"\bpwd\b",
        r"\bls\b",
        r"\bcat\s+/etc/(?:passwd|shadow|hosts|issue)\b",
        r"\bps\b",
        r"\btop\b",
        r"\bnetstat\b",
        r"\bss\b",
        r"\bip\s+addr\b",
        r"\bifconfig\b",
        r"\broute\b",
        r"\bmount\b",
        r"\bdf\b",
        r"\benv\b",
        r"\blscpu\b",
        r"\bfree\b",
    ),
    "file_transfer": (
        r"\bwget\b",
        r"\bcurl\b",
        r"\btftp\b",
        r"\bftp\b",
        r"\bscp\b",
        r"\brsync\b",
        r"\bnc\b",
        r"\bncat\b",
        r"\bsocat\b",
        r"\bbusybox\s+wget\b",
    ),
    "persistence": (
        r"\bcrontab\b",
        r"\bsystemctl\b",
        r"\bservice\b",
        r"\brc\.local\b",
        r"authorized_keys",
        r"\.bashrc",
        r"\bssh-keygen\b",
        r"\buseradd\b",
        r"\badduser\b",
        r"\bchpasswd\b",
        r"\bupdate-rc\.d\b",
        r"/etc/init\.d/",
        r"\bchkconfig\b",
        r"\bschtasks\b",
    ),
    "destructive": (
        r"\brm\s+-rf\b",
        r"\bmkfs(?:\.\w+)?\b",
        r"\bdd\s+if=",
        r"\bshutdown\b",
        r"\breboot\b",
        r"\bhalt\b",
        r"\bkillall\b",
        r"\bpkill\b",
        r"\bwipefs\b",
        r":\(\)\s*\{",
    ),
    "crypto": (
        r"\bxmrig\b",
        r"\bminerd\b",
        r"\bcpuminer\b",
        r"stratum\+tcp",
        r"\bmonero\b",
        r"cryptonight",
        r"--donate-level",
    ),
    "lateral": (
        r"\bnmap\b",
        r"\bmasscan\b",
        r"\bsmbclient\b",
        r"\bcrackmapexec\b",
        r"\bpsexec\b",
        r"\bwmiexec\b",
        r"\bhydra\b",
        r"\bmedusa\b",
        r"\bssh\b",
        r"\bscp\b",
        r"\btelnet\b",
        r"\bnc\b",
    ),
    "privilege": (
        r"\bsudo\b",
        r"\bsu\b",
        r"\bchmod\b",
        r"\bchown\b",
        r"\bsetcap\b",
        r"\bmount\b",
    ),
    "shell_utility": (
        r"\bsh\b",
        r"\bbash\b",
        r"\bdash\b",
        r"\bzsh\b",
        r"\bpython[0-9.]*\b",
        r"\bperl\b",
        r"\bruby\b",
        r"\bphp\b",
        r"\bbusybox\b",
    ),
}

_COMPILED: dict[str, tuple[re.Pattern[str], ...]] = {
    category: tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)
    for category, patterns in COMMAND_CATEGORIES.items()
}

HIGH_RISK_CATEGORIES = frozenset({"persistence", "destructive", "crypto", "lateral", "privilege"})


def classify_command(command: str | None) -> frozenset[str]:
    """Return all documented categories matching one command string."""

    if not command:
        return frozenset()
    text = command.strip()
    if not text:
        return frozenset()
    return frozenset(
        category
        for category, patterns in _COMPILED.items()
        if any(pattern.search(text) for pattern in patterns)
    )


def classify_commands(commands: Iterable[str | None]) -> dict[str, int]:
    """Count category hits across a command sequence.

    A command may contribute to more than one category (for example
    ``busybox wget``); the counts are therefore category incidences, not
    mutually exclusive command totals.
    """

    counts = dict.fromkeys(COMMAND_CATEGORIES, 0)
    for command in commands:
        for category in classify_command(command):
            counts[category] += 1
    return counts


__all__ = [
    "COMMAND_CATEGORIES",
    "HIGH_RISK_CATEGORIES",
    "classify_command",
    "classify_commands",
]
