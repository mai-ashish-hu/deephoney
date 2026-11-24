"""Allow ``python -m deephoney``."""

from __future__ import annotations

from deephoney.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
