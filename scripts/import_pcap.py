#!/usr/bin/env python3
"""Import a PCAP as metadata-only flows (no payloads are retained)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _bootstrap import ensure_schema, repository_for, settings_for
from deephoney.pcap.importer import PcapImportError, import_pcap_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help=".pcap or .pcapng file(s)")
    parser.add_argument("--sample", action="store_true", help="Import the bundled sanitized PCAP")
    parser.add_argument("--init-db", action="store_true")
    parser.add_argument("--config", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    settings = settings_for(args.config)
    if args.init_db:
        ensure_schema(settings)
    repository = repository_for(settings)

    targets = [Path(path).expanduser().resolve() for path in args.paths]
    if args.sample:
        targets.append(settings.sample_dir / "pcap" / "sample-ssh-scan.pcap")
    if not targets:
        print("error: pass a capture path or --sample", file=sys.stderr)
        return 2

    results = []
    exit_code = 0
    for path in targets:
        try:
            result = import_pcap_file(repository, path, settings)
        except PcapImportError as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        results.append(result)
        if not args.json:
            print(
                f"{result['filename']}: imported={result['imported']} "
                f"packets={result['packet_count']} flows={result['flow_count']} "
                f"truncated={result['truncated']}"
            )
    if args.json:
        print(json.dumps(results, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
