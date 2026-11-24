#!/usr/bin/env python3
"""Generate the sanitized sample PCAP used by the demonstration.

Only packet headers and RFC 5737 documentation addresses are used. There are
no payloads, exploits, or real captures. The resulting file is imported with
DeepHoney's metadata-only PCAP path.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from _bootstrap import ROOT

SCANNER = "203.0.113.90"
TARGET = "192.0.2.10"
BASE_TIME = 1_723_716_000.0


def generate_pcap(path: str | Path, *, force: bool = False) -> Path:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not force:
        raise FileExistsError(f"{target} already exists; pass --force to overwrite")
    try:
        from scapy.all import IP, TCP, UDP, wrpcap
    except ImportError as exc:
        raise RuntimeError("Scapy is required to generate the sample PCAP") from exc

    packets = []
    for offset, port in enumerate((22, 23, 80, 445, 21, 8080)):
        packets.append(
            IP(src=SCANNER, dst=TARGET) / TCP(sport=40000 + offset, dport=port, flags="S")
        )
        packets.append(
            IP(src=TARGET, dst=SCANNER) / TCP(sport=port, dport=40000 + offset, flags="RA")
        )
    for offset, port in enumerate((53, 123)):
        packets.append(IP(src=SCANNER, dst=TARGET) / UDP(sport=40020 + offset, dport=port))
    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.1
    wrpcap(str(target), packets)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=str(ROOT / "data/samples/pcap/sample-ssh-scan.pcap"),
        help="Destination .pcap path",
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        path = generate_pcap(args.out, force=args.force)
    except (FileExistsError, RuntimeError) as exc:
        print(f"error: {exc}")
        return 1
    print(f"Wrote sanitized PCAP: {path}")
    if path.suffix == ".pcap":
        fixture = ROOT / "tests/fixtures/sample-ssh-scan.pcap"
        if not fixture.exists() or args.force:
            fixture.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, fixture)
            print(f"Copied test fixture: {fixture}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
