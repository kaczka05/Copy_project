"""Shared fixtures. Tests use ONLY the genuine captures in tests/data/pcap
(integrity-checked here) and mutated temporary copies of them for
rejection tests. No traffic is generated."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import dpkt
import pytest

MODULE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE_ROOT))

from netguard_ingest.config import IngestionConfig  # noqa: E402

PCAP_DIR = Path(__file__).resolve().parent / "data" / "pcap"
_ROW = re.compile(r"^\| (\S+) \| \S+ \| ([0-9a-f]{64}) \|")
CATALOGUE = {m.group(1): m.group(2) for line in (PCAP_DIR / "SOURCES.md").read_text().splitlines()
             if (m := _ROW.match(line))}
CLASSIC = sorted(n for n in CATALOGUE if not n.endswith(".pcapng"))
PCAPNG = sorted(n for n in CATALOGUE if n.endswith(".pcapng"))
ALL = sorted(CATALOGUE)


def genuine(name: str) -> Path:
    """Path of a catalogued genuine capture; skip (not fake) when absent."""
    path = PCAP_DIR / name
    if not path.is_file():
        pytest.skip(f"genuine capture {name} not available (run scripts/fetch_test_pcaps.sh)")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == CATALOGUE[name], f"{name} does not match its catalogued SHA-256"
    return path


@pytest.fixture
def config(tmp_path) -> IngestionConfig:
    return IngestionConfig(output_root=tmp_path / "out")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def independent_packets(path: Path):
    """Packets via dpkt's own high-level readers (independent reference)."""
    with open(path, "rb") as handle:
        reader = dpkt.pcapng.Reader(handle) if path.suffix == ".pcapng" else dpkt.pcap.Reader(handle)
        return list(reader)


def classic_records(path: Path) -> list[tuple[int, int, bytes]]:
    """(record header offset, caplen, data) for every record of a classic pcap."""
    raw = path.read_bytes()
    out, offset = [], 24
    while offset + 16 <= len(raw):
        hdr = dpkt.pcap.LEPktHdr(raw[offset:offset + 16])
        out.append((offset, hdr.caplen, raw[offset + 16: offset + 16 + hdr.caplen]))
        offset += 16 + hdr.caplen
    return out
