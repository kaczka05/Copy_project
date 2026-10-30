"""Identifiers and content hashing used for provenance and repeatability.

* ``flow_id`` and ``event_id`` are deterministic (UUIDv5) functions of the
  input file's SHA-256 and the originating packet/record, so re-ingesting the
  same file with the same configuration yields identical identifiers.
* ``ingestion_id`` is unique per run (UUIDv4) and is used as ``trace_id``.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path

# Fixed namespace for NetGuard ingestion identifiers (never change).
NETGUARD_INGEST_NAMESPACE = uuid.UUID("6f1d2c3e-8a4b-5c6d-9e0f-1a2b3c4d5e6f")
_SAFE = re.compile(r"[^A-Za-z0-9._:-]+")


def file_sha256(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def new_ingestion_id() -> str:
    return "ing-" + uuid.uuid4().hex


def pcap_flow_id(sha256: str, first_packet_index: int, key: tuple) -> str:
    return "flow-" + str(uuid.uuid5(NETGUARD_INGEST_NAMESPACE, f"pcap|{sha256}|{first_packet_index}|{key!r}"))


def dataset_flow_id(sha256: str, record_number: int) -> str:
    return "flow-" + str(uuid.uuid5(NETGUARD_INGEST_NAMESPACE, f"dataset|{sha256}|{record_number}"))


def event_id_for(flow_id: str) -> str:
    return "evt-" + str(uuid.uuid5(NETGUARD_INGEST_NAMESPACE, f"event|{flow_id}"))


def default_dataset_id(path: Path, sha256: str) -> str:
    """``<file-stem>-<sha256[:12]>`` restricted to contract-safe characters."""
    stem = _SAFE.sub("_", path.stem).strip("_") or "input"
    return f"{stem[:100]}-{sha256[:12]}"
