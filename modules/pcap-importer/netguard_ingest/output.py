"""JSON-lines output sink (the designated integration interface).

Layout per ingestion (written to a hidden temporary directory and atomically
renamed when complete, so consumers never see partial output)::

    <output_root>/<ingestion_id>/flows.jsonl       FlowEvent v1, one per line
    <output_root>/<ingestion_id>/provenance.jsonl  flow_id -> origin details
    <output_root>/<ingestion_id>/rejects.jsonl     quarantined packets/records
    <output_root>/<ingestion_id>/report.json       ingestion metadata & stats
    <output_root>/ingestions.jsonl                 catalogue of all ingestions
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

FLOWS_FILE = "flows.jsonl"
PROVENANCE_FILE = "provenance.jsonl"
REJECTS_FILE = "rejects.jsonl"
REPORT_FILE = "report.json"
CATALOGUE_FILE = "ingestions.jsonl"


def _dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


class IngestionOutput:
    def __init__(self, output_root: Path, ingestion_id: str, max_reject_details: int) -> None:
        self.output_root = Path(output_root)
        self.ingestion_id = ingestion_id
        self.final_dir = self.output_root / ingestion_id
        self.tmp_dir = self.output_root / f".{ingestion_id}.partial"
        self.max_reject_details = max_reject_details
        self.rejects_written = 0
        self.rejects_suppressed = 0
        self.flows_written = 0
        self.output_root.mkdir(parents=True, exist_ok=True)
        if self.final_dir.exists():
            raise FileExistsError(f"output directory already exists: {self.final_dir}")
        self.tmp_dir.mkdir()
        self._flows = open(self.tmp_dir / FLOWS_FILE, "w", encoding="utf-8", newline="\n")  # noqa: SIM115
        self._prov = open(self.tmp_dir / PROVENANCE_FILE, "w", encoding="utf-8", newline="\n")  # noqa: SIM115
        self._rejects = open(self.tmp_dir / REJECTS_FILE, "w", encoding="utf-8", newline="\n")  # noqa: SIM115

    def write_flow(self, event: dict[str, Any], provenance: dict[str, Any]) -> None:
        self._flows.write(_dumps(event) + "\n")
        self._prov.write(_dumps(provenance) + "\n")
        self.flows_written += 1

    def write_reject(self, reject: dict[str, Any]) -> None:
        if self.rejects_written >= self.max_reject_details:
            self.rejects_suppressed += 1
            return
        self._rejects.write(_dumps(reject) + "\n")
        self.rejects_written += 1

    def _close_files(self) -> None:
        for handle in (self._flows, self._prov, self._rejects):
            if not handle.closed:
                handle.close()

    def finalize(self, report: dict[str, Any]) -> Path:
        """Write the report, publish the directory atomically, update the catalogue."""
        self._close_files()
        with open(self.tmp_dir / REPORT_FILE, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
        os.replace(self.tmp_dir, self.final_dir)
        entry = {
            "ingestion_id": report["ingestion_id"],
            "status": report["status"],
            "source_type": report["source"]["source_type"],
            "original_filename": report["source"]["original_filename"],
            "sha256": report["source"].get("sha256"),
            "started_at": report["started_at"],
            "completed_at": report["completed_at"],
            "flows_normalized": report["flows"]["normalized"],
            "output_dir": str(self.final_dir),
        }
        with open(self.output_root / CATALOGUE_FILE, "a", encoding="utf-8") as handle:
            handle.write(_dumps(entry) + "\n")
        return self.final_dir

    def abort(self) -> None:
        self._close_files()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)


def read_catalogue(output_root: Path) -> list[dict[str, Any]]:
    path = Path(output_root) / CATALOGUE_FILE
    if not path.is_file():
        return []
    entries = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries
