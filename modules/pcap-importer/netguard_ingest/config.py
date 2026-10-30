"""Centralised ingestion configuration.

Precedence: explicit argument (CLI) > environment variable > default.
All defaults are documented in docs/DESIGN.md (section "Configuration").
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_IDLE_TIMEOUT_S = 60.0
DEFAULT_ACTIVE_TIMEOUT_S = 1800.0
DEFAULT_MAX_ACTIVE_FLOWS = 1_000_000
DEFAULT_SWEEP_INTERVAL_S = 1.0
DEFAULT_MAX_REJECT_DETAILS = 100_000
DEFAULT_OUTPUT_ROOT = "ingestion-output"

ENV_PREFIX = "NETGUARD_INGEST_"


def _env(name: str) -> str | None:
    value = os.environ.get(ENV_PREFIX + name)
    return value if value not in (None, "") else None


def _env_float(name: str, default: float) -> float:
    value = _env(name)
    return float(value) if value is not None else default


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    return int(value) if value is not None else default


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class IngestionConfig:
    """Settings shared by the PCAP and the flow-dataset pipelines."""

    output_root: Path = field(default_factory=lambda: Path(_env("OUTPUT_DIR") or DEFAULT_OUTPUT_ROOT))
    # Flow lifecycle (PCAP only)
    idle_timeout_s: float = field(default_factory=lambda: _env_float("IDLE_TIMEOUT_S", DEFAULT_IDLE_TIMEOUT_S))
    active_timeout_s: float = field(default_factory=lambda: _env_float("ACTIVE_TIMEOUT_S", DEFAULT_ACTIVE_TIMEOUT_S))
    max_active_flows: int = field(default_factory=lambda: _env_int("MAX_ACTIVE_FLOWS", DEFAULT_MAX_ACTIVE_FLOWS))
    sweep_interval_s: float = DEFAULT_SWEEP_INTERVAL_S
    emit_other_protocols: bool = field(default_factory=lambda: _env_bool("EMIT_OTHER_PROTOCOLS", False))
    # Provenance
    dataset_id: str | None = None
    scenario_label: str | None = None
    # Flow datasets
    input_format: str | None = None          # csv | jsonl | None (by extension)
    mapping_profile: str | None = None       # built-in name or path to JSON profile
    assume_timezone: str | None = None       # explicit IANA zone for naive timestamps
    # Output / reporting
    validate_contract: bool = field(default_factory=lambda: _env_bool("VALIDATE_CONTRACT", True))
    contracts_dir: Path | None = field(default_factory=lambda: Path(_env("CONTRACTS_DIR")) if _env("CONTRACTS_DIR") else None)
    max_reject_details: int = field(default_factory=lambda: _env_int("MAX_REJECT_DETAILS", DEFAULT_MAX_REJECT_DETAILS))

    def validate(self) -> None:
        """Raise ``ValueError`` for impossible settings."""
        if not self.idle_timeout_s > 0:
            raise ValueError("idle_timeout_s must be > 0")
        if not self.active_timeout_s > 0:
            raise ValueError("active_timeout_s must be > 0")
        if self.max_active_flows < 1:
            raise ValueError("max_active_flows must be >= 1")
        if not self.sweep_interval_s > 0:
            raise ValueError("sweep_interval_s must be > 0")
        if self.max_reject_details < 0:
            raise ValueError("max_reject_details must be >= 0")
        if self.input_format not in (None, "csv", "jsonl"):
            raise ValueError("input_format must be 'csv' or 'jsonl'")

    def as_report_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["output_root"] = str(self.output_root)
        data["contracts_dir"] = str(self.contracts_dir) if self.contracts_dir else None
        return data
