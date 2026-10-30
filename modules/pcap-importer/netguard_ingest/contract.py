"""FlowEvent v1 contract check against the repository's shared JSON Schema
(``contracts/kafka/flow-event.v1.schema.json``), the designated output
interface of the ingestion tier (topic ``flows.normalized``).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA_RELATIVE_PATH = Path("contracts") / "kafka" / "flow-event.v1.schema.json"
_log = logging.getLogger(__name__)


class ContractUnavailable(RuntimeError):
    """The shared schema file could not be located or loaded."""


def locate_schema(contracts_dir: Path | None = None) -> Path:
    """Find ``flow-event.v1.schema.json``.

    ``contracts_dir`` may point at the ``contracts/kafka`` directory. Otherwise
    the parents of this package are searched for the monorepo ``contracts/``.
    """
    if contracts_dir is not None:
        candidate = Path(contracts_dir) / "flow-event.v1.schema.json"
        if candidate.is_file():
            return candidate
        raise ContractUnavailable(f"FlowEvent schema not found in {contracts_dir}")
    for parent in Path(__file__).resolve().parents:
        candidate = parent / SCHEMA_RELATIVE_PATH
        if candidate.is_file():
            return candidate
    raise ContractUnavailable(
        "contracts/kafka/flow-event.v1.schema.json not found; set NETGUARD_INGEST_CONTRACTS_DIR")


class FlowEventContract:
    """Validates FlowEvent dictionaries with JSON Schema Draft 2020-12 including
    ``format`` assertions (date-time, ipv4, ipv6)."""

    def __init__(self, contracts_dir: Path | None = None) -> None:
        self.schema_path = locate_schema(contracts_dir)
        try:
            schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
        except (OSError, ValueError) as exc:
            raise ContractUnavailable(f"cannot load {self.schema_path}: {exc}") from exc
        checker = FormatChecker()
        missing = {"date-time", "ipv4", "ipv6"} - set(checker.checkers)
        if missing:
            raise ContractUnavailable(
                f"jsonschema format checkers unavailable for {sorted(missing)}; install 'jsonschema[format]'")
        self._validator = Draft202012Validator(schema, format_checker=checker)

    def errors(self, event: dict[str, Any]) -> list[str]:
        """Return human-readable violations (empty when valid)."""
        messages = []
        for error in self._validator.iter_errors(event):
            path = ".".join(str(p) for p in error.absolute_path) or "$"
            messages.append(f"{path}: {error.message}")
        # Semantic rule from examples/kafka/common.py that JSON Schema cannot express.
        if event.get("protocol") != "TCP" and event.get("tcp_flags") is not None:
            messages.append("tcp_flags: must be null/omitted for non-TCP flows")
        return messages
