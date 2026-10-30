"""Structured error codes, categories and exception types.

Every packet, record or file that cannot be converted into a normalised flow
is described by an :class:`ErrorCode`. Codes are stable identifiers that are
written to ``rejects.jsonl`` and counted in ``report.json``.
"""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from enum import Enum
from typing import Any


class ErrorCategory(str, Enum):
    FILE = "FILE"                              # whole input cannot be processed
    CAPTURE_STRUCTURE = "CAPTURE_STRUCTURE"    # pcap/pcapng framing problem
    MALFORMED = "MALFORMED"                    # packet/record bytes are invalid
    UNSUPPORTED = "UNSUPPORTED"                # valid but outside supported scope
    VALIDATION = "VALIDATION"                  # value/consistency rule violated
    CONTRACT = "CONTRACT"                      # output contract violated


class ErrorCode(str, Enum):
    # ---- file level -------------------------------------------------------
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_NOT_READABLE = "FILE_NOT_READABLE"
    FILE_EMPTY = "FILE_EMPTY"
    UNSUPPORTED_FILE_FORMAT = "UNSUPPORTED_FILE_FORMAT"
    CORRUPTED_CAPTURE_HEADER = "CORRUPTED_CAPTURE_HEADER"
    UNSUPPORTED_CAPTURE_VERSION = "UNSUPPORTED_CAPTURE_VERSION"
    UNSUPPORTED_LINK_TYPE = "UNSUPPORTED_LINK_TYPE"
    INVALID_DATASET_HEADER = "INVALID_DATASET_HEADER"
    INVALID_MAPPING_PROFILE = "INVALID_MAPPING_PROFILE"
    # ---- capture structure -------------------------------------------------
    TRUNCATED_CAPTURE = "TRUNCATED_CAPTURE"
    CORRUPTED_RECORD = "CORRUPTED_RECORD"
    MISSING_PACKET_TIMESTAMP = "MISSING_PACKET_TIMESTAMP"
    UNKNOWN_INTERFACE = "UNKNOWN_INTERFACE"
    # ---- packet level ------------------------------------------------------
    MALFORMED_LINK_HEADER = "MALFORMED_LINK_HEADER"
    NON_IP_PACKET = "NON_IP_PACKET"
    MALFORMED_NETWORK_HEADER = "MALFORMED_NETWORK_HEADER"
    TRUNCATED_NETWORK_HEADER = "TRUNCATED_NETWORK_HEADER"
    MALFORMED_TRANSPORT_HEADER = "MALFORMED_TRANSPORT_HEADER"
    TRUNCATED_TRANSPORT_HEADER = "TRUNCATED_TRANSPORT_HEADER"
    IP_FRAGMENT_NOT_REASSEMBLED = "IP_FRAGMENT_NOT_REASSEMBLED"
    UNSUPPORTED_IP_PROTOCOL = "UNSUPPORTED_IP_PROTOCOL"
    # ---- record / value level ----------------------------------------------
    MALFORMED_RECORD = "MALFORMED_RECORD"
    INVALID_ENCODING = "INVALID_ENCODING"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    INVALID_IP_ADDRESS = "INVALID_IP_ADDRESS"
    INVALID_PORT = "INVALID_PORT"
    INVALID_PROTOCOL = "INVALID_PROTOCOL"
    UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL"
    INVALID_COUNTER = "INVALID_COUNTER"
    INCONSISTENT_COUNTERS = "INCONSISTENT_COUNTERS"
    INVALID_DURATION = "INVALID_DURATION"
    INVALID_TCP_FLAGS = "INVALID_TCP_FLAGS"
    INVALID_SCENARIO_LABEL = "INVALID_SCENARIO_LABEL"
    INVALID_SOURCE_TYPE = "INVALID_SOURCE_TYPE"
    SYNTHETIC_RECORD_REJECTED = "SYNTHETIC_RECORD_REJECTED"
    DUPLICATE_RECORD = "DUPLICATE_RECORD"
    # ---- output ------------------------------------------------------------
    CONTRACT_VIOLATION = "CONTRACT_VIOLATION"


_CATEGORY = {
    ErrorCode.FILE_NOT_FOUND: ErrorCategory.FILE,
    ErrorCode.FILE_NOT_READABLE: ErrorCategory.FILE,
    ErrorCode.FILE_EMPTY: ErrorCategory.FILE,
    ErrorCode.UNSUPPORTED_FILE_FORMAT: ErrorCategory.FILE,
    ErrorCode.CORRUPTED_CAPTURE_HEADER: ErrorCategory.FILE,
    ErrorCode.UNSUPPORTED_CAPTURE_VERSION: ErrorCategory.FILE,
    ErrorCode.UNSUPPORTED_LINK_TYPE: ErrorCategory.UNSUPPORTED,
    ErrorCode.INVALID_DATASET_HEADER: ErrorCategory.FILE,
    ErrorCode.INVALID_MAPPING_PROFILE: ErrorCategory.FILE,
    ErrorCode.TRUNCATED_CAPTURE: ErrorCategory.CAPTURE_STRUCTURE,
    ErrorCode.CORRUPTED_RECORD: ErrorCategory.CAPTURE_STRUCTURE,
    ErrorCode.MISSING_PACKET_TIMESTAMP: ErrorCategory.CAPTURE_STRUCTURE,
    ErrorCode.UNKNOWN_INTERFACE: ErrorCategory.CAPTURE_STRUCTURE,
    ErrorCode.MALFORMED_LINK_HEADER: ErrorCategory.MALFORMED,
    ErrorCode.NON_IP_PACKET: ErrorCategory.UNSUPPORTED,
    ErrorCode.MALFORMED_NETWORK_HEADER: ErrorCategory.MALFORMED,
    ErrorCode.TRUNCATED_NETWORK_HEADER: ErrorCategory.MALFORMED,
    ErrorCode.MALFORMED_TRANSPORT_HEADER: ErrorCategory.MALFORMED,
    ErrorCode.TRUNCATED_TRANSPORT_HEADER: ErrorCategory.MALFORMED,
    ErrorCode.IP_FRAGMENT_NOT_REASSEMBLED: ErrorCategory.UNSUPPORTED,
    ErrorCode.UNSUPPORTED_IP_PROTOCOL: ErrorCategory.UNSUPPORTED,
    ErrorCode.MALFORMED_RECORD: ErrorCategory.MALFORMED,
    ErrorCode.INVALID_ENCODING: ErrorCategory.MALFORMED,
    ErrorCode.UNSUPPORTED_PROTOCOL: ErrorCategory.UNSUPPORTED,
    ErrorCode.CONTRACT_VIOLATION: ErrorCategory.CONTRACT,
}


def category_of(code: ErrorCode) -> ErrorCategory:
    """Return the category for ``code`` (validation errors by default)."""
    return _CATEGORY.get(code, ErrorCategory.VALIDATION)


class IngestionError(Exception):
    """Base class carrying a structured :class:`ErrorCode`."""

    def __init__(self, code: ErrorCode, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


class InputFileError(IngestionError):
    """The input file as a whole cannot be processed."""


class PacketRejected(IngestionError):
    """A single packet cannot be attributed to a flow."""


class ValidationIssue(IngestionError):
    """A value or record failed a normalisation/validation rule."""

    def __init__(self, code: ErrorCode, message: str, field: str | None = None,
                 value: Any = None) -> None:
        super().__init__(code, message, field=field)
        self.field = field
        self.value = value


@dataclass(slots=True)
class RejectRecord:
    """One rejected / quarantined item written to ``rejects.jsonl``."""

    code: ErrorCode
    message: str
    location: dict[str, Any]
    field: str | None = None
    value: Any = None
    raw: Any = None
    details: dict[str, Any] = dc_field(default_factory=dict)

    def to_dict(self, ingestion_id: str, source_file: str) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ingestion_id": ingestion_id,
            "source_file": source_file,
            "code": self.code.value,
            "category": category_of(self.code).value,
            "message": self.message,
            "location": self.location,
        }
        if self.field is not None:
            out["field"] = self.field
        if self.value is not None:
            out["value"] = _truncate_repr(self.value)
        if self.raw is not None:
            out["raw"] = self.raw
        if self.details:
            out["details"] = self.details
        return out


def _truncate_repr(value: Any, limit: int = 256) -> Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[:limit] + "...<truncated>"
