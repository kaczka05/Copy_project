"""Common NetGuard flow model (Test Data and Demonstration Environment, sec. 3)
and its FlowEvent v1 serialisation (contracts/kafka/flow-event.v1.schema.json).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

FLOW_EVENT_SCHEMA_VERSION = 1


class Protocol(str, Enum):
    """Normalised protocol identifiers (FlowEvent v1 ``protocol`` enum)."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ICMPV6 = "ICMPV6"
    OTHER = "OTHER"


# IANA protocol numbers of the supported transport/control protocols.
IP_PROTO_TO_PROTOCOL: dict[int, Protocol] = {
    6: Protocol.TCP,
    17: Protocol.UDP,
    1: Protocol.ICMP,
    58: Protocol.ICMPV6,
}
PORT_PROTOCOLS = frozenset({Protocol.TCP, Protocol.UDP})


class SourceType(str, Enum):
    """Origin of a record. SIMULATOR exists in the contract but is never
    produced by this subsystem."""

    PCAP = "PCAP"
    FLOW_DATASET = "FLOW_DATASET"


SCENARIO_LABELS = frozenset({
    "NORMAL", "PORT_SCAN", "DOS_LIKE", "BRUTE_FORCE_LIKE", "ABNORMAL_CONNECTION_PATTERN",
})


@dataclass(slots=True)
class NormalizedFlow:
    """One normalised unidirectional flow (the 13-field common model plus the
    ``dataset_id`` provenance field of FlowEvent v1)."""

    flow_id: str
    start_time: datetime          # timezone-aware UTC, microsecond precision
    duration_ms: float            # >= 0, microsecond precision (3 decimals)
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: Protocol
    packets: int
    bytes: int
    tcp_flags: int | None         # OR of observed TCP flags; None = unavailable
    source_type: SourceType
    scenario_label: str | None
    dataset_id: str | None = None

    def to_flow_event(self, *, event_id: str, trace_id: str, ingest_time: datetime) -> dict[str, Any]:
        """Serialise to a FlowEvent v1 JSON object (field order follows the contract)."""
        from .normalize import format_timestamp  # local import avoids a cycle

        return {
            "schema_version": FLOW_EVENT_SCHEMA_VERSION,
            "event_id": event_id,
            "trace_id": trace_id,
            "flow_id": self.flow_id,
            "ingest_time": format_timestamp(ingest_time),
            "start_time": format_timestamp(self.start_time),
            "duration_ms": self.duration_ms,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol.value,
            "packets": self.packets,
            "bytes": self.bytes,
            "tcp_flags": self.tcp_flags,
            "source_type": self.source_type.value,
            "dataset_id": self.dataset_id,
            "simulation_run_id": None,
            "scenario_label": self.scenario_label,
        }
