"""Unidirectional packet-to-flow aggregation.

Flow key: (src_ip, src_port, dst_ip, dst_port, IP protocol number). Ports are
``None`` for protocols without ports, so e.g. all ICMP packets from A to B
share one key. Opposite directions are always different keys.

Lifecycle policy (configurable):
* a flow starts with the first packet observed for its key;
* IDLE_TIMEOUT  - a packet arriving more than ``idle_timeout`` after the
  flow's last packet closes the flow and starts a new one; idle flows are also
  expired periodically to bound memory;
* ACTIVE_TIMEOUT - a packet arriving more than ``active_timeout`` after the
  flow's first packet closes the flow and starts a new one (continuation);
* END_OF_CAPTURE - flows still open when the capture ends;
* FLOW_TABLE_LIMIT - the least recently updated flow is closed when the
  table exceeds ``max_active_flows``.
TCP FIN/RST do not terminate flows (documented decision).
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from ..model import Protocol
from .decoder import PacketMeta
from .reader import RawPacket

FlowKey = tuple[str, int | None, str, int | None, int]


class EndReason(str, Enum):
    IDLE_TIMEOUT = "IDLE_TIMEOUT"
    ACTIVE_TIMEOUT = "ACTIVE_TIMEOUT"
    END_OF_CAPTURE = "END_OF_CAPTURE"
    FLOW_TABLE_LIMIT = "FLOW_TABLE_LIMIT"


@dataclass(slots=True)
class FlowState:
    flow_id: str
    key: FlowKey
    ip_version: int
    protocol: Protocol
    first_ns: int
    last_ns: int
    packets: int
    bytes: int
    tcp_flags: int | None
    first_tcp_flags: int | None
    first_packet_index: int
    last_packet_index: int
    first_packet_offset: int
    snaplen_truncated_packets: int = 0
    out_of_order_packets: int = 0
    previous_flow_id: str | None = None   # set when continuing after ACTIVE_TIMEOUT
    end_reason: EndReason | None = None


FlowIdFactory = Callable[[FlowKey, RawPacket], str]


class FlowAggregator:
    """Streaming flow table. ``add`` / ``flush`` return the flows they close."""

    def __init__(self, *, idle_timeout_s: float, active_timeout_s: float, max_active_flows: int,
                 flow_id_factory: FlowIdFactory, sweep_interval_s: float = 1.0) -> None:
        self.idle_ns = int(round(idle_timeout_s * 1e9))
        self.active_ns = int(round(active_timeout_s * 1e9))
        self.max_active_flows = max_active_flows
        self.sweep_ns = int(round(sweep_interval_s * 1e9))
        self._flow_id = flow_id_factory
        self._table: OrderedDict[FlowKey, FlowState] = OrderedDict()
        self.clock_ns: int | None = None
        self._last_sweep_ns: int | None = None
        self.peak_active_flows = 0
        self.out_of_order_packets = 0
        self.closed_by_reason = {reason.value: 0 for reason in EndReason}

    @property
    def active_flows(self) -> int:
        return len(self._table)

    def add(self, meta: PacketMeta, packet: RawPacket) -> list[FlowState]:
        closed: list[FlowState] = []
        ts = packet.ts_ns
        out_of_order = self.clock_ns is not None and ts < self.clock_ns
        if out_of_order:
            self.out_of_order_packets += 1
        else:
            self.clock_ns = ts
        key: FlowKey = (meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port, meta.ip_proto)
        state = self._table.get(key)
        previous_id = None
        if state is not None:
            if ts - state.last_ns > self.idle_ns:
                closed.append(self._close(key, EndReason.IDLE_TIMEOUT))
                state = None
            elif ts - state.first_ns > self.active_ns:
                previous_id = state.flow_id
                closed.append(self._close(key, EndReason.ACTIVE_TIMEOUT))
                state = None
        if state is None:
            state = FlowState(
                flow_id=self._flow_id(key, packet), key=key, ip_version=meta.ip_version,
                protocol=meta.protocol, first_ns=ts, last_ns=ts, packets=1, bytes=meta.l3_bytes,
                tcp_flags=meta.tcp_flags if meta.protocol is Protocol.TCP else None,
                first_tcp_flags=meta.tcp_flags if meta.protocol is Protocol.TCP else None,
                first_packet_index=packet.index, last_packet_index=packet.index,
                first_packet_offset=packet.file_offset,
                snaplen_truncated_packets=1 if meta.snaplen_truncated else 0,
                previous_flow_id=previous_id,
            )
            self._table[key] = state
            if len(self._table) > self.max_active_flows:
                oldest = next(iter(self._table))
                closed.append(self._close(oldest, EndReason.FLOW_TABLE_LIMIT))
            self.peak_active_flows = max(self.peak_active_flows, len(self._table))
        else:
            state.packets += 1
            state.bytes += meta.l3_bytes
            state.first_ns = min(state.first_ns, ts)
            if ts >= state.last_ns:
                state.last_ns = ts
            else:
                state.out_of_order_packets += 1
            state.last_packet_index = packet.index
            if meta.tcp_flags is not None:
                state.tcp_flags = (state.tcp_flags or 0) | meta.tcp_flags
            if meta.snaplen_truncated:
                state.snaplen_truncated_packets += 1
            self._table.move_to_end(key)
        closed.extend(self._sweep())
        return closed

    def _sweep(self) -> list[FlowState]:
        """Expire idle flows from the least-recently-updated end (memory bound)."""
        if self.clock_ns is None:
            return []
        if self._last_sweep_ns is not None and self.clock_ns - self._last_sweep_ns < self.sweep_ns:
            return []
        self._last_sweep_ns = self.clock_ns
        closed = []
        while self._table:
            key, state = next(iter(self._table.items()))
            if self.clock_ns - state.last_ns > self.idle_ns:
                closed.append(self._close(key, EndReason.IDLE_TIMEOUT))
            else:
                break
        return closed

    def _close(self, key: FlowKey, reason: EndReason) -> FlowState:
        state = self._table.pop(key)
        state.end_reason = reason
        self.closed_by_reason[reason.value] += 1
        return state

    def flush(self) -> list[FlowState]:
        """Close every open flow at the capture boundary (in first-packet order)."""
        remaining = sorted(self._table.values(), key=lambda s: s.first_packet_index)
        self._table.clear()
        for state in remaining:
            state.end_reason = EndReason.END_OF_CAPTURE
            self.closed_by_reason[EndReason.END_OF_CAPTURE.value] += 1
        return remaining
