"""Cross-field validation of a normalised flow.

Applied identically to flows extracted from PCAPs and to flows imported from
prepared datasets, so both sources obey the same flow semantics.
"""
from __future__ import annotations

import ipaddress
import math

from .errors import ErrorCode, ValidationIssue
from .model import PORT_PROTOCOLS, SCENARIO_LABELS, NormalizedFlow, Protocol

# Byte convention: bytes count the IP layer (network header + transport header +
# payload). Every packet therefore contributes at least the minimal IP header.
MIN_IP_HEADER_BYTES = {4: 20, 6: 40}


def validate_flow(flow: NormalizedFlow) -> None:
    """Raise :class:`ValidationIssue` if ``flow`` violates a model rule."""
    try:
        src = ipaddress.ip_address(flow.src_ip)
        dst = ipaddress.ip_address(flow.dst_ip)
    except ValueError as exc:
        raise ValidationIssue(ErrorCode.INVALID_IP_ADDRESS, str(exc), "src_ip/dst_ip") from None
    if src.version != dst.version:
        raise ValidationIssue(ErrorCode.INVALID_IP_ADDRESS,
                              f"src_ip is IPv{src.version} but dst_ip is IPv{dst.version}", "dst_ip", flow.dst_ip)

    for name in ("src_port", "dst_port"):
        port = getattr(flow, name)
        if port is None:
            continue
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValidationIssue(ErrorCode.INVALID_PORT, f"{name} {port!r} outside 0..65535", name, port)
        if flow.protocol not in PORT_PROTOCOLS:
            raise ValidationIssue(ErrorCode.INVALID_PORT,
                                  f"{name} must be null for protocol {flow.protocol.value} (ports not applicable)",
                                  name, port)

    for name in ("packets", "bytes"):
        value = getattr(flow, name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValidationIssue(ErrorCode.INVALID_COUNTER, f"{name} must be a non-negative integer", name, value)
    if flow.packets < 1:
        raise ValidationIssue(ErrorCode.INCONSISTENT_COUNTERS,
                              "a flow must contain at least one observed packet", "packets", flow.packets)
    min_bytes = flow.packets * MIN_IP_HEADER_BYTES[src.version]
    if flow.bytes < min_bytes:
        raise ValidationIssue(
            ErrorCode.INCONSISTENT_COUNTERS,
            f"bytes={flow.bytes} is below packets x minimal IPv{src.version} header "
            f"({min_bytes}); inconsistent with the NetGuard byte-counting convention", "bytes", flow.bytes)

    if not isinstance(flow.duration_ms, (int, float)) or isinstance(flow.duration_ms, bool) \
            or not math.isfinite(flow.duration_ms) or flow.duration_ms < 0:
        raise ValidationIssue(ErrorCode.INVALID_DURATION, "duration_ms must be finite and non-negative",
                              "duration_ms", flow.duration_ms)
    if flow.packets == 1 and flow.duration_ms != 0:
        raise ValidationIssue(ErrorCode.INVALID_DURATION,
                              "a single-packet flow must have duration_ms = 0", "duration_ms", flow.duration_ms)

    if flow.tcp_flags is not None:
        if flow.protocol is not Protocol.TCP:
            raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS,
                                  f"tcp_flags must be null for protocol {flow.protocol.value}", "tcp_flags",
                                  flow.tcp_flags)
        if isinstance(flow.tcp_flags, bool) or not isinstance(flow.tcp_flags, int) or not 0 <= flow.tcp_flags <= 255:
            raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS, "tcp_flags must be 0..255", "tcp_flags",
                                  flow.tcp_flags)

    if flow.scenario_label is not None and flow.scenario_label not in SCENARIO_LABELS:
        raise ValidationIssue(ErrorCode.INVALID_SCENARIO_LABEL, "unknown scenario label", "scenario_label",
                              flow.scenario_label)
    if flow.start_time.tzinfo is None:
        raise ValidationIssue(ErrorCode.INVALID_TIMESTAMP, "start_time must be timezone-aware UTC", "start_time")
