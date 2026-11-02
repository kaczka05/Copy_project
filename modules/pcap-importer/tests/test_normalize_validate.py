"""Value-level normalisation rules and cross-field flow validation."""
from __future__ import annotations

import dataclasses
import ipaddress
from datetime import datetime, timezone

import pytest
from conftest import genuine

from netguard_ingest.capture.decoder import PacketDecoder
from netguard_ingest.errors import ErrorCode, ValidationIssue
from netguard_ingest.model import NormalizedFlow, Protocol, SourceType
from netguard_ingest.normalize import (
    format_timestamp, normalize_counter, normalize_duration_ms, normalize_ip, normalize_port, normalize_protocol,
    normalize_scenario_label, normalize_tcp_flags, ns_to_datetime, parse_timestamp,
)
from netguard_ingest.validation import validate_flow


def code_of(fn, *args, **kwargs):
    with pytest.raises(ValidationIssue) as info:
        fn(*args, **kwargs)
    return info.value.code


# ---------------------------------------------------------------- IP addresses
@pytest.mark.parametrize("raw,expected", [
    ("192.0.2.10", "192.0.2.10"), (" 10.0.0.1 ", "10.0.0.1"),
    ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"), ("fe80::0001", "fe80::1"), ("::FFFF:192.0.2.1", "::ffff:192.0.2.1"),
])
def test_ip_canonical_form(raw, expected):
    assert normalize_ip(raw, field="src_ip") == expected


def test_ipv4_mapped_form_independent_of_interpreter(monkeypatch):
    """Some CPython releases render IPv4-mapped IPv6 as ``::ffff:c000:201``.
    The canonical form must not depend on that."""
    original = ipaddress.IPv6Address.__str__

    def hex_rendering(self):
        if self.ipv4_mapped is not None:
            low = int(self) & 0xFFFFFFFF
            return f"::ffff:{low >> 16:x}:{low & 0xFFFF:x}"
        return original(self)

    monkeypatch.setattr(ipaddress.IPv6Address, "__str__", hex_rendering)
    assert ipaddress.ip_address("::ffff:192.0.2.1").compressed == "::ffff:c000:201"   # patch is effective
    assert normalize_ip("::FFFF:192.0.2.1", field="src_ip") == "::ffff:192.0.2.1"
    assert normalize_ip("::ffff:c000:201", field="src_ip") == "::ffff:192.0.2.1"
    raw = ipaddress.ip_address("::ffff:192.0.2.1").packed
    assert PacketDecoder()._addr(raw) == "::ffff:192.0.2.1"
    assert normalize_ip("2001:db8::1", field="src_ip") == "2001:db8::1"


@pytest.mark.parametrize("raw", ["256.1.1.1", "192.168.001.1", "1.2.3", "fe80::1%eth0", "gggg::1", "", 3232235777])
def test_invalid_ip_rejected(raw):
    assert code_of(normalize_ip, raw, field="src_ip") is ErrorCode.INVALID_IP_ADDRESS


def test_missing_ip_is_missing_not_invalid():
    assert code_of(normalize_ip, None, field="src_ip") is ErrorCode.MISSING_REQUIRED_FIELD


# ----------------------------------------------------------------------- ports
@pytest.mark.parametrize("raw,expected", [(0, 0), ("0", 0), (65535, 65535), ("443", 443), (None, None)])
def test_valid_ports_and_missing_versus_zero(raw, expected):
    assert normalize_port(raw, field="dst_port") == expected


@pytest.mark.parametrize("raw", [-1, 65536, "70000", "80.0", 80.0, True, "http", "0x50"])
def test_invalid_ports(raw):
    assert code_of(normalize_port, raw, field="dst_port") is ErrorCode.INVALID_PORT


# -------------------------------------------------------------------- protocol
@pytest.mark.parametrize("raw,expected", [
    ("tcp", Protocol.TCP), ("TCP", Protocol.TCP), (6, Protocol.TCP), ("17", Protocol.UDP), ("udp", Protocol.UDP),
    (1, Protocol.ICMP), ("icmp", Protocol.ICMP), (58, Protocol.ICMPV6), ("ICMPv6", Protocol.ICMPV6),
])
def test_protocol_normalisation(raw, expected):
    assert normalize_protocol(raw)[0] is expected


def test_unsupported_protocol_is_reported_or_other_when_enabled():
    assert code_of(normalize_protocol, 47) is ErrorCode.UNSUPPORTED_PROTOCOL
    assert normalize_protocol(47, allow_other=True) == (Protocol.OTHER, 47)
    assert code_of(normalize_protocol, "OTHER") is ErrorCode.UNSUPPORTED_PROTOCOL


@pytest.mark.parametrize("raw", ["XYZ", 256, -1, True, 6.0])
def test_invalid_protocol(raw):
    assert code_of(normalize_protocol, raw) is ErrorCode.INVALID_PROTOCOL


# -------------------------------------------------------------------- counters
def test_counters():
    assert normalize_counter("0", field="bytes") == 0
    assert normalize_counter(15, field="packets") == 15
    for raw in (-1, "-3", "1.5", 2.0, "abc", True):
        assert code_of(normalize_counter, raw, field="packets") is ErrorCode.INVALID_COUNTER
    assert code_of(normalize_counter, None, field="packets") is ErrorCode.MISSING_REQUIRED_FIELD


def test_duration_units_and_rules():
    assert normalize_duration_ms("0") == 0.0
    assert normalize_duration_ms(1.5, unit="s") == 1500.0
    assert normalize_duration_ms("1234567", unit="us") == 1234.567
    assert normalize_duration_ms(132.7684) == 132.768
    for raw in (-0.001, "nan", float("inf"), "abc", True):
        assert code_of(normalize_duration_ms, raw) is ErrorCode.INVALID_DURATION


# ------------------------------------------------------------------ timestamps
def test_timestamps_normalised_to_utc_microseconds():
    a = parse_timestamp("2010-01-07T19:38:34.341715Z")
    b = parse_timestamp("2010-01-07T21:38:34.341715+02:00")
    c = parse_timestamp("1262893114.341715", fmt="epoch_s")
    d = parse_timestamp(1262893114341715, fmt="epoch_us")
    e = parse_timestamp("2010-01-07T19:38:34.341715999Z")      # sub-microsecond truncated
    assert a == b == c == d == e
    assert a.tzinfo is not None and a.utcoffset().total_seconds() == 0
    assert format_timestamp(a) == "2010-01-07T19:38:34.341715Z"
    assert format_timestamp(parse_timestamp("2010-01-07T19:38:34Z")) == "2010-01-07T19:38:34.000000Z"


def test_naive_timestamp_requires_explicit_timezone():
    assert code_of(parse_timestamp, "2010-01-07T19:38:34") is ErrorCode.INVALID_TIMESTAMP
    assert parse_timestamp("2010-01-07T20:38:34", assume_timezone="Europe/Berlin") == parse_timestamp(
        "2010-01-07T19:38:34Z")
    assert code_of(parse_timestamp, "2010-01-07T19:38:34", assume_timezone="Mars/Base") is ErrorCode.INVALID_TIMESTAMP


@pytest.mark.parametrize("raw,fmt", [("yesterday", "rfc3339"), ("2010-13-01T00:00:00Z", "rfc3339"),
                                     ("1969-12-31T23:59:59Z", "rfc3339"), ("-5", "epoch_s"), ("abc", "epoch_ms"),
                                     (True, "rfc3339"), (1262893114, "rfc3339")])
def test_invalid_timestamps(raw, fmt):
    assert code_of(parse_timestamp, raw, fmt=fmt) is ErrorCode.INVALID_TIMESTAMP


def test_ns_to_datetime_truncates_to_microseconds():
    assert ns_to_datetime(1_262_893_114_341_715_999) == datetime(2010, 1, 7, 19, 38, 34, 341715, tzinfo=timezone.utc)


# ------------------------------------------------------------------- TCP flags
def test_tcp_flags_availability():
    assert normalize_tcp_flags(None, protocol=Protocol.TCP) is None            # unavailable, not zero
    assert normalize_tcp_flags("0", protocol=Protocol.TCP) == 0                # genuine zero
    assert normalize_tcp_flags("0x12", protocol=Protocol.TCP) == 18
    assert normalize_tcp_flags("SA", protocol=Protocol.TCP, fmt="letters") == 18
    assert normalize_tcp_flags("FIN|ACK", protocol=Protocol.TCP, fmt="names") == 17
    assert code_of(normalize_tcp_flags, 18, protocol=Protocol.UDP) is ErrorCode.INVALID_TCP_FLAGS
    assert code_of(normalize_tcp_flags, 256, protocol=Protocol.TCP) is ErrorCode.INVALID_TCP_FLAGS
    assert code_of(normalize_tcp_flags, "SX", protocol=Protocol.TCP, fmt="letters") is ErrorCode.INVALID_TCP_FLAGS


def test_scenario_labels():
    assert normalize_scenario_label(None) is None
    assert normalize_scenario_label("PORT_SCAN") == "PORT_SCAN"
    assert normalize_scenario_label("BENIGN", value_map={"BENIGN": "NORMAL"}) == "NORMAL"
    assert code_of(normalize_scenario_label, "attack") is ErrorCode.INVALID_SCENARIO_LABEL


# ----------------------------------------------------- cross-field validation
@pytest.fixture
def genuine_tcp_flow(config) -> NormalizedFlow:
    """The client->server flow extracted from the genuine tcp_handshake capture."""
    from netguard_ingest.pipeline import ingest_pcap
    from conftest import read_jsonl
    event = read_jsonl(ingest_pcap(genuine("tcp_handshake.pcapng"), config).output_dir / "flows.jsonl")[0]
    return NormalizedFlow(
        flow_id=event["flow_id"], start_time=parse_timestamp(event["start_time"]), duration_ms=event["duration_ms"],
        src_ip=event["src_ip"], src_port=event["src_port"], dst_ip=event["dst_ip"], dst_port=event["dst_port"],
        protocol=Protocol(event["protocol"]), packets=event["packets"], bytes=event["bytes"],
        tcp_flags=event["tcp_flags"], source_type=SourceType.PCAP, scenario_label=None)


def test_genuine_flow_is_valid(genuine_tcp_flow):
    validate_flow(genuine_tcp_flow)


@pytest.mark.parametrize("changes,code", [
    ({"protocol": Protocol.UDP}, ErrorCode.INVALID_TCP_FLAGS),                     # flags on non-TCP
    ({"protocol": Protocol.ICMP, "tcp_flags": None}, ErrorCode.INVALID_PORT),       # ports on ICMP
    ({"packets": 0, "bytes": 0}, ErrorCode.INCONSISTENT_COUNTERS),
    ({"bytes": 39}, ErrorCode.INCONSISTENT_COUNTERS),                              # < 2 x 20-byte IPv4 header
    ({"packets": 1}, ErrorCode.INVALID_DURATION),                                  # 1 packet, duration > 0
    ({"dst_ip": "2001:db8::1"}, ErrorCode.INVALID_IP_ADDRESS),                     # mixed IP versions
    ({"duration_ms": -1.0}, ErrorCode.INVALID_DURATION),
    ({"src_port": 70000}, ErrorCode.INVALID_PORT),
    ({"scenario_label": "EVIL"}, ErrorCode.INVALID_SCENARIO_LABEL),
])
def test_cross_field_rules(genuine_tcp_flow, changes, code):
    with pytest.raises(ValidationIssue) as info:
        validate_flow(dataclasses.replace(genuine_tcp_flow, **changes))
    assert info.value.code is code
