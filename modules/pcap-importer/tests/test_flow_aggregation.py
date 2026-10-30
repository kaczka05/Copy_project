"""Packet-to-flow aggregation verified against an independent dpkt reference."""
from __future__ import annotations

from collections import defaultdict

import dpkt
import pytest
from conftest import ALL, genuine, read_jsonl

from netguard_ingest.capture.aggregator import EndReason, FlowAggregator
from netguard_ingest.capture.decoder import PacketDecoder
from netguard_ingest.capture.reader import CaptureReader
from netguard_ingest.errors import PacketRejected
from netguard_ingest.pipeline import ingest_pcap

NO_TIMEOUT = 10 ** 9


def aggregate(name, *, idle=NO_TIMEOUT, active=NO_TIMEOUT, max_flows=10 ** 6):
    agg = FlowAggregator(idle_timeout_s=idle, active_timeout_s=active, max_active_flows=max_flows,
                         flow_id_factory=lambda key, pkt: f"f{pkt.index}")
    decoder, flows, metas = PacketDecoder(), [], []
    with CaptureReader(genuine(name)) as reader:
        for packet in reader:
            try:
                meta = decoder.decode(packet.link_type, packet.data, packet.wirelen)
            except PacketRejected:
                continue
            metas.append((packet, meta))
            flows.extend(agg.add(meta, packet))
    flows.extend(agg.flush())
    return flows, metas, agg


def reference_groups(name):
    """Independent grouping of Ethernet IPv4/IPv6 TCP/UDP/ICMP packets by 5-tuple."""
    import ipaddress

    from conftest import independent_packets
    groups = defaultdict(lambda: {"packets": 0, "bytes": 0, "ts": [], "flags": None})
    for ts, buf in independent_packets(genuine(name)):
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            if ip.offset:
                continue
            length = min(ip.len, len(buf) - 14)
        elif isinstance(ip, dpkt.ip6.IP6):
            length = min(40 + ip.plen, len(buf) - 14)
        else:
            continue
        l4 = ip.data
        if ip.p not in (1, 6, 17, 58):
            continue
        ports = (l4.sport, l4.dport) if ip.p in (6, 17) else (None, None)
        key = (ipaddress.ip_address(ip.src).compressed, ports[0], ipaddress.ip_address(ip.dst).compressed,
               ports[1], ip.p)
        group = groups[key]
        group["packets"] += 1
        group["bytes"] += length
        group["ts"].append(float(ts))
        if ip.p == 6:
            group["flags"] = (group["flags"] or 0) | (l4.flags & 0xFF)
    return groups


@pytest.mark.parametrize("name", [n for n in ALL if n != "tfp_capture.pcapng"])
def test_flows_match_independent_reference_without_timeouts(name):
    flows, _, _ = aggregate(name)
    reference = reference_groups(name)
    assert {f.key for f in flows} == set(reference)
    for flow in flows:
        ref = reference[flow.key]
        assert flow.packets == ref["packets"]                        # packet aggregation
        assert flow.bytes == ref["bytes"]                            # byte aggregation
        assert flow.tcp_flags == ref["flags"]                        # flag OR, None for non-TCP
        assert abs(flow.first_ns / 1e9 - min(ref["ts"])) < 1e-6
        assert abs((flow.last_ns - flow.first_ns) / 1e9 - (max(ref["ts"]) - min(ref["ts"]))) < 2e-6
        assert flow.end_reason is EndReason.END_OF_CAPTURE


def test_directional_separation():
    flows, _, _ = aggregate("tcp_handshake.pcapng")
    assert len(flows) == 2
    a, b = flows
    assert a.key == (b.key[2], b.key[3], b.key[0], b.key[1], b.key[4])
    assert (a.packets, b.packets) == (2, 1)


def test_icmp_request_and_reply_are_separate_portless_flows():
    flows, _, _ = aggregate("icmp_echo.pcapng")
    assert len(flows) == 2 and all(f.packets == 4 for f in flows)
    assert all(f.key[1] is None and f.key[3] is None and f.tcp_flags is None for f in flows)


def _check_conservation(flows, metas):
    assert sum(f.packets for f in flows) == len(metas)
    assert sum(f.bytes for f in flows) == sum(m.l3_bytes for _, m in metas)


def test_idle_timeout_splits_flows():
    idle = 1.0
    flows, metas, agg = aggregate("telnet-raw.pcap", idle=idle)
    _check_conservation(flows, metas)
    assert len(flows) > 2 and agg.closed_by_reason["IDLE_TIMEOUT"] > 0
    by_key = defaultdict(list)
    for packet, meta in metas:
        by_key[(meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port, meta.ip_proto)].append(packet.ts_ns)
    for flow in flows:     # inside a flow, no gap between consecutive packets exceeds the idle timeout
        ts = [t for t in by_key[flow.key] if flow.first_ns <= t <= flow.last_ns]
        assert len(ts) == flow.packets
        assert all(b - a <= idle * 1e9 for a, b in zip(ts, ts[1:]))


def test_active_timeout_splits_long_flows_with_continuation_links():
    flows, metas, agg = aggregate("telnet-raw.pcap", active=5.0)
    _check_conservation(flows, metas)
    assert agg.closed_by_reason["ACTIVE_TIMEOUT"] > 0
    assert all(f.last_ns - f.first_ns <= 5e9 for f in flows)
    continuations = [f for f in flows if f.previous_flow_id]
    assert continuations and {f.previous_flow_id for f in continuations} <= {f.flow_id for f in flows}


def test_flow_table_limit_evicts_without_losing_packets():
    flows, metas, agg = aggregate("synscan.pcapng", max_flows=10)
    _check_conservation(flows, metas)
    assert agg.closed_by_reason["FLOW_TABLE_LIMIT"] > 0 and agg.peak_active_flows <= 11


def test_capture_boundary_marks_flows_open_at_end(config):
    result = ingest_pcap(genuine("tcp_teardown.pcapng"), config)
    provenance = read_jsonl(result.output_dir / "provenance.jsonl")
    assert provenance and all(p["end_reason"] == "END_OF_CAPTURE" for p in provenance)
    assert all("OPEN_AT_CAPTURE_END" in p["incomplete_reasons"] for p in provenance)


def test_incomplete_capture_flows_are_flagged(config, tmp_path):
    from conftest import classic_records
    path = genuine("telnet-raw.pcap")
    rec = classic_records(path)[100]
    trunc = tmp_path / "telnet-truncated.pcap"
    trunc.write_bytes(path.read_bytes()[: rec[0] + 20])
    result = ingest_pcap(trunc, config)
    report = result.report
    assert result.status == "COMPLETED_WITH_REJECTIONS" and report["capture"]["complete"] is False
    assert report["packets"]["examined"] == 101 and report["packets"]["attributed_to_flows"] == 100
    assert report["rejections"]["by_code"] == {"TRUNCATED_CAPTURE": 1}
    provenance = read_jsonl(result.output_dir / "provenance.jsonl")
    assert all("CAPTURE_TRUNCATED_OR_CORRUPTED" in p["incomplete_reasons"] for p in provenance)
    flows = read_jsonl(result.output_dir / "flows.jsonl")
    assert sum(f["packets"] for f in flows) == 100       # only the observed portion


def test_tcp_start_not_observed_is_reported(config):
    result = ingest_pcap(genuine("200722_tcp_anon.pcapng"), config)
    provenance = read_jsonl(result.output_dir / "provenance.jsonl")
    for p in provenance:
        syn_first = bool(p["first_packet_tcp_flags"] & 0x02)
        assert ("TCP_START_NOT_OBSERVED" in p["incomplete_reasons"]) == (not syn_first)
