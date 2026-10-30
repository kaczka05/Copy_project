"""Packet decoding on genuine packets (and mutated copies for malformed cases)."""
from __future__ import annotations

import dpkt
import pytest
from conftest import genuine

from netguard_ingest.capture.decoder import PacketDecoder
from netguard_ingest.capture.reader import CaptureReader
from netguard_ingest.errors import ErrorCode, PacketRejected
from netguard_ingest.model import Protocol


def packets(name):
    with CaptureReader(genuine(name)) as reader:
        return list(reader)


def decode(packet, decoder=None):
    return (decoder or PacketDecoder()).decode(packet.link_type, packet.data, packet.wirelen)


def test_tcp_extraction_matches_reference():
    for packet in packets("tcp_handshake.pcapng"):
        meta = decode(packet)
        ip = dpkt.ethernet.Ethernet(packet.data).data
        assert meta.protocol is Protocol.TCP and meta.ip_version == 4
        assert (meta.src_port, meta.dst_port) == (ip.data.sport, ip.data.dport)
        assert meta.tcp_flags == ip.data.flags & 0xFF
        assert meta.l3_bytes == ip.len                  # IP total length, link layer excluded
    first = decode(packets("tcp_handshake.pcapng")[0])
    assert (first.src_ip, first.src_port, first.dst_ip, first.dst_port) == ("172.16.16.128", 2826, "212.58.226.142", 80)
    assert first.tcp_flags == 0x02                        # SYN


def test_ethernet_padding_not_counted():
    padded = [p for p in packets("dns.cap") + packets("tcp_teardown.pcapng")
              if len(p.data) - 14 > dpkt.ethernet.Ethernet(p.data).data.len]
    assert padded, "expected at least one padded Ethernet frame in the genuine captures"
    for packet in padded:
        assert decode(packet).l3_bytes == dpkt.ethernet.Ethernet(packet.data).data.len


def test_udp_extraction():
    meta = decode(packets("udp_dnsrequest.pcapng")[0])
    assert meta.protocol is Protocol.UDP and meta.dst_port == 53 and meta.tcp_flags is None


def test_icmp_has_no_ports_and_no_flags():
    for packet in packets("icmp_echo.pcapng"):
        meta = decode(packet)
        assert meta.protocol is Protocol.ICMP
        assert meta.src_port is None and meta.dst_port is None and meta.tcp_flags is None


def test_ipv6_tcp_udp_icmpv6():
    seen = {decode(p).protocol for p in packets("v6.pcap")}
    assert seen == {Protocol.TCP, Protocol.UDP, Protocol.ICMPV6}
    meta = decode(packets("v6.pcap")[0])
    assert meta.ip_version == 6 and ":" in meta.src_ip and meta.src_ip == meta.src_ip.lower()


def test_tcp_ecn_flags_preserved():
    flags = {decode(p).tcp_flags for p in packets("tcp-ecn-sample.pcap")}
    assert any(f & 0x40 for f in flags) and any(f & 0x80 for f in flags)   # ECE and CWR observed


def test_non_ip_rejected_as_unsupported():
    with pytest.raises(PacketRejected) as info:
        decode(packets("arp_resolution.pcapng")[0])
    assert info.value.code is ErrorCode.NON_IP_PACKET and info.value.details["network_type"] == "0x0806"


def test_non_first_fragment_rejected():
    codes = []
    for packet in packets("ipv4frags.pcap"):
        try:
            decode(packet)
            codes.append(None)
        except PacketRejected as exc:
            codes.append(exc.code)
    assert codes == [None, ErrorCode.IP_FRAGMENT_NOT_REASSEMBLED, None]


def test_unsupported_ip_protocol_rejected_or_emitted_as_other():
    tunnel = [p for p in packets("sr-header.pcap") if dpkt.ethernet.Ethernet(p.data).data.nxt == 43]
    with pytest.raises(PacketRejected) as info:
        decode(tunnel[0])
    assert info.value.code is ErrorCode.UNSUPPORTED_IP_PROTOCOL and info.value.details["ip_proto"] == 41
    meta = decode(tunnel[0], PacketDecoder(emit_other_protocols=True))
    assert meta.protocol is Protocol.OTHER and meta.ip_proto == 41 and meta.src_port is None


def test_unsupported_link_type_packets():
    usb = next(p for p in packets("tfp_capture.pcapng") if p.link_type == 220)
    with pytest.raises(PacketRejected) as info:
        decode(usb)
    assert info.value.code is ErrorCode.UNSUPPORTED_LINK_TYPE


def test_raw_ip_link_type_on_genuine_packet_bytes():
    """Link-layer handling: the genuine IP packet with its Ethernet header removed."""
    packet = packets("tcp_handshake.pcapng")[0]
    eth_meta = decode(packet)
    raw_meta = PacketDecoder().decode(101, packet.data[14:], packet.wirelen - 14)
    assert raw_meta == eth_meta


def _mutated(packet, mutate):
    data = bytearray(packet.data)
    mutate(data)
    return PacketDecoder().decode(packet.link_type, bytes(data), packet.wirelen)


@pytest.mark.parametrize("mutate,code", [
    (lambda d: d.__setitem__(14, 0x75), ErrorCode.MALFORMED_NETWORK_HEADER),       # IP version 7
    (lambda d: d.__setitem__(14, 0x42), ErrorCode.MALFORMED_NETWORK_HEADER),       # IHL 8 bytes
    (lambda d: d.__setitem__(slice(16, 18), b"\x00\x0a"), ErrorCode.MALFORMED_NETWORK_HEADER),  # total len < IHL
    (lambda d: d.__delitem__(slice(24, None)), ErrorCode.TRUNCATED_NETWORK_HEADER),
    (lambda d: d.__delitem__(slice(44, None)), ErrorCode.TRUNCATED_TRANSPORT_HEADER),  # 10 of 20 TCP bytes
    (lambda d: d.__delitem__(slice(10, None)), ErrorCode.MALFORMED_LINK_HEADER),
])
def test_malformed_packets_are_rejected(mutate, code):
    packet = packets("tcp_handshake.pcapng")[0]
    with pytest.raises(PacketRejected) as info:
        _mutated(packet, mutate)
    assert info.value.code is code


def test_truncated_udp_header_rejected():
    packet = packets("udp_dnsrequest.pcapng")[0]
    with pytest.raises(PacketRejected) as info:
        _mutated(packet, lambda d: d.__delitem__(slice(14 + 20 + 4, None)))
    assert info.value.code is ErrorCode.TRUNCATED_TRANSPORT_HEADER


def test_snaplen_truncated_packet_counts_captured_bytes_only():
    packet = packets("telnet-raw.pcap")[10]
    ip = dpkt.ethernet.Ethernet(packet.data).data
    keep = 14 + ip.hl * 4 + 20 + 1 if len(packet.data) > 14 + ip.hl * 4 + 21 else len(packet.data)
    meta = PacketDecoder().decode(packet.link_type, packet.data[:keep], packet.wirelen)
    assert meta.snaplen_truncated == (keep < packet.wirelen)
    assert meta.l3_bytes == min(ip.len, keep - 14)
