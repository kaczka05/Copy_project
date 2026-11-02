"""Link/network/transport decoding of one captured packet with dpkt.

Produces :class:`PacketMeta` for packets that can be attributed to a
unidirectional flow, or raises :class:`~netguard_ingest.errors.PacketRejected`
with a precise reason. Nothing is inferred that is not present in the bytes.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

import dpkt

from ..errors import ErrorCode, PacketRejected
from ..model import IP_PROTO_TO_PROTOCOL, Protocol
from ..normalize import canonical_ip

# LINKTYPE_* values (https://www.tcpdump.org/linktypes.html) supported here.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_RAW_ALIASES = (12, 14)      # DLT_RAW values used by some BSDs
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

SUPPORTED_LINK_TYPES = {
    LINKTYPE_NULL: "NULL", LINKTYPE_ETHERNET: "ETHERNET", LINKTYPE_RAW: "RAW", 12: "RAW", 14: "RAW",
    LINKTYPE_LOOP: "LOOP", LINKTYPE_LINUX_SLL: "LINUX_SLL", LINKTYPE_IPV4: "IPV4", LINKTYPE_IPV6: "IPV6",
    LINKTYPE_LINUX_SLL2: "LINUX_SLL2",
}

ETH_TYPE_IP = 0x0800
ETH_TYPE_IP6 = 0x86DD
_AF_INET6_VALUES = {10, 24, 28, 30}   # Linux, BSD, FreeBSD, macOS


@dataclass(slots=True)
class PacketMeta:
    """Flow-relevant metadata extracted from one packet."""

    ip_version: int
    src_ip: str
    dst_ip: str
    ip_proto: int
    protocol: Protocol
    src_port: int | None
    dst_port: int | None
    tcp_flags: int | None
    l3_bytes: int            # bytes counted for the flow (see byte convention)
    snaplen_truncated: bool  # caplen < original length


class PacketDecoder:
    """Stateless packet decoder; one instance per ingestion."""

    def __init__(self, emit_other_protocols: bool = False) -> None:
        self.emit_other_protocols = emit_other_protocols
        self._addr_cache: dict[bytes, str] = {}

    # ------------------------------------------------------------------ link
    def decode(self, link_type: int, data: bytes, wirelen: int) -> PacketMeta:
        truncated = len(data) < wirelen
        version, l3, parsed = self._strip_link_layer(link_type, data)
        if version == 4:
            return self._decode_ipv4(l3, parsed, truncated)
        return self._decode_ipv6(l3, parsed, truncated)

    def _strip_link_layer(self, link_type: int, data: bytes):
        """Return (ip_version, raw L3 bytes, already-parsed dpkt IP object|None)."""
        if link_type == LINKTYPE_ETHERNET:
            if len(data) < 14:
                raise PacketRejected(ErrorCode.MALFORMED_LINK_HEADER, f"Ethernet frame too short ({len(data)} bytes)")
            try:
                eth = dpkt.ethernet.Ethernet(data)
            except (dpkt.UnpackError, struct.error, IndexError) as exc:
                raise PacketRejected(ErrorCode.MALFORMED_LINK_HEADER, f"invalid Ethernet header: {exc}") from None
            eth_type = getattr(eth, "_next_type", None) or eth.type
            offset = 14 + 4 * len(getattr(eth, "vlan_tags", None) or []) \
                + 4 * len(getattr(eth, "mpls_labels", None) or [])
            return self._classify_ethertype(eth_type, data[offset:], eth.data, "Ethernet")
        if link_type == LINKTYPE_LINUX_SLL:
            if len(data) < 16:
                raise PacketRejected(ErrorCode.MALFORMED_LINK_HEADER, "Linux SLL header truncated")
            (eth_type,) = struct.unpack(">H", data[14:16])
            return self._classify_ethertype(eth_type, data[16:], None, "Linux SLL")
        if link_type == LINKTYPE_LINUX_SLL2:
            if len(data) < 20:
                raise PacketRejected(ErrorCode.MALFORMED_LINK_HEADER, "Linux SLL2 header truncated")
            (eth_type,) = struct.unpack(">H", data[0:2])
            return self._classify_ethertype(eth_type, data[20:], None, "Linux SLL2")
        if link_type in (LINKTYPE_NULL, LINKTYPE_LOOP):
            if len(data) < 4:
                raise PacketRejected(ErrorCode.MALFORMED_LINK_HEADER, "loopback header truncated")
            family = struct.unpack("<I" if link_type == LINKTYPE_NULL else ">I", data[:4])[0]
            if link_type == LINKTYPE_NULL and family > 0xFFFF:  # written with the other byte order
                family = struct.unpack(">I", data[:4])[0]
            if family == 2:
                return 4, data[4:], None
            if family in _AF_INET6_VALUES:
                return 6, data[4:], None
            raise PacketRejected(ErrorCode.NON_IP_PACKET, f"loopback address family {family} is not IP",
                                 network_type=f"AF_{family}")
        if link_type in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6) or link_type in LINKTYPE_RAW_ALIASES:
            if not data:
                raise PacketRejected(ErrorCode.TRUNCATED_NETWORK_HEADER, "empty raw IP packet")
            version = data[0] >> 4
            expected = {LINKTYPE_IPV4: 4, LINKTYPE_IPV6: 6}.get(link_type)
            if version not in (4, 6) or (expected and version != expected):
                raise PacketRejected(ErrorCode.MALFORMED_NETWORK_HEADER,
                                     f"raw IP packet has IP version field {version}")
            return version, data, None
        raise PacketRejected(ErrorCode.UNSUPPORTED_LINK_TYPE, f"link type {link_type} is not supported",
                             link_type=link_type)

    @staticmethod
    def _classify_ethertype(eth_type: int, l3: bytes, parsed, layer: str):
        if eth_type == ETH_TYPE_IP:
            return 4, l3, parsed if isinstance(parsed, dpkt.ip.IP) else None
        if eth_type == ETH_TYPE_IP6:
            return 6, l3, parsed if isinstance(parsed, dpkt.ip6.IP6) else None
        raise PacketRejected(ErrorCode.NON_IP_PACKET,
                             f"{layer} payload type 0x{eth_type:04x} is not IPv4/IPv6",
                             network_type=f"0x{eth_type:04x}")

    # --------------------------------------------------------------- network
    def _addr(self, raw: bytes) -> str:
        text = self._addr_cache.get(raw)
        if text is None:
            text = canonical_ip(ipaddress.ip_address(raw))
            if len(self._addr_cache) < 65_536:
                self._addr_cache[raw] = text
        return text

    def _decode_ipv4(self, l3: bytes, ip, truncated: bool) -> PacketMeta:
        if len(l3) < 20:
            raise PacketRejected(ErrorCode.TRUNCATED_NETWORK_HEADER, f"IPv4 header truncated ({len(l3)} bytes)")
        version, ihl = l3[0] >> 4, (l3[0] & 0x0F) * 4
        if version != 4:
            raise PacketRejected(ErrorCode.MALFORMED_NETWORK_HEADER, f"IPv4 version field is {version}")
        if ihl < 20:
            raise PacketRejected(ErrorCode.MALFORMED_NETWORK_HEADER, f"IPv4 header length {ihl} < 20")
        if len(l3) < ihl:
            raise PacketRejected(ErrorCode.TRUNCATED_NETWORK_HEADER,
                                 f"IPv4 header with options truncated ({len(l3)} of {ihl} bytes)")
        (total_length,) = struct.unpack(">H", l3[2:4])
        if total_length and total_length < ihl:
            raise PacketRejected(ErrorCode.MALFORMED_NETWORK_HEADER,
                                 f"IPv4 total length {total_length} < header length {ihl}")
        # total_length == 0 occurs with TCP segmentation offload: use captured size.
        l3_bytes = min(total_length, len(l3)) if total_length else len(l3)
        if ip is None:
            try:
                ip = dpkt.ip.IP(l3)
            except (dpkt.UnpackError, struct.error) as exc:
                raise PacketRejected(ErrorCode.MALFORMED_NETWORK_HEADER, f"invalid IPv4 header: {exc}") from None
        if ip.offset:
            raise PacketRejected(ErrorCode.IP_FRAGMENT_NOT_REASSEMBLED,
                                 "non-first IPv4 fragment carries no transport header (no reassembly)",
                                 ip_proto=ip.p)
        return self._transport(4, self._addr(ip.src), self._addr(ip.dst), ip.p, ip.data,
                               l3_bytes, l3_bytes - ihl, truncated)

    def _decode_ipv6(self, l3: bytes, ip, truncated: bool) -> PacketMeta:
        if len(l3) < 40:
            raise PacketRejected(ErrorCode.TRUNCATED_NETWORK_HEADER, f"IPv6 header truncated ({len(l3)} bytes)")
        version = l3[0] >> 4
        if version != 6:
            raise PacketRejected(ErrorCode.MALFORMED_NETWORK_HEADER, f"IPv6 version field is {version}")
        (payload_length,) = struct.unpack(">H", l3[4:6])
        l3_bytes = min(40 + payload_length, len(l3)) if payload_length else len(l3)
        if ip is None:
            try:
                ip = dpkt.ip6.IP6(l3)
            except (dpkt.UnpackError, struct.error, KeyError, IndexError) as exc:
                raise PacketRejected(ErrorCode.MALFORMED_NETWORK_HEADER,
                                     f"invalid IPv6 header or extension header chain: {exc}") from None
        ext_len = 0
        for ext in getattr(ip, "all_extension_headers", []):
            ext_len += getattr(ext, "length", 0)
            if isinstance(ext, dpkt.ip6.IP6FragmentHeader) and ext.frag_off:
                raise PacketRejected(ErrorCode.IP_FRAGMENT_NOT_REASSEMBLED,
                                     "non-first IPv6 fragment carries no transport header (no reassembly)",
                                     ip_proto=ip.p)
        if 40 + ext_len > len(l3):
            raise PacketRejected(ErrorCode.TRUNCATED_NETWORK_HEADER, "IPv6 extension headers truncated")
        return self._transport(6, self._addr(ip.src), self._addr(ip.dst), ip.p, ip.data,
                               l3_bytes, l3_bytes - 40 - ext_len, truncated)

    # ------------------------------------------------------------- transport
    def _transport(self, version: int, src: str, dst: str, proto: int, payload, l3_bytes: int,
                   available: int, truncated: bool) -> PacketMeta:
        protocol = IP_PROTO_TO_PROTOCOL.get(proto)
        if protocol is Protocol.TCP:
            if not isinstance(payload, dpkt.tcp.TCP):
                code = ErrorCode.TRUNCATED_TRANSPORT_HEADER if available < 20 \
                    else ErrorCode.MALFORMED_TRANSPORT_HEADER
                raise PacketRejected(code, f"TCP header could not be decoded ({max(available, 0)} bytes available)")
            data_offset = (payload._off_flags >> 12) * 4
            if data_offset < 20:
                raise PacketRejected(ErrorCode.MALFORMED_TRANSPORT_HEADER, f"TCP data offset {data_offset} < 20")
            return PacketMeta(version, src, dst, proto, protocol, payload.sport, payload.dport,
                              payload.flags & 0xFF, l3_bytes, truncated)
        if protocol is Protocol.UDP:
            if not isinstance(payload, dpkt.udp.UDP):
                code = ErrorCode.TRUNCATED_TRANSPORT_HEADER if available < 8 \
                    else ErrorCode.MALFORMED_TRANSPORT_HEADER
                raise PacketRejected(code, f"UDP header could not be decoded ({max(available, 0)} bytes available)")
            return PacketMeta(version, src, dst, proto, protocol, payload.sport, payload.dport, None,
                              l3_bytes, truncated)
        if protocol in (Protocol.ICMP, Protocol.ICMPV6):
            if available < 4:
                raise PacketRejected(ErrorCode.TRUNCATED_TRANSPORT_HEADER,
                                     f"{protocol.value} header truncated ({max(available, 0)} bytes available)")
            return PacketMeta(version, src, dst, proto, protocol, None, None, None, l3_bytes, truncated)
        if self.emit_other_protocols:
            return PacketMeta(version, src, dst, proto, Protocol.OTHER, None, None, None, l3_bytes, truncated)
        raise PacketRejected(ErrorCode.UNSUPPORTED_IP_PROTOCOL,
                             f"IP protocol {proto} is not supported (TCP, UDP, ICMP, ICMPv6)", ip_proto=proto)
