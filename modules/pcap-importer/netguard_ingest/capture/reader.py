"""Streaming PCAP / PCAPNG record reader.

The record/block *contents* are decoded with dpkt's header classes
(``dpkt.pcap.FileHdr``/``PktHdr``, ``dpkt.pcapng.*Block``). This module only
performs the record framing loop itself because dpkt 1.9.8's high-level
``Reader`` classes (a) discard ``caplen``/original length, (b) honour only the
first pcapng Interface Description Block (link type and timestamp
resolution), (c) silently stop or return short buffers on truncated files and
(d) expose timestamps only as floats. All four are needed for correct flow
extraction, byte counting and incomplete-capture reporting.

Packets are read one at a time; the file is never loaded into memory.
"""
from __future__ import annotations

import os
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

import dpkt

from ..errors import ErrorCode, InputFileError

# pcap magic numbers (as read big-endian from the first 4 bytes)
_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": ("big", 1_000),          # microsecond -> ns factor
    b"\xd4\xc3\xb2\xa1": ("little", 1_000),
    b"\xa1\xb2\x3c\x4d": ("big", 1),              # nanosecond
    b"\x4d\x3c\xb2\xa1": ("little", 1),
}
_MODIFIED_PCAP_MAGICS = {b"\xa1\xb2\xcd\x34", b"\x34\xcd\xb2\xa1"}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_GZIP = b"\x1f\x8b"

# Upper bound for a single captured packet; larger values mean a corrupt header.
MAX_CAPLEN = 262_144
MAX_PCAPNG_BLOCK = 16 * 1024 * 1024

BT_IDB, BT_PB, BT_SPB, BT_EPB = 0x00000001, 0x00000002, 0x00000003, 0x00000006
BT_SHB = 0x0A0D0D0A
OPT_IF_TSRESOL, OPT_IF_TSOFFSET = 9, 14


@dataclass(slots=True)
class RawPacket:
    """One captured packet as stored in the file."""

    index: int            # 1-based ordinal of the packet record in the file
    file_offset: int      # byte offset of the record/block header
    ts_ns: int            # capture timestamp, integer ns since epoch (UTC)
    caplen: int           # bytes present in the file
    wirelen: int          # original length on the wire
    link_type: int
    interface_id: int
    data: bytes


@dataclass(slots=True)
class CaptureIssue:
    """Structural problem found while framing records."""

    code: ErrorCode
    message: str
    file_offset: int
    packet_index: int | None = None   # packet affected (None = whole remainder)
    fatal: bool = False               # framing lost: rest of file not read


@dataclass(slots=True)
class InterfaceInfo:
    interface_id: int
    link_type: int
    snaplen: int
    ts_resolution: str
    ts_offset_s: int
    _units_num: int = 1_000_000_000   # ns = units * num // den
    _units_den: int = 1_000_000

    def to_ns(self, units: int) -> int:
        return units * self._units_num // self._units_den + self.ts_offset_s * 1_000_000_000


@dataclass(slots=True)
class CaptureInfo:
    format: str                      # "pcap" | "pcapng"
    byte_order: str
    version: str
    timestamp_resolution: str
    snaplen: int | None
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    sections: int = 0
    skipped_blocks: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def link_types(self) -> list[int]:
        return sorted({i.link_type for i in self.interfaces})

    def to_dict(self) -> dict:
        return {
            "format": self.format,
            "byte_order": self.byte_order,
            "version": self.version,
            "timestamp_resolution": self.timestamp_resolution,
            "snaplen": self.snaplen,
            "link_types": self.link_types,
            "interfaces": [
                {"interface_id": i.interface_id, "link_type": i.link_type, "snaplen": i.snaplen,
                 "ts_resolution": i.ts_resolution, "ts_offset_s": i.ts_offset_s}
                for i in self.interfaces
            ],
            "sections": self.sections,
            "skipped_blocks": self.skipped_blocks,
            "warnings": self.warnings,
        }


def detect_capture_format(head: bytes) -> str:
    """Return ``pcap`` or ``pcapng`` or raise :class:`InputFileError`."""
    if len(head) < 4:
        raise InputFileError(ErrorCode.CORRUPTED_CAPTURE_HEADER, "file is too short to contain a capture header")
    magic = head[:4]
    if magic in _PCAP_MAGICS:
        return "pcap"
    if magic == _PCAPNG_SHB:
        return "pcapng"
    if magic in _MODIFIED_PCAP_MAGICS:
        raise InputFileError(ErrorCode.UNSUPPORTED_FILE_FORMAT,
                             "modified (Kuznetzov) pcap variant is not supported; convert with editcap/tcpdump")
    if head[:2] == _GZIP:
        raise InputFileError(ErrorCode.UNSUPPORTED_FILE_FORMAT,
                             "gzip-compressed file; decompress the capture before ingestion")
    raise InputFileError(ErrorCode.UNSUPPORTED_FILE_FORMAT,
                         f"not a pcap/pcapng capture (magic bytes {magic.hex()})")


class CaptureReader:
    """Iterate over :class:`RawPacket` objects of a pcap or pcapng file.

    Structural problems are appended to :attr:`issues`; iteration stops early
    only when record framing is lost (truncated or corrupted record header).
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.file_size = os.path.getsize(self.path)
        self._fh: BinaryIO = open(self.path, "rb")  # noqa: SIM115 - closed in close()
        self.issues: list[CaptureIssue] = []
        self.records_read = 0
        self.packets_seen = 0      # packet records encountered (incl. invalid / partial)
        self.ended_abnormally = False
        try:
            head = self._fh.read(4)
            self._fh.seek(0)
            self.format = detect_capture_format(head)
            if self.format == "pcap":
                self.info = self._open_pcap()
            else:
                self.info = self._open_pcapng_first_section()
        except Exception:
            self.close()
            raise

    # ------------------------------------------------------------------ API
    def __enter__(self) -> CaptureReader:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    def __iter__(self) -> Iterator[RawPacket]:
        if self.format == "pcap":
            return self._iter_pcap()
        return self._iter_pcapng()

    def _issue(self, code: ErrorCode, message: str, offset: int, index: int | None = None,
               fatal: bool = False) -> None:
        self.issues.append(CaptureIssue(code, message, offset, index, fatal))
        if fatal:
            self.ended_abnormally = True

    # ------------------------------------------------------------------ pcap
    def _open_pcap(self) -> CaptureInfo:
        raw = self._fh.read(dpkt.pcap.FileHdr.__hdr_len__)
        if len(raw) < dpkt.pcap.FileHdr.__hdr_len__:
            raise InputFileError(ErrorCode.CORRUPTED_CAPTURE_HEADER,
                                 f"pcap global header truncated ({len(raw)} of 24 bytes)")
        order, ns_factor = _PCAP_MAGICS[raw[:4]]
        hdr_cls = dpkt.pcap.LEFileHdr if order == "little" else dpkt.pcap.FileHdr
        hdr = hdr_cls(raw)
        if hdr.v_major != 2:
            raise InputFileError(ErrorCode.UNSUPPORTED_CAPTURE_VERSION,
                                 f"unsupported pcap version {hdr.v_major}.{hdr.v_minor}")
        self._pkt_hdr_cls = dpkt.pcap.LEPktHdr if order == "little" else dpkt.pcap.PktHdr
        self._ns_factor = ns_factor
        link_type = hdr.linktype & 0x0FFFFFFF  # upper bits may carry FCS info
        info = CaptureInfo(
            format="pcap", byte_order=order, version=f"{hdr.v_major}.{hdr.v_minor}",
            timestamp_resolution="microsecond" if ns_factor == 1_000 else "nanosecond",
            snaplen=hdr.snaplen,
            interfaces=[InterfaceInfo(0, link_type, hdr.snaplen,
                                      "microsecond" if ns_factor == 1_000 else "nanosecond", 0)],
        )
        if hdr.thiszone:
            info.warnings.append(
                f"pcap header thiszone={hdr.thiszone} ignored; libpcap defines record timestamps as UTC")
        return info

    def _iter_pcap(self) -> Iterator[RawPacket]:
        fh = self._fh
        hdr_len = self._pkt_hdr_cls.__hdr_len__
        link_type = self.info.interfaces[0].link_type
        sub_limit = 1_000_000 if self._ns_factor == 1_000 else 1_000_000_000
        limit = max(MAX_CAPLEN, self.info.snaplen or 0)
        index = 0
        while True:
            offset = fh.tell()
            raw = fh.read(hdr_len)
            if not raw:
                return
            index += 1
            self.packets_seen = index
            if len(raw) < hdr_len:
                self._issue(ErrorCode.TRUNCATED_CAPTURE,
                            f"capture ends inside a packet record header ({len(raw)} of {hdr_len} bytes)",
                            offset, index, fatal=True)
                return
            hdr = self._pkt_hdr_cls(raw)
            if hdr.caplen > limit:
                self._issue(ErrorCode.CORRUPTED_RECORD,
                            f"record caplen {hdr.caplen} exceeds limit {limit}; record framing lost",
                            offset, index, fatal=True)
                return
            data = fh.read(hdr.caplen)
            if len(data) < hdr.caplen:
                self._issue(ErrorCode.TRUNCATED_CAPTURE,
                            f"capture ends inside packet data ({len(data)} of {hdr.caplen} bytes)",
                            offset, index, fatal=True)
                return
            self.records_read += 1
            if hdr.tv_usec >= sub_limit:
                self._issue(ErrorCode.CORRUPTED_RECORD,
                            f"record timestamp fraction {hdr.tv_usec} out of range", offset, index)
                continue
            if hdr.caplen > hdr.len:
                self._issue(ErrorCode.CORRUPTED_RECORD,
                            f"record caplen {hdr.caplen} exceeds original length {hdr.len}", offset, index)
                continue
            ts_ns = hdr.tv_sec * 1_000_000_000 + hdr.tv_usec * self._ns_factor
            yield RawPacket(index, offset, ts_ns, hdr.caplen, hdr.len, link_type, 0, data)

    # ---------------------------------------------------------------- pcapng
    def _open_pcapng_first_section(self) -> CaptureInfo:
        info = CaptureInfo(format="pcapng", byte_order="", version="", timestamp_resolution="per-interface",
                           snaplen=None)
        self._section_interfaces: list[InterfaceInfo] = []
        self._le = True
        shb = self._read_shb(self._fh.tell(), first=True)
        info.byte_order = "little" if self._le else "big"
        info.version = f"{shb.v_major}.{shb.v_minor}"
        info.sections = 1
        return info

    def _read_shb(self, offset: int, first: bool = False):
        fh = self._fh
        head = fh.read(12)
        if len(head) < 12:
            if first:
                raise InputFileError(ErrorCode.CORRUPTED_CAPTURE_HEADER, "pcapng section header truncated")
            self._issue(ErrorCode.TRUNCATED_CAPTURE, "capture ends inside a section header", offset, fatal=True)
            return None
        bom = head[8:12]
        if bom == b"\x4d\x3c\x2b\x1a":
            le = True
        elif bom == b"\x1a\x2b\x3c\x4d":
            le = False
        else:
            if first:
                raise InputFileError(ErrorCode.CORRUPTED_CAPTURE_HEADER, "pcapng byte-order magic invalid")
            self._issue(ErrorCode.CORRUPTED_RECORD, "section header byte-order magic invalid", offset, fatal=True)
            return None
        (blk_len,) = struct.unpack("<I" if le else ">I", head[4:8])
        if blk_len < 28 or blk_len % 4 or blk_len > MAX_PCAPNG_BLOCK:
            if first:
                raise InputFileError(ErrorCode.CORRUPTED_CAPTURE_HEADER, f"invalid section header length {blk_len}")
            self._issue(ErrorCode.CORRUPTED_RECORD, f"invalid section header length {blk_len}", offset, fatal=True)
            return None
        rest = fh.read(blk_len - 12)
        if len(rest) < blk_len - 12:
            if first:
                raise InputFileError(ErrorCode.CORRUPTED_CAPTURE_HEADER, "pcapng section header truncated")
            self._issue(ErrorCode.TRUNCATED_CAPTURE, "capture ends inside a section header", offset, fatal=True)
            return None
        try:
            shb = (dpkt.pcapng.SectionHeaderBlockLE if le else dpkt.pcapng.SectionHeaderBlock)(head + rest)
        except (dpkt.UnpackError, struct.error, ValueError) as exc:
            if first:
                raise InputFileError(ErrorCode.CORRUPTED_CAPTURE_HEADER, f"invalid section header: {exc}") from None
            self._issue(ErrorCode.CORRUPTED_RECORD, f"invalid section header: {exc}", offset, fatal=True)
            return None
        if shb.v_major != 1:
            if first:
                raise InputFileError(ErrorCode.UNSUPPORTED_CAPTURE_VERSION,
                                     f"unsupported pcapng version {shb.v_major}.{shb.v_minor}")
            self._issue(ErrorCode.CORRUPTED_RECORD, f"unsupported pcapng section version {shb.v_major}",
                        offset, fatal=True)
            return None
        self._le = le
        self._section_interfaces = []
        return shb

    def _parse_idb(self, buf: bytes, offset: int) -> InterfaceInfo | None:
        try:
            idb = (dpkt.pcapng.InterfaceDescriptionBlockLE if self._le
                   else dpkt.pcapng.InterfaceDescriptionBlock)(buf)
        except (dpkt.UnpackError, struct.error, ValueError) as exc:
            self._issue(ErrorCode.CORRUPTED_RECORD, f"invalid interface description block: {exc}",
                        offset, fatal=True)
            return None
        num, den, resolution, ts_offset = 1_000_000_000, 1_000_000, "10^-6", 0
        for opt in idb.opts:
            if opt.code == OPT_IF_TSRESOL and len(opt.data) >= 1:
                raw = opt.data[0]
                exponent = raw & 0x7F
                if raw & 0x80:
                    den, resolution = 2 ** exponent, f"2^-{exponent}"
                else:
                    den, resolution = 10 ** exponent, f"10^-{exponent}"
            elif opt.code == OPT_IF_TSOFFSET and len(opt.data) >= 8:
                (ts_offset,) = struct.unpack("<q" if self._le else ">q", opt.data[:8])
        iface = InterfaceInfo(len(self._section_interfaces), idb.linktype, idb.snaplen, resolution, ts_offset,
                              num, den)
        self._section_interfaces.append(iface)
        self.info.interfaces.append(iface)
        return iface

    def _iter_pcapng(self) -> Iterator[RawPacket]:
        fh = self._fh
        index = 0
        while True:
            offset = fh.tell()
            head = fh.read(8)
            if not head:
                return
            if len(head) < 8:
                self._issue(ErrorCode.TRUNCATED_CAPTURE, "capture ends inside a block header", offset, fatal=True)
                return
            if head[:4] == _PCAPNG_SHB:
                fh.seek(offset)
                if self._read_shb(offset) is None:
                    return
                self.info.sections += 1
                continue
            blk_type, blk_len = struct.unpack("<II" if self._le else ">II", head)
            if blk_len < 12 or blk_len % 4 or blk_len > MAX_PCAPNG_BLOCK:
                self._issue(ErrorCode.CORRUPTED_RECORD, f"invalid block length {blk_len}; block framing lost",
                            offset, fatal=True)
                return
            body = fh.read(blk_len - 8)
            if len(body) < blk_len - 8:
                if blk_type in (BT_EPB, BT_PB, BT_SPB):
                    index += 1
                    self.packets_seen = index
                self._issue(ErrorCode.TRUNCATED_CAPTURE,
                            f"capture ends inside a block ({len(body) + 8} of {blk_len} bytes)", offset,
                            index if blk_type in (BT_EPB, BT_PB, BT_SPB) else None, fatal=True)
                return
            buf = head + body
            (trailer_len,) = struct.unpack("<I" if self._le else ">I", buf[-4:])
            if trailer_len != blk_len:
                self._issue(ErrorCode.CORRUPTED_RECORD,
                            f"block trailing length {trailer_len} != leading length {blk_len}", offset,
                            fatal=True)
                return
            if blk_type == BT_IDB:
                if self._parse_idb(buf, offset) is None:
                    return
                continue
            if blk_type not in (BT_EPB, BT_PB, BT_SPB):
                key = f"0x{blk_type:08x}"
                self.info.skipped_blocks[key] = self.info.skipped_blocks.get(key, 0) + 1
                continue
            index += 1
            self.packets_seen = index
            self.records_read += 1
            packet = self._decode_packet_block(blk_type, buf, offset, index)
            if packet is not None:
                yield packet

    def _decode_packet_block(self, blk_type: int, buf: bytes, offset: int, index: int) -> RawPacket | None:
        if blk_type == BT_SPB:
            self._issue(ErrorCode.MISSING_PACKET_TIMESTAMP,
                        "simple packet block carries no timestamp; packet cannot be placed in a flow", offset, index)
            return None
        try:
            if blk_type == BT_EPB:
                blk = (dpkt.pcapng.EnhancedPacketBlockLE if self._le else dpkt.pcapng.EnhancedPacketBlock)(buf)
                iface_id, wirelen = blk.iface_id, blk.pkt_len
            else:
                blk = (dpkt.pcapng.PacketBlockLE if self._le else dpkt.pcapng.PacketBlock)(buf)
                iface_id, wirelen = blk.iface_id, blk.pkt_len
        except (dpkt.UnpackError, struct.error, ValueError) as exc:
            self._issue(ErrorCode.CORRUPTED_RECORD, f"invalid packet block: {exc}", offset, index)
            return None
        data = bytes(blk.pkt_data)
        if len(data) != blk.caplen:
            self._issue(ErrorCode.CORRUPTED_RECORD,
                        f"packet block captured length {blk.caplen} inconsistent with block size", offset, index)
            return None
        if blk.caplen > wirelen:
            self._issue(ErrorCode.CORRUPTED_RECORD,
                        f"captured length {blk.caplen} exceeds original length {wirelen}", offset, index)
            return None
        if iface_id >= len(self._section_interfaces):
            self._issue(ErrorCode.UNKNOWN_INTERFACE,
                        f"packet references undefined interface {iface_id}", offset, index)
            return None
        iface = self._section_interfaces[iface_id]
        ts_ns = iface.to_ns((blk.ts_high << 32) | blk.ts_low)
        return RawPacket(index, offset, ts_ns, blk.caplen, wirelen, iface.link_type, iface.interface_id, data)
