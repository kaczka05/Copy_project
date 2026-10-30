"""Capture-file framing: pcap/pcapng parsing, timestamps, lengths, structural errors."""
from __future__ import annotations

import gzip

import pytest
from conftest import CLASSIC, PCAPNG, classic_records, genuine, independent_packets

from netguard_ingest.capture.reader import CaptureReader
from netguard_ingest.errors import ErrorCode, InputFileError

SINGLE_IFACE_PCAPNG = [n for n in PCAPNG if n != "tfp_capture.pcapng"]


@pytest.mark.parametrize("name", CLASSIC)
def test_classic_pcap_matches_dpkt_reference(name):
    path = genuine(name)
    reference = independent_packets(path)
    with CaptureReader(path) as reader:
        packets = list(reader)
        assert reader.info.format == "pcap" and not reader.issues and not reader.ended_abnormally
    assert len(packets) == len(reference)
    for ours, (ts, buf) in zip(packets, reference):
        assert ours.data == buf
        assert ours.caplen == len(buf) and ours.wirelen >= ours.caplen
        assert abs(ours.ts_ns / 1e9 - float(ts)) < 1e-6          # timestamp extraction
    assert [p.index for p in packets] == list(range(1, len(packets) + 1))


@pytest.mark.parametrize("name", SINGLE_IFACE_PCAPNG)
def test_pcapng_matches_dpkt_reference(name):
    path = genuine(name)
    reference = independent_packets(path)
    with CaptureReader(path) as reader:
        packets = list(reader)
        assert reader.info.format == "pcapng" and not reader.issues
        assert reader.info.link_types == [1]
    assert [p.data for p in packets] == [buf for _, buf in reference]
    for ours, (ts, _) in zip(packets, reference):
        assert abs(ours.ts_ns / 1e9 - float(ts)) < 1e-6


def test_pcapng_multiple_interfaces_keep_their_own_link_type():
    with CaptureReader(genuine("tfp_capture.pcapng")) as reader:
        packets = list(reader)
        assert reader.info.link_types == [1, 220]
    assert len(packets) == 1648
    assert {p.link_type for p in packets} == {1, 220}
    assert all(p.link_type == reader.info.interfaces[p.interface_id].link_type for p in packets)


def test_timestamps_are_integer_nanoseconds_from_record_headers():
    path = genuine("dns.cap")
    offset, _, _ = classic_records(path)[0]
    raw = path.read_bytes()[offset:offset + 8]
    sec, usec = int.from_bytes(raw[:4], "little"), int.from_bytes(raw[4:8], "little")
    with CaptureReader(path) as reader:
        first = next(iter(reader))
    assert first.ts_ns == sec * 1_000_000_000 + usec * 1_000
    assert first.file_offset == 24


def test_truncated_inside_packet_data(tmp_path):
    path = genuine("dns.cap")
    records = classic_records(path)
    cut = records[10][0] + 16 + records[10][1] // 2          # half of packet 11's data
    trunc = tmp_path / "truncated.pcap"
    trunc.write_bytes(path.read_bytes()[:cut])
    with CaptureReader(trunc) as reader:
        packets = list(reader)
        assert len(packets) == 10 and reader.ended_abnormally and reader.packets_seen == 11
        assert [(i.code, i.packet_index, i.fatal) for i in reader.issues] == [(ErrorCode.TRUNCATED_CAPTURE, 11, True)]


def test_truncated_inside_record_header(tmp_path):
    path = genuine("dns.cap")
    records = classic_records(path)
    trunc = tmp_path / "truncated_hdr.pcap"
    trunc.write_bytes(path.read_bytes()[:records[5][0] + 7])
    with CaptureReader(trunc) as reader:
        assert len(list(reader)) == 5
        assert reader.issues[0].code is ErrorCode.TRUNCATED_CAPTURE


def test_corrupted_record_caplen_stops_framing(tmp_path):
    path = genuine("dns.cap")
    records = classic_records(path)
    data = bytearray(path.read_bytes())
    data[records[3][0] + 8: records[3][0] + 12] = (0x7FFFFFFF).to_bytes(4, "little")
    bad = tmp_path / "bad_caplen.pcap"
    bad.write_bytes(bytes(data))
    with CaptureReader(bad) as reader:
        assert len(list(reader)) == 3
        assert reader.issues[0].code is ErrorCode.CORRUPTED_RECORD and reader.issues[0].fatal


def test_pcapng_truncated_block(tmp_path):
    path = genuine("icmp_echo.pcapng")
    raw = path.read_bytes()
    trunc = tmp_path / "trunc.pcapng"
    trunc.write_bytes(raw[:-30])
    with CaptureReader(trunc) as reader:
        packets = list(reader)
        assert reader.ended_abnormally
        assert reader.issues[-1].code is ErrorCode.TRUNCATED_CAPTURE
    assert len(packets) < 8


def test_pcapng_trailer_length_mismatch(tmp_path):
    path = genuine("tcp_handshake.pcapng")
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 0xFF          # corrupt the trailing length of the last block
    bad = tmp_path / "bad_trailer.pcapng"
    bad.write_bytes(bytes(raw))
    with CaptureReader(bad) as reader:
        list(reader)
        assert reader.issues[-1].code is ErrorCode.CORRUPTED_RECORD


@pytest.mark.parametrize("content,code", [
    (b"this is a text file, not a capture\n", ErrorCode.UNSUPPORTED_FILE_FORMAT),
    (b"\xd4\xc3\xb2\xa1\x02\x00", ErrorCode.CORRUPTED_CAPTURE_HEADER),
    (b"\x34\xcd\xb2\xa1" + bytes(20), ErrorCode.UNSUPPORTED_FILE_FORMAT),
    (b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x00\x00\x00\x00", ErrorCode.CORRUPTED_CAPTURE_HEADER),
])
def test_file_level_rejections(tmp_path, content, code):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(content)
    with pytest.raises(InputFileError) as info:
        CaptureReader(bad)
    assert info.value.code is code


def test_gzip_capture_is_reported(tmp_path):
    gz = tmp_path / "dns.cap.gz"
    gz.write_bytes(gzip.compress(genuine("dns.cap").read_bytes()))
    with pytest.raises(InputFileError, match="gzip"):
        CaptureReader(gz)


def test_unsupported_pcap_version(tmp_path):
    raw = bytearray(genuine("dns.cap").read_bytes())
    raw[4:6] = (3).to_bytes(2, "little")
    bad = tmp_path / "v3.pcap"
    bad.write_bytes(bytes(raw))
    with pytest.raises(InputFileError) as info:
        CaptureReader(bad)
    assert info.value.code is ErrorCode.UNSUPPORTED_CAPTURE_VERSION
