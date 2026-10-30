"""Prepared flow-dataset import. Every dataset used here is DERIVED from the
flows extracted from genuine captures (exported to NetGuard-native CSV /
JSON-lines, or renamed for a custom mapping). Invalid records are mutations
of those genuine rows. No flow record is invented."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone

import pytest
from conftest import genuine, read_jsonl

from netguard_ingest.config import IngestionConfig
from netguard_ingest.pipeline import ingest_flow_dataset, ingest_pcap

MODEL = ["flow_id", "start_time", "duration_ms", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
         "packets", "bytes", "tcp_flags", "source_type", "scenario_label"]
COMPARED = ["start_time", "duration_ms", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "packets",
            "bytes", "tcp_flags", "scenario_label"]


@pytest.fixture(scope="module")
def genuine_events(tmp_path_factory):
    out = tmp_path_factory.mktemp("pcap-out")
    events = []
    for name in ("v6.pcap", "dns.cap", "icmp_echo.pcapng", "tcp-ecn-sample.pcap", "tcp_handshake.pcapng"):
        result = ingest_pcap(genuine(name), IngestionConfig(output_root=out))
        events.extend(read_jsonl(result.output_dir / "flows.jsonl"))
    assert len(events) > 80
    return events


def write_csv(path, rows, columns=MODEL):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        for row in rows:
            writer.writerow(["" if row.get(c) is None else row.get(c) for c in columns])
    return path


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def imported(result):
    return read_jsonl(result.output_dir / "flows.jsonl")


def rejects(result):
    return read_jsonl(result.output_dir / "rejects.jsonl")


def test_native_jsonl_round_trip(tmp_path, config, genuine_events):
    result = ingest_flow_dataset(write_jsonl(tmp_path / "export.jsonl", genuine_events), config)
    assert result.status == "COMPLETED" and result.report["warnings"] == []
    flows = imported(result)
    assert len(flows) == len(genuine_events)
    for original, new in zip(genuine_events, flows):
        assert {k: new[k] for k in COMPARED} == {k: original[k] for k in COMPARED}
        assert new["source_type"] == "FLOW_DATASET" and new["flow_id"] != original["flow_id"]
    provenance = read_jsonl(result.output_dir / "provenance.jsonl")
    assert [p["source_flow_id"] for p in provenance] == [e["flow_id"] for e in genuine_events]
    assert {p["original_source_type"] for p in provenance} == {"PCAP"}
    assert [p["record_number"] for p in provenance] == list(range(1, len(flows) + 1))


def test_native_csv_missing_versus_zero(tmp_path, config, genuine_events):
    result = ingest_flow_dataset(write_csv(tmp_path / "export.csv", genuine_events), config)
    assert result.status == "COMPLETED"
    flows = imported(result)
    for original, new in zip(genuine_events, flows):
        assert {k: new[k] for k in COMPARED} == {k: original[k] for k in COMPARED}
    assert any(f["protocol"] == "ICMP" and f["src_port"] is None and f["tcp_flags"] is None for f in flows)
    assert any(f["duration_ms"] == 0.0 for f in flows)          # genuine zero kept as zero, not missing
    assert all(f["tcp_flags"] is None for f in flows if f["protocol"] != "TCP")


def test_timestamp_offsets_normalised_and_naive_rejected(tmp_path, config, genuine_events):
    rows = [dict(e) for e in genuine_events[:3]]
    utc = datetime.fromisoformat(rows[0]["start_time"].replace("Z", "+00:00"))
    rows[0]["start_time"] = utc.astimezone(timezone(timedelta(hours=-3, minutes=-30))).isoformat()
    rows[1]["start_time"] = rows[1]["start_time"].rstrip("Z")       # naive
    result = ingest_flow_dataset(write_csv(tmp_path / "tz.csv", rows), config)
    flows = imported(result)
    assert flows[0]["start_time"] == genuine_events[0]["start_time"]
    assert [r["code"] for r in rejects(result)] == ["INVALID_TIMESTAMP"]
    assert rejects(result)[0]["location"]["record_number"] == 2
    config2 = IngestionConfig(output_root=config.output_root, assume_timezone="UTC")
    assert ingest_flow_dataset(tmp_path / "tz.csv", config2).status == "COMPLETED"


def test_custom_mapping_profile(tmp_path, config, genuine_events):
    """Schema mapping: genuine flows re-expressed with other column names/units/encodings."""
    letters = "FSRPAUEC"
    rows = []
    for e in genuine_events:
        start = datetime.fromisoformat(e["start_time"].replace("Z", "+00:00"))
        flags = e["tcp_flags"]
        rows.append({
            "StartTime": f"{start.timestamp():.6f}", "Dur": f"{e['duration_ms'] / 1000:.6f}",
            "SrcAddr": e["src_ip"].upper(), "Sport": e["src_port"], "DstAddr": e["dst_ip"], "Dport": e["dst_port"],
            "Proto": {"TCP": "6", "UDP": "17", "ICMP": "1", "ICMPV6": "58"}[e["protocol"]],
            "TotPkts": e["packets"], "TotBytes": e["bytes"],
            "State": None if flags is None else "".join(c for i, c in enumerate(letters) if flags >> i & 1),
            "Label": "-",
        })
    profile = {
        "profile": "test-argus-like", "profile_version": 1, "null_tokens": ["", "-"],
        "fields": {
            "start_time": {"source": "StartTime", "timestamp_format": "epoch_s"},
            "duration_ms": {"source": "Dur", "duration_unit": "s"},
            "src_ip": {"source": "SrcAddr"}, "src_port": {"source": "Sport"},
            "dst_ip": {"source": "DstAddr"}, "dst_port": {"source": "Dport"},
            "protocol": {"source": "Proto"}, "packets": {"source": "TotPkts"}, "bytes": {"source": "TotBytes"},
            "tcp_flags": {"source": "State", "tcp_flags_format": "letters"},
            "scenario_label": {"source": "Label", "value_map": {"background": "NORMAL"}},
        },
    }
    (tmp_path / "profile.json").write_text(json.dumps(profile))
    columns = list(rows[0])
    write_csv(tmp_path / "argus.csv", rows, columns)
    cfg = IngestionConfig(output_root=config.output_root, mapping_profile=str(tmp_path / "profile.json"))
    result = ingest_flow_dataset(tmp_path / "argus.csv", cfg)
    assert result.status == "COMPLETED", result.report
    for original, new in zip(genuine_events, imported(result)):
        assert {k: new[k] for k in COMPARED} == {k: original[k] for k in COMPARED}
    assert result.report["dataset"]["mapping_profile"]["profile"] == "test-argus-like"


def test_missing_required_column_fails_import(tmp_path, config, genuine_events):
    columns = [c for c in MODEL if c != "packets"]
    result = ingest_flow_dataset(write_csv(tmp_path / "nopackets.csv", genuine_events[:3], columns), config)
    assert result.status == "FAILED" and result.report["error"]["code"] == "INVALID_DATASET_HEADER"
    assert imported(result) == [] and result.report["data_imported"] is False


def test_invalid_records_rejected_and_valid_ones_kept(tmp_path, config, genuine_events):
    base = [dict(e) for e in genuine_events[:20]]
    tcp = next(i for i, r in enumerate(base) if r["protocol"] == "TCP")
    udp = next(i for i, r in enumerate(base) if r["protocol"] == "UDP")
    mutations = {
        0: ("src_ip", "10.0.0.999", "INVALID_IP_ADDRESS"),
        1: ("dst_port", 70000, "INVALID_PORT"),
        2: ("packets", -1, "INVALID_COUNTER"),
        3: ("bytes", "lots", "INVALID_COUNTER"),
        4: ("protocol", "XYZ", "INVALID_PROTOCOL"),
        5: ("protocol", "47", "UNSUPPORTED_PROTOCOL"),
        6: ("duration_ms", -5, "INVALID_DURATION"),
        7: ("start_time", "not-a-time", "INVALID_TIMESTAMP"),
        8: ("scenario_label", "ATTACK", "INVALID_SCENARIO_LABEL"),
        9: ("source_type", "SIMULATOR", "SYNTHETIC_RECORD_REJECTED"),
        10: ("src_ip", None, "MISSING_REQUIRED_FIELD"),
        udp: ("tcp_flags", 2, "INVALID_TCP_FLAGS"),
    }
    expected = {}
    for index, (field, value, code) in mutations.items():
        base[index][field] = value
        expected[index + 1] = code
    base.append(dict(base[tcp], start_time=base[tcp]["start_time"]) if tcp not in mutations else dict(base[-1]))
    expected[len(base)] = "DUPLICATE_RECORD"                          # repeated flow_id
    result = ingest_flow_dataset(write_jsonl(tmp_path / "mixed.jsonl", base), config)
    got = {r["location"]["record_number"]: r["code"] for r in rejects(result)}
    assert got == expected
    assert result.status == "COMPLETED_WITH_REJECTIONS"
    assert len(imported(result)) == len(base) - len(expected)
    assert result.report["records"] == {"read": len(base), "accepted": len(base) - len(expected),
                                        "rejected": len(expected)}
    assert all(r["raw"] for r in rejects(result))                     # quarantined with the raw record


def test_malformed_lines(tmp_path, config, genuine_events):
    good = [json.dumps(e) for e in genuine_events[:3]]
    raw = (good[0] + "\n{not json\n" + good[1] + "\n[1,2]\n").encode() + b"\xff\xfe broken\n" + good[2].encode()
    (tmp_path / "lines.jsonl").write_bytes(raw)
    result = ingest_flow_dataset(tmp_path / "lines.jsonl", config)
    assert sorted(r["code"] for r in rejects(result)) == ["INVALID_ENCODING", "MALFORMED_RECORD", "MALFORMED_RECORD"]
    assert len(imported(result)) == 3


def test_csv_wrong_column_count(tmp_path, config, genuine_events):
    path = write_csv(tmp_path / "cols.csv", genuine_events[:3])
    lines = path.read_text().splitlines()
    lines[2] += ",extra"
    path.write_text("\n".join(lines) + "\n")
    result = ingest_flow_dataset(path, config)
    assert [r["code"] for r in rejects(result)] == ["MALFORMED_RECORD"] and len(imported(result)) == 2


def test_unmapped_columns_are_reported(tmp_path, config, genuine_events):
    rows = [dict(e, vendor_field="x") for e in genuine_events[:2]]
    result = ingest_flow_dataset(write_csv(tmp_path / "extra.csv", rows, MODEL + ["vendor_field"]), config)
    assert result.report["dataset"]["unmapped_columns"] == {"vendor_field": 1}
    assert any("vendor_field" in w for w in result.report["warnings"])


def test_unknown_profile_and_format(tmp_path, config, genuine_events):
    cfg = IngestionConfig(output_root=config.output_root, mapping_profile="does-not-exist")
    path = write_jsonl(tmp_path / "x.jsonl", genuine_events[:1])
    assert ingest_flow_dataset(path, cfg).report["error"]["code"] == "INVALID_MAPPING_PROFILE"
    other = tmp_path / "x.parquet"
    other.write_bytes(b"PAR1")
    assert ingest_flow_dataset(other, config).report["error"]["code"] == "UNSUPPORTED_FILE_FORMAT"


def test_operator_label_not_allowed_for_datasets(tmp_path, config, genuine_events):
    cfg = IngestionConfig(output_root=config.output_root, scenario_label="NORMAL")
    result = ingest_flow_dataset(write_jsonl(tmp_path / "x.jsonl", genuine_events[:1]), cfg)
    assert result.status == "FAILED"
