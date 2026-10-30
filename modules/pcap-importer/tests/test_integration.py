"""End-to-end ingestion: output contract, provenance, error reporting,
repeatability and CLI."""
from __future__ import annotations

import json
import sys

import pytest
from conftest import ALL, MODULE_ROOT, genuine, read_jsonl

from netguard_ingest.capture.decoder import PacketDecoder
from netguard_ingest.capture.reader import CaptureReader
from netguard_ingest.cli import main
from netguard_ingest.config import IngestionConfig
from netguard_ingest.pipeline import ingest_pcap

sys.path.insert(0, str(MODULE_ROOT.parents[1] / "examples" / "kafka"))
from common import validate as repo_contract_validate  # noqa: E402  existing repository contract helper


@pytest.mark.parametrize("name", ALL)
def test_every_genuine_capture_ingests_with_consistent_accounting(name, config):
    result = ingest_pcap(genuine(name), config)
    report, out = result.report, result.output_dir
    assert result.status in ("COMPLETED", "COMPLETED_WITH_REJECTIONS")
    packets = report["packets"]
    assert packets["examined"] == packets["attributed_to_flows"] + packets["rejected"]
    flows = read_jsonl(out / "flows.jsonl")
    provenance = read_jsonl(out / "provenance.jsonl")
    assert len(flows) == len(provenance) == report["flows"]["normalized"] == report["flows"]["extracted"]
    assert sum(f["packets"] for f in flows) == packets["attributed_to_flows"]
    assert len(read_jsonl(out / "rejects.jsonl")) == report["rejections"]["total"]
    for flow in flows:
        repo_contract_validate("flows.normalized", flow)          # existing repo FlowEvent v1 contract
        assert flow["source_type"] == "PCAP" and flow["scenario_label"] is None
        assert flow["start_time"].endswith("Z") and flow["trace_id"] == result.ingestion_id
    assert report["source"]["sha256"] and report["source"]["original_filename"] == name
    assert not list(config.output_root.glob(".*.partial"))


def test_provenance_traces_flow_to_its_first_packet(config):
    path = genuine("v6.pcap")
    result = ingest_pcap(path, config)
    with CaptureReader(path) as reader:
        by_index = {p.index: p for p in reader}
    decoder = PacketDecoder()
    flows = {f["flow_id"]: f for f in read_jsonl(result.output_dir / "flows.jsonl")}
    for prov in read_jsonl(result.output_dir / "provenance.jsonl"):
        flow = flows[prov["flow_id"]]
        packet = by_index[prov["first_packet_index"]]
        meta = decoder.decode(packet.link_type, packet.data, packet.wirelen)
        assert (meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port) == \
            (flow["src_ip"], flow["src_port"], flow["dst_ip"], flow["dst_port"])
        assert prov["first_packet_file_offset"] == packet.file_offset
        assert prov["source_sha256"] == result.report["source"]["sha256"]


def test_repeatable_processing(config):
    path = genuine("dns.cap")
    first, second = ingest_pcap(path, config), ingest_pcap(path, config)
    assert first.ingestion_id != second.ingestion_id

    def stable(result):
        return [{k: v for k, v in f.items() if k not in ("trace_id", "ingest_time")}
                for f in read_jsonl(result.output_dir / "flows.jsonl")]
    assert stable(first) == stable(second)


@pytest.mark.parametrize("setup,code", [
    (lambda p: None, "FILE_NOT_FOUND"),
    (lambda p: p.write_bytes(b""), "FILE_EMPTY"),
    (lambda p: p.write_text("ts,src,dst\n"), "UNSUPPORTED_FILE_FORMAT"),
])
def test_file_errors_produce_failed_report(tmp_path, config, setup, code):
    path = tmp_path / "input.pcap"
    setup(path)
    result = ingest_pcap(path, config)
    assert result.status == "FAILED" and result.report["error"]["code"] == code
    assert result.report["data_imported"] is False and "No data imported" in result.report["summary"]
    assert (result.output_dir / "report.json").is_file()


def test_operator_scenario_label(config):
    cfg = IngestionConfig(output_root=config.output_root, scenario_label="PORT_SCAN", dataset_id="pp-synscan")
    result = ingest_pcap(genuine("synscan.pcapng"), cfg)
    flows = read_jsonl(result.output_dir / "flows.jsonl")
    assert {f["scenario_label"] for f in flows} == {"PORT_SCAN"} and {f["dataset_id"] for f in flows} == {"pp-synscan"}
    assert {p["scenario_label_origin"] for p in read_jsonl(result.output_dir / "provenance.jsonl")} == {"operator"}
    bad = IngestionConfig(output_root=config.output_root, scenario_label="HACKED")
    assert ingest_pcap(genuine("synscan.pcapng"), bad).status == "FAILED"


def test_reject_detail_cap_still_counts_everything(config):
    cfg = IngestionConfig(output_root=config.output_root, max_reject_details=10)
    report = ingest_pcap(genuine("arp-storm.pcap"), cfg).report
    assert report["rejections"] == {"total": 622, "by_code": {"NON_IP_PACKET": 622},
                                    "by_category": {"UNSUPPORTED": 622}, "details_written": 10,
                                    "details_suppressed": 612}
    assert report["unsupported"]["network_types"] == {"0x0806": 622}
    assert report["data_imported"] is False


def test_mixed_link_types_reported(config):
    report = ingest_pcap(genuine("tfp_capture.pcapng"), config).report
    assert report["unsupported"]["link_types"] == {"220": 975}
    assert report["capture"]["link_types"] == [1, 220]
    assert any("unsupported link types" in w for w in report["warnings"])


def test_cli_end_to_end(tmp_path, capsys):
    out = tmp_path / "cli-out"
    assert main(["list", "--output-dir", str(out)]) == 0
    assert "No data has been imported" in capsys.readouterr().out
    assert main(["pcap", str(genuine("icmp_echo.pcapng")), "--output-dir", str(out), "--idle-timeout", "30"]) == 0
    assert "[COMPLETED] icmp_echo.pcapng" in capsys.readouterr().out
    assert main(["pcap", str(genuine("arp_resolution.pcapng")), "--output-dir", str(out),
                 "--fail-on-rejections"]) == 3
    assert main(["pcap", str(tmp_path / "missing.pcap"), "--output-dir", str(out)]) == 1
    capsys.readouterr()
    assert main(["list", "--output-dir", str(out), "--json"]) == 0
    entries = json.loads(capsys.readouterr().out)
    assert [e["status"] for e in entries] == ["COMPLETED", "COMPLETED_WITH_REJECTIONS", "FAILED"]
    flows_file = f"{entries[0]['output_dir']}/flows.jsonl"
    assert main(["validate-output", flows_file]) == 0
    report = json.loads(open(f"{entries[0]['output_dir']}/report.json").read())
    assert report["config"]["idle_timeout_s"] == 30.0
    assert main(["flows", flows_file, "--output-dir", str(out)]) == 0      # exported flows re-imported
    assert main(["pcap", str(genuine("dns.cap")), "--idle-timeout", "-1", "--output-dir", str(out)]) == 2
