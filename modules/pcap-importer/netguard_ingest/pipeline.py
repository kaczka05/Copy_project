"""Ingestion pipelines: PCAP/PCAPNG -> flows and prepared dataset -> flows.

Both pipelines share :class:`_IngestionRun`, which applies the *same*
cross-field validation, FlowEvent v1 serialisation, contract check,
rejection handling and metadata reporting to every flow.
"""
from __future__ import annotations

import json
import os
import platform
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from . import TOOL_NAME, __version__
from .capture.aggregator import EndReason, FlowAggregator, FlowState
from .capture.decoder import SUPPORTED_LINK_TYPES, PacketDecoder
from .capture.reader import CaptureReader
from .config import IngestionConfig
from .contract import FlowEventContract
from .datasets.mapping import MappingProfile
from .datasets.reader import RecordError, detect_dataset_format, iter_csv, iter_jsonl
from .errors import ErrorCode, InputFileError, PacketRejected, RejectRecord, ValidationIssue, category_of
from .ids import dataset_flow_id, default_dataset_id, event_id_for, file_sha256, new_ingestion_id, pcap_flow_id
from .logging_setup import get_logger
from .model import NormalizedFlow, Protocol, SourceType
from .normalize import UTC, format_timestamp, normalize_scenario_label, ns_to_datetime
from .output import IngestionOutput
from .validation import validate_flow

STATUS_COMPLETED = "COMPLETED"
STATUS_COMPLETED_WITH_REJECTIONS = "COMPLETED_WITH_REJECTIONS"
STATUS_FAILED = "FAILED"


@dataclass(slots=True)
class IngestionResult:
    ingestion_id: str
    status: str
    output_dir: Path
    report: dict[str, Any]


def _lib_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _json_safe(value: Any, limit: int = 2048) -> Any:
    text = json.dumps(value, ensure_ascii=False, default=str)
    return value if len(text) <= limit else text[:limit] + "...<truncated>"


class _IngestionRun:
    """State, statistics and output handling for one ingestion operation."""

    def __init__(self, path: str | Path, source_type: SourceType, config: IngestionConfig) -> None:
        config.validate()
        self.config = config
        self.path = Path(path)
        self.source_type = source_type
        self.ingestion_id = new_ingestion_id()
        self.log = get_logger(self.ingestion_id, str(self.path))
        self.started_at = datetime.now(UTC)
        self._t0 = time.perf_counter()
        self.sha256: str | None = None
        self.size: int | None = None
        self.dataset_id: str | None = None
        self.rejections: Counter[str] = Counter()
        self.flows_extracted = 0
        self.flows_normalized = 0
        self.flows_rejected = 0
        self.warnings: list[str] = []
        self.fatal: dict[str, Any] | None = None
        self.contract = FlowEventContract(config.contracts_dir) if config.validate_contract else None
        self.output = IngestionOutput(config.output_root, self.ingestion_id, config.max_reject_details)
        self.log.info("ingestion started source_type=%s file=%s", source_type.value, self.path)

    # ------------------------------------------------------------ helpers
    def check_file(self) -> None:
        """Existence, type, accessibility and size checks."""
        if not self.path.exists():
            raise InputFileError(ErrorCode.FILE_NOT_FOUND, f"input file does not exist: {self.path}")
        if not self.path.is_file():
            raise InputFileError(ErrorCode.FILE_NOT_READABLE, f"input is not a regular file: {self.path}")
        if not os.access(self.path, os.R_OK):
            raise InputFileError(ErrorCode.FILE_NOT_READABLE, f"input file is not readable: {self.path}")
        self.size = self.path.stat().st_size
        if self.size == 0:
            raise InputFileError(ErrorCode.FILE_EMPTY, "input file is empty")
        try:
            self.sha256 = file_sha256(self.path)
        except OSError as exc:
            raise InputFileError(ErrorCode.FILE_NOT_READABLE, f"cannot read input file: {exc}") from None
        self.dataset_id = self.config.dataset_id or default_dataset_id(self.path, self.sha256)

    def reject(self, record: RejectRecord) -> None:
        self.rejections[record.code.value] += 1
        self.output.write_reject(record.to_dict(self.ingestion_id, str(self.path)))

    def emit(self, flow: NormalizedFlow, provenance: dict[str, Any], location: dict[str, Any]) -> bool:
        """Validate, serialise, contract-check and write one flow."""
        try:
            validate_flow(flow)
        except ValidationIssue as issue:
            self.flows_rejected += 1
            self.reject(RejectRecord(issue.code, issue.message, location, issue.field, issue.value,
                                     details={"flow_id": flow.flow_id}))
            return False
        event = flow.to_flow_event(event_id=event_id_for(flow.flow_id), trace_id=self.ingestion_id,
                                   ingest_time=self.started_at)
        if self.contract is not None:
            errors = self.contract.errors(event)
            if errors:
                self.flows_rejected += 1
                self.reject(RejectRecord(ErrorCode.CONTRACT_VIOLATION, "FlowEvent v1 contract violated",
                                         location, details={"flow_id": flow.flow_id, "errors": errors}))
                return False
        self.output.write_flow(event, provenance)
        self.flows_normalized += 1
        return True

    def fail(self, error: InputFileError | Exception) -> None:
        if isinstance(error, InputFileError):
            self.fatal = {"code": error.code.value, "category": category_of(error.code).value,
                          "message": error.message}
            self.log.error("ingestion failed code=%s message=%s", error.code.value, error.message)
        else:
            self.fatal = {"code": "INTERNAL_ERROR", "category": "INTERNAL", "message": repr(error)}
            self.log.exception("ingestion failed with an unexpected error")

    def finish(self, source_details: dict[str, Any], sections: dict[str, Any]) -> IngestionResult:
        completed_at = datetime.now(UTC)
        total_rejections = sum(self.rejections.values())
        if self.fatal is not None:
            status = STATUS_FAILED
        elif total_rejections:
            status = STATUS_COMPLETED_WITH_REJECTIONS
        else:
            status = STATUS_COMPLETED
        by_category: Counter[str] = Counter()
        for code, count in self.rejections.items():
            by_category[category_of(ErrorCode(code)).value] += count
        report: dict[str, Any] = {
            "report_version": 1,
            "ingestion_id": self.ingestion_id,
            "status": status,
            "data_imported": self.flows_normalized > 0,
            "summary": self._summary(status),
            "tool": {"name": TOOL_NAME, "version": __version__, "python": platform.python_version(),
                     "dpkt": _lib_version("dpkt"), "jsonschema": _lib_version("jsonschema")},
            "source": {
                "source_type": self.source_type.value,
                "original_filename": self.path.name,
                "path": str(self.path.resolve()) if self.path.exists() else str(self.path),
                "size_bytes": self.size,
                "sha256": self.sha256,
                "dataset_id": self.dataset_id,
                **source_details,
            },
            "config": self.config.as_report_dict(),
            "started_at": format_timestamp(self.started_at),
            "completed_at": format_timestamp(completed_at),
            "processing_duration_ms": round((time.perf_counter() - self._t0) * 1000, 3),
            **sections,
            "flows": {
                "extracted": self.flows_extracted,
                "normalized": self.flows_normalized,
                "rejected": self.flows_rejected,
                **sections.get("flows", {}),
            },
            "rejections": {
                "total": total_rejections,
                "by_code": dict(sorted(self.rejections.items())),
                "by_category": dict(sorted(by_category.items())),
                "details_written": self.output.rejects_written,
                "details_suppressed": self.output.rejects_suppressed,
            },
            "error": self.fatal,
            "warnings": self.warnings,
            "contract": {"validated": self.contract is not None,
                         "schema": str(self.contract.schema_path) if self.contract else None},
            "outputs": {"flows": "flows.jsonl", "provenance": "provenance.jsonl", "rejects": "rejects.jsonl",
                        "report": "report.json"},
        }
        output_dir = self.output.finalize(report)
        self.log.info("ingestion finished status=%s flows=%d rejections=%d output=%s", status,
                      self.flows_normalized, total_rejections, output_dir)
        return IngestionResult(self.ingestion_id, status, output_dir, report)

    def _summary(self, status: str) -> str:
        if status == STATUS_FAILED:
            return f"Ingestion failed: {self.fatal['message'] if self.fatal else 'unknown error'}. No data imported."
        if self.flows_normalized == 0:
            return "No flows were imported: the input contained no packets/records convertible to flows."
        return f"{self.flows_normalized} normalised flows imported."


# =============================================================== PCAP pipeline
def ingest_pcap(path: str | Path, config: IngestionConfig) -> IngestionResult:
    """Import one prepared PCAP/PCAPNG capture."""
    run = _IngestionRun(path, SourceType.PCAP, config)
    capture_info: dict[str, Any] = {}
    packets = Counter()
    unsupported = {"link_types": Counter(), "network_types": Counter(), "ip_protocols": Counter()}
    agg: FlowAggregator | None = None
    capture: dict[str, Any] = {}
    try:
        if config.scenario_label is not None:
            normalize_scenario_label(config.scenario_label)
        run.check_file()
        sha = run.sha256
        label = config.scenario_label
        with CaptureReader(run.path) as reader:
            capture_info = reader.info.to_dict()
            run.warnings.extend(reader.info.warnings)
            bad_links = [lt for lt in reader.info.link_types if lt not in SUPPORTED_LINK_TYPES]
            if reader.info.format == "pcap" and bad_links:
                raise InputFileError(ErrorCode.UNSUPPORTED_LINK_TYPE,
                                     f"capture link type {bad_links[0]} is not supported "
                                     f"(supported: {sorted(set(SUPPORTED_LINK_TYPES))})")
            decoder = PacketDecoder(config.emit_other_protocols)
            agg = FlowAggregator(idle_timeout_s=config.idle_timeout_s, active_timeout_s=config.active_timeout_s,
                                 max_active_flows=config.max_active_flows, sweep_interval_s=config.sweep_interval_s,
                                 flow_id_factory=lambda key, pkt: pcap_flow_id(sha, pkt.index, key))
            first_ns: int | None = None
            last_ns: int | None = None

            def emit_states(states: list[FlowState], abnormal_end: bool = False) -> None:
                for state in states:
                    run.flows_extracted += 1
                    _emit_pcap_flow(run, state, label, abnormal_end, config)

            for packet in reader:
                first_ns = packet.ts_ns if first_ns is None else min(first_ns, packet.ts_ns)
                last_ns = packet.ts_ns if last_ns is None else max(last_ns, packet.ts_ns)
                if packet.caplen < packet.wirelen:
                    packets["snaplen_truncated"] += 1
                try:
                    meta = decoder.decode(packet.link_type, packet.data, packet.wirelen)
                except PacketRejected as rejected:
                    packets["rejected"] += 1
                    details = dict(rejected.details)
                    if "link_type" in details:
                        unsupported["link_types"][str(details["link_type"])] += 1
                    if "network_type" in details:
                        unsupported["network_types"][details["network_type"]] += 1
                    if rejected.code is ErrorCode.UNSUPPORTED_IP_PROTOCOL and "ip_proto" in details:
                        unsupported["ip_protocols"][str(details["ip_proto"])] += 1
                    run.reject(RejectRecord(rejected.code, rejected.message, _packet_location(packet),
                                            details=details or {}))
                    continue
                packets["attributed_to_flows"] += 1
                emit_states(agg.add(meta, packet))

            for issue in reader.issues:
                if issue.packet_index is not None:
                    packets["rejected"] += 1
                run.reject(RejectRecord(issue.code, issue.message,
                                        {"packet_index": issue.packet_index, "file_offset": issue.file_offset},
                                        details={"framing_lost": issue.fatal}))
                if issue.fatal:
                    run.warnings.append(
                        f"capture incomplete ({issue.code.value} at byte {issue.file_offset}); "
                        f"flows describe only the {reader.packets_seen - 1 if issue.packet_index else reader.packets_seen}"
                        " packets read before that point")
            emit_states(agg.flush(), abnormal_end=reader.ended_abnormally)
            packets["examined"] = reader.packets_seen
            capture_info = reader.info.to_dict()  # pcapng interfaces are known only after reading
            unsupported_ifaces = [i["link_type"] for i in capture_info["interfaces"]
                                  if i["link_type"] not in SUPPORTED_LINK_TYPES]
            if unsupported_ifaces:
                run.warnings.append(f"interfaces with unsupported link types {sorted(set(unsupported_ifaces))}: "
                                    "their packets were rejected (UNSUPPORTED_LINK_TYPE)")
            capture = {
                "complete": not reader.ended_abnormally,
                "first_packet_time": format_timestamp(ns_to_datetime(first_ns)) if first_ns is not None else None,
                "last_packet_time": format_timestamp(ns_to_datetime(last_ns)) if last_ns is not None else None,
            }
    except InputFileError as error:
        run.fail(error)
    except ValidationIssue as issue:
        run.fail(InputFileError(ErrorCode.INVALID_SCENARIO_LABEL, issue.message))
    except Exception as error:  # noqa: BLE001 - always produce a report
        run.fail(error)

    sections = {
        "capture": {**capture_info, **capture},
        "packets": {
            "examined": packets["examined"],
            "attributed_to_flows": packets["attributed_to_flows"],
            "rejected": packets["rejected"],
            "snaplen_truncated": packets["snaplen_truncated"],
            "out_of_order": agg.out_of_order_packets if agg else 0,
        },
        "unsupported": {k: dict(sorted(v.items())) for k, v in unsupported.items()},
        "flow_table": {
            "idle_timeout_s": config.idle_timeout_s,
            "active_timeout_s": config.active_timeout_s,
            "max_active_flows": config.max_active_flows,
            "peak_active_flows": agg.peak_active_flows if agg else 0,
            "closed_by_reason": agg.closed_by_reason if agg else {},
        },
    }
    return run.finish({"format": capture_info.get("format")}, sections)


def _packet_location(packet) -> dict[str, Any]:
    return {"packet_index": packet.index, "file_offset": packet.file_offset,
            "timestamp": format_timestamp(ns_to_datetime(packet.ts_ns)), "interface_id": packet.interface_id,
            "caplen": packet.caplen, "wirelen": packet.wirelen}


def _emit_pcap_flow(run: _IngestionRun, state: FlowState, label: str | None, abnormal_end: bool,
                    config: IngestionConfig) -> None:
    src_ip, src_port, dst_ip, dst_port, ip_proto = state.key
    first_us, last_us = state.first_ns // 1000, state.last_ns // 1000
    flow = NormalizedFlow(
        flow_id=state.flow_id, start_time=ns_to_datetime(state.first_ns), duration_ms=(last_us - first_us) / 1000,
        src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, protocol=state.protocol,
        packets=state.packets, bytes=state.bytes,
        tcp_flags=state.tcp_flags if state.protocol is Protocol.TCP else None,
        source_type=SourceType.PCAP, scenario_label=label, dataset_id=run.dataset_id,
    )
    reasons = []
    if state.end_reason is EndReason.END_OF_CAPTURE:
        reasons.append("OPEN_AT_CAPTURE_END")
        if abnormal_end:
            reasons.append("CAPTURE_TRUNCATED_OR_CORRUPTED")
    if state.end_reason is EndReason.ACTIVE_TIMEOUT:
        reasons.append("SPLIT_BY_ACTIVE_TIMEOUT")
    if state.end_reason is EndReason.FLOW_TABLE_LIMIT:
        reasons.append("EVICTED_FLOW_TABLE_LIMIT")
    if state.previous_flow_id:
        reasons.append("CONTINUATION_AFTER_ACTIVE_TIMEOUT")
    if state.protocol is Protocol.TCP and state.first_tcp_flags is not None and not state.first_tcp_flags & 0x02:
        reasons.append("TCP_START_NOT_OBSERVED")
    if state.snaplen_truncated_packets:
        reasons.append("SNAPLEN_TRUNCATED_PACKETS")
    provenance = {
        "flow_id": state.flow_id,
        "ingestion_id": run.ingestion_id,
        "source_type": SourceType.PCAP.value,
        "source_file": run.path.name,
        "source_sha256": run.sha256,
        "ip_version": state.ip_version,
        "ip_protocol_number": ip_proto,
        "first_packet_index": state.first_packet_index,
        "last_packet_index": state.last_packet_index,
        "first_packet_file_offset": state.first_packet_offset,
        "first_packet_tcp_flags": state.first_tcp_flags,
        "end_reason": state.end_reason.value if state.end_reason else None,
        "previous_flow_id": state.previous_flow_id,
        "snaplen_truncated_packets": state.snaplen_truncated_packets,
        "out_of_order_packets": state.out_of_order_packets,
        "observed_portion_only": bool(reasons),
        "incomplete_reasons": reasons,
        "scenario_label_origin": "operator" if label else None,
        "timeouts_s": {"idle": config.idle_timeout_s, "active": config.active_timeout_s},
    }
    location = {"flow_id": state.flow_id, "first_packet_index": state.first_packet_index,
                "last_packet_index": state.last_packet_index}
    run.emit(flow, provenance, location)


# ============================================================ dataset pipeline
def ingest_flow_dataset(path: str | Path, config: IngestionConfig) -> IngestionResult:
    """Import one prepared flow dataset (CSV or JSON-lines) via a mapping profile."""
    run = _IngestionRun(path, SourceType.FLOW_DATASET, config)
    records = Counter()
    unmapped: Counter[str] = Counter()
    details: dict[str, Any] = {}
    try:
        if config.scenario_label is not None:
            raise InputFileError(ErrorCode.INVALID_SCENARIO_LABEL,
                                 "scenario labels of flow datasets come from the dataset itself; "
                                 "an operator label is only accepted for PCAP captures")
        profile = MappingProfile.load(config.mapping_profile)
        details["mapping_profile"] = profile.describe()
        run.check_file()
        fmt = detect_dataset_format(run.path, config.input_format)
        details["format"] = fmt
        if fmt not in profile.formats:
            raise InputFileError(ErrorCode.UNSUPPORTED_FILE_FORMAT,
                                 f"profile {profile.name!r} does not support format {fmt!r}")
        if fmt == "csv":
            header, items = iter_csv(run.path)
            missing = [c for c in profile.required_columns() if c not in header]
            if missing:
                items.close()
                raise InputFileError(ErrorCode.INVALID_DATASET_HEADER,
                                     f"dataset header lacks required columns {missing}")
            details["columns"] = header
            for column in profile.unmapped(header):
                unmapped[column] += 1
        else:
            items = iter_jsonl(run.path)
        seen_source_ids: set[str] = set()
        sha = run.sha256
        for item in items:
            if isinstance(item, RecordError):
                if item.record_number:
                    records["read"] += 1
                records["rejected"] += 1
                run.reject(RejectRecord(item.code, item.message,
                                        {"record_number": item.record_number or None, "line_number": item.line_number},
                                        raw=item.raw))
                continue
            records["read"] += 1
            location = {"record_number": item.record_number, "line_number": item.line_number}
            if fmt == "jsonl":
                for key in profile.unmapped(item.values):
                    unmapped[key] += 1
            try:
                conv = profile.convert(item.values, csv=fmt == "csv", allow_other=config.emit_other_protocols,
                                       assume_timezone=config.assume_timezone)
                if conv.source_flow_id is not None:
                    if conv.source_flow_id in seen_source_ids:
                        raise ValidationIssue(ErrorCode.DUPLICATE_RECORD,
                                              f"flow_id {conv.source_flow_id!r} already imported from this dataset",
                                              "flow_id", conv.source_flow_id)
                    seen_source_ids.add(conv.source_flow_id)
            except ValidationIssue as issue:
                records["rejected"] += 1
                run.reject(RejectRecord(issue.code, issue.message, location, issue.field, issue.value,
                                        raw=_json_safe(item.values)))
                continue
            flow_id = dataset_flow_id(sha, item.record_number)
            flow = NormalizedFlow(
                flow_id=flow_id, start_time=conv.start_time, duration_ms=conv.duration_ms,
                src_ip=conv.src_ip, src_port=conv.src_port, dst_ip=conv.dst_ip, dst_port=conv.dst_port,
                protocol=conv.protocol, packets=conv.packets, bytes=conv.bytes, tcp_flags=conv.tcp_flags,
                source_type=SourceType.FLOW_DATASET, scenario_label=conv.scenario_label, dataset_id=run.dataset_id,
            )
            run.flows_extracted += 1
            provenance = {
                "flow_id": flow_id,
                "ingestion_id": run.ingestion_id,
                "source_type": SourceType.FLOW_DATASET.value,
                "source_file": run.path.name,
                "source_sha256": sha,
                "record_number": item.record_number,
                "line_number": item.line_number,
                "source_flow_id": conv.source_flow_id,
                "original_source_type": conv.original_source_type,
                "source_dataset_id": conv.source_dataset_id,
                "ip_protocol_number": conv.ip_proto,
                "mapping_profile": profile.name,
                "mapping_profile_version": profile.version,
                "scenario_label_origin": "dataset" if conv.scenario_label else None,
            }
            if not run.emit(flow, provenance, {**location, "flow_id": flow_id}):
                records["rejected"] += 1
        if unmapped:
            run.warnings.append(f"columns/keys not mapped to the flow model (not imported): {sorted(unmapped)}")
    except InputFileError as error:
        run.fail(error)
    except Exception as error:  # noqa: BLE001 - always produce a report
        run.fail(error)

    sections = {
        "records": {"read": records["read"], "accepted": run.flows_normalized, "rejected": records["rejected"]},
        "dataset": {**details, "unmapped_columns": dict(sorted(unmapped.items()))},
    }
    return run.finish({"format": details.get("format")}, sections)
