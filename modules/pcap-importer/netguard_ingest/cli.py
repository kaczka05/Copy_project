"""Command-line interface: ``netguard-ingest`` / ``python -m netguard_ingest``.

Sub-commands:
  pcap             import prepared PCAP/PCAPNG captures (files or directories)
  flows            import a prepared NetGuard-native (or mapped) flow dataset
  list             list previous ingestions recorded in the output directory
  validate-output  re-check a flows.jsonl file against FlowEvent v1

Exit codes: 0 success (incl. completed with rejections), 1 at least one
ingestion FAILED, 2 usage error, 3 rejections present with --fail-on-rejections.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import TOOL_NAME, __version__
from .config import (DEFAULT_ACTIVE_TIMEOUT_S, DEFAULT_IDLE_TIMEOUT_S, DEFAULT_MAX_ACTIVE_FLOWS,
                     DEFAULT_MAX_REJECT_DETAILS, IngestionConfig)
from .contract import ContractUnavailable, FlowEventContract
from .logging_setup import configure_logging
from .output import read_catalogue
from .pipeline import STATUS_FAILED, IngestionResult, ingest_flow_dataset, ingest_pcap

CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output-dir", type=Path, help="output root (default: $NETGUARD_INGEST_OUTPUT_DIR or "
                        "./ingestion-output)")
    parser.add_argument("--dataset-id", help="dataset identifier written to every flow (default: <stem>-<sha12>)")
    parser.add_argument("--emit-other-protocols", action="store_true", default=None,
                        help="emit flows for IP protocols other than TCP/UDP/ICMP/ICMPv6 as protocol OTHER "
                        "(default: reject and report them)")
    parser.add_argument("--no-contract-validation", action="store_true",
                        help="skip the JSON Schema check of each FlowEvent (cross-field validation still applies)")
    parser.add_argument("--contracts-dir", type=Path, help="directory containing flow-event.v1.schema.json")
    parser.add_argument("--max-reject-details", type=int,
                        help=f"max rejects written per ingestion (default {DEFAULT_MAX_REJECT_DETAILS}); all are counted")
    parser.add_argument("--fail-on-rejections", action="store_true", help="exit 3 when anything was rejected")
    parser.add_argument("--json", action="store_true", help="print the full report(s) as JSON on stdout")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=TOOL_NAME, description="NetGuard PCAP/flow ingestion and normalisation")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--log-format", default="text", choices=["text", "json"])
    sub = parser.add_subparsers(dest="command", required=True)

    pcap = sub.add_parser("pcap", help="import prepared PCAP/PCAPNG captures")
    pcap.add_argument("inputs", nargs="+", type=Path, help="capture files or directories (*.pcap, *.pcapng, *.cap)")
    pcap.add_argument("--idle-timeout", type=float, help=f"flow idle timeout in seconds (default {DEFAULT_IDLE_TIMEOUT_S})")
    pcap.add_argument("--active-timeout", type=float,
                      help=f"flow active timeout in seconds (default {DEFAULT_ACTIVE_TIMEOUT_S})")
    pcap.add_argument("--max-active-flows", type=int,
                      help=f"flow table limit (default {DEFAULT_MAX_ACTIVE_FLOWS})")
    pcap.add_argument("--scenario-label", help="ground-truth label documented for the WHOLE capture "
                      "(NORMAL, PORT_SCAN, DOS_LIKE, BRUTE_FORCE_LIKE, ABNORMAL_CONNECTION_PATTERN); default null")
    _common(pcap)

    flows = sub.add_parser("flows", help="import a prepared flow dataset (CSV / JSON-lines)")
    flows.add_argument("inputs", nargs="+", type=Path, help="dataset files (*.csv, *.jsonl, *.ndjson)")
    flows.add_argument("--format", choices=["csv", "jsonl"], help="override format detection by extension")
    flows.add_argument("--mapping", help="mapping profile: built-in name (netguard-native) or path to JSON")
    flows.add_argument("--assume-timezone", help="IANA timezone for timestamps WITHOUT offset (otherwise rejected)")
    _common(flows)

    lst = sub.add_parser("list", help="list ingestions recorded in an output directory")
    lst.add_argument("--output-dir", type=Path)
    lst.add_argument("--json", action="store_true")

    val = sub.add_parser("validate-output", help="check a flows.jsonl file against FlowEvent v1")
    val.add_argument("flows_file", type=Path)
    val.add_argument("--contracts-dir", type=Path)
    return parser


def _config_from_args(args: argparse.Namespace) -> IngestionConfig:
    config = IngestionConfig()
    if args.output_dir is not None:
        config.output_root = args.output_dir
    for attr, name in (("idle_timeout", "idle_timeout_s"), ("active_timeout", "active_timeout_s"),
                       ("max_active_flows", "max_active_flows"), ("max_reject_details", "max_reject_details"),
                       ("dataset_id", "dataset_id"), ("scenario_label", "scenario_label"),
                       ("format", "input_format"), ("mapping", "mapping_profile"),
                       ("assume_timezone", "assume_timezone"), ("contracts_dir", "contracts_dir")):
        value = getattr(args, attr, None)
        if value is not None:
            setattr(config, name, value)
    if args.emit_other_protocols:
        config.emit_other_protocols = True
    if args.no_contract_validation:
        config.validate_contract = False
    config.validate()
    return config


def _expand_captures(inputs: list[Path]) -> list[Path]:
    files: list[Path] = []
    for item in inputs:
        if item.is_dir():
            found = sorted(p for p in item.iterdir() if p.is_file() and p.suffix.lower() in CAPTURE_SUFFIXES)
            if not found:
                print(f"warning: no capture files (*.pcap, *.pcapng, *.cap) in {item}", file=sys.stderr)
            files.extend(found)
        else:
            files.append(item)
    return files


def _print_result(result: IngestionResult) -> None:
    report = result.report
    src = report["source"]
    print(f"[{result.status}] {src['original_filename']} -> {result.output_dir}")
    print(f"  {report['summary']}")
    if "packets" in report:
        p = report["packets"]
        print(f"  packets: examined={p['examined']} in_flows={p['attributed_to_flows']} rejected={p['rejected']}")
    if "records" in report:
        r = report["records"]
        print(f"  records: read={r['read']} accepted={r['accepted']} rejected={r['rejected']}")
    f = report["flows"]
    print(f"  flows: extracted={f['extracted']} normalized={f['normalized']} rejected={f['rejected']}")
    if report["rejections"]["by_code"]:
        print("  rejections: " + ", ".join(f"{k}={v}" for k, v in report["rejections"]["by_code"].items()))
    for warning in report["warnings"]:
        print(f"  warning: {warning}")
    if report["error"]:
        print(f"  error: {report['error']['code']}: {report['error']['message']}")


def _run_ingest(args: argparse.Namespace) -> int:
    try:
        config = _config_from_args(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    inputs = _expand_captures(args.inputs) if args.command == "pcap" else list(args.inputs)
    if not inputs:
        print("No input files given: no data has been imported.", file=sys.stderr)
        return 1
    ingest = ingest_pcap if args.command == "pcap" else ingest_flow_dataset
    results = []
    for path in inputs:
        try:
            results.append(ingest(path, config))
        except ContractUnavailable as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps([r.report for r in results], indent=2))
    else:
        for result in results:
            _print_result(result)
    if any(r.status == STATUS_FAILED for r in results):
        return 1
    if args.fail_on_rejections and any(r.report["rejections"]["total"] for r in results):
        return 3
    return 0


def _run_list(args: argparse.Namespace) -> int:
    root = args.output_dir or IngestionConfig().output_root
    entries = read_catalogue(root)
    if args.json:
        print(json.dumps(entries, indent=2))
        return 0
    if not entries:
        print(f"No data has been imported (no ingestions recorded in {root}).")
        return 0
    for e in entries:
        print(f"{e['started_at']}  {e['status']:<26} {e['source_type']:<12} flows={e['flows_normalized']:<7} "
              f"{e['original_filename']}  ({e['ingestion_id']})")
    return 0


def _run_validate(args: argparse.Namespace) -> int:
    try:
        contract = FlowEventContract(args.contracts_dir)
    except ContractUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    valid = invalid = 0
    with open(args.flows_file, encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                errors = contract.errors(json.loads(line))
            except ValueError as exc:
                errors = [f"invalid JSON: {exc}"]
            if errors:
                invalid += 1
                print(f"line {line_number}: INVALID: {'; '.join(errors)}")
            else:
                valid += 1
    print(f"{valid} valid, {invalid} invalid FlowEvent v1 records ({contract.schema_path})")
    return 0 if invalid == 0 else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level, args.log_format)
    if args.command in ("pcap", "flows"):
        return _run_ingest(args)
    if args.command == "list":
        return _run_list(args)
    return _run_validate(args)


if __name__ == "__main__":
    sys.exit(main())
