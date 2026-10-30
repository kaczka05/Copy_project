"""Explicit schema mapping from a prepared dataset to the NetGuard flow model.

A *mapping profile* (JSON) names, for every NetGuard target field, the source
column and how to interpret it (timestamp format/timezone, duration unit,
value maps). Nothing is inferred implicitly: unknown columns are reported,
missing required columns fail the import, and naive timestamps are rejected
unless a timezone is explicitly configured.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..errors import ErrorCode, InputFileError, ValidationIssue
from ..model import Protocol
from ..normalize import (
    duration_ms_between,
    normalize_counter,
    normalize_duration_ms,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_scenario_label,
    normalize_tcp_flags,
    parse_timestamp,
)

PROFILES_DIR = Path(__file__).resolve().parent / "profiles"
BUILTIN_PROFILE = "netguard-native"

REQUIRED_TARGETS = ("start_time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "packets", "bytes")
OPTIONAL_TARGETS = ("duration_ms", "end_time", "tcp_flags", "scenario_label", "source_flow_id",
                    "original_source_type", "source_dataset_id", "simulation_run_id")
ALL_TARGETS = set(REQUIRED_TARGETS) | set(OPTIONAL_TARGETS)
FIELD_OPTIONS = {"source", "optional_column", "timestamp_format", "timezone", "duration_unit",
                 "tcp_flags_format", "value_map"}


@dataclass(slots=True)
class FieldSpec:
    target: str
    source: str
    optional_column: bool = False
    timestamp_format: str = "rfc3339"
    timezone: str | None = None
    duration_unit: str = "ms"
    tcp_flags_format: str = "int"
    value_map: dict[str, Any] | None = None


@dataclass(slots=True)
class ConvertedRecord:
    start_time: Any
    duration_ms: float
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: Protocol
    ip_proto: int | None
    packets: int
    bytes: int
    tcp_flags: int | None
    scenario_label: str | None
    source_flow_id: str | None
    original_source_type: str | None
    source_dataset_id: str | None


@dataclass(slots=True)
class MappingProfile:
    name: str
    version: int
    description: str
    formats: list[str]
    null_tokens: frozenset[str]
    fields: dict[str, FieldSpec]
    ignored_columns: frozenset[str] = field(default_factory=frozenset)
    source_path: str | None = None

    # ------------------------------------------------------------- loading
    @classmethod
    def load(cls, name_or_path: str | None) -> MappingProfile:
        """Load a built-in profile by name or a custom profile from a JSON file."""
        name_or_path = name_or_path or BUILTIN_PROFILE
        path = Path(name_or_path)
        if not path.suffix and (PROFILES_DIR / f"{name_or_path}.json").is_file():
            path = PROFILES_DIR / f"{name_or_path}.json"
        if not path.is_file():
            raise InputFileError(ErrorCode.INVALID_MAPPING_PROFILE,
                                 f"mapping profile {name_or_path!r} not found (built-in: {BUILTIN_PROFILE})")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise InputFileError(ErrorCode.INVALID_MAPPING_PROFILE, f"cannot read profile {path}: {exc}") from None
        return cls.from_dict(data, source_path=str(path))

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: str | None = None) -> MappingProfile:
        def bad(message: str) -> InputFileError:
            return InputFileError(ErrorCode.INVALID_MAPPING_PROFILE, f"invalid mapping profile: {message}")

        if not isinstance(data, dict) or not isinstance(data.get("fields"), dict):
            raise bad("'fields' object is required")
        specs: dict[str, FieldSpec] = {}
        for target, raw in data["fields"].items():
            if target not in ALL_TARGETS:
                raise bad(f"unknown target field {target!r}")
            if not isinstance(raw, dict) or not isinstance(raw.get("source"), str) or not raw["source"]:
                raise bad(f"field {target!r} needs a non-empty 'source' column name")
            unknown = set(raw) - FIELD_OPTIONS
            if unknown:
                raise bad(f"field {target!r} has unknown options {sorted(unknown)}")
            spec = FieldSpec(target=target, **raw)
            if target in REQUIRED_TARGETS and spec.optional_column:
                raise bad(f"required field {target!r} cannot be optional_column")
            if spec.duration_unit not in ("s", "ms", "us", "ns"):
                raise bad(f"field {target!r}: duration_unit must be s|ms|us|ns")
            if spec.tcp_flags_format not in ("int", "letters", "names"):
                raise bad(f"field {target!r}: tcp_flags_format must be int|letters|names")
            fmt = spec.timestamp_format
            if not (fmt in ("rfc3339", "epoch_s", "epoch_ms", "epoch_us", "epoch_ns") or fmt.startswith("strptime:")):
                raise bad(f"field {target!r}: unsupported timestamp_format {fmt!r}")
            if spec.value_map is not None and not isinstance(spec.value_map, dict):
                raise bad(f"field {target!r}: value_map must be an object")
            specs[target] = spec
        missing = [t for t in REQUIRED_TARGETS if t not in specs]
        if missing:
            raise bad(f"required target fields not mapped: {missing}")
        if "duration_ms" not in specs and "end_time" not in specs:
            raise bad("either 'duration_ms' or 'end_time' must be mapped")
        formats = data.get("formats", ["csv", "jsonl"])
        if not set(formats) <= {"csv", "jsonl"}:
            raise bad("formats must be a subset of ['csv', 'jsonl']")
        return cls(
            name=str(data.get("profile", "custom")), version=int(data.get("profile_version", 1)),
            description=str(data.get("description", "")), formats=list(formats),
            null_tokens=frozenset(data.get("null_tokens", [""])), fields=specs,
            ignored_columns=frozenset(data.get("ignored_columns", [])), source_path=source_path,
        )

    # ------------------------------------------------------------- columns
    @property
    def source_columns(self) -> set[str]:
        return {spec.source for spec in self.fields.values()}

    def required_columns(self) -> list[str]:
        return sorted({s.source for s in self.fields.values() if not s.optional_column})

    def unmapped(self, columns) -> list[str]:
        return sorted(set(columns) - self.source_columns - self.ignored_columns)

    # ---------------------------------------------------------- conversion
    def _get(self, record: dict[str, Any], target: str, *, csv: bool) -> tuple[bool, Any]:
        """Return (column_present, value-or-None) applying null tokens."""
        spec = self.fields.get(target)
        if spec is None:
            return False, None
        if spec.source not in record:
            if not spec.optional_column:
                raise ValidationIssue(ErrorCode.MISSING_REQUIRED_FIELD,
                                      f"required column/key {spec.source!r} ({target}) is absent", target)
            return False, None
        value = record[spec.source]
        if isinstance(value, str) and value.strip() in self.null_tokens:
            return True, None
        if spec.value_map is not None and value is not None and target not in ("scenario_label",):
            key = value if isinstance(value, str) else json.dumps(value)
            if key not in spec.value_map:
                code = {"protocol": ErrorCode.INVALID_PROTOCOL,
                        "original_source_type": ErrorCode.INVALID_SOURCE_TYPE}.get(target,
                                                                                   ErrorCode.MALFORMED_RECORD)
                raise ValidationIssue(code, f"{target} value {value!r} has no entry in value_map", target, value)
            value = spec.value_map[key]
        return True, value

    def convert(self, record: dict[str, Any], *, csv: bool, allow_other: bool,
                assume_timezone: str | None) -> ConvertedRecord:
        """Map + type-convert + normalise one source record (raises ValidationIssue)."""
        def value(target: str) -> Any:
            return self._get(record, target, csv=csv)[1]

        start_spec = self.fields["start_time"]
        start = parse_timestamp(value("start_time"), fmt=start_spec.timestamp_format,
                                assume_timezone=start_spec.timezone or assume_timezone, field="start_time")
        if "duration_ms" in self.fields:
            duration = normalize_duration_ms(value("duration_ms"), unit=self.fields["duration_ms"].duration_unit)
        else:
            end_spec = self.fields["end_time"]
            end = parse_timestamp(value("end_time"), fmt=end_spec.timestamp_format,
                                  assume_timezone=end_spec.timezone or assume_timezone, field="end_time")
            duration = duration_ms_between(start, end)
        protocol, ip_proto = normalize_protocol(value("protocol"), allow_other=allow_other)
        raw_label = value("scenario_label")
        label_map = self.fields["scenario_label"].value_map if "scenario_label" in self.fields else None
        flags_fmt = self.fields["tcp_flags"].tcp_flags_format if "tcp_flags" in self.fields else "int"
        source_flow_id = value("source_flow_id")
        original_type = value("original_source_type")
        source_dataset = value("source_dataset_id")
        simulation_run = value("simulation_run_id")
        if original_type is not None and original_type not in ("PCAP", "FLOW_DATASET", "SIMULATOR"):
            raise ValidationIssue(ErrorCode.INVALID_SOURCE_TYPE, f"source_type {original_type!r} is not recognised",
                                  "source_type", original_type)
        if original_type == "SIMULATOR" or simulation_run is not None:
            raise ValidationIssue(ErrorCode.SYNTHETIC_RECORD_REJECTED,
                                  "record originates from a traffic simulator; synthetic records are never mixed "
                                  "with imported prepared data", "source_type", original_type or simulation_run)
        return ConvertedRecord(
            start_time=start, duration_ms=duration,
            src_ip=normalize_ip(value("src_ip"), field="src_ip"),
            src_port=normalize_port(value("src_port"), field="src_port"),
            dst_ip=normalize_ip(value("dst_ip"), field="dst_ip"),
            dst_port=normalize_port(value("dst_port"), field="dst_port"),
            protocol=protocol, ip_proto=ip_proto,
            packets=normalize_counter(value("packets"), field="packets"),
            bytes=normalize_counter(value("bytes"), field="bytes"),
            tcp_flags=normalize_tcp_flags(value("tcp_flags"), protocol=protocol, fmt=flags_fmt),
            scenario_label=normalize_scenario_label(raw_label, value_map=label_map),
            source_flow_id=None if source_flow_id is None else str(source_flow_id),
            original_source_type=original_type,
            source_dataset_id=None if source_dataset is None else str(source_dataset),
        )

    def describe(self) -> dict[str, Any]:
        return {"profile": self.name, "profile_version": self.version, "source_path": self.source_path}
