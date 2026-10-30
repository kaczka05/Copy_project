"""Streaming readers for CSV and JSON-lines flow datasets.

Each item yielded is either a ``SourceRecord`` (a dict of raw values) or a
``RecordError`` describing a malformed line. Files are read incrementally.
"""
from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import ErrorCode, InputFileError


@dataclass(slots=True)
class SourceRecord:
    record_number: int     # 1-based data record ordinal
    line_number: int       # physical line where the record ends
    values: dict[str, Any]


@dataclass(slots=True)
class RecordError:
    record_number: int
    line_number: int
    code: ErrorCode
    message: str
    raw: str | None = None


def detect_dataset_format(path: Path, explicit: str | None) -> str:
    if explicit:
        return explicit
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix in (".jsonl", ".ndjson"):
        return "jsonl"
    raise InputFileError(ErrorCode.UNSUPPORTED_FILE_FORMAT,
                         f"cannot infer dataset format from extension {suffix!r}; use --format csv|jsonl")


class _LineDecoder:
    """Decode UTF-8 line by line so one bad line does not abort the file."""

    def __init__(self, handle) -> None:
        self._handle = handle
        self.line_number = 0
        self.bad_lines: list[tuple[int, str]] = []

    def __iter__(self) -> Iterator[str]:
        for raw in self._handle:
            self.line_number += 1
            try:
                text = raw.decode("utf-8-sig" if self.line_number == 1 else "utf-8")
            except UnicodeDecodeError as exc:
                self.bad_lines.append((self.line_number, f"invalid UTF-8: {exc}"))
                continue
            yield text


def iter_csv(path: Path) -> tuple[list[str], Iterator[SourceRecord | RecordError]]:
    handle = open(path, "rb")  # noqa: SIM115 - closed by generator
    lines = _LineDecoder(handle)
    reader = csv.reader(lines, strict=True)
    try:
        header = next(reader)
    except StopIteration:
        handle.close()
        raise InputFileError(ErrorCode.INVALID_DATASET_HEADER, "CSV dataset has no header row") from None
    except csv.Error as exc:
        handle.close()
        raise InputFileError(ErrorCode.INVALID_DATASET_HEADER, f"CSV header cannot be parsed: {exc}") from None
    header = [h.strip() for h in header]
    if len(set(header)) != len(header) or any(not h for h in header):
        handle.close()
        raise InputFileError(ErrorCode.INVALID_DATASET_HEADER, "CSV header has empty or duplicate column names")

    def flush_bad(state: list[int]) -> Iterator[RecordError]:
        while state[0] < len(lines.bad_lines):
            line_no, message = lines.bad_lines[state[0]]
            state[0] += 1
            yield RecordError(0, line_no, ErrorCode.INVALID_ENCODING, message)

    def generate() -> Iterator[SourceRecord | RecordError]:
        record_number = 0
        reported = [0]
        try:
            while True:
                syntax_error = None
                try:
                    row = next(reader)
                except StopIteration:
                    yield from flush_bad(reported)
                    break
                except csv.Error as exc:
                    row, syntax_error = None, exc
                yield from flush_bad(reported)
                if syntax_error is not None:
                    record_number += 1
                    yield RecordError(record_number, lines.line_number, ErrorCode.MALFORMED_RECORD,
                                      f"CSV syntax error: {syntax_error}")
                    continue
                if not row or all(not cell.strip() for cell in row):
                    continue  # blank line
                record_number += 1
                if len(row) != len(header):
                    yield RecordError(record_number, lines.line_number, ErrorCode.MALFORMED_RECORD,
                                      f"row has {len(row)} columns, header has {len(header)}",
                                      raw=",".join(row)[:512])
                    continue
                yield SourceRecord(record_number, lines.line_number, dict(zip(header, row)))
        finally:
            handle.close()

    return header, generate()


def iter_jsonl(path: Path) -> Iterator[SourceRecord | RecordError]:
    with open(path, "rb") as handle:
        lines = _LineDecoder(handle)
        record_number = 0
        reported_bad = 0
        for text in lines:
            while reported_bad < len(lines.bad_lines):
                line_no, message = lines.bad_lines[reported_bad]
                reported_bad += 1
                yield RecordError(0, line_no, ErrorCode.INVALID_ENCODING, message)
            if not text.strip():
                continue
            record_number += 1
            try:
                value = json.loads(text, parse_constant=_reject_constant)
            except ValueError as exc:
                yield RecordError(record_number, lines.line_number, ErrorCode.MALFORMED_RECORD,
                                  f"invalid JSON: {exc}", raw=text.strip()[:512])
                continue
            if not isinstance(value, dict):
                yield RecordError(record_number, lines.line_number, ErrorCode.MALFORMED_RECORD,
                                  "JSON line is not an object", raw=text.strip()[:512])
                continue
            yield SourceRecord(record_number, lines.line_number, value)
        while reported_bad < len(lines.bad_lines):
            line_no, message = lines.bad_lines[reported_bad]
            reported_bad += 1
            yield RecordError(0, line_no, ErrorCode.INVALID_ENCODING, message)


def _reject_constant(name: str):
    raise ValueError(f"non-standard JSON constant {name}")
