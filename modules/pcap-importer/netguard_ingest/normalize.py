"""Value normalisation rules shared by every input source.

Each function either returns the normalised value or raises
:class:`~netguard_ingest.errors.ValidationIssue`. Invalid values are never
replaced by defaults. ``None`` always means *missing / unavailable* and is
kept distinct from a genuine zero.
"""
from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import ErrorCode, ValidationIssue
from .model import IP_PROTO_TO_PROTOCOL, SCENARIO_LABELS, Protocol


UTC = timezone.utc  # noqa: UP017 - keep Python 3.10 compatibility
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_INT_RE = re.compile(r"^[+]?\d+$")
_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
_DECIMAL_RE = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")

# TCP flag letters (tcpdump/Argus style) -> bit
TCP_FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}
TCP_FLAG_NAMES = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "PUSH": 0x08, "ACK": 0x10,
                  "URG": 0x20, "ECE": 0x40, "CWR": 0x80}


# --------------------------------------------------------------------------- time
def format_timestamp(dt: datetime) -> str:
    """RFC 3339 UTC with fixed microsecond precision, e.g. 2004-05-13T10:17:07.311224Z."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime cannot be formatted as a normalised timestamp")
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ns_to_datetime(ts_ns: int) -> datetime:
    """Capture timestamp (integer ns since the Unix epoch, UTC) -> aware UTC
    datetime truncated to microsecond precision."""
    return _EPOCH + timedelta(microseconds=ts_ns // 1000)


def parse_timestamp(value: Any, *, fmt: str = "rfc3339", assume_timezone: str | None = None,
                    field: str = "start_time") -> datetime:
    """Parse a timestamp according to an explicitly declared format.

    ``fmt``: ``rfc3339`` (ISO 8601 date-time), ``epoch_s``, ``epoch_ms``,
    ``epoch_us``, ``epoch_ns`` or ``strptime:<pattern>``.
    Timestamps without timezone information are rejected unless
    ``assume_timezone`` explicitly names the zone (never silently assumed).
    """
    if value is None:
        raise ValidationIssue(ErrorCode.MISSING_REQUIRED_FIELD, f"{field} is missing", field)
    if isinstance(value, bool):
        raise ValidationIssue(ErrorCode.INVALID_TIMESTAMP, f"{field} must not be a boolean", field, value)
    try:
        if fmt.startswith("epoch_"):
            dt = _parse_epoch(value, fmt)
        elif fmt == "rfc3339":
            if not isinstance(value, str):
                raise ValueError("RFC 3339 timestamp must be a string")
            text = value.strip()
            if not re.match(r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?", text):
                raise ValueError("not an ISO 8601 / RFC 3339 date-time")
            text = _trim_fraction(text)
            if text[-1:] in ("z", "Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
        elif fmt.startswith("strptime:"):
            if not isinstance(value, str):
                raise ValueError("strptime timestamp must be a string")
            dt = datetime.strptime(value.strip(), fmt[len("strptime:"):])
        else:
            raise ValueError(f"unknown timestamp format {fmt!r}")
    except ValidationIssue:
        raise
    except (ValueError, OverflowError, OSError, TypeError) as exc:
        raise ValidationIssue(ErrorCode.INVALID_TIMESTAMP, f"{field}: {exc}", field, value) from None

    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        if not assume_timezone:
            raise ValidationIssue(
                ErrorCode.INVALID_TIMESTAMP,
                f"{field} has no timezone information and no timezone was configured "
                "(the importer never assumes an unknown timezone)", field, value)
        try:
            dt = dt.replace(tzinfo=ZoneInfo(assume_timezone))
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValidationIssue(ErrorCode.INVALID_TIMESTAMP,
                                  f"unknown configured timezone {assume_timezone!r}: {exc}", field, value) from None
    dt = dt.astimezone(UTC)
    if dt < _EPOCH:
        raise ValidationIssue(ErrorCode.INVALID_TIMESTAMP, f"{field} precedes the Unix epoch", field, value)
    return dt


def _trim_fraction(text: str) -> str:
    """Truncate sub-microsecond fractions (datetime supports 6 digits)."""
    return re.sub(r"(\.\d{6})\d+", r"\1", text, count=1)


_EPOCH_DIVISOR = {"epoch_s": 1, "epoch_ms": 1_000, "epoch_us": 1_000_000, "epoch_ns": 1_000_000_000}


def _parse_epoch(value: Any, fmt: str) -> datetime:
    if fmt not in _EPOCH_DIVISOR:
        raise ValueError(f"unknown epoch format {fmt!r}")
    divisor = _EPOCH_DIVISOR[fmt]
    if isinstance(value, str):
        text = value.strip()
        if not _DECIMAL_RE.match(text):
            raise ValueError("epoch timestamp is not numeric")
        from decimal import Decimal
        number = Decimal(text)
    elif isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("epoch timestamp is not finite")
        from decimal import Decimal
        number = Decimal(str(value))
    else:
        raise ValueError("epoch timestamp must be a number")
    if number < 0:
        raise ValueError("negative epoch timestamp")
    micros = int((number * 1_000_000) / divisor)  # truncate to µs
    return _EPOCH + timedelta(microseconds=micros)


# ------------------------------------------------------------------------ numbers
def parse_int_strict(value: Any, *, field: str, code: ErrorCode) -> int | None:
    """Parse an integer without lossy coercion. ``None`` -> ``None``.

    Accepts JSON integers and decimal digit strings. Rejects booleans, floats,
    fractional strings and anything non-numeric.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValidationIssue(code, f"{field} must be an integer, got a boolean", field, value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if _INT_RE.match(text):
            return int(text)
        raise ValidationIssue(code, f"{field} must be an integer, got {value!r}", field, value)
    raise ValidationIssue(code, f"{field} must be an integer, got {type(value).__name__}", field, value)


def normalize_port(value: Any, *, field: str) -> int | None:
    """Port 0..65535, or ``None`` when unavailable / not applicable."""
    port = parse_int_strict(value, field=field, code=ErrorCode.INVALID_PORT)
    if port is None:
        return None
    if not 0 <= port <= 65535:
        raise ValidationIssue(ErrorCode.INVALID_PORT, f"{field} {port} outside 0..65535", field, value)
    return port


def normalize_counter(value: Any, *, field: str) -> int:
    """Required non-negative integer counter (packets / bytes)."""
    if value is None:
        raise ValidationIssue(ErrorCode.MISSING_REQUIRED_FIELD, f"{field} is missing", field)
    number = parse_int_strict(value, field=field, code=ErrorCode.INVALID_COUNTER)
    assert number is not None
    if number < 0:
        raise ValidationIssue(ErrorCode.INVALID_COUNTER, f"{field} must be non-negative, got {number}", field, value)
    return number


_DURATION_FACTOR_TO_MS = {"s": 1000.0, "ms": 1.0, "us": 0.001, "ns": 0.000001}


def normalize_duration_ms(value: Any, *, unit: str = "ms", field: str = "duration_ms") -> float:
    """Required non-negative finite duration converted to milliseconds,
    rounded to microsecond precision (3 decimals)."""
    if value is None:
        raise ValidationIssue(ErrorCode.MISSING_REQUIRED_FIELD, f"{field} is missing", field)
    if unit not in _DURATION_FACTOR_TO_MS:
        raise ValueError(f"unknown duration unit {unit!r}")
    if isinstance(value, bool):
        raise ValidationIssue(ErrorCode.INVALID_DURATION, f"{field} must be numeric", field, value)
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str) and _DECIMAL_RE.match(value.strip()):
        number = float(value.strip())
    else:
        raise ValidationIssue(ErrorCode.INVALID_DURATION, f"{field} must be numeric, got {value!r}", field, value)
    if not math.isfinite(number):
        raise ValidationIssue(ErrorCode.INVALID_DURATION, f"{field} must be finite", field, value)
    if number < 0:
        raise ValidationIssue(ErrorCode.INVALID_DURATION, f"{field} must be non-negative", field, value)
    return round(number * _DURATION_FACTOR_TO_MS[unit], 3)


def duration_ms_between(start: datetime, end: datetime, *, field: str = "end_time") -> float:
    """Duration derived from start/end timestamps (both µs precision)."""
    delta = end - start
    micros = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    if micros < 0:
        raise ValidationIssue(ErrorCode.INVALID_DURATION, "end time precedes start time", field)
    return micros / 1000.0


# ------------------------------------------------------------------------- IP
def canonical_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Canonical text of an address: IPv4 dotted quad; IPv6 RFC 5952
    compressed lower-case, with IPv4-mapped addresses written as
    ``::ffff:a.b.c.d`` (RFC 5952 section 5).

    The mapped form is produced explicitly because ``ipaddress`` renders it
    differently across CPython patch releases (``::ffff:c000:201`` on some,
    ``::ffff:192.0.2.1`` on others), which would make flow keys and output
    depend on the interpreter version.
    """
    if address.version == 6:
        mapped = address.ipv4_mapped
        if mapped is not None:
            return f"::ffff:{mapped}"
    return address.compressed


def normalize_ip(value: Any, *, field: str) -> str:
    """Validate IPv4/IPv6 text and return its canonical form (see
    :func:`canonical_ip`)."""
    if value is None:
        raise ValidationIssue(ErrorCode.MISSING_REQUIRED_FIELD, f"{field} is missing", field)
    if not isinstance(value, str):
        raise ValidationIssue(ErrorCode.INVALID_IP_ADDRESS, f"{field} must be a string", field, value)
    text = value.strip()
    if "%" in text:
        raise ValidationIssue(ErrorCode.INVALID_IP_ADDRESS, f"{field} contains an IPv6 zone index", field, value)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ValidationIssue(ErrorCode.INVALID_IP_ADDRESS, f"{field} {value!r} is not a valid IPv4/IPv6 address",
                              field, value) from None
    return canonical_ip(address)


def ip_version(address: str) -> int:
    return ipaddress.ip_address(address).version


# ------------------------------------------------------------------- protocol
_PROTOCOL_NAMES = {
    "TCP": Protocol.TCP, "UDP": Protocol.UDP, "ICMP": Protocol.ICMP,
    "ICMPV6": Protocol.ICMPV6, "IPV6-ICMP": Protocol.ICMPV6, "ICMP6": Protocol.ICMPV6,
}


def normalize_protocol(value: Any, *, allow_other: bool = False, field: str = "protocol") -> tuple[Protocol, int | None]:
    """Return (normalised protocol, IANA number when known).

    Accepts names (case-insensitive) or IANA numbers. Valid but unsupported
    numbers raise UNSUPPORTED_PROTOCOL unless ``allow_other`` (then OTHER).
    """
    if value is None:
        raise ValidationIssue(ErrorCode.MISSING_REQUIRED_FIELD, f"{field} is missing", field)
    if isinstance(value, bool):
        raise ValidationIssue(ErrorCode.INVALID_PROTOCOL, f"{field} must not be boolean", field, value)
    number: int | None = None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if _INT_RE.match(text):
            number = int(text)
        else:
            upper = text.upper()
            if upper in _PROTOCOL_NAMES:
                proto = _PROTOCOL_NAMES[upper]
                return proto, {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.ICMP: 1, Protocol.ICMPV6: 58}[proto]
            if upper == "OTHER":
                if allow_other:
                    return Protocol.OTHER, None
                raise ValidationIssue(ErrorCode.UNSUPPORTED_PROTOCOL,
                                      "protocol OTHER is not enabled (see --emit-other-protocols)", field, value)
            raise ValidationIssue(ErrorCode.INVALID_PROTOCOL, f"{field} {value!r} is not a recognised protocol",
                                  field, value)
    else:
        raise ValidationIssue(ErrorCode.INVALID_PROTOCOL, f"{field} has invalid type {type(value).__name__}",
                              field, value)
    if not 0 <= number <= 255:
        raise ValidationIssue(ErrorCode.INVALID_PROTOCOL, f"{field} number {number} outside 0..255", field, value)
    if number in IP_PROTO_TO_PROTOCOL:
        return IP_PROTO_TO_PROTOCOL[number], number
    if allow_other:
        return Protocol.OTHER, number
    raise ValidationIssue(ErrorCode.UNSUPPORTED_PROTOCOL,
                          f"IP protocol number {number} is not supported (TCP, UDP, ICMP, ICMPv6)", field, value)


# ------------------------------------------------------------------ TCP flags
def normalize_tcp_flags(value: Any, *, protocol: Protocol, fmt: str = "int", field: str = "tcp_flags") -> int | None:
    """TCP flag bitmask 0..255 or ``None`` (= unavailable, NOT zero).

    ``fmt``: ``int`` (decimal or 0x-hex), ``letters`` (e.g. ``SA``, ``FPA``)
    or ``names`` (e.g. ``SYN|ACK``). Flags for non-TCP protocols are rejected.
    """
    if value is None:
        return None
    if protocol is not Protocol.TCP:
        raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS,
                              f"{field} present for non-TCP protocol {protocol.value}", field, value)
    if isinstance(value, bool):
        raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS, f"{field} must not be boolean", field, value)
    flags: int
    if fmt == "int":
        if isinstance(value, int):
            flags = value
        elif isinstance(value, str) and _INT_RE.match(value.strip()):
            flags = int(value.strip())
        elif isinstance(value, str) and _HEX_RE.match(value.strip()):
            flags = int(value.strip(), 16)
        else:
            raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS, f"{field} {value!r} is not an integer bitmask",
                                  field, value)
    elif fmt == "letters":
        if not isinstance(value, str):
            raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS, f"{field} must be a flag-letter string", field, value)
        flags = 0
        for char in value.strip().upper():
            if char in (".", "_", "-"):
                continue
            if char not in TCP_FLAG_BITS:
                raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS, f"{field} has unknown flag letter {char!r}",
                                      field, value)
            flags |= TCP_FLAG_BITS[char]
    elif fmt == "names":
        if not isinstance(value, str):
            raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS, f"{field} must be a flag-name string", field, value)
        flags = 0
        for name in re.split(r"[|,+\s]+", value.strip().upper()):
            if not name:
                continue
            if name not in TCP_FLAG_NAMES:
                raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS, f"{field} has unknown flag name {name!r}",
                                      field, value)
            flags |= TCP_FLAG_NAMES[name]
    else:
        raise ValueError(f"unknown tcp_flags format {fmt!r}")
    if not 0 <= flags <= 255:
        raise ValidationIssue(ErrorCode.INVALID_TCP_FLAGS, f"{field} {flags} outside 0..255", field, value)
    return flags


# -------------------------------------------------------------- scenario label
def normalize_scenario_label(value: Any, *, value_map: dict[str, str | None] | None = None,
                             field: str = "scenario_label") -> str | None:
    """Ground-truth label from the source, or ``None``. Never fabricated."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationIssue(ErrorCode.INVALID_SCENARIO_LABEL, f"{field} must be a string", field, value)
    text = value.strip()
    if value_map is not None:
        if text not in value_map:
            raise ValidationIssue(ErrorCode.INVALID_SCENARIO_LABEL,
                                  f"{field} {value!r} has no entry in the mapping profile", field, value)
        mapped = value_map[text]
        if mapped is None:
            return None
        text = mapped
    if text not in SCENARIO_LABELS:
        raise ValidationIssue(ErrorCode.INVALID_SCENARIO_LABEL,
                              f"{field} {value!r} is not one of {sorted(SCENARIO_LABELS)}", field, value)
    return text
