"""Pure compact-JSON system-journal record parsing."""

from __future__ import annotations

import json
import math
from enum import Enum
from typing import Any

from sigwood.common.journal_probe import parse_receipt_timestamp
from sigwood.parsers.syslog import normalize_pids, parse_program


class JournalSkipReason(str, Enum):
    """Typed reasons a journal JSON record cannot become a canonical row."""

    MALFORMED_JSON = "malformed_json"
    DUPLICATE_KEYS = "duplicate_keys"
    NON_OBJECT = "non_object"
    MISSING_TIMESTAMP = "missing_timestamp"
    INVALID_TIMESTAMP = "invalid_timestamp"
    MISSING_MESSAGE = "missing_message"
    INVALID_MESSAGE = "invalid_message"


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON number is outside the finite float range")
    return parsed


def _load_json(line: str) -> Any:
    return json.loads(
        line,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )


def _has_identity_control(value: str) -> bool:
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in value)


def _identity(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or _has_identity_control(candidate):
        return None
    try:
        candidate.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    return candidate


def _message(value: object) -> str | None:
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return None
        return value
    if not isinstance(value, list):
        return None
    if not all(
        isinstance(item, int)
        and not isinstance(item, bool)
        and 0 <= item <= 255
        for item in value
    ):
        return None
    try:
        return bytes(value).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _program(record: dict[str, Any]) -> tuple[str, bool]:
    for field in ("SYSLOG_IDENTIFIER", "_COMM"):
        candidate = _identity(record.get(field))
        if candidate is None:
            continue
        token = parse_program(candidate)
        if token != "unknown":
            return token, True
    return "unknown", False


def _pid(record: dict[str, Any]) -> str | None:
    for field in ("_PID", "SYSLOG_PID"):
        candidate = record.get(field)
        if (
            isinstance(candidate, str)
            and candidate
            and candidate.isascii()
            and all("0" <= ch <= "9" for ch in candidate)
        ):
            return candidate
    return None


def parse_receipt_from_record(line: str) -> float | None:
    """Return a record's receipt timestamp without requiring MESSAGE fields."""
    try:
        value = _load_json(line)
    except (
        _DuplicateKeyError,
        json.JSONDecodeError,
        ValueError,
        OverflowError,
        RecursionError,
    ):
        return None
    if not isinstance(value, dict):
        return None
    return parse_receipt_timestamp(value.get("__REALTIME_TIMESTAMP"))


def parse_record(line: str) -> dict[str, object] | JournalSkipReason:
    """Parse one compact journal JSON object into the minimal syslog row."""
    try:
        value = _load_json(line)
    except _DuplicateKeyError:
        return JournalSkipReason.DUPLICATE_KEYS
    except (json.JSONDecodeError, ValueError, OverflowError, RecursionError):
        return JournalSkipReason.MALFORMED_JSON
    if not isinstance(value, dict):
        return JournalSkipReason.NON_OBJECT

    if "__REALTIME_TIMESTAMP" not in value:
        return JournalSkipReason.MISSING_TIMESTAMP
    ts = parse_receipt_timestamp(value.get("__REALTIME_TIMESTAMP"))
    if ts is None:
        return JournalSkipReason.INVALID_TIMESTAMP

    if "MESSAGE" not in value or value.get("MESSAGE") is None:
        return JournalSkipReason.MISSING_MESSAGE
    message = _message(value.get("MESSAGE"))
    if message is None:
        return JournalSkipReason.INVALID_MESSAGE

    program, known = _program(value)
    pid = _pid(value)
    host_candidate = _identity(value.get("_HOSTNAME"))
    host = (
        host_candidate
        if host_candidate is not None
        and not any(ch.isspace() for ch in host_candidate)
        else "unknown"
    )
    if known:
        tag = f"{program}[{pid}]" if pid is not None else program
        analysis = normalize_pids(f"{tag}: {message}")
    else:
        analysis = normalize_pids(message)
    return {
        "ts": ts,
        "host": host,
        "program": program,
        "raw": message,
        "message": analysis,
    }
