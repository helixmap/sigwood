"""Pure system-journal JSON parser contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sigwood.parsers.journal import (
    JournalSkipReason,
    parse_receipt_from_record,
    parse_record,
)


def _line(**overrides: object) -> str:
    record: dict[str, object] = {
        "__REALTIME_TIMESTAMP": "1700000000123456",
        "_SOURCE_REALTIME_TIMESTAMP": "1",
        "MESSAGE": "accepted connection",
        "_HOSTNAME": "host.example",
        "SYSLOG_IDENTIFIER": "sshd",
        "_COMM": "fallback",
        "_PID": "1234",
        "SYSLOG_PID": "9999",
    }
    record.update(overrides)
    return json.dumps(record)


def test_exact_mapping_receipt_clock_and_column_order() -> None:
    row = parse_record(_line(extra="ignored"))
    assert isinstance(row, dict)
    assert list(row) == ["ts", "host", "program", "raw", "message"]
    assert row == {
        "ts": 1700000000.123456,
        "host": "host.example",
        "program": "sshd",
        "raw": "accepted connection",
        "message": "sshd[*]: accepted connection",
    }


@pytest.mark.parametrize(
    ("field", "value", "expected_program"),
    [
        ("SYSLOG_IDENTIFIER", "bad tag", "bad"),
        ("SYSLOG_IDENTIFIER", ":invalid", "fallback"),
        ("SYSLOG_IDENTIFIER", "\x1bunsafe", "fallback"),
        ("SYSLOG_IDENTIFIER", "", "fallback"),
    ],
)
def test_program_candidate_fallthrough(
    field: str, value: str, expected_program: str
) -> None:
    row = parse_record(_line(**{field: value}))
    assert isinstance(row, dict)
    assert row["program"] == expected_program


def test_pid_precedence_fallthrough_and_unknown_program() -> None:
    row = parse_record(
        _line(
            SYSLOG_IDENTIFIER=":bad",
            _COMM="[bad",
            _PID="not-a-pid",
            SYSLOG_PID="42",
        )
    )
    assert isinstance(row, dict)
    assert row["program"] == "unknown"
    assert row["message"] == "accepted connection"


@pytest.mark.parametrize("host", ["two tokens", "host\tname", "\x7fhost", "\ud800"])
def test_host_requires_the_entire_safe_token(host: str) -> None:
    row = parse_record(_line(_HOSTNAME=host))
    assert isinstance(row, dict)
    assert row["host"] == "unknown"


def test_message_fidelity_blank_multiline_controls_and_byte_array() -> None:
    for message in ("", "first\nsecond\t\x1b", [0xCF, 0x80]):
        row = parse_record(_line(MESSAGE=message))
        assert isinstance(row, dict)
    assert parse_record(_line(MESSAGE=""))["raw"] == ""  # type: ignore[index]
    assert parse_record(_line(MESSAGE="first\nsecond\t\x1b"))["raw"] == (  # type: ignore[index]
        "first\nsecond\t\x1b"
    )
    assert parse_record(_line(MESSAGE=[0xCF, 0x80]))["raw"] == "π"  # type: ignore[index]
    assert parse_record(_line(MESSAGE=[]))["raw"] == ""  # type: ignore[index]


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("{", JournalSkipReason.MALFORMED_JSON),
        ('{"extra":NaN}', JournalSkipReason.MALFORMED_JSON),
        ('{"extra":1e999}', JournalSkipReason.MALFORMED_JSON),
        ('{"MESSAGE":"x","MESSAGE":"y"}', JournalSkipReason.DUPLICATE_KEYS),
        ("[]", JournalSkipReason.NON_OBJECT),
        (json.dumps({"MESSAGE": "x"}), JournalSkipReason.MISSING_TIMESTAMP),
        (_line(__REALTIME_TIMESTAMP=1), JournalSkipReason.INVALID_TIMESTAMP),
        (_line(__REALTIME_TIMESTAMP="-1"), JournalSkipReason.INVALID_TIMESTAMP),
        (_line(MESSAGE=None), JournalSkipReason.MISSING_MESSAGE),
        (_line(MESSAGE=[True]), JournalSkipReason.INVALID_MESSAGE),
        (_line(MESSAGE=[[65]]), JournalSkipReason.INVALID_MESSAGE),
        (_line(MESSAGE=[255]), JournalSkipReason.INVALID_MESSAGE),
        (_line(MESSAGE="\ud800"), JournalSkipReason.INVALID_MESSAGE),
    ],
)
def test_typed_skip_reasons(line: str, reason: JournalSkipReason) -> None:
    assert parse_record(line) is reason


def test_receipt_only_helper_does_not_require_message() -> None:
    assert parse_receipt_from_record('{"__REALTIME_TIMESTAMP":"2000000"}') == 2.0
    assert parse_receipt_from_record(
        '{"__REALTIME_TIMESTAMP":"1","__REALTIME_TIMESTAMP":"2"}'
    ) is None


def test_parser_has_no_loader_or_heavy_layer_imports() -> None:
    import sigwood.parsers.journal as journal_parser

    source = Path(journal_parser.__file__).read_text(encoding="utf-8")
    forbidden = ("loader", "runner", "config", "detectors", "outputs", "pandas")
    assert not any(f"import {name}" in source for name in forbidden)
    assert not any(f"from sigwood.{name}" in source for name in forbidden)
