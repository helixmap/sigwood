"""Parity and identity contract for the additive audit-event parser helper."""

from __future__ import annotations

import pytest

from sigwood.parsers import auth as frozen_auth
from sigwood.parsers.audit_event import (
    _AUDIT_EVENT_ID_RE,
    extract_audit_event_id,
)


@pytest.mark.parametrize(
    ("text", "expected_id", "expected_serial"),
    [
        (
            "audisp-syslog[*]: type=USER_AUTH "
            "msg=audit(1700000000.125:42): acct=admin res=failed",
            "1700000000.125:42",
            "42",
        ),
        (
            "audit[*]: AUDIT1112 pid=3001 acct=admin res=success",
            None,
            None,
        ),
        (
            "audisp-syslog[*]: type=USER_AUTH msg=audit(malformed) "
            "acct=admin res=failed",
            None,
            None,
        ),
    ],
)
def test_full_id_helper_matches_frozen_serial_reader(
    text: str,
    expected_id: str | None,
    expected_serial: str | None,
) -> None:
    full_match = _AUDIT_EVENT_ID_RE.search(text)
    frozen_match = frozen_auth._AUDIT_EVENT_RE.search(text)

    assert extract_audit_event_id(text) == expected_id
    assert (
        None if full_match is None else full_match.group("serial")
    ) == expected_serial
    assert (
        None if frozen_match is None else frozen_match.group("serial")
    ) == expected_serial


def test_full_id_distinguishes_reused_serials_across_epochs() -> None:
    first = extract_audit_event_id(
        "type=USER_AUTH msg=audit(1700000000.125:42): res=failed"
    )
    second = extract_audit_event_id(
        "type=USER_AUTH msg=audit(1700003600.125:42): res=failed"
    )

    assert first == "1700000000.125:42"
    assert second == "1700003600.125:42"
    assert first != second
