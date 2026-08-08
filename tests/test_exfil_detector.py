"""Tests for the measured bulk-transfer exfil detector.

All fixture addresses use RFC 5737 documentation space outside the default
RFC1918 home network unless a test deliberately exercises local topology.
"""

from __future__ import annotations

from datetime import datetime, timezone
import re

import pandas as pd
import pytest

from sigwood.common.finding import DetectorContext, Severity
from sigwood.detectors import exfil
from tests.test_voice_consistency import assert_report_voice


_WINDOW = (
    datetime(2026, 8, 1, tzinfo=timezone.utc),
    datetime(2026, 8, 2, tzinfo=timezone.utc),
)
_FLOOR = 1_000


def _row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "src": "10.0.0.10",
        "dst": "198.51.100.20",
        "port": 443,
        "proto": "tcp",
        "bytes": 1_200,
        "resp_bytes": 100,
        "ts": 60.0,
        "duration": 3.5,
        "local_orig": True,
    }
    row.update(overrides)
    return row


def _context(rows: list[dict[str, object]], **config: object) -> DetectorContext:
    return DetectorContext.unsuppressed(
        {"conn*.log*": pd.DataFrame(rows)},
        config={"min_outbound_bytes": _FLOOR, "min_orig_share": 0.6, **config},
        data_window=_WINDOW,
    )


def test_constants_and_discovery_contract() -> None:
    assert exfil.DETECTOR_NAME == "exfil"
    assert exfil.STATUS == "available"
    assert exfil.IN_DEFAULT_HUNT is False
    assert exfil.DEFAULT_CONFIG == {
        "min_outbound_bytes": 1 << 30,
        "min_orig_share": 0.6,
    }
    exfil.validate_config(exfil.DEFAULT_CONFIG)


def test_pair_uses_sum_then_divide_and_sorts_by_measured_outbound() -> None:
    findings = exfil.run(_context([
        _row(bytes=700, resp_bytes=300),
        _row(bytes=500, resp_bytes=500, ts=120.0),
        _row(src="10.0.0.11", dst="203.0.113.30", bytes=1_300, resp_bytes=100),
    ]))

    assert [finding.evidence["orig_bytes_total"] for finding in findings] == [1300.0, 1200.0]
    second = findings[1]
    assert second.evidence["orig_share"] == 0.6
    assert second.evidence["connection_count"] == 2
    assert second.severity is Severity.MEDIUM
    assert "severity_basis" not in second.evidence


def test_empty_or_missing_responder_column_abstains_without_exception() -> None:
    assert exfil.run(DetectorContext.unsuppressed({}, data_window=_WINDOW)) == []
    frame = pd.DataFrame([_row()]).drop(columns=["resp_bytes"])
    context = DetectorContext.unsuppressed(
        {"conn*.log*": frame}, config={"min_outbound_bytes": _FLOOR}, data_window=_WINDOW,
    )
    assert exfil.run(context) == []


def test_parse_gate_rejects_malformed_endpoints_before_policy_composition() -> None:
    malformed_dst = _context([_row(dst="not-an-ip")])
    malformed_local_src = _context([_row(src="not-an-ip", local_orig=True)])

    assert exfil.run(malformed_dst) == []
    assert exfil.run(malformed_local_src) == []


def test_duplicate_dataframe_indexes_preserve_row_alignment_through_parse_gate() -> None:
    frame = pd.DataFrame([
        _row(bytes=700, resp_bytes=300),
        _row(bytes=500, resp_bytes=100),
    ], index=[7, 7])
    context = DetectorContext.unsuppressed(
        {"conn*.log*": frame},
        config={"min_outbound_bytes": _FLOOR, "min_orig_share": 0.6},
        data_window=_WINDOW,
    )

    findings = exfil.run(context)

    assert len(findings) == 1
    assert findings[0].evidence["orig_bytes_total"] == 1200.0
    assert findings[0].evidence["connection_count"] == 2


@pytest.mark.parametrize(
    "dst",
    ["224.0.0.251", "255.255.255.255", "127.0.0.1", "::1", "0.0.0.0", "fe80::1"],
)
def test_non_routable_destinations_never_surface(dst: str) -> None:
    assert exfil.run(_context([_row(dst=dst)])) == []


def test_private_destination_outside_home_net_and_mapped_ipv6_are_external() -> None:
    findings = exfil.run(_context([
        _row(dst="100.64.0.10"),
        _row(src="::ffff:10.0.0.12", dst="::ffff:198.51.100.22"),
    ]))

    assert [finding.title for finding in findings] == [
        "10.0.0.10 → 100.64.0.10",
        "10.0.0.12 → 198.51.100.22",
    ]


@pytest.mark.parametrize(
    "value", [None, -1, float("nan"), float("inf"), "not-a-number", True, []],
)
def test_invalid_byte_values_are_not_measured(value: object) -> None:
    assert exfil.run(_context([_row(bytes=value)])) == []
    assert exfil.run(_context([_row(resp_bytes=value)])) == []


def test_zero_denominator_does_not_surface() -> None:
    assert exfil.run(_context([_row(bytes=0, resp_bytes=0)])) == []


def test_duration_is_optional_and_timestamp_uses_finite_values_including_epoch() -> None:
    finding = exfil.run(_context([
        _row(ts=0.0, duration=None),
        _row(ts=float("nan"), duration=float("nan")),
    ]))[0]

    assert finding.evidence["first_seen"] == "1970-01-01T00:00:00+00:00"
    assert finding.evidence["last_seen"] == "1970-01-01T00:00:00+00:00"
    assert finding.evidence["span_seconds"] == 0.0
    assert finding.evidence["max_duration_seconds"] is None


def test_port_mix_ties_break_by_port_then_protocol() -> None:
    finding = exfil.run(_context([
        _row(port=8443, proto="tcp", bytes=500, resp_bytes=0),
        _row(port=443, proto="udp", bytes=500, resp_bytes=0),
        _row(port=443, proto="tcp", bytes=500, resp_bytes=0),
    ]))[0]

    assert finding.evidence["port_mix"].split(", ") == [
        "443/tcp (500 B)", "443/udp (500 B)", "8443/tcp (500 B)",
    ]


def test_partial_pair_facts_are_identity_keyed_and_best_case_is_detector_owned() -> None:
    frame = pd.DataFrame([
        _row(bytes=900, resp_bytes=900),
        _row(bytes=600, resp_bytes=None),
    ])

    facts = exfil.eligibility(frame, config={"min_outbound_bytes": _FLOOR, "min_orig_share": 0.6})
    pair = facts["partial_pairs"][("10.0.0.10", "198.51.100.20")]

    assert pair == {
        "eligible_orig": 900.0,
        "eligible_resp": 900.0,
        "excluded_orig": 600.0,
        "surfaced": False,
        "best_case_surfaces": True,
    }


def test_commands_quote_hostile_log_derived_values_and_voice_contract_holds() -> None:
    finding = exfil.run(_context([
        _row(src="10.0.0.10", dst="198.51.100.20"),
    ]))[0]

    assert "grep 10.0.0.10" in finding.next_steps[0]
    assert "whois 198.51.100.20" in finding.next_steps[1]
    assert_report_voice([finding])


@pytest.mark.parametrize(
    "cfg, message",
    [
        ({"min_outbound_bytes": True}, "[detectors.exfil].min_outbound_bytes"),
        ({"min_outbound_bytes": 0}, "[detectors.exfil].min_outbound_bytes"),
        ({"min_orig_share": True}, "[detectors.exfil].min_orig_share"),
        ({"min_orig_share": float("nan")}, "[detectors.exfil].min_orig_share"),
        ({"min_orig_share": 1.1}, "[detectors.exfil].min_orig_share"),
    ],
)
def test_config_validation_rejects_invalid_values_without_echoing_them(
    cfg: dict[str, object], message: str,
) -> None:
    with pytest.raises(ValueError, match=re.escape(message)):
        exfil.validate_config(cfg)
