"""Tests for the measured bulk-transfer exfil detector.

All fixture addresses use RFC 5737 documentation space outside the default
RFC1918 home network unless a test deliberately exercises local topology.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
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


def _finding_snapshot(rows: list[dict[str, object]]) -> bytes:
    """Stable UTF-8 serialization of all rendered-finding contract fields."""
    payload = [
        {
            "data_window": [item.isoformat() for item in finding.data_window],
            "description": finding.description,
            "evidence": finding.evidence,
            "next_steps": finding.next_steps,
            "severity": finding.severity.value,
            "title": finding.title,
        }
        for finding in exfil.run(_context(rows))
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def test_shared_topology_migration_keeps_frozen_exfil_bytes_and_is_sensitivity_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_net_fallback = _row(src="10.0.0.12", dst="203.0.113.31", bytes=1_300, resp_bytes=100)
    home_net_fallback.pop("local_orig")
    rows = [
        *[
            _row(dst=f"198.51.100.{host}", bytes=1_200, resp_bytes=100)
            for host in (20, 21, 22, 23)
        ],
        _row(dst="203.0.113.30", bytes=1_300, resp_bytes=100),
        _row(dst="203.0.113.30", bytes=500, resp_bytes=None),
        _row(dst="2001:db8::20", bytes=1_300, resp_bytes=100),
        _row(src="::ffff:10.0.0.11", dst="::ffff:203.0.113.20", bytes=1_400, resp_bytes=100),
        home_net_fallback,
        _row(dst="10.0.0.50", bytes=1_500, resp_bytes=100),
        _row(dst="224.0.0.251", bytes=1_500, resp_bytes=100),
    ]
    frozen = _finding_snapshot(rows)

    assert hashlib.sha256(frozen).hexdigest() == "8989bc58a220374cd387ef7b83a159c24e8b7c6d593b6f97da411c557bd16316"
    assert _finding_snapshot(rows) == frozen

    with monkeypatch.context() as altered:
        altered.setattr(exfil, "is_non_routable", lambda _address: False)
        assert _finding_snapshot(rows) != frozen
    with monkeypatch.context() as altered:
        altered.setattr(exfil, "parse_address", lambda _address: None)
        assert _finding_snapshot(rows) != frozen
    with monkeypatch.context() as altered:
        altered.setattr(exfil, "in_home_net", lambda *_args, **_kwargs: False)
        assert _finding_snapshot(rows) != frozen


def test_constants_and_discovery_contract() -> None:
    assert exfil.DETECTOR_NAME == "exfil"
    assert exfil.STATUS == "available"
    assert exfil.IN_DEFAULT_HUNT is True
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


def test_subthreshold_destination_pool_retains_the_exact_pair_shape() -> None:
    """Three surfaced pairs share the /20 but remain ordinary pair findings."""
    rows = [
        _row(dst=f"198.51.100.{host}", bytes=1_200, resp_bytes=100)
        for host in (20, 21, 22)
    ]

    findings = exfil.run(_context(rows))
    singleton = exfil.run(_context([rows[0]]))[0]

    assert len(findings) == 3
    assert [finding.title for finding in findings] == [
        "10.0.0.10 → 198.51.100.20",
        "10.0.0.10 → 198.51.100.21",
        "10.0.0.10 → 198.51.100.22",
    ]
    assert findings[0].evidence == singleton.evidence
    assert findings[0].next_steps == singleton.next_steps
    assert all("tier" not in finding.evidence for finding in findings)
    assert all("members" not in finding.evidence for finding in findings)


def test_four_surfaced_pairs_fold_to_one_lossless_destination_pool() -> None:
    findings = exfil.run(_context([
        _row(dst="198.51.100.20", bytes=1_500, resp_bytes=100, port=443, ts=90.0),
        _row(dst="198.51.100.21", bytes=1_300, resp_bytes=200, port=8443, ts=60.0),
        _row(dst="198.51.100.22", bytes=1_200, resp_bytes=100, port=443, ts=120.0),
        _row(dst="198.51.100.23", bytes=1_000, resp_bytes=100, port=22, ts=180.0),
    ]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.title == "10.0.0.10 → 198.51.96.0/20"
    assert finding.evidence["tier"] == "destination_pool"
    assert finding.evidence["destination_network"] == "198.51.96.0/20"
    assert finding.evidence["destination_count"] == 4
    assert finding.evidence["orig_bytes_total"] == 5_000.0
    assert finding.evidence["resp_bytes_total"] == 500.0
    assert finding.evidence["orig_share"] == round(5_000 / 5_500, 4)
    assert finding.evidence["connection_count"] == 4
    assert finding.evidence["first_seen"] == "1970-01-01T00:01:00+00:00"
    assert finding.evidence["last_seen"] == "1970-01-01T00:03:00+00:00"
    assert finding.evidence["span_seconds"] == 120.0
    assert [member["dst"] for member in finding.evidence["members"]] == [
        "198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23",
    ]
    assert all(
        {"port_mix", "first_seen", "last_seen", "max_duration_seconds"} <= set(member)
        for member in finding.evidence["members"]
    )
    assert "whois 198.51.96.0/20" in finding.next_steps[1]


def test_only_surfaced_pairs_count_toward_destination_pool_fold() -> None:
    findings = exfil.run(_context([
        _row(dst=f"198.51.100.{host}", bytes=1_000, resp_bytes=100)
        for host in (20, 21, 22)
    ] + [
        _row(dst="198.51.100.23", bytes=999, resp_bytes=0),
    ]))

    assert len(findings) == 3
    assert all(finding.evidence.get("tier") != "destination_pool" for finding in findings)
    assert {finding.evidence["dst"] for finding in findings} == {
        "198.51.100.20", "198.51.100.21", "198.51.100.22",
    }


def test_ipv6_destination_pool_uses_a_canonical_40_prefix() -> None:
    findings = exfil.run(_context([
        _row(dst=f"2001:db8:abcd:{host}::1", bytes=1_100, resp_bytes=100)
        for host in range(1, 5)
    ]))

    assert len(findings) == 1
    assert findings[0].title == "10.0.0.10 → 2001:db8:ab00::/40"
    assert findings[0].evidence["destination_network"] == "2001:db8:ab00::/40"
    assert len(findings[0].evidence["members"]) == 4


def test_mapped_ipv6_destination_joins_native_ipv4_pool() -> None:
    findings = exfil.run(_context([
        _row(dst="::ffff:198.51.100.23", bytes=1_100, resp_bytes=100),
        _row(dst="198.51.100.22", bytes=1_100, resp_bytes=100),
        _row(dst="198.51.100.21", bytes=1_100, resp_bytes=100),
        _row(dst="198.51.100.20", bytes=1_100, resp_bytes=100),
    ]))

    assert len(findings) == 1
    assert findings[0].title == "10.0.0.10 → 198.51.96.0/20"
    assert [member["dst"] for member in findings[0].evidence["members"]] == [
        "198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23",
    ]


def test_destination_pools_do_not_merge_across_sources_or_networks() -> None:
    findings = exfil.run(_context([
        _row(src="10.0.0.10", dst="198.51.100.20"),
        _row(src="10.0.0.10", dst="198.51.100.21"),
        _row(src="10.0.0.11", dst="198.51.100.22"),
        _row(src="10.0.0.11", dst="198.51.100.23"),
        _row(src="10.0.0.12", dst="198.51.100.24"),
        _row(src="10.0.0.12", dst="198.51.116.20"),
        _row(src="10.0.0.12", dst="198.51.116.21"),
        _row(src="10.0.0.12", dst="198.51.116.22"),
    ]))

    assert len(findings) == 8
    assert all(finding.evidence.get("tier") != "destination_pool" for finding in findings)


def test_destination_pool_share_is_sum_then_divide_and_ties_sort_by_destination() -> None:
    findings = exfil.run(_context([
        _row(dst="198.51.100.23", bytes=1_000, resp_bytes=600),
        _row(dst="198.51.100.21", bytes=1_000, resp_bytes=600),
        _row(dst="198.51.100.22", bytes=1_000, resp_bytes=600),
        _row(dst="198.51.100.20", bytes=10_000, resp_bytes=0),
    ]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence["orig_share"] == round(13_000 / 14_800, 4)
    assert [member["dst"] for member in finding.evidence["members"]] == [
        "198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23",
    ]


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
