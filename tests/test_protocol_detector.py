"""Frozen classifier and population contracts for the protocol detector."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from sigwood.common.finding import DetectorContext, Severity
from sigwood.detectors import protocol
from tests.test_voice_consistency import assert_report_voice

UTC = timezone.utc
START = datetime(2026, 6, 1, tzinfo=UTC)


def _row(
    *, src: str = "192.0.2.10", dst: str = "198.51.100.20", port: int = 443,
    proto: str = "tcp", service: str | None = "ssh", ts: float = START.timestamp(),
    history: str = "ShADadFf", orig_port: int | None = 50000,
) -> dict:
    row = {
        "src": src, "dst": dst, "port": port, "proto": proto, "service": service,
        "ts": ts, "history": history, "orig_port": orig_port, "bytes": 100,
        "resp_bytes": 200, "missed_bytes": 0, "orig_pkts": 2, "resp_pkts": 2,
        "orig_ip_bytes": 180, "resp_ip_bytes": 280, "conn_state": "SF",
    }
    for name in (
        "service", "history", "missed_bytes", "orig_pkts", "resp_pkts",
        "orig_ip_bytes", "resp_ip_bytes",
    ):
        row[f"_source_has_{name}"] = True
    return row


def _context(rows: list[dict], config: dict | None = None) -> DetectorContext:
    return DetectorContext.unsuppressed(
        {"conn*.log*": pd.DataFrame(rows)},
        data_window=(START, START + timedelta(days=1)),
        config=config,
    )


def test_service_table_is_the_pinned_generator_output() -> None:
    raw = Path("sigwood/data/services").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == protocol._TABLE_SHA256
    table = protocol.load_service_table()
    assert sum(map(len, table.registered.values())) == 70
    assert sum(map(len, table.conventional.values())) == 3
    assert table.conventional[("dns", "tcp")] == {853}
    assert table.conventional[("ssl", "tcp")] == {853, 8443}
    assert table.reasons[("ssl", "tcp", 8443)] == "HTTPS alternate-port convention"
    with pytest.raises(TypeError):
        table.registered[("ssh", "tcp")] = frozenset({2222})  # type: ignore[index]
    with pytest.raises(TypeError):
        table.flags["ssl"]["dependent_on"] = ("ssh",)  # type: ignore[index]


def test_service_table_refuses_cross_tier_and_flag_contradictions(monkeypatch) -> None:
    header = "# sigwood protocol services\n"
    monkeypatch.setattr(
        protocol,
        "_table_text",
        lambda: header + "ssh 22/tcp # tier=registered\n"
        "ssh 22/tcp # tier=conventional reason=conflict\n",
    )
    protocol.load_service_table.cache_clear()
    with pytest.raises(ValueError, match="contradictory protocol service-table row"):
        protocol.load_service_table()

    monkeypatch.setattr(
        protocol,
        "_table_text",
        lambda: header + "# flag service=ssl kind=dependent_on values=http\n"
        "# flag service=ssl kind=dependent_on values=smtp\n",
    )
    protocol.load_service_table.cache_clear()
    with pytest.raises(ValueError, match="contradictory protocol service-table flag"):
        protocol.load_service_table()
    protocol.load_service_table.cache_clear()


@pytest.mark.parametrize(
    ("labels", "port", "proto", "expected"),
    [
        (("ssh",), 22, "tcp", {"ssh": "registered"}),
        (("ssh",), 2222, "tcp", {"ssh": "off-expectation"}),
        (("ssh",), 443, "tcp", {"ssh": "off-expectation"}),
        (("ssh", "ssl"), 443, "tcp", {"ssh": "off-expectation", "ssl": "registered"}),
        (("http", "ssh"), 80, "tcp", {"http": "registered", "ssh": "off-expectation"}),
        (("smtp", "ssl"), 25, "tcp", {"smtp": "registered", "ssl": "dependent-exempt"}),
        (("http", "ssl"), 80, "tcp", {"http": "registered", "ssl": "dependent-exempt"}),
        (("quic", "ssl"), 443, "udp", {"quic": "registered", "ssl": "dependent-exempt"}),
        (("ssl",), 8443, "tcp", {"ssl": "conventional-only"}),
        (("ssl",), 25, "tcp", {"ssl": "ambiguous"}),
        (("ssl",), 2222, "tcp", {"ssl": "off-expectation"}),
        (("dce_rpc",), 49152, "tcp", {"dce_rpc": "unavailable"}),
        (("ayiya",), 443, "udp", {"ayiya": "unavailable"}),
        (("zzz",), 443, "tcp", {"zzz": "unavailable"}),
    ],
)
def test_pinned_classifier_cases(labels, port, proto, expected) -> None:
    outcomes, reason = protocol.classify_labels(
        labels, _row(port=port, proto=proto, service=",".join(labels))
    )
    assert reason is None
    assert outcomes == expected


def test_role_inversion_and_missing_originator_port_are_distinct() -> None:
    outcomes, reason = protocol.classify_labels(
        ("ssh",), _row(port=443, history="Sh^ADad", orig_port=22)
    )
    assert outcomes == {}
    assert reason == "role-inverted"
    outcomes, reason = protocol.classify_labels(
        ("ssh",), _row(port=443, history="Sh^ADad", orig_port=None)
    )
    assert outcomes == {}
    assert reason == "role-inversion-unavailable"
    outcomes, reason = protocol.classify_labels(
        ("ssh",), _row(port=22, history="Sh^ADad", orig_port=50000)
    )
    assert reason is None
    assert outcomes == {"ssh": "registered"}


def test_validate_config_refuses_bool_zero_and_non_integer() -> None:
    protocol.validate_config(protocol.DEFAULT_CONFIG)
    for value in (True, 0, 1.5, "3"):
        with pytest.raises(ValueError):
            protocol.validate_config({"min_connections": value})


def test_finding_grain_floor_and_demo_norm_are_exact() -> None:
    rows = [
        _row(src=f"192.0.2.{index % 200 + 1}", port=22, ts=START.timestamp() + index)
        for index in range(425)
    ]
    rows.extend(
        _row(src="192.168.1.240", dst="192.0.2.240", port=443,
             ts=START.timestamp() + 1000 + index * 900)
        for index in range(6)
    )
    findings = protocol.run(_context(rows))
    mismatch = next(f for f in findings if f.evidence["kind"] == "mismatch")
    assert mismatch.severity is Severity.LOW
    assert mismatch.evidence["conns"] == 6
    assert mismatch.evidence["norm_class"] == "routine"
    assert mismatch.evidence["window_share"] == pytest.approx(6 / 431)
    assert "orig_port" not in mismatch.evidence
    assert findings[-1].evidence["kind"] == "context"
    assert_report_voice(findings)


def test_finding_keeps_expected_maps_for_every_confirmed_label() -> None:
    rows = [
        _row(service="ssh,ssl", port=443, ts=START.timestamp() + index)
        for index in range(3)
    ]
    mismatch = next(
        f for f in protocol.run(_context(rows)) if f.evidence["kind"] == "mismatch"
    )
    assert mismatch.evidence["mismatched_services"] == ["ssh"]
    assert set(mismatch.evidence["expected_ports"]) == {"ssh", "ssl"}
    assert mismatch.evidence["expected_ports"]["ssh"] == [22]
    assert 443 in mismatch.evidence["expected_ports"]["ssl"]
    assert mismatch.evidence["conventional_ports"]["ssl"] == [853, 8443]


def test_removed_set_is_part_of_floor_grain() -> None:
    rows = [_row(service="ssh", ts=START.timestamp() + index) for index in range(2)]
    rows.extend(_row(service="ssh,-ssl", ts=START.timestamp() + 10 + index) for index in range(2))
    findings = protocol.run(_context(rows))
    assert [f for f in findings if f.evidence["kind"] == "mismatch"] == []
    assert findings[-1].evidence["pairs_below_floor"] == 2


def test_four_matching_entity_findings_fold_losslessly() -> None:
    rows = [
        _row(
            src=f"192.0.2.{group + 1}",
            dst=f"198.51.100.{group + 1}",
            port=443,
            service="ssh",
            ts=START.timestamp() + group * 10 + member,
        )
        for group in range(4)
        for member in range(3)
    ]
    findings = protocol.run(_context(rows))
    rollup = next(f for f in findings if f.evidence["kind"] == "rollup")
    assert rollup.title == "ssh on 443/tcp"
    assert rollup.severity is Severity.LOW
    assert rollup.evidence["member_count"] == 4
    assert len(rollup.evidence["members"]) == 4
    assert {member["src"] for member in rollup.evidence["members"]} == {
        "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4",
    }
    assert not [f for f in findings if f.evidence["kind"] == "mismatch"]
    assert_report_voice(findings)


def test_leg_b_uses_strictly_earlier_reference_and_full_flow_identity() -> None:
    rows = [
        _row(src=f"192.0.2.{index % 200 + 1}", dst="198.51.100.80", port=80,
             service="http", ts=START.timestamp() + index)
        for index in range(100)
    ]
    # Earlier traffic on another port must not make this full flow identity old.
    rows.append(_row(src="192.0.2.250", dst="198.51.100.250", port=443,
                     service="ssl", ts=START.timestamp() + 50))
    rows.append(_row(src="192.0.2.250", dst="198.51.100.250", port=80,
                     service=None, ts=START.timestamp() + 200))
    findings = protocol.run(_context(rows))
    unlabeled = [f for f in findings if f.evidence["kind"] == "unlabeled"]
    assert len(unlabeled) == 1
    assert unlabeled[0].evidence["reference_size"] == 100
    assert unlabeled[0].evidence["reference_labeled_share"] == 1.0
    assert_report_voice(findings)


def test_invalid_identity_is_outside_context_eligible_row_counts() -> None:
    rows = [_row(proto="icmp", service="ssh"), _row(port=0, service=None)]
    context = protocol.run(_context(rows))[-1]
    assert context.evidence["labeled_rows"] == 0
    assert context.evidence["unlabeled_rows"] == 0
    assert context.evidence["not_evaluable_reasons"]["identity-invalid"] == 2
    assert context.evidence["not_evaluable_reasons"]["service-not-supplied"] == 0
    assert "No eligible rows after filtering" in context.description
    assert "invalid connection identity" in context.description
    assert_report_voice([context])


def test_leg_b_same_timestamp_reference_is_not_earlier() -> None:
    stamp = START.timestamp()
    rows = [
        _row(src=f"192.0.2.{index + 1}", port=80, service="http", ts=stamp)
        for index in range(100)
    ]
    rows.append(_row(src="192.0.2.250", port=80, service=None, ts=stamp))
    assert not [f for f in protocol.run(_context(rows)) if f.evidence["kind"] == "unlabeled"]


def test_leg_b_removed_analyzer_is_neither_candidate_nor_reference() -> None:
    rows = [
        _row(src=f"192.0.2.{index + 1}", port=80, service="http,-ssl",
             ts=START.timestamp() + index)
        for index in range(100)
    ]
    rows.append(_row(src="192.0.2.250", port=80, service=None,
                     ts=START.timestamp() + 200))
    assert not [f for f in protocol.run(_context(rows)) if f.evidence["kind"] == "unlabeled"]


@pytest.mark.parametrize("history", ["Sh^ADad", "ShgDad", "ShD"])
def test_leg_b_rejects_flipped_lossy_or_incomplete_candidates(history: str) -> None:
    rows = [
        _row(src=f"192.0.2.{index % 200 + 1}", port=80, service="http",
             ts=START.timestamp() + index)
        for index in range(100)
    ]
    rows.append(_row(src="192.0.2.250", port=80, service=None,
                     history=history, ts=START.timestamp() + 200))
    assert not [f for f in protocol.run(_context(rows)) if f.evidence["kind"] == "unlabeled"]


def test_context_discloses_missing_source_inputs() -> None:
    row = _row()
    for key in list(row):
        if key.startswith("_source_has_"):
            row[key] = False
    finding = protocol.run(_context([row]))[-1]
    assert finding.severity is Severity.INFO
    assert finding.title == "what this run could evaluate"
    assert finding.evidence["leg_b"] == "service-not-supplied"
    assert finding.evidence["not_evaluable_reasons"]["service-not-supplied"] == 1
    assert "service not supplied by this input" in finding.description
    assert "leg B not evaluable" in finding.description


@pytest.mark.parametrize(
    ("overrides", "phrase"),
    [
        ({"labeled_rows": 0, "unlabeled_rows": 0}, "no eligible rows after filtering"),
        ({"labeled_rows": 0, "unlabeled_rows": 1}, "no labeled rows"),
        ({"labeled_rows": 1, "unavailable_rows": 1}, "only unavailable or ambiguous labels"),
        ({"labeled_rows": 1}, "all conformant"),
        ({"leg_b": "quality-not-supplied"}, "leg B not evaluable"),
    ],
)
def test_context_vocabulary_phrase_is_literal(overrides: dict, phrase: str) -> None:
    evidence = {
        "labeled_rows": 0, "unlabeled_rows": 0, "unavailable_rows": 0,
        "ambiguous_rows": 0, "not_evaluable_rows": 0, "pairs_below_floor": 0,
        "leg_b": "evaluated", "not_evaluable_reasons": {"identity-invalid": 0},
    }
    evidence.update(overrides)
    rendered = protocol._context_description(evidence, 0)
    assert phrase in rendered or (phrase[:1].upper() + phrase[1:]) in rendered
