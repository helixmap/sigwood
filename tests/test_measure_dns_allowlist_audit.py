"""Tests for the private, runner-observed DNS below-gate allowlist audit."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigwood import runner
from sigwood.detectors import dns as dns_mod
from tools import measure_dns_allowlist_audit as measure


_UNTIL = datetime(2026, 7, 28, tzinfo=timezone.utc)
_PARENT = "audit.example.com"
_LETTERS = ("bcdfghjklmnpqrst", "cdfghjklmnpqrstv", "dfghjklmnpqrstvw",
            "fghjklmnpqrstvwz", "ghjklmnpqrstvwzb")
_HIGH_LABEL = "0123456789bcdfgh"


def _dns_record(ts: float, query: str, *, rcode: int) -> dict[str, object]:
    return {
        "_path": "dns",
        "ts": ts,
        "uid": f"D{int(ts * 1000)}",
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 53000,
        "id.resp_h": "198.51.100.53",
        "id.resp_p": 53,
        "proto": "udp",
        "query": query,
        "qtype": 1,
        "rcode": rcode,
        "rtt": 0.05,
        "TTLs": [60.0],
    }


def _zeek_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "zeek"
    directory.mkdir()
    records: list[dict[str, object]] = []
    # Four children are in the nested day; the fifth makes the 7d arm, not 1d,
    # reach the below-gate promotion's live distinct-child floor.
    for index, label in enumerate(_LETTERS):
        when = _UNTIL - (timedelta(hours=12 + index) if index < 4 else timedelta(days=6))
        records.append(_dns_record(
            when.timestamp(), f"{label}.{_PARENT}", rcode=3,
        ))
    # The real Zeek clustering path receives a population at its configured
    # 2,000-row floor. These high-scoring filler rows cannot promote below the gate.
    for index in range(2_000):
        records.append(_dns_record(
            (_UNTIL - timedelta(hours=1, seconds=index / 10_000)).timestamp(),
            f"{_HIGH_LABEL}.noise.example.net", rcode=0,
        ))
    (directory / "dns.log").write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8",
    )
    return directory


def _config(tmp_path: Path, *, suppress_below_gate: bool) -> dict[str, object]:
    patterns: list[str] = []
    if suppress_below_gate:
        patterns_file = tmp_path / "audit-patterns.txt"
        patterns_file.write_text("*.audit.example.com\n", encoding="utf-8")
        patterns.append(str(patterns_file))
    return {
        "sigwood": {
            "root": str(tmp_path),
            "default_window": "",
            "warn_above": 0,
            "syslog_source": "off",
        },
        "allowlist": {
            "enabled": True,
            "allowlist_dir": "",
            "domain_patterns": patterns,
            "connection_rules": [],
        },
    }


def _product_payload(config: dict[str, object], zeek_dir: Path) -> dict[str, object]:
    report = zeek_dir.parent / "product.json"
    assert runner.run(
        config,
        detect="default",
        zeek_dir=zeek_dir,
        scope=frozenset({"zeek_dir"}),
        since=_UNTIL - timedelta(days=7),
        until=_UNTIL,
        output_format="json",
        output_file=report,
        load_all=True,
        quiet=True,
        syslog_source="off",
    ) == 0
    return json.loads(report.read_text(encoding="utf-8"))


def _stable_findings(payload: dict[str, object]) -> list[dict[str, object]]:
    """Drop runner-clock provenance before comparing product behavior."""
    findings = payload["findings"]
    assert isinstance(findings, list)
    return [
        {key: value for key, value in finding.items() if key != "ts_generated"}
        for finding in findings
        if isinstance(finding, dict)
    ]


def test_real_runner_audit_exercises_below_gate_and_keeps_output_aggregate_only(tmp_path: Path) -> None:
    config = _config(tmp_path, suppress_below_gate=True)
    zeek_dir = _zeek_dir(tmp_path)
    before = _product_payload(config, zeek_dir)

    record = measure.observe_below_gate_audit(config, zeek_dir=zeek_dir, until=_UNTIL)

    after = _product_payload(config, zeek_dir)
    assert _stable_findings(after) == _stable_findings(before)
    assert all(dns_mod.entropy(label) < 1.8 for label in _LETTERS)
    assert record["kind"] == "dns_below_gate_allowlist_audit"

    on = record["arms"]["configured_allowlist"]
    off = record["arms"]["no_allowlist"]
    assert on["7d"]["below_gate_parent_count"] == 0
    assert off["1d"]["below_gate_parent_count"] == 0
    assert off["7d"]["below_gate_parent_count"] == 1
    assert off["7d"]["below_gate_info_parent_count"] == 1
    assert off["7d"]["funnel"]["returned_funnel_parity"] is True
    assert off["7d"]["clustering"] == {
        "status": "ran",
        "input_rows": 2_005,
        "min_cluster_size": 2_000,
        "meets_min_cluster_size": True,
    }
    assert record["window_comparison"]["no_allowlist"] == {
        "one_day_only": 0,
        "seven_day_only": 1,
        "both": 0,
        "status": "comparable",
        "reason": "both_arms_ran_with_at_least_min_cluster_size_rows",
    }
    assert record["l4"]["additional_below_gate_parents"] == 1
    assert record["l4"]["excess_is_failure_not_cap"] is True

    encoded = json.dumps(record, sort_keys=True)
    assert _PARENT not in encoded
    assert _LETTERS[0] not in encoded
    assert "192.0.2.10" not in encoded
    assert str(zeek_dir) not in encoded


def test_l4_failure_keeps_the_full_count_and_zero_denominator_is_not_lenient() -> None:
    primary = measure._ArmMeasurement(
        record={"same_arm_visible_defaults_excluding_below_gate": 0},
        below_gate_parents=frozenset({f"parent-{index}" for index in range(8)}),
    )

    l4 = measure._l4_record(primary)

    assert l4["additional_below_gate_parents"] == 8
    assert l4["existing_default_visible_excluding_below_gate"] == 0
    assert l4["parent_limit"] == 7
    assert l4["additional_fraction"] is None
    assert l4["passes"] is False
    assert l4["excess_is_failure_not_cap"] is True


def test_window_comparison_marks_a_subfloor_cluster_arm_confounded() -> None:
    small = measure._ArmMeasurement(
        record={"clustering": {
            "status": "ran", "input_rows": 100, "min_cluster_size": 2_000,
            "meets_min_cluster_size": False,
        }},
        below_gate_parents=frozenset({"one"}),
    )
    large = measure._ArmMeasurement(
        record={"clustering": {
            "status": "ran", "input_rows": 2_000, "min_cluster_size": 2_000,
            "meets_min_cluster_size": True,
        }},
        below_gate_parents=frozenset({"one", "seven"}),
    )

    comparison = measure._window_comparison(small, large)

    assert comparison["status"] == "confounded"
    assert comparison["reason"] == "one_or_more_arms_did_not_meet_the_clustering_population_floor"
    assert comparison["seven_day_only"] == 1


def test_observer_releases_dns_frame_and_findings_after_aggregating() -> None:
    frame = measure.pd.DataFrame({
        "query": ["short.audit.example.com"],
        "rcode": [3],
    })
    context = SimpleNamespace(
        logs={"dns*.log*": frame},
        data_window=(_UNTIL - timedelta(days=1), _UNTIL),
        config={"min_cluster_size": 2_000},
    )
    finding = SimpleNamespace(
        detector="dns",
        evidence={"tier": "below_gate_group", "registrable_domain": _PARENT},
        severity=measure.Severity.INFO,
        title=_PARENT,
    )

    def fake_run(_context):
        return [finding]

    original = measure.detector.run
    measure.detector.run = fake_run
    try:
        with measure._observe_dns_run() as observations:
            assert measure.detector.run(context) == [finding]
    finally:
        measure.detector.run = original

    assert len(observations) == 1
    observation = observations[0]
    assert not hasattr(observation, "frame")
    assert not hasattr(observation, "findings")
    assert observation.below_gate_parents == frozenset({_PARENT})
    assert observation.below_gate_info_parent_count == 1
    assert observation.funnel["returned_below_gate_parents"] == 1


def test_main_keeps_argument_and_config_errors_path_free(
    tmp_path: Path, capsys, monkeypatch,
) -> None:
    with pytest.raises(SystemExit) as invalid:
        measure.main([])
    assert invalid.value.code == 2
    assert capsys.readouterr().err == "measure-dns-allowlist-audit: invalid arguments\n"

    missing = tmp_path / "private-config.toml"
    assert measure.main(["--config", str(missing), "--zeek-dir", str(tmp_path),
                         "--until", "2026-07-28T00:00:00+00:00"]) == 2
    error = capsys.readouterr().err
    assert error == "measure-dns-allowlist-audit: could not read the config\n"
    assert str(missing) not in error

    assert measure.main(["--config", str(missing), "--zeek-dir", str(tmp_path),
                         "--until", "2026-07-28T00:00:00"]) == 2
    error = capsys.readouterr().err
    assert error == "measure-dns-allowlist-audit: an end-time timezone offset is required\n"
    assert str(tmp_path) not in error

    monkeypatch.setattr(measure.cfg, "load", lambda _path: {})

    def fail_measurement(*_args, **_kwargs):
        raise measure.MeasurementError("runner measurement did not complete")

    monkeypatch.setattr(measure, "observe_below_gate_audit", fail_measurement)
    assert measure.main(["--config", str(missing), "--zeek-dir", str(tmp_path),
                         "--until", "2026-07-28T00:00:00+00:00"]) == 2
    assert capsys.readouterr().err == (
        "measure-dns-allowlist-audit: runner measurement did not complete\n"
    )
