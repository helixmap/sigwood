"""Tests for the private, runner-observed Lane A rate-baseline measurement."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

from sigwood import runner
from sigwood.common import config as cfg
from sigwood.common.finding import Finding, Severity
from tools import measure_syslog_rate_baseline as measure


_WIDTH = 15 * 60


def _observation(
    counts: list[int],
    *,
    start: float = -900.0,
    findings: tuple[Finding, ...] = (),
) -> measure._RunObservation:
    rows: list[dict[str, object]] = []
    for index, count in enumerate(counts):
        for offset in range(count):
            rows.append({
                "ts": start + index * _WIDTH + 700 + (offset / 1000),
                "host": "host-a",
                "program": "app",
            })
    return measure._RunObservation(
        frame=pd.DataFrame(rows),
        window_start=start,
        window_end=start + len(counts) * _WIDTH,
        findings=findings,
    )


def _finding(*, start: float, end: float) -> Finding:
    return Finding(
        detector="syslog",
        severity=Severity.LOW,
        title="private text never leaves the measurement",
        description="",
        evidence={
            "tier": "family",
            "host": "host-a",
            "program": "app",
            "start_ts": start,
            "end_ts": end,
        },
        next_steps=[],
        ts_generated=datetime.now(timezone.utc),
        data_window=(datetime.now(timezone.utc), datetime.now(timezone.utc)),
    )


def _variable_counts(*, spike_index: int, spike_count: int) -> list[int]:
    counts = [1 + (index % 3) for index in range(24)]
    counts[spike_index] = spike_count
    return counts


def test_measurement_requires_both_origins_and_records_nonredundant_episode() -> None:
    result = measure._measure_observation(
        _observation(_variable_counts(spike_index=12, spike_count=20)),
        cohort="frozen-week",
    )

    assert result["l2"] == {
        "surfaced_streams": 1,
        "eligible_streams": 1,
        "surface_fraction": 1.0,
    }
    assert result["l3"] == {
        "unmatched_episodes": 1,
        "passes_nonredundancy": True,
    }
    assert result["l4"] == {
        "cohort": "frozen-week",
        "existing_default_visible": 0,
        "additional_episodes": 1,
        "stop_rule_limit": 7,
        "passes": True,
        "excess_is_failure_not_cap": True,
    }
    assert result["scales"]["15m"]["candidate_episodes"] == 1


def test_first_nonempty_candidate_is_an_explicit_abstention() -> None:
    result = measure._measure_observation(
        _observation(_variable_counts(spike_index=0, spike_count=20)),
        cohort="frozen-week",
    )

    assert result["l4"]["additional_episodes"] == 0
    assert result["scales"]["15m"]["abstentions"]["all_first_bin_streams"] == 1


def test_zero_mad_stream_abstains_without_an_epsilon() -> None:
    result = measure._measure_observation(
        _observation([2] * 24), cohort="frozen-week",
    )

    assert result["l4"]["additional_episodes"] == 0
    assert result["scales"]["15m"]["abstentions"]["steady_or_zero_mad_streams"] == 1
    assert result["scales"]["15m"]["near_miss"]["max_deviation"] is None


def test_near_miss_distribution_reports_a_single_bar_stream() -> None:
    result = measure._measure_observation(
        _observation(_variable_counts(spike_index=12, spike_count=7)),
        cohort="frozen-week",
    )

    near_miss = result["scales"]["15m"]["near_miss"]
    assert near_miss["streams_clearing_one_bar"] == 1
    assert near_miss["streams_clearing_two_bars"] == 0
    assert near_miss["streams_clearing_all_three_bars"] == 0
    assert near_miss["max_deviation"] is not None
    assert near_miss["max_ratio"] is not None


def test_l3_counts_matching_existing_syslog_finding_as_redundant() -> None:
    counts = _variable_counts(spike_index=12, spike_count=20)
    start = -900 + 12 * _WIDTH
    result = measure._measure_observation(
        _observation(counts, findings=(_finding(start=start, end=start + _WIDTH),)),
        cohort="frozen-week",
    )

    assert result["l3"] == {
        "unmatched_episodes": 0,
        "passes_nonredundancy": False,
    }
    assert result["l4"]["existing_default_visible"] == 1


def test_l4_stop_rule_is_not_a_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    episodes = [
        measure._Episode("host-a", f"app-{index}", float(index), float(index + 1))
        for index in range(8)
    ]
    monkeypatch.setattr(
        measure,
        "_measure_scale",
        lambda *_args, **_kwargs: (episodes, {"candidate_episodes": len(episodes)}),
    )

    result = measure._measure_observation(
        _observation(_variable_counts(spike_index=12, spike_count=20)),
        cohort="frozen-week",
    )
    assert result["l4"]["additional_episodes"] == 8
    assert result["l4"]["stop_rule_limit"] == 7
    assert result["l4"]["passes"] is False
    assert result["l4"]["excess_is_failure_not_cap"] is True


def test_l3_matches_transaction_program_mix_on_its_stored_interval() -> None:
    counts = _variable_counts(spike_index=12, spike_count=20)
    start = -900 + 12 * _WIDTH
    finding = _finding(start=start, end=start + _WIDTH)
    finding.evidence.pop("program")
    finding.evidence["tier"] = "transaction"
    finding.evidence["program_mix"] = [["app", 20]]
    result = measure._measure_observation(
        _observation(counts, findings=(finding,)), cohort="frozen-week",
    )

    assert result["l3"]["passes_nonredundancy"] is False


def test_eligibility_reports_each_exclusion_reason_without_identity_leakage() -> None:
    frame = pd.DataFrame([
        {"ts": 1.0, "host": "host-a", "program": "app"},
        {"ts": float("nan"), "host": "host-a", "program": "app"},
        {"ts": 2.0, "host": "", "program": "app"},
        {"ts": 3.0, "host": "host-a", "program": ""},
        {"ts": 4.0, "host": "host-a", "program": "unknown"},
    ])

    eligible, reasons = measure._eligible_frame(frame)

    assert len(eligible) == 1
    assert reasons == {
        "nonfinite_timestamp": 1,
        "missing_host": 1,
        "missing_program": 1,
        "unknown_program": 1,
    }


def _config(tmp_path: Path) -> Path:
    config_file = tmp_path / "freeze.toml"
    config_file.write_text(
        "\n".join((
            "[sigwood]",
            f'root = "{tmp_path}"',
            'default_window = ""',
            'syslog_source = "off"',
            "warn_above = 0",
            "",
            "[allowlist]",
            "enabled = true",
        )),
        encoding="utf-8",
    )
    return config_file


def _zeek_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "zeek"
    directory.mkdir()
    rows: list[dict[str, object]] = []
    for index, count in enumerate(_variable_counts(spike_index=12, spike_count=20)):
        for offset in range(count):
            rows.append({
                "_path": "syslog",
                "ts": 1_784_376_000 + index * _WIDTH + 700 + (offset / 1000),
                "uid": f"C{index}_{offset}",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 40001,
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 514,
                "proto": "udp",
                "facility": "DAEMON",
                "severity": "INFO",
                "message": "Jul 21 12:00:00 host-a app[101]: repeated sample",
            })
    (directory / "syslog.log").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8",
    )
    return directory


def _product_payload(config: dict, zeek: Path) -> dict[str, object]:
    report = zeek.parent / "product.json"
    assert runner.run(
        config,
        detect="syslog",
        zeek_dir=zeek,
        scope=frozenset({"zeek_dir"}),
        output_format="json",
        output_file=report,
        load_all=True,
        quiet=True,
        syslog_source="off",
    ) == 0
    return json.loads(report.read_text(encoding="utf-8"))


def test_runner_observation_is_aggregate_only_and_preserves_safe_cli_errors(
    tmp_path: Path, capsys,
) -> None:
    config_file = _config(tmp_path)
    zeek = _zeek_dir(tmp_path)
    config = cfg.load(config_file)
    before = _product_payload(config, zeek)
    observed = measure.observe_rate_baseline(
        config,
        syslog_dir=None,
        zeek_dir=zeek,
        since=None,
        until=None,
        load_all=True,
        no_allowlist=False,
        cohort="frozen-week",
    )
    after = _product_payload(config, zeek)

    assert after["findings"] == before["findings"]
    assert observed["eligibility"]["eligible_rows"] > 0

    assert measure.main([
        "--config", str(config_file), "--zeek-dir", str(zeek), "--all",
        "--cohort", "frozen-week",
    ]) == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["kind"] == "syslog_rate_baseline_measurement"
    assert payload["interpretation"] == (
        "deliberately conservative diagnostic constants, not a claimed production calibration"
    )
    assert "host-a" not in output
    assert "repeated sample" not in output

    missing = tmp_path / "not-present.toml"
    assert measure.main([
        "--config", str(missing), "--zeek-dir", str(zeek), "--cohort", "frozen-week",
    ]) == 2
    error = capsys.readouterr().err
    assert error == "measure-syslog-rate-baseline: could not read the config\n"
    assert str(missing) not in error
    assert cfg.load(config_file)["sigwood"]["syslog_source"] == "off"
