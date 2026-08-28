"""Human evidence-instant display without machine-contract mutation."""

from __future__ import annotations

import copy
import io
from datetime import datetime, timezone

from sigwood.common.display import set_display_utc
from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.outputs._evidence import format_evidence_instants
from sigwood.outputs._render_model import project_row
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs.html import render_report_html
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler

_WINDOW = (
    datetime(2026, 7, 8, 9, 0, tzinfo=timezone.utc),
    datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc),
)


def _finding(detector: str, evidence: dict) -> Finding:
    return Finding(
        detector=detector,
        severity=Severity.HIGH,
        title=f"{detector} timestamp fixture",
        description="Timestamp fixture.",
        evidence=evidence,
        next_steps=["Inspect the transition"],
        ts_generated=_WINDOW[1],
        data_window=_WINDOW,
    )


def _summary(findings: list[Finding]) -> RunSummary:
    detectors = list(dict.fromkeys(finding.detector for finding in findings))
    return RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=detectors,
        detectors_skipped={},
        detector_missions={name: f"Mission for {name}." for name in detectors},
    )


def _text(findings: list[Finding], level: int) -> str:
    stream = io.StringIO()
    handler = TextHandler(
        stream=stream,
        verbose_level=level,
        max_findings_per_detector=100,
    )
    handler.begin(_summary(findings))
    handler.write(findings)
    handler.end()
    return stream.getvalue()


def _html(findings: list[Finding], level: int) -> str:
    return render_report_html(
        findings,
        _summary(findings),
        verbose_level=level,
        max_findings_per_detector=100,
    )


def _machine_bytes(handler_cls, finding: Finding) -> str:
    stream = io.StringIO()
    handler = handler_cls(stream=stream)
    handler.begin(_summary([finding]))
    handler.write([finding])
    handler.end()
    return stream.getvalue()


def _auth_finding() -> Finding:
    return _finding("auth", {
        "signal": "landing",
        "severity_basis": ["host_spread", "landing"],
        "decision_record_count": 14,
        "denial_count": 12,
        "host_count": 3,
        "span_seconds": 600.0,
        "first_seen": "2026-07-08T09:49:05+00:00",
        "landing_episodes": [{
            "first_failure_at": "2026-07-08T09:49:05+00:00",
            "success_at": "2026-07-08T09:49:47+00:00",
        }],
    })


def test_evidence_walk_is_recursive_detached_and_strictly_allow_listed(
    pin_tz, restore_display_utc,
) -> None:
    pin_tz("Etc/GMT+5")
    set_display_utc(False)
    raw = {
        "landing_episodes": ({
            "first_failure_at": "2026-07-08T09:49:05+00:00",
            "success_at": "malformed",
            "first_seen_epoch": 1783504145,
            "looks_like_time": "2026-07-08T09:49:47+00:00",
        },),
        "peak_period_start": "2026-07-08T00:00:00+00:00",
        "first_associated_period": "2026-07-07T00:00:00+00:00",
        "first_seen": 1783504145,
    }
    frozen = copy.deepcopy(raw)

    rendered = format_evidence_instants(raw)

    assert raw == frozen
    assert rendered is not raw
    assert isinstance(rendered["landing_episodes"], tuple)
    episode = rendered["landing_episodes"][0]
    assert episode["first_failure_at"] == "2026-07-08 04:49:05 local"
    assert episode["success_at"] == "malformed"
    assert episode["first_seen_epoch"] == 1783504145
    assert episode["looks_like_time"] == "2026-07-08T09:49:47+00:00"
    assert rendered["peak_period_start"] == raw["peak_period_start"]
    assert rendered["first_associated_period"] == raw["first_associated_period"]
    assert rendered["first_seen"] == 1783504145


def test_text_and_html_format_selected_and_nested_instants_at_honest_levels(
    pin_tz, restore_display_utc,
) -> None:
    pin_tz("Etc/GMT+5")
    set_display_utc(False)
    auth = _auth_finding()
    scan = _finding("scan", {
        "scan_type": "vertical",
        "scan_state_ratio": 0.95,
        "src": "192.0.2.10",
        "dst": "198.51.100.20",
        "distinct_ports": 42,
        "window_start": "2026-07-08 09:49:05",
    })

    text_v = _text([auth, scan], 1)
    html_v = _html([auth, scan], 1)
    for surface in (text_v, html_v):
        assert "2026-07-08 04:49:05 local" in surface
        assert "window_start" not in surface
        assert "first_failure_at" not in surface

    text_vv = _text([auth, scan], 2)
    html_vv = _html([auth, scan], 2)
    for surface in (text_vv, html_vv):
        assert "window_start" in surface
        assert "2026-07-08 04:49:05 local" in surface
        assert "first_failure_at" in surface
        assert "success_at" in surface
        assert "2026-07-08 04:49:47 local" in surface


def test_reading_renders_do_not_change_same_finding_json_or_csv_bytes(
    pin_tz, restore_display_utc,
) -> None:
    pin_tz("Etc/GMT+5")
    set_display_utc(False)
    finding = _auth_finding()
    frozen = copy.deepcopy(finding.evidence)
    json_before = _machine_bytes(JsonHandler, finding)
    csv_before = _machine_bytes(CsvHandler, finding)

    _text([finding], 1)
    _text([finding], 2)
    _html([finding], 1)
    _html([finding], 2)

    assert finding.evidence == frozen
    assert _machine_bytes(JsonHandler, finding) == json_before
    assert _machine_bytes(CsvHandler, finding) == csv_before
    assert "2026-07-08T09:49:05+00:00" in json_before
    assert "first_seen=2026-07-08T09:49:05+00:00" in csv_before


def test_ssl_level_zero_first_seen_uses_same_seconds_owner_and_can_vanish(
    pin_tz, restore_display_utc,
) -> None:
    pin_tz("Etc/GMT+5")
    set_display_utc(False)
    finding = _finding("ssl", {
        "src": "192.0.2.10",
        "dst": "198.51.100.20",
        "severity_basis": ["validation"],
        "conn_count": 4,
        "first_seen": "2026-07-08T09:49:05+00:00",
    })

    first = next(cell for cell in project_row(finding) if cell.key == "first")
    assert first.value == "2026-07-08 04:49:05 local"

    set_display_utc(True)
    first = next(cell for cell in project_row(finding) if cell.key == "first")
    assert first.value == "2026-07-08 09:49:05 UTC"

    finding.evidence["first_seen"] = 1783504145
    first = next(cell for cell in project_row(finding) if cell.key == "first")
    assert first.value == "1783504145"

    finding.evidence.pop("first_seen")
    first = next(cell for cell in project_row(finding) if cell.key == "first")
    assert first.value == ""
    assert first.optional is True
