"""Designed human-output regressions for the auth detector."""

from __future__ import annotations

import io
import json
import re
from html import unescape
from datetime import datetime, timezone

import pytest

from sigwood.common.finding import Finding, MethodTag, RunSummary, Severity
from sigwood.outputs._evidence import curated_evidence
from sigwood.outputs._render_model import (
    _build_renderable,
    html_cell_value,
    project_row,
    section_columns,
)
from sigwood.outputs.html import render_report_html
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler


_WINDOW = (
    datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc),
    datetime(2026, 8, 5, 1, 0, tzinfo=timezone.utc),
)
_RULE = "─" * 80


def _finding(
    signal: str,
    title: str,
    *,
    severity: Severity = Severity.MEDIUM,
    attempts: int = 18,
    failures: int = 18,
    hosts: int = 1,
    span: float = 120.0,
    basis: list[str] | None = None,
    landings: int = 0,
) -> Finding:
    evidence = {
        "signal": signal,
        "decision_record_count": attempts,
        "denial_count": failures,
        "host_count": hosts,
        "real_account_count": 0,
        "nonexistent_account_count": failures,
        "unknown_account_count": 0,
        "live_account_count": 0,
        "first_seen": "2026-08-05T00:00:00+00:00",
        "last_seen": "2026-08-05T00:02:00+00:00",
        "span_seconds": span,
        "window_coverage_pct": 3.3333333333,
        "window_spanning": False,
        "severity_basis": basis or [signal],
    }
    if landings:
        evidence["landing_episodes"] = [
            {
                "transition_id": f"transition-{index}",
                "host": f"host-{index}.example.test",
                "service": "sshd",
                "failure_count": 6,
                "first_failure_at": "2026-08-05T00:00:00+00:00",
                "success_at": "2026-08-05T00:02:00+00:00",
                "failure_run_ended": True,
            }
            for index in range(landings)
        ]
    return Finding(
        detector="auth",
        severity=severity,
        title=title,
        description="Authentication activity crossed a measured floor.",
        evidence=evidence,
        next_steps=["Review the affected service logs"],
        ts_generated=_WINDOW[1],
        data_window=_WINDOW,
    )


def _summary() -> RunSummary:
    return RunSummary(
        data_window=_WINDOW,
        record_counts={"*.log*": 18},
        data_size_bytes=0,
        detectors_run=["auth"],
        detectors_skipped={},
        detector_methods={"auth": MethodTag("heuristics", named=False)},
    )


def _render_text(findings: list[Finding], *, level: int = 0, cap: int = 100) -> str:
    stream = io.StringIO()
    TextHandler(
        stream=stream,
        verbose_level=level,
        max_findings_per_detector=cap,
    ).write(findings)
    return stream.getvalue()


def test_auth_projector_has_one_uniform_reader_grammar() -> None:
    finding = _finding(
        "host_spread",
        "alice",
        severity=Severity.HIGH,
        attempts=15,
        failures=13,
        hosts=3,
        basis=["host_spread", "landing"],
        landings=2,
    )

    assert [(cell.key, cell.value, cell.optional) for cell in project_row(finding)] == [
        (None, "alice", False),
        ("shape", "multi-host failures + success", False),
        ("failed", "13 failed / 15 records", False),
        ("hosts", "3 hosts", False),
        ("successes", "2 successes", True),
        ("span", "2m", False),
    ]


def test_auth_high_label_requires_exact_basis() -> None:
    finding = _finding(
        "host_spread",
        "192.0.2.40",
        severity=Severity.HIGH,
        basis=["host_spread"],
    )
    assert project_row(finding)[1].value == "multi-host failures"


def test_auth_partition_is_high_then_frozen_signal_order() -> None:
    findings = [
        _finding("landing", "landing"),
        _finding("host_spread", "high", severity=Severity.HIGH,
                 basis=["host_spread", "landing"], landings=1),
        _finding("account_volume", "account"),
        _finding("concentration", "concentration"),
        _finding("source_volume", "source"),
        _finding("host_spread", "spread"),
    ]
    renderable = _build_renderable("auth", findings, 0, 100)
    assert [finding.title for finding in renderable.sections[0].findings] == [
        "high", "concentration", "source", "account", "spread", "landing",
    ]
    capped = _build_renderable("auth", findings, 0, 2)
    assert [finding.title for finding in capped.sections[0].findings] == [
        "high", "concentration",
    ]
    assert capped.cap_truncated == 4


_AUTH_VARIANTS = {
    "concentration": _finding("concentration", "host-a.example.test · sshd"),
    "source_volume": _finding("source_volume", "192.0.2.41"),
    "account_volume": _finding("account_volume", "high-volume authentication failures"),
    "host_spread": _finding("host_spread", "192.0.2.42", hosts=3),
    "landing": _finding("landing", "alice", landings=1),
    "high": _finding(
        "host_spread",
        "alice",
        severity=Severity.HIGH,
        attempts=15,
        failures=13,
        hosts=3,
        basis=["host_spread", "landing"],
        landings=2,
    ),
}


@pytest.mark.parametrize("variant", list(_AUTH_VARIANTS))
def test_auth_row_signal_parity_text_and_html(variant: str) -> None:
    finding = _AUTH_VARIANTS[variant]
    text = _render_text([finding])
    raw_html = render_report_html(
        [finding], _summary(), verbose_level=0, max_findings_per_detector=100,
    )
    visible_html = unescape(re.sub(r"<[^>]+>", " ", raw_html))
    checked = 0
    for cell in project_row(finding):
        if not cell.value:
            continue
        assert cell.value in text
        assert html_cell_value(cell) in visible_html
        checked += 1
    assert checked == (6 if finding.evidence.get("landing_episodes") else 5)


def test_auth_related_count_is_reader_visible_and_vanishes_when_absent() -> None:
    related = _finding("host_spread", "192.0.2.42", hosts=3)
    related.evidence["overlaps"] = [
        {"signal": "source_volume", "title": "192.0.2.42"},
        {"signal": "account_volume", "title": "alice"},
    ]
    control = _finding("host_spread", "192.0.2.43", hosts=3)

    related_cells = project_row(related)
    assert ("related", "2 related", True) in [
        (cell.key, cell.value, cell.optional) for cell in related_cells
    ]
    assert all(cell.key != "related" for cell in project_row(control))
    mixed = _build_renderable("auth", [related, control], 0, 100)
    assert [column.key for column in section_columns(mixed.sections[0])][-2:] == [
        "span",
        "related",
    ]

    text = _render_text([related])
    raw_html = render_report_html(
        [related], _summary(), verbose_level=0, max_findings_per_detector=100,
    )
    visible_html = unescape(re.sub(r"<[^>]+>", " ", raw_html))
    related_cell = next(cell for cell in related_cells if cell.key == "related")
    assert related_cell.value in text
    assert ">related</th>" in raw_html
    assert html_cell_value(related_cell) in visible_html

    control_html = render_report_html(
        [control], _summary(), verbose_level=0, max_findings_per_detector=100,
    )
    assert ">related</th>" not in control_html

    mixed_text = _render_text([related, control])
    mixed_html = render_report_html(
        [related, control],
        _summary(),
        verbose_level=0,
        max_findings_per_detector=100,
    )
    assert mixed_text.count("2 related") == 1
    assert mixed_html.count(">related</th>") == 1
    assert all(line == line.rstrip() for line in mixed_text.splitlines())


def test_golden_auth_mixed_rows() -> None:
    findings = [
        _finding("source_volume", "192.0.2.44"),
        _finding(
            "host_spread",
            "alice",
            severity=Severity.HIGH,
            attempts=15,
            failures=13,
            hosts=3,
            basis=["host_spread", "landing"],
            landings=2,
        ),
        _finding(
            "concentration", "host-a.example.test · sshd",
            attempts=100, failures=100,
        ),
    ]

    assert _render_text(findings) == (
        f"\nauth - 3 findings · 1 H  2 M\n{_RULE}\n"
        "[H]   alice                       multi-host failures + success    13 failed / 15 records  3 hosts  2 successes  2m\n"
        "[M]   host-a.example.test · sshd  concentrated failures          100 failed / 100 records   1 host               2m\n"
        "[M]   192.0.2.44                  source volume                    18 failed / 18 records   1 host               2m\n\n"
    )


def test_auth_curated_evidence_is_small_and_identity_free() -> None:
    finding = _finding("account_volume", "high-volume authentication failures")
    finding.evidence.update(
        {
            "account": "<script>attacker</script>",
            "account_namespace": "preauth_username",
            "source": "192.0.2.90",
            "host": "host-a.example.test",
            "service": "sshd",
            "last_seen": "2026-08-05T00:02:00+00:00",
        }
    )

    assert list(curated_evidence(finding)) == [
        "severity_basis",
        "decision_record_count",
        "denial_count",
        "host_count",
        "first_seen",
        "span_seconds",
        "window_coverage_pct",
        "window_spanning",
    ]
    level_one = _render_text([finding], level=1)
    assert "<script>attacker</script>" not in level_one
    assert "192.0.2.90" not in level_one
    assert "host-a.example.test" not in level_one


def test_auth_html_consumes_projection_and_existing_house_method_chip() -> None:
    finding = _finding("landing", "alice", landings=1)
    rendered = render_report_html(
        [finding], _summary(), verbose_level=0, max_findings_per_detector=100,
    )

    for header in ("shape", "failed", "hosts", "successes", "span"):
        assert f">{header}</th>" in rendered
    assert "failures then success" in rendered
    assert '<span class="chip chip-house">auth [heuristics]</span>' in rendered
    assert '<span class="chip chip-named">auth' not in rendered
    assert "\x1b" not in rendered


def test_auth_json_remains_lossless_and_verbosity_invariant() -> None:
    finding = _finding("account_volume", "high-volume authentication failures")
    finding.evidence["account"] = "<script>attacker</script>\x1b[31m"
    payloads = []
    for level in (0, 1, 2):
        stream = io.StringIO()
        handler = JsonHandler(stream=stream, verbose_level=level)
        handler.begin(_summary())
        handler.write([finding])
        handler.end()
        payloads.append(json.loads(stream.getvalue()))

    evidence = payloads[0]["findings"][0]["evidence"]
    assert evidence == finding.evidence
    assert all(payload["findings"] == payloads[0]["findings"] for payload in payloads)
