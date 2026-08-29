"""Shipped detector missions and legacy plugin compatibility."""

from __future__ import annotations

import html
import importlib
import io
import re
import sys
from datetime import datetime, timezone

from sigwood import runner
from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.common.display import TEXT_RULE, TEXT_RULE_WIDTH
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs.html import render_report_html
from sigwood.outputs.json import JsonHandler
from sigwood.outputs.text import TextHandler


_NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)

_EXPECTED_SHIPPED_MISSIONS = {
    "auth": (
        "Finds failed logins concentrated around a source, account, service, or set "
        "of hosts, including a success after a sustained run of failures."
    ),
    "aws": (
        "Finds CloudTrail principals whose activity stands out in the loaded window, "
        "or that add several first-seen actions close together. You decide how far a "
        "principal must stand out, and how many actions count as several."
    ),
    "beacon": (
        "Finds outbound connections that keep a regular rhythm, a pattern worth "
        "checking for automated check-ins. You decide how strict the rhythm has to be "
        "before it surfaces."
    ),
    "dns": (
        "Finds domain names that stand apart from the rest, including machine-generated-"
        "looking names of the sort malware uses for disposable command domains, and "
        "large batches of related lookups. You decide how machine-generated a name must "
        "look, and how large a batch of lookups counts."
    ),
    "dnsblock": (
        "Finds clients newly or suddenly busy against names your own blocklists already "
        "block."
    ),
    "exfil": (
        "Finds large outbound transfers to hosts outside your network. You decide how "
        "big a transfer has to be to count as large."
    ),
    "scan": (
        "Finds one host reaching for many ports or many hosts - the shape of something "
        "looking around. You decide how many ports or hosts count as many."
    ),
    "ssl": "Finds outbound TLS sessions whose setup looks unlike the rest of your estate.",
    "syslog": (
        "Finds rare log patterns and recorded reboots or administrative runs, so changes "
        "on a machine do not disappear into routine logs. You decide how seldom a pattern "
        "must appear to count as rare."
    ),
}

_BANNED_MISSION_VOCABULARY = (
    "configured",
    "threshold",
    "floor",
    "minimum",
    "scored by entropy",
)


def _finding(detector: str, *, kind: str | None = None) -> Finding:
    evidence = {} if kind is None else {"kind": kind, "pair_count": 1}
    return Finding(
        detector=detector,
        severity=Severity.INFO if kind == "recurring_activity" else Severity.LOW,
        title=f"synthetic {detector} finding",
        description="",
        evidence=evidence,
        next_steps=[],
        ts_generated=_NOW,
        data_window=(_NOW, _NOW),
    )


def _summary(*names: str, missions: dict[str, str] | None = None) -> RunSummary:
    return RunSummary(
        data_window=(_NOW, _NOW),
        record_counts={},
        data_size_bytes=0,
        detectors_run=list(names),
        detectors_skipped={},
        detector_missions=(
            missions
            if missions is not None
            else {name: f"Mission for {name}." for name in names}
        ),
        generated_at=_NOW,
    )


def test_shipped_inventory_has_one_nonempty_mission_per_available_detector() -> None:
    detectors = runner.discover_detectors()

    assert set(detectors) == {
        "auth", "aws", "beacon", "dns", "dnsblock", "exfil", "scan", "ssl", "syslog",
    }
    assert all(
        isinstance(module.DETECTOR_MISSION, str) and module.DETECTOR_MISSION.strip()
        for module in detectors.values()
    )


def test_all_nine_shipped_missions_are_exact_plain_rendered_surfaces() -> None:
    detectors = runner.discover_detectors()
    actual = {
        name: module.DETECTOR_MISSION
        for name, module in detectors.items()
    }

    assert actual == _EXPECTED_SHIPPED_MISSIONS
    for mission in actual.values():
        lowered = mission.casefold()
        assert all(
            re.search(rf"\b{re.escape(word)}\b", lowered) is None
            for word in _BANNED_MISSION_VOCABULARY
        )

    for mission in actual.values():
        finding = _finding("probe")
        summary = _summary("probe", missions={"probe": mission})
        stream = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=1)
        handler.begin(summary)
        handler.write([finding])
        handler.end()
        flattened_text = " ".join(stream.getvalue().splitlines())
        rendered_html = render_report_html(
            [finding], summary, verbose_level=1, max_findings_per_detector=100,
        )
        assert mission in flattened_text
        assert html.escape(mission) in rendered_html


def test_legacy_missionless_dropin_coexists_with_the_shipped_inventory(
    tmp_path, monkeypatch,
) -> None:
    dropins = tmp_path / "dropins"
    dropins.mkdir()
    (dropins / "legacy_probe.py").write_text(
        "\n".join([
            'DETECTOR_NAME = "legacy_probe"',
            'STATUS = "available"',
            'IN_DEFAULT_HUNT = False',
            'REQUIRED_LOGS = []',
            'OPTIONAL_LOGS = []',
            'DEFAULT_CONFIG = {}',
            'def run(context):',
            '    return []',
        ]) + "\n",
        encoding="utf-8",
    )
    package = runner._detectors_pkg
    module_name = f"{package.__name__}.legacy_probe"
    monkeypatch.setattr(package, "__path__", [*package.__path__, str(dropins)])
    importlib.invalidate_caches()
    sys.modules.pop(module_name, None)

    try:
        detectors = runner.discover_detectors()
        assert set(detectors) == {
            "auth", "aws", "beacon", "dns", "dnsblock", "exfil",
            "legacy_probe", "scan", "ssl", "syslog",
        }
        assert not hasattr(detectors["legacy_probe"], "DETECTOR_MISSION")
    finally:
        sys.modules.pop(module_name, None)


def test_missionless_plugin_keeps_summary_and_renderers_compatible() -> None:
    finding = _finding("probe")
    summary = _summary("probe", missions={})

    stream = io.StringIO()
    handler = TextHandler(stream=stream)
    handler.begin(summary)
    handler.write([finding])
    handler.end()
    text_lines = stream.getvalue().splitlines()
    header_index = next(
        index for index, line in enumerate(text_lines)
        if line.startswith("probe - 1 finding")
    )

    assert text_lines[header_index + 1] == TEXT_RULE

    html = render_report_html(
        [finding], summary, verbose_level=0, max_findings_per_detector=100,
    )
    assert (
        '<div class="group-head"><span class="group-name">probe</span>'
        '<span class="group-tail"> - 1 finding'
        in html
    )
    assert 'class="mission"' not in html


def test_text_renders_each_mission_once_below_its_group_at_every_level() -> None:
    findings = [_finding("beacon"), _finding("scan")]
    summary = _summary("beacon", "scan")

    for level in (0, 1, 2):
        stream = io.StringIO()
        handler = TextHandler(stream=stream, verbose_level=level)
        handler.begin(summary)
        handler.write(findings)
        handler.end()
        lines = stream.getvalue().splitlines()
        for name in ("beacon", "scan"):
            mission = f"Mission for {name}."
            header_index = next(
                index for index, line in enumerate(lines)
                if line.startswith(f"{name} - 1 finding")
            )
            rule_index = lines.index(TEXT_RULE, header_index + 1)
            mission_lines = lines[header_index + 1:rule_index]
            assert " ".join(mission_lines) == mission
            assert " ".join(lines).count(mission) == 1


def test_text_wraps_a_long_exact_mission_inside_the_80_column_frame() -> None:
    finding = _finding("beacon")
    mission = (
        "Finds domain names and query patterns that stand apart from the rest, "
        "including generated-looking names and dense groups that can accompany "
        "automated traffic."
    )
    summary = _summary("beacon", missions={"beacon": mission})

    stream = io.StringIO()
    handler = TextHandler(stream=stream)
    handler.begin(summary)
    handler.write([finding])
    handler.end()

    lines = stream.getvalue().splitlines()
    header_index = next(
        index for index, line in enumerate(lines)
        if line.startswith("beacon - 1 finding")
    )
    rule_index = lines.index(TEXT_RULE, header_index + 1)
    mission_lines = lines[header_index + 1:rule_index]

    assert len(mission_lines) == 2
    assert all(0 < len(line) <= TEXT_RULE_WIDTH for line in mission_lines)
    assert " ".join(mission_lines) == mission
    assert " ".join(lines).count(mission) == 1


def test_html_renders_escaped_mission_once_below_group_at_every_level() -> None:
    finding = _finding("beacon")
    mission = "Finds <script>alert(1)</script> & keeps it inert."
    summary = _summary("beacon", missions={"beacon": mission})

    for level in (0, 1, 2):
        rendered = render_report_html(
            [finding], summary, verbose_level=level,
            max_findings_per_detector=100,
        )
        escaped = "Finds &lt;script&gt;alert(1)&lt;/script&gt; &amp; keeps it inert."
        assert rendered.count(f'<div class="mission">{escaped}</div>') == 1
        assert mission not in rendered
        assert rendered.index('<div class="group-head">') < rendered.index(
            '<div class="mission">'
        ) < rendered.index('<table class="findings-table">')


def test_mission_vanishes_with_a_level_hidden_group() -> None:
    recurring = _finding("dnsblock", kind="recurring_activity")
    summary = _summary("dnsblock")

    text_stream = io.StringIO()
    text_handler = TextHandler(stream=text_stream, verbose_level=0)
    text_handler.begin(summary)
    text_handler.write([recurring])
    text_handler.end()
    html = render_report_html(
        [recurring], summary, verbose_level=0, max_findings_per_detector=100,
    )
    assert "Mission for dnsblock." not in text_stream.getvalue()
    assert 'class="mission"' not in html


def test_mission_chrome_is_absent_from_frozen_json_and_csv_at_every_level() -> None:
    finding = _finding("beacon")
    outputs: dict[str, list[str]] = {"json": [], "csv": []}

    for level in (0, 1, 2):
        summary = _summary(
            "beacon",
            missions={"beacon": f"Mission sentinel at level {level}."},
        )
        for name, handler_type in (("json", JsonHandler), ("csv", CsvHandler)):
            stream = io.StringIO()
            handler = handler_type(stream=stream, verbose_level=level)
            handler.begin(summary)
            handler.write([finding])
            handler.end()
            output = stream.getvalue()
            assert "Mission sentinel" not in output
            outputs[name].append(output)

    assert len(set(outputs["json"])) == 1
    assert len(set(outputs["csv"])) == 1
