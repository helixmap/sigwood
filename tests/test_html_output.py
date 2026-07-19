"""HTML handler - the designed, self-contained reading report."""

from __future__ import annotations

import io
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigwood.common.finding import Finding, MethodTag, RunSummary, Severity
from sigwood.outputs.html import HtmlHandler, render_report_html


def test_html_handler_requires_a_target() -> None:
    """A bare construction (neither stream nor output_path) is a caller misuse -
    fail fast at construction with an actionable error, never a raw AttributeError
    in end()'s file write."""
    with pytest.raises(ValueError, match="requires a stream or an output_path"):
        HtmlHandler()

_W = (
    datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
    datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
)


def _summary(**kw) -> RunSummary:
    base = dict(
        data_window=_W,
        record_counts={"conn*.log*": 3},
        data_size_bytes=2048,
        detectors_run=["beacon", "aws"],
        detectors_skipped={"dns": "no dns.log"},
        notes=["a disclosure note"],
        detector_methods={
            "beacon": MethodTag("FFT", True),
            "aws": MethodTag("statistical", False),
        },
    )
    base.update(kw)
    return RunSummary(**base)


def _finding(
    detector: str = "beacon",
    severity: Severity = Severity.HIGH,
    title: str = "192.0.2.10 → 192.0.2.20:443/tcp",
    evidence: dict | None = None,
    description: str = "A regular beat.",
    next_steps: list[str] | None = None,
) -> Finding:
    return Finding(
        detector=detector,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence if evidence is not None else {"beacon_score": 0.61},
        next_steps=next_steps if next_steps is not None else ["Inspect the flow"],
        ts_generated=datetime(2026, 6, 1, 18, 0, tzinfo=timezone.utc),
        data_window=_W,
    )


def _render(findings, *, verbose_level=0, cap=100) -> str:
    return render_report_html(
        findings, _summary(), verbose_level=verbose_level, max_findings_per_detector=cap
    )


_DATA_CONTROLS = ("\x1b", "\x00", "\x07", "\r", "\x9b")


def _assert_no_data_controls(value: str) -> None:
    for ch in _DATA_CONTROLS:
        assert ch not in value


# ── self-containment ─────────────────────────────────────────────────────────
def test_no_external_resources() -> None:
    out = _render([_finding()])
    # No remote resource-loading vectors (NOT a blanket no-http grep).
    for needle in ("<link", "<script", "@import", "url(http", " src=", " href="):
        assert needle not in out


def test_url_in_evidence_is_inert_text_not_a_link() -> None:
    out = _render(
        [_finding(evidence={"endpoint": "http://192.0.2.50/c2"})], verbose_level=2
    )
    assert "http://192.0.2.50/c2" in out  # present as inert escaped text
    assert "href=" not in out             # but never turned into a link


# ── escaping (security) ──────────────────────────────────────────────────────
def test_script_in_evidence_renders_inert() -> None:
    out = _render(
        [_finding(evidence={"payload": "<script>alert(1)</script>"})], verbose_level=2
    )
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "<script>alert(1)</script>" not in out


def test_title_with_markup_is_escaped() -> None:
    # dns singleton: the domain bare cell IS finding.title - a markup domain must
    # be escaped (the _esc choke point routes every Cell.value through it).
    out = _render([_finding(
        detector="dns", title="<b>x</b>",
        evidence={"source": "zeek", "label_score": 1.0, "query_count": 1, "unique_sources": 1},
    )])
    assert "&lt;b&gt;x&lt;/b&gt;" in out
    assert "<b>x</b>" not in out


def test_control_bytes_and_markup_are_neutralized_in_html_values() -> None:
    hostile = "Z9HOST" + "".join(_DATA_CONTROLS) + "ILE9Z<script>alert(1)</script>"
    key = "Z9KEY" + "".join(_DATA_CONTROLS) + "END9Z"
    value = "Z9VALUE" + "".join(_DATA_CONTROLS) + "END9Z"
    out = _render(
        [_finding(
            detector="dns",
            title=hostile,
            description=hostile,
            next_steps=[hostile],
            evidence={
                "source": "zeek",
                "label_score": 1.0,
                "query_count": 1,
                "unique_sources": 1,
                key: value,
            },
        )],
        verbose_level=2,
    )

    _assert_no_data_controls(out)
    assert "Z9HOSTILE9Z" in out
    assert '<td class="k">Z9KEYEND9Z</td>' in out
    assert '<td class="v">Z9VALUEEND9Z</td>' in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "<script>alert(1)</script>" not in out


def test_control_bytes_stripped_from_header_notes() -> None:
    hostile = "loaded Z9HOST" + "".join(_DATA_CONTROLS) + "ILE9Z"
    out = render_report_html(
        [], _summary(notes=[hostile]),
        verbose_level=0, max_findings_per_detector=100,
    )

    _assert_no_data_controls(out)
    assert "Z9HOSTILE9Z" in out


# ── header: chips + local time ───────────────────────────────────────────────
def test_method_chips_distinguish_named_vs_house() -> None:
    out = _render([_finding()])
    assert "chip-named" in out and "beacon (FFT)" in out      # published technique
    assert "chip-house" in out and "aws [statistical]" in out  # house method


def test_header_uses_local_time_not_iso() -> None:
    out = _render([_finding()])
    assert "2026-06-01 12:00 → 2026-06-01 18:30 local" in out
    assert "2026-06-01T12:00:00+00:00" not in out


def test_header_window_none_renders_none() -> None:
    """data_window=None (no loaded rows establish a window) → the header window
    row reads `none`; fmt_window is never handed None."""
    out = render_report_html(
        [], _summary(data_window=None),
        verbose_level=0, max_findings_per_detector=100,
    )
    assert (
        '<span class="meta-label">window</span>'
        '<span class="meta-value">none</span>'
    ) in out


# ── severity summary strip ───────────────────────────────────────────────────
def test_severity_strip_and_classes_present() -> None:
    out = _render([_finding(severity=Severity.HIGH), _finding(severity=Severity.MEDIUM)])
    assert "sev-strip" in out
    for cls in ("sev-high", "sev-medium", "sev-low", "sev-info"):
        assert cls in out


# ── verbose tiers ────────────────────────────────────────────────────────────
def test_tiers_differ_across_levels() -> None:
    f = _finding(description="why it scored", next_steps=["do a thing"])
    at0 = _render([f], verbose_level=0)
    at1 = _render([f], verbose_level=1)
    assert "why it scored" not in at0       # level 0: pill + entity only
    assert "why it scored" in at1           # level 1: description shows
    assert "do a thing" in at1              # next_steps show


def test_full_evidence_at_level_2_is_structured_not_str_dict() -> None:
    f = _finding(evidence={"rcode_distribution": {"NOERROR": 10, "NXDOMAIN": 2}})
    out = _render([f], verbose_level=2)
    assert "NOERROR: 10" in out                       # readable kv, recursed
    assert "{'NOERROR'" not in out                    # NOT a str(dict) dump
    assert "<pre>" not in out                         # no raw <pre> dump


# ── the 5-step pipeline ──────────────────────────────────────────────────────
def test_duration_low_hidden_at_level_0() -> None:
    low = _finding(
        detector="duration", severity=Severity.LOW, title="x",
        evidence={"src": "192.0.2.50", "dst": "198.51.100.9", "port": 22,
                  "proto": "tcp", "max_duration_str": "31m", "connection_count": 1,
                  "avg_bytes_per_second": None, "conn_states": []},
    )
    assert "192.0.2.50" not in _render([low], verbose_level=0)  # LOW hidden at L0
    assert "192.0.2.50" in _render([low], verbose_level=1)      # shown at L1


def test_group_header_uses_pre_cap_counts() -> None:
    findings = [_finding(title=f"f{i}") for i in range(5)]
    out = _render(findings, cap=2)
    # header reflects the pre-cap total, not the 2 shown cards
    assert "beacon - 5 findings" in out


def test_cap_disclosure_and_card_count() -> None:
    findings = [_finding(title=f"flow-{i}") for i in range(5)]
    out = _render(findings, cap=2)
    assert "showing 2 of 5" in out
    assert out.count('class="finding-row') == 2  # only 2 rows rendered


def test_empty_findings_render_empty_state() -> None:
    assert "No findings." in _render([])


# ── section-aware html sidecars (RAIL SUPERSESSION: html matches text) ───────
def test_html_section_vanishes_when_emptied_by_cap() -> None:
    """dns: singletons-first; with cap=2 the 2 singletons consume the budget and
    the groups section is emptied → its label VANISHES (no lonely label)."""
    findings = [
        _finding(detector="dns", severity=Severity.MEDIUM, title="s1.example",
                 evidence={"source": "zeek", "label_score": 4.1, "query_count": 11, "unique_sources": 1}),
        _finding(detector="dns", severity=Severity.MEDIUM, title="s2.example",
                 evidence={"source": "zeek", "label_score": 4.2, "query_count": 12, "unique_sources": 2}),
        _finding(detector="dns", severity=Severity.MEDIUM, title="g",
                 evidence={"source": "zeek", "registrable_domain": "grp.example",
                           "subdomain_count": 9, "max_label_score": 4.3, "min_label_score": 3.1,
                           "total_queries": 99, "unique_sources": 3}),
    ]
    out = _render(findings, cap=2)
    assert "singletons (2)" in out      # singletons section present
    assert "groups (" not in out        # groups section emptied by cap → vanished
    assert "showing 2 of 3" in out


def test_html_syslog_three_section_order_privileged_rare_events_bursts() -> None:
    """syslog cap order is privileged MEDIUM, sieve LOW, then burst INFO."""
    findings = [
        _finding(detector="syslog", severity=Severity.LOW, title="evt-sentinel-A",
                 evidence={"host": "h", "template_str": "k", "count": 2, "threshold": 9}),
        _finding(detector="syslog", severity=Severity.MEDIUM, title="member-sentinel-P",
                 evidence={"host": "h", "template_str": "m", "count": 1,
                           "threshold": 1, "privileged": True}),
        _finding(detector="syslog", severity=Severity.INFO, title="host-sentinel-B",
                 evidence={"tier": "reboot", "host": "host-sentinel-B",
                           "reboot_ts": "2026-06-01T03:04:05+00:00", "label": "rebooted"}),
    ]
    out = _render(findings)
    assert out.index("privileged") < out.index("rare events") < out.index("bursts")
    assert out.index("member-sentinel-P") < out.index("evt-sentinel-A")
    assert out.index("evt-sentinel-A") < out.index("host-sentinel-B")
    assert '>1</div><div class="sev-label">Low<' in out


def test_html_syslog_cap_spends_privileged_first_and_empty_labels_vanish() -> None:
    findings = [
        _finding(detector="syslog", severity=Severity.LOW, title="sieve",
                 evidence={"host": "h", "template_str": "s", "count": 1, "threshold": 1}),
        _finding(detector="syslog", severity=Severity.MEDIUM, title="member",
                 evidence={"host": "h", "template_str": "m", "count": 1,
                           "threshold": 1, "privileged": True}),
        _finding(detector="syslog", severity=Severity.INFO, title="reboot-host",
                 evidence={"tier": "reboot", "host": "reboot-host",
                           "reboot_ts": "2026-06-01T03:04:05+00:00", "label": "rebooted"}),
    ]
    out = _render(findings, cap=1)
    assert "privileged (1)" in out
    assert "member" in out
    assert "rare events (" not in out
    assert "bursts (" not in out
    assert "sieve" not in out
    assert "reboot-host" not in out


def test_html_syslog_sample_details_real_path_is_closed_escaped_and_print_hidden() -> None:
    hostile = 'raw\x1b<script>x</script>"</details><img src=x>'
    finding = _finding(
        detector="syslog", severity=Severity.LOW, title="host-family",
        evidence={
            "tier": "family", "host": "host-family", "program": "kernel",
            "line_count": 2, "start_ts": 1.0, "end_ts": 2.0,
            "span_seconds": 1.0, "sample_raw": [hostile, "safe-second"],
            "label": None,
        },
    )
    for level in (0, 1, 2):
        out = _render([finding], verbose_level=level)
        _assert_no_data_controls(out)
        assert '<details><summary>sampled log lines</summary>' in out
        assert "<th>first</th>" in out
        assert out.index("<th>first</th>") < out.index("host-family")
        assert "<details open" not in out
        assert "sample-detail-body" in out
        assert ".sample-detail-body { display: none; }" in out
        assert '&lt;script&gt;x&lt;/script&gt;&quot;&lt;/details&gt;&lt;img src=x&gt;' in out
        assert "<script>x</script>" not in out
        assert "<img src=x>" not in out


def test_html_syslog_level_one_sample_is_three_while_details_keeps_full_sample() -> None:
    samples = [f"sample-{i}" for i in range(5)]
    finding = _finding(
        detector="syslog", severity=Severity.INFO, title="host-burst",
        evidence={
            "tier": "burst", "line_count": 5, "span_seconds": 4.0,
            "start_ts": 1.0, "end_ts": 5.0, "first_seen": "1970-01-01T00:00:01+00:00",
            "program_mix": [["kernel", 5]], "sample_raw": samples, "label": None,
        },
    )
    out = _render([finding], verbose_level=1)
    # sample-0..2 appear once in the -v grid and once in the full details body;
    # sample-3..4 appear only in the full details body.
    assert out.count("sample-0") == 2
    assert out.count("sample-2") == 2
    assert out.count("sample-3") == 1
    assert out.count("sample-4") == 1


def test_html_aws_ranked_summary_survives_as_full_width_row() -> None:
    """aws ranked_summary is an always-show synthetic row: even a summary-ONLY
    ranked section (no per-principal rows → 0 grid columns) renders it as a
    full-width row (caution-3 defensive colspan), never dropped."""
    finding = _finding(
        detector="aws", severity=Severity.INFO,
        title="ranked tier: no principals cleared the LOW band",
        evidence={"tier": "ranked_summary", "scorable_count": 117,
                  "top_principal": "role/topdog", "top_composite_z": 2.71},
    )
    out = _render([finding])
    assert "full-width" in out                       # rendered as a spanning row
    assert "117 scored; top role/topdog z=2.71" in out
    assert "ranked principals (1)" in out            # the section label survives


def test_html_strips_control_bytes_from_full_width_row() -> None:
    hostile = "Z9HOST" + "".join(_DATA_CONTROLS) + "ILE9Z"
    finding = _finding(
        detector="aws", severity=Severity.INFO,
        title=f"ranked tier: {hostile}",
        evidence={"tier": "ranked_summary", "scorable_count": 117,
                  "top_principal": "role/topdog", "top_composite_z": 2.71},
    )
    out = _render([finding])

    _assert_no_data_controls(out)
    assert "full-width" in out
    assert "Z9HOSTILE9Z" in out


# ── destination: html no target → stdout, NO surprise file in CWD ────────────
def test_html_no_target_streams_to_stdout_no_cwd_file(tmp_path, monkeypatch) -> None:
    """`-f html` with no target streams markup to stdout (the redirect idiom) and
    writes NO sigwood-report.html in CWD - the surprise-file class is deleted."""
    from sigwood.runner import _build_output_handler

    monkeypatch.chdir(tmp_path)
    fake_stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    handler, close_handler, written = _build_output_handler(
        "html", output_dir=None, output_file=None, verbose_level=0,
    )
    assert written is None  # stdout target → nothing to report
    handler.begin(_summary())
    handler.write([_finding()])
    handler.end()
    close_handler()

    markup = fake_stdout.getvalue()
    assert markup.startswith("<!doctype html>")
    assert "findings-table" in markup  # per-detector table rendered to the stream
    assert not (tmp_path / "sigwood-report.html").exists()
    assert list(tmp_path.iterdir()) == []


# ── print-CSS + pdf orientation (wrapping is the correctness floor; landscape is
#    a best-effort readability estimate layered on top - never the other way) ────
def _wide_duration() -> Finding:
    """A duration finding whose table overflows A4 portrait - full IPv6 flow +
    conn_states. Exercises project_row/html_columns (the seam under test)."""
    return _finding(
        detector="duration",
        title="",
        evidence={
            "src": "2001:db8:1234:5678:9abc:def0:1234:5678",
            "dst": "2001:db8:8765:4321:fedc:ba98:7654:3210",
            "port": 443, "proto": "tcp", "max_duration_str": "4h 30m",
            "avg_bytes_per_second": 1_500_000, "connection_count": 37,
            "conn_states": ["S0", "SF", "REJ", "RSTO"],
        },
    )


def _narrow_beacon() -> Finding:
    """A realistic v4 beacon table - the default-portrait MUST: it stays portrait
    even with a 7-digit conn count."""
    return _finding(
        detector="beacon",
        evidence={
            "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "dst_port": 443,
            "proto": "tcp", "period_str": "60.0m", "beacon_score": 0.608,
            "conn_count": 918_273,
        },
    )


def test_print_css_data_nowrap_is_screen_only() -> None:
    """The correctness floor: the data-cell nowrap lives under
    @media screen, so the PRINT page wraps (word-break) instead of clipping wide
    tables. The @media print block carries NO unconditional data-cell nowrap."""
    markup = _render([_narrow_beacon()])
    assert "@media screen {" in markup
    # the only td.data nowrap is inside @media screen
    screen_start = markup.index("@media screen {")
    print_start = markup.index("@media print")
    screen_block = markup[screen_start:print_start]
    assert ".findings-table td.data { white-space: nowrap; }" in screen_block
    assert "td.data" not in markup[print_start:]  # print wraps, never nowrap-clips


def test_needs_landscape_wide_vs_narrow() -> None:
    """The pure estimator, through the REAL _build_renderable +
    projection path: a wide IPv6 table trips landscape; a realistic v4 beacon
    stays portrait."""
    from sigwood.outputs._render_model import _build_renderable, needs_landscape

    wide = _build_renderable("duration", [_wide_duration()], 0, 100)
    narrow = _build_renderable("beacon", [_narrow_beacon()], 0, 100)
    assert needs_landscape([("duration", wide)]) is True
    assert needs_landscape([("beacon", narrow)]) is False


def test_render_emits_landscape_for_wide_portrait_for_narrow() -> None:
    """Render-level: render_report_html flips ONLY the print @page
    size from the content estimate; screen html is inert (paged media only)."""
    wide = _render([_wide_duration()])
    narrow = _render([_narrow_beacon()])
    assert "@page { size: A4 landscape; margin: 1.5cm; }" in wide
    assert "@page { size: A4; margin: 1.5cm; }" in narrow
    assert "landscape" not in narrow


# ── failed-detector header row ───────────────────────────────────────────────


def test_failed_detector_row_renders_in_header() -> None:
    html = _render([], )
    assert 'class="fail"' not in html  # clean run - vanish
    html = render_report_html(
        [],
        _summary(detectors_failed={"beacon": "detector error - boom"}),
        verbose_level=0,
        max_findings_per_detector=100,
    )
    assert '<div class="fail">beacon - detector error - boom</div>' in html


def test_failed_detector_reason_is_escaped_and_control_stripped() -> None:
    """The reason can echo log-derived bytes - it must pass the _esc choke
    point (markup escaped, control bytes stripped)."""
    html = render_report_html(
        [],
        _summary(detectors_failed={
            "dns": 'detector error - <script>alert(1)</script>\x1b[31m&"',
        }),
        verbose_level=0,
        max_findings_per_detector=100,
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    _assert_no_data_controls(html)
