"""HTML handler - the designed, self-contained reading report."""

from __future__ import annotations

import io
import re
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
        assert (
            '<details class="row-toggle"><summary><span class="pill sev-low">'
            '[L]</span></summary></details>'
        ) in out
        assert "sampled log lines" not in out
        assert '<th class="col-first">first</th>' in out
        assert out.index('<th class="col-first">first</th>') < out.index("host-family")
        assert "<details open" not in out
        assert "sample-detail-body" in out
        assert ".findings-table tr.sample-detail { display: none; }" in out
        sample_start = out.index('<tr class="sample-detail">')
        sample_end = out.index("</tr>", sample_start)
        sample_row = out[sample_start:sample_end]
        assert "<details" not in sample_row
        assert "<summary" not in sample_row
        print_block = out[out.index("@media print"):]
        assert ".findings-table tr.sample-detail { display: none; }" in print_block
        assert (
            '<span class="hl-ts"></span><span class="hl-host"></span>'
            '<span class="hl-prog"></span><span class="sample-message">'
            'raw&lt;script&gt;x&lt;/script&gt;&quot;&lt;/details&gt;&lt;img src=x&gt;</span>'
        ) in out
        assert "<script>x</script>" not in out
        assert "<img src=x>" not in out


def test_html_syslog_transaction_summary_and_member_drilldown_are_safe() -> None:
    finding = _finding(
        detector="syslog", severity=Severity.MEDIUM, title="host-a",
        evidence={
            "tier": "transaction", "label": "admin session", "host": "host-a",
            "member_count": 2, "represented_line_count": 3,
            "start_ts": 1.0, "end_ts": 121.0,
            "first_seen": "1970-01-01T00:00:01+00:00", "span_seconds": 120.0,
            "program_mix": [["useradd", 2], ["cron", 1]],
            "members": [
                {"severity": "medium", "tier": "family",
                 "represented_line_count": 2, "program": "useradd",
                 "title": "safe\x1b<script>member</script>", "privileged": True},
                {"severity": "low", "tier": "needle",
                 "represented_line_count": 1, "program": "cron",
                 "title": "second-member"},
            ],
            "privileged": True,
        },
    )

    out = _render([finding], verbose_level=2)

    _assert_no_data_controls(out)
    assert "privileged (1)" in out
    assert "bursts (" not in out
    assert (
        "host-a · admin session · 2 member findings · 2m · "
        "mostly useradd, cron"
    ) in out
    assert (
        '<details class="row-toggle"><summary><span class="pill sev-medium">'
        '[M]</span></summary></details>'
    ) in out
    assert "[M] · useradd · family · 2 rare lines · " in out
    assert "safe&lt;script&gt;member&lt;/script&gt;" in out
    assert "[L] · cron · needle · 1 rare line · second-member" in out
    assert "<script>member</script>" not in out
    assert '<td class="k">members</td>' not in out
    assert ".findings-table tr.sample-detail { display: none; }" in out[out.index("@media print"):]


def test_html_syslog_sample_highlight_uses_exact_parser_split_and_safe_fallback() -> None:
    rfc = '<134>Jul  1 12:00:00 host<script> sshd[7]: accepted <img src=x>'
    iso = '2026-06-28T14:34:43-05:00 web01 cron[2]: ran "job"'
    journal = 'kernel: headerless <script>alert(1)</script>'
    finding = _finding(
        detector="syslog", severity=Severity.INFO, title="host-burst",
        evidence={
            "tier": "burst", "line_count": 3, "span_seconds": 2.0,
            "start_ts": 1.0, "end_ts": 3.0,
            "program_mix": [["kernel", 3]],
            "sample_raw": [rfc, iso, journal], "label": None,
        },
    )

    out = _render([finding])

    assert (
        '<span class="hl-ts">&lt;134&gt;Jul  1 12:00:00 </span>'
        '<span class="hl-host">host&lt;script&gt; </span>'
        '<span class="hl-prog">sshd[7]: </span><span class="sample-message">'
        'accepted &lt;img src=x&gt;</span>'
    ) in out
    assert (
        '<span class="hl-ts">2026-06-28T14:34:43-05:00 </span>'
        '<span class="hl-host">web01 </span>'
        '<span class="hl-prog">cron[2]: </span>'
        '<span class="sample-message">ran &quot;job&quot;</span>'
    ) in out
    assert (
        '<span class="hl-ts"></span><span class="hl-host"></span>'
        '<span class="hl-prog">kernel: </span><span class="sample-message">'
        'headerless &lt;script&gt;alert(1)&lt;/script&gt;</span>'
    ) in out
    assert "<script>alert(1)</script>" not in out
    assert "<img src=x>" not in out
    assert "data-" not in out


def test_html_syslog_severity_pill_is_native_css_only_toggle() -> None:
    finding = _finding(
        detector="syslog", severity=Severity.INFO, title="host-burst",
        evidence={
            "tier": "burst", "line_count": 1, "span_seconds": 0.0,
            "start_ts": 1.0, "end_ts": 1.0,
            "program_mix": [["kernel", 1]], "sample_raw": ["kernel: one"],
            "label": None,
        },
    )

    out = _render([finding])

    assert (
        '<details class="row-toggle"><summary><span class="pill sev-info">'
        '[I]</span></summary></details>'
    ) in out
    screen_block = out[out.index("@media screen {"):out.index("@media print")]
    assert (
        '.row-toggle summary::after { content: "+"; color: var(--muted); '
        'margin-left: 3px; }'
    ) in screen_block
    assert '.row-toggle[open] summary::after { content: "−"; }' in screen_block
    assert ".row-toggle summary::after" not in out[out.index("@media print"):]
    assert ".row-toggle .pill::after" not in out
    assert "sampled log lines" not in out
    assert '<script' not in out


def test_html_non_capsule_severity_pills_remain_inert() -> None:
    needle = _finding(
        detector="syslog", severity=Severity.LOW,
        title="Jul 1 12:00:00 host kernel: needle",
        evidence={
            "host": "host", "template_str": "kernel: <*> ",
            "sample_raw": ["kernel: ignored toggle bait"],
        },
    )
    out = _render([needle, _narrow_beacon()])

    assert 'class="row-toggle"' not in out
    assert out.count('class="pill sev-low"') == 1
    assert out.count('class="pill sev-high"') == 1


def test_html_syslog_utc_stamp_class_follows_display_label(
    restore_display_utc,
) -> None:
    from sigwood.common.display import set_display_utc

    finding = _finding(
        detector="syslog", severity=Severity.INFO, title="host-burst",
        evidence={
            "tier": "burst", "line_count": 1, "span_seconds": 0.0,
            "start_ts": 1.0, "end_ts": 1.0,
            "program_mix": [["kernel", 1]], "sample_raw": ["kernel: one"],
            "label": None,
        },
    )

    set_display_utc(False)
    local = _render([finding])
    assert '<table class="findings-table syslog-table">' in local
    assert '<table class="findings-table syslog-table utc-stamps">' not in local

    set_display_utc(True)
    utc = _render([finding])
    assert '<table class="findings-table syslog-table utc-stamps">' in utc


def test_html_syslog_open_pill_swaps_both_meat_shapes_for_raw_on_screen() -> None:
    case_one = _finding(
        detector="syslog", severity=Severity.LOW, title="family",
        evidence={
            "tier": "family", "host": "host", "program": "kernel",
            "line_count": 2, "start_ts": 1.0, "end_ts": 2.0,
            "span_seconds": 1.0, "sample_raw": ["kernel: a", "kernel: b"],
            "member_fragments": ["tokens: a b"], "label": None,
        },
    )
    case_two = _finding(
        detector="syslog", severity=Severity.INFO, title="burst",
        evidence={
            "tier": "burst", "line_count": 2, "start_ts": 3.0, "end_ts": 4.0,
            "span_seconds": 1.0, "sample_raw": ["kernel: c", "kernel: d"],
            "program_mix": [["kernel", 2]],
            "member_fragments": ["fragment c", "fragment d"], "label": None,
        },
    )

    out = _render([case_one, case_two])
    screen_block = out[out.index("@media screen {"):out.index("@media print")]

    assert out.count('class="row-toggle"') == 2
    assert out.count('class="meat-row"') == 2
    assert out.count('class="sample-detail"') == 2
    assert (
        ".syslog-table tr.finding-row:has(.row-toggle[open]) + tr.meat-row"
        in screen_block
    )
    assert (
        ".syslog-table tr.finding-row:has(.row-toggle[open]) + tr.sample-detail"
        in screen_block
    )
    assert (
        ".syslog-table tr.finding-row:has(.row-toggle[open]) + tr.meat-row "
        "+ tr.sample-detail"
        in screen_block
    )
    assert "tr.meat-row" not in out[out.index("@media print"):]


def test_html_syslog_highlight_palettes_keep_timestamp_brightest() -> None:
    out = _render([_finding()])
    light = ("#9a6700", "#0969da", "#8250df")
    dark = ("#ffd166", "#70d6ff", "#c4a7e7")

    def luminance(value: str) -> float:
        channels = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [
            channel / 12.92
            if channel <= 0.04045
            else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    assert "--hl-ts: #9a6700; --hl-host: #0969da; --hl-prog: #8250df;" in out
    assert "--hl-ts: #ffd166; --hl-host: #70d6ff; --hl-prog: #c4a7e7;" in out
    assert luminance(light[0]) > max(map(luminance, light[1:]))
    assert luminance(dark[0]) > max(map(luminance, dark[1:]))
    assert ".hl-ts { color: var(--hl-ts); font-weight: 700; }" in out
    assert ".hl-host { color: var(--hl-host); font-weight: 600; }" in out
    assert ".hl-prog { color: var(--hl-prog); font-weight: 600; }" in out


def test_html_severity_pill_palettes_meet_wcag_contrast_floor() -> None:
    out = _render([_finding()])
    style = out[out.index("<style>") + len("<style>"):out.index("</style>")]
    palette_blocks = re.findall(
        r"(?ms)^(?:  )?:root \{\n(.*?)^(?:  )?\}", style
    )
    assert len(palette_blocks) == 2

    severity_names = ("high", "medium", "low", "info")

    def variables(block: str) -> dict[str, str]:
        return dict(re.findall(
            r"--(sev-(?:high|medium|low|info)(?:-ink)?):\s*"
            r"(#[0-9a-fA-F]{6})",
            block,
        ))

    def luminance(value: str) -> float:
        channels = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [
            channel / 12.92
            if channel <= 0.04045
            else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    for block in palette_blocks:
        palette = variables(block)
        assert set(palette) == {
            *(f"sev-{name}" for name in severity_names),
            *(f"sev-{name}-ink" for name in severity_names),
        }
        for name in severity_names:
            background = luminance(palette[f"sev-{name}"])
            ink = luminance(palette[f"sev-{name}-ink"])
            ratio = (max(background, ink) + 0.05) / (min(background, ink) + 0.05)
            assert ratio >= 4.5, (name, palette[f"sev-{name}"], ratio)


def test_html_syslog_meat_row_is_escaped_visible_and_ordered() -> None:
    hostile = 'safe\x1b\x07\x9b<script>x</script>"</div><img src=x>'
    finding = _finding(
        detector="syslog", severity=Severity.LOW, title="host-family",
        evidence={
            "tier": "family", "host": "host-family", "program": "kernel",
            "line_count": 2, "start_ts": 1.0, "end_ts": 61.0,
            "span_seconds": 60.0, "sample_raw": ["raw-a", "raw-b"],
            "member_fragments": [hostile, "second-fragment"], "label": None,
        },
    )
    out = _render([finding])
    _assert_no_data_controls(out)
    assert out.index('class="finding-row') < out.index('class="meat-row"')
    assert out.index('class="meat-row"') < out.index('class="sample-detail"')
    assert (
        '<div class="meat-line">safe&lt;script&gt;x&lt;/script&gt;&quot;'
        '&lt;/div&gt;&lt;img src=x&gt;</div>'
    ) in out
    assert '<div class="meat-line">second-fragment</div>' in out
    assert "<script>x</script>" not in out
    assert "<img src=x>" not in out
    assert ".findings-table tr.sample-detail { display: none; }" in out
    print_block = out[out.index("@media print"):]
    assert ".meat-line" not in print_block


def test_html_syslog_mixed_keyed_and_full_width_rows_clip_in_one_table() -> None:
    family = _finding(
        detector="syslog", severity=Severity.LOW, title="host-family",
        evidence={
            "tier": "family", "host": "host-family", "program": "kernel",
            "line_count": 2, "start_ts": 1.0, "end_ts": 61.0,
            "span_seconds": 60.0, "sample_raw": ["raw-a", "raw-b"],
            "member_fragments": ["family-fragment"], "label": None,
        },
    )
    needle = _finding(
        detector="syslog", severity=Severity.LOW,
        title="Jul 12 21:57:33 host-a kernel: one long self-stamped needle line",
        evidence={"host": "host-a", "template_str": "kernel: <*>"},
    )
    out = _render([family, needle])
    assert '<table class="findings-table syslog-table">' in out
    assert '<th class="col-first">first</th>' in out
    assert '<td class="data col-first">Jan  1 00:00:01</td>' in out
    assert '<div class="clip">host-family · kernel · 2 rare lines · 1m</div>' in out
    assert (
        '<div class="clip">Jul 12 21:57:33 host-a kernel: one long '
        'self-stamped needle line</div>'
    ) in out


def test_html_syslog_stamp_preserves_both_day_widths_in_effective_css(
    restore_display_utc,
) -> None:
    from sigwood.common.display import set_display_utc

    set_display_utc(True)

    def family(day: int) -> Finding:
        start = datetime(2026, 7, day, 3, 12, 47, tzinfo=timezone.utc).timestamp()
        return _finding(
            detector="syslog", severity=Severity.LOW, title=f"host-{day}",
            evidence={
                "tier": "family", "host": f"host-{day}", "program": "kernel",
                "line_count": 2, "start_ts": start, "end_ts": start + 60.0,
                "span_seconds": 60.0, "sample_raw": ["raw-a", "raw-b"],
                "member_fragments": ["fragment"], "label": None,
            },
        )

    out = _render([family(1), family(12)])
    assert '<td class="data col-first">Jul  1 03:12:47 UTC</td>' in out
    assert '<td class="data col-first">Jul 12 03:12:47 UTC</td>' in out

    # Both matching rules have specificity (0, 2, 1). The unconditional stamp
    # rule deliberately follows the screen-only generic data-cell rule, so the
    # effective white-space value is `pre` on screen and remains `pre` in print.
    rules = [
        ((0, 2, 1), out.index(".findings-table td.data { white-space: nowrap; }"),
         "nowrap"),
        ((0, 2, 1), out.index(".syslog-table td.col-first { white-space: pre; }"),
         "pre"),
    ]
    computed_white_space = max(rules, key=lambda rule: (rule[0], rule[1]))[2]
    assert computed_white_space == "pre"


def test_html_syslog_all_needle_table_has_no_header_but_keeps_clip_structure() -> None:
    needle = _finding(
        detector="syslog", severity=Severity.LOW,
        title="Jul 12 21:57:33 host-a kernel: needle",
        evidence={"host": "host-a", "template_str": "kernel: <*>"},
    )
    out = _render([needle])
    assert '<table class="findings-table syslog-table"><tbody>' in out
    assert '<div class="clip">Jul 12 21:57:33 host-a kernel: needle</div>' in out


def test_non_syslog_table_does_not_gain_syslog_clip_classes() -> None:
    out = _render([_narrow_beacon()])
    assert '<table class="findings-table syslog-table">' not in out
    assert 'class="clip"' not in out


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
    assert "max-width: 1600px" in markup
    assert "@media screen {" in markup
    # the only td.data nowrap is inside @media screen
    screen_start = markup.index("@media screen {")
    print_start = markup.index("@media print")
    screen_block = markup[screen_start:print_start]
    assert ".findings-table td.data { white-space: nowrap; }" in screen_block
    assert ".syslog-table { table-layout: fixed; width: 100%; }" in screen_block
    assert (
        ".syslog-table th.sev-col, .syslog-table td.sev-cell { width: 64px; }"
        in screen_block
    )
    assert (
        ".syslog-table th.col-first, .syslog-table td.col-first { width: 135px; }"
        in screen_block
    )
    assert (
        ".syslog-table.utc-stamps th.col-first, .syslog-table.utc-stamps "
        "td.col-first { width: 169px; }"
        in screen_block
    )
    assert ".syslog-table .clip, .syslog-table .meat-line" in screen_block
    assert "overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" in screen_block
    assert ".desc, .next-steps { max-width: 46em; }" in screen_block
    assert "td.data" not in markup[print_start:]  # print wraps, never nowrap-clips
    print_block = markup[print_start:]
    assert ".clip" not in print_block
    assert ".meat-line" not in print_block
    assert "text-overflow: ellipsis" not in print_block
    assert "overflow: hidden" not in print_block
    assert "max-width: 46em" not in print_block


def test_needs_landscape_wide_vs_narrow() -> None:
    """The pure estimator, through the REAL _build_renderable +
    projection path: a wide IPv6 table trips landscape; a realistic v4 beacon
    stays portrait."""
    from sigwood.outputs._render_model import _build_renderable, needs_landscape

    wide = _build_renderable("duration", [_wide_duration()], 0, 100)
    narrow = _build_renderable("beacon", [_narrow_beacon()], 0, 100)
    assert needs_landscape([("duration", wide)]) is True
    assert needs_landscape([("beacon", narrow)]) is False


def test_syslog_stamp_orientation_estimate_local_and_utc(
    restore_display_utc,
) -> None:
    """The shorter syslog stamp moves a realistic near-threshold table to portrait.

    The pre-change measurements were 704px/local and 688px/UTC, both landscape.
    The new local/UTC forms measure 648px and 680px respectively.
    """
    from sigwood.common.display import set_display_utc
    from sigwood.outputs._render_model import (
        _build_renderable,
        _section_table_px,
        needs_landscape,
    )

    finding = _finding(
        detector="syslog", severity=Severity.LOW, title="host-" + ("x" * 26),
        description="", next_steps=[],
        evidence={
            "tier": "family", "host": "h", "program": "sshd",
            "line_count": 2, "start_ts": 0.0, "end_ts": 60.0,
            "span_seconds": 60.0, "sample_raw": ["a", "b"],
            "member_fragments": ["m"], "label": None,
        },
    )

    set_display_utc(False)
    local = _build_renderable("syslog", [finding], 0, 100)
    assert _section_table_px(local.sections[0]) == 648.0
    assert needs_landscape([("syslog", local)]) is False

    set_display_utc(True)
    utc = _build_renderable("syslog", [finding], 0, 100)
    assert _section_table_px(utc.sections[0]) == 680.0
    assert needs_landscape([("syslog", utc)]) is False


def test_stamped_long_journal_needle_deliberately_flips_to_landscape(
    restore_display_utc,
) -> None:
    from sigwood.common.display import set_display_utc
    from sigwood.outputs._render_model import (
        _build_renderable,
        _section_table_px,
        needs_landscape,
    )

    set_display_utc(False)
    title = "journal " + ("x" * 192)
    assert len(title) == 200
    base_evidence = {
        "host": "host-journal",
        "first_seen": "2026-07-12T21:57:33+00:00",
    }
    legacy = _finding(
        detector="syslog", severity=Severity.LOW, title=title,
        description="", next_steps=[], evidence=base_evidence,
    )
    stamped = _finding(
        detector="syslog", severity=Severity.LOW, title=title,
        description="", next_steps=[],
        evidence={**base_evidence, "self_stamped": False},
    )

    before = _build_renderable("syslog", [legacy], 0, 100)
    after = _build_renderable("syslog", [stamped], 0, 100)
    assert _section_table_px(before.sections[0]) == 0.0
    assert needs_landscape([("syslog", before)]) is False
    assert _section_table_px(after.sections[0]) == 1784.0
    assert needs_landscape([("syslog", after)]) is True


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
