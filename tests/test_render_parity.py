"""Row-scoped signal-parity tripwire: text ↔ html(↔pdf).

The guarded bug class is text and html DRIFTING on what a finding renders.
This pins parity at the source: every NON-empty ``project_row`` cell must render
its datum in BOTH surfaces - compared PER detector / variant / row (a global
"value in text and value in html" sweep is explicitly NOT acceptable). Fixtures
carry UNIQUE SENTINEL values so a match is attributable to its row, not a
coincidental common int.

The two surfaces render the datum DIFFERENTLY by design: text keeps the labeled
``Cell.value`` (``period=61.5m``); html shows the header-stripped
``html_cell_value(cell)`` (``61.5m``) beneath a ``period`` header, so the label
is not double-printed. Parity is checked per-surface against what that surface
shows; the html value is a substring of text's, so the shared datum is pinned.
"""

from __future__ import annotations

import html as _htmllib
import io
import re
from datetime import datetime, timezone

import pytest

from sigwood.common.display import set_display_utc
from sigwood.common.finding import Finding, Severity
from sigwood.outputs._render_model import (
    Section,
    html_cell_value,
    project_row,
    section_columns,
)
from sigwood.outputs.html import render_report_html
from sigwood.outputs.text import TextHandler

_W = (
    datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
    datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
)


def _f(detector, severity, title, evidence):
    return Finding(detector=detector, severity=severity, title=title, description="",
                   evidence=evidence, next_steps=[], ts_generated=_W[1], data_window=_W)


def _text(findings, level=0):
    buf = io.StringIO()
    TextHandler(stream=buf, verbose_level=level, max_findings_per_detector=100).write(findings)
    return buf.getvalue()


def _html_text(findings, level=0):
    """Render html, strip tags, unescape - the visible text of the table."""
    raw = render_report_html(findings, None, verbose_level=level, max_findings_per_detector=100)
    stripped = re.sub(r"<[^>]+>", " ", raw)
    return _htmllib.unescape(stripped)


# ── one finding per detector AND per variant, UNIQUE SENTINEL values ─────────
_VARIANTS: dict[str, Finding] = {
    "beacon": _f("beacon", Severity.HIGH, "x", {
        "src_ip": "192.0.2.211", "dst_ip": "198.51.100.222", "dst_port": 4433,
        "proto": "tcp", "period_str": "61.5m", "beacon_score": 0.6171, "conn_count": 918273}),
    "dns_singleton": _f("dns", Severity.MEDIUM, "sentineldomain.example", {
        "source": "zeek", "label_score": 4.7731, "query_count": 53117, "unique_sources": 71}),
    "dns_singleton_blocked": _f("dns", Severity.HIGH, "blockeddomain.example", {
        "source": "pihole", "label_score": 4.6621, "query_count": 6121, "unique_sources": 31,
        "was_blocked": True, "block_ratio": 0.5}),
    "dns_group": _f("dns", Severity.MEDIUM, "g", {
        "source": "zeek", "registrable_domain": "sentinelgroup.example",
        "subdomain_count": 4217, "max_label_score": 4.9117, "min_label_score": 3.1127,
        "total_queries": 81237, "unique_sources": 91}),
    "scan_vertical": _f("scan", Severity.HIGH, "x", {
        "scan_type": "vertical", "src": "192.0.2.231", "dst": "198.51.100.241",
        "scan_state_ratio": 0.9117, "distinct_ports": 7717}),
    "scan_horizontal": _f("scan", Severity.HIGH, "x", {
        "scan_type": "horizontal", "src": "192.0.2.232", "port": 2237,
        "scan_state_ratio": 0.8227, "distinct_hosts": 6547}),
    "scan_block": _f("scan", Severity.MEDIUM, "x", {
        "scan_type": "block", "src": "192.0.2.233", "scan_state_ratio": 0.7337,
        "distinct_ports": 887, "distinct_hosts": 997}),
    "scan_slow": _f("scan", Severity.LOW, "x", {
        "scan_type": "slow", "src": "192.0.2.234", "scan_state_ratio": 0.6447,
        "distinct_ports": 317, "active_buckets": 177}),
    "syslog_event": _f("syslog", Severity.LOW, "kernel: sentinel-evt-717117", {
        "host": "host-sentinel-9", "template_str": "kernel: <*>", "count": 2, "threshold": 9}),
    "syslog_stamped_event": _f(
        "syslog", Severity.LOW, "journal-stamped-sentinel-727117", {
            "host": "host-journal-9", "template_str": "cron: <*>",
            "count": 1, "threshold": 9,
            "first_seen": "2026-07-12T21:57:33+00:00",
            "self_stamped": False,
        }),
    "syslog_family": _f("syslog", Severity.LOW, "host-sentinel-family-9", {
        "tier": "family", "host": "host-sentinel-family-9",
        "program": "progsentinel", "line_count": 137, "span_seconds": 7320.0,
        "start_ts": 1.0, "end_ts": 7321.0,
        "sample_raw": ["family-raw-sentinel-a"],
        "member_fragments": ["family-fragment-sentinel-717"], "label": None}),
    "syslog_reboot": _f("syslog", Severity.INFO, "host-sentinel-reboot-9", {
        "tier": "reboot", "host": "host-sentinel-reboot-9",
        "reboot_ts": "2026-06-01T07:08:09+00:00", "label": "rebooted"}),
    "syslog_burst": _f("syslog", Severity.INFO, "host-sentinel-burst-9", {
        "tier": "burst", "line_count": 137, "span_seconds": 4577.0,
        "start_ts": 1.0, "end_ts": 4578.0,
        "program_mix": [["kernsentinel", 91], ["syssentinel", 41]],
        "sample_raw": ["raw-sentinel-a", "raw-sentinel-b"],
        "member_fragments": ["burst-fragment-sentinel-727"], "label": "rebooted"}),
    "syslog_transaction": _f("syslog", Severity.INFO, "host-sentinel-txn-9", {
        "tier": "transaction", "label": "update run", "host": "host-sentinel-txn-9",
        "member_count": 2, "represented_line_count": 7,
        "start_ts": 1.0, "end_ts": 121.0,
        "first_seen": "1970-01-01T00:00:01+00:00", "span_seconds": 120.0,
        "program_mix": [["dnfsentinel", 5], ["kernsentinel", 2]],
        "members": [
            {"severity": "low", "tier": "family", "represented_line_count": 5,
             "title": "host-sentinel-txn-9", "program": "dnfsentinel"},
            {"severity": "low", "tier": "family", "represented_line_count": 2,
             "title": "host-sentinel-txn-9", "program": "kernsentinel"},
        ],
    }),
    "duration": _f("duration", Severity.HIGH, "x", {
        "src": "192.0.2.241", "dst": "198.51.100.251", "port": 9931, "proto": "tcp",
        "max_duration_str": "4h 17m", "connection_count": 37,
        "avg_bytes_per_second": 1700000.0, "conn_states": ["SF", "RSTO"]}),
    "aws_burst": _f("aws", Severity.MEDIUM, "role/sentinel-burst-7", {
        "tier": "burst", "principal": "role/sentinel-burst-7", "span_seconds": 4577.0,
        "new_action_count": 137, "new_service_count": 47, "error_rate": 0.27, "mean_rarity": 2.0}),
    "aws_ranked": _f("aws", Severity.LOW, "role/sentinel-rank-7", {
        "tier": "ranked", "principal": "role/sentinel-rank-7", "composite_z": 3.147,
        "error_rate": 0.057, "event_count": 4247, "distinct_source_ip": 67}),
    "aws_ranked_summary": _f("aws", Severity.INFO, "ranked tier: no principals cleared the LOW band", {
        "tier": "ranked_summary", "scorable_count": 117, "top_principal": "role/sentinel-top-7",
        "top_composite_z": 2.717}),
    "aws_ranked_summary_below_floor": _f(
        "aws", Severity.INFO, "ranked tier: too few principals to compare", {
            "tier": "ranked_summary", "scorable_count": 2, "population_floor": 5}),
    "dns_scan_summary": _f(
        "dns", Severity.INFO, "dense-cluster scan: high-entropy clusters surfaced", {
            "tier": "scan_summary", "cluster_count": 2, "total_members": 3217,
            "registrable_domains": ["sentineltunnel.example", "sentineldga.example"]}),
}


@pytest.mark.parametrize("variant", list(_VARIANTS))
def test_row_signal_parity_text_and_html(variant: str) -> None:
    """Every NON-empty project_row cell of this row appears in BOTH surfaces.

    Row-scoped: the finding is rendered ALONE so a hit is attributable to it.
    Empty cells (e.g. dns blocked when not blocked) are SKIPPED - never asserted.
    """
    finding = _VARIANTS[variant]
    text_out = _text([finding])
    html_out = _html_text([finding])
    cells = project_row(finding)
    assert cells, f"{variant}: project_row produced no cells"

    checked = 0
    for cell in cells:
        if cell.value == "":
            continue  # empty optional / vanished cell - never assert presence
        html_val = html_cell_value(cell)  # header-stripped for keyed cols; bare cells unchanged
        assert cell.value in text_out, f"{variant}: {cell.value!r} missing from TEXT"
        assert html_val in html_out, f"{variant}: {html_val!r} missing from HTML"
        checked += 1
    assert checked > 0, f"{variant}: no non-empty cells exercised"


def test_html_strips_redundant_keyed_labels() -> None:
    """The `period=61.5m under a period header` double-label bug class: for a keyed
    cell whose value embeds its own key as a `<key>=` / ` <key>` affix, the LABELED
    form is TEXT-only - html shows just the bare datum beneath its header. A keyed
    cell whose value does not embed the key (dur / bps / states / scan type) has no
    label to strip and is exempt."""
    for variant, finding in _VARIANTS.items():
        text_out = _text([finding])
        html_out = _html_text([finding])
        for cell in project_row(finding):
            if cell.key is None or cell.value == "":
                continue
            stripped = html_cell_value(cell)
            if stripped == cell.value:
                continue  # no embedded label - nothing to double-print
            assert cell.value in text_out, f"{variant}/{cell.key}: labeled form missing from TEXT"
            assert cell.value not in html_out, (
                f"{variant}/{cell.key}: double-labeled {cell.value!r} leaked into HTML"
            )
            assert stripped in html_out, f"{variant}/{cell.key}: bare datum {stripped!r} missing from HTML"


def test_html_projectorless_detector_falls_back_to_title() -> None:
    """A detector with no project_row projector (project_row → []) must still show
    the finding's title as a spanning cell - mirrors text's generic _render_finding,
    never a bare severity pill (the removed-behavior gap)."""
    finding = _f("future", Severity.HIGH, "future-sentinel-title-XYZ", {"k": "v"})
    assert project_row(finding) == []  # no projector for this detector
    assert "future-sentinel-title-XYZ" in _html_text([finding])  # html surfaces it
    assert "future-sentinel-title-XYZ" in _text([finding])       # text already did


def test_dns_blocked_cell_skipped_when_absent() -> None:
    """Negative control: the optional blocked cell is empty on an unblocked dns
    singleton, so 'BLOCKED' appears in NEITHER surface (no vacuous empty assert)."""
    finding = _VARIANTS["dns_singleton"]
    assert any(c.key == "blocked" and c.value == "" for c in project_row(finding))
    assert "BLOCKED" not in _text([finding])
    assert "BLOCKED" not in _html_text([finding])


def test_syslog_family_without_timestamps_omits_span() -> None:
    finding = _f("syslog", Severity.LOW, "host-no-time", {
        "tier": "family", "host": "host-no-time", "program": "unknown",
        "line_count": 2, "start_ts": None, "end_ts": None,
        "span_seconds": None, "sample_raw": ["a", "b"], "label": None,
    })
    cells = project_row(finding)
    assert [cell.value for cell in cells] == [
        "host-no-time · unknown · 2 rare lines"
    ]
    assert cells[0].full_width is True
    assert section_columns(Section(None, [finding], 1)) == []
    assert "None" not in _text([finding])
    assert "None" not in _html_text([finding])


def test_syslog_first_cell_is_keyed_for_html_but_bare_in_text() -> None:
    finding = _f("syslog", Severity.LOW, "host-first", {
        "tier": "family", "host": "host-first", "program": "kernel",
        "line_count": 2, "start_ts": 0.0, "end_ts": 60.0,
        "span_seconds": 60.0, "sample_raw": ["a", "b"], "label": None,
    })
    cells = project_row(finding)
    assert cells[0].key == "first"
    assert cells[0].value == "Jan  1 00:00:00"
    assert cells[1].value == "host-first · kernel · 2 rare lines · 1m"
    text_out = _text([finding])
    html_out = _html_text([finding])
    assert "Jan  1 00:00:00 · host-first" in text_out
    assert "first=" not in text_out
    assert "first" in html_out
    assert html_out.index("first") < html_out.index("host-first")


def test_syslog_needle_stamp_projection_uses_strict_four_arm_gate(
    restore_display_utc,
) -> None:
    set_display_utc(False)
    first_seen = "2026-07-12T21:57:33+00:00"

    def needle(title: str, evidence: dict) -> Finding:
        return _f("syslog", Severity.LOW, title, evidence)

    self_stamped = needle(
        "Jul 12 21:57:33 host-a cron: flat payload",
        {"first_seen": first_seen, "self_stamped": True},
    )
    cells = project_row(self_stamped)
    assert [(cell.key, cell.value, cell.full_width) for cell in cells] == [
        (None, self_stamped.title, True),
    ]

    stamped = needle(
        "bare journal payload",
        {"first_seen": first_seen, "self_stamped": False},
    )
    cells = project_row(stamped)
    assert [(cell.key, cell.value, cell.full_width) for cell in cells] == [
        ("first", "Jul 12 21:57:33", False),
        (None, "bare journal payload", False),
    ]

    no_timestamp = needle(
        "undated journal payload",
        {"first_seen": None, "self_stamped": False},
    )
    cells = project_row(no_timestamp)
    assert [(cell.key, cell.value, cell.full_width) for cell in cells] == [
        (None, no_timestamp.title, True),
    ]

    legacy = needle("legacy producer payload", {"first_seen": first_seen})
    cells = project_row(legacy)
    assert [(cell.key, cell.value, cell.full_width) for cell in cells] == [
        (None, legacy.title, True),
    ]

    text_out = _text([stamped])
    html_out = render_report_html(
        [stamped], None, verbose_level=0, max_findings_per_detector=100,
    )
    assert "Jul 12 21:57:33 · bare journal payload" in text_out
    assert '<th class="col-first">first</th>' in html_out
    assert '<td class="data col-first">Jul 12 21:57:33</td>' in html_out
    assert '<div class="clip">bare journal payload</div>' in html_out


def test_syslog_burst_reboot_label_follows_host_and_timestamp_leads() -> None:
    finding = _f("syslog", Severity.INFO, "host-burst", {
        "tier": "burst", "line_count": 3, "span_seconds": 2.0,
        "start_ts": 0.0, "end_ts": 2.0,
        "program_mix": [["kernel", 3]], "sample_raw": ["a", "b", "c"],
        "label": "rebooted",
    })
    cells = project_row(finding)
    assert [(cell.key, cell.value) for cell in cells] == [
        ("first", "Jan  1 00:00:00"),
        (None, "host-burst · rebooted · 3 rare lines · 2s · mostly kernel"),
    ]

    indeterminate = _f("syslog", Severity.INFO, "host-no-burst-time", {
        "tier": "burst", "line_count": 3, "span_seconds": 2.0,
        "start_ts": None, "end_ts": None,
        "program_mix": [["kernel", 3]], "sample_raw": ["a", "b", "c"],
        "label": "rebooted",
    })
    cells = project_row(indeterminate)
    assert [(cell.key, cell.value) for cell in cells] == [
        (None, "host-no-burst-time · rebooted · 3 rare lines · 2s · mostly kernel"),
    ]
    assert cells[0].full_width is True


def test_syslog_reboot_timestamp_uses_display_formatter_and_null_vanishes(
    restore_display_utc,
) -> None:
    stamped = _f("syslog", Severity.INFO, "host-reboot", {
        "tier": "reboot", "host": "host-reboot",
        "reboot_ts": "2026-06-01T07:08:09+00:00", "label": "rebooted",
    })
    assert [(cell.key, cell.value) for cell in project_row(stamped)] == [
        ("first", "Jun  1 07:08:09"),
        (None, "host-reboot · rebooted"),
    ]

    set_display_utc(True)
    assert [(cell.key, cell.value) for cell in project_row(stamped)] == [
        ("first", "Jun  1 07:08:09 UTC"),
        (None, "host-reboot · rebooted"),
    ]

    indeterminate = _f("syslog", Severity.INFO, "host-unknown", {
        "tier": "reboot", "host": "host-unknown",
        "reboot_ts": None, "label": "rebooted",
    })
    cells = project_row(indeterminate)
    assert [(cell.key, cell.value) for cell in cells] == [
        (None, "host-unknown · rebooted"),
    ]
    assert cells[0].full_width is True
    rendered = _text([indeterminate])
    assert "host-unknown · rebooted" in rendered
    assert "rebooted @" not in rendered


@pytest.mark.parametrize("variant", ["syslog_family", "syslog_burst"])
def test_syslog_member_fragment_parity_outside_projector(variant: str) -> None:
    finding = _VARIANTS[variant]
    fragments = finding.evidence["member_fragments"]
    text_out = _text([finding])
    html_out = _html_text([finding])
    for fragment in fragments:
        assert fragment in text_out
        assert fragment in html_out


def test_projection_covers_every_detector_variant() -> None:
    """project_row + section_columns handle every detector/variant without error,
    and produce a stable positional column template (no KeyError / empty grid)."""
    for variant, finding in _VARIANTS.items():
        cells = project_row(finding)
        assert cells, f"{variant}: empty projection"
        # section_columns must not raise and must be positional (len >= row width
        # for a single-row grid, full_width rows excepted).
        sec = Section(None, [finding], 1)
        cols = section_columns(sec)
        if cells[0].full_width:
            assert cols == []  # full-width carries no grid columns
        else:
            assert len(cols) == len(cells)
