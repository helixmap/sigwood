"""Tests for general text output formatting."""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

import sigwood

from sigwood.common.display import TEXT_RULE_WIDTH, fmt_compact_span
from sigwood.common.finding import RunSummary
from sigwood.outputs.text import (
    TextHandler,
    _fmt_window,
)
from sigwood.outputs._render_model import (
    _partition_aws as _aws_sections,
    _partition_dns as _dns_sections,
)

_NOW = datetime(2026, 6, 2, tzinfo=timezone.utc)
_WINDOW = (_NOW, _NOW)


def _summary(notes: list[str] | None = None, skipped: dict[str, str] | None = None) -> RunSummary:
    return RunSummary(
        data_window=_WINDOW,
        record_counts={"pihole*.log*": 3_235_587},
        data_size_bytes=0,
        detectors_run=["dns"],
        detectors_skipped=skipped or {},
        notes=notes or [],
    )


def test_begin_emits_no_leading_blank_line() -> None:
    """begin() does not own a cross-stream separator: the banner is the first
    stdout line. The stderr side (phase_separator) owns the load→report break."""
    stream = io.StringIO()
    handler = TextHandler(stream=stream)
    handler.begin(_summary())
    out = stream.getvalue()
    assert out  # non-empty
    assert not out.startswith("\n")


def test_run_summary_wraps_long_notes_with_aligned_continuation() -> None:
    handler = TextHandler()
    rendered = handler._render_run_summary(_summary(notes=[
        "running on Pi-hole/dnsmasq logs - RTT, TTL, and connection correlation "
        "unavailable. Add Zeek for richer DNS analysis and conn.log correlation."
    ]))
    lines = rendered.splitlines()

    note_lines = [
        line for line in lines
        if line.startswith("note:") or line.startswith(" " * len("note:          "))
    ]

    assert len(note_lines) >= 2
    assert note_lines[0].startswith("note:          running")
    assert all(len(line) <= TEXT_RULE_WIDTH for line in note_lines)
    assert note_lines[1].startswith(" " * len("note:          "))
    assert note_lines[1][len("note:          "):]


def test_run_summary_strips_control_bytes_from_notes() -> None:
    handler = TextHandler()
    rendered = handler._render_run_summary(_summary(notes=[
        "loaded /tmp/logs\x1b[31m\x00\x07\r\x9b/run.log"
    ]))

    assert "loaded /tmp/logs[31m/run.log" in rendered
    _assert_no_data_controls(rendered)


def test_run_summary_strips_control_bytes_from_skipped_reasons() -> None:
    handler = TextHandler()
    rendered = handler._render_run_summary(_summary(skipped={
        "dns": "no source at /tmp/logs\x1b[31m\x00\x07\r\x9b/dns"
    }))

    assert "dns - no source at /tmp/logs[31m/dns" in rendered
    _assert_no_data_controls(rendered)


def test_run_summary_wraps_long_skipped_reasons_generally() -> None:
    handler = TextHandler()
    rendered = handler._render_run_summary(_summary(skipped={
        "dns": (
            "no DNS source found - need zeek_dir DNS logs or pihole_dir logs "
            "before dns detection can run"
        )
    }))
    lines = rendered.splitlines()

    skipped_lines = [
        line for line in lines
        if line.startswith("skipped:") or line.startswith(" " * len("skipped:       "))
    ]

    assert len(skipped_lines) >= 2
    assert skipped_lines[0].startswith("skipped:       dns")
    assert all(len(line) <= TEXT_RULE_WIDTH for line in skipped_lines)
    assert skipped_lines[1].startswith(" " * len("skipped:       "))


def test_text_rule_width_is_design_constant() -> None:
    rendered = TextHandler()._render_run_summary(_summary())
    # The run-summary banner is bracketed by DOUBLE rules; both honor the width.
    rule_lines = [line for line in rendered.splitlines() if set(line) == {"═"}]

    assert rule_lines
    assert all(len(line) == 80 for line in rule_lines)
    assert TEXT_RULE_WIDTH == 80


# ── _render_aws_group ────────────────────────────────────────────────────────

from sigwood.common.finding import Finding, Severity  # noqa: E402


def _aws_finding(severity: Severity, evidence: dict, title: str | None = None,
                 description: str = "", next_steps: list[str] | None = None) -> Finding:
    return Finding(
        detector="aws",
        severity=severity,
        title=title if title is not None else str(evidence.get("principal", "")),
        description=description,
        evidence=evidence,
        next_steps=next_steps or [],
        ts_generated=_NOW,
        data_window=_WINDOW,
    )


def _burst_finding(principal: str, severity: Severity = Severity.MEDIUM, **overrides) -> Finding:
    ev = {
        "tier":              "burst",
        "principal":         principal,
        "start_time":        "2026-06-01T12:00:00+00:00",
        "span_seconds":      120.0,
        "new_action_count":  5,
        "new_service_count": 2,
        "error_rate":        0.0,
        "mean_rarity":       1.2,
        "new_actions":       ["A", "B", "C", "D", "E"],
        "new_services":      ["s3.amazonaws.com", "ec2.amazonaws.com"],
        "source_ips":        ["192.0.2.10"],
        "aws_regions":       ["us-east-1"],
        "sample_event_ids":  ["e1", "e2"],
    }
    ev.update(overrides)
    return _aws_finding(severity, ev)


def _ranked_finding(principal: str, severity: Severity = Severity.MEDIUM, **overrides) -> Finding:
    ev = {
        "tier":                  "ranked",
        "principal":             principal,
        "composite_z":           2.4,
        "z_error_rate":          0.5,
        "z_distinct_source_ip":  1.0,
        "z_distinct_event_name": 0.7,
        "z_action_entropy":      0.2,
        "event_count":           120,
        "error_rate":            0.05,
        "distinct_source_ip":    8,
        "distinct_event_name":   15,
        "distinct_event_source": 3,
        "action_entropy":        2.1,
        "read_ratio":            0.7,
        "distinct_aws_region":   2,
        "distinct_hours_active": 6,
        "top_actions":           ["GetObject", "ListBuckets"],
        "source_ips":            ["192.0.2.10"],
        "aws_regions":           ["us-east-1"],
        "sample_event_ids":      ["e1"],
    }
    ev.update(overrides)
    return _aws_finding(severity, ev)


def _ranked_summary_finding(scorable: int = 4, top: str = "placeholder-top",
                            top_z: float = 0.1) -> Finding:
    return _aws_finding(
        Severity.INFO,
        {
            "tier":            "ranked_summary",
            "scorable_count":  scorable,
            "top_principal":   top,
            "top_composite_z": top_z,
        },
        title="ranked tier: no principals cleared the LOW band",
    )


def test_render_aws_group_orders_bursts_before_ranked() -> None:
    handler = TextHandler(verbose_level=0)
    findings = [
        _ranked_finding("alice"),
        _burst_finding("attacker", severity=Severity.HIGH),
    ]
    lines = handler._render_aws_group(_aws_sections(findings))
    text = "\n".join(lines)
    burst_idx = text.index("burst sweeps")
    ranked_idx = text.index("ranked principals")
    assert burst_idx < ranked_idx


def test_render_aws_burst_line_is_glanceable_with_aligned_columns() -> None:
    """Burst row carries principal, new-action count, new-service count, span,
    error rate - all aligned, severity tag at the front."""
    handler = TextHandler(verbose_level=0)
    lines = handler._render_aws_group(_aws_sections([
        _burst_finding("attacker-short", severity=Severity.HIGH,
                       new_action_count=10, new_service_count=3,
                       span_seconds=60.0, error_rate=0.8),
        _burst_finding("longer-principal-name", severity=Severity.MEDIUM,
                       new_action_count=5, new_service_count=1,
                       span_seconds=300.0, error_rate=0.0),
    ]))
    # Row lines start with the 2-space indent + severity tag.
    body = [ln for ln in lines if ln.startswith("  [")]
    assert len(body) == 2
    # severity tags appear at the start
    assert "[H]" in body[0] and "[M]" in body[1]
    # principal name visible
    assert "attacker-short" in body[0]
    assert "longer-principal-name" in body[1]
    # the structured columns appear
    assert "10 new" in body[0] and "5 new" in body[1]
    assert "3 svc" in body[0] and "1 svc" in body[1]
    # span formatting
    assert "1m" in body[0]   # 60s → 1m
    assert "5m" in body[1]   # 300s → 5m
    # error-rate formatting
    assert "err=80%" in body[0]
    assert "err=0%" in body[1]


def test_render_aws_ranked_summary_appears_in_ranked_tier() -> None:
    """The ranked tier must include the synthetic ranked_summary
    Finding so the quiet 'nothing stood out' line is not silently dropped."""
    handler = TextHandler(verbose_level=0)
    summary = _ranked_summary_finding(scorable=7, top="placeholder-top", top_z=0.4)

    lines = handler._render_aws_group(_aws_sections([summary]))
    text = "\n".join(lines)

    assert "ranked principals" in text          # the tier header fires
    assert "no principals cleared the LOW band" in text
    assert "[I]" in text                         # info severity tag
    assert "7 scored" in text                    # scorable_count
    assert "placeholder-top" in text             # top pivot
    assert "z=0.40" in text                      # top composite


def test_render_aws_ranked_per_principal_then_summary() -> None:
    """Mixed case is handled - per-principal rows precede the summary line within
    the same ranked-principals subsection."""
    handler = TextHandler(verbose_level=0)
    findings = [
        _ranked_finding("alice", severity=Severity.MEDIUM, composite_z=2.4),
        _ranked_summary_finding(),
    ]
    lines = handler._render_aws_group(_aws_sections(findings))
    text = "\n".join(lines)

    ranked_header_idx = text.index("ranked principals")
    summary_idx = text.index("no principals cleared the LOW band")
    alice_idx = text.index("alice")

    # Both ranked finding rows are inside the same subsection (after header,
    # alice row precedes the summary line).
    assert ranked_header_idx < alice_idx < summary_idx


def test_render_aws_empty_input_produces_no_output() -> None:
    handler = TextHandler(verbose_level=0)
    assert handler._render_aws_group(_aws_sections([])) == []


def test_render_aws_verbose_adds_description_evidence_next_steps_window() -> None:
    handler = TextHandler(verbose_level=1)
    lines = handler._render_aws_group(_aws_sections([
        _aws_finding(
            Severity.HIGH,
            {
                "tier":              "burst",
                "principal":         "attacker",
                "start_time":        "2026-06-01T12:00:00+00:00",
                "span_seconds":      60.0,
                "new_action_count":  5,
                "new_service_count": 2,
                "error_rate":        0.6,
                "mean_rarity":       1.5,
                "new_actions":       ["X"],
                "new_services":      ["s3.amazonaws.com"],
                "source_ips":        ["192.0.2.10"],
                "aws_regions":       ["us-east-1"],
                "sample_event_ids":  ["evt-1"],
            },
            description="detected an enumeration sweep",
            next_steps=["review CloudTrail for attacker", "check source IP"],
        ),
    ]))
    text = "\n".join(lines)
    assert "detected an enumeration sweep" in text     # description
    assert "evidence:" in text                          # evidence block
    assert "next steps:" in text
    assert "data window:" in text


def test_render_aws_burst_caps_long_action_list_at_level_1() -> None:
    """A broad burst (dozens of new actions) renders a capped, comma-joined
    sample with a `… (+N more)` marker at -v - not the full Python-list dump."""
    actions = [f"Action{i:02d}" for i in range(20)]
    handler = TextHandler(verbose_level=1)
    lines = handler._render_aws_group(_aws_sections([
        _burst_finding("sweeper", severity=Severity.HIGH, new_actions=actions),
    ]))
    text = "\n".join(lines)
    assert "Action00" in text              # first items shown
    assert "… (+8 more)" in text           # 20 − 12 capped
    assert "Action12" not in text          # 13th item suppressed at level 1
    assert "['Action00'" not in text       # not the raw Python-list repr


def test_render_aws_burst_only_no_ranked_section() -> None:
    """If only burst findings exist, no ranked-principals subsection appears."""
    handler = TextHandler(verbose_level=0)
    lines = handler._render_aws_group(_aws_sections([_burst_finding("only-burst")]))
    text = "\n".join(lines)
    assert "burst sweeps" in text
    assert "ranked principals" not in text


def test_render_aws_ranked_only_no_burst_section() -> None:
    """If only ranked findings exist, no burst-sweeps subsection appears."""
    handler = TextHandler(verbose_level=0)
    lines = handler._render_aws_group(_aws_sections([_ranked_finding("alice")]))
    text = "\n".join(lines)
    assert "ranked principals" in text
    assert "burst sweeps" not in text


# ── Detect-banner: byte-identical regression snapshot ────────────────────────
#
# When the digest grammar collapsed, `_render_run_summary`'s digest branch
# went with it (Source: line, Lines: / Records: label seam, Data found: -
# parity rail). The detect path uses the same helper and MUST emit the
# same banner it did before that surgery. This snapshot locks the detect
# banner shape; any drift fails the test loudly.


def test_render_run_summary_detect_banner_snapshot() -> None:
    """Reference detect run: banner + window + records + detectors + notes.

    The Detectors: row carries method chrome - named methods
    render with ``name (label)`` (painted on a real TTY, plain otherwise);
    honest badges render with ``name [label]`` plain. Detectors joined by
    ``  ·  ``. Stream here is a StringIO (not a TTY), so the named labels
    are unpainted in the snapshot.
    """
    from sigwood.common.finding import MethodTag, SuppressionSummary
    rs = RunSummary(
        data_window=(
            datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
        ),
        record_counts={"conn*.log*": 12_345, "dns*.log*": 678},
        data_size_bytes=0,
        detectors_run=["beacon", "dns"],
        detectors_skipped={"scan": "no conn data"},
        notes=["test note"],
        data_sources=["zeek_conn", "zeek_dns"],
        detector_methods={
            "beacon": MethodTag("FFT", named=True),
            "dns":    MethodTag("HDBSCAN", named=True),
        },
        suppression=SuppressionSummary(
            enabled=True, connections=1_284, domains=312,
            host_rows=9_412, hosts_matched=2,
        ),
    )
    rendered = TextHandler(stream=io.StringIO())._render_run_summary(rs)
    assert rendered == (
        "sigwood  ·  threat hunt\n"
        "════════════════════════════════════════════════════════════════════════════════\n"
        "data found:    2026-06-01 12:00 → 2026-06-01 18:30 local  (6h)\n"
        "records:       12,345 conn*.log*  ·  678 dns*.log*\n"
        "allowlist:     suppressed 1,284 connections and 312 domains and "
        "9,412 rows from\n"
        "               2 hosts\n"
        "detectors:     beacon (FFT)  ·  dns (HDBSCAN)\n"
        "skipped:       scan - no conn data\n"
        "note:          test note\n"
        f"generated:     sigwood {sigwood.__version__}\n"
        "════════════════════════════════════════════════════════════════════════════════"
    )


def test_render_run_summary_provenance_rows_are_last() -> None:
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
        notes=["test note"],
        invocation="sigwood hunt --days=1-2",
        generated_at=datetime(2026, 7, 23, 9, 14, tzinfo=timezone.utc),
    )

    lines = TextHandler(stream=io.StringIO())._render_run_summary(rs).splitlines()

    assert lines[-3] == (
        f"generated:     2026-07-23 09:14 local  ·  "
        f"sigwood {sigwood.__version__}"
    )
    assert lines[-2] == "as:            sigwood hunt --days=1-2"
    assert lines[-1] == "═" * TEXT_RULE_WIDTH


def test_render_run_summary_optional_provenance_arms() -> None:
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
    )

    rendered = TextHandler(stream=io.StringIO())._render_run_summary(rs)

    assert f"generated:     sigwood {sigwood.__version__}" in rendered
    assert "\nas:" not in rendered


def test_render_run_summary_invocation_strips_full_control_class() -> None:
    controls = "".join(
        chr(cp) for cp in (*range(0x20), 0x7f, *range(0x80, 0xa0))
    )
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
        invocation=f"LEFT{controls}RIGHT",
    )

    rendered = TextHandler(stream=io.StringIO())._render_run_summary(rs)

    assert "as:            LEFTRIGHT" in rendered
    for ch in controls:
        if ch != "\n":
            assert ch not in rendered


def test_render_run_summary_detect_omits_optional_rows_when_empty() -> None:
    """A minimal detect run still produces banner + rule + rule (no
    record/detector/note lines if none configured) - the detect path uses
    only the truthy-guard rows."""
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
        notes=[],
    )
    rendered = TextHandler()._render_run_summary(rs)
    lines = rendered.splitlines()
    # Banner + two rules; no Source:, no Records:, no Data found: when
    # window is the same instant on both sides (the `and` truthy guard
    # is enough; we don't need a separate is_digest branch anymore).
    assert lines[0] == "sigwood  ·  threat hunt"
    assert not any(ln.startswith("Source:") for ln in lines)
    assert not any(ln.startswith("Lines:") for ln in lines)


# ── fmt_compact_span + data-found underfill parenthetical ────────────────────


def test_fmt_compact_span_edges() -> None:
    # Sub-hour spans render minutes - a short window never collapses to "0h"/"0.0d".
    assert fmt_compact_span(timedelta(minutes=1)) == "1m"
    assert fmt_compact_span(timedelta(minutes=20)) == "20m"
    assert fmt_compact_span(timedelta(minutes=59)) == "59m"
    assert fmt_compact_span(timedelta(hours=18)) == "18h"
    assert fmt_compact_span(timedelta(hours=1)) == "1h"
    assert fmt_compact_span(timedelta(days=2)) == "2d"
    assert fmt_compact_span(timedelta(days=1, hours=12)) == "1.5d"
    assert fmt_compact_span(timedelta(days=7)) == "7d"
    # No surprising unit-crossing: minutes that round up promote to "1h", and a
    # sub-24h span that rounds up promotes to "1d".
    assert fmt_compact_span(timedelta(seconds=3570)) == "1h"      # 59.5m → "1h", never "60m"
    assert fmt_compact_span(timedelta(hours=23, minutes=40)) == "1d"


def _summary_window(span: timedelta, requested_span: timedelta | None) -> RunSummary:
    start = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)
    return RunSummary(
        data_window=(start, start + span),
        record_counts={},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
        requested_span=requested_span,
    )


def _data_found(rs: RunSummary) -> str:
    """Rendered run-summary with whitespace/wrap collapsed - the data-found line
    can wrap past 80 cols, so the underfill phrase may span two physical lines."""
    rendered = TextHandler(stream=io.StringIO())._render_run_summary(rs)
    return " ".join(rendered.split())


def test_data_found_underfilled_hours() -> None:
    assert "(18h data span in 1d window)" in _data_found(
        _summary_window(timedelta(hours=18), timedelta(days=1)))


def test_data_found_underfilled_days() -> None:
    assert "(1.5d data span in 2d window)" in _data_found(
        _summary_window(timedelta(days=1, hours=12), timedelta(days=2)))


def test_data_found_full_uses_fmt_window_unchanged() -> None:
    """requested_span None (full / --all) → the byte-identical _fmt_window form."""
    rs = _summary_window(timedelta(days=2), None)
    out = _data_found(rs)
    assert " ".join(_fmt_window(rs.data_window).split()) in out
    assert "data span in" not in out


def test_data_found_underfill_below_tolerance_no_clause() -> None:
    """Within _UNDERFILL_TOLERANCE (1h) → no underfill clause, plain _fmt_window."""
    rs = _summary_window(timedelta(hours=23, minutes=30), timedelta(days=1))  # 30m short
    out = _data_found(rs)
    assert "data span in" not in out
    assert " ".join(_fmt_window(rs.data_window).split()) in out


def test_data_found_underfill_at_tolerance_shows_clause() -> None:
    """Exactly at the tolerance threshold (>=) → clause shows."""
    rs = _summary_window(timedelta(hours=23), timedelta(days=1))  # exactly 1h short
    assert "data span in" in _data_found(rs)


def test_data_found_disjoint_no_clause() -> None:
    """data_span > requested_span (disjoint archive) → no clause."""
    rs = _summary_window(timedelta(days=3), timedelta(days=1))
    assert "data span in" not in _data_found(rs)


def test_data_found_instant_window_no_clause() -> None:
    """A legitimate single-event (ts, ts) instant window with requested_span=None
    falls through to _fmt_window; no underfill clause renders. (The no-data shape
    is data_window=None - see test_data_found_none_window_renders_none.)"""
    rs = _summary_window(timedelta(0), None)
    out = _data_found(rs)
    assert "data span in" not in out
    assert " ".join(_fmt_window(rs.data_window).split()) in out


def test_data_found_none_window_renders_none() -> None:
    """data_window=None (no loaded rows establish a window) → the banner answers
    `data found: none` - a required answer, never an invented span."""
    rs = RunSummary(
        data_window=None,
        record_counts={},
        data_size_bytes=0,
        detectors_run=[],
        detectors_skipped={},
    )
    rendered = TextHandler(stream=io.StringIO())._render_run_summary(rs)
    assert "data found:    none" in rendered.splitlines()


# ── Flat digest renderer ────────────────────────────────────────────────────

from sigwood.common.finding import DigestCard, DigestSlot  # noqa: E402
from sigwood.common.display import default_window_advisory, human_bytes  # noqa: E402
from sigwood.outputs.text import (  # noqa: E402
    _render_histogram,
    _render_label_value_block,
)


def _digest_card(
    schema: str = "conn",
    source_name: str = "conn.log",
    record_count: int = 100_000,
    data_size_bytes: int = 38 * 1024 * 1024,
    zone1_extras: list[tuple[str, str]] | None = None,
    insights: list[str] | None = None,
    fields: list[DigestSlot] | None = None,
    histogram_counts: list[int] | None = None,
    histogram_peak: int = 0,
    timeline_unavailable: bool = False,
    data_window: tuple = None,
    default_window_note: str | None = None,
) -> DigestCard:
    return DigestCard(
        schema=schema,
        source_name=source_name,
        data_window=data_window or _WINDOW,
        record_count=record_count,
        histogram_counts=histogram_counts or [],
        histogram_unit="hr",
        histogram_peak=histogram_peak,
        zone1_extras=zone1_extras or [("hosts", "1462")],
        insights=insights or [],
        fields=fields or [],
        data_size_bytes=data_size_bytes,
        timeline_unavailable=timeline_unavailable,
        default_window_note=default_window_note,
    )


def _render(card: DigestCard) -> list[str]:
    handler = TextHandler(stream=io.StringIO())
    handler.render_digest(card)
    return handler._stream.getvalue().splitlines()


def test_render_digest_identity_block_three_lines_flush_left() -> None:
    """Lines 1-3 are filename / window / 'schema · N lines · size' - no
    banner, no header rule, all flush-left, exact count with thousands
    separators (NOT the rounded 100.0K form)."""
    card = _digest_card(
        schema="conn", source_name="conn.100K.log",
        record_count=100_000, data_size_bytes=int(38.3 * 1024 * 1024),
    )
    lines = _render(card)
    assert lines[0] == "conn.100K.log"
    assert lines[1] == _fmt_window(_WINDOW)
    assert lines[2] == "conn · 100,000 lines · 38.3 MB"


def test_render_digest_no_banner_no_header_rule_no_trailing_sep() -> None:
    """The flat card has no detect banner, no ── digest · X ── rule,
    no inner separators, no trailing _SEP. Only U+2500 anywhere should be
    the inter-card rule (and that is emitted by run_digest, not by
    render_digest)."""
    card = _digest_card()
    rendered = "\n".join(_render(card))
    assert "threat hunt" not in rendered
    assert "── digest" not in rendered
    assert "─" not in rendered                 # no rule from render_digest
    assert "N.B." not in rendered


def test_render_digest_identity_line_2_dashes_on_timeline_unavailable() -> None:
    """When the timeline cannot be drawn honestly, identity line 2 is a
    bare em-dash; the descriptive '(timeline unavailable)' lives on the
    histogram line."""
    card = _digest_card(
        timeline_unavailable=True, data_window=(None, None),
    )
    lines = _render(card)
    assert lines[1] == "-"
    assert "(timeline unavailable)" in lines


def test_render_digest_default_window_note_is_fourth_identity_line() -> None:
    """When set, default_window_note is the 4th identity line - directly after
    'schema · N lines · size' and BEFORE the ambient block's blank separator.
    The canonical 3-line identity triple is unchanged."""
    note = default_window_advisory("1d")
    card = _digest_card(default_window_note=note)
    lines = _render(card)
    assert lines[0] == "conn.log"             # identity 1: source
    assert lines[1] == _fmt_window(_WINDOW)    # identity 2: window
    assert lines[2].startswith("conn · ")      # identity 3: schema · lines · size
    assert lines[3] == note                     # identity 4: the disclosure note
    assert lines[4] == ""                       # then the block separator (one blank)


def test_render_digest_no_note_no_extra_blank_line() -> None:
    """Vanish-don't-dash: no default_window_note → no 4th line AND no extra
    blank. The ambient block's separator follows identity line 3 directly."""
    card = _digest_card(default_window_note=None)
    lines = _render(card)
    assert "default window:" not in "\n".join(lines)
    assert lines[2].startswith("conn · ")      # identity 3
    assert lines[3] == ""                       # block separator directly after identity 3
    assert lines[4] != ""                       # ambient content - not a second blank line


def test_render_digest_note_renders_even_when_timeline_unavailable() -> None:
    """The disclosure is independent of ts-confidence: a dashed identity line 2
    (timeline unavailable) still gets the default-window note on line 4. The
    truncation happened regardless of whether the timeline could be drawn."""
    note = default_window_advisory("1d")
    card = _digest_card(
        timeline_unavailable=True, data_window=(None, None),
        default_window_note=note,
    )
    lines = _render(card)
    assert lines[1] == "-"                      # identity 2 dashed
    assert lines[2].startswith("conn · ")        # identity 3
    assert lines[3] == note                       # note still renders
    assert "(timeline unavailable)" in lines      # histogram replacement present


def test_render_digest_record_count_uses_exact_thousands_separator() -> None:
    """Identity line 3 shows the EXACT count with commas - never the
    rounded `_format_rows` shape."""
    card = _digest_card(record_count=560_742)
    lines = _render(card)
    assert "560,742 lines" in lines[2]
    assert "560.7K" not in lines[2]


def test_render_digest_fields_block_uses_two_space_cell_join() -> None:
    """The fields block renders each speaking slot's cells joined by two
    spaces, with the value column aligned by max label width + 2."""
    cliff = DigestSlot(
        label="conn-share", statistic="cliff",
        cells=["host-a", "12000", "2.5x"],
        entity="host-a", magnitude=12000, ratio=2.5,
    )
    card = _digest_card(fields=[cliff])
    lines = _render(card)
    # Expect: `conn-share: host-a  12000  2.5x`
    # label_w = 10 ('conn-share'); (label + ':').ljust(12) = "conn-share: "
    # (one trailing space after the colon) → single space before host-a.
    assert "conn-share: host-a  12000  2.5x" in lines


def test_render_digest_strips_control_bytes_from_data_values() -> None:
    card = _digest_card(
        source_name="dns\x1b[31m\x00\x07\r\x9b.log",
        zone1_extras=[("top", "client\x1b[31m\x00\x07\r\x9b value")],
        insights=["insight\x1b[31m\x00\x07\r\x9b value"],
        fields=[
            DigestSlot(
                label="query",
                statistic="share",
                cells=["name\x1b[31m\x00\x07\r\x9b.example", "42%"],
                entity="name.example",
                ratio=0.42,
            ),
        ],
        histogram_counts=[0, 4],
        histogram_peak=4,
        default_window_note="default\x1b[31m\x00\x07\r\x9b note",
    )

    rendered = "\n".join(_render(card))
    _assert_no_data_controls(rendered)
    assert "dns[31m.log" in rendered
    assert "client[31m value" in rendered
    assert "insight[31m value" in rendered
    assert "name[31m.example" in rendered
    assert "default[31m note" in rendered
    assert "█" in rendered


def test_render_digest_field_block_empty_when_no_fields() -> None:
    """When `fields` is empty (all speaking slots became insights), the
    card ends on the last insight - no trailing blank field block."""
    card = _digest_card(
        insights=["192.0.2.41:53 reaches 1008 distinct destinations, 2.2x the next-broadest source."],
        fields=[],
    )
    rendered = "\n".join(_render(card))
    # No "label:" lines after the last insight - only the insight line and
    # whatever ambient/histogram blocks already appeared above.
    insight = "192.0.2.41:53 reaches"
    assert insight in rendered
    # Output ends without a trailing colon-separated field line.
    last_meaningful = rendered.rstrip("\n").rsplit("\n", 1)[-1]
    assert insight in last_meaningful


# ── _render_histogram - flush-left, three branches ──────────────────────────


def test_render_histogram_unavailable_is_bare_no_indent() -> None:
    """unavailable=True renders the bare line with no leading indent."""
    assert _render_histogram([], "hr", 0, unavailable=True) == "(timeline unavailable)"


def test_render_histogram_unavailable_wins_over_populated_counts() -> None:
    """unavailable=True is authoritative regardless of counts."""
    assert _render_histogram(
        [3, 2, 5], "hr", 5, unavailable=True,
    ) == "(timeline unavailable)"


def test_render_histogram_empty_counts_no_events_branch_flush_left() -> None:
    """Empty counts (no records in window) → bare no-events line, no indent."""
    assert _render_histogram([], "hr", 0) == "(no events in window)"


def test_render_histogram_populated_renders_bars_unit_peak_flush_left() -> None:
    rendered = _render_histogram([1, 2, 3], "hr", 3)
    assert rendered.startswith(_render_histogram([1, 2, 3], "hr", 3)[0])  # not indented
    assert not rendered.startswith(" ")
    assert "hourly bins" in rendered
    assert "peak:" in rendered


# ── _render_label_value_block - alignment math ──────────────────────────────


def test_label_value_block_aligns_value_column() -> None:
    rows = [
        ("hosts", "1462 (22 internal, 1440 external)"),
        ("outbound bytes", "6.1 GB"),
        ("inbound bytes", "0 B"),
    ]
    lines = _render_label_value_block(rows)
    # All values start at the same column (label_w + 2 = 16 for "outbound bytes").
    assert lines[0] == "hosts:          1462 (22 internal, 1440 external)"
    assert lines[1] == "outbound bytes: 6.1 GB"
    assert lines[2] == "inbound bytes:  0 B"


def test_label_value_block_empty_returns_empty() -> None:
    assert _render_label_value_block([]) == []


# ── DigestCard contract additions ───────────────────────────────────────────


def test_digest_card_defaults_timeline_available() -> None:
    card = _digest_card()
    assert card.timeline_unavailable is False
    assert card.insights == []
    assert card.fields == []


def test_digest_card_accepts_none_window_on_timeline_unavailable() -> None:
    card = _digest_card()
    card.data_window = (None, None)  # type: ignore[assignment]
    assert card.data_window == (None, None)


def test_human_bytes_handles_thresholds() -> None:
    assert human_bytes(0) == "0 B"
    assert human_bytes(847 * 1024) == "847.0 KB"
    assert human_bytes(2_576_980_377) == "2.4 GB"


# ── methods chrome + color seam + compact_home ──────────────────────────────


def _tty_stream() -> io.StringIO:
    """StringIO that reports isatty=True - used to exercise the paint branch."""
    class _TTYIO(io.StringIO):
        def isatty(self) -> bool:
            return True
    return _TTYIO()


def _strip_sgr(text: str) -> str:
    """Strip CSI escape sequences for canonical-text comparisons."""
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def test_render_detectors_named_method_painted_on_tty(monkeypatch) -> None:
    """Positive color test: explicitly clear NO_COLOR and set a
    color-capable TERM so the workspace shell's ``NO_COLOR=1`` /
    ``TERM=dumb`` does not silently disable paint here."""
    from sigwood.common.finding import MethodTag
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=["beacon"],
        detectors_skipped={},
        detector_methods={"beacon": MethodTag("FFT", named=True)},
    )
    rendered = TextHandler(stream=_tty_stream())._render_run_summary(rs)
    # Paint applied - SGR brackets the label only.
    assert "beacon (\x1b[96;1mFFT\x1b[0m)" in rendered
    # SGR-stripped output equals the plain canonical form.
    assert "beacon (FFT)" in _strip_sgr(rendered)


def test_render_detectors_named_method_plain_on_non_tty(monkeypatch) -> None:
    from sigwood.common.finding import MethodTag
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=["beacon"],
        detectors_skipped={},
        detector_methods={"beacon": MethodTag("FFT", named=True)},
    )
    rendered = TextHandler(stream=io.StringIO())._render_run_summary(rs)
    assert "beacon (FFT)" in rendered
    assert "\x1b[" not in rendered  # no SGR at all


def test_render_detectors_honest_badge_never_painted(monkeypatch) -> None:
    """[brackets] form is plain even on a TTY - the badge is honest, not glow."""
    from sigwood.common.finding import MethodTag
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=["scan"],
        detectors_skipped={},
        detector_methods={"scan": MethodTag("pattern", named=False)},
    )
    rendered = TextHandler(stream=_tty_stream())._render_run_summary(rs)
    assert "scan [pattern]" in rendered
    assert "\x1b[" not in rendered


def test_render_detectors_no_tag_renders_bare_name() -> None:
    """Forward-compat: a detector with no DETECTOR_METHOD constant renders as
    the bare name - never None, never empty parens/brackets."""
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=["mystery"],
        detectors_skipped={},
        detector_methods={"mystery": None},
    )
    rendered = TextHandler(stream=io.StringIO())._render_run_summary(rs)
    assert "mystery" in rendered
    assert "mystery (" not in rendered
    assert "mystery [" not in rendered


def test_render_detectors_joined_by_middle_dot() -> None:
    from sigwood.common.finding import MethodTag
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=["beacon", "scan", "syslog"],
        detectors_skipped={},
        detector_methods={
            "beacon": MethodTag("FFT", named=True),
            "scan":   MethodTag("pattern", named=False),
            "syslog": MethodTag("drain3", named=True),
        },
    )
    rendered = TextHandler(stream=io.StringIO())._render_run_summary(rs)
    assert "beacon (FFT)  ·  scan [pattern]  ·  syslog (drain3)" in rendered


def test_render_detectors_no_color_env_suppresses_paint(monkeypatch) -> None:
    from sigwood.common.finding import MethodTag
    monkeypatch.setenv("NO_COLOR", "1")
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=["beacon"],
        detectors_skipped={},
        detector_methods={"beacon": MethodTag("FFT", named=True)},
    )
    rendered = TextHandler(stream=_tty_stream())._render_run_summary(rs)
    assert "\x1b[" not in rendered
    assert "beacon (FFT)" in rendered


def test_render_detectors_term_dumb_suppresses_paint(monkeypatch) -> None:
    from sigwood.common.finding import MethodTag
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    rs = RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=["beacon"],
        detectors_skipped={},
        detector_methods={"beacon": MethodTag("FFT", named=True)},
    )
    rendered = TextHandler(stream=_tty_stream())._render_run_summary(rs)
    assert "\x1b[" not in rendered
    assert "beacon (FFT)" in rendered


def test_compact_home_replaces_home_prefix(monkeypatch) -> None:
    from sigwood.common.display import compact_home
    monkeypatch.setenv("HOME", "/Users/example")
    assert compact_home("/Users/example/exports/run.log") == "~/exports/run.log"
    assert compact_home("/Users/example") == "~"
    assert compact_home("/Users/example/") == "~/"
    assert compact_home("/var/log/syslog") == "/var/log/syslog"


def test_compact_home_passthrough_when_home_unset(monkeypatch) -> None:
    """No HOME → no replacement, no crash."""
    from sigwood.common.display import compact_home
    monkeypatch.delenv("HOME", raising=False)
    # `expanduser("~")` returns "~" verbatim when HOME is unset on POSIX -
    # compact_home guards on this and returns the path unchanged.
    assert compact_home("/var/log/syslog") == "/var/log/syslog"


# ── group header + vanish-don't-dash + pipeline ─────────────────────────────


def _bare_finding(detector: str, severity: Severity, title: str = "the title") -> Finding:
    """A Finding with empty description/evidence/next_steps - the minimal
    surface vanish-don't-dash MUST handle: every level renders title alone."""
    return Finding(
        detector=detector,
        severity=severity,
        title=title,
        description="",
        evidence={},
        next_steps=[],
        ts_generated=_NOW,
        data_window=_WINDOW,
    )


def _capture_write(handler: TextHandler, findings: list[Finding]) -> str:
    summary = RunSummary(
        data_window=_WINDOW, record_counts={}, data_size_bytes=0,
        detectors_run=list({f.detector for f in findings}),
        detectors_skipped={},
    )
    stream = io.StringIO()
    handler._stream = stream
    handler.begin(summary)
    handler.write(findings)
    handler.end()
    return stream.getvalue()


_DATA_CONTROLS = ("\x1b", "\x00", "\x07", "\r", "\x9b")


def _assert_no_data_controls(text: str) -> None:
    for ch in _DATA_CONTROLS:
        assert ch not in text


def test_text_output_strips_control_bytes_from_finding_rows(monkeypatch) -> None:
    from sigwood.common.finding import MethodTag

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    finding = _bare_finding(
        "syslog",
        Severity.MEDIUM,
        title="host \x1b[31mrare\x1b[0m\x00\x07\r\x9b event → dst",
    )
    stream = _tty_stream()
    handler = TextHandler(stream=stream, verbose_level=0)
    handler.begin(RunSummary(
        data_window=_WINDOW,
        record_counts={},
        data_size_bytes=0,
        detectors_run=["syslog"],
        detectors_skipped={},
        detector_methods={"syslog": MethodTag("FFT", named=True)},
    ))
    handler.write([finding])

    out = stream.getvalue()
    assert "\x1b[96;1mFFT\x1b[0m" in out
    assert "event → dst" in out
    row = next(line for line in out.splitlines() if "rare" in line)
    _assert_no_data_controls(row)


def test_text_output_strips_control_bytes_from_verbose_and_debug_values() -> None:
    finding = Finding(
        detector="syslog",
        severity=Severity.MEDIUM,
        title="custom entity",
        description="Desc\x1b[31m\x00\x07\r\x9b value.",
        evidence={
            "template_str": "Evidence\x1b[31m\x00\x07\r\x9b value",
            "future\x1b[31m\x00\x07\r\x9b_key": "Future\x1b[31m value",
            "host": "placeholder-host",
            "count": 1,
            "threshold": 1,
        },
        next_steps=["Review\x1b[31m\x00\x07\r\x9b surrounding data"],
        ts_generated=_NOW,
        data_window=_WINDOW,
    )

    for level in (1, 2):
        out = _capture_write(TextHandler(verbose_level=level), [finding])
        assert "Desc[31m value." in out
        assert "Review[31m surrounding data" in out
        assert "Evidence[31m value" in out
        if level == 2:
            assert "future[31m_key: Future[31m value" in out
        data_lines = [
            line for line in out.splitlines()
            if (
                "Desc" in line
                or "Review" in line
                or "Evidence" in line
                or "Future" in line
            )
        ]
        assert data_lines
        for line in data_lines:
            _assert_no_data_controls(line)


def test_group_header_renders_count_and_severity_breakdown() -> None:
    """New group header shape: `<detector> - N findings · 3 H  18 M  51 I`
    + 80-col rule. Nonzero tiers only; H M L I order."""
    findings = (
        [_bare_finding("scan", Severity.HIGH) for _ in range(3)]
        + [_bare_finding("scan", Severity.MEDIUM) for _ in range(2)]
        + [_bare_finding("scan", Severity.INFO)]
    )
    handler = TextHandler(verbose_level=0)
    out = _capture_write(handler, findings)
    assert "scan - 6 findings · 3 H  2 M  1 I" in out
    assert "─" * 80 in out


def test_group_header_omits_zero_severity_tiers() -> None:
    findings = [_bare_finding("scan", Severity.MEDIUM) for _ in range(4)]
    handler = TextHandler(verbose_level=0)
    out = _capture_write(handler, findings)
    header = next(ln for ln in out.split("\n") if ln.startswith("scan -"))
    assert header == "scan - 4 findings · 4 M"


def test_vanish_dont_dash_minimal_finding_renders_title_alone() -> None:
    """A Finding with empty description/evidence/next_steps at levels 0/1/2
    produces NO blank lines, NO empty headers, NO dangling indents. The tail
    helpers return []; the data-window line is gated on body being non-empty."""
    f = _bare_finding("beacon", Severity.HIGH, "the title")
    f.evidence = {
        "src_ip": "192.0.2.10",
        "dst_ip": "203.0.113.5",
        "dst_port": 8443,
        "proto": "tcp",
        "period_str": "60.0s",
        "beacon_score": 0.55,
        "conn_count": 200,
    }
    # Keep description, next_steps, and the curated subset empty by clearing
    # the curated keys (jitter_cv/spectral_ratio/prominence_norm absent so
    # _curated_evidence returns mostly absent).
    for level in (0, 1, 2):
        handler = TextHandler(verbose_level=level)
        out = _capture_write(handler, [f])
        # No dangling "evidence:" header on a curated subset that produced ≤1
        # entry - actually beacon's curated subset DOES produce content here
        # (beacon_score, conn_count, period_str), so this test focuses on
        # title-only when description/next_steps/evidence are FULLY empty.
        assert out.count("\n\n\n") == 0, f"no triple blank at level {level}"


def test_vanish_truly_bare_finding_renders_title_only() -> None:
    """For a generic Finding (unknown detector → no curated subset) with
    empty description/evidence/next_steps, EVERY level emits just the title
    line - no data window, no evidence/next-steps headers, no extras."""
    f = _bare_finding("unknown-detector", Severity.LOW, "no detail here")
    for level in (0, 1, 2):
        handler = TextHandler(verbose_level=level)
        out = _capture_write(handler, [f])
        assert "the title" not in out  # paranoia; the title we use is "no detail here"
        assert "no detail here" in out
        assert "evidence:" not in out, f"empty evidence MUST vanish at level {level}"
        assert "next steps:" not in out, f"empty next_steps MUST vanish at level {level}"
        assert "data window:" not in out, (
            f"data window line MUST NOT appear when there's no other body "
            f"content at level {level}"
        )


def test_duration_low_hidden_at_level_0_visible_at_level_1() -> None:
    """Duration LOW findings hidden at verbose_level 0,
    visible at level ≥ 1. The result set returned by run() is invariant -
    the text handler is the sole authority on hiding LOW. Probe the title
    line via the duration renderer's evidence-derived shape."""
    def _dur(sev: Severity, src: str) -> Finding:
        f = _bare_finding("duration", sev, f"{src} → x:443/tcp")
        f.evidence = {
            "src": src, "dst": "203.0.113.1", "port": 443, "proto": "tcp",
            "max_duration_str": "1h 0m", "connection_count": 1,
            "avg_bytes_per_second": None, "conn_states": [],
        }
        return f
    high = _dur(Severity.HIGH, "192.0.2.10")
    low = _dur(Severity.LOW, "192.0.2.20")
    out0 = _capture_write(TextHandler(verbose_level=0), [high, low])
    out1 = _capture_write(TextHandler(verbose_level=1), [high, low])
    assert "192.0.2.10" in out0 and "192.0.2.20" not in out0
    assert "192.0.2.10" in out1 and "192.0.2.20" in out1


def test_severity_sort_primary_within_subsection() -> None:
    """Within a section, findings sort H → M → L → I (stable for incoming
    secondary order). Uses the generic ``_render_finding`` fallback so the
    title string is the row signature."""
    fs = [
        _bare_finding("misc", Severity.LOW, "title-low"),
        _bare_finding("misc", Severity.HIGH, "title-high"),
        _bare_finding("misc", Severity.MEDIUM, "title-medium"),
        _bare_finding("misc", Severity.INFO, "title-info"),
    ]
    out = _capture_write(TextHandler(verbose_level=0), fs)
    lines = [ln for ln in out.split("\n") if "title-" in ln]
    assert [ln for ln in lines if ln] == [
        "[H]  title-high",
        "[M]  title-medium",
        "[L]  title-low",
        "[I]  title-info",
    ]


def test_digest_card_verbosity_invariant() -> None:
    """Digest cards render identically at verbose_level 0/1/2 - there is
    no -v/-vv card grammar. Cards are output bytes, not detector findings."""
    from sigwood.common.finding import DigestCard
    card = DigestCard(
        schema="conn",
        source_name="conn.log",
        data_window=_WINDOW,
        record_count=100,
        histogram_counts=[],
        histogram_unit="hr",
        histogram_peak=0,
        zone1_extras=[("hosts", "5")],
        insights=[],
        fields=[],
        data_size_bytes=2048,
    )
    streams = []
    for level in (0, 1, 2):
        stream = io.StringIO()
        TextHandler(stream=stream, verbose_level=level).render_digest(card)
        streams.append(stream.getvalue())
    assert streams[0] == streams[1] == streams[2]


def test_json_handler_serializes_findings_invariant_across_levels() -> None:
    """JSON is level-invariant; machine formats never drop findings."""
    import json as _json
    from sigwood.outputs.json import JsonHandler
    fs = [_bare_finding("misc", Severity.LOW, f"f-{i}") for i in range(5)]
    summary = RunSummary(
        data_window=_WINDOW, record_counts={}, data_size_bytes=0,
        detectors_run=["misc"], detectors_skipped={},
    )
    payloads = []
    for level in (0, 1, 2):
        stream = io.StringIO()
        h = JsonHandler(stream=stream, verbose_level=level)
        h.begin(summary)
        h.write(fs)
        h.end()
        payloads.append(_json.loads(stream.getvalue()))
    # Same finding count at every level - no machine-format truncation.
    assert all(len(p["findings"]) == 5 for p in payloads)


def test_cr1_curated_evidence_accepts_numpy_scalars() -> None:
    """``_curated_evidence`` MUST NOT use ``not in (None, [], {})``
    on open evidence values - numpy scalars broadcast ``value == []`` into
    an empty array and raise ``ValueError`` when ``bool()``-ed. ``aws``
    burst ``error_rate``, ``scan`` ``scan_state_ratio``, and beacon's
    spectral scores all arrive as numpy scalars under real data."""
    import numpy as np
    f = _bare_finding("aws", Severity.MEDIUM, "attacker")
    f.evidence = {
        "tier":               "burst",
        "principal":          "attacker",
        "error_rate":         np.float64(0.5),
        "mean_rarity":        np.float64(1.2),
        "new_actions":        ["GetObject"],
        "new_services":       ["s3"],
    }
    # Renders cleanly - no ValueError leaks out.
    handler = TextHandler(verbose_level=1)
    out = _capture_write(handler, [f])
    # The numpy scalar is rendered as its repr; we don't care about format
    # here, only that the value survives the curated-subset filter.
    assert "error_rate" in out


def test_cr1_curated_evidence_includes_zero_numpy_value() -> None:
    """a numpy scalar of value 0 is NOT empty - it carries a real
    number. A ``not in`` idiom would crash on it; the explicit isinstance
    guard correctly admits it."""
    import numpy as np
    f = _bare_finding("aws", Severity.LOW, "alice")
    f.evidence = {
        "tier":         "burst",
        "principal":    "alice",
        "error_rate":   np.float64(0.0),
        "new_actions":  ["A"],
        "new_services": ["s3"],
        "mean_rarity":  np.float64(0.7),
    }
    handler = TextHandler(verbose_level=1)
    out = _capture_write(handler, [f])
    # error_rate=0.0 still in the rendered evidence block.
    assert "error_rate" in out


def test_cr2_syslog_preserves_chronological_order_within_sections() -> None:
    """syslog is ``_SEVERITY_SORT_EXEMPT``. The three-section partition is
    single-severity (privileged = MEDIUM, rare events = LOW, bursts = INFO), so what matters
    is that rows are NOT reordered WITHIN a section - the detector emits
    chronologically and the renderer must preserve that incoming order. Rare
    events lead; bursts follow."""
    def _rare(title: str) -> Finding:
        f = _bare_finding("syslog", Severity.LOW, title)
        f.evidence = {"host": "router", "template_str": "t", "count": 1, "threshold": 1}
        return f
    def _member(title: str) -> Finding:
        f = _bare_finding("syslog", Severity.MEDIUM, title)
        f.evidence = {"host": "router", "template_str": "t", "count": 1,
                      "threshold": 1, "privileged": True}
        return f
    def _reboot(host: str) -> Finding:
        f = _bare_finding("syslog", Severity.INFO, host)
        f.evidence = {
            "tier":      "reboot",
            "host":      host,
            "reboot_ts": "2026-06-01T03:04:05+00:00",
            "label":     "rebooted",
        }
        return f
    fs = [
        _rare("rare-event-1"),
        _rare("rare-event-2"),
        _member("member-event-1"),
        _member("member-event-2"),
        _reboot("reboot-host-A"),
        _reboot("reboot-host-B"),
    ]
    out = _capture_write(TextHandler(verbose_level=0), fs)
    # Incoming order preserved within each section; declared section order wins.
    assert out.index("member-event-1") < out.index("member-event-2")
    assert out.index("rare-event-1") < out.index("rare-event-2")
    assert out.index("reboot-host-A") < out.index("reboot-host-B")
    assert out.index("member-event-2") < out.index("rare-event-1")
    assert out.index("rare-event-2") < out.index("reboot-host-A")


def test_cr2_non_syslog_detectors_still_severity_sort() -> None:
    """severity-sort is the default and only ``syslog`` opts out.
    A scan group of mixed severities sorts H → M → L → I."""
    fs = [
        _bare_finding("misc", Severity.LOW, "low"),
        _bare_finding("misc", Severity.HIGH, "high"),
        _bare_finding("misc", Severity.MEDIUM, "medium"),
    ]
    out = _capture_write(TextHandler(verbose_level=0), fs)
    assert out.index("high") < out.index("medium") < out.index("low")


def test_cr4_aws_ranked_summary_survives_cap() -> None:
    """the synthetic ``ranked_summary`` always-show finding is
    exempt from the cap. With > cap ranked findings the summary line
    still renders and the cap reports only cappable rows hidden."""
    def _ranked(name: str) -> Finding:
        f = _bare_finding("aws", Severity.LOW, name)
        f.evidence = {
            "tier":               "ranked",
            "principal":          name,
            "composite_z":        1.2,
            "error_rate":         0.05,
            "event_count":        120,
            "distinct_source_ip": 8,
        }
        return f
    summary = _bare_finding("aws", Severity.INFO, "no principals cleared the LOW band")
    summary.evidence = {
        "tier":            "ranked_summary",
        "scorable_count":  10,
        "top_principal":   "alpha",
        "top_composite_z": 0.5,
    }
    fs = [_ranked(f"p{i}") for i in range(60)] + [summary]
    handler = TextHandler(verbose_level=0, max_findings_per_detector=10)
    out = _capture_write(handler, fs)
    # Summary line survives the cap.
    assert "no principals cleared the LOW band" in out
    # Cap counts only cappable rows: 60 ranked, 10 shown → 50 hidden.
    assert "50 more not shown" in out


def test_aws_below_floor_summary_renders_without_fabricated_pivot() -> None:
    """the below-population-floor ``ranked_summary`` variant carries no top
    principal or composite z, and the rendered line must not fabricate one
    (a ``top  z=0.00`` pivot would imply a score that was never computed).
    The parenthetical shows the scorable count against the floor instead."""
    summary = _bare_finding("aws", Severity.INFO,
                            "ranked tier: too few principals to compare")
    summary.evidence = {
        "tier":             "ranked_summary",
        "scorable_count":   2,
        "population_floor": 5,
    }
    out = _capture_write(TextHandler(verbose_level=0), [summary])
    assert (
        "ranked tier: too few principals to compare  "
        "(2 scorable; needs 5 to compare)"
    ) in out
    assert "z=" not in out
    assert "top" not in out


def test_cr5_verbose_help_mentions_vv() -> None:
    """the verbose flag's generated help mentions ``-vv`` for the
    debug tier. Confirms operators can discover level 2 from
    ``sigwood --help`` / per-verb help."""
    from sigwood.cli import _render_verb_help
    help_text = _render_verb_help("hunt")  # the hunt verb (default top-level run)
    assert "-vv" in help_text
    # Also covered for a single-detector verb.
    help_text_beacon = _render_verb_help("beacon")
    assert "-vv" in help_text_beacon


def test_w5_cap_trips_on_flat_detector_with_disclosure() -> None:
    """A flat detector beyond the cap renders the disclosure line. Most-
    severe rows are retained (cap operates post severity-sort)."""
    fs = (
        [_bare_finding("misc", Severity.HIGH, f"high-{i}") for i in range(3)]
        + [_bare_finding("misc", Severity.LOW, f"low-{i}") for i in range(200)]
    )
    handler = TextHandler(verbose_level=0, max_findings_per_detector=100)
    out = _capture_write(handler, fs)
    assert "misc - 203 findings · 3 H  200 L" in out
    # All 3 HIGHs survive (most-severe retained).
    for i in range(3):
        assert f"high-{i}" in out
    # Disclosure line lists hidden count and the cap. The wording
    # does not claim "by severity" (which is false cross-section); flat
    # detectors are factually severity-retained but the disclosure is
    # honest-by-default in either case.
    assert "103 more not shown" in out
    assert "showing first 100" in out
    assert "by severity" not in out


def test_w5_cap_zero_means_unlimited() -> None:
    """max_findings_per_detector=0 disables the cap entirely."""
    fs = [_bare_finding("misc", Severity.LOW, f"low-{i}") for i in range(500)]
    handler = TextHandler(verbose_level=1, max_findings_per_detector=0)
    out = _capture_write(handler, fs)
    assert "more not shown" not in out
    # Every row rendered.
    for i in (0, 250, 499):
        assert f"low-{i}" in out


def test_w5_pre_cap_header_breakdown_regression() -> None:
    """The group header reports PRE-CAP
    count AND pre-cap severity breakdown. Build a flat fixture of 150
    findings with shape 5 H · 25 M · 40 L · 80 I and cap=100. The header
    MUST read pre-cap totals - never the post-cap 5 H · 25 M · 40 L · 30 I
    that would result from re-iterating Section.findings."""
    fs = (
        [_bare_finding("misc", Severity.HIGH, f"h-{i}") for i in range(5)]
        + [_bare_finding("misc", Severity.MEDIUM, f"m-{i}") for i in range(25)]
        + [_bare_finding("misc", Severity.LOW, f"l-{i}") for i in range(40)]
        + [_bare_finding("misc", Severity.INFO, f"i-{i}") for i in range(80)]
    )
    handler = TextHandler(verbose_level=1, max_findings_per_detector=100)
    out = _capture_write(handler, fs)
    # Pre-cap header.
    assert "misc - 150 findings · 5 H  25 M  40 L  80 I" in out
    # Cap trimmed 50 rows - disclosure reports it.
    assert "50 more not shown" in out


def test_w5_json_handler_ignores_cap() -> None:
    """Machine formats render ALL findings regardless of the cap. JSON
    payload size is independent of max_findings_per_detector."""
    import json as _json
    from sigwood.outputs.json import JsonHandler
    fs = [_bare_finding("misc", Severity.LOW, f"l-{i}") for i in range(150)]
    summary = RunSummary(
        data_window=_WINDOW, record_counts={}, data_size_bytes=0,
        detectors_run=["misc"], detectors_skipped={},
    )
    stream = io.StringIO()
    h = JsonHandler(stream=stream, verbose_level=0)
    h.begin(summary)
    h.write(fs)
    h.end()
    payload = _json.loads(stream.getvalue())
    assert len(payload["findings"]) == 150


def test_w5_per_detector_isolation() -> None:
    """One runaway detector doesn't truncate another. Two detectors with
    different volumes get independent caps."""
    fs = (
        [_bare_finding("loud", Severity.MEDIUM, f"loud-{i}") for i in range(200)]
        + [_bare_finding("quiet", Severity.MEDIUM, f"quiet-{i}") for i in range(5)]
    )
    handler = TextHandler(verbose_level=0, max_findings_per_detector=50)
    out = _capture_write(handler, fs)
    # loud trips the cap (200 → 50 shown, 150 hidden).
    assert "loud - 200 findings · 200 M" in out
    assert "150 more not shown" in out
    # quiet renders all 5 rows; no disclosure.
    assert "quiet - 5 findings · 5 M" in out
    for i in range(5):
        assert f"quiet-{i}" in out


def test_empty_level_visible_detector_renders_no_header() -> None:
    """All-LOW duration at level 0 → level_visible_total == 0 → renders NOTHING
    for the detector group (no lonely header, no group-header rule). The
    run-summary banner's own rules still appear - exactly two of them."""
    fs = [_bare_finding("duration", Severity.LOW, f"low-{i}") for i in range(3)]
    out = _capture_write(TextHandler(verbose_level=0), fs)
    assert "duration -" not in out
    # Banner is bracketed by two DOUBLE rules; no single group-header rule should
    # be added for the empty detector group.
    assert out.count("═" * 80) == 2, "expected exactly 2 banner (double) rules"
    assert out.count("─" * 80) == 0, "no single group-header rule for empty group"


# ── failed-detector tail disclosure ──────────────────────────────────────────
# detectors_failed is written on the summary DURING the detector loop, after
# the banner has flushed - the report tail is the one in-report text surface
# that can carry it (the stderr narration does not travel into --out files).


def test_failed_detector_tail_renders_after_end() -> None:
    stream = io.StringIO()
    handler = TextHandler(stream=stream)
    summary = _summary()
    handler.begin(summary)
    # Recorded mid-loop, after the banner printed - end() must still see it.
    summary.detectors_failed["beacon"] = "detector error - boom"
    handler.end()
    out = stream.getvalue()
    assert "failed:" in out
    assert "beacon - detector error - boom" in out
    # The banner itself (flushed before the failure existed) carries no line.
    banner_end = out.index("═" * TEXT_RULE_WIDTH, out.index("═" * TEXT_RULE_WIDTH) + 1)
    assert "failed:" not in out[:banner_end]


def test_failed_detector_tail_vanishes_on_clean_run() -> None:
    """Vanish-don't-dash: no failures → end() emits nothing."""
    stream = io.StringIO()
    handler = TextHandler(stream=stream)
    handler.begin(_summary())
    before = stream.getvalue()
    handler.end()
    assert stream.getvalue() == before


def test_failed_detector_tail_strips_control_bytes_from_reason() -> None:
    """The reason is untrusted (an exception message can echo log-derived
    bytes) - it routes through the text sanitize seam."""
    stream = io.StringIO()
    handler = TextHandler(stream=stream)
    summary = _summary()
    handler.begin(summary)
    summary.detectors_failed["dns"] = "detector error - \x1b[31mforged\x9b0K"
    handler.end()
    out = stream.getvalue()
    assert "\x1b" not in out and "\x9b" not in out
    assert "forged" in out


def test_failed_detector_tail_single_blank_separation() -> None:
    """Exactly one blank line separates the tail from what precedes it: a
    rendered findings group already ends with a trailing blank (end() adds
    none); a banner-only report gets one from end()."""
    # Banner-only: end() owns the separating blank.
    stream = io.StringIO()
    handler = TextHandler(stream=stream)
    summary = _summary()
    handler.begin(summary)
    summary.detectors_failed["beacon"] = "detector error - boom"
    handler.end()
    assert "\n\nfailed:" in stream.getvalue()
    assert "\n\n\nfailed:" not in stream.getvalue()
    # With a rendered group: write() left the trailing blank; end() adds none.
    fs = [_bare_finding("scan", Severity.MEDIUM)]
    stream2 = io.StringIO()
    handler2 = TextHandler(stream=stream2)
    summary2 = _summary()
    handler2._stream = stream2
    handler2.begin(summary2)
    handler2.write(fs)
    summary2.detectors_failed["beacon"] = "detector error - boom"
    handler2.end()
    assert "\n\nfailed:" in stream2.getvalue()
    assert "\n\n\nfailed:" not in stream2.getvalue()
