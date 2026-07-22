"""Text output handler - default stdout format.

Output is grouped by detector, each section with a header and ───── separator.
Default output: title, severity tag, key evidence fields only.
Verbose adds: description, full evidence dict, next_steps, data window.
next_steps are never shown in default output.

Looks crafted, not generated. Minimal ASCII decoration.
"""

from __future__ import annotations

import sys
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, TextIO

from sigwood.common.display import (
    TEXT_RULE,
    TEXT_RULE_DOUBLE,
    TEXT_RULE_WIDTH,
    fmt_compact_span,
    fmt_suppression,
    fmt_window,
    human_bytes,
    paint,
    plural,
)
from sigwood.common.finding import (
    BlobCard,
    DigestCard,
    Finding,
    MethodTag,
    RunSummary,
    SuppressionSummary,
)
from sigwood.common.output import OutputHandler, register_handler
from sigwood.outputs._evidence import evidence_at_level
from sigwood.outputs._render_model import (
    DetectorRenderable,
    Section,
    _SEVERITY_ORDER,
    _build_renderable,
    project_row,
    text_columns,
)
from sigwood.outputs._sanitize import strip_control

_WIDTH = TEXT_RULE_WIDTH
_SEP = TEXT_RULE
_SEP_DOUBLE = TEXT_RULE_DOUBLE
_SUMMARY_LABEL_WIDTH = 14

# Minimum (requested_span − data_span) before the data-found line discloses an
# underfilled window - below this the operator effectively got what they asked for.
_UNDERFILL_TOLERANCE = timedelta(hours=1)


def _fmt_window(window: tuple) -> str:
    """Shared window renderer + the compact span parenthetical the data-found /
    digest / verbose finding tails need. The timestamp half routes through the
    single ``fmt_window`` renderer; the span half through the single
    ``fmt_compact_span`` renderer (``(20m)`` / ``(7h)`` / ``(2d)``) so a sub-hour
    window never collapses to ``(0.0d)``. All three surfaces share this wrapper, so
    they stay byte-identical to each other."""
    s, e = window
    return f"{fmt_window(window)}  ({fmt_compact_span(e - s)})"


def _sanitize(value: object) -> str:
    """Strip terminal control code points from untrusted text data values."""
    return strip_control(value)


# ── digest helpers (used by TextHandler.render_digest) ───────────────────────

_HIST_GLYPHS = "▁▂▃▄▅▆▇█"   # U+2581..U+2588


def _bar_glyph(value: int, peak: int) -> str:
    """Map a per-bin count to one of 8 block-character glyphs.

    Zero and below render as the lowest glyph (▁) - visual continuity beats
    a blank space when the histogram band is meant to be read as a line.
    Values at or above peak render as the highest glyph (█).
    """
    if peak <= 0 or value <= 0:
        return _HIST_GLYPHS[0]
    if value >= peak:
        return _HIST_GLYPHS[-1]
    idx = int((value / peak) * (len(_HIST_GLYPHS) - 1))
    return _HIST_GLYPHS[max(0, min(len(_HIST_GLYPHS) - 1, idx))]


def _format_count(n: int) -> str:
    """Compact-number formatter for histogram peak anchors."""
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k"
    if n < 1_000_000_000:
        return f"{n / 1_000_000:.1f}M"
    return f"{n / 1_000_000_000:.1f}B"


def _render_histogram(
    counts: list[int], unit: str, peak: int, *, unavailable: bool = False,
) -> str:
    """Render the temporal histogram as a single-line band, flush-left.

    The line carries BOTH an axis unit label ("hourly bins" / "daily bins")
    AND a scale anchor ("peak: N"). Without both, a busy-flat and a
    quiet-flat timeline render identically - the unit names the bar width
    and the anchor names the bar height.

    Three rendering branches, in precedence order:

    1. ``unavailable=True`` → bare ``(timeline unavailable)`` - the caller
       suppressed the histogram because timestamps in the source frame
       could not be parsed with confidence. Distinct from "no events".
       Both former failure modes (low-coverage / zero-span) render here
       identically; the flat card has no footer to differentiate them.
    2. ``peak <= 0`` or empty ``counts`` → ``(no events in window)`` - the
       valid empty-timeline case: no records in the loaded window.
    3. Otherwise → the bar render with unit label + peak anchor.
    """
    if unavailable:
        return "(timeline unavailable)"
    if peak <= 0 or not counts:
        return "(no events in window)"
    bars = "".join(_bar_glyph(c, peak) for c in counts)
    unit_label = "hourly bins" if unit == "hr" else "daily bins"
    return f"{bars}  {unit_label} · peak: {_format_count(peak)}"


def _render_label_value_block(rows: list[tuple[str, str]]) -> list[str]:
    """Flush-left ``label: value`` block with the value column aligned.

    Shared by the ambient block and the fields block on every digest
    card. Label width is computed from the rows
    in this block only - no cross-block alignment. The labels are
    flush-left at column 0; alignment is in the value column.

    Long entities (flows, domains) render in FULL - never truncated. The
    text-output rail forbids truncating naturally-long values on schema
    cards. Blob's wide-list slots use a separate blob-local clamp; see
    ``_wrap_blob_slot_value`` below.
    """
    if not rows:
        return []
    label_w = max(len(label) for label, _ in rows)
    return [
        f"{(label + ':').ljust(label_w + 2)}{value}"
        for label, value in rows
    ]


def _render_sanitized_label_value_block(rows: list[tuple[str, str]]) -> list[str]:
    """Render label/value rows while stripping control code points from values only."""
    return _render_label_value_block([
        (label, _sanitize(value)) for label, value in rows
    ])


# ── Blob-only: two-line clamp for the wide-list slot (`fields:` / `tokens:`)
#
# Blob's `fields:` row carries a top-level-keys list that on a Zeek conn
# log can easily run 20+ names; the `tokens:` row defensively shares the
# same clamp so a degenerate token row cannot blow past the 80-col frame.
# Schema cards keep rendering through ``_render_label_value_block`` and
# are exempt from this clamp - long entities like flows/domains must
# render in full per the text-output rail.

def _wrap_blob_slot_value(
    value: str, *, label_col: int, sep: str,
) -> list[str]:
    """Two-line clamp for blob's wide-list slot value.

    Line 1 starts at column ``label_col`` (max blob-slot label width + 2,
    matching ``_render_label_value_block``'s sizing exactly). Line 2 hang-
    indents to ``label_col``. Splits ONLY on ``sep`` - never breaks a
    part - so the "never split a field name" rule is honoured.

    A list that fits one line renders one line, no suffix. When the full
    list doesn't fit two lines, truncates to what fits on line 2 and
    appends ``… +N more`` (N = total parts minus parts rendered). A part
    longer than the available width lands on its own line and may exceed
    the 80-col frame; the required rule is unbroken parts.
    """
    available = _WIDTH - label_col
    parts = value.split(sep)

    # Single-line short-circuit.
    if len(value) <= available:
        return [value]

    # Greedy-pack line 1.
    line1_parts: list[str] = []
    line1_len = 0
    i = 0
    while i < len(parts):
        part = parts[i]
        added = len(part) if not line1_parts else len(sep) + len(part)
        if line1_parts and line1_len + added > available:
            break
        line1_parts.append(part)
        line1_len += added
        i += 1
    if not line1_parts:  # first part already too wide - emit it alone
        line1_parts = [parts[0]]
        i = 1
    line1 = sep.join(line1_parts)

    # Greedy-pack line 2, reserving suffix room only if MORE parts remain
    # after a tentative full pack.
    indent = " " * label_col
    remaining = parts[i:]
    suffix_template = f"{sep}… +{{n}} more"

    # First pass: greedy pack remaining into line 2 without suffix reserve.
    line2_parts: list[str] = []
    line2_len = 0
    j = 0
    while j < len(remaining):
        part = remaining[j]
        added = len(part) if not line2_parts else len(sep) + len(part)
        if line2_parts and line2_len + added > available:
            break
        line2_parts.append(part)
        line2_len += added
        j += 1
    if not line2_parts and remaining:
        line2_parts = [remaining[0]]
        j = 1

    truncated = j < len(remaining)
    if truncated:
        # Re-pack reserving room for `… +N more`. N is unknown until
        # we know how many parts we kept, so iterate: each removed part
        # bumps N (suffix grows by ~1 char per digit decade). Cap the
        # re-pack loop trivially - at most len(remaining) iterations.
        for _ in range(len(remaining) + 1):
            n_remaining = len(remaining) - len(line2_parts)
            if n_remaining <= 0:
                break
            suffix = suffix_template.format(n=n_remaining)
            candidate_len = (
                sum(len(p) for p in line2_parts)
                + len(sep) * (len(line2_parts) - 1)
                + len(suffix)
            )
            if candidate_len <= available:
                break
            if len(line2_parts) <= 1:
                break  # can't shrink further - accept overflow
            line2_parts.pop()
        n_remaining = len(remaining) - len(line2_parts)
        line2 = (
            indent
            + sep.join(line2_parts)
            + suffix_template.format(n=n_remaining)
        )
    else:
        line2 = indent + sep.join(line2_parts) if line2_parts else ""

    return [line1, line2] if line2 else [line1]


def _summary_line(label: str, value: object) -> list[str]:
    """Render a wrapped run-summary row with continuation text aligned."""
    prefix = f"{label:<{_SUMMARY_LABEL_WIDTH}} "
    subsequent = " " * len(prefix)
    text = str(value)
    wrap_width = max(20, _WIDTH - len(prefix))
    wrapped = textwrap.wrap(
        text,
        width=wrap_width,
        break_long_words=False,
        break_on_hyphens=False,
    )
    if not wrapped:
        wrapped = [""]
    return [
        f"{prefix if i == 0 else subsequent}{part}"
        for i, part in enumerate(wrapped)
    ]


# ── card pipeline ────────────────────────────────────────────────────────────
# The pipeline (Section / DetectorRenderable / _build_renderable / partitioners /
# the two exemptions / the section-walking cap / pre-cap sidecars) MOVED verbatim
# to ``outputs/_render_model.py`` - the single owner shared with html/pdf so the
# two reading surfaces cannot drift. Imported at the top of this module.


def _cells(finding: Finding) -> tuple[dict[str, str], list[str]]:
    """Split a finding's ``project_row`` into (keyed values, ordered bare values).

    ``keyed`` maps each non-None column key → its formatted value; ``bare`` is the
    ordered list of bare (entity/flow/domain/principal) cell values. The per-
    detector renderers below source their cell VALUES from here (the format strings
    live ONCE in ``_render_model.project_row``), then strip terminal controls before
    applying their own width / pad / arrow logic."""
    cells = project_row(finding)
    keyed = {c.key: _sanitize(c.value) for c in cells if c.key is not None}
    bare = [_sanitize(c.value) for c in cells if c.key is None]
    return keyed, bare


def _verbose_tail(finding: Finding, indent: str, extras: dict[str, Any] | None = None) -> list[str]:
    """Curated 'why it scored' - level 1. Returns [] when no material to show.

    Vanish discipline: a Finding with empty description / next_steps and an
    empty curated-evidence subset renders the title line ALONE - no empty
    headers, no dangling indents, NO trailing ``data window:`` line. The
    data-window line appears only when at least one other body element is
    present.
    """
    body: list[str] = []
    if finding.description:
        body.append(f"{indent}{_sanitize(finding.description)}")
    if extras:
        body.append(f"{indent}evidence:")
        for k, v in extras.items():
            if k == "sample_raw" and isinstance(v, (list, tuple)):
                body.append(f"{indent}  sample_raw:")
                for line in v:
                    body.append(f"{indent}    · {_sanitize(line)}")
            else:
                body.append(f"{indent}  {_sanitize(k)}: {_sanitize(v)}")
    if finding.next_steps:
        body.append(f"{indent}next steps:")
        for step in finding.next_steps:
            body.append(f"{indent}  · {_sanitize(step)}")
    if not body:
        return []
    body.append(f"{indent}data window: {_fmt_window(finding.data_window)}")
    return body


def _debug_tail(finding: Finding, indent: str) -> list[str]:
    """Raw debug - level 2. Full evidence dict. Same vanish discipline as
    ``_verbose_tail``: empty description / evidence / next_steps → ``[]``."""
    body: list[str] = []
    if finding.description:
        body.append(f"{indent}{_sanitize(finding.description)}")
    if finding.evidence:
        body.append(f"{indent}evidence:")
        for k, v in finding.evidence.items():
            if k in ("member_fragments", "members"):
                continue  # already rendered as syslog row/drilldown content
            body.append(f"{indent}  {_sanitize(k)}: {_sanitize(v)}")
    if finding.next_steps:
        body.append(f"{indent}next steps:")
        for step in finding.next_steps:
            body.append(f"{indent}  · {_sanitize(step)}")
    if not body:
        return []
    body.append(f"{indent}data window: {_fmt_window(finding.data_window)}")
    return body


def _level_tail(finding: Finding, indent: str, verbose_level: int) -> list[str]:
    """Dispatch to the right tail by level. Level 0 returns []; level 1 emits
    the curated tail; level 2 emits the full debug tail. Both tails honor
    vanish-don't-dash."""
    if verbose_level <= 0:
        return []
    if verbose_level >= 2:
        return _debug_tail(finding, indent)
    return _verbose_tail(finding, indent, evidence_at_level(finding, 1))


def _transaction_member_lines(finding: Finding, indent: str) -> list[str]:
    """Render conserved transaction members as a compact human drilldown."""
    if finding.detector != "syslog" or finding.evidence.get("tier") != "transaction":
        return []
    members = finding.evidence.get("members")
    if not isinstance(members, (list, tuple)) or not members:
        return []
    lines = [f"{indent}members:"]
    for member in members:
        if not isinstance(member, dict):
            continue
        severity = str(member.get("severity", "info"))[:1].upper() or "I"
        program = member.get("program")
        if program is None:
            mix = member.get("program_mix")
            if isinstance(mix, (list, tuple)):
                program = ", ".join(
                    str(item[0])
                    for item in mix
                    if isinstance(item, (list, tuple)) and item
                )
        count = int(member.get("represented_line_count", 1))
        parts = [
            f"[{severity}]",
            str(program or "unknown"),
            str(member.get("tier", "needle")),
            f"{count} {plural(count, 'rare line')}",
            str(member.get("title", "")),
        ]
        lines.append(f"{indent}  · {_sanitize(' · '.join(parts))}")
    return lines if len(lines) > 1 else []


def _render_group_header(detector: str, renderable: DetectorRenderable) -> list[str]:
    """Header line: ``detector - N findings · 3 H  18 M  51 I`` + 80-col rule.

    Counts and breakdown are PRE-CAP - read straight off the renderable's
    ``level_visible_total`` and ``severity_breakdown`` sidecars, never
    recomputed from ``Section.findings`` (which is post-cap)."""
    total = renderable.level_visible_total
    label = "findings" if total != 1 else "finding"
    parts = [f"{detector} - {total} {label}"]
    breakdown = renderable.severity_breakdown
    cells = []
    for sev in _SEVERITY_ORDER:
        n = breakdown.get(sev, 0)
        if n > 0:
            cells.append(f"{n} {sev.value}")
    if cells:
        parts.append(" · " + "  ".join(cells))
    return ["".join(parts), TEXT_RULE]


def _render_cap_disclosure(detector: str, renderable: DetectorRenderable, cap: int) -> str:
    """Cap disclosure: factual wording.

    Honesty rail: the cap trims sections in DECLARED order, NOT
    global severity. For a FLAT detector (one implicit section) the cap is
    indeed by severity - sort-then-cap retains the highest tiers. For a
    SUBSECTIONED detector (dns: singletons-first; aws: bursts-first) a
    later section's HIGH row can be dropped while an earlier section's LOW
    row survives the cap. So "by severity" is true only in the flat case.

    Rather than spell out the cross-section non-guarantee in two arms, the
    wording simply drops the severity claim. The hidden count and the cap
    cap are what the operator needs to act on. The binding constraint is
    that the wording MUST NOT claim severity-retention the cap doesn't provide.
    """
    hidden = renderable.cap_truncated
    return (
        f"… {hidden:,} more not shown (showing first {cap:,}). "
        f"Unusually high - narrow with the allowlist, or this detector may be "
        f"misbehaving."
    )


class TextHandler(OutputHandler):
    """Write findings as aligned plain text to stdout (or a given stream)."""

    def __init__(
        self,
        stream: TextIO = sys.stdout,
        verbose_level: int = 0,
        max_findings_per_detector: int = 100,
    ) -> None:
        self._stream = stream
        self._verbose_level = verbose_level
        self._max_findings_per_detector = max_findings_per_detector
        self._run_summary: RunSummary | None = None
        # Whether write() rendered at least one detector group - a rendered
        # group already ends with a trailing blank, so the failed-detector
        # tail must not add a second one (single-blank separation either way).
        self._wrote_groups = False

    def begin(self, run_summary: RunSummary) -> None:
        """Print the run summary header before any findings.

        No leading blank: cross-stream separation from the preceding stderr
        load phase is owned by the stderr side (``display.phase_separator``,
        called by the runner). The banner is the first stdout line.

        The summary is also stashed for ``end()``: ``detectors_failed`` is
        written during the detector loop (after this banner has flushed), so
        the failed-detector disclosure can only render at the report tail.
        """
        self._run_summary = run_summary
        print(self._render_run_summary(run_summary), file=self._stream)

    def write(self, findings: list[Finding]) -> None:
        """Print findings grouped by detector with aligned columns.

        Per detector, runs the render pipeline via ``_build_renderable`` (level-
        filter → partition → pre-cap stats → severity-sort → cap). A detector
        whose level-visible set is empty renders NOTHING - no header, no
        rule, no label (the vanish rule). The disclosure line fires only
        when the cap actually trimmed rows.
        """
        if not findings:
            return

        by_detector: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            by_detector[f.detector].append(f)

        for detector, group in by_detector.items():
            renderable = _build_renderable(
                detector, group, self._verbose_level, self._max_findings_per_detector,
            )
            if renderable.level_visible_total == 0:
                continue
            print(file=self._stream)
            for line in _render_group_header(detector, renderable):
                print(line, file=self._stream)
            for line in self._render_group(detector, renderable.sections):
                print(line, file=self._stream)
            if renderable.cap_truncated > 0:
                print(file=self._stream)
                print(
                    _render_cap_disclosure(detector, renderable, self._max_findings_per_detector),
                    file=self._stream,
                )
            print(file=self._stream)
            self._wrote_groups = True

    def end(self) -> None:
        """Render the failed-detector tail; stdout needs no closing.

        A detector that crashed mid-run (prep or run) contributed zero
        findings and would otherwise vanish from a saved report - the stderr
        narration does not travel into ``--out`` files. Failures are recorded
        on the run summary DURING the loop, after the banner has flushed, so
        the report tail is the one in-report surface that can carry them.
        Mirrors the banner's ``skipped:`` grammar; the REASON is untrusted
        (an exception message can echo log-derived bytes) and routes through
        ``_sanitize``; the detector name is tool-authored and left alone.
        Vanish-don't-dash: a clean run renders nothing here.
        """
        if self._run_summary is None or not self._run_summary.detectors_failed:
            return
        if not self._wrote_groups:
            print(file=self._stream)
        for name, reason in self._run_summary.detectors_failed.items():
            for line in _summary_line("failed:", f"{name} - {_sanitize(reason)}"):
                print(line, file=self._stream)

    def _render_run_summary(
        self,
        run_summary: RunSummary,
        banner: str = "sigwood  ·  threat hunt",
    ) -> str:
        """Render the detect-run banner.

        Digest does not flow through this helper - each digest card
        carries its own identity block. This stays the single source of
        truth for the detect-path banner; its output must be byte-identical
        to its pre-flat-digest form on a normal detect run.
        """
        lines = [
            banner,
            _SEP_DOUBLE,
        ]

        if run_summary.data_window is None:
            # A load that established no window is a critical answer for a
            # security tool - say "none", never an invented span.
            lines.extend(_summary_line("data found:", "none"))
        elif run_summary.data_window[0] and run_summary.data_window[1]:
            lines.extend(_summary_line(
                "data found:", self._fmt_data_found(run_summary)
            ))

        if run_summary.record_counts:
            counts_str = "  ·  ".join(
                f"{v:,} {k}" for k, v in run_summary.record_counts.items()
            )
            lines.extend(_summary_line("records:", counts_str))

        if run_summary.suppression is not None:
            lines.extend(_summary_line(
                "allowlist:", self._fmt_suppression(run_summary.suppression)
            ))

        if run_summary.detectors_run:
            lines.extend(_summary_line(
                "detectors:",
                self._render_detectors_value(run_summary),
            ))

        if run_summary.detectors_skipped:
            for name, reason in run_summary.detectors_skipped.items():
                lines.extend(_summary_line(
                    "skipped:", f"{name} - {_sanitize(reason)}"
                ))

        for note in run_summary.notes:
            lines.extend(_summary_line("note:", _sanitize(note)))

        lines.append(_SEP_DOUBLE)
        return "\n".join(lines)

    @staticmethod
    def _fmt_suppression(s: SuppressionSummary) -> str:
        """The `allowlist:` banner value - delegates to the shared formatter so
        the text banner and HTML header never drift."""
        return fmt_suppression(s)

    @staticmethod
    def _fmt_data_found(run_summary: RunSummary) -> str:
        """Render the data-found value.

        Full / disjoint runs use ``_fmt_window`` UNCHANGED (the same helper feeds
        the digest card and verbose finding tails - it must stay byte-identical).
        Only an underfilled default/explicit window - data span short of the
        requested span by at least ``_UNDERFILL_TOLERANCE`` - swaps in the
        informative parenthetical (both spans via ``fmt_compact_span``).
        """
        s, e = run_summary.data_window
        data_span = e - s
        rs = run_summary.requested_span
        if rs is not None and (rs - data_span) >= _UNDERFILL_TOLERANCE:
            return (
                f"{fmt_window(run_summary.data_window)}"
                f"  ({fmt_compact_span(data_span)} data span in {fmt_compact_span(rs)} window)"
            )
        return _fmt_window(run_summary.data_window)

    def _render_detectors_value(self, run_summary: RunSummary) -> str:
        """Build the right-hand side of the Detectors: row.

        Named methods (``MethodTag(named=True)``) render as ``name (label)``
        with the label painted when ``self._stream`` is a real TTY (and
        NO_COLOR / TERM=dumb don't opt out). Honest house badges
        (``named=False``) render as ``name [label]`` plain. Detectors with
        no ``DETECTOR_METHOD`` constant fall back to the bare name -
        forward-compat for any future detector that ships without one.
        Detectors joined by ``  ·  ``.
        """
        parts: list[str] = []
        for name in run_summary.detectors_run:
            tag: "MethodTag | None" = run_summary.detector_methods.get(name)
            if tag is None:
                parts.append(name)
            elif tag.named:
                parts.append(f"{name} ({paint(tag.label, stream=self._stream)})")
            else:
                parts.append(f"{name} [{tag.label}]")
        return "  ·  ".join(parts)

    def _render_group(self, detector: str, sections: list[Section]) -> list[str]:
        """Render a detector's already-prepared sections (post level-filter,
        sort, and cap). Per-detector renderers do pure row formatting only -
        no filtering, sorting, counting, or capping leaks back here.
        """
        # Drop empty sections (cap may have emptied a later section - its label
        # vanishes, no lonely label).
        live = [s for s in sections if s.findings]
        if not live:
            return []
        if detector == "beacon":
            return self._render_beacon_group(live)
        if detector == "dns":
            return self._render_dns_group(live)
        if detector == "scan":
            return self._render_scan_group(live)
        if detector == "syslog":
            return self._render_syslog_group(live)
        if detector == "duration":
            return self._render_duration_group(live)
        if detector == "aws":
            return self._render_aws_group(live)
        # Generic fallback - flat detector, one Section with label=None.
        out: list[str] = []
        for s in live:
            for f in s.findings:
                out.append(self._render_finding(f))
        return out

    def _render_beacon_group(self, sections: list[Section]) -> list[str]:
        """Render beacon findings with fully aligned columns. Beacon is a flat
        detector - one Section with label=None - so per-section column widths
        match per-detector. → arrows align via independent sub-field padding."""
        indent = "     "
        out: list[str] = []
        findings = sections[0].findings  # flat: single section

        rows = []
        for f in findings:
            keyed, bare = _cells(f)  # bare = [src, "→", dst]
            src, dst_str = bare[0], bare[2]
            period_col, score_col, conns_col = keyed["period"], keyed["score"], keyed["conns"]
            rows.append((str(f.severity), src, dst_str, period_col, score_col, conns_col, f))

        src_w    = max(len(r[1]) for r in rows)
        dst_w    = max(len(r[2]) for r in rows)
        period_w = max(len(r[3]) for r in rows)
        # score is always "score=0.XXX" - 11 chars, no padding needed
        conns_w  = max(len(r[5]) for r in rows)

        for tag, src, dst_str, period_col, score_col, conns_col, f in rows:
            line = (
                f"{tag}  {src:<{src_w}}  →  {dst_str:<{dst_w}}   "
                f"{period_col:<{period_w}}   {score_col}   "
                f"{conns_col:>{conns_w}}"
            )
            tail = _level_tail(f, indent, self._verbose_level)
            if tail:
                out.append(line + "\n" + "\n".join(tail))
            else:
                out.append(line)
        return out

    def _render_dns_group(self, sections: list[Section]) -> list[str]:
        """Render DNS findings: singletons FIRST, then groups (singletons
        lead - the more interesting tier). Each section gets a plain lowercase
        ``label (N)`` line (pre-cap count from the section) - no ── rules.
        Column widths derived from the section's findings before any row is
        formatted. blocked column omitted when no row in the section has
        was_blocked=True - preserves the pre-pihole Zeek-only output exactly.
        """
        indent = "     "
        out: list[str] = []

        for si, section in enumerate(sections):
            label_line = f"{section.label} ({section.pre_cap_count})"
            if si > 0:
                out.append("")
            out.append(label_line)

            # dense-cluster scan summary: full-width prose rows (mirror
            # _render_aws_group's summary loop). Keyed on tier, not the label - a
            # full-width row must never fall through to the keyed[...] reads below.
            if section.findings and section.findings[0].evidence.get("tier") == "scan_summary":
                for f in section.findings:
                    _keyed, bare = _cells(f)  # bare = [full-width prose]
                    tag = f"{str(f.severity):<4}"
                    line = f"  {tag}  {bare[0]}"
                    tail = _level_tail(f, indent, self._verbose_level)
                    if tail:
                        out.append(line + "\n" + "\n".join(tail))
                    else:
                        out.append(line)
                continue

            # Shared emptiness owner: the (optional) blocked column drops iff no
            # row in this section was blocked - text's drop rule via section_columns
            # (== the historical ``blocked_w > 0`` branch, now the ONE owner so the
            # html table and text can't disagree on column presence).
            show_blocked = any(c.key == "blocked" for c in text_columns(section))

            if section.label == "singletons":
                rows = []
                for f in section.findings:
                    keyed, bare = _cells(f)  # bare = [domain]
                    tag = f"{str(f.severity):<4}"
                    score_col, qry_col, src_col = keyed["score"], keyed["qry"], keyed["src"]
                    blocked_col = keyed["blocked"]
                    rows.append((tag, score_col, qry_col, src_col, blocked_col, bare[0], f))

                score_w     = max(len(r[1]) for r in rows)
                qry_w     = max(len(r[2]) for r in rows)
                src_w     = max(len(r[3]) for r in rows)
                blocked_w = max(len(r[4]) for r in rows)

                for tag, score_col, qry_col, src_col, blocked_col, domain, f in rows:
                    if show_blocked:
                        line = (
                            f"  {tag}  {score_col:<{score_w}}  "
                            f"{qry_col:>{qry_w}}  {src_col:>{src_w}}  "
                            f"{blocked_col:<{blocked_w}}  {domain}"
                        )
                    else:
                        line = (
                            f"  {tag}  {score_col:<{score_w}}  "
                            f"{qry_col:>{qry_w}}  {src_col:>{src_w}}  {domain}"
                        )
                    tail = _level_tail(f, indent, self._verbose_level)
                    if tail:
                        out.append(line + "\n" + "\n".join(tail))
                    else:
                        out.append(line)
            else:  # "groups"
                rows = []
                for f in section.findings:
                    keyed, bare = _cells(f)  # bare = [registrable_domain]
                    tag = f"{str(f.severity):<4}"
                    sub_col = keyed["sub"]
                    score_col = keyed["score"]
                    qry_col = keyed["qry"]
                    src_col = keyed["src"]
                    blocked_col = keyed["blocked"]
                    rows.append((tag, sub_col, score_col, qry_col, src_col, blocked_col, bare[0], f))

                sub_w     = max(len(r[1]) for r in rows)
                score_w     = max(len(r[2]) for r in rows)
                qry_w     = max(len(r[3]) for r in rows)
                src_w     = max(len(r[4]) for r in rows)
                blocked_w = max(len(r[5]) for r in rows)

                for tag, sub_col, score_col, qry_col, src_col, blocked_col, domain, f in rows:
                    if show_blocked:
                        line = (
                            f"  {tag}  {sub_col:>{sub_w}}  {score_col:<{score_w}}  "
                            f"{qry_col:>{qry_w}}  {src_col:>{src_w}}  "
                            f"{blocked_col:<{blocked_w}}  {domain}"
                        )
                    else:
                        line = (
                            f"  {tag}  {sub_col:>{sub_w}}  {score_col:<{score_w}}  "
                            f"{qry_col:>{qry_w}}  {src_col:>{src_w}}  {domain}"
                        )
                    tail = _level_tail(f, indent, self._verbose_level)
                    if tail:
                        out.append(line + "\n" + "\n".join(tail))
                    else:
                        out.append(line)

        return out

    def _render_scan_group(self, sections: list[Section]) -> list[str]:
        """Render scan findings with aligned columns across all scan types. Flat
        detector. Columns: severity | scan_type | ratio | src | type-specific
        middle | metric. Widths derived from the section's findings before any
        row is formatted."""
        indent = "     "
        out: list[str] = []
        findings = sections[0].findings

        rows = []
        for f in findings:
            keyed, bare = _cells(f)  # bare = [src]; middle/metric type-specific
            tag       = f"{str(f.severity):<4}"
            type_col  = keyed["type"]
            ratio_col = keyed["ratio"]
            src_col   = bare[0]
            middle_col = keyed["middle"]
            metric_col = keyed["metric"]
            rows.append((tag, type_col, ratio_col, src_col, middle_col, metric_col, f))

        type_w   = max(len(r[1]) for r in rows)
        ratio_w  = max(len(r[2]) for r in rows)
        src_w    = max(len(r[3]) for r in rows)
        middle_w = max(len(r[4]) for r in rows)
        metric_w = max(len(r[5]) for r in rows)

        for tag, type_col, ratio_col, src_col, middle_col, metric_col, f in rows:
            line = (
                f"{tag}  {type_col:<{type_w}}  {ratio_col:<{ratio_w}}  "
                f"{src_col:<{src_w}}  {middle_col:<{middle_w}}  {metric_col:>{metric_w}}"
            )
            tail = _level_tail(f, indent, self._verbose_level)
            if tail:
                out.append(line + "\n" + "\n".join(tail))
            else:
                out.append(line)
        return out

    def _render_syslog_group(self, sections: list[Section]) -> list[str]:
        """Render syslog's privileged / rare-events / bursts subsections.

        Projected cells render in order as one ``·``-joined reading line; keyed
        labels belong only to HTML headers, so text keeps the bare cell values.
        Section labels carry pre-cap counts; ts-order
        within a section is preserved (syslog is severity-sort exempt). Verbose
        tails are shared via ``_level_tail``."""
        indent = "     "
        out: list[str] = []

        for si, section in enumerate(sections):
            if section.label:
                if si > 0:
                    out.append("")
                out.append(f"{section.label} ({section.pre_cap_count})")

            for f in section.findings:
                tag = f"{str(f.severity):<4}"
                values = [_sanitize(cell.value) for cell in project_row(f)]
                line = f"  {tag}  {' · '.join(values)}"
                row_lines = [line]
                if f.evidence.get("tier") in ("family", "burst"):
                    fragments = f.evidence.get("member_fragments")
                    if isinstance(fragments, (list, tuple)):
                        row_lines.extend(
                            f"        {_sanitize(fragment)}"
                            for fragment in fragments
                            if str(fragment)
                        )
                if (
                    self._verbose_level >= 1
                    and f.evidence.get("tier") == "transaction"
                ):
                    row_lines.extend(_transaction_member_lines(f, indent))
                tail = _level_tail(f, indent, self._verbose_level)
                row_lines.extend(tail)
                out.append("\n".join(row_lines))

        return out

    def _render_duration_group(self, sections: list[Section]) -> list[str]:
        """Render duration findings with aligned columns. Flat detector. Each
        sub-field of the flow is padded independently so → arrows align
        vertically. Columns: severity | src → dst:port/proto | max_dur_str |
        avg_bps | N_conns | states."""
        indent = "     "
        out: list[str] = []
        findings = sections[0].findings

        rows = []
        for f in findings:
            keyed, bare = _cells(f)  # bare = [src, "→", dst]
            src, dst_str = bare[0], bare[2]
            dur_str = keyed["dur"]
            bps_col = keyed["bps"]
            conns_col = keyed["conns"]
            state_col = keyed["states"]
            rows.append((str(f.severity), src, dst_str, dur_str, bps_col, conns_col, state_col, f))

        src_w    = max(len(r[1]) for r in rows)
        dst_w    = max(len(r[2]) for r in rows)
        dur_w    = max(len(r[3]) for r in rows)
        bps_w    = max(len(r[4]) for r in rows)
        conns_w  = max(len(r[5]) for r in rows)
        state_w  = max(len(r[6]) for r in rows)

        for tag, src, dst_str, dur_str, bps_col, conns_col, state_col, f in rows:
            line = (
                f"{tag}  {src:<{src_w}}  →  {dst_str:<{dst_w}}  "
                f"{dur_str:<{dur_w}}  {bps_col:>{bps_w}}  {conns_col:>{conns_w}}  {state_col:>{state_w}}"
            ).rstrip()
            tail = _level_tail(f, indent, self._verbose_level)
            if tail:
                out.append(line + "\n" + "\n".join(tail))
            else:
                out.append(line)
        return out

    def _render_aws_group(self, sections: list[Section]) -> list[str]:
        """Render AWS findings as subsections: burst sweeps, then ranked
        principals. The ranked section already bundles per-principal
        ``ranked`` rows + the synthetic ``ranked_summary`` quiet line (the
        partitioner glued them together). Plain lowercase subsection labels
        (no ── rules). Each tier computes its own column widths."""
        indent = "     "
        out: list[str] = []

        for si, section in enumerate(sections):
            label_line = f"{section.label} ({section.pre_cap_count})"
            if si > 0:
                out.append("")
            out.append(label_line)

            if section.label == "burst sweeps":
                rows = []
                for f in section.findings:
                    keyed, bare = _cells(f)  # bare = [principal]
                    tag = f"{str(f.severity):<4}"
                    principal = bare[0]
                    actions_col = keyed["new"]
                    svcs_col = keyed["svc"]
                    span_col = keyed["span"]
                    err_col = keyed["err"]
                    rows.append((tag, principal, actions_col, svcs_col, span_col, err_col, f))

                principal_w = max(len(r[1]) for r in rows)
                actions_w   = max(len(r[2]) for r in rows)
                svcs_w      = max(len(r[3]) for r in rows)
                span_w      = max(len(r[4]) for r in rows)
                err_w       = max(len(r[5]) for r in rows)

                for tag, principal, actions_col, svcs_col, span_col, err_col, f in rows:
                    line = (
                        f"  {tag}  {principal:<{principal_w}}  "
                        f"{actions_col:>{actions_w}}  {svcs_col:>{svcs_w}}  "
                        f"{span_col:>{span_w}}  {err_col:>{err_w}}"
                    )
                    tail = _level_tail(f, indent, self._verbose_level)
                    if tail:
                        out.append(line + "\n" + "\n".join(tail))
                    else:
                        out.append(line)
            else:  # "ranked principals"
                ranked = [f for f in section.findings if f.evidence.get("tier") == "ranked"]
                summary = [f for f in section.findings if f.evidence.get("tier") == "ranked_summary"]

                if ranked:
                    rows = []
                    for f in ranked:
                        keyed, bare = _cells(f)  # bare = [principal]
                        tag = f"{str(f.severity):<4}"
                        principal = bare[0]
                        z_col   = keyed["z"]
                        err_col = keyed["err"]
                        ev_col  = keyed["ev"]
                        ip_col  = keyed["ip"]
                        rows.append((tag, principal, z_col, err_col, ev_col, ip_col, f))

                    principal_w = max(len(r[1]) for r in rows)
                    z_w   = max(len(r[2]) for r in rows)
                    err_w = max(len(r[3]) for r in rows)
                    ev_w  = max(len(r[4]) for r in rows)
                    ip_w  = max(len(r[5]) for r in rows)

                    for tag, principal, z_col, err_col, ev_col, ip_col, f in rows:
                        line = (
                            f"  {tag}  {principal:<{principal_w}}  "
                            f"{z_col:>{z_w}}  {err_col:>{err_w}}  "
                            f"{ev_col:>{ev_w}}  {ip_col:>{ip_w}}"
                        )
                        tail = _level_tail(f, indent, self._verbose_level)
                        if tail:
                            out.append(line + "\n" + "\n".join(tail))
                        else:
                            out.append(line)

                for f in summary:
                    keyed, bare = _cells(f)  # bare = [full-width prose line]
                    tag = f"{str(f.severity):<4}"
                    line = f"  {tag}  {bare[0]}"
                    tail = _level_tail(f, indent, self._verbose_level)
                    if tail:
                        out.append(line + "\n" + "\n".join(tail))
                    else:
                        out.append(line)

        return out

    def _render_finding(self, finding: Finding) -> str:
        tag = str(finding.severity)
        line = f"{tag}  {_sanitize(finding.title)}"

        indent = "     "
        tail = _level_tail(finding, indent, self._verbose_level)
        if not tail:
            return line
        return line + "\n" + "\n".join(tail)

    def render_digest(self, card: DigestCard) -> None:
        """Render a digest schema card - flat, flush-left, no banner.

        Order: identity block (3 lines + an optional default-window note) ·
        ambient block · histogram · insights · fields. Each block separated
        by one blank line. No header rule,
        no N.B. footer, no trailing rule. The inter-card separator on a
        multi-card run is emitted by the caller (run_digest) immediately
        before invoking this method.

        Called directly by ``runner.run_digest`` - bypassing the Finding-
        shaped Reporter.begin/write/end lifecycle, because a digest run
        produces ONE card. The Finding render path is intentionally
        untouched.
        """
        # ── Identity block ────────────────────────────────────────────────
        print(_sanitize(card.source_name), file=self._stream)
        if card.data_window[0] and card.data_window[1]:
            print(_fmt_window(card.data_window), file=self._stream)
        else:
            # Timeline unavailable: line 2 dashes; the histogram line
            # below carries the descriptive "(timeline unavailable)".
            print("-", file=self._stream)
        print(
            f"{card.schema} · {card.record_count:,} lines · "
            f"{human_bytes(card.data_size_bytes)}",
            file=self._stream,
        )
        # Optional 4th identity line - default-window disclosure. Vanish-
        # don't-dash: print ONLY when set, so the canonical 3-line identity
        # triple stays byte-stable for every card without a default window.
        if card.default_window_note:
            print(_sanitize(card.default_window_note), file=self._stream)

        # ── Ambient block ─────────────────────────────────────────────────
        ambient = _render_sanitized_label_value_block(card.zone1_extras)
        if ambient:
            print(file=self._stream)
            for line in ambient:
                print(line, file=self._stream)

        # ── Histogram ─────────────────────────────────────────────────────
        print(file=self._stream)
        print(
            _render_histogram(
                card.histogram_counts,
                card.histogram_unit,
                card.histogram_peak,
                unavailable=card.timeline_unavailable,
            ),
            file=self._stream,
        )

        # ── Insights ──────────────────────────────────────────────────────
        if card.insights:
            print(file=self._stream)
            for insight in card.insights:
                print(_sanitize(insight), file=self._stream)

        # ── Fields block ──────────────────────────────────────────────────
        field_rows = [
            (slot.label, "  ".join(_sanitize(cell) for cell in slot.cells))
            for slot in card.fields
            if slot.cells is not None
        ]
        field_lines = _render_sanitized_label_value_block(field_rows)
        if field_lines:
            print(file=self._stream)
            for line in field_lines:
                print(line, file=self._stream)


    def render_blob(self, card: BlobCard) -> None:
        """Render a blob digest card - flat, flush-left, no banner.

        Two-line identity block (blob has no window), labeled best-guess
        headline, vanish-don't-dash slot list rendered through the shared
        flat label/value helper. No footer, no inner separator, no
        trailing rule. The inter-card separator on a multi-card run is
        emitted by the caller (_render_blob_for_path) immediately before
        invoking this method.
        """
        # ── Identity block (two lines - blob has no window) ───────────────
        print(_sanitize(card.source_name), file=self._stream)
        # Provenance line - blob's own; not the schema cards' rows/size line.
        # Terminal-binary FIRST: a positive-magic ID has no line concept.
        # For today's gzip-container path, file_type_guess is None -
        # containers profile the content under decompression - so this
        # ordering does not steal the compressed branch. The "binary,
        # sampled from head" phrasing is card grammar, not a literal I/O
        # trace: a large plain binary may have done seek reads before the
        # terminal verdict held; the user-facing fact is "we ID'd it from
        # the head and stopped looking for log content."
        if card.shape_guess is None:  # binary - magic-ID'd OR char-class verdict
            provenance = (
                f"{human_bytes(card.byte_size)}  ·  binary, sampled from head"
            )
        elif card.is_compressed:
            provenance = (
                f"{human_bytes(card.byte_size)} compressed  ·  sampled from head"
            )
        else:
            provenance = (
                f"{human_bytes(card.byte_size)}  ·  "
                f"sampled {card.sampled_line_count:,} lines across "
                f"{card.sample_read_count} reads"
            )
        print(provenance, file=self._stream)
        print(file=self._stream)

        # ── Headline - labeled best-guess ─────────────────────────────────
        if card.file_type_guess is not None:
            headline = (
                f"This looks like a {_sanitize(card.file_type_guess)}, not a log."
            )
        elif card.shape_guess is None:  # binary by char-class, no magic ID
            headline = "This looks like binary data, not a log."
        else:
            headline = (
                f"Unrecognized source - but this looks like {_sanitize(card.shape_guess)}."
            )
        print(headline, file=self._stream)
        print(file=self._stream)

        # ── Slot list (vanish-don't-dash) ─────────────────────────────────
        slot_rows: list[tuple[str, str]] = []

        # bytes: always present. Binary (shape_guess None) - magic-ID'd or a
        # char-class verdict; the magic clause is appended only when a signature
        # matched, so a char-class binary reads "binary (38.0% printable)".
        if card.shape_guess is None:
            if card.file_type_magic is not None:
                magic_part = _sanitize(
                    f", magic {repr(card.file_type_magic)[2:-1]}"  # strip b'...'
                )
            else:
                magic_part = ""
            slot_rows.append((
                "bytes",
                f"binary ({card.printable_pct:.1f}% printable){magic_part}",
            ))
        else:
            tail = ", UTF-8 clean" if card.utf8_clean else ""
            slot_rows.append((
                "bytes",
                f"text ({card.printable_pct:.1f}% printable){tail}",
            ))

        # shape: text only.
        if card.shape_guess is not None:
            slot_rows.append(("shape", _sanitize(card.shape_guess)))

        # lines: text only; absent on binary terminal.
        if card.mean_line_length is not None:
            shape_tail = (
                f", {_sanitize(card.line_length_shape)}"
                if card.line_length_shape else ""
            )
            slot_rows.append((
                "lines",
                f"mean {card.mean_line_length:.0f} chars, "
                f"p95 {card.line_length_p95}, "
                f"max {card.max_line_length}{shape_tail}",
            ))

        # fields: / tokens: - one or the other, never both. The summariser
        # sets json_field_names on a JSON shape-guess (names-no-values),
        # which the renderer prefers; otherwise the existing top-tokens
        # row carries the literal-token spray. Vanish if neither populates.
        wrap_label: str | None = None  # which label gets the two-line clamp
        wrap_sep: str = ", "
        if card.json_field_names:
            slot_rows.append((
                "fields",
                ", ".join(_sanitize(name) for name in card.json_field_names),
            ))
            wrap_label = "fields"
            wrap_sep = ", "
        elif card.top_tokens:
            tokens_str = " ".join(
                f'"{_sanitize(tok)}"' for tok, _ in card.top_tokens[:5]
            )
            slot_rows.append(("tokens", f"{tokens_str}  [literal]"))
            wrap_label = "tokens"
            wrap_sep = " "

        # templates: text only; vanish on freeform floor / drain3 dormant.
        if card.distinct_templates is not None:
            slot_rows.append((
                "templates",
                f"~{card.distinct_templates} distinct structures over "
                f"{card.sampled_line_count:,} sampled lines",
            ))

        # Render: single-line slots through the shared label/value shape
        # (matching _render_label_value_block's sizing exactly so the two
        # cannot drift); the wrap-label row through the blob-local
        # _wrap_blob_slot_value clamp.
        label_w = max(len(lbl) for lbl, _ in slot_rows)
        label_col = label_w + 2
        for lbl, val in slot_rows:
            if lbl == wrap_label:
                wrapped = _wrap_blob_slot_value(
                    val, label_col=label_col, sep=wrap_sep,
                )
                print(
                    f"{(lbl + ':').ljust(label_col)}{wrapped[0]}",
                    file=self._stream,
                )
                for cont in wrapped[1:]:
                    print(cont, file=self._stream)
            else:
                print(
                    f"{(lbl + ':').ljust(label_col)}{val}",
                    file=self._stream,
                )


register_handler("text", TextHandler)
