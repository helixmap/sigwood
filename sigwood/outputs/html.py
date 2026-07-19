"""HTML output handler - a designed, shareable READING report.

A self-contained single ``.html`` file (inline CSS, system fonts, NO external
resources) built for a browser AND for the WeasyPrint PDF twin (``outputs/pdf.py``
reuses ``render_report_html`` verbatim). A human reading surface: display-timezone
labeled time (local by default, UTC under ``--utc``/``use_utc``), ``-v`` / ``-vv``
tiers, capped per detector.

SECURITY RAIL: every data-derived string passes through the single ``_esc`` choke
point - a ``<script>`` in evidence renders inert. No data value is ever turned into
an ``<a href>`` or a CSS ``url()``; URLs / ARNs / domains appear only as inert
escaped text.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, TextIO

from sigwood.common.display import fmt_suppression, fmt_window, human_bytes, plural
from sigwood.common.finding import Finding, MethodTag, RunSummary, Severity
from sigwood.common.output import OutputHandler, register_handler
from sigwood.outputs._evidence import evidence_at_level
from sigwood.outputs._render_model import (
    ColumnSpec,
    DetectorRenderable,
    Section,
    _SEVERITY_ORDER,
    _build_renderable,
    html_cell_value,
    html_columns,
    needs_landscape,
    project_row,
)
from sigwood.outputs._sanitize import strip_control
from sigwood.outputs._serialize import jsonable_to_human, to_jsonable

_WORDMARK = "sigwood · threat hunt"


# --------------------------------------------------------------------------- #
# Escaping - the single security choke point
# --------------------------------------------------------------------------- #
def _esc(value: object) -> str:
    """THE choke point: strip controls, then ``html.escape(..., quote=True)``.

    The ONLY call to ``html.escape`` in this module. ``quote=True`` so a value
    that lands in an attribute context is also safe. Every data-derived string
    routes through here exactly once, at the leaf where it becomes markup."""
    return html.escape(strip_control(value), quote=True)


def _cell(value: Any) -> str:
    """Render an evidence value (normalised via ``to_jsonable``) as a clean,
    escaped, readable string - never a Python ``repr``/``str(dict)`` dump. Uses
    the shared ``jsonable_to_human`` so the csv worklist and the html report
    can't drift on value rendering."""
    return _esc(jsonable_to_human(to_jsonable(value), item_sep=", ", kv_sep=": "))


# --------------------------------------------------------------------------- #
# Per-detector renderables - the SAME section-aware pipeline text uses
# --------------------------------------------------------------------------- #
def _build_renderables(
    findings: list[Finding],
    *,
    verbose_level: int,
    max_findings_per_detector: int,
) -> list[tuple[str, DetectorRenderable]]:
    """Group findings by detector (first-seen) and run the SHARED pipeline per
    detector - the SAME sections + pre-cap sidecars text consumes (html/pdf
    match text's section-aware pipeline, not a flat list). A detector whose
    level-visible set is empty renders nothing."""
    by_detector: dict[str, list[Finding]] = {}
    for f in findings:
        by_detector.setdefault(f.detector, []).append(f)
    out: list[tuple[str, DetectorRenderable]] = []
    for detector, group in by_detector.items():
        renderable = _build_renderable(detector, group, verbose_level, max_findings_per_detector)
        if renderable.level_visible_total == 0:
            continue
        out.append((detector, renderable))
    return out


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
def _render_method_chip(name: str, tag: "MethodTag | None") -> str:
    """One detector chip. (parens) for a named published technique (filled),
    [brackets] for a house method (outlined), bare name when untagged. The
    convention carries the meaning; the CSS class only adds colour."""
    if tag is None:
        return f'<span class="chip chip-house">{_esc(name)}</span>'
    if tag.named:
        label = f"{name} ({tag.label})"
        return f'<span class="chip chip-named">{_esc(label)}</span>'
    label = f"{name} [{tag.label}]"
    return f'<span class="chip chip-house">{_esc(label)}</span>'


def _meta_row(label: str, value_html: str) -> str:
    return (
        f'<div class="meta-row"><span class="meta-label">{_esc(label)}</span>'
        f'<span class="meta-value">{value_html}</span></div>'
    )


def _render_header(run_summary: "RunSummary | None") -> str:
    """The always-full, verbosity-independent header block."""
    rows: list[str] = []
    if run_summary is not None:
        window_cell = (
            "none" if run_summary.data_window is None
            else fmt_window(run_summary.data_window)
        )
        rows.append(_meta_row("window", _esc(window_cell)))
        if run_summary.record_counts:
            records = " · ".join(
                f"{count:,} {_esc(name)}" for name, count in run_summary.record_counts.items()
            )
            rows.append(_meta_row("records", records))
        rows.append(_meta_row("data", _esc(human_bytes(run_summary.data_size_bytes))))
        if run_summary.suppression is not None:
            rows.append(_meta_row("allowlist", _esc(fmt_suppression(run_summary.suppression))))
        if run_summary.detectors_run:
            chips = "".join(
                _render_method_chip(name, run_summary.detector_methods.get(name))
                for name in run_summary.detectors_run
            )
            rows.append(_meta_row("detectors", f'<span class="chips">{chips}</span>'))
        for name, reason in run_summary.detectors_skipped.items():
            rows.append(f'<div class="skip">{_esc(name)} - {_esc(reason)}</div>')
        # Failed detectors (crashed during prep or run - recorded on the
        # summary during the detector loop; html renders at end(), so the
        # header sees the final state). The REASON can echo log-derived
        # bytes - it routes through the _esc choke point like every value.
        for name, reason in run_summary.detectors_failed.items():
            rows.append(f'<div class="fail">{_esc(name)} - {_esc(reason)}</div>')
        for note in run_summary.notes:
            rows.append(f'<div class="note">{_esc(note)}</div>')

    return (
        "<header>"
        f'<div class="wordmark">{_esc(_WORDMARK)}</div>'
        f'<div class="meta">{"".join(rows)}</div>'
        "</header>"
    )


# --------------------------------------------------------------------------- #
# Severity summary strip
# --------------------------------------------------------------------------- #
def _render_severity_strip(renderables: list[tuple[str, DetectorRenderable]]) -> str:
    """H / M / L / I count cards, summed from the PRE-CAP breakdowns (so the
    strip agrees with the group headers, not the capped card count)."""
    totals: dict[Severity, int] = {s: 0 for s in _SEVERITY_ORDER}
    for _detector, renderable in renderables:
        for sev, n in renderable.severity_breakdown.items():
            totals[sev] = totals.get(sev, 0) + n
    labels = {
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Info",
    }
    cards = "".join(
        f'<div class="sev-card sev-{sev.name.lower()}">'
        f'<div class="sev-count">{totals[sev]:,}</div>'
        f'<div class="sev-label">{labels[sev]}</div></div>'
        for sev in _SEVERITY_ORDER
    )
    return f'<div class="sev-strip">{cards}</div>'


# --------------------------------------------------------------------------- #
# Findings + the ONE generic card renderer
# --------------------------------------------------------------------------- #
def _render_next_steps(steps: list[str]) -> str:
    if not steps:
        return ""
    items = "".join(f"<li>{_esc(step)}</li>" for step in steps)
    return f'<ul class="next-steps">{items}</ul>'


def _render_kv_grid(data: dict[str, Any]) -> str:
    """A borderless key/value table (NOT CSS grid - weasyprint-safe). Empty
    dict → '' (vanish-don't-dash). Keys AND values escaped."""
    if not data:
        return ""
    rows = "".join(
        f'<tr><td class="k">{_esc(key)}</td><td class="v">{_cell(value)}</td></tr>'
        for key, value in data.items()
    )
    return f'<table class="kv">{rows}</table>'


def _render_detail_row(finding: Finding, *, verbose_level: int, colspan: int) -> str:
    """The -v / -vv detail as a spanning row under the finding (colspan = HTML-
    surviving data columns). L0 → '' ; L1 → desc + next_steps + curated grid ;
    L2 → desc + next_steps + FULL grid. Vanish-don't-dash: empty → no row."""
    if verbose_level < 1:
        return ""
    parts: list[str] = []
    if finding.description:
        parts.append(f'<p class="desc">{_esc(finding.description)}</p>')
    parts.append(_render_next_steps(finding.next_steps))
    # evidence_at_level dispatches curated (1) vs full (2).
    parts.append(_render_kv_grid(evidence_at_level(finding, verbose_level)))
    body = "".join(p for p in parts if p)
    if not body:
        return ""
    return (
        f'<tr class="detail"><td class="sev-cell"></td>'
        f'<td colspan="{colspan}">{body}</td></tr>'
    )


def _render_sample_details(finding: Finding, *, colspan: int) -> str:
    """Always-available, default-closed full syslog member sample.

    Every member reaches markup only through ``_esc``. Data never enters an
    attribute, URL, or CSS value. Print keeps the summary but hides the body so a
    level-0 PDF cannot disclose verbose evidence.
    """
    if finding.detector != "syslog" or finding.evidence.get("tier") not in (
        "family", "burst",
    ):
        return ""
    samples = finding.evidence.get("sample_raw")
    if not isinstance(samples, (list, tuple)) or not samples:
        return ""
    lines = "".join(
        f'<div class="sample-line">{_esc(line)}</div>' for line in samples[:20]
    )
    return (
        '<tr class="sample-detail"><td class="sev-cell"></td>'
        f'<td colspan="{colspan}"><details><summary>sampled log lines</summary>'
        f'<div class="sample-detail-body">{lines}</div></details></td></tr>'
    )


def _render_finding_row(
    finding: Finding,
    keep: list[tuple[int, "ColumnSpec"]],
    *,
    verbose_level: int,
) -> str:
    """One ``<tr>`` from project_row cells (severity is a leftmost pill cell, NOT
    a data cell). A full_width finding spans the data columns (aws ranked-summary
    prose or a syslog row with no timestamp column). A projector-less detector
    (project_row → []) falls back
    to the title as a spanning cell - mirrors text's generic ``_render_finding`` so
    a future detector's content is never lost. SECURITY: every value routes through
    ``_esc``."""
    sev_class = f"sev-{finding.severity.name.lower()}"
    colspan = max(1, len(keep))  # defensive: a ranked_summary-only section has 0 cols
    pill = (
        f'<td class="sev-cell"><span class="pill {sev_class}">'
        f"{_esc(str(finding.severity))}</span></td>"
    )
    cells = project_row(finding)
    if not cells:
        # No projector for this detector - show the title (generic fallback,
        # matching text's `{tag}  {finding.title}`), never a bare pill.
        data = f'<td colspan="{colspan}">{_esc(finding.title)}</td>'
    elif cells[0].full_width:
        # Syslog uses full_width structurally for self-stamped needles and
        # null-timestamp aggregates; keep those in the default monospace cell.
        # Other full-width rows are prose and retain the sans-serif class.
        cls = "" if finding.detector == "syslog" else ' class="full-width"'
        data = f'<td{cls} colspan="{colspan}">{_esc(cells[0].value)}</td>'
    elif len(cells) == 1 and cells[0].key is None:
        # A lone bare cell is a whole line of text, not column 0 of a table. Span
        # it so a long value wraps across the full width instead of defining a
        # narrow first column that squeezes structured sibling rows. Kept on the
        # default monospace td - NOT the sans `full-width` prose class.
        data = f'<td colspan="{colspan}">{_esc(cells[0].value)}</td>'
    else:
        tds = []
        for i, spec in keep:
            # A keyed column carries its label in the `<th>` header, so strip the
            # redundant in-value label (`period=61.5m` → `61.5m`) - text keeps the
            # labeled form. A missing/bare cell renders "" / its value unchanged.
            value = html_cell_value(cells[i]) if i < len(cells) else ""
            # Keyed columns are short data tokens (dur / bps / counts / states):
            # mark them `data` so CSS can nowrap them - they must never mid-break
            # (`54bps` → `54bp`/`s`) or wrap at a space when a long flow squeezes
            # the row. Keyless entity/flow cells keep the default break-word so a
            # long IPv6 / domain can still fold. `num` still right-justifies.
            classes = []
            if spec.align == "right":
                classes.append("num")
            if spec.key is not None:
                classes.append("data")
            cls = f' class="{" ".join(classes)}"' if classes else ""
            tds.append(f"<td{cls}>{_esc(value)}</td>")
        data = "".join(tds)
    row = f'<tr class="finding-row {sev_class}">{pill}{data}</tr>'
    return (
        row
        + _render_sample_details(finding, colspan=colspan)
        + _render_detail_row(finding, verbose_level=verbose_level, colspan=colspan)
    )


def _render_section(section: Section, *, verbose_level: int) -> str:
    """One section as a tight ``<table>``: header row of the HTML-surviving
    columns + one ``<tr>`` per finding. A subsectioned detector (dns / aws) shows
    the plain section label; a flat detector has none."""
    keep = html_columns(section)  # [(positional index, spec), …] - all_empty dropped
    parts: list[str] = []
    if section.label:
        parts.append(
            f'<div class="section-label">{_esc(section.label)} '
            f"({section.pre_cap_count})</div>"
        )
    if keep:
        header_cells = []
        for _i, spec in keep:
            cls = ' class="num"' if spec.align == "right" else ""
            label = _esc(spec.key) if spec.key else ""
            header_cells.append(f"<th{cls}>{label}</th>")
        thead = (
            f'<thead><tr><th class="sev-col"></th>'
            f'{"".join(header_cells)}</tr></thead>'
        )
    else:
        thead = ""  # no grid columns (e.g. a ranked_summary-only section)
    rows = "".join(
        _render_finding_row(f, keep, verbose_level=verbose_level)
        for f in section.findings
    )
    parts.append(f'<table class="findings-table">{thead}<tbody>{rows}</tbody></table>')
    return "".join(parts)


def _render_group_header(detector: str, renderable: DetectorRenderable) -> str:
    """``beacon - 12 findings · 3 H · 9 M`` from the PRE-CAP sidecars."""
    total = renderable.level_visible_total
    bits = [
        f"{renderable.severity_breakdown[sev]} {sev.value}"
        for sev in _SEVERITY_ORDER
        if renderable.severity_breakdown.get(sev)
    ]
    tail = (" · " + " · ".join(bits)) if bits else ""
    head = f"{_esc(detector)} - {total} {_esc(plural(total, 'finding'))}{tail}"
    return f'<div class="group-head">{head}</div>'


def _render_detector_block(
    detector: str, renderable: DetectorRenderable, *, verbose_level: int
) -> str:
    parts = [_render_group_header(detector, renderable)]
    if renderable.cap_truncated:
        shown = renderable.level_visible_total - renderable.cap_truncated
        parts.append(
            f'<div class="cap-note">showing {shown:,} of '
            f"{renderable.level_visible_total:,}</div>"
        )
    for section in renderable.sections:
        if not section.findings:
            continue  # a section emptied by the cap vanishes
        parts.append(_render_section(section, verbose_level=verbose_level))
    return f'<div class="group">{"".join(parts)}</div>'


def _render_findings(
    renderables: list[tuple[str, DetectorRenderable]], *, verbose_level: int
) -> str:
    if not renderables:
        return '<div class="empty">No findings.</div>'
    return "".join(
        _render_detector_block(det, r, verbose_level=verbose_level)
        for det, r in renderables
    )


# --------------------------------------------------------------------------- #
# Document shell + styles
# --------------------------------------------------------------------------- #
def _styles(landscape: bool) -> str:
    """Inline CSS. System fonts, NO external resources, NO CSS grid (weasyprint
    partial). Light palette via :root custom properties; dark mode re-binds them;
    an @media print block makes the same string PDF-safe.

    ``landscape`` flips ONLY the print ``@page`` size - everything
    else, including the on-screen html, is inert to it (paged media only). The
    data-cell ``nowrap`` lives under ``@media screen`` so the PRINT page wraps
    instead of clipping wide tables (the correctness floor)."""
    page_size = "A4 landscape" if landscape else "A4"
    return ("""
:root {
  --bg: #ffffff; --fg: #1f2933; --muted: #677181; --border: #d7dde4;
  --card-bg: #ffffff; --head-bg: #f6f8fa;
  --chip-named-bg: #e3f6fb; --chip-named-border: #18a0bd; --chip-named-fg: #0b6b80;
  --chip-house-border: #c2cbd6; --chip-house-fg: #475160;
  --sev-high: #c0392b; --sev-medium: #d98910; --sev-low: #2c7fb8; --sev-info: #7a8493;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14181d; --fg: #e6eaef; --muted: #9aa4b1; --border: #2a3038;
    --card-bg: #1b2128; --head-bg: #1f2630;
    --chip-named-bg: #0c2f38; --chip-named-border: #2bb6d4; --chip-named-fg: #7fd6e8;
    --chip-house-border: #3a424d; --chip-house-fg: #aab4c0;
    --sev-high: #e06a5c; --sev-medium: #e8a94a; --sev-low: #5aa6d8; --sev-info: #98a2b0;
  }
}
* { box-sizing: border-box; }
body {
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: var(--fg); background: var(--bg); margin: 0; padding: 32px;
  max-width: 1100px; margin-left: auto; margin-right: auto;
}
header { border-bottom: 2px solid var(--border); padding-bottom: 18px; margin-bottom: 24px; }
.wordmark { font-size: 22px; font-weight: 700; letter-spacing: .2px; margin-bottom: 14px; }
.meta-row { display: flex; align-items: baseline; margin: 3px 0; }
.meta-label { color: var(--muted); width: 96px; flex: 0 0 96px; text-transform: lowercase; }
.meta-value { color: var(--fg); }
.skip, .note { color: var(--muted); font-size: 13px; margin: 3px 0 0 96px; }
.fail { color: var(--sev-high); font-size: 13px; margin: 3px 0 0 96px; }
.chips { display: inline-flex; flex-wrap: wrap; gap: 6px; }
.chip {
  display: inline-block; padding: 1px 9px; border-radius: 11px; font-size: 13px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: nowrap;
}
.chip-named { background: var(--chip-named-bg); border: 1px solid var(--chip-named-border); color: var(--chip-named-fg); font-weight: 600; }
.chip-house { background: transparent; border: 1px solid var(--chip-house-border); color: var(--chip-house-fg); }
.sev-strip { display: flex; gap: 12px; margin: 0 0 28px; }
.sev-card { flex: 1 1 0; border: 1px solid var(--border); border-top: 4px solid var(--border); border-radius: 6px; padding: 12px 14px; background: var(--card-bg); }
.sev-count { font-size: 26px; font-weight: 700; }
.sev-label { color: var(--muted); font-size: 13px; }
.sev-strip .sev-high { border-top-color: var(--sev-high); }
.sev-strip .sev-medium { border-top-color: var(--sev-medium); }
.sev-strip .sev-low { border-top-color: var(--sev-low); }
.sev-strip .sev-info { border-top-color: var(--sev-info); }
.group { margin-bottom: 30px; }
.group-head { font-size: 16px; font-weight: 600; padding-bottom: 8px; border-bottom: 1px solid var(--border); margin-bottom: 10px; }
.cap-note { color: var(--muted); font-size: 13px; margin-bottom: 10px; }
.empty { color: var(--muted); }
.pill { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-weight: 700; font-size: 13px; padding: 0 6px; border-radius: 4px; color: #fff; }
.pill.sev-high { background: var(--sev-high); }
.pill.sev-medium { background: var(--sev-medium); }
.pill.sev-low { background: var(--sev-low); }
.pill.sev-info { background: var(--sev-info); }
.desc { margin: 10px 0 6px; }
.next-steps { margin: 6px 0; padding-left: 22px; }
.next-steps li { margin: 2px 0; }
.kv { border-collapse: collapse; margin: 8px 0 2px; width: 100%; }
.kv td { vertical-align: top; padding: 2px 10px 2px 0; font-size: 14px; }
.kv .k { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: nowrap; }
.kv .v { word-break: break-word; }
.section-label { color: var(--muted); font-size: 13px; margin: 12px 0 4px; }
.findings-table { border-collapse: collapse; width: 100%; margin: 4px 0 14px; font-size: 14px; }
.findings-table th { text-align: left; color: var(--muted); font-weight: 600; font-size: 12px; padding: 4px 12px 4px 0; border-bottom: 1px solid var(--border); white-space: nowrap; }
.findings-table td { padding: 5px 12px 5px 0; border-bottom: 1px solid var(--border); vertical-align: top; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-word; }
.findings-table th.num, .findings-table td.num { text-align: right; }
.findings-table .sev-col, .findings-table .sev-cell { width: 1%; padding-right: 10px; white-space: nowrap; }
.findings-table .full-width { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.findings-table tr.detail td { padding: 2px 0 10px 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.findings-table tr.detail .desc { margin: 6px 0 4px; }
.findings-table tr.detail .next-steps { margin: 4px 0; }
.findings-table tr.sample-detail td { padding: 2px 0 8px 0; }
.sample-detail summary { color: var(--muted); cursor: pointer; }
.sample-detail-body { margin: 5px 0 2px; }
.sample-line { white-space: pre-wrap; overflow-wrap: anywhere; }
@media screen {
  /* Screen-only: short data tokens (dur/bps/counts/states) never mid-break on
     screen. In PRINT this is ABSENT, so td.data falls back to the base
     word-break: break-word and WRAPS - the page wraps instead of clipping wide
     tables (the correctness floor; paged media has no horizontal scroll). */
  .findings-table td.data { white-space: nowrap; }
}
@media print {
  @page { size: __SIGWOOD_PAGE_SIZE__; margin: 1.5cm; }
  body { padding: 0; max-width: none; }
  .sev-card { break-inside: avoid; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .findings-table tr { break-inside: avoid; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .group-head, .section-label { break-after: avoid; }
  .sample-detail-body { display: none; }
}
""".strip().replace("__SIGWOOD_PAGE_SIZE__", page_size))


def render_report_html(
    findings: list[Finding],
    run_summary: "RunSummary | None",
    *,
    verbose_level: int,
    max_findings_per_detector: int = 100,
) -> str:
    """Produce the complete self-contained HTML document string. PURE - no I/O.

    Both ``HtmlHandler.end()`` and ``PdfHandler.end()`` call this (ONE renderer,
    two outputs)."""
    renderables = _build_renderables(
        findings,
        verbose_level=verbose_level,
        max_findings_per_detector=max_findings_per_detector,
    )
    # Orientation decided HERE so html and pdf agree (one renderer, two outputs);
    # @page only affects paged media, so the on-screen html is inert to it.
    landscape = needs_landscape(renderables)
    header = _render_header(run_summary)
    strip = _render_severity_strip(renderables)
    body = _render_findings(renderables, verbose_level=verbose_level)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n'
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "  <title>sigwood report</title>\n"
        f"  <style>{_styles(landscape)}</style>\n"
        "</head>\n<body>\n"
        f"{header}\n{strip}\n<main>{body}</main>\n"
        "</body>\n</html>\n"
    )


class HtmlHandler(OutputHandler):
    """Write findings as a self-contained HTML report file."""

    def __init__(
        self,
        stream: TextIO | None = None,
        output_path: Path | None = None,
        verbose_level: int = 0,
        *,
        max_findings_per_detector: int = 100,
    ) -> None:
        # Exactly one of ``stream`` / ``output_path`` is set by the runner:
        # ``stream`` (sys.stdout) for the redirect idiom, ``output_path`` for a
        # file. No CWD default - html joins text/json/csv in defaulting to
        # stdout, and the surprise-file class is deleted. Neither set is a caller
        # misuse - fail fast with an actionable error, not a raw AttributeError
        # deep in end()'s file write.
        if stream is None and output_path is None:
            raise ValueError("HtmlHandler requires a stream or an output_path")
        self._stream = stream
        self._output_path = output_path
        self._verbose_level = verbose_level
        self._max_findings_per_detector = max_findings_per_detector
        self._findings: list[Finding] = []
        self._run_summary: RunSummary | None = None

    def begin(self, run_summary: RunSummary) -> None:
        """Store run summary for the report header."""
        self._run_summary = run_summary

    def write(self, findings: list[Finding]) -> None:
        """Accumulate findings for rendering at end()."""
        self._findings.extend(findings)

    def end(self) -> None:
        """Render and emit the complete HTML - to the caller's stream or a file."""
        html_str = render_report_html(
            self._findings,
            self._run_summary,
            verbose_level=self._verbose_level,
            max_findings_per_detector=self._max_findings_per_detector,
        )
        if self._stream is not None:
            # stdout target - the runner owns the stream; never close it.
            self._stream.write(html_str)
            self._stream.flush()
            return
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._output_path.write_text(html_str, encoding="utf-8")


register_handler("html", HtmlHandler)
