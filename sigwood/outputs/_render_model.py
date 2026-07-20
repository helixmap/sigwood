"""Shared render model for the reading surfaces (text · html · pdf).

The SINGLE owner of "what a finding renders": the per-detector pipeline
(``_build_renderable`` + ``Section`` + partitioners + the two exemptions +
the section-walking cap + pre-cap sidecars) AND the per-finding cell projection
(``project_row`` / ``section_columns``). text and html/pdf BOTH consume this so
they cannot drift.

PURE - no I/O, no ``detectors/`` imports. Imports ``common/`` and
``outputs/_evidence`` (``level_visible``) only.

Cell-projection contract:
  - ``project_row(finding)`` → the ordered data columns text builds today
    (severity is NOT a cell - each surface renders its own tag). ``Cell.value``
    is the fully-formatted string EXACTLY as text builds it. ``key`` is the
    column id + html header (None = a bare entity/flow/domain/principal cell).
    ``align`` mirrors text's justify (right for numeric counts). ``optional`` is
    True ONLY for a column text conditionally DROPS today (dns ``blocked``).
    ``full_width`` marks a single spanning row (aws ``ranked_summary`` prose,
    or a syslog row that must not reserve an absent timestamp column).
  - ``section_columns(section)`` → the per-section POSITIONAL column template
    with ``all_empty`` computed ACROSS the section (never inferred from one row).
    ``text_columns`` / ``html_columns`` apply the two per-surface drop rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sigwood.common.display import (
    fmt_compact_span,
    fmt_syslog_timestamp,
    fmt_timestamp,
    plural,
)
from sigwood.common.finding import Finding, Severity
from sigwood.outputs._evidence import level_visible


# ── pipeline (moved verbatim from text.py - semantics byte-preserved) ────────


@dataclass
class Section:
    """One subsection of a detector's findings - already level-filtered,
    severity-sorted, and post-cap. Renderers consume this - no filtering,
    sorting, or capping happens inside per-detector row formatters.

    ``label`` is None for a flat detector (no subsection line emitted).
    ``pre_cap_count`` is this section's level-visible size BEFORE the cap;
    the subsection label always reports the pre-cap count.
    """

    label: str | None
    findings: list[Finding]
    pre_cap_count: int


@dataclass
class DetectorRenderable:
    """Per-detector pipeline result. Built by ``_build_renderable`` before any
    row formatting. Carries pre-cap counts and severity breakdown as sidecars
    so the group header NEVER re-reads severity from post-cap ``Section.findings``.
    """

    sections: list[Section]
    level_visible_total: int
    severity_breakdown: dict[Severity, int]
    cap_truncated: int = 0


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def _severity_sort_key(f: Finding) -> int:
    """Stable severity-primary sort key (HIGH=0 … INFO=3). Within a band, the
    detector's incoming secondary order survives (label-score desc, composite-z
    desc, etc.) because Python's sort is stable."""
    return _SEVERITY_ORDER.index(f.severity)


def _partition_dns(findings: list[Finding]) -> list[Section]:
    """DNS: singletons FIRST (no subdomain_count), then groups (the singletons
    tier is consistently the more interesting one), then the synthetic
    dense-cluster scan summary in its OWN trailing section. Each
    speaks-iff-non-empty: an empty subsection vanishes entirely. The
    scan_summary finding is pulled out FIRST - it has no subdomain_count and must
    not land in the singleton branch."""
    scan = [f for f in findings if f.evidence.get("tier") == "scan_summary"]
    rest = [f for f in findings if f.evidence.get("tier") != "scan_summary"]
    singletons = [f for f in rest if "subdomain_count" not in f.evidence]
    groups = [f for f in rest if "subdomain_count" in f.evidence]
    out: list[Section] = []
    if singletons:
        out.append(Section("singletons", singletons, len(singletons)))
    if groups:
        out.append(Section("groups", groups, len(groups)))
    if scan:
        out.append(Section("dense-cluster scan", scan, len(scan)))
    return out


def _partition_aws(findings: list[Finding]) -> list[Section]:
    """AWS: bursts first, then ranked (+ synthetic ranked_summary). The ranked
    section bundles per-principal and the summary line together."""
    bursts = [f for f in findings if f.evidence.get("tier") == "burst"]
    ranked = [f for f in findings if f.evidence.get("tier") in ("ranked", "ranked_summary")]
    out: list[Section] = []
    if bursts:
        out.append(Section("burst sweeps", bursts, len(bursts)))
    if ranked:
        out.append(Section("ranked principals", ranked, len(ranked)))
    return out


def _partition_syslog(findings: list[Finding]) -> list[Section]:
    """Syslog: privileged MEDIUM, sieve LOW, then burst/reboot INFO.

    Membership keys on evidence, never severity. Declared order makes the cap spend
    its budget on the strongest channel first while preserving timestamp order inside
    each single-severity section.
    """
    privileged = [f for f in findings if f.evidence.get("privileged")]
    rare = [
        f for f in findings
        if not f.evidence.get("privileged")
        and f.evidence.get("tier") in (None, "family")
    ]
    bursts = [f for f in findings if f.evidence.get("tier") in ("burst", "reboot")]
    out: list[Section] = []
    if privileged:
        out.append(Section("privileged", privileged, len(privileged)))
    if rare:
        out.append(Section("rare events", rare, len(rare)))
    if bursts:
        out.append(Section("bursts", bursts, len(bursts)))
    return out


def _partition_flat(findings: list[Finding]) -> list[Section]:
    """Flat detector - one section with no label."""
    return [Section(None, findings, len(findings))]


_PARTITIONERS = {
    "dns": _partition_dns,
    "aws": _partition_aws,
    "syslog": _partition_syslog,
}

# Per-detector severity-sort opt-out. Severity sort is the
# right DEFAULT - within a flat or per-section list, H → M → L → I reads as
# urgency-first. But syslog's row order CARRIES meaning: the detector emits
# chronologically, and its three sections ("privileged" = MEDIUM, "rare events"
# = LOW, "bursts" = INFO collapsed-bursts + standalone reboots) are each single-severity
# - so severity-sort is a no-op anyway, and what matters is preserving ts-order
# WITHIN a section (a burst sits next to the reboot near it in time). Listing
# syslog here keeps that incoming order explicit.
_SEVERITY_SORT_EXEMPT: frozenset[str] = frozenset({"syslog"})

# Synthetic always-show finding tiers. These are
# all-clear / quiet-summary rows the detector designed to render
# unconditionally. They are exempt from the cap budget - they neither
# count against the budget nor get dropped when the budget runs out. Today
# the only entry is aws's ``ranked_summary``, which covers both ranked-tier
# quiet lines: the zero-cleared "nothing stood out" summary and the
# below-population-floor "too few principals to compare" summary.
# New synthetic all-show tiers join this set; the renderer is otherwise
# unchanged. dns's ``scan_summary`` (the dense-cluster scan disclosure) is the
# second entry.
_ALWAYS_SHOW_TIERS: frozenset[str] = frozenset({"ranked_summary", "scan_summary"})


def _is_always_show(finding: Finding) -> bool:
    """True for synthetic always-show findings. Exempt from the cap."""
    return finding.evidence.get("tier") in _ALWAYS_SHOW_TIERS


def _build_renderable(
    detector: str,
    findings: list[Finding],
    verbose_level: int,
    max_per_detector: int,
) -> DetectorRenderable:
    """Run the render pipeline on one detector's findings.

    Order is binding:
      1. level-filter (duration LOW at level 0)
      2. partition into Sections (detector-specific)
      3. capture pre-cap level_visible_total + severity_breakdown
      4. severity-sort each section in place
      5. cap walks sections in declared order; truncates findings; sets
         cap_truncated; later sections may end up with findings=[] and
         vanish at render time

    Both ``level_visible_total`` and ``severity_breakdown`` are captured
    BEFORE the cap so the group header NEVER drifts to post-cap counts -
    the pre-cap regression test in tests/test_text_output.py guards this.
    """
    visible = [f for f in findings if level_visible(f, verbose_level)]

    partition = _PARTITIONERS.get(detector, _partition_flat)
    sections = partition(visible)

    level_visible_total = len(visible)
    breakdown: dict[Severity, int] = {}
    for f in visible:
        breakdown[f.severity] = breakdown.get(f.severity, 0) + 1

    if detector not in _SEVERITY_SORT_EXEMPT:
        for s in sections:
            s.findings.sort(key=_severity_sort_key)

    # Synthetic always-show findings are exempt from the cap. Pull
    # them out per-section before the budget walk so they neither consume
    # the budget nor risk being dropped, then re-append them at the tail
    # of their section (preserving the existing aws renderer's
    # per-principal-then-summary order). Renderer code is unchanged.
    always_show_by_section: list[list[Finding]] = []
    for s in sections:
        always = [f for f in s.findings if _is_always_show(f)]
        if always:
            s.findings = [f for f in s.findings if not _is_always_show(f)]
        always_show_by_section.append(always)

    cap_truncated = 0
    # Cap accounting runs against the cappable count only (always-show
    # findings live outside the budget).
    cappable_total = sum(len(s.findings) for s in sections)
    if max_per_detector > 0 and cappable_total > max_per_detector:
        remaining = max_per_detector
        for s in sections:
            if remaining <= 0:
                cap_truncated += len(s.findings)
                s.findings = []
                continue
            if len(s.findings) > remaining:
                cap_truncated += len(s.findings) - remaining
                s.findings = s.findings[:remaining]
                remaining = 0
            else:
                remaining -= len(s.findings)

    # Re-append the held-back always-show findings at the tail of their
    # section. This preserves the existing aws renderer's "per-principal
    # rows, then summary line" layout and keeps the all-clear visible even
    # when the cap empties the cappable rows.
    for s, always in zip(sections, always_show_by_section):
        if always:
            s.findings.extend(always)

    return DetectorRenderable(
        sections=sections,
        level_visible_total=level_visible_total,
        severity_breakdown=breakdown,
        cap_truncated=cap_truncated,
    )


# ── per-finding cell projection ──────────────────────────────────────────────


@dataclass(frozen=True)
class Cell:
    """One data column of a rendered finding. ``value`` is the fully-formatted
    string EXACTLY as text builds it. ``key`` is the column id + html header
    (None = a bare entity/flow/domain/principal cell). ``align`` is text's
    justify ("right" for numeric counts). ``optional`` marks a column text
    conditionally drops (dns ``blocked``). ``full_width`` marks a single
    spanning prose row (aws ``ranked_summary``)."""

    key: str | None
    value: str
    align: str = "left"
    optional: bool = False
    full_width: bool = False


def html_cell_value(cell: Cell) -> str:
    """The value HTML renders for a KEYED column, with the in-value label stripped
    so it is not double-printed beneath its own ``<th>`` header (``period=61.5m``
    under a ``period`` header → ``61.5m``; ``4217 sub`` under ``sub`` → ``4217``).

    Text keeps the labeled ``value`` verbatim - the label is redundant ONLY where a
    column header carries it, which is an HTML/PDF-only surface (text has no header
    row). A bare or full-width cell (``key is None``), or a keyed cell whose value
    does not embed its key as a ``<key>=`` prefix or a `` <key>`` suffix (dur / bps /
    states / a scan type or metric), is returned unchanged - those headers are not
    duplicated in the cell, so there is nothing to strip."""
    if cell.key is None:
        return cell.value
    prefix = f"{cell.key}="
    if cell.value.startswith(prefix):
        return cell.value[len(prefix):]
    suffix = f" {cell.key}"
    if cell.value.endswith(suffix):
        return cell.value[: -len(suffix)]
    return cell.value


def _aws_span_str(seconds: float) -> str:
    """Compact span used by burst rows: 45s / 7m / 3h / 2d."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def _project_beacon(f: Finding) -> list[Cell]:
    ev = f.evidence
    dst = f"{ev.get('dst_ip', '')}:{ev.get('dst_port', '')}/{ev.get('proto', '')}"
    return [
        Cell(None, ev.get("src_ip", "")),
        Cell(None, "→"),
        Cell(None, dst),
        Cell("period", f"period={ev.get('period_str', '?')}"),
        Cell("score", f"score={ev.get('beacon_score', 0):.3f}"),
        Cell("conns", f"{ev.get('conn_count', 0):,} conns", align="right"),
    ]


def _project_dns(f: Finding) -> list[Cell]:
    ev = f.evidence
    if ev.get("tier") == "scan_summary":
        # Full-width disclosure row (aws ranked_summary shape). MUST come before
        # the subdomain_count / singleton reads - it has neither.
        cc = int(ev.get("cluster_count", 0))
        tm = int(ev.get("total_members", 0))
        value = (
            f"dense-cluster scan surfaced {cc} high-entropy {plural(cc, 'cluster')} "
            f"({tm} {plural(tm, 'query', 'queries')}) - review before allowlisting"
        )
        return [Cell(None, value, full_width=True)]
    blocked = Cell("blocked", "BLOCKED" if ev.get("was_blocked") else "", optional=True)
    if "subdomain_count" in ev:  # group
        max_e, min_e = ev["max_label_score"], ev["min_label_score"]
        score = f"score={max_e:.2f}" if max_e == min_e else f"score={max_e:.2f}-{min_e:.2f}"
        return [
            Cell("sub", f"{ev['subdomain_count']} sub", align="right"),
            Cell("score", score),
            Cell("qry", f"{ev['total_queries']} qry", align="right"),
            Cell("src", f"{ev['unique_sources']} src", align="right"),
            blocked,
            Cell(None, ev["registrable_domain"]),
        ]
    return [  # singleton
        Cell("score", f"score={ev['label_score']:.2f}"),
        Cell("qry", f"{ev['query_count']} qry", align="right"),
        Cell("src", f"{ev['unique_sources']} src", align="right"),
        blocked,
        Cell(None, f.title),
    ]


def _project_scan(f: Finding) -> list[Cell]:
    ev = f.evidence
    scan_type = ev.get("scan_type", "")
    if scan_type == "vertical":
        middle = f"→ {ev.get('dst', '')}"
        metric = f"{ev.get('distinct_ports', 0)} ports"
    elif scan_type == "horizontal":
        middle = f"→ *:{ev.get('port', '')}"
        metric = f"{ev.get('distinct_hosts', 0)} hosts"
    elif scan_type == "block":
        middle = "→ *"
        metric = f"{ev.get('distinct_ports', 0)}p × {ev.get('distinct_hosts', 0)}h"
    else:  # slow
        middle = ""
        metric = f"{ev.get('distinct_ports', 0)} ports/{ev.get('active_buckets', 0)} win"
    return [
        Cell("type", scan_type),
        Cell("ratio", f"ratio={ev.get('scan_state_ratio', 0):.2f}"),
        Cell(None, ev.get("src", "")),
        Cell("middle", middle),
        Cell("metric", metric, align="right"),
    ]


def _project_syslog(f: Finding) -> list[Cell]:
    # Variant by TIER (matches _partition_syslog + curated_evidence). Each kind
    # with a determinate timestamp starts with the keyed ``first`` cell; text joins
    # its bare value while HTML exposes the key as the first data-column header.
    # Rows without a timestamp span the grid so they start directly at their
    # content instead of reserving an empty timestamp column. An isolated rare row
    # (tier absent) shows its self-stamped raw line as before.
    ev = f.evidence
    tier = ev.get("tier")
    if tier == "burst":
        host = f.title  # burst title IS the host (evidence carries no host key)
        line_count = int(ev.get("line_count", 0))
        span = float(ev.get("span_seconds", 0.0))
        progs = ", ".join(str(name) for name, _count in ev.get("program_mix", []))
        parts = [host]
        if ev.get("label") == "rebooted":
            parts.append("rebooted")
        parts.extend([
            f"{line_count} rare lines",
            f"{span:.0f}s",
            f"mostly {progs}",
        ])
        line = " · ".join(parts)
        start_ts = ev.get("start_ts")
        if start_ts is None:
            return [Cell(None, line, full_width=True)]
        return [
            Cell(
                "first",
                fmt_syslog_timestamp(
                    datetime.fromtimestamp(float(start_ts), tz=timezone.utc)
                ),
            ),
            Cell(None, line),
        ]
    if tier == "family":
        line_count = int(ev.get("line_count", 0))
        parts = [
            f.title,
            str(ev.get("program", "unknown")),
            f"{line_count} {plural(line_count, 'rare line')}",
        ]
        span = ev.get("span_seconds")
        if span is not None:
            parts.append(fmt_compact_span(timedelta(seconds=float(span))))
        line = " · ".join(parts)
        start_ts = ev.get("start_ts")
        if start_ts is None:
            return [Cell(None, line, full_width=True)]
        return [
            Cell(
                "first",
                fmt_syslog_timestamp(
                    datetime.fromtimestamp(float(start_ts), tz=timezone.utc)
                ),
            ),
            Cell(None, line),
        ]
    if tier == "reboot":
        host = f.title  # reboot title IS the host
        line = f"{host} · rebooted"
        reboot_ts = ev.get("reboot_ts")
        if reboot_ts is None:
            return [Cell(None, line, full_width=True)]
        return [
            Cell(
                "first",
                fmt_syslog_timestamp(datetime.fromisoformat(str(reboot_ts))),
            ),
            Cell(None, line),
        ]
    return [Cell(None, f.title, full_width=True)]  # self-stamped raw needle


def _project_duration(f: Finding) -> list[Cell]:
    ev = f.evidence
    port = ev.get("port")
    port_str = str(port) if port is not None else "?"
    dst = f"{ev.get('dst', '')}:{port_str}/{ev.get('proto', '')}"
    bps = ev.get("avg_bytes_per_second")
    if bps is None:
        bps_col = ""
    elif bps >= 1_000_000:
        bps_col = f"{bps / 1_000_000:.1f}mbps"
    elif bps >= 1_000:
        bps_col = f"{bps / 1_000:.1f}kbps"
    else:
        bps_col = f"{bps:.0f}bps"
    count = ev.get("connection_count", 1)
    conns = f"{count} conn" if count == 1 else f"{count} conns"
    states = ev.get("conn_states", [])
    state_col = ", ".join(states) if states else ""
    return [
        Cell(None, ev.get("src", "")),
        Cell(None, "→"),
        Cell(None, dst),
        Cell("dur", ev.get("max_duration_str", "")),
        Cell("bps", bps_col, align="right"),
        Cell("conns", conns, align="right"),
        Cell("states", state_col, align="right"),
    ]


def _project_aws(f: Finding) -> list[Cell]:
    ev = f.evidence
    tier = ev.get("tier")
    if tier == "burst":
        return [
            Cell(None, str(ev.get("principal", ""))),
            Cell("new", f"{int(ev.get('new_action_count', 0))} new", align="right"),
            Cell("svc", f"{int(ev.get('new_service_count', 0))} svc", align="right"),
            Cell("span", _aws_span_str(float(ev.get("span_seconds", 0.0))), align="right"),
            Cell("err", f"err={float(ev.get('error_rate', 0.0)):.0%}", align="right"),
        ]
    if tier == "ranked_summary":
        # The below-floor variant deliberately carries no top principal or
        # composite z - key the parenthetical on the finding's own
        # ``population_floor`` discriminator so no pivot is ever fabricated.
        if "population_floor" in ev:
            value = (
                f"{f.title}  "
                f"({int(ev.get('scorable_count', 0))} scorable; "
                f"needs {int(ev['population_floor'])} to compare)"
            )
        else:
            value = (
                f"{f.title}  "
                f"({int(ev.get('scorable_count', 0))} scored; "
                f"top {ev.get('top_principal', '')} "
                f"z={float(ev.get('top_composite_z', 0.0)):.2f})"
            )
        return [Cell(None, value, full_width=True)]
    # ranked (per-principal)
    return [
        Cell(None, str(ev.get("principal", ""))),
        Cell("z", f"z={float(ev.get('composite_z', 0.0)):.2f}", align="right"),
        Cell("err", f"err={float(ev.get('error_rate', 0.0)):.0%}", align="right"),
        Cell("ev", f"{int(ev.get('event_count', 0))} ev", align="right"),
        Cell("ip", f"{int(ev.get('distinct_source_ip', 0))} ip", align="right"),
    ]


_PROJECTORS = {
    "beacon": _project_beacon,
    "dns": _project_dns,
    "scan": _project_scan,
    "syslog": _project_syslog,
    "duration": _project_duration,
    "aws": _project_aws,
}


def project_row(finding: Finding) -> list[Cell]:
    """The per-finding headline-signal cells (no severity). Empty list for an
    unknown detector (the generic fallback renders ``finding.title`` alone)."""
    projector = _PROJECTORS.get(finding.detector)
    return projector(finding) if projector else []


# ── per-section column plan ──────────────────────────────────────────────────


@dataclass(frozen=True)
class ColumnSpec:
    """One POSITIONAL column of a section's table. ``all_empty`` is computed
    ACROSS the whole section (every grid row's cell at this index is empty)."""

    key: str | None
    align: str
    optional: bool
    all_empty: bool


def section_columns(section: Section) -> list[ColumnSpec]:
    """The section's POSITIONAL column template + section-wide ``all_empty``.

    Positional, never key-indexed: repeated bare (``key=None``) columns do NOT
    collapse. The template is the positional UNION over the section's GRID rows
    (``full_width`` rows - aws ranked_summary and no-timestamp syslog rows -
    carry no grid cells and are skipped here; they render as a spanning row).
    A row shorter than the union
    contributes ``""`` at the missing positions, so ``all_empty`` stays honest
    for heterogeneous sections (syslog event vs reboot).
    """
    grid_rows = [project_row(f) for f in section.findings]
    grid_rows = [cells for cells in grid_rows if not (cells and cells[0].full_width)]
    if not grid_rows:
        return []
    width = max(len(cells) for cells in grid_rows)
    cols: list[ColumnSpec] = []
    for i in range(width):
        present = [cells[i] for cells in grid_rows if i < len(cells)]
        template = present[0]  # all rows reaching index i share key/align/optional
        all_empty = all(
            (cells[i].value if i < len(cells) else "") == "" for cells in grid_rows
        )
        cols.append(
            ColumnSpec(
                key=template.key,
                align=template.align,
                optional=template.optional,
                all_empty=all_empty,
            )
        )
    return cols


def _keep_indices(cols: list[ColumnSpec], *, html: bool) -> list[int]:
    """Indices of columns that survive the per-surface drop rule (over the ONE
    shared ``all_empty`` computed by ``section_columns``).

    TEXT drops a column iff (optional AND all_empty) - byte-identical to today's
    dns ``if blocked_w > 0`` branch; non-optional all-empty columns stay (padded
    to width 0). HTML drops a column iff all_empty (optional or not - an empty
    table column has no place).
    """
    out: list[int] = []
    for i, c in enumerate(cols):
        drop = c.all_empty if html else (c.optional and c.all_empty)
        if not drop:
            out.append(i)
    return out


def text_columns(section: Section) -> list[ColumnSpec]:
    """Surviving columns (with specs) for the TEXT surface - drops only
    (optional AND all_empty), i.e. dns ``blocked`` when no row was blocked."""
    cols = section_columns(section)
    return [cols[i] for i in _keep_indices(cols, html=False)]


def html_columns(section: Section) -> list[tuple[int, ColumnSpec]]:
    """Surviving (POSITIONAL index, spec) pairs for the HTML surface - drops all
    all_empty columns. The index maps back into each row's ``project_row`` cells
    (a row shorter than the union - syslog event - has no cell there → empty)."""
    cols = section_columns(section)
    return [(i, cols[i]) for i in _keep_indices(cols, html=True)]


# ── pdf orientation estimate (best-effort readability, NOT a correctness gate) ──
#
# The screen-only ``td.data`` nowrap is the CORRECTNESS guarantee: in
# paged media every cell wraps, so the pdf NEVER clips regardless of this estimate.
# This helper only chooses portrait vs landscape so a wide table wraps LESS - a
# mis-estimate yields a slightly-sub-optimal-but-lossless layout, never dropped data.
# The numbers are a character-based model (honest because data cells are
# ui-monospace); the two B-tests pin a wide IPv6 table → landscape and a realistic
# v4 beacon/scan table → portrait (the default-portrait MUST).

_PDF_PORTRAIT_CONTENT_PX = 680.0  # A4 portrait content box, 1.5cm margins, 96dpi
_PDF_MONO_CHAR_PX = 8.0  # ~14px ui-monospace advance (calibrated down from the 8.4
# starting estimate so a realistic v4 beacon/scan table stays portrait)
_PDF_COL_GUTTER_PX = 12.0  # the td right-padding per column
_PDF_SEV_PILL_PX = 40.0  # leftmost severity-pill column allowance


def _section_table_px(section: Section) -> float:
    """Estimated natural (unwrapped) width, in px, of one section rendered as a
    HTML findings table. Returns 0.0 for a wrap-by-design section that never forces
    table width: a section with no grid rows (aws ``ranked_summary``-only,
    no-timestamp syslog rows, or a projector-less detector) OR a single-bare-cell
    prose section. ``full_width`` rows are skipped from BOTH the column derivation
    (``section_columns``) AND this
    measurement loop, so a section that mixes grid rows with a ``full_width`` row
    can't over-measure (a structural guard, not a lean on the aws summary-xor-grid
    detector invariant). Measures over the section's OWN grid rows so the positional
    index maps into each ``project_row`` cell exactly as html renders it."""
    cols = section_columns(section)
    if not cols:
        return 0.0
    if len(cols) == 1 and cols[0].key is None:
        return 0.0
    rows = [
        r for r in (project_row(f) for f in section.findings)
        if not (r and r[0].full_width)
    ]
    total = _PDF_SEV_PILL_PX
    for idx, spec in html_columns(section):
        header = len(spec.key or "")
        widest = max((len(cells[idx].value) for cells in rows if idx < len(cells)), default=0)
        col_chars = max(header, widest)
        total += col_chars * _PDF_MONO_CHAR_PX + _PDF_COL_GUTTER_PX
    return total


def needs_landscape(renderables: list[tuple[str, DetectorRenderable]]) -> bool:
    """True iff the WIDEST per-detector table's estimated natural width exceeds the
    A4 portrait content box - the document then renders landscape so the wide table
    wraps less. PURE. Best-effort READABILITY, not a correctness gate (the
    screen-only ``td.data`` nowrap already guarantees the pdf never clips, in
    either orientation)."""
    widest = 0.0
    for _detector, renderable in renderables:
        for section in renderable.sections:
            widest = max(widest, _section_table_px(section))
    return widest > _PDF_PORTRAIT_CONTENT_PX
