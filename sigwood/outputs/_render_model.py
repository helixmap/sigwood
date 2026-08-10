"""Shared render model for the reading surfaces (text · html · pdf).

The SINGLE owner of "what a finding renders": the per-detector pipeline
(``_build_renderable`` + ``Section`` + partitioners + the two exemptions +
the section-walking cap + pre-cap sidecars) AND the per-finding cell projection
(``project_row`` / ``section_columns``). text and html/pdf BOTH consume this so
they cannot drift.

PURE - no I/O, no ``detectors/`` imports. Imports ``common/`` and
``outputs/_evidence`` only.

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

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import gcd

from sigwood.common.display import (
    fmt_compact_span,
    fmt_syslog_timestamp,
    fmt_timestamp,
    human_bytes,
    plural,
)
from sigwood.common.finding import Finding, Severity


def fold_mix_names(mix: Iterable[object]) -> str:
    """Join first-seen program names after case-insensitive display deduplication."""
    names: list[str] = []
    seen: set[str] = set()
    for item in mix:
        # Evidence is an open dict; malformed mix entries are skipped, never raised.
        if not isinstance(item, (list, tuple)) or not item:
            continue
        rendered = str(item[0])
        key = rendered.casefold()
        if key in seen:
            continue
        seen.add(key)
        names.append(rendered)
    return ", ".join(names)


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
    """DNS: groups first, then singletons, then the synthetic dense-cluster scan
    summary in its own trailing section. Corroborated and promoted families lead
    before the benign-dominant singleton tier. Each
    speaks-iff-non-empty: an empty subsection vanishes entirely. The
    scan_summary finding is pulled out FIRST - it has no subdomain_count and must
    not land in the singleton branch."""
    scan = [f for f in findings if f.evidence.get("tier") == "scan_summary"]
    rest = [f for f in findings if f.evidence.get("tier") != "scan_summary"]
    singletons = [f for f in rest if "subdomain_count" not in f.evidence]
    groups = [f for f in rest if "subdomain_count" in f.evidence]
    out: list[Section] = []
    if groups:
        out.append(Section("groups", groups, len(groups)))
    if singletons:
        out.append(Section("singletons", singletons, len(singletons)))
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
    """Syslog: privileged MEDIUM, sieve LOW, then aggregate INFO.

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
    bursts = [
        f for f in findings
        if not f.evidence.get("privileged")
        and f.evidence.get("tier") in ("burst", "reboot", "transaction")
    ]
    out: list[Section] = []
    if privileged:
        out.append(Section("privileged", privileged, len(privileged)))
    if rare:
        out.append(Section("rare events", rare, len(rare)))
    if bursts:
        out.append(Section("bursts", bursts, len(bursts)))
    return out


_AUTH_SIGNAL_ORDER = {
    "concentration": 0,
    "source_volume": 1,
    "account_volume": 2,
    "host_spread": 3,
    "landing": 4,
}


def _partition_auth(findings: list[Finding]) -> list[Section]:
    """Auth: one urgency-first section with the reconciled signal order."""
    ordered = sorted(
        findings,
        key=lambda finding: (
            _AUTH_SIGNAL_ORDER.get(str(finding.evidence.get("signal", "")), 99),
            finding.title,
        ),
    )
    return [Section(None, ordered, len(ordered))]


def _partition_dnsblock(findings: list[Finding]) -> list[Section]:
    """dnsblock's frozen operator order, independent of detector emission order."""
    kinds: dict[str, list[Finding]] = {
        "arrival": [],
        "burst": [],
        "arrival_fold": [],
        "context": [],
        "other": [],
    }
    for finding in findings:
        kind = str(finding.evidence.get("kind", ""))
        if kind in ("prior_handling_exclusions", "recurring_activity"):
            kinds["context"].append(finding)
        elif kind in kinds:
            kinds[kind].append(finding)
        else:
            kinds["other"].append(finding)
    kinds["arrival"].sort(key=lambda f: (
        str(f.evidence.get("first_associated_period", "")),
        str(f.evidence.get("address", "")),
        str(f.evidence.get("family_key", "")),
    ))
    kinds["burst"].sort(key=lambda f: (
        -int(f.evidence.get("peak_count", 0)),
        str(f.evidence.get("peak_period_start", "")),
        str(f.evidence.get("address", "")),
        str(f.evidence.get("family_key", "")),
    ))
    kinds["arrival_fold"].sort(key=lambda f: (
        str(f.evidence.get("earliest_first_associated_period", "")),
        str(f.evidence.get("address", "")),
    ))
    context_order = {"prior_handling_exclusions": 0, "recurring_activity": 1}
    kinds["context"].sort(
        key=lambda f: context_order.get(str(f.evidence.get("kind", "")), 99)
    )
    out: list[Section] = []
    for key, label in (
        ("arrival", "first activity"),
        ("burst", "query bursts"),
        ("arrival_fold", "folded first activity"),
        ("context", "context"),
        ("other", "other"),
    ):
        if kinds[key]:
            out.append(Section(label, kinds[key], len(kinds[key])))
    return out


def _partition_flat(findings: list[Finding]) -> list[Section]:
    """Flat detector - one section with no label."""
    return [Section(None, findings, len(findings))]


_PARTITIONERS = {
    "dns": _partition_dns,
    "aws": _partition_aws,
    "syslog": _partition_syslog,
    "auth": _partition_auth,
    "dnsblock": _partition_dnsblock,
}

# Per-detector severity-sort opt-out. Severity sort is the
# right DEFAULT - within a flat or per-section list, H → M → L → I reads as
# urgency-first. But syslog's row order CARRIES meaning: the detector emits
# chronologically, and its three sections ("privileged" = MEDIUM, "rare events"
# = LOW, "bursts" = INFO bursts + reboots + transactions) are each single-severity
# - so severity-sort is a no-op anyway, and what matters is preserving ts-order
# WITHIN a section (a burst sits next to the reboot near it in time). Listing
# syslog here keeps that incoming order explicit.
_SEVERITY_SORT_EXEMPT: frozenset[str] = frozenset({"syslog", "dnsblock"})

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
    return (
        finding.evidence.get("tier") in _ALWAYS_SHOW_TIERS
        or (
            finding.detector == "dnsblock"
            and finding.evidence.get("kind")
            in ("prior_handling_exclusions", "recurring_activity")
        )
    )


def _build_renderable(
    detector: str,
    findings: list[Finding],
    verbose_level: int,
    max_per_detector: int,
) -> DetectorRenderable:
    """Run the render pipeline on one detector's findings.

    Order is binding:
      1. partition into Sections (detector-specific)
      2. capture pre-cap level_visible_total + severity_breakdown
      3. severity-sort each section in place
      4. cap walks sections in declared order; truncates findings; sets
         cap_truncated; later sections may end up with findings=[] and
         vanish at render time

    Both ``level_visible_total`` and ``severity_breakdown`` are captured
    BEFORE the cap so the group header NEVER drifts to post-cap counts -
    the pre-cap regression test in tests/test_text_output.py guards this.
    """
    visible = list(findings)
    if detector == "dnsblock" and verbose_level <= 0:
        has_entity = any(
            finding.evidence.get("kind") in ("arrival", "burst", "arrival_fold")
            for finding in findings
        )
        if not has_entity:
            visible = [
                finding for finding in visible
                if finding.evidence.get("kind") != "recurring_activity"
            ]

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
        progs = fold_mix_names(ev.get("program_mix", []))
        parts = [host]
        if ev.get("label") == "rebooted":
            parts.append("rebooted")
        parts.extend([
            f"{line_count} {plural(line_count, 'rare line')}",
            fmt_compact_span(timedelta(seconds=span)),
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
    if tier == "transaction":
        host = f.title
        label = str(ev.get("label", "transaction"))
        represented_line_count = int(ev.get("represented_line_count", 0))
        span = fmt_compact_span(
            timedelta(seconds=float(ev.get("span_seconds", 0.0)))
        )
        progs = fold_mix_names(ev.get("program_mix", [])) or "unknown"
        line = " · ".join([
            host,
            label,
            (
                f"{represented_line_count} "
                f"{plural(represented_line_count, 'rare line')}"
            ),
            span,
            f"mostly {progs}",
        ])
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
    first_seen = ev.get("first_seen")
    if ev.get("self_stamped") is False and first_seen is not None:
        return [
            Cell(
                "first",
                fmt_syslog_timestamp(datetime.fromisoformat(str(first_seen))),
            ),
            Cell(None, f.title),
        ]
    return [Cell(None, f.title, full_width=True)]


def _project_exfil(f: Finding) -> list[Cell]:
    ev = f.evidence
    count = int(ev.get("connection_count", 0))
    span = ev.get("span_seconds")
    span_col = "" if span is None else fmt_compact_span(timedelta(seconds=float(span)))
    destination_count = ev.get("destination_count")
    destination_col = (
        f"dsts={int(destination_count):,}"
        if ev.get("tier") == "destination_pool" and destination_count is not None
        else ""
    )
    return [
        Cell(None, ev.get("src", "")),
        Cell(None, "→"),
        Cell(None, ev.get("destination_network", ev.get("dst", ""))),
        Cell("dsts", destination_col, align="right", optional=True),
        Cell("out", f"out={human_bytes(float(ev.get('orig_bytes_total', 0)))}", align="right"),
        Cell("share", f"share={float(ev.get('orig_share', 0)):.4f}", align="right"),
        Cell("conns", f"conns={count:,}", align="right"),
        Cell("span", span_col, align="right", optional=True),
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


_AUTH_SHAPE_LABELS = {
    "concentration": "concentrated failures",
    "source_volume": "source volume",
    "account_volume": "account volume",
    "host_spread": "multi-host failures",
    "landing": "failures then success",
}


def _project_auth(f: Finding) -> list[Cell]:
    """Auth: one identity-safe row grammar for every reconciled signal."""
    ev = f.evidence
    signal = str(ev.get("signal", ""))
    shape = _AUTH_SHAPE_LABELS.get(signal, "authentication activity")
    if (
        f.severity is Severity.HIGH
        and ev.get("severity_basis") == ["host_spread", "landing"]
    ):
        shape = "multi-host failures + success"

    records = int(ev.get("decision_record_count", 0))
    failures = int(ev.get("denial_count", 0))
    hosts = int(ev.get("host_count", 0))
    landings = ev.get("landing_episodes")
    success_count = len(landings) if isinstance(landings, (list, tuple)) else 0
    overlaps = ev.get("overlaps")
    related_count = len(overlaps) if isinstance(overlaps, (list, tuple)) else 0
    span = max(0.0, float(ev.get("span_seconds", 0.0)))
    cells = [
        Cell(None, f.title),
        Cell("shape", shape),
        Cell(
            "failed",
            f"{failures:,} failed / {records:,} records",
            align="right",
        ),
        Cell("hosts", f"{hosts:,} {plural(hosts, 'host')}", align="right"),
        Cell(
            "successes",
            (
                f"{success_count:,} {plural(success_count, 'success', 'successes')}"
                if success_count
                else ""
            ),
            align="right",
            optional=True,
        ),
    ]
    cells.append(
        Cell("span", fmt_compact_span(timedelta(seconds=span)), align="right")
    )
    if related_count:
        cells.append(
            Cell(
                "related",
                f"{related_count:,} related",
                align="right",
                optional=True,
            )
        )
    return cells


def _dnsblock_time(value: object) -> str:
    try:
        return fmt_timestamp(datetime.fromisoformat(str(value)))
    except (TypeError, ValueError):
        return str(value or "")


def _half_integer(value: object) -> str:
    twice = int(value)
    return str(twice // 2) if twice % 2 == 0 else f"{twice // 2}.5"


def _closed_multiplier(peak: object, baseline_twice: object) -> str:
    numerator = 2 * int(peak)
    denominator = int(baseline_twice)
    if denominator == 0:
        return "multiplier unavailable"
    if numerator % denominator == 0:
        return f"{numerator // denominator}×"
    common = gcd(numerator, denominator)
    return f"{numerator // common}/{denominator // common}×"


def _project_dnsblock(f: Finding) -> list[Cell]:
    ev = f.evidence
    kind = ev.get("kind")
    if kind not in (
        "arrival",
        "burst",
        "arrival_fold",
        "prior_handling_exclusions",
        "recurring_activity",
    ):
        return [Cell(None, f.title, full_width=True)]
    if kind in ("prior_handling_exclusions", "recurring_activity"):
        return [Cell(None, f.title, full_width=True)]
    if kind == "arrival_fold":
        return [
            Cell(None, str(ev.get("address", f.title))),
            Cell("members", f"{int(ev.get('member_count', 0))} members", align="right"),
            Cell("first", _dnsblock_time(ev.get("earliest_first_associated_period"))),
        ]
    if kind == "burst":
        peak = int(ev.get("peak_count", 0))
        baseline_twice = int(ev.get("baseline_median_twice", 0))
        return [
            Cell(None, f.title),
            Cell("peak", f"peak={peak:,}", align="right"),
            Cell("median", f"median={_half_integer(baseline_twice)}", align="right"),
            Cell("multiple", _closed_multiplier(peak, baseline_twice), align="right"),
            Cell("periods", f"{int(ev.get('active_periods', 0))}/{int(ev.get('eligible_periods', 0))} periods", align="right"),
            Cell("queries", f"{int(ev.get('attributed_query_count', 0)):,} queries", align="right"),
        ]
    prior = (
        "≥100"
        if ev.get("prior_other_address_count_at_cap")
        else str(int(ev.get("prior_other_address_count", 0)))
    )
    return [
        Cell(None, f.title),
        Cell("names", f"{int(ev.get('qualifying_name_count', 0)):,} names", align="right"),
        Cell("queries", f"{int(ev.get('attributed_query_count', 0)):,} queries", align="right"),
        Cell("periods", f"{int(ev.get('active_periods', 0))}/{int(ev.get('eligible_periods', 0))} periods", align="right"),
        Cell("first", _dnsblock_time(ev.get("first_associated_period"))),
        Cell("prior", f"prior={prior}", align="right"),
    ]


_PROJECTORS = {
    "beacon": _project_beacon,
    "dns": _project_dns,
    "scan": _project_scan,
    "syslog": _project_syslog,
    "exfil": _project_exfil,
    "aws": _project_aws,
    "auth": _project_auth,
    "dnsblock": _project_dnsblock,
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
