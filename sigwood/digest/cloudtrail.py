"""cloudtrail summariser - orient-before-the-hunt for CloudTrail data.

Six fixed slots, two of which are scoped to the interactive lane only:

  - lane-split    - dist  - interactive vs service share of the WHOLE pile
                            (HEADLINE orient; renders first; never produces
                            an insight)
  - principal-vol - cliff - INTERACTIVE ONLY: largest share of interactive events
  - event-source  - cliff - busiest AWS service across the whole pile
  - source-ip     - share - INTERACTIVE ONLY: concentration of one source IP
                            against interactive total. NO population floor -
                            single-IP-dominates is the SIGNAL this slot was
                            introduced to surface, and that case inherently
                            has few distinct IPs. Gated at SHARE_GATE only.
  - region        - dist  - top-3 aws_region share across the whole pile
                            (always shows; never produces an insight)
  - error-rate    - rate  - fraction of events that errored
                            (error_code non-null); names the top error CODE

Lane scoping is the one structural wrinkle on this card. principal-vol and
source-ip read the interactive subset only; lane-split, event-source, region,
and error-rate read the whole frame. The aws detector takes the same
interactive-first discipline; we read aws.py for understanding but do NOT
import from it - same no-cross-import rail dns/syslog follow with their
detectors.

Cliff machinery is imported from conn so the cards cannot drift on gate /
floor / display-cap behaviour. Rate (and its RATE_FLOOR) and share (and its
SHARE_GATE) live in ``sigwood.digest._stats`` - the shared stats module
factored once three cards needed an identical rate (dns + syslog +
cloudtrail) and once a second statistic without a sibling needed its
canonical home.

Dist slots (lane-split, region) never contribute an insight - ambient
orientation, not a standout, same rule as dns's qtype-mix. On a quiet
account every gating slot stays non-speaking and vanishes from ``fields``;
the card carries only the two dist slots - that IS the honest digest of a
quiet pile.
"""

from __future__ import annotations

import pandas as pd

from sigwood.common.finding import DigestSlot
from sigwood.digest._stats import (
    RATE_FLOOR,
    SHARE_GATE,
    _rate,
    _share,
    _top_n_remainder_cell,
)
from sigwood.digest.conn import (
    CLIFF_DISPLAY_CAP,  # noqa: F401 - re-exported for downstream symmetry
    CLIFF_GATE,         # noqa: F401 - re-exported for downstream symmetry
    POPULATION_FLOOR,   # noqa: F401 - cliff slots in this card use it via _cliff
    _cliff,
    _format_ratio_cell,
    _format_ratio_lede,
)


# ── dist helpers - local, no shared base ────────────────────────────────────

def _lane_split_dist(lane_series: pd.Series | None) -> str:
    """Render the lane-split binary share for the lane-split dist slot.

    Two distinct fallbacks (consistency with dns.qtype-mix):
      - Missing column (lane_series is None) → "(no lane)" (schema-presence fact)
      - Empty / all-NaN series → "(no events)" (data-shape fact)
    Otherwise: ``"interactive N% / service M%"``. Any non-interactive label
    counts toward the service share - the parser's derivation is "default
    interactive, escalate to service when service-marked," and any unknown
    label is closer to service than to interactive.
    """
    if lane_series is None:
        return "(no lane)"
    labels = lane_series.dropna()
    if labels.empty:
        return "(no events)"
    total = int(len(labels))
    interactive_count = int((labels == "interactive").sum())
    service_count = total - interactive_count
    interactive_pct = int(round(interactive_count / total * 100))
    service_pct = int(round(service_count / total * 100))
    return f"interactive {interactive_pct}% / service {service_pct}%"


def _region_dist(region_series: pd.Series | None) -> str:
    """Render top-3 region share string for the region dist slot.

    Two distinct fallbacks (consistency with dns.qtype-mix):
      - Missing column (region_series is None) → "(no region)" (schema-presence fact)
      - Empty / all-NaN series → "(no events)" (data-shape fact)
    Single-region pile → "us-east-1 100%". Mix → top-3 joined by " · ".
    """
    if region_series is None:
        return "(no region)"
    labels = region_series.dropna().astype(str)
    if labels.empty:
        return "(no events)"
    counts = labels.value_counts()
    total = int(counts.sum())
    top_three = counts.head(3)
    parts = [
        f"{label} {int(round(count / total * 100))}%"
        for label, count in top_three.items()
    ]
    remainder = _top_n_remainder_cell(counts, total, 3)
    if remainder is not None:
        parts.append(remainder)
    return " · ".join(parts)


# ── Slot computers ──────────────────────────────────────────────────────────

def _slot_lane_split(frame: pd.DataFrame) -> DigestSlot:
    """lane-split - dist over the lane column; whole pile; always shows."""
    label = "lane-split"
    lane = frame["lane"] if "lane" in frame.columns else None
    rendered = _lane_split_dist(lane)
    return DigestSlot(label=label, statistic="dist", cells=[rendered])


def _slot_principal_vol(frame_interactive: pd.DataFrame) -> DigestSlot:
    """principal-vol - cliff over per-principal counts in the interactive lane.

    Share denominator is the interactive total, not the whole pile. On a
    pile with two ≈balanced interactive principals (population below
    POPULATION_FLOOR or rank1/rank2 ratio below CLIFF_GATE) this slot
    correctly DASHES - that is the spec.
    """
    label = "principal-vol"
    if frame_interactive.empty or "principal" not in frame_interactive.columns:
        return DigestSlot(label=label, statistic="cliff")
    counts = (
        frame_interactive["principal"]
        .value_counts(dropna=True)
        .sort_values(ascending=False)
    )
    result = _cliff(counts)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    entity, magnitude, ratio = result
    total = int(len(frame_interactive))
    share_pct = (magnitude / total * 100.0) if total > 0 else 0.0
    entity_str = str(entity)
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[entity_str, f"{share_pct:.0f}%", _format_ratio_cell(ratio)],
        entity=entity_str,
        magnitude=share_pct,
        ratio=ratio,
    )


def _slot_event_source(frame: pd.DataFrame) -> DigestSlot:
    """event-source - cliff over per-service counts across the whole pile."""
    label = "event-source"
    if frame.empty or "event_source" not in frame.columns:
        return DigestSlot(label=label, statistic="cliff")
    counts = frame["event_source"].value_counts(dropna=True).sort_values(ascending=False)
    result = _cliff(counts)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    entity, magnitude, ratio = result
    entity_str = str(entity)
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[entity_str, f"{int(magnitude)}", _format_ratio_cell(ratio)],
        entity=entity_str,
        magnitude=magnitude,
        ratio=ratio,
    )


def _slot_source_ip(frame_interactive: pd.DataFrame) -> DigestSlot:
    """source-ip - share of one source IP against the interactive total.

    Concentration-against-total, NOT rank-dominance. The question this slot
    asks is "is interactive traffic concentrated in one source," which is
    answered by share-of-total - not by a rank1/rank2 ratio. The case the
    slot exists to surface (a single attacker IP) inherently produces a
    low-cardinality distribution; using cliff's POPULATION_FLOOR=5 here
    would suppress exactly that signal. The share statistic has no
    population floor - a pile of one distinct IP at 100% speaks, two IPs
    with one at 99% speaks.

    Interactive-scoped because service-lane source_ip is frequently a
    service hostname (e.g. "s3.amazonaws.com"), not an IP - that string
    would dominate the whole-pile share and manufacture a meaningless
    "standout".

    Cell vs entity split: the table cell leads with "1 IP" to make the
    concentration legible at a glance; the entity field carries the actual
    address so the lede names it. Two cells, not three - there is no
    rank-2 ratio in a share statistic.
    """
    label = "source-ip"
    if frame_interactive.empty or "source_ip" not in frame_interactive.columns:
        return DigestSlot(label=label, statistic="share")
    counts = (
        frame_interactive["source_ip"]
        .value_counts(dropna=True)
        .sort_values(ascending=False)
    )
    total = int(len(frame_interactive))
    result = _share(counts, total)
    if result is None:
        return DigestSlot(label=label, statistic="share")
    entity, top_share = result
    share_pct = top_share * 100.0
    entity_str = str(entity)
    return DigestSlot(
        label=label,
        statistic="share",
        cells=["1 IP", f"{share_pct:.0f}% of interactive"],
        entity=entity_str,
        magnitude=share_pct,
    )


def _slot_region(frame: pd.DataFrame) -> DigestSlot:
    """region - dist over aws_region across the whole pile; always shows."""
    label = "region"
    regions = frame["aws_region"] if "aws_region" in frame.columns else None
    rendered = _region_dist(regions)
    return DigestSlot(label=label, statistic="dist", cells=[rendered])


def _slot_error_rate(frame: pd.DataFrame) -> DigestSlot:
    """error-rate - rate of events with non-null error_code; names top error code.

    Kind definition: ``error_code.notna()``. The parser emits None on
    success; a non-null string means the call errored. The top contributor
    is the most common errorCode value among errored events - NOT a
    principal.

    Literal notna() semantics: rows with None or NaN read as clean; rows
    with an empty string read as errored (the parser does not emit "" on
    success, so this is a no-op in practice but pinned by tests).
    """
    label = "error-rate"
    if frame.empty or "error_code" not in frame.columns:
        return DigestSlot(label=label, statistic="rate")
    kind_mask = frame["error_code"].notna()
    result = _rate(kind_mask, frame["error_code"])
    if result is None:
        return DigestSlot(label=label, statistic="rate")
    fraction, top = result
    pct = fraction * 100.0
    return DigestSlot(
        label=label,
        statistic="rate",
        cells=[f"{pct:.0f}%", top],
        entity=top,
        magnitude=pct,
    )


# ── Lede formatters ─────────────────────────────────────────────────────────

def _lede_principal_vol(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} drove {slot.magnitude:.0f}% of interactive events, "
        f"{_format_ratio_lede(slot.ratio)} the next principal."
    )


def _lede_event_source(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} accounted for {int(slot.magnitude)} events, "
        f"{_format_ratio_lede(slot.ratio)} the next service."
    )


def _lede_source_ip(slot: DigestSlot) -> str:
    # Share statistic - no rank-2 ratio, so no "Nx the next" clause.
    return (
        f"{slot.entity} is the source of {slot.magnitude:.0f}% of "
        f"interactive events."
    )


def _lede_error_rate(slot: DigestSlot) -> str:
    return (
        f"{slot.magnitude:.0f}% of events errored, "
        f"led by {slot.entity}."
    )


_INSIGHT_FORMATTERS = {
    "principal-vol": _lede_principal_vol,
    "event-source":  _lede_event_source,
    "source-ip":     _lede_source_ip,
    "error-rate":    _lede_error_rate,
}


# ── Zone 1 extras ───────────────────────────────────────────────────────────

def _zone1_extras(frame: pd.DataFrame) -> list[tuple[str, str]]:
    """Two lines, brief-pinned: distinct principals + distinct event sources."""
    if frame.empty:
        return [("principals", "0"), ("event sources", "0")]
    distinct_principals = (
        int(frame["principal"].nunique(dropna=True))
        if "principal" in frame.columns else 0
    )
    distinct_sources = (
        int(frame["event_source"].nunique(dropna=True))
        if "event_source" in frame.columns else 0
    )
    return [
        ("principals", str(distinct_principals)),
        ("event sources", str(distinct_sources)),
    ]


# ── Public entry point ─────────────────────────────────────────────────────

def summarize(frame: pd.DataFrame) -> dict:
    """Return the schema-specific body of a cloudtrail DigestCard.

    The interactive subset is derived once at the top so the two
    interactive-scoped slots (principal-vol, source-ip) see the same view
    of the data.
    """
    from sigwood.digest._stats import select_insights_and_fields

    if "lane" in frame.columns:
        frame_interactive = frame[frame["lane"] == "interactive"]
    else:
        frame_interactive = frame.iloc[0:0]
    slots = [
        _slot_lane_split(frame),
        _slot_principal_vol(frame_interactive),
        _slot_event_source(frame),
        _slot_source_ip(frame_interactive),
        _slot_region(frame),
        _slot_error_rate(frame),
    ]
    insights, fields = select_insights_and_fields(slots, _INSIGHT_FORMATTERS)
    return {
        "zone1_extras": _zone1_extras(frame),
        "insights": insights,
        "fields": fields,
    }
