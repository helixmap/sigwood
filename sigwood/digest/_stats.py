"""Shared digest stats - the home for primitives that more than one card needs.

Hosts:
  - ``_rate``  / ``RATE_FLOOR``  - fraction-of-events-matching-a-kind statistic
                                   with top-contributor attribution
  - ``_share`` / ``SHARE_GATE``  - concentration-against-total statistic with no
                                   population floor
  - ``_top_n_remainder_cell``     - disclosure for positive mass hidden by a
                                   truncated categorical distribution
  - ``select_insights_and_fields`` - shared selection helper that promotes the
                                     top-N speaking gated slots to insights and
                                     returns the leftover slots as fields

Cliff machinery (``_cliff``, ``CLIFF_GATE``, ``CLIFF_DISPLAY_CAP``,
``POPULATION_FLOOR``, ``_format_ratio_cell``, ``_format_ratio_lede``) lives in
``sigwood.digest.conn`` and stays there - that is the established shared
origin and every card already imports cliff helpers from it.

The trigger for factoring into this module is "three identical real uses"
(``_rate``, now imported by dns + syslog + cloudtrail) or "shared by the new
statistic by design" (``_share`` introduced by the cloudtrail source-ip slot
and reusable by any future concentration-against-total slot). Tail
(``_tail`` / ``TAIL_GATE``) stays local to dns.py - one-use primitives do not
belong here yet.
"""

from __future__ import annotations

from typing import Any, Callable

import pandas as pd

from sigwood.common.finding import DigestSlot
from sigwood.digest.conn import POPULATION_FLOOR


# ── Calibration constants ───────────────────────────────────────────────────

RATE_FLOOR = 0.01    # fraction below this → rate slots dash. Pure presence
                     # floor, NOT a badness threshold - meaning is the same on
                     # every network. Calibratable here.

SHARE_GATE = 0.80    # top-share at or above this → share slots speak. The
                     # share statistic exists to surface concentration; this
                     # gate is the concentration threshold. There is no
                     # paired population floor - see ``_share`` below.


# ── Rate statistic ──────────────────────────────────────────────────────────
#
# Behavior must NOT change from the previous in-card definitions - that is the
# proof-of-correctness for the factoring. Identical body to the three card
# copies it replaces.

def _rate(kind_mask: pd.Series, contributor_series: pd.Series) -> tuple | None:
    """Rate statistic: what fraction of events are of a notable kind?

    Returns ``(fraction, top_contributor)`` when speaking, None when dashed.
    Dashes when total < POPULATION_FLOOR or fraction < RATE_FLOOR. The floor
    is a pure presence bar - meaning the same on every network, never a
    badness judgment.
    """
    total = len(kind_mask)
    if total < POPULATION_FLOOR:
        return None
    kind_count = int(kind_mask.sum())
    if kind_count == 0:
        return None
    fraction = kind_count / total
    if fraction < RATE_FLOOR:
        return None
    matching = contributor_series[kind_mask].dropna()
    if matching.empty:
        return None
    top = matching.value_counts().idxmax()
    return fraction, str(top)


# ── Share statistic ─────────────────────────────────────────────────────────

def _share(sorted_counts: pd.Series, total: int) -> tuple[Any, float] | None:
    """Share statistic: is one entity's count a dominant fraction of the total?

    Returns ``(rank1_entity, top_share)`` when speaking, None when dashed.
    Dashes only when ``top_share < SHARE_GATE`` - there is NO population
    floor. The slot using this statistic exists to surface concentration
    against the total, and low entity cardinality is the SIGNAL, not noise:
    a pile of ONE distinct value at 100% MUST speak (top_share == 1.0); two
    distinct entities with one at 99% MUST speak. Adding a population floor
    here would suppress the exact attack shape the share slot was introduced
    to catch.

    ``sorted_counts`` must be descending; the caller's value_counts output is
    already that shape. ``total`` is the caller-supplied denominator - for
    source-ip in cloudtrail that is the interactive-event count, NOT a
    derived sum, so the share is measured against the lane the caller meant.

    Defensive returns:
      - empty series or non-positive total → None
      - NaN rank1 → None
    """
    if total <= 0 or len(sorted_counts) == 0:
        return None
    rank1 = sorted_counts.iloc[0]
    if pd.isna(rank1):
        return None
    top_share = float(rank1) / float(total)
    if top_share < SHARE_GATE:
        return None
    return sorted_counts.index[0], top_share


def _top_n_remainder_cell(
    sorted_counts: pd.Series,
    total: int,
    top_n: int,
) -> str | None:
    """Render the positive share withheld by a top-N distribution.

    The caller owns category labels and named-cell formatting. This helper owns
    only the shared fact: no hidden positive count means no cell; a share that
    rounds below one percent remains visible as ``(other) <1%``.
    """
    if total <= 0 or top_n < 0 or len(sorted_counts) <= top_n:
        return None
    shown = int(sorted_counts.head(top_n).sum())
    hidden = total - shown
    if hidden <= 0:
        return None
    percent = hidden / total * 100
    rounded = int(round(percent))
    if rounded < 1:
        return "(other) <1%"
    return f"(other) {rounded}%"


# ── Insight selection ───────────────────────────────────────────────────────
#
# Shared by all four schema summarisers. Identical mechanic across cards:
# filter speaking gated slots, sort by per-statistic salience, take top-3,
# format via the per-card formatter map → those become insights. Everything
# else with cells goes to fields. A promoted slot is suppressed from fields.

_INSIGHT_TOP_N = 3
_GATING_STATISTICS = frozenset({"cliff", "tail", "rate", "share"})


def _salience(slot: DigestSlot) -> float:
    """Per-statistic salience on one comparable scale.

    cliff/tail use the rank-ratio directly. rate slots are stored with the
    percentage as magnitude (e.g. 1.0 for 1%), so dividing by
    ``RATE_FLOOR * 100`` puts a rate slot's salience on the same scale as a
    cliff ratio (1% over a 1% floor scores 1.0, comparable to a 1x cliff).
    share is stored as percentage 0-100; a heavily concentrated single
    source IS one of the most salient things on a card, so its raw
    percentage ranks above typical cliff ratios.
    """
    if slot.statistic in {"cliff", "tail"}:
        return slot.ratio or 0.0
    if slot.statistic == "rate":
        return (slot.magnitude or 0.0) / (RATE_FLOOR * 100.0)
    if slot.statistic == "share":
        return slot.magnitude or 0.0
    return 0.0


def select_insights_and_fields(
    slots: list[DigestSlot],
    formatters: dict[str, Callable[[DigestSlot], str]],
) -> tuple[list[str], list[DigestSlot]]:
    """Promote speaking gated slots to insights; return leftover speaking
    slots as fields.

    Suppression rule: a slot is removed from
    ``fields`` ONLY when it actually produced an insight - i.e. it was in
    the top-N speaking gated set AND its label had a formatter that ran.
    A gating slot whose label has no formatter falls through to fields
    instead of vanishing, preserving "each fact appears exactly once."

    Dist slots (statistic not in the gating set) never produce insights;
    they pass straight through to fields if they have cells.
    Non-speaking slots (cells is None) are omitted from both insights
    and fields.

    Slot labels are unique within a card, so label-based suppression is
    safe - no ``id()`` ceremony.
    """
    speaking_gated = [
        s for s in slots
        if s.cells is not None and s.statistic in _GATING_STATISTICS
    ]
    speaking_gated.sort(key=_salience, reverse=True)

    promoted_labels: set[str] = set()
    insights: list[str] = []
    for s in speaking_gated[:_INSIGHT_TOP_N]:
        fmt = formatters.get(s.label)
        if fmt is None:
            continue
        insights.append(fmt(s))
        promoted_labels.add(s.label)

    fields = [
        s for s in slots
        if s.cells is not None and s.label not in promoted_labels
    ]
    return insights, fields
