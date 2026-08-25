"""The weird digest card - sonar over Zeek's own protocol-anomaly log.

`weird.log` is a categorical stream: Zeek names a condition its analyzers found
odd and records who was involved. The card reports the shape of that stream -
which names dominate, which hosts produce them, which analyzers raise them -
and reaches no verdict. A weird name is a fact about parsing, not a finding:
the same name that means something on one network is an ordinary artifact of
protocol-detection on another.

Card slots, in render order: name-volume (cliff), host-volume (cliff),
name-mix (dist), analyzer-mix (dist).
"""

from __future__ import annotations

import pandas as pd

from sigwood.common.finding import DigestSlot
from sigwood.common.sanitize import strip_control
from sigwood.digest._stats import _top_n_remainder_cell
from sigwood.digest.conn import (
    CLIFF_GATE,  # noqa: F401 - re-exported for downstream symmetry
    POPULATION_FLOOR,  # noqa: F401 - re-exported for downstream symmetry
    _cliff,
    _format_ratio_cell,
    _format_ratio_lede,
)

_DIST_TOP_N = 3
_NO_ANALYZER = "(no analyzer)"
_NO_NAMES = "(no names)"


def _clean(value: object) -> str:
    """Render one category, control-stripped and trimmed.

    Categories that render identically must COUNT together: without the strip
    two names differing only by a control byte would occupy two rows of the mix
    while looking like one.
    """
    return strip_control(str(value)).strip()


def _names(frame: pd.DataFrame) -> pd.Series:
    """The usable weird names - non-null and non-empty after cleaning."""
    if "name" not in frame.columns:
        return pd.Series(dtype=object)
    cleaned = frame["name"].dropna().map(_clean)
    return cleaned[cleaned != ""]


def _hosts(frame: pd.DataFrame) -> pd.Series:
    """The origin hosts that were recorded. Rows naming no host are EXCLUDED.

    A missing host is not a host entity, so counting it would put a phantom
    into a cliff whose whole question is which host dominates. Its prevalence
    is disclosed in the ambient block instead of vanishing.
    """
    if "src" not in frame.columns:
        return pd.Series(dtype=object)
    cleaned = frame["src"].dropna().map(_clean)
    return cleaned[cleaned != ""]


def _render_dist(counts: pd.Series, total: int, empty: str) -> str:
    """Top-N categories with their share of ``total``, in the card's grammar."""
    if counts.empty or total <= 0:
        return empty
    parts = [
        f"{name} {count / total * 100:.0f}%"
        for name, count in counts.head(_DIST_TOP_N).items()
    ]
    remainder = _top_n_remainder_cell(counts, total, _DIST_TOP_N)
    if remainder is not None:
        parts.append(remainder)
    return " · ".join(parts)


def _slot_name_volume(frame: pd.DataFrame) -> DigestSlot:
    """name-volume - does one weird name tower over the next?"""
    label = "name-volume"
    names = _names(frame)
    if names.empty:
        return DigestSlot(label=label, statistic="cliff")
    result = _cliff(names.value_counts())
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    entity, magnitude, ratio = result
    entity_str = str(entity)
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[entity_str, f"{int(magnitude)}", _format_ratio_cell(ratio)],
        entity=entity_str,
        magnitude=float(magnitude),
        ratio=ratio,
    )


def _slot_host_volume(frame: pd.DataFrame) -> DigestSlot:
    """host-volume - does one origin host tower over the next?

    The share is against rows that NAMED a host, not against every row: a
    percentage whose denominator included hostless rows would understate a
    host's dominance of the population the slot actually measures.
    """
    label = "host-volume"
    hosts = _hosts(frame)
    if hosts.empty:
        return DigestSlot(label=label, statistic="cliff")
    counts = hosts.value_counts()
    result = _cliff(counts)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    entity, magnitude, ratio = result
    named_rows = int(counts.sum())
    share_pct = (magnitude / named_rows * 100.0) if named_rows > 0 else 0.0
    entity_str = str(entity)
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[entity_str, f"{share_pct:.0f}%", _format_ratio_cell(ratio)],
        entity=entity_str,
        magnitude=share_pct,
        ratio=ratio,
    )


def _slot_name_mix(frame: pd.DataFrame) -> DigestSlot:
    """name-mix - the shape of the name distribution; always shows.

    The denominator is rows carrying a usable name. A nameless weird row is
    malformed rather than a kind of weird, so it is not given a category - the
    deliberate difference from analyzer-mix below.
    """
    names = _names(frame)
    counts = names.value_counts()
    return DigestSlot(
        label="name-mix",
        statistic="dist",
        cells=[_render_dist(counts, int(counts.sum()), _NO_NAMES)],
    )


def _slot_analyzer_mix(frame: pd.DataFrame) -> DigestSlot:
    """analyzer-mix - which Zeek analyzers raise these; always shows.

    The denominator is EVERY row, and a missing analyzer becomes its own
    category. An event raised outside a protocol analyzer is an ordinary and
    common kind of weird, so dropping those rows would let the remainder
    misrepresent the mix.
    """
    label = "analyzer-mix"
    if frame.empty:
        return DigestSlot(label=label, statistic="dist", cells=[_NO_ANALYZER])
    if "source" in frame.columns:
        rendered = frame["source"].map(
            lambda v: _clean(v) if pd.notna(v) else ""
        )
        rendered = rendered.map(lambda v: v if v else _NO_ANALYZER)
    else:
        rendered = pd.Series([_NO_ANALYZER] * len(frame), index=frame.index)
    counts = rendered.value_counts()
    return DigestSlot(
        label=label,
        statistic="dist",
        cells=[_render_dist(counts, int(counts.sum()), _NO_ANALYZER)],
    )


def _zone1_extras(frame: pd.DataFrame) -> list[tuple[str, str]]:
    """The ambient rows: distinct names, distinct hosts, and the hostless count.

    The hostless row is OMITTED at zero (vanish-don't-dash) and present
    otherwise, so the host measurement's population is visible without a
    permanently empty line.
    """
    names = _names(frame)
    hosts = _hosts(frame)
    extras = [
        ("names", f"{names.nunique():,}"),
        ("hosts", f"{hosts.nunique():,}"),
    ]
    without_host = len(frame) - len(hosts)
    if without_host > 0:
        extras.append(("rows without origin host", f"{without_host:,}"))
    return extras


def _lede_name_volume(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} is the most frequent weird at {int(slot.magnitude)} "
        f"events, {_format_ratio_lede(slot.ratio)} the next name."
    )


def _lede_host_volume(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} raises {slot.magnitude:.0f}% of the events that name a "
        f"host, {_format_ratio_lede(slot.ratio)} its nearest peer."
    )


_INSIGHT_FORMATTERS = {
    "name-volume": _lede_name_volume,
    "host-volume": _lede_host_volume,
}


def summarize(frame: pd.DataFrame) -> dict:
    """Return the schema-specific body of a weird DigestCard.

    Returned keys:
      zone1_extras - list[(label, value)] in render order
      insights     - list[str], 0..2 prose sentences
      fields       - list[DigestSlot] speaking-and-not-promoted, in declared order
    """
    from sigwood.digest._stats import select_insights_and_fields

    slots = [
        _slot_name_volume(frame),
        _slot_host_volume(frame),
        _slot_name_mix(frame),
        _slot_analyzer_mix(frame),
    ]
    insights, fields = select_insights_and_fields(slots, _INSIGHT_FORMATTERS)
    return {
        "zone1_extras": _zone1_extras(frame),
        "insights": insights,
        "fields": fields,
    }
