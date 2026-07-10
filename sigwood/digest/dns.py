"""dns summariser - orient-before-the-hunt for DNS data.

The first fidelity-aware digest card: a slot set that depends on which DNS
feed was loaded. Four slots are shared (cliff/cliff/tail/dist over columns
present on both feeds); two are feed-specific:

  - nxdomain-rate (rcode-based) - Zeek only; non-speaking on Pi-hole
  - block-rate (event_type-based) - Pi-hole only; non-speaking on Zeek

A feed-uncomputable slot returns a non-speaking ``DigestSlot`` (cells=None);
``select_insights_and_fields`` filters it out of ``fields`` and the slot
simply vanishes from the rendered card. No ABSENT marker, no footer text.

Cliff machinery imported from conn so the two cards cannot drift on gate /
floor / display-cap behaviour. The rate statistic - and its RATE_FLOOR
constant - live in ``sigwood.digest._stats`` (factored once three cards
needed an identical copy: this one, syslog, and cloudtrail). Two more
statistics computed locally:

  - tail: max/median ratio over a distribution, with an owner attribution
  - dist: top-3 share-of-mix; orientation only, never produces an insight

A row is "blocked" on Pi-hole iff event_type ∈ {gravity_blocked,
regex_blocked} - digest computes this locally; the detector is not imported.
"""

from __future__ import annotations

import pandas as pd

from sigwood.common.finding import DigestSlot
from sigwood.digest._stats import RATE_FLOOR, _rate
from sigwood.digest.conn import (
    CLIFF_DISPLAY_CAP,  # noqa: F401 - re-exported for downstream symmetry
    CLIFF_GATE,         # noqa: F401 - re-exported for downstream symmetry
    POPULATION_FLOOR,
    _cliff,
    _format_ratio_cell,
    _format_ratio_lede,
)


# ── Calibration constants - provisional, tunable in one place ───────────────

TAIL_GATE = 3.0       # max/median ratio below this → query-length is non-speaking

# Zeek emits qtype as a numeric type code; map the common ones to mnemonics
# for display. Unmapped codes render as "TYPE<n>" so an analyst still has a
# breadcrumb to look up.
_ZEEK_QTYPE_MNEMONICS = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 257: "CAA",
}

_BLOCK_EVENT_TYPES = frozenset({"gravity_blocked", "regex_blocked"})


# ── tail statistic ──────────────────────────────────────────────────────────

def _tail(values: pd.Series, owner_series: pd.Series) -> tuple | None:
    """Tail statistic: is the extreme far from the body of the distribution?

    Returns ``(max_val, ratio, owner)`` when speaking, None when dashed.
    Dashes when population < POPULATION_FLOOR, median is 0/NaN, or
    max/median is below TAIL_GATE.

    ``values`` and ``owner_series`` must share an index - the owner of the
    max is looked up by that index.
    """
    cleaned = values.dropna()
    if len(cleaned) < POPULATION_FLOOR:
        return None
    median = cleaned.median()
    if pd.isna(median) or median == 0:
        return None
    max_val = cleaned.max()
    if pd.isna(max_val) or max_val == 0:
        return None
    ratio = float(max_val) / float(median)
    if ratio < TAIL_GATE:
        return None
    max_idx = cleaned.idxmax()
    try:
        owner = owner_series.loc[max_idx]
    except (KeyError, ValueError):
        return None
    if pd.isna(owner):
        return None
    return int(max_val), ratio, str(owner)


# ── dist statistic - qtype-mix, always shows ────────────────────────────────

def _qtype_label(value: object, feed: str) -> str | None:
    """Map a single qtype value to a display string.

    Zeek: numeric code → mnemonic from _ZEEK_QTYPE_MNEMONICS; unmapped
    integers → ``"TYPE<n>"``. Pi-hole: already a string mnemonic; used
    as-is. NaN / unparseable → None (caller filters).
    """
    if pd.isna(value):
        return None
    if feed == "pihole":
        s = str(value).strip()
        return s if s else None
    try:
        code = int(value)
    except (TypeError, ValueError):
        s = str(value).strip()
        return s if s else None
    return _ZEEK_QTYPE_MNEMONICS.get(code, f"TYPE{code}")


def _qtype_dist(qtypes: pd.Series | None, feed: str) -> str:
    """Render top-3 qtype share string for the qtype-mix dist slot.

    Two distinct fallbacks:
      - Missing column (qtypes is None) → "(no qtype)" (schema-presence fact)
      - Empty / all-NaN series → "(no queries)" (data-shape fact)
    Single-type pile → "A 100%". Mix → "A 82% · AAAA 11% · HTTPS 4%".
    """
    if qtypes is None:
        return "(no qtype)"
    labels = qtypes.map(lambda v: _qtype_label(v, feed)).dropna()
    if labels.empty:
        return "(no queries)"
    counts = labels.value_counts()
    total = int(counts.sum())
    top_three = counts.head(3)
    parts = [
        f"{label} {int(round(count / total * 100))}%"
        for label, count in top_three.items()
    ]
    return " · ".join(parts)


# ── Slot computers ──────────────────────────────────────────────────────────

def _slot_client_volume(frame: pd.DataFrame) -> DigestSlot:
    """client-volume - cliff over per-src query counts."""
    label = "client-volume"
    if frame.empty or "src" not in frame.columns:
        return DigestSlot(label=label, statistic="cliff")
    counts = frame["src"].value_counts(dropna=True).sort_values(ascending=False)
    result = _cliff(counts)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    entity, magnitude, ratio = result
    total = len(frame)
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


def _slot_domain_volume(frame: pd.DataFrame) -> DigestSlot:
    """domain-volume - cliff over per-query counts."""
    label = "domain-volume"
    if frame.empty or "query" not in frame.columns:
        return DigestSlot(label=label, statistic="cliff")
    counts = frame["query"].value_counts(dropna=True).sort_values(ascending=False)
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


def _slot_query_length(frame: pd.DataFrame) -> DigestSlot:
    """query-length - tail over query character lengths; names the owner.

    Cell order per brief: ``[maxlen, ratio, owner]``. The lede leads with
    the owner, but the table row leads with the magnitude (length of
    longest query) first.
    """
    label = "query-length"
    if frame.empty or "query" not in frame.columns or "src" not in frame.columns:
        return DigestSlot(label=label, statistic="tail")
    queries = frame["query"].dropna().astype(str)
    if queries.empty:
        return DigestSlot(label=label, statistic="tail")
    lengths = queries.str.len()
    src_aligned = frame.loc[queries.index, "src"]
    result = _tail(lengths, src_aligned)
    if result is None:
        return DigestSlot(label=label, statistic="tail")
    max_val, ratio, owner = result
    return DigestSlot(
        label=label,
        statistic="tail",
        cells=[f"{max_val} chars", _format_ratio_cell(ratio), owner],
        entity=owner,
        magnitude=float(max_val),
        ratio=ratio,
    )


def _slot_qtype_mix(frame: pd.DataFrame, feed: str) -> DigestSlot:
    """qtype-mix - dist over query types; always shows."""
    label = "qtype-mix"
    qtypes = frame["qtype"] if "qtype" in frame.columns else None
    rendered = _qtype_dist(qtypes, feed)
    return DigestSlot(label=label, statistic="dist", cells=[rendered])


def _slot_nxdomain_rate(frame: pd.DataFrame, feed: str) -> DigestSlot:
    """nxdomain-rate - rate of NXDOMAIN (rcode == 3). Zeek only.

    Non-Zeek feeds return a non-speaking slot - the summariser filters those
    out, so the slot vanishes from the card entirely on Pi-hole.
    """
    label = "nxdomain-rate"
    if feed != "zeek":
        return DigestSlot(label=label, statistic="rate")
    if frame.empty or "rcode" not in frame.columns or "src" not in frame.columns:
        return DigestSlot(label=label, statistic="rate")
    kind_mask = (frame["rcode"] == 3).fillna(False).astype(bool)
    result = _rate(kind_mask, frame["src"])
    if result is None:
        return DigestSlot(label=label, statistic="rate")
    fraction, top = result
    pct = fraction * 100.0
    return DigestSlot(
        label=label,
        statistic="rate",
        cells=[f"{pct:.0f}% failed", top],
        entity=top,
        magnitude=pct,
    )


def _slot_block_rate(frame: pd.DataFrame, feed: str) -> DigestSlot:
    """block-rate - rate of blocked queries (gravity_blocked / regex_blocked).
    Pi-hole only. Block-status derivation is local; the detector is not
    imported.

    Non-Pi-hole feeds return a non-speaking slot - the summariser filters
    those out, so the slot vanishes from the card entirely on Zeek.
    """
    label = "block-rate"
    if feed != "pihole":
        return DigestSlot(label=label, statistic="rate")
    if frame.empty or "event_type" not in frame.columns or "query" not in frame.columns:
        return DigestSlot(label=label, statistic="rate")
    kind_mask = frame["event_type"].isin(_BLOCK_EVENT_TYPES).fillna(False).astype(bool)
    result = _rate(kind_mask, frame["query"])
    if result is None:
        return DigestSlot(label=label, statistic="rate")
    fraction, top = result
    pct = fraction * 100.0
    return DigestSlot(
        label=label,
        statistic="rate",
        cells=[f"{pct:.0f}% blocked", top],
        entity=top,
        magnitude=pct,
    )


# ── Lede formatters ─────────────────────────────────────────────────────────

def _lede_client_volume(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} issued {slot.magnitude:.0f}% of queries, "
        f"{_format_ratio_lede(slot.ratio)} its nearest peer."
    )


def _lede_domain_volume(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} was queried {int(slot.magnitude)} times, "
        f"{_format_ratio_lede(slot.ratio)} the next domain."
    )


def _lede_query_length(slot: DigestSlot) -> str:
    # Lede leads with owner (entity); cell order leads with maxlen.
    return (
        f"{slot.entity} issued a {int(slot.magnitude)}-character query, "
        f"{_format_ratio_lede(slot.ratio)} the median length."
    )


def _lede_nxdomain_rate(slot: DigestSlot) -> str:
    return (
        f"{slot.magnitude:.0f}% of queries failed with NXDOMAIN, "
        f"led by {slot.entity}."
    )


def _lede_block_rate(slot: DigestSlot) -> str:
    return (
        f"{slot.magnitude:.0f}% of queries were blocked, "
        f"led by {slot.entity}."
    )


_INSIGHT_FORMATTERS = {
    "client-volume":  _lede_client_volume,
    "domain-volume":  _lede_domain_volume,
    "query-length":   _lede_query_length,
    "nxdomain-rate":  _lede_nxdomain_rate,
    "block-rate":     _lede_block_rate,
}


# ── Zone 1 extras ───────────────────────────────────────────────────────────

def _zone1_extras(frame: pd.DataFrame) -> list[tuple[str, str]]:
    """Two lines, brief-pinned: distinct clients + distinct domains."""
    if frame.empty:
        return [("clients", "0"), ("domains", "0")]
    distinct_clients = (
        int(frame["src"].nunique(dropna=True)) if "src" in frame.columns else 0
    )
    distinct_domains = (
        int(frame["query"].nunique(dropna=True)) if "query" in frame.columns else 0
    )
    return [
        ("clients", str(distinct_clients)),
        ("domains", str(distinct_domains)),
    ]


# ── Public entry point ──────────────────────────────────────────────────────

def summarize(frame: pd.DataFrame, feed: str) -> dict:
    """Return the schema-specific body of a dns DigestCard.

    ``feed`` is ``"zeek"`` or ``"pihole"`` - selects which feed-specific
    slots populate vs. return a non-speaking slot (which the summariser
    then filters out of ``fields``). The four shared slots populate (or
    stay non-speaking) the same way on both feeds.
    """
    from sigwood.digest._stats import select_insights_and_fields

    slots = [
        _slot_client_volume(frame),
        _slot_domain_volume(frame),
        _slot_query_length(frame),
        _slot_qtype_mix(frame, feed),
        _slot_nxdomain_rate(frame, feed),
        _slot_block_rate(frame, feed),
    ]
    insights, fields = select_insights_and_fields(slots, _INSIGHT_FORMATTERS)
    return {
        "zone1_extras": _zone1_extras(frame),
        "insights": insights,
        "fields": fields,
    }
