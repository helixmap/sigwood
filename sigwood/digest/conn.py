"""conn summariser - orient-before-the-hunt for Zeek conn data.

Reads a normalised conn frame (canonical columns ``src, dst, port, proto, ts,
bytes, conn_state, local_orig``) and returns the schema-specific body of a
DigestCard: ``zone1_extras`` (the ambient label/value block), ``insights``
(prose sentences mechanically derived from speaking gated slots), and
``fields`` (the display-ready, already-filtered speaking non-insight slots).

All four conn slots use the ``cliff`` statistic: rank1 / rank2 over the sorted
entity counts. A slot is non-speaking when the population is below
``POPULATION_FLOOR`` or when the ratio is below ``CLIFF_GATE``; non-speaking
slots are filtered out of ``fields`` by ``select_insights_and_fields`` and
never reach the renderer.

Internal/external classification is computed locally; the scan detector's
home_net is intentionally not imported.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import pandas as pd

from sigwood.common.finding import DigestSlot


# ── Calibration constants - provisional, tunable in one place ────────────────

CLIFF_GATE = 2.0
POPULATION_FLOOR = 5
# Display-only ceiling for rendered cliff ratios. Above this, "625000.0x" and
# "60x" tell the reader the same thing (one entity utterly dominates), so the
# extra magnitude is noise. We cap the RENDERED string at >50x / "more than
# 50x"; slot.ratio continues to carry the true float so lede sort ordering
# still respects the real value.
CLIFF_DISPLAY_CAP = 50.0

_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


# ── Internal/external classifier ─────────────────────────────────────────────

def _is_internal(ip: object) -> bool:
    """Return True iff ip is a string parsable as an RFC1918 address."""
    if not isinstance(ip, str) or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918_NETWORKS)


def _origin_internal_series(frame: pd.DataFrame) -> pd.Series:
    """Rule B per-row originator-is-internal classification.

    ``local_orig`` is the per-row signal when present (True → internal,
    False → external). When ``local_orig`` is missing or NaN, fall back to
    RFC1918 membership of ``src`` (Rule A applied to src).
    """
    src_internal = frame["src"].map(_is_internal)
    if "local_orig" not in frame.columns:
        return src_internal.astype(bool)
    local_orig = frame["local_orig"]
    resolved = local_orig.where(local_orig.notna(), src_internal)
    return resolved.astype(bool)


# ── Cliff ratio display formatting ───────────────────────────────────────────

def _format_ratio_cell(ratio: float) -> str:
    """Compact Zone-3 table cell. Caps at CLIFF_DISPLAY_CAP."""
    if ratio >= CLIFF_DISPLAY_CAP:
        return f">{int(CLIFF_DISPLAY_CAP)}x"
    return f"{ratio:.1f}x"


def _format_ratio_lede(ratio: float) -> str:
    """Prose Zone-2 lede fragment. Caps at CLIFF_DISPLAY_CAP.

    Returns just the comparator phrase (e.g. ``"3.7x"`` or
    ``"more than 50x"``); the surrounding "the next destination" / "its
    nearest peer" / etc. lives in the per-slot lede formatter.
    """
    if ratio >= CLIFF_DISPLAY_CAP:
        return f"more than {int(CLIFF_DISPLAY_CAP)}x"
    return f"{ratio:.1f}x"


# ── Cliff statistic ──────────────────────────────────────────────────────────

def _cliff(sorted_counts: pd.Series) -> tuple[Any, float, float] | None:
    """Evaluate the cliff slot over a descending series of entity magnitudes.

    Returns ``(rank1_entity, rank1_magnitude, ratio)`` when the slot speaks;
    None when it should dash. Dashes when population is below
    POPULATION_FLOOR, when rank2 is zero/NaN, or when the rank1/rank2 ratio
    is below CLIFF_GATE.
    """
    if len(sorted_counts) < POPULATION_FLOOR:
        return None
    rank1 = sorted_counts.iloc[0]
    rank2 = sorted_counts.iloc[1]
    if pd.isna(rank2) or rank2 == 0:
        return None
    ratio = float(rank1) / float(rank2)
    if ratio < CLIFF_GATE:
        return None
    return sorted_counts.index[0], float(rank1), ratio


# ── Slot computations ────────────────────────────────────────────────────────

def _slot_conn_share(frame: pd.DataFrame) -> DigestSlot:
    """conn-share: which host owns the largest share of connections.

    Host involvement = rows where host appears as src OR dst. Each row
    contributes to two hosts' counts (src and dst); a row with src == dst
    counts once for that host. "Share of connections" is endpoint
    involvement, not source-only.
    """
    label = "conn-share"
    if frame.empty:
        return DigestSlot(label=label, statistic="cliff")

    src_counts = frame["src"].value_counts(dropna=False)
    dst_counts = frame["dst"].value_counts(dropna=False)
    same = frame.loc[frame["src"] == frame["dst"], "src"].value_counts(dropna=False)
    involvement = src_counts.add(dst_counts, fill_value=0).sub(same, fill_value=0)
    involvement = involvement.sort_values(ascending=False)

    result = _cliff(involvement)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    entity, magnitude, ratio = result
    total_rows = len(frame)
    share_pct = (magnitude / total_rows * 100.0) if total_rows > 0 else 0.0
    entity_str = str(entity)
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[entity_str, f"{share_pct:.0f}%", _format_ratio_cell(ratio)],
        entity=entity_str,
        magnitude=share_pct,
        ratio=ratio,
    )


def _slot_densest_tuple(frame: pd.DataFrame) -> DigestSlot:
    """densest-tuple: the single busiest (src, dst, port) flow.

    Proto is intentionally not part of the key - the fill format is
    ``src->dst:port``.
    """
    label = "densest-tuple"
    if frame.empty:
        return DigestSlot(label=label, statistic="cliff")

    counts = (
        frame.groupby(["src", "dst", "port"], dropna=False)
        .size()
        .sort_values(ascending=False)
    )
    result = _cliff(counts)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    (src, dst, port), magnitude, ratio = result
    port_token = str(int(port)) if pd.notna(port) else "?"
    flow = f"{src} → {dst}:{port_token}"
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[flow, f"{int(magnitude)}", _format_ratio_cell(ratio)],
        entity=flow,
        magnitude=magnitude,
        ratio=ratio,
    )


def _slot_fan_out(frame: pd.DataFrame) -> DigestSlot:
    """fan-out: src:port reaching the most distinct destinations."""
    label = "fan-out"
    if frame.empty:
        return DigestSlot(label=label, statistic="cliff")

    distinct_dsts = (
        frame.groupby(["src", "port"], dropna=False)["dst"]
        .nunique()
        .sort_values(ascending=False)
    )
    result = _cliff(distinct_dsts)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    (src, port), magnitude, ratio = result
    port_token = str(int(port)) if pd.notna(port) else "?"
    src_port = f"{src}:{port_token}"
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[src_port, f"{int(magnitude)} dsts", _format_ratio_cell(ratio)],
        entity=src_port,
        magnitude=magnitude,
        ratio=ratio,
    )


def _slot_byte_direction(frame: pd.DataFrame) -> DigestSlot:
    """byte-direction: external dst receiving the largest share of outbound bytes.

    A row is outbound iff (Rule B src-internal) AND (Rule A dst-external);
    neither alone is sufficient. NaN/missing bytes count as 0.
    """
    label = "byte-direction"
    if frame.empty or "bytes" not in frame.columns:
        return DigestSlot(label=label, statistic="cliff")

    src_internal = _origin_internal_series(frame)
    dst_external = ~frame["dst"].map(_is_internal)
    outbound_mask = src_internal & dst_external
    if not outbound_mask.any():
        return DigestSlot(label=label, statistic="cliff")

    outbound = frame.loc[outbound_mask]
    bytes_filled = outbound["bytes"].fillna(0)
    per_dst_bytes = bytes_filled.groupby(outbound["dst"]).sum().sort_values(ascending=False)
    result = _cliff(per_dst_bytes)
    if result is None:
        return DigestSlot(label=label, statistic="cliff")
    dst, magnitude, ratio = result
    total_outbound = float(bytes_filled.sum())
    pct = (magnitude / total_outbound * 100.0) if total_outbound > 0 else 0.0
    entity = str(dst)
    return DigestSlot(
        label=label,
        statistic="cliff",
        cells=[entity, f"{pct:.0f}%", _format_ratio_cell(ratio)],
        entity=entity,
        magnitude=pct,
        ratio=ratio,
    )


# ── Zone-1 extras ────────────────────────────────────────────────────────────

def _format_bytes(n: float) -> str:
    """Format a byte count for the Zone-1 descriptive line."""
    if n < 1024:
        return f"{int(n)} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / (1024 ** 2):.1f} MB"
    if n < 1024 ** 4:
        return f"{n / (1024 ** 3):.1f} GB"
    return f"{n / (1024 ** 4):.1f} TB"


def _zone1_extras(frame: pd.DataFrame) -> list[tuple[str, str]]:
    """Return the ambient label/value rows the conn card prints.

    The four ambient pieces: host count, internal/external
    split, outbound bytes, inbound bytes. Host count and split share one
    rendered line (the split is the parenthetical of the count). Outbound and
    inbound bytes are two further lines.
    """
    if frame.empty:
        return [
            ("hosts", "0"),
            ("outbound bytes", _format_bytes(0)),
            ("inbound bytes", _format_bytes(0)),
        ]

    hosts: set[str] = set()
    for col in ("src", "dst"):
        for value in frame[col].dropna().tolist():
            if isinstance(value, str) and value:
                hosts.add(value)

    internal_count = sum(1 for h in hosts if _is_internal(h))
    external_count = len(hosts) - internal_count

    hosts_row = (
        "hosts",
        f"{len(hosts)} ({internal_count} internal, {external_count} external)",
    )

    # No `bytes` column → no byte data (NOT zero traffic). One honest row in place
    # of the two outbound/inbound rows; a PRESENT all-zero column stays `0 B`.
    if "bytes" not in frame.columns:
        return [hosts_row, ("bytes", "no byte data")]

    src_internal = _origin_internal_series(frame)
    src_external = ~src_internal
    dst_internal = frame["dst"].map(_is_internal)
    dst_external = ~dst_internal
    bytes_series = frame["bytes"].fillna(0)
    outbound_bytes = float(bytes_series[src_internal & dst_external].sum())
    inbound_bytes = float(bytes_series[src_external & dst_internal].sum())

    return [
        hosts_row,
        ("outbound bytes", _format_bytes(outbound_bytes)),
        ("inbound bytes", _format_bytes(inbound_bytes)),
    ]


# ── Lede formatters ──────────────────────────────────────────────────────────

def _lede_conn_share(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} is in {slot.magnitude:.0f}% of connections, "
        f"{_format_ratio_lede(slot.ratio)} its nearest peer."
    )


def _lede_densest_tuple(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} is the densest flow at {int(slot.magnitude)} connections, "
        f"{_format_ratio_lede(slot.ratio)} the next flow."
    )


def _lede_fan_out(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} reaches {int(slot.magnitude)} distinct destinations, "
        f"{_format_ratio_lede(slot.ratio)} the next-broadest source."
    )


def _lede_byte_direction(slot: DigestSlot) -> str:
    return (
        f"{slot.entity} receives {slot.magnitude:.0f}% of outbound bytes, "
        f"{_format_ratio_lede(slot.ratio)} the next destination."
    )


_INSIGHT_FORMATTERS = {
    "conn-share":     _lede_conn_share,
    "densest-tuple":  _lede_densest_tuple,
    "fan-out":        _lede_fan_out,
    "byte-direction": _lede_byte_direction,
}


# ── Public entry point ──────────────────────────────────────────────────────

def summarize(frame: pd.DataFrame) -> dict:
    """Return the schema-specific body of a conn DigestCard.

    Returned keys:
      zone1_extras - list[(label, value)] in render order
      insights     - list[str], 0..3 prose sentences
      fields       - list[DigestSlot] speaking-and-not-promoted, in declared order
    """
    from sigwood.digest._stats import select_insights_and_fields

    slots = [
        _slot_conn_share(frame),
        _slot_densest_tuple(frame),
        _slot_fan_out(frame),
        _slot_byte_direction(frame),
    ]
    insights, fields = select_insights_and_fields(slots, _INSIGHT_FORMATTERS)
    return {
        "zone1_extras": _zone1_extras(frame),
        "insights": insights,
        "fields": fields,
    }
