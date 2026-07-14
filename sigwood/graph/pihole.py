"""Pi-hole disposition-spine graph builder."""

from __future__ import annotations

from typing import Any

import pandas as pd

from sigwood.common.errors import GraphEmpty
from sigwood.common.tld import roll_domain
from sigwood.graph._core import (
    _clean_label,
    _coerce_timestamp,
    build_payload,
    require_columns,
)


_DISPOSITIONS = {
    "gravity_blocked": "blocked",
    "regex_blocked": "blocked",
    "cached": "cached",
    "forwarded": "forwarded",
    "config": "local",
}


def _event_label(value: object) -> str:
    """Return a canonical parser event label without exposing malformed values."""
    return _clean_label(value).lower()


def _accepted_rows(frame: pd.DataFrame) -> pd.DataFrame:
    """Keep timestamped rows with a usable raw query identity."""
    rows = frame.copy()
    rows["_graph_ts"] = rows["ts"].map(_coerce_timestamp)
    rows["_raw_query"] = rows["query"].map(_clean_label)
    return rows[
        rows["_graph_ts"].notna()
        & rows["_raw_query"].ne("(unknown)")
    ].copy()


def _domain_shares(rows: pd.DataFrame, domain_level: str) -> pd.DataFrame:
    """Return each rolled domain's deduplicated disposition share vector."""
    dispositions = rows.assign(
        _disposition=rows["event_type"].map(_event_label).map(_DISPOSITIONS),
    ).dropna(subset=["_disposition"])
    if dispositions.empty:
        return pd.DataFrame(columns=["_domain", "svc", "metric"])

    dispositions = dispositions.assign(
        _second=dispositions["_graph_ts"].map(int),
    ).drop_duplicates(
        subset=["_raw_query", "_disposition", "_second"],
        keep="first",
    )
    dispositions["_domain"] = dispositions["_raw_query"].map(
        lambda value: roll_domain(value, domain_level),
    )
    counts = (
        dispositions.groupby(["_domain", "_disposition"], sort=False)
        .size()
        .rename("_count")
        .reset_index()
    )
    counts["metric"] = counts["_count"] / counts.groupby(
        "_domain", sort=False,
    )["_count"].transform("sum")
    return counts.rename(columns={"_disposition": "svc"})[
        ["_domain", "svc", "metric"]
    ]


def build(
    frame: pd.DataFrame,
    *,
    config: dict[str, Any],
    source_label: str,
    default_window_note: str | None = None,
    display_utc: bool = False,
    trim_sparse_edges: bool = False,
) -> dict[str, Any]:
    """Build a weighted-query Pi-hole graph from canonical dnsmasq rows."""
    require_columns(frame, {"ts", "src", "query", "event_type"}, "pihole")
    rows = _accepted_rows(frame)
    query_rows = rows.loc[
        rows["event_type"].map(_event_label).eq("query"),
        ["_graph_ts", "src", "_raw_query"],
    ].copy()
    if query_rows.empty:
        raise GraphEmpty("pihole", _clean_label(source_label), "no query rows")

    evidence_window = (
        float(rows["_graph_ts"].min()),
        float(rows["_graph_ts"].max()),
    )

    query_rows["_domain"] = query_rows["_raw_query"].map(
        lambda value: roll_domain(value, config["domain_level"]),
    )
    shares = _domain_shares(rows, config["domain_level"])
    attributed = query_rows.merge(shares, on="_domain", how="left", sort=False)
    attributed["svc"] = attributed["svc"].where(
        attributed["svc"].notna(), "(unattributed)",
    )
    attributed["metric"] = pd.to_numeric(
        attributed["metric"], errors="coerce",
    ).fillna(1.0)
    prepared = pd.DataFrame(
        {
            "ts": attributed["_graph_ts"],
            "src": attributed["src"],
            "dst": attributed["_domain"],
            "svc": attributed["svc"],
            "metric": attributed["metric"],
        }
    )
    return build_payload(
        prepared,
        kind="pihole",
        source_label=source_label,
        config=config,
        default_window_note=default_window_note,
        count_by="weight",
        row_count=len(query_rows),
        window=evidence_window,
        trim_sparse_edges=trim_sparse_edges,
        meta={
            "kind": "pihole",
            "single_metric": True,
            "rows_label": "queries",
            "hosts_label": "entities seen",
            "mid_label": "dispositions",
            "mid_singular": "disposition",
            "metric_note": "weighted by disposition share",
            "trim_noun_singular": "query",
            "trim_noun_plural": "queries",
            "display_utc": display_utc,
        },
    )
