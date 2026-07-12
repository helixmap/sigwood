"""DNS-log graph builder."""

from __future__ import annotations

import math
from typing import Any

import pandas as pd

from sigwood.common.errors import GraphEmpty
from sigwood.common.sanitize import strip_control
from sigwood.common.tld import roll_domain
from sigwood.graph._core import _clean_label, build_payload, require_columns


_QTYPE_MNEMONIC = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    257: "CAA",
}


def _qtype_labels(values: pd.Series) -> pd.Series:
    def _label(value: object) -> str:
        if value is None:
            return "unknown"
        try:
            missing = pd.isna(value)
            if getattr(missing, "ndim", 0) != 0:
                return "unknown"
            if bool(missing):
                return "unknown"
        except (TypeError, ValueError):
            return "unknown"
        try:
            numeric = float(value)
        except (TypeError, ValueError, OverflowError):
            return _clean_label(value)
        if math.isfinite(numeric) and numeric.is_integer():
            mnemonic = _QTYPE_MNEMONIC.get(int(numeric))
            if mnemonic is not None:
                return mnemonic
        return _clean_label(value)

    return values.map(_label)


def build(
    frame: pd.DataFrame,
    *,
    config: dict[str, Any],
    source_label: str,
    default_window_note: str | None = None,
    display_utc: bool = False,
) -> dict[str, Any]:
    """Build a single-metric DNS graph from canonical DNS columns."""
    require_columns(frame, {"ts", "src", "query"}, "dns")
    rows = frame.dropna(subset=["query"]).copy()
    if rows.empty:
        source = strip_control(source_label).strip() or "(unknown)"
        raise GraphEmpty("dns", source, "no query rows")
    if "resolver" in rows.columns and rows["resolver"].notna().any():
        service = rows["resolver"].map(_clean_label)
        mid_label, mid_singular = "resolvers", "resolver"
    elif "qtype" in rows.columns:
        service = _qtype_labels(rows["qtype"])
        mid_label, mid_singular = "qtypes", "qtype"
    else:
        service = pd.Series("dns", index=rows.index)
        mid_label, mid_singular = "qtypes", "qtype"
    prepared = pd.DataFrame(
        {
            "ts": rows["ts"],
            "src": rows["src"],
            "dst": rows["query"].map(
                lambda value: roll_domain(_clean_label(value), config["domain_level"])
            ),
            "svc": service,
            "metric": 1,
        }
    )
    return build_payload(
        prepared,
        kind="dns",
        source_label=source_label,
        config=config,
        default_window_note=default_window_note,
        meta={
            "kind": "dns",
            "single_metric": True,
            "rows_label": "queries",
            "hosts_label": "entities seen",
            "mid_label": mid_label,
            "mid_singular": mid_singular,
            "metric_note": f"domains rolled to {config['domain_level']}",
            "display_utc": display_utc,
        },
    )
