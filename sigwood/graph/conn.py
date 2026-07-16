"""Connection-log graph builder."""

from __future__ import annotations

import math
from typing import Any

import pandas as pd

from sigwood.graph._core import _clean_label, build_payload, require_columns


def _clean_nonnegative(value: object) -> float:
    """Return one finite non-negative optional conn magnitude or zero."""
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if not math.isfinite(number) or number < 0:
        return 0.0
    return number


def _service_series(frame: pd.DataFrame) -> pd.Series:
    def _port_label(value: object) -> str:
        try:
            port = float(value)
        except (TypeError, ValueError, OverflowError):
            return "unknown"
        if not math.isfinite(port):
            return "unknown"
        rounded = round(port)
        if not 0 <= rounded <= 65_535:
            return "unknown"
        return str(rounded)

    port_label = frame["port"].map(_port_label)
    proto = frame["proto"].map(_clean_label).str.lower()
    service = port_label + "/" + proto
    return service.where(proto != "icmp", "icmp")


def build(
    frame: pd.DataFrame,
    *,
    config: dict[str, Any],
    source_label: str,
    default_window_note: str | None = None,
    display_utc: bool = False,
    trim_sparse_edges: bool = False,
) -> dict[str, Any]:
    """Build a conn graph from canonical spine and optional enrichment."""
    require_columns(frame, {"ts", "src", "dst"}, "conn")
    missing_service = not {"port", "proto"}.issubset(frame.columns)
    clean_bytes = (
        pd.Series(0.0, index=frame.index, dtype=float)
        if "bytes" not in frame.columns
        else frame["bytes"].map(_clean_nonnegative)
    )
    missing_bytes = not bool((clean_bytes > 0).any())
    clean_duration = (
        pd.Series(0.0, index=frame.index, dtype=float)
        if "duration" not in frame.columns
        else frame["duration"].map(_clean_nonnegative)
    )
    bands_active = bool(
        ((clean_bytes > 0) & (clean_duration > 0)).any()
    )
    service = (
        pd.Series("unknown", index=frame.index)
        if missing_service
        else _service_series(frame)
    )
    metric = (
        pd.Series(1, index=frame.index)
        if missing_bytes
        else clean_bytes
    )
    prepared_data = {
        "ts": frame["ts"],
        "src": frame["src"],
        "dst": frame["dst"],
        "svc": service,
        "metric": metric,
    }
    if bands_active:
        prepared_data["dur"] = clean_duration
    prepared = pd.DataFrame(prepared_data)
    return build_payload(
        prepared,
        kind="conn",
        source_label=source_label,
        config=config,
        default_window_note=default_window_note,
        trim_sparse_edges=trim_sparse_edges,
        meta={
            "kind": "conn",
            "single_metric": missing_bytes,
            "rows_label": "conn starts" if bands_active else "conns",
            "hosts_label": "hosts seen",
            "mid_label": "services",
            "mid_singular": "service",
            "metric_note": (
                "bytes drawn at a constant rate across each connection's recorded "
                "duration; connection counts stay at connection start"
                if bands_active else None
            ),
            "metric_note_with_straddlers": (
                "bytes drawn at a constant rate across each connection's recorded "
                "duration; connection counts stay at recorded starts; retained "
                "pre-window connections count at the window edge"
                if bands_active else None
            ),
            **({"bands_active": True} if bands_active else {}),
            "missing_bytes": missing_bytes,
            "trim_noun_singular": "connection",
            "trim_noun_plural": "connections",
            "display_utc": display_utc,
        },
    )
