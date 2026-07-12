"""Connection-log graph builder."""

from __future__ import annotations

import math
from typing import Any

import pandas as pd

from sigwood.graph._core import _clean_label, build_payload, require_columns


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
) -> dict[str, Any]:
    """Build a dual-metric conn graph from canonical conn columns."""
    require_columns(frame, {"ts", "src", "dst", "port", "proto", "bytes"}, "conn")
    prepared = pd.DataFrame(
        {
            "ts": frame["ts"],
            "src": frame["src"],
            "dst": frame["dst"],
            "svc": _service_series(frame),
            "metric": frame["bytes"],
        }
    )
    return build_payload(
        prepared,
        kind="conn",
        source_label=source_label,
        config=config,
        default_window_note=default_window_note,
        meta={
            "kind": "conn",
            "single_metric": False,
            "rows_label": "conns",
            "hosts_label": "hosts seen",
            "mid_label": "services",
            "mid_singular": "service",
            "metric_note": "orig bytes",
            "display_utc": display_utc,
        },
    )
