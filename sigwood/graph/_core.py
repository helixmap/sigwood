"""Shared graph payload construction and graph tuning validation."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd

from sigwood import __version__
from sigwood.common.errors import GraphEmpty
from sigwood.common.sanitize import strip_control


GRAPH_MAX_FLOWS = 4_000
GRAPH_MAX_SMOOTH_OPS = 400_000_000
GRAPH_MAX_PAYLOAD_PAIRS = 1_500_000

_NICE_BIN_SECONDS = (
    1, 5, 10, 30, 60, 300, 900, 1_800, 3_600, 7_200, 21_600,
    43_200, 86_400, 604_800,
)
_OTHER = "(other)"
_FLOAT32_MAX = float(np.finfo(np.float32).max)


def validate_config(cfg: object) -> dict[str, Any]:
    """Validate and normalize the graph-only configuration table."""
    if not isinstance(cfg, dict):
        raise ValueError("[graph] must be a table")

    defaults = {
        "target_bins": 2000,
        "top_hosts": 24,
        "top_services": 12,
        "domain_level": "domain",
    }
    out = dict(defaults)
    out.update(cfg)
    for key, upper in (
        ("target_bins", 20_000),
        ("top_hosts", 500),
        ("top_services", 500),
    ):
        value = out[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= upper:
            raise ValueError(
                f"[graph].{key} must be an integer from 1 to {upper}"
            )
    if (
        not isinstance(out["domain_level"], str)
        or out["domain_level"] not in {"domain", "tld"}
    ):
        raise ValueError("[graph].domain_level must be 'domain' or 'tld'")
    return out


def _clean_label(value: object) -> str:
    """Return a control-free identity label before grouping/ranking."""
    if value is None:
        return "(unknown)"
    try:
        if pd.isna(value):
            return "(unknown)"
    except (TypeError, ValueError):
        # Object-shaped values are not canonical labels.  Their safe string
        # representation below is still preferable to leaking a raw failure.
        pass
    try:
        cleaned = strip_control(value).strip()
    except (ValueError, OverflowError, RecursionError):
        # Python intentionally rejects decimal conversion of excessively large
        # integers.  Treat those hostile labels as unknown rather than letting
        # a public builder escape with an implementation traceback.
        return "(unknown)"
    return cleaned or "(unknown)"


def _coerce_timestamp(value: object) -> float | None:
    """Return a finite, UTC-datetime-representable graph timestamp or None."""
    try:
        timestamp = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(timestamp):
        return None
    try:
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None
    return timestamp


def _metric_error() -> ValueError:
    return ValueError("graph metric values are too large to render safely")


def _coerce_metric(value: object) -> float:
    """Coerce null/non-finite metrics to zero and reject unsafe finite sizes."""
    try:
        metric = float(value)
    except OverflowError as exc:
        raise _metric_error() from exc
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(metric):
        return 0.0
    if abs(metric) > _FLOAT32_MAX:
        raise _metric_error()
    return metric


def pick_bin_seconds(span_seconds: float, target_bins: int) -> int:
    """Choose a nice bin width while keeping the emitted bin count bounded."""
    span = max(float(span_seconds), 1.0)
    raw = span / max(target_bins - 1, 1)
    # Timestamp endpoints are inclusive. With a one-bin target, a width equal
    # to the span would put the final endpoint in a second bin, so that one
    # shape deliberately chooses the next strictly larger nice unit.
    strict = target_bins == 1
    for unit in _NICE_BIN_SECONDS:
        if unit > raw or (not strict and unit >= raw):
            return unit
    if strict:
        return int((math.floor(raw / 604_800) + 1) * 604_800)
    return int(math.ceil(raw / 604_800) * 604_800)


def _slider_radius(bins: int) -> int:
    """Mirror JavaScript ``Math.round(B / 12)`` for the player max slider."""
    return max(6, math.floor(bins / 12 + 0.5))


def _require_columns(frame: pd.DataFrame, columns: set[str], kind: str) -> None:
    missing = sorted(columns - set(frame.columns))
    if missing:
        raise ValueError(f"{kind}.log fields not found: {', '.join(missing)}")


def require_columns(frame: pd.DataFrame, columns: set[str], kind: str) -> None:
    """Validate a kind's raw canonical fields before its builder selects them.

    ``build_payload`` validates the shared prepared shape. Kind builders must
    call this first because selecting a missing raw DataFrame column otherwise
    leaks pandas' ``KeyError`` through the CLI instead of the controlled graph
    schema error.
    """
    _require_columns(frame, columns, kind)


def _top_values(frame: pd.DataFrame, column: str, limit: int) -> list[str]:
    totals = (
        frame.groupby(column, sort=False)
        .agg(metric=("metric", "sum"), count=("metric", "size"))
        .reset_index()
    )
    totals["score"] = totals["metric"] + totals["count"]
    totals["_label"] = totals[column].astype(str)
    ranked = totals.sort_values(
        ["score", "_label"], ascending=[False, True], kind="stable"
    )
    return [
        str(value)
        for value in ranked[column].head(limit)
        if str(value) != _OTHER
    ]


def _budget_error() -> ValueError:
    return ValueError(
        "graph too dense for smooth interaction - narrow the window "
        "(--since/--days) or lower [graph] top_hosts / top_services / target_bins"
    )


def _assert_budgets(grouped: pd.DataFrame, bins: int) -> None:
    flow_count = int(grouped.groupby(["s", "d", "v"], sort=False).ngroups)
    if flow_count > GRAPH_MAX_FLOWS:
        raise _budget_error()
    radius_max = _slider_radius(bins)
    smooth_ops = 2 * flow_count * bins * (2 * radius_max + 1)
    if smooth_ops > GRAPH_MAX_SMOOTH_OPS:
        raise _budget_error()
    serialized_pairs = 2 * len(grouped)
    if serialized_pairs > GRAPH_MAX_PAYLOAD_PAIRS:
        raise _budget_error()


def _pairs(group: pd.DataFrame, field: str) -> list[int]:
    pairs: list[int] = []
    for row in group.sort_values("bin", kind="stable").itertuples(index=False):
        pairs.extend((int(row.bin), int(round(float(getattr(row, field))))))
    return pairs


def build_payload(
    frame: pd.DataFrame,
    *,
    kind: str,
    source_label: str,
    config: dict[str, Any],
    meta: dict[str, Any],
    default_window_note: str | None,
) -> dict[str, Any]:
    """Build the common graph payload from a prepared canonical frame.

    The caller supplies columns ts, src, dst, svc, and metric. Labels become
    identities only after control stripping, which prevents post-serialization
    duplicate node IDs. The grouped frame is deliberately budgeted before
    sparse pair lists are allocated.
    """
    _require_columns(frame, {"ts", "src", "dst", "svc", "metric"}, kind)
    df = frame.copy()
    df["ts"] = df["ts"].map(_coerce_timestamp)
    finite_ts = df["ts"].notna()
    df = df[finite_ts].copy()
    if df.empty:
        raise GraphEmpty(kind, _clean_label(source_label), "no timestamped rows")

    df["metric"] = df["metric"].map(_coerce_metric)
    for column in ("src", "dst", "svc"):
        df[column] = df[column].map(_clean_label)

    t0 = float(df["ts"].min())
    t1 = float(df["ts"].max())
    bin_seconds = pick_bin_seconds(t1 - t0, config["target_bins"])
    df["bin"] = ((df["ts"] - t0) // bin_seconds).astype(int)
    bins = int(df["bin"].max()) + 1

    keep_src = _top_values(df, "src", config["top_hosts"])
    keep_dst = _top_values(df, "dst", config["top_hosts"])
    keep_svc = _top_values(df, "svc", config["top_services"])
    df["s"] = df["src"].where(df["src"].isin(keep_src), _OTHER)
    df["d"] = df["dst"].where(df["dst"].isin(keep_dst), _OTHER)
    df["v"] = df["svc"].where(df["svc"].isin(keep_svc), _OTHER)

    grouped = (
        df.groupby(["s", "d", "v", "bin"], sort=False)
        .agg(b=("metric", "sum"), c=("metric", "size"))
        .reset_index()
    )
    if (
        not np.isfinite(grouped["b"]).all()
        or (grouped["b"].abs() > _FLOAT32_MAX).any()
    ):
        raise _metric_error()
    _assert_budgets(grouped, bins)

    # Check all numeric series before materializing sparse [bin, value] pairs.
    # A set of individually safe flows can still overflow the player total.
    totals_b = grouped.groupby("bin", sort=False)["b"].sum().reindex(
        range(bins), fill_value=0
    )
    absolute_totals_b = grouped.assign(_abs_b=grouped["b"].abs()).groupby(
        "bin", sort=False,
    )["_abs_b"].sum().reindex(range(bins), fill_value=0)
    if (
        not np.isfinite(totals_b).all()
        or (totals_b.abs() > _FLOAT32_MAX).any()
        or not np.isfinite(absolute_totals_b).all()
        or (absolute_totals_b > _FLOAT32_MAX).any()
    ):
        raise _metric_error()

    src_nodes = keep_src + ([_OTHER] if (df["s"] == _OTHER).any() else [])
    svc_nodes = keep_svc + ([_OTHER] if (df["v"] == _OTHER).any() else [])
    src_rank = {value: idx for idx, value in enumerate(src_nodes)}

    weights = df.groupby(["s", "d"], sort=False)["metric"].sum().reset_index()
    weights["src_rank"] = weights["s"].map(src_rank)
    weights["weighted_rank"] = weights["metric"].clip(lower=1) * weights["src_rank"]
    weights["weight"] = weights["metric"].clip(lower=1)
    bary = (
        weights.groupby("d", sort=False)["weighted_rank"].sum()
        / weights.groupby("d", sort=False)["weight"].sum()
    )
    dst_candidates = keep_dst + ([_OTHER] if (df["d"] == _OTHER).any() else [])
    dst_nodes = sorted(
        (value for value in dst_candidates if value != _OTHER),
        key=lambda value: (float(bary.get(value, float("inf"))), value),
    )
    if _OTHER in dst_candidates:
        dst_nodes.append(_OTHER)

    union_metric = df.groupby("s", sort=False)["metric"].sum().add(
        df.groupby("d", sort=False)["metric"].sum(), fill_value=0
    )
    union_count = df.groupby("s", sort=False).size().add(
        df.groupby("d", sort=False).size(), fill_value=0
    )
    union_score = (union_metric + union_count).sort_values(
        ascending=False, kind="stable"
    )
    color_rank = {
        str(value): index
        for index, value in enumerate(
            value for value in union_score.index if str(value) != _OTHER
        )
    }

    src_index = {value: index for index, value in enumerate(src_nodes)}
    dst_index = {value: index for index, value in enumerate(dst_nodes)}
    svc_index = {value: index for index, value in enumerate(svc_nodes)}
    flows: list[dict[str, Any]] = []
    for (src, dst, svc), group in grouped.groupby(["s", "d", "v"], sort=False):
        flows.append(
            {
                "s": src_index[str(src)],
                "d": dst_index[str(dst)],
                "v": svc_index[str(svc)],
                "b": _pairs(group, "b"),
                "c": _pairs(group, "c"),
            }
        )
    flows.sort(key=lambda flow: (-sum(flow["b"][1::2]), flow["s"], flow["d"], flow["v"]))

    first_src = df.groupby("s", sort=False)["bin"].min()
    first_dst = df.groupby("d", sort=False)["bin"].min()
    hosts_first = pd.concat(
        [
            df.groupby("src", sort=False)["bin"].min(),
            df.groupby("dst", sort=False)["bin"].min(),
        ]
    ).groupby(level=0).min()
    hosts_seen = (
        hosts_first.value_counts()
        .reindex(range(bins), fill_value=0)
        .sort_index()
        .cumsum()
    )
    totals_c = df.groupby("bin", sort=False).size().reindex(range(bins), fill_value=0)

    payload_meta_extra = dict(meta)
    payload_meta = {
        "source": _clean_label(source_label),
        "rows": int(len(df)),
        "t0": t0,
        "t1": t1,
        "bin_seconds": int(bin_seconds),
        "bins": bins,
        "distinct_hosts": int(hosts_first.size),
        "distinct_services": int(df["svc"].nunique()),
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "generator": f"sigwood {__version__}",
        "display_utc": bool(payload_meta_extra.pop("display_utc", False)),
        "default_window_note": default_window_note,
        **payload_meta_extra,
    }
    return {
        "meta": payload_meta,
        "srcNodes": [
            {
                "id": value,
                "first": int(first_src.get(value, 0)),
                "cr": int(color_rank.get(value, 0)),
            }
            for value in src_nodes
        ],
        "dstNodes": [
            {
                "id": value,
                "first": int(first_dst.get(value, 0)),
                "cr": int(color_rank.get(value, 0)),
            }
            for value in dst_nodes
        ],
        "svcNodes": svc_nodes,
        "flows": flows,
        "totB": [int(round(float(value))) for value in totals_b],
        "totC": [int(value) for value in totals_c],
        "hostsSeen": [int(value) for value in hosts_seen],
    }
