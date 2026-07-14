"""Shared graph payload construction and graph tuning validation."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

import numpy as np
import pandas as pd

from sigwood import __version__
from sigwood.common.display import fmt_timestamp, plural
from sigwood.common.errors import GraphEmpty
from sigwood.common.sanitize import strip_control


GRAPH_MAX_FLOWS = 4_000
GRAPH_MAX_SMOOTH_OPS = 400_000_000
GRAPH_MAX_PAYLOAD_PAIRS = 1_500_000
TRIM_DENSITY_FRACTION = 0.05
MIN_DENSE_BINS = 8
TRIM_MIN_TAIL_BINS = 6
_TRIM_MASS_CAP_DEN = 1_000

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
        "top_hosts": 30,
        "top_services": 16,
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


def _clean_identity(value: object) -> str:
    """Return a scalar host identity without inventing structured labels."""
    if not isinstance(value, str):
        return "(unknown)"
    return _clean_label(value)


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


def _coerce_metric_with_flag(value: object) -> tuple[float, bool]:
    """Return one finite size metric and whether saturation changed it."""
    try:
        metric = float(value)
    except OverflowError:
        try:
            negative = bool(value < 0)  # type: ignore[operator]
        except (TypeError, ValueError, OverflowError, RecursionError):
            negative = False
        return (-_FLOAT32_MAX if negative else _FLOAT32_MAX), True
    except (TypeError, ValueError):
        return 0.0, False
    if not math.isfinite(metric):
        return 0.0, False
    if abs(metric) > _FLOAT32_MAX:
        return math.copysign(_FLOAT32_MAX, metric), True
    return metric, False


def _coerce_metric(value: object) -> float:
    """Coerce null/non-finite metrics to zero and saturate finite sizes."""
    return _coerce_metric_with_flag(value)[0]


def _metric_error() -> ValueError:
    return ValueError("graph metric values are too large to render safely")


def _coerce_weight(value: object) -> float:
    """Return one finite non-negative weighted-count contribution.

    Weighted counts are builder-authored shares, not source size magnitudes.
    Invalid values therefore remain a builder-contract error instead of using
    the size-metric saturation path.
    """
    try:
        weight = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise _metric_error() from exc
    if not math.isfinite(weight) or not 0 <= weight <= _FLOAT32_MAX:
        raise _metric_error()
    return weight


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


def _rank_values(frame: pd.DataFrame, column: str) -> list[str]:
    """Return deterministic metric-ranked identities for one graph axis."""
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
        for value in ranked[column]
        if str(value) != _OTHER
    ]


@dataclass
class _GroupState:
    """One recomputable folded/binned graph shape."""

    frame: pd.DataFrame
    grouped: pd.DataFrame
    keep_src: list[str]
    keep_dst: list[str]
    keep_svc: list[str]
    host_limit: int
    service_limit: int
    bin_seconds: int
    bins: int

    @property
    def flow_count(self) -> int:
        return int(self.grouped.groupby(["s", "d", "v"], sort=False).ngroups)

    @property
    def payload_pairs(self) -> int:
        return 2 * len(self.grouped)


@dataclass(frozen=True)
class _TrimResult:
    """One sparse-edge trim result and its disclosure facts."""

    frame: pd.DataFrame
    trimmed_leading: int = 0
    trimmed_trailing: int = 0
    lead_boundary_epoch: float | None = None
    trail_boundary_epoch: float | None = None


def _trim_sparse_edges(
    frame: pd.DataFrame,
    *,
    t0: float,
    t1: float,
    bin_seconds: int,
) -> _TrimResult:
    """Trim small, distant outer runs around a robust dense body."""
    if t1 < t0:
        return _TrimResult(frame)
    indexes = ((frame["ts"] - t0) // bin_seconds).astype(int)
    bin_count = int(indexes.max()) + 1
    counts = np.bincount(indexes.to_numpy(), minlength=bin_count)
    total = int(counts.sum())
    nonempty = counts[counts > 0]
    if nonempty.size < MIN_DENSE_BINS:
        return _TrimResult(frame)

    dense_reference = float(np.quantile(nonempty, 0.75))
    floor = dense_reference * TRIM_DENSITY_FRACTION
    crossings = np.flatnonzero(counts >= floor)
    leading_bin = int(crossings[0])
    trailing_bin = int(crossings[-1])
    if leading_bin < TRIM_MIN_TAIL_BINS:
        leading_bin = 0
    if bin_count - 1 - trailing_bin < TRIM_MIN_TAIL_BINS:
        trailing_bin = bin_count - 1
    if leading_bin == 0 and trailing_bin == bin_count - 1:
        return _TrimResult(frame)

    trimmed_leading = int(counts[:leading_bin].sum())
    trimmed_trailing = int(counts[trailing_bin + 1 :].sum())
    trimmed = trimmed_leading + trimmed_trailing
    if trimmed * _TRIM_MASS_CAP_DEN > total:
        return _TrimResult(frame)

    keep = indexes.between(leading_bin, trailing_bin)
    # This is a positional mask. Loader concatenation can preserve duplicate
    # source indexes, so label-aligned boolean selection is the wrong seam.
    kept = frame.loc[keep.to_numpy()].copy()
    lead_epoch = float(kept["ts"].min()) if trimmed_leading else None
    trail_epoch = float(kept["ts"].max()) if trimmed_trailing else None
    return _TrimResult(
        kept,
        trimmed_leading=trimmed_leading,
        trimmed_trailing=trimmed_trailing,
        lead_boundary_epoch=lead_epoch,
        trail_boundary_epoch=trail_epoch,
    )


def _group_shape(
    frame: pd.DataFrame,
    *,
    rankings: dict[str, list[str]],
    host_limit: int,
    service_limit: int,
    bin_seconds: int,
    t0: float,
    t1: float,
    count_by: Literal["size", "weight"],
) -> _GroupState:
    """Fold, bin, and group one candidate build shape."""
    shaped = frame.copy()
    shaped["bin"] = ((shaped["ts"] - t0) // bin_seconds).astype(int)
    bins = max(
        int(shaped["bin"].max()) + 1,
        math.floor((t1 - t0) / bin_seconds) + 1,
    )
    keep_src = rankings["src"][:host_limit]
    keep_dst = rankings["dst"][:host_limit]
    keep_svc = rankings["svc"][:service_limit]
    shaped["s"] = shaped["src"].where(shaped["src"].isin(keep_src), _OTHER)
    shaped["d"] = shaped["dst"].where(shaped["dst"].isin(keep_dst), _OTHER)
    shaped["v"] = shaped["svc"].where(shaped["svc"].isin(keep_svc), _OTHER)
    count_aggregation = "sum" if count_by == "weight" else "size"
    grouped = (
        shaped.groupby(["s", "d", "v", "bin"], sort=False)
        .agg(
            b=("metric", "sum"),
            c=("metric", count_aggregation),
            _metric_altered=("_metric_altered", "any"),
        )
        .reset_index()
    )
    return _GroupState(
        frame=shaped,
        grouped=grouped,
        keep_src=keep_src,
        keep_dst=keep_dst,
        keep_svc=keep_svc,
        host_limit=host_limit,
        service_limit=service_limit,
        bin_seconds=bin_seconds,
        bins=bins,
    )


def _largest_fitting_limit(upper: int, fits: Any) -> int | None:
    """Return the largest integer limit accepted by a monotone predicate."""
    if fits(upper):
        return upper
    if not fits(1):
        return None
    low, high, best = 2, upper - 1, 1
    while low <= high:
        middle = (low + high) // 2
        if fits(middle):
            best = middle
            low = middle + 1
        else:
            high = middle - 1
    return best


def _next_bin_seconds(current: int, span_seconds: float) -> int | None:
    """Return the next coarser nice width, ending at one inclusive bin."""
    terminal = pick_bin_seconds(span_seconds, 1)
    for unit in _NICE_BIN_SECONDS:
        if current < unit <= terminal:
            return unit
    if current < terminal:
        return terminal
    return None


def _float32_abs_sum_is_finite(values: pd.Series) -> bool:
    """Mirror the player's Float32 accumulation for one bin's absolute mass."""
    total = np.float32(0.0)
    with np.errstate(over="ignore", invalid="ignore"):
        for value in values:
            total = np.float32(total + np.float32(abs(float(value))))
    return bool(np.isfinite(total))


def _saturate_grouped_metrics(
    grouped: pd.DataFrame, *, count_by: Literal["size", "weight"],
) -> tuple[pd.DataFrame, int]:
    """Make serialized grouped metrics safe for every player subset sum."""
    safe = grouped.copy()
    raw = pd.to_numeric(safe["b"], errors="coerce")
    saturated = raw.clip(lower=-_FLOAT32_MAX, upper=_FLOAT32_MAX).fillna(0.0)
    cell_changed = safe["_metric_altered"].astype(bool) | raw.ne(saturated)
    safe["b"] = saturated.astype(float)

    absolute = safe["b"].abs().groupby(safe["bin"], sort=False).transform("sum")
    scale = pd.Series(1.0, index=safe.index, dtype=float)
    over = absolute > _FLOAT32_MAX
    scale.loc[over] = _FLOAT32_MAX / absolute.loc[over]
    if over.any():
        safe.loc[over, "b"] = safe.loc[over, "b"] * scale.loc[over]
        cell_changed.loc[over] = True

    # Values round once more when the player loads them into Float32Array.
    # If exact-ceiling scaling still overflows a sequential Float32 sum, add
    # generous headroom for that bin and prove the representation again.
    for bin_index, indexes in safe.groupby("bin", sort=False).groups.items():
        del bin_index
        values = safe.loc[indexes, "b"]
        if _float32_abs_sum_is_finite(values):
            continue
        safe.loc[indexes, "b"] = values * 0.5
        cell_changed.loc[indexes] = True
        assert _float32_abs_sum_is_finite(safe.loc[indexes, "b"])

    if count_by == "weight":
        safe["c"] = safe["b"]
    safe = safe.drop(columns=["_metric_altered"])
    return safe, int(cell_changed.sum())


def _human_bin_seconds(seconds: int) -> str:
    """Render one tool-authored bin width for the degrade note."""
    for unit, suffix in ((86_400, "d"), (3_600, "h"), (60, "m")):
        if seconds >= unit and seconds % unit == 0:
            return f"{seconds // unit}{suffix}"
    return f"{seconds}s"


def _format_trim_boundary(value: object) -> str:
    """Render one validated retained-window epoch through the display owner."""
    epoch = _coerce_timestamp(value)
    if epoch is None:
        raise ValueError("graph trim boundary must be a finite timestamp")
    return fmt_timestamp(datetime.fromtimestamp(epoch, tz=timezone.utc))


def _format_degrade_note(meta: dict[str, Any]) -> str | None:
    """Compose the one artifact/stderr degradation disclosure."""
    parts: list[str] = []
    max_radius = int(meta["max_radius"])
    natural_radius = int(meta["natural_radius"])
    if max_radius < natural_radius:
        parts.append(
            f"capped max smoothing to +/-{max_radius} bins to stay interactive"
        )
    bin_seconds = int(meta["bin_seconds"])
    requested_bin_seconds = int(meta["requested_bin_seconds"])
    if bin_seconds > requested_bin_seconds:
        parts.append(
            f"binned to {_human_bin_seconds(bin_seconds)} to stay interactive"
        )
    effective_services = int(meta["effective_top_services"])
    effective_hosts = int(meta["effective_top_hosts"])
    if (
        effective_services < int(meta["requested_top_services"])
        or effective_hosts < int(meta["requested_top_hosts"])
    ):
        parts.append(
            f"showing top {effective_services} services / {effective_hosts} hosts "
            "to stay interactive"
        )
    trimmed_leading = int(meta.get("trimmed_leading", 0))
    if trimmed_leading:
        noun = plural(
            trimmed_leading,
            str(meta["trim_noun_singular"]),
            str(meta["trim_noun_plural"]),
        )
        boundary = _format_trim_boundary(meta["trim_lead_epoch"])
        parts.append(
            f"trimmed {trimmed_leading} {noun} before the retained window "
            "to focus the timeline "
            f"(window begins {boundary})"
        )
    trimmed_trailing = int(meta.get("trimmed_trailing", 0))
    if trimmed_trailing:
        noun = plural(
            trimmed_trailing,
            str(meta["trim_noun_singular"]),
            str(meta["trim_noun_plural"]),
        )
        boundary = _format_trim_boundary(meta["trim_trail_epoch"])
        parts.append(
            f"trimmed {trimmed_trailing} {noun} after the retained window "
            "to focus the timeline "
            f"(window ends {boundary})"
        )
    altered_cells = int(meta.get("altered_metric_cells", 0))
    if altered_cells:
        parts.append(
            f"scaled {altered_cells} metric cells to the render ceiling"
        )
    if meta.get("date_window_widened"):
        parts.append(
            f"date window held no {meta['kind']} rows that started that day; "
            "widened to the full archive"
        )
    if meta.get("missing_bytes"):
        parts.append(
            "conn.log has no byte counts; showing connection counts only"
        )
    return "; ".join(parts) or None


def _payload_number(value: object, *, preserve_fraction: bool) -> int | float:
    """Serialize one validated graph value without losing weighted mass."""
    number = float(value)
    if preserve_fraction:
        return number
    return int(round(number))


def _pairs(
    group: pd.DataFrame, field: str, *, preserve_fraction: bool,
) -> list[int | float]:
    pairs: list[int | float] = []
    for row in group.sort_values("bin", kind="stable").itertuples(index=False):
        pairs.extend((
            int(row.bin),
            _payload_number(
                getattr(row, field), preserve_fraction=preserve_fraction,
            ),
        ))
    return pairs


def build_payload(
    frame: pd.DataFrame,
    *,
    kind: str,
    source_label: str,
    config: dict[str, Any],
    meta: dict[str, Any],
    default_window_note: str | None,
    count_by: Literal["size", "weight"] = "size",
    row_count: int | None = None,
    window: tuple[float, float] | None = None,
    trim_sparse_edges: bool = False,
) -> dict[str, Any]:
    """Build the common graph payload from a prepared canonical frame.

    The caller supplies columns ts, src, dst, svc, and metric. Labels become
    identities only after control stripping, which prevents post-serialization
    duplicate node IDs. The grouped frame is deliberately budgeted before
    sparse pair lists are allocated.
    """
    _require_columns(frame, {"ts", "src", "dst", "svc", "metric"}, kind)
    if count_by not in {"size", "weight"}:
        raise ValueError("graph count mode must be 'size' or 'weight'")
    if (
        row_count is not None
        and (
            isinstance(row_count, bool)
            or not isinstance(row_count, int)
            or row_count < 0
        )
    ):
        raise ValueError("graph row count must be a non-negative integer")
    df = frame.copy()
    df["ts"] = df["ts"].map(_coerce_timestamp)
    finite_ts = df["ts"].notna()
    df = df[finite_ts].copy()
    if df.empty:
        raise GraphEmpty(kind, _clean_label(source_label), "no timestamped rows")

    if count_by == "weight":
        df["metric"] = df["metric"].map(_coerce_weight)
        df["_metric_altered"] = False
    else:
        coerced = df["metric"].map(_coerce_metric_with_flag)
        df["metric"] = coerced.map(lambda item: item[0])
        df["_metric_altered"] = coerced.map(lambda item: item[1])
    for column in ("src", "dst"):
        df[column] = df[column].map(_clean_identity)
    df["svc"] = df["svc"].map(_clean_label)

    t0 = float(df["ts"].min())
    t1 = float(df["ts"].max())
    if window is not None:
        try:
            raw_t0, raw_t1 = window
        except (TypeError, ValueError):
            raw_t0 = raw_t1 = None
        window_t0 = _coerce_timestamp(raw_t0)
        window_t1 = _coerce_timestamp(raw_t1)
        if window_t0 is not None and window_t1 is not None:
            t0 = min(t0, window_t0, window_t1)
            t1 = max(t1, window_t0, window_t1)
    span_seconds = t1 - t0
    requested_bin_seconds = pick_bin_seconds(
        span_seconds, config["target_bins"],
    )
    trim_result = _TrimResult(df)
    if trim_sparse_edges and window is None:
        trim_result = _trim_sparse_edges(
            df,
            t0=t0,
            t1=t1,
            bin_seconds=requested_bin_seconds,
        )
        if trim_result.trimmed_leading or trim_result.trimmed_trailing:
            df = trim_result.frame
            t0 = float(df["ts"].min())
            t1 = float(df["ts"].max())
            span_seconds = t1 - t0
            requested_bin_seconds = pick_bin_seconds(
                span_seconds, config["target_bins"],
            )
    rankings = {
        column: _rank_values(df, column)
        for column in ("src", "dst", "svc")
    }
    states: dict[tuple[int, int, int], _GroupState] = {}

    def state_for(host_limit: int, service_limit: int, width: int) -> _GroupState:
        key = (host_limit, service_limit, width)
        if key not in states:
            states[key] = _group_shape(
                df,
                rankings=rankings,
                host_limit=host_limit,
                service_limit=service_limit,
                bin_seconds=width,
                t0=t0,
                t1=t1,
                count_by=count_by,
            )
        return states[key]

    host_limit = int(config["top_hosts"])
    service_limit = int(config["top_services"])
    bin_seconds = requested_bin_seconds
    state = state_for(host_limit, service_limit, bin_seconds)

    if state.flow_count > GRAPH_MAX_FLOWS:
        service_fit = _largest_fitting_limit(
            service_limit,
            lambda limit: state_for(host_limit, limit, bin_seconds).flow_count
            <= GRAPH_MAX_FLOWS,
        )
        if service_fit is not None:
            service_limit = service_fit
        else:
            service_limit = 1
            host_fit = _largest_fitting_limit(
                host_limit,
                lambda limit: state_for(limit, service_limit, bin_seconds).flow_count
                <= GRAPH_MAX_FLOWS,
            )
            # The 1/1 fold has at most eight grouped flows.
            host_limit = 1 if host_fit is None else host_fit
        state = state_for(host_limit, service_limit, bin_seconds)

    def fold_for_pairs(current: _GroupState) -> _GroupState:
        """Fold farther only when the terminal bin width cannot fit pairs."""
        nonlocal host_limit, service_limit
        service_fit = _largest_fitting_limit(
            service_limit,
            lambda limit: state_for(
                host_limit, limit, current.bin_seconds,
            ).payload_pairs <= GRAPH_MAX_PAYLOAD_PAIRS,
        )
        if service_fit is not None:
            service_limit = service_fit
        else:
            service_limit = 1
            host_fit = _largest_fitting_limit(
                host_limit,
                lambda limit: state_for(
                    limit, service_limit, current.bin_seconds,
                ).payload_pairs <= GRAPH_MAX_PAYLOAD_PAIRS,
            )
            host_limit = 1 if host_fit is None else host_fit
        return state_for(host_limit, service_limit, current.bin_seconds)

    while True:
        while state.payload_pairs > GRAPH_MAX_PAYLOAD_PAIRS:
            next_width = _next_bin_seconds(state.bin_seconds, span_seconds)
            if next_width is None:
                state = fold_for_pairs(state)
                break
            bin_seconds = next_width
            state = state_for(host_limit, service_limit, bin_seconds)

        flow_count = state.flow_count
        denominator = 2 * flow_count * state.bins
        radius_fit = math.floor(
            (GRAPH_MAX_SMOOTH_OPS / denominator - 1) / 2
        )
        if radius_fit >= 6:
            natural_radius = _slider_radius(state.bins)
            max_radius = min(natural_radius, radius_fit)
            break
        next_width = _next_bin_seconds(state.bin_seconds, span_seconds)
        if next_width is None:
            # Production budgets make the 1/1/1 floor fit with wide margin.
            natural_radius = _slider_radius(state.bins)
            max_radius = natural_radius
            break
        bin_seconds = next_width
        state = state_for(host_limit, service_limit, bin_seconds)

    df = state.frame
    keep_src = state.keep_src
    keep_dst = state.keep_dst
    keep_svc = state.keep_svc
    bins = state.bins
    bin_seconds = state.bin_seconds
    grouped, altered_metric_cells = _saturate_grouped_metrics(
        state.grouped, count_by=count_by,
    )
    totals_b = grouped.groupby("bin", sort=False)["b"].sum().reindex(
        range(bins), fill_value=0,
    )

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
    preserve_fraction = count_by == "weight"
    for (src, dst, svc), group in grouped.groupby(["s", "d", "v"], sort=False):
        flows.append(
            {
                "s": src_index[str(src)],
                "d": dst_index[str(dst)],
                "v": svc_index[str(svc)],
                "b": _pairs(group, "b", preserve_fraction=preserve_fraction),
                "c": _pairs(group, "c", preserve_fraction=preserve_fraction),
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
    totals_c = grouped.groupby("bin", sort=False)["c"].sum().reindex(
        range(bins), fill_value=0,
    )

    payload_meta_extra = dict(meta)
    payload_meta_extra.pop("hunt_hint", None)
    payload_meta = {
        "source": _clean_label(source_label),
        "rows": int(len(df) if row_count is None else row_count),
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
        "requested_bin_seconds": int(requested_bin_seconds),
        "requested_top_hosts": int(config["top_hosts"]),
        "requested_top_services": int(config["top_services"]),
        "effective_top_hosts": int(host_limit),
        "effective_top_services": int(service_limit),
        "natural_radius": int(natural_radius),
        "max_radius": int(max_radius),
        "altered_metric_cells": altered_metric_cells,
        "trimmed_leading": trim_result.trimmed_leading,
        "trimmed_trailing": trim_result.trimmed_trailing,
        "trim_lead_epoch": trim_result.lead_boundary_epoch,
        "trim_trail_epoch": trim_result.trail_boundary_epoch,
        "date_window_widened": False,
        "degrade_note": None,
        "weighted": count_by == "weight",
        "hunt_hint": None,
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
        "totB": [
            _payload_number(value, preserve_fraction=preserve_fraction)
            for value in totals_b
        ],
        "totC": [
            _payload_number(value, preserve_fraction=preserve_fraction)
            for value in totals_c
        ],
        "hostsSeen": [int(value) for value in hosts_seen],
    }


def attach_hunt_hint(payload: dict[str, Any], hint: str | None) -> None:
    """Attach one runner-composed hunt hint to an existing graph payload."""
    assert "meta" in payload and "hunt_hint" in payload["meta"]
    if hint is None:
        return
    payload["meta"]["hunt_hint"] = strip_control(hint)
