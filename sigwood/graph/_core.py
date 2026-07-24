"""Shared graph payload construction and graph tuning validation."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

import numpy as np
import pandas as pd

from sigwood.common.display import (
    fmt_timestamp,
    human_bytes,
    plural,
    version_string,
)
from sigwood.common.errors import GraphEmpty
from sigwood.common.sanitize import strip_control


GRAPH_MAX_FLOWS = 4_000
GRAPH_MAX_SMOOTH_OPS = 400_000_000
GRAPH_MAX_PAYLOAD_PAIRS = 1_500_000
GRAPH_MAX_SPREAD_FRAGMENTS = 3_000_000
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


def _coerce_duration(value: object) -> float:
    """Return one finite non-negative optional duration or zero."""
    try:
        duration = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if not math.isfinite(duration) or duration < 0:
        return 0.0
    return duration


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


@dataclass(frozen=True)
class _ShapeMeasure:
    """Scalar-only measurement for one folded graph candidate."""

    host_limit: int
    service_limit: int
    bin_seconds: int
    bins: int
    flow_count: int
    payload_pairs: int


@dataclass
class _RawBasis:
    """Current-width code-keyed bases retained while candidates are measured."""

    b: pd.DataFrame
    c: pd.DataFrame
    bins: int
    bin_seconds: int
    prune_dead: bool
    preserve_fraction: bool


@dataclass(frozen=True)
class _Codebook:
    """First-seen labels and ranked compact identity codes for one build."""

    src: tuple[str, ...]
    dst: tuple[str, ...]
    svc: tuple[str, ...]
    ranked_src: tuple[int, ...]
    ranked_dst: tuple[int, ...]
    ranked_svc: tuple[int, ...]


@dataclass(frozen=True)
class _TrimResult:
    """One sparse-edge trim result and its disclosure facts."""

    frame: pd.DataFrame
    trimmed_leading: int = 0
    trimmed_trailing: int = 0
    lead_boundary_epoch: float | None = None
    trail_boundary_epoch: float | None = None
    retained_start_epoch: float | None = None
    retained_end_epoch: float | None = None
    retained_straddlers: int = 0


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

    retained_start = t0 + leading_bin * bin_seconds
    retained_end = t0 + (trailing_bin + 1) * bin_seconds
    ordinary_keep = indexes.between(leading_bin, trailing_bin)
    straddlers = np.zeros(len(frame), dtype=bool)
    if "dur" in frame.columns and leading_bin:
        with np.errstate(over="ignore", invalid="ignore"):
            ends = frame["ts"].to_numpy(dtype=float) + frame["dur"].to_numpy(
                dtype=float,
            )
        straddlers = (
            (frame["ts"].to_numpy(dtype=float) < retained_start)
            & (frame["dur"].to_numpy(dtype=float) > 0)
            & (ends > retained_start)
        )
    keep = ordinary_keep.to_numpy() | straddlers
    # This is a positional mask. Loader concatenation can preserve duplicate
    # source indexes, so label-aligned boolean selection is the wrong seam.
    kept = frame.loc[keep].copy()
    kept_start = float(
        np.maximum(kept["ts"].to_numpy(dtype=float), retained_start).min()
    )
    kept_end = float(kept["ts"].max())
    actual_leading = int((~keep & (indexes.to_numpy() < leading_bin)).sum())
    actual_trailing = int(
        (~keep & (indexes.to_numpy() > trailing_bin)).sum()
    )
    straddler_count = int(straddlers.sum())
    lead_epoch = kept_start if actual_leading else None
    trail_epoch = kept_end if actual_trailing else None
    return _TrimResult(
        kept,
        trimmed_leading=actual_leading,
        trimmed_trailing=actual_trailing,
        lead_boundary_epoch=lead_epoch,
        trail_boundary_epoch=trail_epoch,
        retained_start_epoch=kept_start,
        retained_end_epoch=kept_end,
        retained_straddlers=straddler_count,
    )


def _factor_identities(
    frame: pd.DataFrame,
    *,
    rankings: dict[str, list[str]],
) -> tuple[pd.DataFrame, _Codebook]:
    """Factor graph identities once while preserving first-seen label tables."""
    coded = frame.copy()
    labels: dict[str, tuple[str, ...]] = {}
    ranked: dict[str, tuple[int, ...]] = {}
    for column, code_column in (("src", "sc"), ("dst", "dc"), ("svc", "vc")):
        codes, uniques = pd.factorize(coded[column], sort=False)
        coded[code_column] = codes.astype(np.int32, copy=False)
        table = tuple(str(value) for value in uniques)
        labels[column] = table
        by_label = {value: index for index, value in enumerate(table)}
        ranked[column] = tuple(by_label[value] for value in rankings[column])
    return coded, _Codebook(
        src=labels["src"],
        dst=labels["dst"],
        svc=labels["svc"],
        ranked_src=ranked["src"],
        ranked_dst=ranked["dst"],
        ranked_svc=ranked["svc"],
    )


def _bin_extent(
    frame: pd.DataFrame, *, t0: float, t1: float, bin_seconds: int,
) -> tuple[np.ndarray, int, float]:
    """Return clamped start bins, bin count, and exclusive render end."""
    raw = np.floor(
        (frame["ts"].to_numpy(dtype=float) - t0) / bin_seconds
    ).astype(np.int64)
    bins = max(
        int(raw.max(initial=0)) + 1,
        math.floor((t1 - t0) / bin_seconds) + 1,
    )
    starts = np.clip(raw, 0, bins - 1)
    return starts, bins, t0 + bins * bin_seconds


def _band_extents(
    frame: pd.DataFrame,
    *,
    t0: float,
    t1: float,
    bin_seconds: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, int, float]:
    """Return vectorized clipped duration-band extents for one width."""
    starts, bins, render_end = _bin_extent(
        frame, t0=t0, t1=t1, bin_seconds=bin_seconds,
    )
    ts = frame["ts"].to_numpy(dtype=float)
    dur = frame["dur"].to_numpy(dtype=float)
    with np.errstate(over="ignore", invalid="ignore"):
        ends = ts + dur
    clipped_start = np.maximum(ts, t0)
    clipped_end = np.minimum(ends, render_end)
    positive = (dur > 0) & (clipped_end > clipped_start)
    first = np.clip(
        np.floor((clipped_start - t0) / bin_seconds).astype(np.int64),
        0,
        bins - 1,
    )
    last = np.clip(
        np.floor(
            (np.nextafter(clipped_end, -np.inf) - t0) / bin_seconds
        ).astype(np.int64),
        0,
        bins - 1,
    )
    touches = np.where(positive, last - first + 1, 0).astype(np.int64)
    return starts, first, touches, ends, bins, render_end


def _spread_fragment_count(
    frame: pd.DataFrame, *, t0: float, t1: float, bin_seconds: int,
) -> int:
    """Count exactly the positive-byte multi-bin fragments that can explode."""
    _, _, touches, _, _, _ = _band_extents(
        frame, t0=t0, t1=t1, bin_seconds=bin_seconds,
    )
    positive_mass = frame["metric"].to_numpy(dtype=float) > 0
    return int(touches[(touches > 1) & positive_mass].sum())


def _group_base(
    cells: pd.DataFrame, *, value: str, altered: bool = False,
) -> pd.DataFrame:
    """Aggregate one code-keyed raw basis without materializing labels."""
    aggregations: dict[str, tuple[str, str]] = {value: (value, "sum")}
    if altered:
        aggregations["_metric_altered"] = ("_metric_altered", "any")
    return (
        cells.groupby(["sc", "dc", "vc", "bin"], sort=False)
        .agg(**aggregations)
        .reset_index()
    )


def _build_raw_basis(
    frame: pd.DataFrame,
    *,
    t0: float,
    t1: float,
    bin_seconds: int,
    count_by: Literal["size", "weight"],
) -> _RawBasis:
    """Build the only retained code-keyed bases for one candidate width."""
    starts, bins, _ = _bin_extent(
        frame, t0=t0, t1=t1, bin_seconds=bin_seconds,
    )
    keys = ["sc", "dc", "vc"]
    unique_flows = not bool(frame.duplicated(keys).any())

    def raw_or_grouped(
        cells: pd.DataFrame, *, value: str, altered: bool = False,
    ) -> pd.DataFrame:
        if unique_flows:
            return cells.reset_index(drop=True)
        return _group_base(cells, value=value, altered=altered)

    c_cells = frame[keys].copy()
    c_cells["bin"] = starts
    if count_by == "weight":
        c_cells["c"] = frame["metric"].to_numpy(dtype=float)
        c_base = raw_or_grouped(c_cells, value="c")
    else:
        c_cells["c"] = np.int64(1)
        c_base = raw_or_grouped(c_cells, value="c")
        c_base["c"] = c_base["c"].astype(np.int64)

    if "dur" not in frame.columns:
        b_cells = frame[keys].copy()
        b_cells["bin"] = starts
        b_cells["b"] = frame["metric"].to_numpy(dtype=float)
        b_cells["_metric_altered"] = frame["_metric_altered"].to_numpy(
            dtype=bool,
        )
        return _RawBasis(
            raw_or_grouped(b_cells, value="b", altered=True),
            c_base,
            bins,
            bin_seconds,
            False,
            count_by == "weight",
        )

    starts, first, touches, ends, bins, render_end = _band_extents(
        frame, t0=t0, t1=t1, bin_seconds=bin_seconds,
    )
    metric = frame["metric"].to_numpy(dtype=float)
    duration = frame["dur"].to_numpy(dtype=float)
    positive_mass = metric > 0
    pieces: list[pd.DataFrame] = []

    point_rows = np.flatnonzero(positive_mass & (duration <= 0))
    if point_rows.size:
        points = frame.iloc[point_rows][keys].copy()
        points["bin"] = starts[point_rows]
        points["b"] = metric[point_rows]
        points["_metric_altered"] = frame["_metric_altered"].to_numpy(
            dtype=bool,
        )[point_rows]
        pieces.append(points)

    one_rows = np.flatnonzero(positive_mass & (duration > 0) & (touches == 1))
    if one_rows.size:
        one = frame.iloc[one_rows][keys].copy()
        one["bin"] = first[one_rows]
        left = np.maximum(
            frame["ts"].to_numpy(dtype=float)[one_rows],
            t0 + first[one_rows] * bin_seconds,
        )
        right = np.minimum(
            ends[one_rows], t0 + (first[one_rows] + 1) * bin_seconds,
        )
        one["b"] = metric[one_rows] * (
            (right - left) / duration[one_rows]
        )
        one["_metric_altered"] = frame["_metric_altered"].to_numpy(
            dtype=bool,
        )[one_rows]
        pieces.append(one)

    multi_rows = np.flatnonzero(positive_mass & (touches > 1))
    if multi_rows.size:
        counts = touches[multi_rows]
        row_ids = np.repeat(multi_rows.astype(np.int64), counts)
        beginnings = np.repeat(np.cumsum(counts) - counts, counts)
        fragment_bins = first[row_ids] + (
            np.arange(row_ids.size, dtype=np.int64) - beginnings
        )
        left = np.maximum(
            frame["ts"].to_numpy(dtype=float)[row_ids],
            t0 + fragment_bins * bin_seconds,
        )
        right = np.minimum(
            ends[row_ids], t0 + (fragment_bins + 1) * bin_seconds,
        )
        multi = pd.DataFrame({
            "sc": frame["sc"].to_numpy(dtype=np.int32)[row_ids],
            "dc": frame["dc"].to_numpy(dtype=np.int32)[row_ids],
            "vc": frame["vc"].to_numpy(dtype=np.int32)[row_ids],
            "bin": fragment_bins,
            "b": metric[row_ids] * (
                (right - left) / duration[row_ids]
            ),
            "_metric_altered": frame["_metric_altered"].to_numpy(
                dtype=bool,
            )[row_ids],
        })
        pieces.append(multi)

    if pieces:
        b_cells = (
            pieces[0].reset_index(drop=True)
            if len(pieces) == 1
            else pd.concat(pieces, ignore_index=True, copy=False)
        )
        b_base = raw_or_grouped(b_cells, value="b", altered=True)
    else:
        b_base = pd.DataFrame({
            "sc": pd.Series(dtype=np.int32),
            "dc": pd.Series(dtype=np.int32),
            "vc": pd.Series(dtype=np.int32),
            "bin": pd.Series(dtype=np.int64),
            "b": pd.Series(dtype=float),
            "_metric_altered": pd.Series(dtype=bool),
        })
    del pieces
    return _RawBasis(
        b_base, c_base, bins, bin_seconds, True, count_by == "weight",
    )


def _fold_basis(
    basis: _RawBasis,
    *,
    codebook: _Codebook,
    host_limit: int,
    service_limit: int,
) -> pd.DataFrame:
    """Fold current-width bases and return one ephemeral code-keyed grouping."""
    keep = {
        "sc": np.asarray(codebook.ranked_src[:host_limit], dtype=np.int32),
        "dc": np.asarray(codebook.ranked_dst[:host_limit], dtype=np.int32),
        "vc": np.asarray(codebook.ranked_svc[:service_limit], dtype=np.int32),
    }

    def fold(raw: pd.DataFrame, values: dict[str, tuple[str, str]]) -> pd.DataFrame:
        columns: dict[str, np.ndarray] = {}
        for column in ("sc", "dc", "vc"):
            data = raw[column].to_numpy(dtype=np.int32)
            columns[column] = np.where(
                np.isin(data, keep[column]), data, np.int32(-1),
            ).astype(np.int32, copy=False)
        columns["bin"] = raw["bin"].to_numpy(copy=False)
        for source, _aggregation in values.values():
            columns[source] = raw[source].to_numpy(copy=False)
        candidate = pd.DataFrame(columns, copy=False)
        return (
            candidate.groupby(["sc", "dc", "vc", "bin"], sort=False)
            .agg(**values)
            .reset_index()
        )

    folded_b = fold(
        basis.b,
        {"b": ("b", "sum"), "_metric_altered": ("_metric_altered", "any")},
    )
    folded_c = fold(basis.c, {"c": ("c", "sum")})
    grouped = folded_b.merge(
        folded_c,
        how="outer",
        on=["sc", "dc", "vc", "bin"],
        sort=False,
    )
    grouped["b"] = grouped["b"].fillna(0.0).astype(float)
    grouped["c"] = grouped["c"].fillna(0)
    if not basis.preserve_fraction:
        grouped["c"] = grouped["c"].astype(np.int64)
    grouped["_metric_altered"] = grouped["_metric_altered"].eq(True)
    if basis.prune_dead:
        grouped = grouped.loc[
            (grouped["c"] != 0) | grouped["b"].round().ne(0)
        ].copy()
    return grouped


def _measure_basis(
    basis: _RawBasis,
    *,
    codebook: _Codebook,
    host_limit: int,
    service_limit: int,
) -> _ShapeMeasure:
    """Measure and release one ephemeral folded candidate."""
    grouped = _fold_basis(
        basis,
        codebook=codebook,
        host_limit=host_limit,
        service_limit=service_limit,
    )
    measure = _ShapeMeasure(
        host_limit=host_limit,
        service_limit=service_limit,
        bin_seconds=basis.bin_seconds,
        bins=basis.bins,
        flow_count=int(grouped.groupby(["sc", "dc", "vc"], sort=False).ngroups),
        payload_pairs=2 * len(grouped),
    )
    del grouped
    return measure


def _shape_rows(
    frame: pd.DataFrame,
    *,
    codebook: _Codebook,
    host_limit: int,
    service_limit: int,
    bin_seconds: int,
    t0: float,
    bins: int,
) -> tuple[pd.DataFrame, list[str], list[str], list[str]]:
    """Materialize the final row-true folded frame exactly once."""
    shaped = frame.copy()
    raw_bins = np.floor(
        (shaped["ts"].to_numpy(dtype=float) - t0) / bin_seconds
    ).astype(np.int64)
    shaped["bin"] = np.clip(raw_bins, 0, bins - 1)
    keep_src_codes = codebook.ranked_src[:host_limit]
    keep_dst_codes = codebook.ranked_dst[:host_limit]
    keep_svc_codes = codebook.ranked_svc[:service_limit]
    keep_src = [codebook.src[code] for code in keep_src_codes]
    keep_dst = [codebook.dst[code] for code in keep_dst_codes]
    keep_svc = [codebook.svc[code] for code in keep_svc_codes]
    shaped["s"] = shaped["src"].where(shaped["sc"].isin(keep_src_codes), _OTHER)
    shaped["d"] = shaped["dst"].where(shaped["dc"].isin(keep_dst_codes), _OTHER)
    shaped["v"] = shaped["svc"].where(shaped["vc"].isin(keep_svc_codes), _OTHER)
    return shaped, keep_src, keep_dst, keep_svc


def _label_grouped(grouped: pd.DataFrame, codebook: _Codebook) -> pd.DataFrame:
    """Map final compact codes to their stable wire labels."""
    labeled = grouped.copy()
    for column, labels, target in (
        ("sc", codebook.src, "s"),
        ("dc", codebook.dst, "d"),
        ("vc", codebook.svc, "v"),
    ):
        labeled[target] = [
            _OTHER if int(code) < 0 else labels[int(code)]
            for code in labeled[column]
        ]
    return labeled.drop(columns=["sc", "dc", "vc"])


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
    scale.loc[over] = (_FLOAT32_MAX * 0.5) / absolute.loc[over]
    if over.any():
        safe.loc[over, "b"] = safe.loc[over, "b"] * scale.loc[over]
        cell_changed.loc[over & raw.ne(0)] = True

    # Values round once more when the player loads them into Float32Array.
    # The unconditional half-ceiling target leaves reordering headroom for
    # every player partition; this loop remains a representation tripwire.
    for bin_index, indexes in safe.groupby("bin", sort=False).groups.items():
        del bin_index
        values = safe.loc[indexes, "b"]
        if _float32_abs_sum_is_finite(values):
            continue
        safe.loc[indexes, "b"] = values * 0.5
        cell_changed.loc[indexes] |= values.ne(0)
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


def _band_loss(
    frame: pd.DataFrame, *, t0: float, render_end: float,
) -> dict[str, int] | None:
    """Compute finite hidden duration-band mass outside the render window."""
    ts = frame["ts"].to_numpy(dtype=float)
    dur = frame["dur"].to_numpy(dtype=float)
    metric = frame["metric"].to_numpy(dtype=float)
    with np.errstate(over="ignore", invalid="ignore"):
        ends = ts + dur
    positive = (dur > 0) & (metric > 0)
    lead_seconds = np.where(
        positive,
        np.clip(np.minimum(ends, t0) - ts, 0.0, dur),
        0.0,
    )
    trail_seconds = np.where(
        positive,
        np.clip(ends - render_end, 0.0, dur),
        0.0,
    )
    lead_fraction = np.divide(
        lead_seconds, dur, out=np.zeros_like(metric), where=dur > 0,
    )
    trail_fraction = np.divide(
        trail_seconds, dur, out=np.zeros_like(metric), where=dur > 0,
    )
    lead_mass = metric * lead_fraction
    trail_mass = metric * trail_fraction
    facts = {
        "lead_conns": int((lead_mass > 0).sum()),
        "lead_bytes": max(0, int(round(float(lead_mass.sum())))),
        "trail_conns": int((trail_mass > 0).sum()),
        "trail_bytes": max(0, int(round(float(trail_mass.sum())))),
    }
    if facts["lead_bytes"] == 0 and facts["trail_bytes"] == 0:
        return None
    return facts


def _format_band_loss_note(
    facts: dict[str, int], *, t0: float, render_end: float,
) -> str:
    """Render one exact builder-owned duration-band loss disclosure."""
    parts: list[str] = []
    if facts["lead_bytes"]:
        count = facts["lead_conns"]
        noun = plural(count, "connection", "connections")
        parts.append(
            f"{count} {noun} began before the retained window; "
            f"{human_bytes(facts['lead_bytes'])} not shown before "
            f"{_format_trim_boundary(t0)}"
        )
    if facts["trail_bytes"]:
        count = facts["trail_conns"]
        noun = plural(count, "connection", "connections")
        verb = "continues" if count == 1 else "continue"
        parts.append(
            f"{count} {noun} {verb} past the retained window end; "
            f"{human_bytes(facts['trail_bytes'])} not shown after "
            f"{_format_trim_boundary(render_end)}"
        )
    return "; ".join(parts)


def _format_straddler_note(count: int) -> str | None:
    """Render the exact retained pre-window count-relocation fact."""
    if count <= 0:
        return None
    noun = plural(count, "connection", "connections")
    verb = "is" if count == 1 else "are"
    return (
        f"{count} {noun} that began before the retained window {verb} drawn "
        "within it and counted at its edge"
    )


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
    if "dur" in df.columns:
        df["dur"] = df["dur"].map(_coerce_duration)
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
        if trim_result.retained_start_epoch is not None:
            df = trim_result.frame
            t0 = float(
                np.maximum(
                    df["ts"].to_numpy(dtype=float),
                    trim_result.retained_start_epoch,
                ).min()
            )
            t1 = float(df["ts"].max())
            span_seconds = t1 - t0
            requested_bin_seconds = pick_bin_seconds(
                span_seconds, config["target_bins"],
            )
    bin_seconds = requested_bin_seconds
    if "dur" in df.columns:
        while (
            _spread_fragment_count(
                df,
                t0=t0,
                t1=t1,
                bin_seconds=bin_seconds,
            )
            > GRAPH_MAX_SPREAD_FRAGMENTS
        ):
            next_width = _next_bin_seconds(bin_seconds, span_seconds)
            if next_width is None:
                break
            bin_seconds = next_width

    rankings = {
        column: _rank_values(df, column)
        for column in ("src", "dst", "svc")
    }
    coded, codebook = _factor_identities(df, rankings=rankings)
    basis = _build_raw_basis(
        coded,
        t0=t0,
        t1=t1,
        bin_seconds=bin_seconds,
        count_by=count_by,
    )

    def measure_for(host_limit: int, service_limit: int) -> _ShapeMeasure:
        return _measure_basis(
            basis,
            codebook=codebook,
            host_limit=host_limit,
            service_limit=service_limit,
        )

    host_limit = int(config["top_hosts"])
    service_limit = int(config["top_services"])
    state = measure_for(host_limit, service_limit)

    if state.flow_count > GRAPH_MAX_FLOWS:
        service_fit = _largest_fitting_limit(
            service_limit,
            lambda limit: measure_for(host_limit, limit).flow_count
            <= GRAPH_MAX_FLOWS,
        )
        if service_fit is not None:
            service_limit = service_fit
        else:
            service_limit = 1
            host_fit = _largest_fitting_limit(
                host_limit,
                lambda limit: measure_for(limit, service_limit).flow_count
                <= GRAPH_MAX_FLOWS,
            )
            # The 1/1 fold has at most eight grouped flows.
            host_limit = 1 if host_fit is None else host_fit
        state = measure_for(host_limit, service_limit)

    def fold_for_pairs(current: _ShapeMeasure) -> _ShapeMeasure:
        """Fold farther only when the terminal bin width cannot fit pairs."""
        nonlocal host_limit, service_limit
        service_fit = _largest_fitting_limit(
            service_limit,
            lambda limit: measure_for(
                host_limit, limit,
            ).payload_pairs <= GRAPH_MAX_PAYLOAD_PAIRS,
        )
        if service_fit is not None:
            service_limit = service_fit
        else:
            service_limit = 1
            host_fit = _largest_fitting_limit(
                host_limit,
                lambda limit: measure_for(
                    limit, service_limit,
                ).payload_pairs <= GRAPH_MAX_PAYLOAD_PAIRS,
            )
            host_limit = 1 if host_fit is None else host_fit
        return measure_for(host_limit, service_limit)

    while True:
        while state.payload_pairs > GRAPH_MAX_PAYLOAD_PAIRS:
            next_width = _next_bin_seconds(state.bin_seconds, span_seconds)
            if next_width is None:
                state = fold_for_pairs(state)
                break
            bin_seconds = next_width
            del basis
            basis = _build_raw_basis(
                coded,
                t0=t0,
                t1=t1,
                bin_seconds=bin_seconds,
                count_by=count_by,
            )
            state = measure_for(host_limit, service_limit)

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
        del basis
        basis = _build_raw_basis(
            coded,
            t0=t0,
            t1=t1,
            bin_seconds=bin_seconds,
            count_by=count_by,
        )
        state = measure_for(host_limit, service_limit)

    bins = state.bins
    bin_seconds = state.bin_seconds
    grouped_codes = _fold_basis(
        basis,
        codebook=codebook,
        host_limit=host_limit,
        service_limit=service_limit,
    )
    del basis
    df, keep_src, keep_dst, keep_svc = _shape_rows(
        coded,
        codebook=codebook,
        host_limit=host_limit,
        service_limit=service_limit,
        bin_seconds=bin_seconds,
        t0=t0,
        bins=bins,
    )
    grouped_labeled = _label_grouped(grouped_codes, codebook)
    del grouped_codes
    grouped, altered_metric_cells = _saturate_grouped_metrics(
        grouped_labeled, count_by=count_by,
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
    straddler_metric_note = payload_meta_extra.pop(
        "metric_note_with_straddlers", None,
    )
    retained_straddlers = trim_result.retained_straddlers
    if retained_straddlers and straddler_metric_note:
        payload_meta_extra["metric_note"] = straddler_metric_note
    straddler_note = _format_straddler_note(retained_straddlers)
    if straddler_note is not None:
        payload_meta_extra["retained_straddlers"] = retained_straddlers
        payload_meta_extra["straddler_note"] = straddler_note
    if payload_meta_extra.get("bands_active") is True and "dur" in coded.columns:
        render_end = t0 + bins * bin_seconds
        loss = _band_loss(coded, t0=t0, render_end=render_end)
        if loss is not None:
            payload_meta_extra["band_loss"] = loss
            payload_meta_extra["band_loss_note"] = _format_band_loss_note(
                loss, t0=t0, render_end=render_end,
            )
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
        "generator": version_string(),
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
