"""Beacon detector - FFT-based periodic connection detection.

Algorithm:
- Bin connection timestamps into 30-second intervals. The bin size sets the FFT's
  Nyquist floor at twice the bin: nothing faster than a 60s cadence is representable,
  a sub-60s cadence aliases to a longer reported period, and a cadence exactly at the
  floor scores anchor-sensitively (arrivals of a bin-multiple cadence sit on bin
  boundaries, so identical flows can score far apart). bin_seconds is a calibration
  constant - threshold, period band, and the reference calibration are tuned to 30s.
- Compute FFT over the binned time grid (resilient to data gaps vs raw inter-arrival)
- Composite score: 40% spectral ratio + 40% peak prominence + 20% inverted jitter CV
- Peak prominence: peak magnitude relative to the local spectral noise floor, normalized at 100x
- Jitter CV computed on outlier-cleaned inter-arrival deltas
- Minimum 20 connections per candidate flow

Reference calibration: the demo corpus's seeded 180-second beacon (480 connections
over 24 hours) scores ~0.62 with dominant period exactly 180.0s - a single-day,
favorable-realization figure. Resolving a jittered periodic beacon needs about a week
of span; at a single day the same cadence clears the threshold only intermittently. A
60s cadence sits at the band edge and scores anchor-sensitively.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Callable
from datetime import datetime, timezone
from numbers import Real
from typing import Any

import numpy as np
import pandas as pd

from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity

DETECTOR_NAME = "beacon"
STATUS = "available"
IN_DEFAULT_HUNT: bool = True

REQUIRED_LOGS = [
    {"source": "zeek_dir", "pattern": "conn*.log*"},
]

OPTIONAL_LOGS: list[dict] = []

DEFAULT_CONFIG = {
    "threshold": 0.5,
    "min_connections": 20,
    "bin_seconds": 30,
}

DETECTOR_METHOD = MethodTag("FFT", named=True)

# Period range to consider (seconds). Outside this, FFT peaks are ignored.
_MIN_PERIOD = 45
_MAX_PERIOD = 7200
_MIN_SCORABLE_SAMPLES = 10

# Scoring holds several bin-proportional arrays at once: full-width counts and
# normalized counts, plus half-width magnitudes, frequencies, periods, masks,
# and masked magnitudes, with additional NumPy transients. That is on the order
# of 30-40 bytes per bin, so this ceiling keeps dense working memory around
# 150-200 MB. At the default 30-second bin size it permits about 4.75 years.
_MAX_SCORABLE_BINS = 5_000_000

# Beacon-required scoring columns, in the stable order used by runner disclosure.
# Several are canonically optional/nullable Zeek fields; absence is a fidelity
# limitation that makes this detector abstain, not a malformed-log error.
_REQUIRED_SCORING_COLUMNS = (
    "conn_state",
    "bytes",
    "src",
    "dst",
    "port",
    "proto",
    "ts",
)
_GROUPING_COLUMNS = ("src", "dst", "port", "proto")

# Fallback internal networks when the operator declares no home_net (mirrors scan).
_DEFAULT_HOME_NET = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# Non-established-share disclosure thresholds. The runner reads these to fire one
# RunSummary note; a single source, never re-derived. The note fires when the loaded
# conn frame has at least _NON_ESTABLISHED_NOTE_MIN_ROWS rows and the non-established
# share reaches _NON_ESTABLISHED_NOTE_SHARE.
_NON_ESTABLISHED_NOTE_MIN_ROWS = 1000
_NON_ESTABLISHED_NOTE_SHARE = 0.5

# Reliable beaconing detection needs roughly a week of span: a jittered periodic flow
# clears the score threshold only intermittently on a single day of data but reliably
# across seven. The runner reads this constant to disclose an inadequate analysis span;
# a single source, never re-derived.
_MIN_RELIABLE_SPAN_DAYS = 7


def run(context: DetectorContext) -> list[Finding]:
    """Detect beaconing flows using FFT on binned connection timestamps."""
    cfg = context.config
    threshold: float = cfg.get("threshold", DEFAULT_CONFIG["threshold"])
    min_conns: int = cfg.get("min_connections", DEFAULT_CONFIG["min_connections"])
    bin_size: int = cfg.get("bin_seconds", DEFAULT_CONFIG["bin_seconds"])

    df = context.logs.get("conn*.log*")
    if df is None or df.empty:
        return []
    if _missing_scoring_columns(df):
        return []

    home_net = list(context.home_net) if context.home_net else list(_DEFAULT_HOME_NET)
    df = _filter_conn(df, home_net)
    if df.empty:
        return []

    findings: list[Finding] = []

    for (src, dst, port, proto), group in df.groupby(["src", "dst", "port", "proto"]):
        if len(group) < min_conns:
            continue

        ts_arr = group["ts"].sort_values().to_numpy(dtype=float)
        score_data = _compute_beacon_score(ts_arr, bin_size)
        if score_data is None or score_data["beacon_score"] < threshold:
            continue

        first_ts, last_ts = _finite_ts_bounds(group["ts"])
        time_evidence = _event_time_evidence(first_ts, last_ts)
        findings.append(_make_finding(
            str(src), str(dst), int(port), str(proto),
            score_data, group, context.data_window,
            time_evidence=time_evidence,
        ))

    findings.sort(key=lambda f: f.evidence["beacon_score"], reverse=True)
    return findings


def _filter_conn(df: Any, home_net: list[str]) -> Any:
    """Apply beacon scoring gates: state, addresses, local origin, bytes, grouping keys.

    Classifier masks stay indexed boolean Series so an empty post-conn_state frame remains a
    row mask. An empty object-dtype series used in ``df[...]`` is read by pandas as column
    selection, collapsing the frame to zero columns, after which ``df["src"]`` raises
    KeyError. The explicit boolean shape keeps masks empty-safe; the same reason the
    effective-local mask below stays chained to its ``.astype(bool)``.

    Origin is effective-local: ``local_orig`` decides when set (a False value stays excluded -
    the sensor wins when it speaks); when null or absent, membership of ``src`` in ``home_net``
    decides. This mirrors the blend in the conn digest so a sensor without local-network
    config (all-null ``local_orig``) is not blind.
    """
    if _missing_scoring_columns(df):
        return _empty_frame_like(df)
    filtered, _facts = _apply_scoring_eligibility(df, home_net)
    return filtered


def _missing_scoring_columns(df: Any) -> tuple[str, ...]:
    """Return absent Beacon-required columns in the module's stable order."""
    try:
        columns = df.columns
    except Exception:
        return _REQUIRED_SCORING_COLUMNS
    return tuple(column for column in _REQUIRED_SCORING_COLUMNS if column not in columns)


def _empty_frame_like(df: Any) -> Any:
    """Return an empty slice that preserves a frame's columns when possible."""
    try:
        return df.iloc[0:0].copy()
    except Exception:
        return pd.DataFrame()


def _no_measurement_facts(
    *,
    missing_columns: tuple[str, ...] = (),
    rows_total: int = 0,
) -> dict[str, int | tuple[str, ...]]:
    """Complete eligibility shape for absent or unreadable input."""
    return {
        "missing_columns": missing_columns,
        "rows_total": rows_total,
        "rows_after_state": 0,
        "rows_before_bytes": 0,
        "rows_after_bytes": 0,
        "rows_before_keys": 0,
        "rows_after_keys": 0,
    }


def _classify_distinct(
    series: pd.Series,
    classifier: Callable[[object], bool],
) -> pd.Series:
    """Classify each distinct hashable value once, preserving scalar tolerance."""
    try:
        codes, uniques = pd.factorize(series)
    except (TypeError, ValueError):
        return series.map(classifier).astype(bool)

    answers = np.asarray(
        [classifier(value) for value in uniques],
        dtype=bool,
    )
    missing_answer = bool(classifier(None))
    result = np.full(len(codes), missing_answer, dtype=bool)
    present = codes >= 0
    if answers.size:
        result[present] = answers[codes[present]]
    return pd.Series(result, index=series.index, dtype=bool)


def _apply_scoring_eligibility(
    df: Any,
    home_net: list[str],
) -> tuple[Any, dict[str, int | tuple[str, ...]]]:
    """Apply Beacon's existing gates once and return the surviving frame + counts."""
    rows_total = len(df)
    df = df[df["conn_state"].isin(["SF", "S1"])].copy()
    rows_after_state = len(df)
    if df.empty:
        facts = _no_measurement_facts(rows_total=rows_total)
        facts["rows_after_state"] = rows_after_state
        return df, facts
    df = df[~_classify_distinct(df["dst"], _is_non_unicast)]
    df = df[~_classify_distinct(df["src"], _is_non_unicast)]
    src_internal = _classify_distinct(
        df["src"],
        lambda ip: _ip_in_home_net(ip, home_net),
    )
    if "local_orig" not in df.columns:
        effective_local = src_internal.astype(bool)
    else:
        lo = df["local_orig"]
        effective_local = lo.where(lo.notna(), src_internal).astype(bool)
    df = df[effective_local]
    rows_before_bytes = len(df)
    df = df[df["bytes"].notna()]
    rows_after_bytes = len(df)
    rows_before_keys = rows_after_bytes
    df = df[df[list(_GROUPING_COLUMNS)].notna().all(axis=1)]
    rows_after_keys = len(df)
    return df, {
        "missing_columns": (),
        "rows_total": rows_total,
        "rows_after_state": rows_after_state,
        "rows_before_bytes": rows_before_bytes,
        "rows_after_bytes": rows_after_bytes,
        "rows_before_keys": rows_before_keys,
        "rows_after_keys": rows_after_keys,
    }


def scoring_eligibility(
    df: Any,
    home_net: list[str] | None = None,
) -> dict[str, int | tuple[str, ...]]:
    """Return defensive facts about rows surviving each Beacon scoring gate.

    The runner calls this before the detector loop on Beacon's post-allowlist view,
    so it must never raise. ``home_net`` is optional for the public one-argument
    contract; omission uses the same RFC1918 fallback as ``run``.
    """
    missing = _missing_scoring_columns(df)
    try:
        rows_total = len(df)
    except Exception:
        rows_total = 0
    if missing:
        return _no_measurement_facts(
            missing_columns=missing,
            rows_total=rows_total,
        )
    networks = list(home_net) if home_net else list(_DEFAULT_HOME_NET)
    try:
        _filtered, facts = _apply_scoring_eligibility(df, networks)
    except Exception:
        return _no_measurement_facts(rows_total=rows_total)
    return facts


def validate_config(cfg: dict) -> None:
    """Validate Beacon's overlaid tuning section without reading config files."""
    if not isinstance(cfg, dict):
        raise ValueError("[detectors.beacon] must be a table")

    threshold = cfg.get("threshold", DEFAULT_CONFIG["threshold"])
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, Real)
        or not math.isfinite(float(threshold))
        or not 0 < threshold <= 1
    ):
        raise ValueError(
            "[detectors.beacon].threshold must be a finite number greater than 0 "
            "and at most 1"
        )

    min_connections = cfg.get("min_connections", DEFAULT_CONFIG["min_connections"])
    if (
        isinstance(min_connections, bool)
        or not isinstance(min_connections, int)
        or min_connections < 1
    ):
        raise ValueError(
            "[detectors.beacon].min_connections must be a positive integer"
        )

    bin_seconds = cfg.get("bin_seconds", DEFAULT_CONFIG["bin_seconds"])
    if (
        isinstance(bin_seconds, bool)
        or not isinstance(bin_seconds, int)
        or bin_seconds < 1
    ):
        raise ValueError(
            "[detectors.beacon].bin_seconds must be a positive integer"
        )


def _is_non_unicast(ip: object) -> bool:
    """True for a multicast, link-local, or IPv4 limited-broadcast address.

    Uses the stdlib ipaddress classifier, never a string prefix: an endswith(".255")
    test over-fires on a unicast ".255" host in a network wider than /24 (dropping a
    real beacon before it scores) and misses IPv4 link-local 169.254/16. is_link_local
    subsumes both fe80::/10 and 169.254/16; the limited broadcast is exactly
    255.255.255.255.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return (
        addr.is_multicast
        or addr.is_link_local
        or (addr.version == 4 and str(addr) == "255.255.255.255")
    )


def _ip_in_home_net(ip: object, home_net: list[str]) -> bool:
    """True iff ip is a string parsable as an address inside any home_net network.

    Non-string, empty, and unparsable values are not internal - the same guard shape the
    conn digest uses, so a NaN or malformed address never raises.
    """
    if not isinstance(ip, str) or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n, strict=False) for n in home_net)


def non_established_share(df: Any) -> tuple[int, int]:
    """Count connections outside the Zeek SF/S1 states beacon analyzes, over the total loaded.

    Defensive: returns ``(0, total)`` when ``conn_state`` is absent, so the runner's
    pre-loop disclosure - which runs outside the detector's error containment - never raises
    on a frame missing the optional ``conn_state`` column. A zero count is below the
    disclosure gate, so the no-disclosure shape emits no note.
    """
    total = len(df)
    if "conn_state" not in df.columns:
        return (0, total)
    non_est = int((~df["conn_state"].isin(["SF", "S1"])).sum())
    return (non_est, total)


def analyzed_span_seconds(df: Any) -> float:
    """Seconds between the earliest and latest finite timestamp in the loaded conn frame.

    Defensive by contract: read by the runner's pre-loop span disclosure, outside the
    detector's error containment. An absent ``ts`` column, non-numeric or non-finite
    values, an empty or single-row frame, or an unexpected input shape all yield 0.0 -
    the no-measurement sentinel, distinct from a genuine short span.
    """
    try:
        if "ts" not in df.columns:
            return 0.0
        ts = np.asarray(df["ts"].to_numpy(), dtype="float64")
    except Exception:
        return 0.0
    ts = ts[np.isfinite(ts)]
    if ts.size < 2:
        return 0.0
    return float(ts.max() - ts.min())


def _compute_beacon_score(
    ts_array: np.ndarray,
    bin_size: int = 30,
) -> dict[str, Any] | None:
    """Score a single flow's connection timestamps for periodic beaconing via FFT.

    Returns None if the flow cannot be scored (too few points, no variance, no
    dominant period in the configured range).

    Why binning over raw inter-arrival deltas: gaps produce delta outliers that
    corrupt FFT results; binning represents gaps as zero-count bins, preserving
    the periodicity signal.

    Why prominence alongside spectral ratio: sparse binary signals spread energy
    across harmonics, keeping the absolute spectral ratio low even for perfectly
    periodic flows. Prominence measures peak magnitude above the local noise floor,
    robust to harmonic spreading.
    """
    if len(ts_array) < _MIN_SCORABLE_SAMPLES:
        return None

    t_start = ts_array.min()
    t_end = ts_array.max()
    n_bins = int((t_end - t_start) / bin_size) + 1
    if n_bins > _MAX_SCORABLE_BINS:
        return None

    bin_idx = ((ts_array - t_start) / bin_size).astype(int)
    counts = np.zeros(n_bins)
    np.add.at(counts, bin_idx, 1)

    std = counts.std()
    if std == 0:
        return None
    counts_norm = (counts - counts.mean()) / std

    fft_mag = np.abs(np.fft.rfft(counts_norm))
    freqs = np.fft.rfftfreq(n_bins, d=bin_size)
    fft_mag[0] = 0  # zero DC component

    with np.errstate(divide="ignore"):
        periods = np.where(freqs > 0, 1.0 / freqs, np.inf)

    mask = (periods >= _MIN_PERIOD) & (periods <= _MAX_PERIOD)
    fft_masked = np.where(mask, fft_mag, 0)
    if fft_masked.max() == 0:
        return None

    peak_idx = int(fft_masked.argmax())
    peak_period = float(periods[peak_idx])
    peak_magnitude = float(fft_mag[peak_idx])
    total_magnitude = float(fft_mag[1:].sum())
    if total_magnitude == 0:
        return None

    spectral_ratio = peak_magnitude / total_magnitude

    window = max(10, int(peak_idx * 0.05))
    lo = max(1, peak_idx - window)
    hi = min(len(fft_mag) - 1, peak_idx + window)
    local = np.concatenate([fft_mag[lo:peak_idx], fft_mag[peak_idx + 1:hi + 1]])
    noise_floor = float(np.median(local)) if len(local) > 0 else 1.0
    prominence = peak_magnitude / (noise_floor + 1e-10)
    prominence_norm = min(prominence / 100.0, 1.0)

    deltas = np.diff(ts_array)
    d_mean = deltas.mean()
    d_std = deltas.std()
    if d_std == 0:
        jitter_cv = 0.0
    else:
        clean_deltas = deltas[np.abs(deltas - d_mean) < 3 * d_std]
        if len(clean_deltas) > 1 and clean_deltas.mean() > 0:
            jitter_cv = float(clean_deltas.std() / clean_deltas.mean())
        else:
            jitter_cv = 1.0

    beacon_score = (
        0.4 * spectral_ratio +
        0.4 * prominence_norm +
        0.2 * (1.0 - min(jitter_cv, 1.0))
    )

    return {
        "beacon_score": round(beacon_score, 4),
        "dominant_period": round(peak_period, 1),
        "dominant_period_m": round(peak_period / 60, 2),
        "spectral_ratio": round(spectral_ratio, 4),
        "prominence": round(prominence, 2),
        "prominence_norm": round(prominence_norm, 4),
        "jitter_cv": round(jitter_cv, 4),
        "conn_count": len(ts_array),
        "occupancy": round(float((counts > 0).sum()) / n_bins, 4),
    }


def _finite_ts_bounds(values: Any) -> tuple[float | None, float | None]:
    """Return the finite numeric timestamp extrema, or no bounds."""
    if values is None:
        return None, None
    numeric = pd.to_numeric(values, errors="coerce")
    finite = numeric[np.isfinite(numeric)]
    if len(finite) == 0:
        return None, None
    return float(finite.min()), float(finite.max())


def _event_time_evidence(
    first_ts: Any,
    last_ts: Any,
) -> dict[str, str | float | None]:
    """Project numeric event bounds into the beacon evidence contract."""
    try:
        first = float(first_ts)
        last = float(last_ts)
    except (TypeError, ValueError, OverflowError):
        first = last = math.nan
    if not math.isfinite(first) or not math.isfinite(last):
        return {
            "first_seen": None,
            "last_seen": None,
            "span_seconds": None,
        }
    try:
        first_seen = datetime.fromtimestamp(first, timezone.utc).isoformat()
        last_seen = datetime.fromtimestamp(last, timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return {
            "first_seen": None,
            "last_seen": None,
            "span_seconds": None,
        }
    return {
        "first_seen": first_seen,
        "last_seen": last_seen,
        "span_seconds": float(last - first),
    }


def _make_finding(
    src: str,
    dst: str,
    port: int,
    proto: str,
    score_data: dict[str, Any],
    group: Any,
    data_window: tuple[datetime, datetime],
    time_evidence: dict[str, str | float | None] | None = None,
) -> Finding:
    score = score_data["beacon_score"]
    period_s = score_data["dominant_period"]
    period_m = score_data["dominant_period_m"]
    conn_count = score_data["conn_count"]

    # Severity caps at MEDIUM: the composite is timing evidence from one category, and
    # HIGH requires corroboration from an independent evidence category that beacon's
    # timing analysis cannot supply alone. Do not reintroduce a score band to HIGH.
    if score >= 0.5:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    period_str = f"{period_m:.1f}m" if period_m >= 2 else f"{period_s:.0f}s"
    title = f"{src} → {dst}:{port}/{proto}"

    bytes_s = group["bytes"].dropna()
    bytes_mean = round(float(bytes_s.mean()), 1) if len(bytes_s) > 0 else 0.0

    if time_evidence is None:
        time_evidence = {
            "first_seen": None,
            "last_seen": None,
            "span_seconds": None,
        }
    span_seconds = time_evidence["span_seconds"]
    cycles: float | None = None
    try:
        span = float(span_seconds) if span_seconds is not None else math.nan
        period = float(period_s)
    except (TypeError, ValueError, OverflowError):
        span = period = math.nan
    if math.isfinite(span) and math.isfinite(period) and period > 0:
        cycles = round(span / period, 1)

    description = (
        f"Connections recur on a near-fixed {period_str} period - the regular "
        "cadence of an automated check-in."
    )

    next_steps = [
        f"Identify the process on {src} making connections every {period_str}",
        f"Pivot to dns.log - search for lookups resolving to {dst}",
        f"Review the full connection history for {dst} in conn.log",
        f"Check {dst} on VirusTotal, Shodan, and ASN lookup",
        "Review allowlist controls: sigwood allowlist",
    ]

    evidence = {
        **score_data,
        "period_str": period_str,
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "proto": proto,
        "bytes_mean": bytes_mean,
        **time_evidence,
        "cycles": cycles,
    }

    return Finding(
        detector=DETECTOR_NAME,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        next_steps=next_steps,
        ts_generated=datetime.now(timezone.utc),
        data_window=data_window,
    )
