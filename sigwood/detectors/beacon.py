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
- Peak prominence: peak power relative to local spectral noise floor, normalized at 100x
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
from datetime import datetime, timezone
from typing import Any

import numpy as np

from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity

DETECTOR_NAME = "beacon"
STATUS = "available"

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

# Fallback internal networks when the operator declares no home_net (mirrors scan).
_DEFAULT_HOME_NET = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# Non-established-share disclosure thresholds. The runner reads these to fire one
# RunSummary note; a single source, never re-derived. The note fires when the loaded
# conn frame has at least _NON_ESTABLISHED_NOTE_MIN_ROWS rows and the non-established
# share reaches _NON_ESTABLISHED_NOTE_SHARE.
_NON_ESTABLISHED_NOTE_MIN_ROWS = 1000
_NON_ESTABLISHED_NOTE_SHARE = 0.5

# Reliable beaconing detection needs roughly a week of span: a jittered periodic flow
# clears the score threshold only ~13% of the time given a single day of data but ~100%
# given seven. The runner reads this constant to disclose an inadequate analysis span; a
# single source, never re-derived.
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

        findings.append(_make_finding(
            str(src), str(dst), int(port), str(proto),
            score_data, group, context.data_window,
        ))

    findings.sort(key=lambda f: f.evidence["beacon_score"], reverse=True)
    return findings


def _filter_conn(df: Any, home_net: list[str]) -> Any:
    """Apply beacon pre-filters: established conns, no non-unicast dst/src, local origin.

    Masks derived from ``.map`` are cast to bool so an empty post-conn_state frame stays a
    boolean mask. An empty object-dtype series used in ``df[...]`` is read by pandas as
    column selection, collapsing the frame to zero columns, after which ``df["src"]`` raises
    KeyError. The cast keeps the mask boolean and empty-safe; the same reason the
    effective-local mask below stays chained to its ``.astype(bool)``.

    Origin is effective-local: ``local_orig`` decides when set (a False value stays excluded -
    the sensor wins when it speaks); when null or absent, membership of ``src`` in ``home_net``
    decides. This mirrors the blend in the conn digest so a sensor without local-network
    config (all-null ``local_orig``) is not blind.
    """
    df = df[df["conn_state"].isin(["SF", "S1"])].copy()
    if df.empty:
        return df
    df = df[~df["dst"].map(_is_non_unicast).astype(bool)]
    df = df[~df["src"].map(_is_non_unicast).astype(bool)]
    src_internal = df["src"].map(lambda ip: _ip_in_home_net(ip, home_net))
    if "local_orig" not in df.columns:
        effective_local = src_internal.astype(bool)
    else:
        lo = df["local_orig"]
        effective_local = lo.where(lo.notna(), src_internal).astype(bool)
    df = df[effective_local]
    df = df[df["bytes"].notna()]
    return df


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
    """Count connections not in an established state, over the total loaded.

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
    periodic flows. Prominence measures peak power above the local noise floor,
    robust to harmonic spreading.
    """
    if len(ts_array) < 10:
        return None

    t_start = ts_array.min()
    t_end = ts_array.max()
    n_bins = int((t_end - t_start) / bin_size) + 1

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
    peak_power = float(fft_mag[peak_idx])
    total_power = float(fft_mag[1:].sum())
    if total_power == 0:
        return None

    spectral_ratio = peak_power / total_power

    window = max(10, int(peak_idx * 0.05))
    lo = max(1, peak_idx - window)
    hi = min(len(fft_mag) - 1, peak_idx + window)
    local = np.concatenate([fft_mag[lo:peak_idx], fft_mag[peak_idx + 1:hi + 1]])
    noise_floor = float(np.median(local)) if len(local) > 0 else 1.0
    prominence = peak_power / (noise_floor + 1e-10)
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


def _make_finding(
    src: str,
    dst: str,
    port: int,
    proto: str,
    score_data: dict[str, Any],
    group: Any,
    data_window: tuple[datetime, datetime],
) -> Finding:
    score = score_data["beacon_score"]
    period_s = score_data["dominant_period"]
    period_m = score_data["dominant_period_m"]
    conn_count = score_data["conn_count"]

    if score >= 0.7:
        severity = Severity.HIGH
    elif score >= 0.5:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    period_str = f"{period_m:.1f}m" if period_m >= 2 else f"{period_s:.0f}s"
    title = f"{src} → {dst}:{port}/{proto}"

    bytes_s = group["bytes"].dropna()
    bytes_mean = round(float(bytes_s.mean()), 1) if len(bytes_s) > 0 else 0.0

    description = (
        f"Connections recur on a near-fixed {period_str} period - the regular "
        "cadence of an automated check-in or C2 beacon."
    )

    next_steps = [
        f"Identify the process on {src} making connections every {period_str}",
        f"Pivot to dns.log - search for lookups resolving to {dst}",
        f"Check {dst} on VirusTotal, Shodan, and ASN lookup",
        f"Review full history: zeek-cut id.orig_h id.resp_h id.resp_p ts | grep '{dst}'",
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
