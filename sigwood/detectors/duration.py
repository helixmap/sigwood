"""Duration detector - long-lived connection detection from Zeek conn.log.

Flags connections that remain open for an unusually long time, which may indicate
tunneling, C2 keep-alive sessions, or data exfiltration channels.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import pandas as pd

from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity

DETECTOR_NAME = "duration"
STATUS = "available"
# Wall-clock duration alone is not corroborated evidence; keep this detector
# opt-in until its severity model earns default membership.
IN_DEFAULT_HUNT: bool = False

REQUIRED_LOGS = [
    {"source": "zeek_dir", "pattern": "conn*.log*"},
]

OPTIONAL_LOGS: list[dict] = []

DEFAULT_CONFIG = {
    "min_duration_seconds": 1800,
}

DETECTOR_METHOD = MethodTag("heuristics", named=False)

_DURATION_HIGH   = 14400  # 4 hours
_DURATION_MEDIUM = 7200   # 2 hours


def _duration_str(seconds: float) -> str:
    """Return a compact human-readable string for a duration in seconds."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        m, rem = divmod(s, 60)
        return f"{m}m {rem}s"
    if s < 86400:
        h, rem = divmod(s, 3600)
        return f"{h}h {rem // 60}m"
    d, rem = divmod(s, 86400)
    return f"{d}d {rem // 3600}h"


def _to_severity(duration: float) -> Severity:
    if duration >= _DURATION_HIGH:
        return Severity.HIGH
    if duration >= _DURATION_MEDIUM:
        return Severity.MEDIUM
    return Severity.LOW


def _is_non_unicast_dst(dst: str) -> bool:
    try:
        ip = ipaddress.ip_address(dst)
    except (ValueError, TypeError):
        return False
    return (
        ip.is_multicast
        or ip.is_link_local
        or (ip.version == 4 and str(ip) == "255.255.255.255")
    )


def run(context: DetectorContext) -> list[Finding]:
    """Flag flows exceeding the minimum duration threshold, grouped by (src, dst, port, proto)."""
    cfg: dict = {**DEFAULT_CONFIG, **context.config}
    min_dur = cfg["min_duration_seconds"]

    df = context.logs.get("conn*.log*")
    if df is None or df.empty:
        return []

    if "duration" not in df.columns:
        return []

    df = df.copy()
    df["duration"] = pd.to_numeric(df["duration"], errors="coerce")

    df = df[df["duration"].notna() & (df["duration"] > 0)]
    if df.empty:
        return []

    df = df[df["duration"] >= min_dur]
    if df.empty:
        return []

    # Normalize grouping keys. Port may be NaN; fill with sentinel so groupby
    # doesn't silently drop portless rows. dropna=False is a second safety net.
    for col in ("src", "dst", "proto"):
        if col not in df.columns:
            df[col] = ""
    if "port" in df.columns:
        df["port"] = pd.to_numeric(df["port"], errors="coerce")
    else:
        df["port"] = float("nan")
    df["_port_key"] = df["port"].fillna(-1).astype(int)

    findings: list[Finding] = []
    for (src, dst, port_key, proto), group in df.groupby(
            ["src", "dst", "_port_key", "proto"], sort=False, dropna=False):

        port: int | None = None if port_key == -1 else int(port_key)

        max_row = group.loc[group["duration"].idxmax()]
        max_dur = round(float(max_row["duration"]), 1)
        max_dur_str = _duration_str(max_dur)

        # total_bytes: None if column absent or all null
        if "bytes" in group.columns:
            bytes_series = group["bytes"].dropna()
            total_bytes: int | None = int(bytes_series.sum()) if not bytes_series.empty else None
        else:
            total_bytes = None

        # avg_bytes_per_second: derived from the max-duration row, not group total
        avg_bps: float | None
        if "bytes" in group.columns:
            row_bytes = max_row["bytes"]
            avg_bps = (
                round(float(row_bytes) / max_dur, 1)
                if pd.notna(row_bytes) and max_dur > 0
                else None
            )
        else:
            avg_bps = None

        # conn_states: distinct non-null values, sorted; empty list if column absent
        if "conn_state" in group.columns:
            states: list[str] = sorted(group["conn_state"].dropna().unique().tolist())
        else:
            states = []

        # first_seen / last_seen: UTC ISO strings from unix epoch seconds
        if "ts" in group.columns:
            ts_series = pd.to_numeric(group["ts"], errors="coerce").dropna()
        else:
            ts_series = pd.Series(dtype=float)
        if not ts_series.empty:
            first_seen: str | None = datetime.fromtimestamp(
                float(ts_series.min()), tz=timezone.utc
            ).isoformat()
            last_seen: str | None = datetime.fromtimestamp(
                float(ts_series.max()), tz=timezone.utc
            ).isoformat()
        else:
            first_seen = last_seen = None

        port_str = str(port) if port is not None else "?"
        title = f"{src} → {dst}:{port_str}/{proto}"

        severity = _to_severity(max_dur)
        non_unicast_dst = _is_non_unicast_dst(str(dst))
        if non_unicast_dst:
            severity = Severity.LOW

        if non_unicast_dst:
            description = (
                "A long-lived multicast, broadcast, or link-local connection was observed. "
                "This commonly reflects local service discovery, address assignment, or "
                "link-local infrastructure traffic."
            )
            next_steps = [
                f"Review {max_dur_str} connection in conn.log: zeek-cut id.orig_h id.resp_h id.resp_p duration conn_state < conn.log | grep {src}",
                "Confirm whether this local-scope destination is expected for "
                "service discovery, address assignment, or link-local infrastructure",
                "Add expected local-scope traffic to the allowlist if it repeats",
            ]
        else:
            description = (
                "A long-lived connection may indicate tunneling, a C2 keep-alive session, "
                "or an active data exfiltration channel."
            )
            next_steps = [
                f"Review {max_dur_str} connection in conn.log: zeek-cut id.orig_h id.resp_h id.resp_p duration conn_state < conn.log | grep {src}",
                "Check if this is expected infrastructure (VPN, backup, monitoring) - if so, add to allowlist",
                f"Check the destination: whois {dst}",
            ]

        findings.append(Finding(
            detector="duration",
            severity=severity,
            title=title,
            description=description,
            evidence={
                "src":                  src,
                "dst":                  dst,
                "port":                 port,
                "proto":                proto,
                "max_duration_seconds": max_dur,
                "max_duration_str":     max_dur_str,
                "connection_count":     len(group),
                "total_bytes":          total_bytes,
                "avg_bytes_per_second": avg_bps,
                "conn_states":          states,
                "first_seen":           first_seen,
                "last_seen":            last_seen,
            },
            next_steps=next_steps,
            ts_generated=datetime.now(tz=timezone.utc),
            data_window=context.data_window,
        ))

    findings.sort(key=lambda f: f.evidence["max_duration_seconds"], reverse=True)
    return findings
