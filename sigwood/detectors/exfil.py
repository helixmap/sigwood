"""Bulk outbound-transfer detection from Zeek connection logs.

The detector identifies local-to-external address pairs whose complete-byte
connection rows carry substantial originator-dominant byte volume.  It keeps
row eligibility, aggregation, and evidence derivation here; suppression,
run-level disclosures, and rendering belong to their respective owners.
"""

from __future__ import annotations

import ipaddress
import math
import shlex
from datetime import datetime, timezone
from numbers import Real
from typing import Any

import numpy as np
import pandas as pd

from sigwood.common.display import human_bytes
from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity
from sigwood.common.topology import IPAddress, in_home_net, is_non_routable, parse_address

DETECTOR_NAME = "exfil"
STATUS = "available"
IN_DEFAULT_HUNT: bool = True

REQUIRED_LOGS = [
    {"source": "zeek_dir", "pattern": "conn*.log*"},
]

OPTIONAL_LOGS: list[dict] = []

DEFAULT_CONFIG = {
    "min_outbound_bytes": 1 << 30,
    "min_orig_share": 0.6,
}

DETECTOR_METHOD = MethodTag("heuristics", named=False)

_REQUIRED_SCORING_COLUMNS = ("src", "dst", "bytes", "resp_bytes")
_DEFAULT_HOME_NET = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
# Frozen calibration values, not operator configuration: a rotating destination
# pool folds only when four already-surfaced pairs share one canonical network.
DESTINATION_POOL_FOLD_COUNT = 4
_DESTINATION_POOL_PREFIX = {4: 20, 6: 40}


def validate_config(cfg: dict) -> None:
    """Validate an overlaid exfil detector configuration without mutation."""
    if not isinstance(cfg, dict):
        raise ValueError("[detectors.exfil] must be a table")

    minimum = cfg.get("min_outbound_bytes", DEFAULT_CONFIG["min_outbound_bytes"])
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        raise ValueError(
            "[detectors.exfil].min_outbound_bytes must be a positive integer"
        )

    share = cfg.get("min_orig_share", DEFAULT_CONFIG["min_orig_share"])
    if (
        isinstance(share, bool)
        or not isinstance(share, Real)
        or not math.isfinite(float(share))
        or not 0 < float(share) <= 1
    ):
        raise ValueError(
            "[detectors.exfil].min_orig_share must be a finite number greater than "
            "0 and at most 1"
        )


def _empty_facts(
    *,
    missing_columns: tuple[str, ...] = (),
    rows_total: int = 0,
) -> dict[str, Any]:
    """Return the complete no-measurement eligibility shape."""
    return {
        "missing_columns": missing_columns,
        "rows_total": rows_total,
        "rows_after_parse": 0,
        "rows_after_local": 0,
        "rows_after_external": 0,
        "rows_after_byte_pairing": 0,
        "pairs_surviving": 0,
        "partial_pairs": {},
    }


def _missing_scoring_columns(df: Any) -> tuple[str, ...]:
    """Return absent required scoring columns in stable disclosure order."""
    try:
        columns = df.columns
    except Exception:
        return _REQUIRED_SCORING_COLUMNS
    return tuple(column for column in _REQUIRED_SCORING_COLUMNS if column not in columns)


def _finite_nonnegative(series: pd.Series) -> pd.Series:
    """Coerce a series to finite non-negative numbers while excluding booleans."""
    def clean(value: object) -> float:
        if isinstance(value, (bool, np.bool_)):
            return float("nan")
        try:
            numeric = float(value)
        except (TypeError, ValueError, OverflowError):
            return float("nan")
        return numeric if math.isfinite(numeric) and numeric >= 0 else float("nan")

    return series.map(clean)


def _port_proto_label(port: object, proto: object) -> str:
    """Render one service key without making missing values look measured."""
    numeric_port = pd.to_numeric(pd.Series([port]), errors="coerce").iloc[0]
    if pd.notna(numeric_port) and np.isfinite(numeric_port):
        port_text = str(int(numeric_port)) if float(numeric_port).is_integer() else str(numeric_port)
    else:
        port_text = "?"
    proto_text = "?" if pd.isna(proto) else str(proto)
    return f"{port_text}/{proto_text}"


def _port_mix(group: pd.DataFrame) -> str:
    """Return the three largest measured outbound services in deterministic order."""
    labels = [
        _port_proto_label(port, proto)
        for port, proto in zip(group.get("port", pd.Series(index=group.index)),
                               group.get("proto", pd.Series(index=group.index)))
    ]
    by_service: dict[str, float] = {}
    for label, value in zip(labels, group["_orig_bytes"]):
        by_service[label] = by_service.get(label, 0.0) + float(value)
    ranked = sorted(by_service.items(), key=lambda item: (-item[1], item[0]))[:3]
    return ", ".join(f"{label} ({human_bytes(total)})" for label, total in ranked)


def _time_evidence(group: pd.DataFrame) -> tuple[str | None, str | None, float | None]:
    """Return finite timestamp bounds and span, or all ``None`` when unavailable."""
    if "ts" not in group.columns:
        return None, None, None
    numeric = pd.to_numeric(group["ts"], errors="coerce")
    numeric = numeric[numeric.notna() & np.isfinite(numeric)]
    if numeric.empty:
        return None, None, None
    first = float(numeric.min())
    last = float(numeric.max())
    return (
        datetime.fromtimestamp(first, tz=timezone.utc).isoformat(),
        datetime.fromtimestamp(last, tz=timezone.utc).isoformat(),
        last - first,
    )


def _max_duration(group: pd.DataFrame) -> float | None:
    """Return the largest finite positive duration from complete-byte rows."""
    if "duration" not in group.columns:
        return None
    numeric = pd.to_numeric(group["duration"], errors="coerce")
    numeric = numeric[numeric.notna() & np.isfinite(numeric) & (numeric > 0)]
    return None if numeric.empty else float(numeric.max())


def _surface_pair(orig_bytes: float, resp_bytes: float, cfg: dict) -> bool:
    """Apply the two absolute gates to one pair-level byte population."""
    total = orig_bytes + resp_bytes
    return (
        orig_bytes >= cfg["min_outbound_bytes"]
        and total > 0
        and (orig_bytes / total) >= cfg["min_orig_share"]
    )


def _destination_pool_network(
    address: object,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Return the explicit rollup network for one already-normalized address."""
    if not isinstance(address, IPAddress):
        raise TypeError("destination pool address must be parsed")
    return ipaddress.ip_network(
        f"{address}/{_DESTINATION_POOL_PREFIX[address.version]}", strict=False,
    )


def _pair_summary(
    src: str,
    dst: str,
    group: pd.DataFrame,
    cfg: dict,
) -> dict[str, Any] | None:
    """Measure one pair once for either its pair or pooled finding shape."""
    orig_total = float(group["_orig_bytes"].sum())
    resp_total = float(group["_resp_bytes"].sum())
    if not _surface_pair(orig_total, resp_total, cfg):
        return None
    total = orig_total + resp_total
    first_seen, last_seen, span_seconds = _time_evidence(group)
    return {
        "src": str(src),
        "dst": str(dst),
        "destination_ip": group["_dst_ip"].iloc[0],
        "group": group,
        "orig_bytes_total": orig_total,
        "resp_bytes_total": resp_total,
        "orig_share": round(orig_total / total, 4),
        "connection_count": len(group),
        "port_mix": _port_mix(group),
        "span_seconds": span_seconds,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "max_duration_seconds": _max_duration(group),
    }


def _pair_next_steps(src: str, dst: str) -> list[str]:
    """Build pair commands with every log-derived value quoted at composition."""
    return [
        "Review the measured transfer in conn.log: zeek-cut id.orig_h id.resp_h "
        f"id.resp_p orig_bytes resp_bytes < conn.log | grep {shlex.quote(src)}",
        f"Check destination ownership: whois {shlex.quote(dst)}",
        "Confirm whether the transfer is an expected backup, sync, or upload",
        "Add an expected recurring pair to the allowlist",
    ]


def _pair_finding(summary: dict[str, Any], context: DetectorContext) -> Finding:
    """Build the legacy pair shape byte-for-byte from its single measurement."""
    src = summary["src"]
    dst = summary["dst"]
    return Finding(
        detector=DETECTOR_NAME,
        severity=Severity.MEDIUM,
        title=f"{src} → {dst}",
        description=(
            "Complete-byte connection rows show originator-dominant traffic to an "
            "external destination, which resembles bulk data transfer."
        ),
        evidence={
            "src": src,
            "dst": dst,
            "orig_bytes_total": summary["orig_bytes_total"],
            "resp_bytes_total": summary["resp_bytes_total"],
            "orig_share": summary["orig_share"],
            "connection_count": summary["connection_count"],
            "port_mix": summary["port_mix"],
            "span_seconds": summary["span_seconds"],
            "first_seen": summary["first_seen"],
            "last_seen": summary["last_seen"],
            "max_duration_seconds": summary["max_duration_seconds"],
        },
        next_steps=_pair_next_steps(src, dst),
        ts_generated=datetime.now(tz=timezone.utc),
        data_window=context.data_window,
    )


def _rollup_finding(
    src: str,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    summaries: list[dict[str, Any]],
    context: DetectorContext,
) -> Finding:
    """Build one lossless finding for a folded rotating destination pool."""
    represented = pd.concat([summary["group"] for summary in summaries])
    orig_total = sum(float(summary["orig_bytes_total"]) for summary in summaries)
    resp_total = sum(float(summary["resp_bytes_total"]) for summary in summaries)
    total = orig_total + resp_total
    members = [
        {
            "dst": summary["dst"],
            "orig_bytes": summary["orig_bytes_total"],
            "resp_bytes": summary["resp_bytes_total"],
            "orig_share": summary["orig_share"],
            "connection_count": summary["connection_count"],
            "port_mix": summary["port_mix"],
            "span_seconds": summary["span_seconds"],
            "first_seen": summary["first_seen"],
            "last_seen": summary["last_seen"],
            "max_duration_seconds": summary["max_duration_seconds"],
        }
        for summary in summaries
    ]
    members.sort(key=lambda member: (-float(member["orig_bytes"]), str(member["dst"])))
    first_seen, last_seen, span_seconds = _time_evidence(represented)
    network_text = str(network)
    return Finding(
        detector=DETECTOR_NAME,
        severity=Severity.MEDIUM,
        title=f"{src} → {network_text}",
        description=(
            "Complete-byte connection rows show originator-dominant traffic across "
            "a rotating external destination pool, which resembles bulk data transfer."
        ),
        evidence={
            "tier": "destination_pool",
            "src": src,
            "destination_network": network_text,
            "destination_count": len(members),
            "orig_bytes_total": orig_total,
            "resp_bytes_total": resp_total,
            "orig_share": round(orig_total / total, 4),
            "connection_count": int(sum(int(summary["connection_count"]) for summary in summaries)),
            "port_mix": _port_mix(represented),
            "span_seconds": span_seconds,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "max_duration_seconds": _max_duration(represented),
            "members": members,
        },
        next_steps=[
            "Review the represented transfers in conn.log: zeek-cut id.orig_h id.resp_h "
            f"id.resp_p orig_bytes resp_bytes < conn.log | grep {shlex.quote(src)}",
            f"Check destination-pool ownership: whois {shlex.quote(network_text)}",
            "Confirm whether the transfer is an expected backup, sync, or upload",
            "Add an expected recurring destination pool to the allowlist",
        ],
        ts_generated=datetime.now(tz=timezone.utc),
        data_window=context.data_window,
    )


def _partial_pair_facts(
    complete: pd.DataFrame,
    excluded: pd.DataFrame,
    cfg: dict,
) -> dict[tuple[str, str], dict[str, float | bool]]:
    """Return identity-keyed measured and missing-byte totals for runner disclosure.

    The returned keys are detector-analysis data, not report data.  The runner
    may use them only to count material pairs and sum excluded originator mass.
    """
    complete_totals = (
        complete.groupby(["src", "dst"], sort=False)[["_orig_bytes", "_resp_bytes"]]
        .sum()
        .rename(columns={"_orig_bytes": "eligible_orig", "_resp_bytes": "eligible_resp"})
    )
    excluded_totals = (
        excluded.groupby(["src", "dst"], sort=False)["_orig_bytes"]
        .sum()
        .rename("excluded_orig")
    )
    facts: dict[tuple[str, str], dict[str, float | bool]] = {}
    for key, excluded_orig in excluded_totals.items():
        if key in complete_totals.index:
            eligible = complete_totals.loc[key]
            eligible_orig = float(eligible["eligible_orig"])
            eligible_resp = float(eligible["eligible_resp"])
        else:
            eligible_orig = 0.0
            eligible_resp = 0.0
        reconstructed_orig = eligible_orig + float(excluded_orig)
        facts[(str(key[0]), str(key[1]))] = {
            "eligible_orig": eligible_orig,
            "eligible_resp": eligible_resp,
            "excluded_orig": float(excluded_orig),
            "surfaced": _surface_pair(eligible_orig, eligible_resp, cfg),
            "best_case_surfaces": _surface_pair(
                reconstructed_orig, eligible_resp, cfg,
            ),
        }
    return facts


def _apply_eligibility(
    df: pd.DataFrame,
    home_net: list[str],
    cfg: dict,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Apply exfil's ordered eligibility pipeline and return complete-byte rows."""
    rows_total = len(df)
    if df.empty:
        return df.copy(), _empty_facts(rows_total=rows_total)
    missing = _missing_scoring_columns(df)
    if missing:
        return df.iloc[0:0].copy(), _empty_facts(
            missing_columns=missing, rows_total=rows_total,
        )

    prepared = df.copy()
    parsed_src = prepared["src"].map(parse_address)
    parsed_dst = prepared["dst"].map(parse_address)
    parse_mask = (parsed_src.notna() & parsed_dst.notna()).astype(bool)
    prepared = prepared[parse_mask].copy()
    parsed_src = parsed_src[parse_mask]
    parsed_dst = parsed_dst[parse_mask]
    rows_after_parse = len(prepared)
    if prepared.empty:
        return prepared, _empty_facts(rows_total=rows_total) | {
            "rows_after_parse": rows_after_parse,
        }

    prepared["src"] = parsed_src.map(str)
    prepared["dst"] = parsed_dst.map(str)
    prepared["_src_ip"] = parsed_src
    prepared["_dst_ip"] = parsed_dst
    src_internal = pd.Series(
        [in_home_net(address, home_net) for address in parsed_src],
        index=prepared.index,
        dtype=bool,
    )
    if "local_orig" in prepared.columns:
        local_orig = prepared["local_orig"]
        effective_local = local_orig.where(local_orig.notna(), src_internal).astype(bool)
    else:
        effective_local = src_internal.astype(bool)
    prepared = prepared[effective_local].copy()
    rows_after_local = len(prepared)
    if prepared.empty:
        return prepared, _empty_facts(rows_total=rows_total) | {
            "rows_after_parse": rows_after_parse,
            "rows_after_local": rows_after_local,
        }

    dst_external = pd.Series(
        [
            not in_home_net(address, home_net) and not is_non_routable(address)
            for address in prepared["_dst_ip"]
        ],
        index=prepared.index,
        dtype=bool,
    )
    prepared = prepared[dst_external].copy()
    rows_after_external = len(prepared)
    if prepared.empty:
        return prepared, _empty_facts(rows_total=rows_total) | {
            "rows_after_parse": rows_after_parse,
            "rows_after_local": rows_after_local,
            "rows_after_external": rows_after_external,
        }

    prepared["_orig_bytes"] = _finite_nonnegative(prepared["bytes"])
    prepared["_resp_bytes"] = _finite_nonnegative(prepared["resp_bytes"])
    origin_usable = prepared["_orig_bytes"].notna().astype(bool)
    byte_pair = (origin_usable & prepared["_resp_bytes"].notna()).astype(bool)
    excluded = prepared[origin_usable & ~byte_pair].copy()
    complete = prepared[byte_pair].copy()
    rows_after_byte_pairing = len(complete)
    partial_pairs = _partial_pair_facts(complete, excluded, cfg)
    return complete, {
        "missing_columns": (),
        "rows_total": rows_total,
        "rows_after_parse": rows_after_parse,
        "rows_after_local": rows_after_local,
        "rows_after_external": rows_after_external,
        "rows_after_byte_pairing": rows_after_byte_pairing,
        "pairs_surviving": int(complete.groupby(["src", "dst"]).ngroups),
        "partial_pairs": partial_pairs,
    }


def eligibility(
    df: Any,
    home_net: list[str] | None = None,
    config: dict | None = None,
) -> dict[str, Any]:
    """Return defensive exfil eligibility facts for runner-owned disclosures."""
    try:
        rows_total = len(df)
    except Exception:
        return _empty_facts()
    if not isinstance(df, pd.DataFrame):
        return _empty_facts(rows_total=rows_total)
    if df.empty:
        return _empty_facts(rows_total=rows_total)
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    networks = list(home_net) if home_net else list(_DEFAULT_HOME_NET)
    try:
        _complete, facts = _apply_eligibility(df, networks, cfg)
    except Exception:
        return _empty_facts(rows_total=rows_total)
    return facts


def run(context: DetectorContext) -> list[Finding]:
    """Surface measured high-mass, originator-dominant external transfers."""
    cfg = {**DEFAULT_CONFIG, **context.config}
    df = context.logs.get("conn*.log*")
    if df is None or df.empty:
        return []
    home_net = list(context.home_net) if context.home_net else list(_DEFAULT_HOME_NET)
    complete, facts = _apply_eligibility(df, home_net, cfg)
    if facts["missing_columns"] or complete.empty:
        return []

    summaries: list[dict[str, Any]] = []
    for (src, dst), group in complete.groupby(["src", "dst"], sort=False):
        summary = _pair_summary(str(src), str(dst), group, cfg)
        if summary is not None:
            summaries.append(summary)

    pools: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for summary in summaries:
        network = _destination_pool_network(summary["destination_ip"])
        pools.setdefault((summary["src"], str(network)), []).append(summary)

    folded_pair_ids: set[tuple[str, str]] = set()
    findings: list[Finding] = []
    for (src, _network_text), members in pools.items():
        if len(members) < DESTINATION_POOL_FOLD_COUNT:
            continue
        network = _destination_pool_network(members[0]["destination_ip"])
        findings.append(_rollup_finding(src, network, members, context))
        folded_pair_ids.update((member["src"], member["dst"]) for member in members)
    for summary in summaries:
        if (summary["src"], summary["dst"]) not in folded_pair_ids:
            findings.append(_pair_finding(summary, context))
    findings.sort(key=lambda finding: finding.evidence["orig_bytes_total"], reverse=True)
    return findings
