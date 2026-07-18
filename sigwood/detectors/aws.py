"""AWS detector - per-principal behavioral surfacing from CloudTrail events.

Reads the canonical 12-column per-event frame produced by parsers/cloudtrail.py
and surfaces two tiers of Findings:

1. **Burst sweeps** - per-principal first-seen actions clumped within a
   sliding gap become one "enumeration sweep" Finding. The strongest primitive
   we have, glanceable on a single line.
2. **Ranked principals** - a model-free transparent z-score composite over
   intuitive danger signals (error rate, distinct source IPs, distinct action
   names, action entropy). Severity is by absolute composite bands, not rank
   position; on a clean corpus the tier honestly reports nothing stood out
   rather than manufacturing a verdict. With fewer scorable principals than
   ``min_scorable_principals`` the tier abstains from banding entirely -
   population z-scores at tiny n are rank position by construction.

Architecture mirrors detectors/dns.py: front half does feature derivation, back
half assembles Findings at a single shared point. Service-lane events are
excluded from all three signals - AWS-run background activity is supposed to be
broad and repetitive; scoring it produces noise.

Model-free by design. pandas + numpy only - reaching for sklearn would betray
the transparency point (a humble user must be able to read why a principal was
surfaced).

Blind spot - disclosed via RunSummary, not buried behind --verbose: a
low-volume principal performing a small number of high-impact actions is not
reliably caught by any of these signals. Principals below ``min_events`` are
set aside; their count is surfaced via ``below_floor_count()``, which the
runner reads during RunSummary note assembly. The "first-seen" label is also
window-relative; the runner emits a second note disclosing that limitation.

Investigation pivot: principal → CloudTrail console / event_id drill-back →
source IPs → whois / threat-intel on non-AWS source IPs → regions touched.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd

from sigwood.common.display import plural
from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity

DETECTOR_NAME = "aws"
STATUS = "available"
IN_DEFAULT_HUNT: bool = True

REQUIRED_LOGS = [
    {"source": "cloudtrail_dir", "pattern": "*.json*"},
]

OPTIONAL_LOGS: list[dict] = []

DETECTOR_METHOD = MethodTag("statistical", named=False)

DEFAULT_CONFIG = {
    # Per-principal event floor. Interactive principals with fewer events are
    # set aside (not scored). Count surfaced via the RunSummary below-floor note.
    # Valid: int >= 1.
    "min_events": 50,

    # Ranked-tier population floor: with fewer scorable principals than this,
    # the ranked tier abstains from MEDIUM/LOW verdicts and says so via the
    # synthetic INFO finding. Population z-scores are meaningless by
    # construction at tiny n (max |z| = sqrt(n-1); at n=2 every non-degenerate
    # signal is exactly +/-1 - scoring IS rank position there).
    # Valid: int >= 1; 1 disables the population gate.
    "min_scorable_principals": 5,

    # Burst aggregation gap: consecutive first-seen actions whose inter-arrival
    # gap is strictly less than this threshold remain in the same burst.
    # Valid: seconds, int > 0.
    "burst_gap_seconds": 300,

    # Opening-window safety margin: service-spread-only bursts whose first
    # first-seen action falls this close to the loaded window start stay MEDIUM.
    # Valid: seconds, int >= 0.
    "burst_window_edge_margin_seconds": 300,

    # A burst must contain at least this many first-seen actions to be a Finding.
    # Valid: int >= 2.
    "burst_min_firsts": 3,

    # Severity escalation gates for bursts. A burst at-or-above EITHER gate
    # promotes from MEDIUM to HIGH. Never auto-HIGH on size alone - that would
    # manufacture verdicts a noisy-but-benign sweep does not deserve.
    # Valid: error_rate in [0,1], service_count int >= 1.
    "burst_high_error_rate": 0.5,
    "burst_high_service_count": 3,

    # Absolute composite-z bands for ranked-principal severity. NOT rank
    # position - a clean corpus should not have a HIGH purely for being
    # top-of-list. Valid: float, low <= medium.
    "composite_medium_threshold": 2.0,  # absolute calibrated constant → MEDIUM
    "composite_low_threshold":    1.0,  # mild standout → LOW; below → INFO band
}


# ── Pure helper: below-floor count ────────────────────────────────────────────
#
# Pre-detector: the runner calls this during RunSummary note assembly (before
# the detector loop starts). The detector also calls it internally to size the
# scorable set, so the disclosed count cannot drift from the analysis count.

def below_floor_count(df: pd.DataFrame | None, min_events: int) -> int:
    """Number of interactive-lane principals with fewer than ``min_events`` events.

    Pure function over the canonical CloudTrail frame. Returns 0 on empty /
    None / missing-columns input.
    """
    if df is None or df.empty:
        return 0
    if "lane" not in df.columns or "principal" not in df.columns:
        return 0
    interactive = df[df["lane"] == "interactive"]
    if interactive.empty:
        return 0
    counts = interactive.groupby("principal").size()
    return int((counts < min_events).sum())


def interactive_count(df: pd.DataFrame | None) -> int:
    """Number of interactive-lane EVENTS (rows) in the canonical CloudTrail frame.

    Pure function; 0 on None / empty / missing-``lane`` input. ``== 0`` exactly
    when ``run()``'s ``_filter_interactive(df)`` is empty - the silent-"nothing"
    condition the runner's no-interactive disclosure note keys on.
    """
    if df is None or df.empty:
        return 0
    if "lane" not in df.columns:
        return 0
    return int((df["lane"] == "interactive").sum())


# ── Front half: lane filter, per-principal aggregation ────────────────────────

def _filter_interactive(df: pd.DataFrame) -> pd.DataFrame:
    """Return only interactive-lane events.

    The parser emits ``lane`` per event. We filter first, then aggregate the
    resulting subset by principal - no assumption that a principal is purely
    one lane. Service-lane events do not feed rarity, weirdness, or bursts.
    """
    if "lane" not in df.columns:
        return df.iloc[0:0]
    return df[df["lane"] == "interactive"]


def _shannon_entropy(value_counts: pd.Series) -> float:
    """Shannon entropy (base 2) of a value-count distribution."""
    total = value_counts.sum()
    if total <= 0:
        return 0.0
    probs = value_counts / total
    nonzero = probs[probs > 0]
    if nonzero.empty:
        return 0.0
    return float(-(nonzero * np.log2(nonzero)).sum())


_PER_PRINCIPAL_COLUMNS = [
    "principal", "event_count", "error_rate",
    "distinct_source_ip", "distinct_event_name", "distinct_event_source",
    "read_ratio", "action_entropy",
    "distinct_aws_region", "distinct_hours_active",
]


def _aggregate_per_principal(interactive_df: pd.DataFrame) -> pd.DataFrame:
    """One row per principal in the interactive lane, with behavioral features.

    All features derive from the canonical 12-column schema; we never recompute
    principal/lane/read_write - those come from the parser.
    """
    if interactive_df.empty:
        return pd.DataFrame(columns=_PER_PRINCIPAL_COLUMNS)

    g = interactive_df.groupby("principal", sort=False)
    event_count = g.size()

    def _series(col_in_df: bool, default: float | int) -> pd.Series:
        return pd.Series(default, index=event_count.index)

    if "error_code" in interactive_df.columns:
        error_count = g["error_code"].apply(lambda s: int(s.notna().sum()))
    else:
        error_count = _series(False, 0)
    error_rate = (error_count / event_count).astype(float)

    distinct_source_ip = (
        g["source_ip"].nunique() if "source_ip" in interactive_df.columns
        else _series(False, 0)
    )
    distinct_event_name = (
        g["event_name"].nunique() if "event_name" in interactive_df.columns
        else _series(False, 0)
    )
    distinct_event_source = (
        g["event_source"].nunique() if "event_source" in interactive_df.columns
        else _series(False, 0)
    )
    distinct_aws_region = (
        g["aws_region"].nunique() if "aws_region" in interactive_df.columns
        else _series(False, 0)
    )

    if "read_write" in interactive_df.columns:
        read_count = g["read_write"].apply(lambda s: int((s == "read").sum()))
    else:
        read_count = _series(False, 0)
    read_ratio = (read_count / event_count).astype(float)

    if "event_name" in interactive_df.columns:
        action_entropy = g["event_name"].apply(
            lambda s: _shannon_entropy(s.value_counts())
        )
    else:
        action_entropy = _series(False, 0.0)

    if "ts" in interactive_df.columns:
        hours = pd.to_datetime(
            interactive_df["ts"], unit="s", utc=True, errors="coerce"
        ).dt.hour
        with_hour = interactive_df.assign(_hour=hours.values)
        distinct_hours = (
            with_hour.groupby("principal", sort=False)["_hour"].nunique()
        )
    else:
        distinct_hours = _series(False, 0)

    out = pd.DataFrame({
        "principal":             list(event_count.index),
        "event_count":           event_count.values.astype(int),
        "error_rate":            error_rate.values,
        "distinct_source_ip":    distinct_source_ip.values.astype(int),
        "distinct_event_name":   distinct_event_name.values.astype(int),
        "distinct_event_source": distinct_event_source.values.astype(int),
        "read_ratio":            read_ratio.values,
        "action_entropy":        action_entropy.values,
        "distinct_aws_region":   distinct_aws_region.values.astype(int),
        "distinct_hours_active": distinct_hours.values.astype(int),
    })
    return out


# ── Signal 1: corpus rarity ───────────────────────────────────────────────────

def _compute_rarity(interactive_df: pd.DataFrame) -> dict[str, float]:
    """log10(N / count(event_name)) over interactive-lane events only.

    Returns ``event_name → rarity``. Pure plain-odds - no domain opinion.
    Higher = rarer action in this corpus. Returns ``{}`` on empty input.
    """
    if interactive_df.empty or "event_name" not in interactive_df.columns:
        return {}
    counts = interactive_df["event_name"].dropna().value_counts()
    n = int(counts.sum())
    if n == 0:
        return {}
    rarities = np.log10(float(n)) - np.log10(counts.astype(float).values)
    return {str(k): float(v) for k, v in zip(counts.index, rarities)}


# ── Signal 2: behavioral weirdness composite ──────────────────────────────────

def _zscore(values: np.ndarray) -> np.ndarray:
    """Population z-score; degenerate (std == 0) populations collapse to zeros."""
    if values.size == 0:
        return values.astype(float)
    mean = float(values.mean())
    std = float(values.std())
    if std == 0:
        return np.zeros_like(values, dtype=float)
    return (values.astype(float) - mean) / std


def _compute_weirdness(scorable: pd.DataFrame) -> pd.DataFrame:
    """Add component z-scores and a composite to the scorable per-principal frame.

    Heavy-tailed count features (distinct_source_ip, distinct_event_name) are
    log1p-scaled before z-scoring. Ratios (error_rate) and bounded entropy
    (action_entropy) are not log1p'd.

    Caller is responsible for filtering to ``event_count >= min_events`` before
    calling this; we trust that contract and do not re-filter.
    """
    if scorable.empty:
        return scorable

    out = scorable.copy()
    out["z_error_rate"] = _zscore(out["error_rate"].values)
    out["z_distinct_source_ip"] = _zscore(
        np.log1p(out["distinct_source_ip"].values.astype(float))
    )
    out["z_distinct_event_name"] = _zscore(
        np.log1p(out["distinct_event_name"].values.astype(float))
    )
    out["z_action_entropy"] = _zscore(out["action_entropy"].values)
    out["composite_z"] = (
        out["z_error_rate"]
        + out["z_distinct_source_ip"]
        + out["z_distinct_event_name"]
        + out["z_action_entropy"]
    )
    return out


# ── Signal 3: first-seen + burst aggregation ──────────────────────────────────

def _compute_bursts(
    interactive_df: pd.DataFrame,
    rarity: dict[str, float],
    burst_gap_seconds: int,
    burst_min_firsts: int,
) -> list[dict]:
    """Time-ordered pass yielding per-principal burst candidates.

    For each principal, the VERY first event is skipped (all-new is
    uninformative). Subsequent events whose event_name has not been seen for
    this principal are recorded as first-seen records. Consecutive first-seen
    records less than ``burst_gap_seconds`` apart form one burst; a closed
    burst with at least ``burst_min_firsts`` records becomes a candidate.

    "First seen" is first seen within this loaded window. sigwood is batch
    and stateless - no cross-run persistence, no rolling baseline. The
    limitation is disclosed via a RunSummary note assembled by the runner.
    """
    needed = {"ts", "principal", "event_name"}
    if interactive_df.empty or not needed.issubset(interactive_df.columns):
        return []

    sorted_df = interactive_df.sort_values("ts", kind="stable").reset_index(drop=True)
    columns = sorted_df.columns

    seen_actions: dict[str, set[str]] = {}
    first_seen_records: dict[str, list[dict]] = {}

    for row in sorted_df.itertuples(index=False):
        principal = getattr(row, "principal", None)
        event_name = getattr(row, "event_name", None)
        ts = getattr(row, "ts", None)
        if principal is None or event_name is None or ts is None or pd.isna(ts):
            continue

        if principal not in seen_actions:
            # Very first event for this principal - skip and seed the seen set.
            seen_actions[principal] = {event_name}
            continue

        if event_name in seen_actions[principal]:
            continue

        seen_actions[principal].add(event_name)
        first_seen_records.setdefault(principal, []).append({
            "ts": float(ts),
            "event_name": str(event_name),
            "rarity": rarity.get(str(event_name), 0.0),
            "errored": (
                bool(pd.notna(getattr(row, "error_code", None)))
                if "error_code" in columns else False
            ),
            "event_source": (
                str(getattr(row, "event_source"))
                if "event_source" in columns
                and getattr(row, "event_source") is not None else ""
            ),
            "source_ip": (
                str(getattr(row, "source_ip"))
                if "source_ip" in columns
                and getattr(row, "source_ip") is not None else ""
            ),
            "aws_region": (
                str(getattr(row, "aws_region"))
                if "aws_region" in columns
                and getattr(row, "aws_region") is not None else ""
            ),
            "event_id": (
                str(getattr(row, "event_id"))
                if "event_id" in columns
                and getattr(row, "event_id") is not None else ""
            ),
        })

    bursts: list[dict] = []
    for principal, records in first_seen_records.items():
        current: list[dict] = []
        for rec in records:
            if not current:
                current.append(rec)
                continue
            gap = rec["ts"] - current[-1]["ts"]
            if gap < burst_gap_seconds:
                current.append(rec)
            else:
                if len(current) >= burst_min_firsts:
                    bursts.append(_summarize_burst(principal, current))
                current = [rec]
        if len(current) >= burst_min_firsts:
            bursts.append(_summarize_burst(principal, current))

    return bursts


def _summarize_burst(principal: str, records: list[dict]) -> dict:
    """Compute per-burst aggregates from a list of first-seen records."""
    n = len(records)
    start_ts = records[0]["ts"]
    end_ts = records[-1]["ts"]
    new_services = sorted({r["event_source"] for r in records if r["event_source"]})
    source_ips = sorted({r["source_ip"] for r in records if r["source_ip"]})
    aws_regions = sorted({r["aws_region"] for r in records if r["aws_region"]})
    new_actions = [r["event_name"] for r in records]
    event_ids = [r["event_id"] for r in records if r["event_id"]]
    error_count = sum(1 for r in records if r["errored"])
    error_rate = error_count / n if n else 0.0
    mean_rarity = sum(r["rarity"] for r in records) / n if n else 0.0
    return {
        "principal":         str(principal),
        "start_time":        datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat(),
        "start_ts":          start_ts,
        "span_seconds":      float(end_ts - start_ts),
        "new_action_count":  int(n),
        "new_service_count": int(len(new_services)),
        "new_actions":       new_actions,
        "new_services":      new_services,
        "source_ips":        source_ips,
        "aws_regions":       aws_regions,
        "sample_event_ids":  event_ids[:10],
        "error_rate":        round(error_rate, 4),
        "mean_rarity":       round(mean_rarity, 4),
    }


# ── Finding constructors ──────────────────────────────────────────────────────

def _make_burst_finding(
    burst: dict,
    burst_high_error_rate: float,
    burst_high_service_count: int,
    burst_window_edge_margin_seconds: int,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding:
    """One burst → one Finding. Severity structural by signal kind."""
    err_gate_hit = burst["error_rate"] >= burst_high_error_rate
    svc_gate_hit = burst["new_service_count"] >= burst_high_service_count
    at_edge = (
        burst["start_ts"] - data_window[0].timestamp()
    ) < burst_window_edge_margin_seconds
    severity = (
        Severity.HIGH
        if (err_gate_hit or (svc_gate_hit and not at_edge))
        else Severity.MEDIUM
    )

    title = str(burst["principal"])
    description = (
        "A burst of first-seen actions across multiple services in a short window. "
        "The pattern resembles an enumeration or recon sweep - recon, manual "
        "exploration, or a misconfigured first-time deploy."
    )
    next_steps = [
        f"Review CloudTrail events for principal {burst['principal']}",
        "Drill back via event IDs: " + ", ".join(burst["sample_event_ids"][:5]),
        "Verify source IPs are expected: " + ", ".join(burst["source_ips"][:5]),
        "Check the regions touched: " + ", ".join(burst["aws_regions"]),
        "Whois / threat-intel any non-AWS source IPs",
    ]
    evidence: dict[str, Any] = {
        "tier":              "burst",
        "principal":         burst["principal"],
        "start_time":        burst["start_time"],
        "span_seconds":      burst["span_seconds"],
        "new_action_count":  burst["new_action_count"],
        "new_service_count": burst["new_service_count"],
        "error_rate":        burst["error_rate"],
        "mean_rarity":       burst["mean_rarity"],
        "new_actions":       burst["new_actions"],
        "new_services":      burst["new_services"],
        "source_ips":        burst["source_ips"],
        "aws_regions":       burst["aws_regions"],
        "sample_event_ids":  burst["sample_event_ids"],
    }
    return Finding(
        detector=DETECTOR_NAME,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        next_steps=next_steps,
        ts_generated=now,
        data_window=data_window,
    )


def _make_ranked_finding(
    row: pd.Series,
    severity: Severity,
    interactive_df: pd.DataFrame,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding:
    """One ranked principal → one Finding. Components + composite + raw values in evidence."""
    principal = row["principal"]
    sub = interactive_df[interactive_df["principal"] == principal]

    top_actions = (
        sub["event_name"].value_counts().head(5).index.tolist()
        if "event_name" in sub.columns else []
    )
    source_ips = (
        sorted(s for s in sub["source_ip"].dropna().unique() if isinstance(s, str))[:10]
        if "source_ip" in sub.columns else []
    )
    aws_regions = (
        sorted(s for s in sub["aws_region"].dropna().unique() if isinstance(s, str))
        if "aws_region" in sub.columns else []
    )
    sample_event_ids = (
        [s for s in sub["event_id"].head(5).tolist() if isinstance(s, str)]
        if "event_id" in sub.columns else []
    )

    title = str(principal)
    description = (
        f"Composite z-score {row['composite_z']:.2f} across error rate, "
        "distinct source IPs, distinct action names, and action entropy - this "
        "principal's behavioral fingerprint is unusual for the population."
    )
    next_steps = [
        f"Review CloudTrail events for principal {principal}",
        "Pivot on top actions: " + ", ".join(top_actions),
        "Whois / threat-intel any non-AWS source IPs: " + ", ".join(source_ips[:5]),
        "Drill back via event IDs: " + ", ".join(sample_event_ids),
    ]
    evidence: dict[str, Any] = {
        "tier":                  "ranked",
        "principal":             str(principal),
        "composite_z":           round(float(row["composite_z"]), 4),
        "z_error_rate":          round(float(row["z_error_rate"]), 4),
        "z_distinct_source_ip":  round(float(row["z_distinct_source_ip"]), 4),
        "z_distinct_event_name": round(float(row["z_distinct_event_name"]), 4),
        "z_action_entropy":      round(float(row["z_action_entropy"]), 4),
        "event_count":           int(row["event_count"]),
        "error_rate":            round(float(row["error_rate"]), 4),
        "distinct_source_ip":    int(row["distinct_source_ip"]),
        "distinct_event_name":   int(row["distinct_event_name"]),
        "distinct_event_source": int(row["distinct_event_source"]),
        "action_entropy":        round(float(row["action_entropy"]), 4),
        "read_ratio":            round(float(row["read_ratio"]), 4),
        "distinct_aws_region":   int(row["distinct_aws_region"]),
        "distinct_hours_active": int(row["distinct_hours_active"]),
        "top_actions":           top_actions,
        "source_ips":            source_ips,
        "aws_regions":           aws_regions,
        "sample_event_ids":      sample_event_ids,
    }
    return Finding(
        detector=DETECTOR_NAME,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        next_steps=next_steps,
        ts_generated=now,
        data_window=data_window,
    )


def _make_ranked_summary_finding(
    scored: pd.DataFrame,
    now: datetime,
    data_window: tuple[datetime, datetime],
    *,
    population_floor: int | None = None,
) -> Finding:
    """One synthetic INFO Finding - the single owner of both ranked-tier quiet lines.

    ``population_floor=None`` (the default): the "nothing stood out" line,
    emitted when at least one scorable interactive principal exists AND zero
    MEDIUM/LOW per-principal Findings result. Carries the count and the top
    composite (least-unremarkable actor) as analyst pivot.

    ``population_floor=<int>``: the too-few-to-compare line, emitted when the
    scorable population is smaller than the floor. Deliberately carries NO
    composite z and NO top principal - at tiny n the by-construction z invites
    exactly the rank-position misreading the gate prevents.
    """
    if population_floor is not None:
        n = int(len(scored))
        return Finding(
            detector=DETECTOR_NAME,
            severity=Severity.INFO,
            title="ranked tier: too few principals to compare",
            description=(
                f"Only {n} interactive {plural(n, 'principal')} had enough events "
                f"to score; population comparison needs at least "
                f"{int(population_floor)}. No principal was ranked."
            ),
            evidence={
                "tier":             "ranked_summary",
                "scorable_count":   n,
                "population_floor": int(population_floor),
            },
            next_steps=[
                "No recommended action - population too small to rank",
                "Set min_scorable_principals in [detectors.aws] to compare smaller populations",
            ],
            ts_generated=now,
            data_window=data_window,
        )

    top = scored.sort_values("composite_z", ascending=False).iloc[0]
    return Finding(
        detector=DETECTOR_NAME,
        severity=Severity.INFO,
        title="ranked tier: no principals cleared the LOW band",
        description=(
            "No scored interactive principal cleared the LOW band. Closest to the "
            f"bar was {top['principal']} (composite z {float(top['composite_z']):.2f})."
        ),
        evidence={
            "tier":            "ranked_summary",
            "scorable_count":  int(len(scored)),
            "top_principal":   str(top["principal"]),
            "top_composite_z": round(float(top["composite_z"]), 4),
        },
        next_steps=[
            "No recommended action - nothing stood out",
            "Lower composite_low_threshold in [detectors.aws] to widen the surface",
        ],
        ts_generated=now,
        data_window=data_window,
    )


# ── Detector entry point ──────────────────────────────────────────────────────

def run(context: DetectorContext) -> list[Finding]:
    """Surface noteworthy CloudTrail principals: bursts first, then ranked weirdness."""
    cfg = context.config
    min_events:        int   = cfg.get("min_events",        DEFAULT_CONFIG["min_events"])
    burst_gap:         int   = cfg.get("burst_gap_seconds", DEFAULT_CONFIG["burst_gap_seconds"])
    burst_min_firsts:  int   = cfg.get("burst_min_firsts",  DEFAULT_CONFIG["burst_min_firsts"])
    burst_high_err:    float = cfg.get("burst_high_error_rate",
                                       DEFAULT_CONFIG["burst_high_error_rate"])
    burst_high_svcs:   int   = cfg.get("burst_high_service_count",
                                       DEFAULT_CONFIG["burst_high_service_count"])
    burst_edge_margin: int   = cfg.get(
        "burst_window_edge_margin_seconds",
        DEFAULT_CONFIG["burst_window_edge_margin_seconds"],
    )
    medium_threshold:  float = cfg.get("composite_medium_threshold",
                                       DEFAULT_CONFIG["composite_medium_threshold"])
    low_threshold:     float = cfg.get("composite_low_threshold",
                                       DEFAULT_CONFIG["composite_low_threshold"])
    min_scorable:      int   = cfg.get("min_scorable_principals",
                                       DEFAULT_CONFIG["min_scorable_principals"])

    df = context.logs.get("*.json*")
    if df is None or df.empty:
        return []

    interactive = _filter_interactive(df)
    if interactive.empty:
        return []

    per_principal = _aggregate_per_principal(interactive)
    scorable = per_principal[per_principal["event_count"] >= min_events].copy()

    rarity = _compute_rarity(interactive)
    scored = _compute_weirdness(scorable)
    burst_dicts = _compute_bursts(interactive, rarity, burst_gap, burst_min_firsts)

    now = datetime.now(tz=timezone.utc)

    # Burst findings: bursts first, sorted by service spread then action count.
    burst_findings = [
        _make_burst_finding(
            b, burst_high_err, burst_high_svcs, burst_edge_margin,
            now, context.data_window,
        )
        for b in burst_dicts
    ]
    burst_findings.sort(
        key=lambda f: (f.evidence["new_service_count"], f.evidence["new_action_count"]),
        reverse=True,
    )

    # Ranked findings: MEDIUM and LOW per-principal (no verbose gating); when
    # zero per-principal Findings result and scorable principals exist, one
    # synthetic INFO summary Finding so the analyst sees the tier was scored.
    # Below the population floor the tier abstains from banding entirely -
    # population z-scores at tiny n are rank position by construction.
    ranked_findings: list[Finding] = []
    if not scored.empty:
        if len(scored) < min_scorable:
            ranked_findings.append(
                _make_ranked_summary_finding(
                    scored, now, context.data_window,
                    population_floor=min_scorable,
                )
            )
        else:
            scored_sorted = scored.sort_values("composite_z", ascending=False)
            for _, row in scored_sorted.iterrows():
                cz = float(row["composite_z"])
                if cz >= medium_threshold:
                    ranked_findings.append(
                        _make_ranked_finding(row, Severity.MEDIUM, interactive, now, context.data_window)
                    )
                elif cz >= low_threshold:
                    ranked_findings.append(
                        _make_ranked_finding(row, Severity.LOW, interactive, now, context.data_window)
                    )
                # cz < low_threshold → INFO band, not emitted per-principal.

            if not ranked_findings:
                ranked_findings.append(
                    _make_ranked_summary_finding(scored_sorted, now, context.data_window)
                )

    return burst_findings + ranked_findings
