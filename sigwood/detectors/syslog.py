"""Syslog anomaly detector - drain3 templating + rarity scoring + burst collapse.

Pipeline:
1. drain3 log templating: assigns each message row a template_id and template_str
2. Rarity scoring: flags templates whose GLOBAL occurrence count (across all
   hosts) falls at or below min(percentile_threshold, max_count) as anomalous
   (the "rare" set). The shipped default max_count=1 floors that min(), so the
   effective rule at the default is "flag globally-singleton templates" and
   rarity_pct is inert; rarity_pct engages only once max_count is raised above
   the percentile-derived count. A line common to many hosts is not rare.
3. Reboot detection (full-frame, rarity-blind): a vectorized mask over `message`
   selects every reboot-signal row regardless of rarity, so a banner whose drain3
   template repeats across boots is still caught. Reboot rows are removed from the
   rare set (rare_df = is_anomaly & ~reboot_mask), so a reboot row is never a rare
   needle and never inflates a burst's line_count.
4. Per-host temporal burst collapse over the rare set: rare NON-reboot rows on one
   host that cluster within burst_gap_seconds fold into a single INFO burst
   finding; the rest stay isolated MEDIUM needles. Every rare NON-reboot row is
   represented exactly once.
5. Reconciliation: reboot rows are clustered per host into boot events
   (reboot_cluster_seconds); each event either labels the nearest contemporaneous
   burst "rebooted" (within burst_gap_seconds) or emits one standalone INFO reboot
   finding - exactly one representation per boot event. run() owns the final
   cross-channel output sort.
"""

from __future__ import annotations

import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import NamedTuple

import pandas as pd
from tqdm import tqdm

from sigwood.common.display import narration_active
from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity
from sigwood.parsers.syslog import REBOOT_SIGNALS_RE

DETECTOR_NAME = "syslog"
STATUS = "available"

# syslog is fidelity-aware: flat rsyslog, the live system journal, or Zeek's
# own syslog.log. At least one must be present; satisfiable feeds
# concat before drain3. Detector is SOURCE-BLIND - references only the
# minimal-5 (ts, host, program, raw, message). Zeek's extended facility /
# severity ride along on the frame but are NEVER read here; the digest
# consumes them. Mirrors the dns detector's Zeek + Pi-hole shape.
REQUIRED_LOGS: list[dict] = []

OPTIONAL_LOGS = [
    {"source": "syslog_dir", "pattern": "*.log*"},
    {"source": "journal",    "pattern": "*.log*"},
    {"source": "zeek_dir",   "pattern": "syslog*.log*"},
]

REQUIRES_ONE_OF_OPTIONAL = True
# The reason NEVER embeds the detector name - both render surfaces (the live skip
# warning and the dry-run banner) prefix it, so a name here double-names ("syslog -
# syslog - …").
REQUIRES_ONE_OF_OPTIONAL_REASON = (
    "no syslog source found (need a readable system journal, syslog files, "
    "or Zeek syslog.log)"
)

DRAIN_SIM_THRESH          = 0.5
DRAIN_DEPTH               = 4
DRAIN_PARAMETRIZE_NUMERIC = True
BURST_GAP_SECONDS         = 60   # rare rows on a host closer than this = one burst
BURST_MIN_SIZE            = 3    # min rare rows in a window to collapse to a burst
LINE_TRIM_LIMIT           = 200  # max finding trim length
REBOOT_CLUSTER_SECONDS    = 600  # reboot signals on a host closer than this = one boot event

DEFAULT_CONFIG = {
    "rarity_pct":         10,
    "max_count":           1,
    "sim_thresh":          DRAIN_SIM_THRESH,
    "depth":               DRAIN_DEPTH,
    "parametrize_numeric": DRAIN_PARAMETRIZE_NUMERIC,
    "burst_gap_seconds":   BURST_GAP_SECONDS,
    "burst_min_size":      BURST_MIN_SIZE,
    "reboot_cluster_seconds": REBOOT_CLUSTER_SECONDS,
    "line_trim_limit":     LINE_TRIM_LIMIT,
}

DETECTOR_METHOD = MethodTag("drain3", named=True)


class _BootEvent(NamedTuple):
    """One reboot event on a host: a gap-cluster of reboot-signal rows. A boot
    event is indeterminate (start_ts is None) when all its rows lack a parseable
    timestamp - the sole indeterminate marker, no separate flag field."""
    host: str
    start_ts: float | None
    end_ts: float | None
    signal_count: int


def run(context: DetectorContext) -> list[Finding]:
    """Detect anomalous syslog lines using drain3 templating, rarity scoring,
    and per-host temporal burst collapse."""
    flat_df = context.logs.get("*.log*")
    zeek_df = context.logs.get("syslog*.log*")

    frames = [df for df in (flat_df, zeek_df) if df is not None and not df.empty]
    if not frames:
        return []
    df = frames[0] if len(frames) == 1 else pd.concat(frames, ignore_index=True)

    cfg = context.config
    sim_thresh  = cfg.get("sim_thresh",          DEFAULT_CONFIG["sim_thresh"])
    depth       = cfg.get("depth",               DEFAULT_CONFIG["depth"])
    parametrize = cfg.get("parametrize_numeric", DEFAULT_CONFIG["parametrize_numeric"])
    rarity_pct  = cfg.get("rarity_pct",          DEFAULT_CONFIG["rarity_pct"])
    max_count   = cfg.get("max_count",           DEFAULT_CONFIG["max_count"])
    gap_seconds = cfg.get("burst_gap_seconds",   DEFAULT_CONFIG["burst_gap_seconds"])
    min_size    = cfg.get("burst_min_size",      DEFAULT_CONFIG["burst_min_size"])
    cluster_seconds = cfg.get("reboot_cluster_seconds", DEFAULT_CONFIG["reboot_cluster_seconds"])

    df = _run_drain3(df, sim_thresh, depth, parametrize)
    df, threshold, freq = _score_rarity(df, rarity_pct, max_count)

    now = datetime.now(timezone.utc)

    # Reboot detection is a SECOND, rarity-blind, full-frame channel: a vectorized
    # mask over canonical `message` catches every reboot signal even when its
    # drain3 template
    # repeats across boots (count > max_count, so NOT in the rare set). Removing
    # reboot rows from the rare set is the anti-leak keystone - a reboot row can
    # never be tallied in a burst's line_count nor surface as a MEDIUM needle.
    # str.contains(na=False) is bool dtype by construction, and run() already
    # returned on an empty frame, so the combined mask is always a real boolean.
    reboot_mask = df["message"].astype(str).str.contains(REBOOT_SIGNALS_RE, na=False)
    boot_events = _detect_boot_events(df[reboot_mask], cluster_seconds=cluster_seconds)
    rare_df     = df[df["is_anomaly"] & ~reboot_mask].copy()

    burst_pairs = _collapse_bursts(
        rare_df, freq, threshold,
        gap_seconds=gap_seconds, min_size=min_size,
        now=now, data_window=context.data_window,
    )
    pairs = _reconcile(
        boot_events, burst_pairs,
        gap_seconds=gap_seconds, now=now, data_window=context.data_window,
    )
    # run() owns the SINGLE final cross-channel output sort; the helpers keep their
    # own internal stable ts sorts but return unsorted pairs.
    pairs.sort(key=lambda pair: pair[0])
    return [f for _, f in pairs]


def _run_drain3(
    df: pd.DataFrame,
    sim_thresh: float,
    depth: int,
    parametrize_numeric: bool,
) -> pd.DataFrame:
    """Add template_id and template_str columns via drain3 log templating."""
    try:
        from drain3 import TemplateMiner
        from drain3.template_miner_config import TemplateMinerConfig
    except ImportError:
        raise ImportError(
            "drain3 is required for syslog detection. Run: pip install drain3"
        )

    cfg = TemplateMinerConfig()
    cfg.drain_sim_th               = sim_thresh
    cfg.drain_depth                = depth
    cfg.parametrize_numeric_tokens = parametrize_numeric

    miner = TemplateMiner(config=cfg)
    template_ids: list[int] = []
    template_strs: list[str] = []

    # leave=True + clean bar_format makes this the liveness narration for the
    # syslog detector phase (the runner deliberately skips its outer spinner
    # for syslog so the two writers don't fight for the same stderr line).
    # ``narration_active`` is the runner-set global gate (-q) + the stderr TTY
    # check: -q or a piped run disables the bar WITHOUT this detector reading a
    # quiet field, so the detectors-are-render-blind rail stays intact.
    for msg in tqdm(
        df["message"],
        desc="syslog: mining templates",
        unit=" lines",
        unit_scale=True,
        leave=True,
        bar_format="{desc}: {n_fmt} lines [{elapsed}]",
        disable=not narration_active(sys.stderr),
    ):
        result = miner.add_log_message(str(msg))
        template_ids.append(result["cluster_id"])
        template_strs.append(result["template_mined"])

    df = df.copy()
    df["template_id"]  = template_ids
    df["template_str"] = template_strs
    return df


def _score_rarity(
    df: pd.DataFrame,
    rarity_pct: int,
    max_count: int,
) -> tuple[pd.DataFrame, int, dict[int, int]]:
    """Add is_anomaly column; return (df, effective_threshold, freq_dict)."""
    freq: dict[int, int] = {
        int(k): int(v) for k, v in df["template_id"].value_counts().items()
    }

    sorted_counts = sorted(freq.values())
    idx           = max(0, int(len(sorted_counts) * rarity_pct / 100) - 1)
    pct_threshold = sorted_counts[idx]
    threshold     = min(pct_threshold, max_count)

    rare_ids = {tid for tid, count in freq.items() if count <= threshold}

    df = df.copy()
    df["is_anomaly"] = df["template_id"].map(lambda tid: int(tid) in rare_ids)
    return df, threshold, freq


def _gap_cluster(rows_iter, gap_seconds: int) -> list[list]:
    """Gap-cluster ts-sorted rows into groups. STRICT split: a neighbour gap
    >= gap_seconds starts a NEW group - equality does NOT merge. Reads
    float(row.ts). Shared by the burst pass (gap_seconds) and the boot-event pass
    (reboot_cluster_seconds) so the two can never drift on split semantics."""
    groups: list[list] = []
    current: list = []
    prev_ts: float | None = None
    for row in rows_iter:
        ts = float(row.ts)
        if prev_ts is not None and (ts - prev_ts) >= gap_seconds:
            groups.append(current)
            current = []
        current.append(row)
        prev_ts = ts
    if current:
        groups.append(current)
    return groups


def _detect_boot_events(
    reboot_df: pd.DataFrame, *, cluster_seconds: int
) -> list[_BootEvent]:
    """Cluster reboot-signal rows into per-host boot events. Pure. One reboot can
    fire several signals spanning more than burst_gap_seconds apart, so they are
    clustered on their OWN wider window (cluster_seconds) - a boot event is one
    cluster. All timestamp-less reboot rows on a host collapse into ONE
    indeterminate boot event (start_ts is None), bounded one-per-host. Empty or
    columnless input -> []."""
    if reboot_df.empty or not {"host", "ts"}.issubset(reboot_df.columns):
        return []

    # Copy BEFORE mutating: the caller passes a df[reboot_mask] slice, and
    # assigning into a slice raises SettingWithCopyWarning - this change's own
    # prerequisite is removing pandas warning noise, so do not add a new one.
    reboot_df = reboot_df.copy()
    reboot_df["host"] = reboot_df["host"].fillna("unknown")

    events: list[_BootEvent] = []
    for host, host_df in reboot_df.groupby("host", sort=False):
        parseable = host_df[host_df["ts"].notna()].sort_values("ts", kind="stable")
        nan_rows  = host_df[host_df["ts"].isna()]
        for cluster in _gap_cluster(parseable.itertuples(), cluster_seconds):
            events.append(_BootEvent(
                host=str(host),
                start_ts=float(cluster[0].ts),
                end_ts=float(cluster[-1].ts),
                signal_count=len(cluster),
            ))
        if len(nan_rows) > 0:
            events.append(_BootEvent(str(host), None, None, len(nan_rows)))
    return events


def _collapse_bursts(
    rare_df: pd.DataFrame,
    freq: dict[int, int],
    threshold: int,
    *,
    gap_seconds: int,
    min_size: int,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> list[tuple[float, Finding]]:
    """Per-host temporal burst collapse over the rare set.

    Pure: no I/O, no suppression. Reboot rows are excluded upstream (via
    ~reboot_mask in run()), so every rare NON-reboot row is represented EXACTLY
    once - folded into a burst summary (its line_count / program_mix / sample_raw)
    or emitted as an isolated MEDIUM needle; a 'rebooted' burst's line_count
    therefore counts non-reboot rare rows only. Returns the UNSORTED
    (sort_ts, Finding) pairs - run() owns the final cross-channel sort. [] on an
    empty rare set.
    """
    if rare_df.empty:
        return []

    # Defensive: pandas groupby drops NaN keys by default, which would silently
    # lose rows whose host failed to parse. Normalize to the "unknown" sentinel
    # (parse_host's own fallback) so every rare row survives the grouping.
    rare_df = rare_df.copy()
    rare_df["host"] = rare_df["host"].fillna("unknown")

    timestamped: list[tuple[float, Finding]] = []

    for host, host_df in rare_df.groupby("host", sort=False):
        # STABLE sort: rows sharing a ts (a ring-buffer flush at one second) must
        # keep input order so the chronological sample_raw cap is deterministic
        # and version-independent (default quicksort is unstable on ties).
        parseable = host_df[host_df["ts"].notna()].sort_values("ts", kind="stable")
        nan_rows  = host_df[host_df["ts"].isna()]

        for group in _gap_cluster(parseable.itertuples(), gap_seconds):
            if len(group) >= min_size:
                timestamped.append(_burst_finding(str(host), group, now, data_window))
            else:
                for row in group:
                    timestamped.append(
                        _isolated_finding(str(host), row, freq, threshold, now, data_window)
                    )

        for row in nan_rows.itertuples():
            timestamped.append(
                _isolated_finding(str(host), row, freq, threshold, now, data_window)
            )

    return timestamped


def _burst_finding(
    host: str,
    group: list,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> tuple[float, Finding]:
    """Build one INFO burst finding from a gap-clustered group of rare rows
    (already ts-sorted). Returns (sort_ts, finding). label is always None here -
    _reconcile is the SOLE writer of "rebooted" on a burst."""
    start_ts = float(group[0].ts)
    end_ts   = float(group[-1].ts)

    # program_mix from the canonical `program` column (govern-don't-grep -
    # `program` is part of the syslog minimal-5). A missing column / NaN coerces
    # to the "unknown" sentinel so a minimal frame never raises; this is the only
    # path that reads `program`. Pinned shape: list[[str, int]], top-3 by count
    # desc with name-asc tie-break (deterministic for goldens).
    counts: Counter = Counter()
    for r in group:
        prog = getattr(r, "program", None)
        counts["unknown" if prog is None or pd.isna(prog) else str(prog)] += 1
    program_mix = [
        [name, int(count)]
        for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    ]

    sample_raw = [str(r.raw) for r in group][:20]

    finding = Finding(
        detector=DETECTOR_NAME,
        severity=Severity.INFO,
        title=host,
        # Neutral wording at construction: whether this cluster is a reboot is
        # not known here - _reconcile is the sole writer of the "rebooted"
        # label and upgrades the description alongside it. An unlabeled burst
        # must not be narrated as a boot the detector never observed.
        description=(
            "A cluster of rare log lines on this host within a short window."
        ),
        evidence={
            "tier":         "burst",
            "line_count":   len(group),
            "span_seconds": end_ts - start_ts,
            "start_ts":     start_ts,
            "end_ts":       end_ts,
            "program_mix":  program_mix,
            "sample_raw":   sample_raw,
            "label":        None,
        },
        next_steps=["Skim the sampled lines to confirm the cluster's cause"],
        ts_generated=now,
        data_window=data_window,
    )
    return (start_ts, finding)


def _isolated_finding(
    host: str,
    row,
    freq: dict[int, int],
    threshold: int,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> tuple[float, Finding]:
    """Classify a single rare NON-reboot row that did not join a burst as a MEDIUM
    needle. Returns (sort_ts, finding). Reboot rows are handled on the separate
    full-frame channel (run() excludes them via ~reboot_mask), so a reboot row
    never reaches here through the detector and is never a MEDIUM needle."""
    ts_sort = float("inf") if pd.isna(row.ts) else float(row.ts)

    finding = Finding(
        detector=DETECTOR_NAME,
        severity=Severity.MEDIUM,
        title=str(row.raw)[:LINE_TRIM_LIMIT],
        description="Rare log template observed at or below the rarity threshold.",
        evidence={
            "host":         host,
            "template_id":  int(row.template_id),
            "template_str": row.template_str,
            "count":        int(freq[int(row.template_id)]),
            "threshold":    int(threshold),
        },
        next_steps=[
            "Review surrounding log context for this host",
            "Check if template appears in recent incidents",
        ],
        ts_generated=now,
        data_window=data_window,
    )
    return (ts_sort, finding)


def _reboot_finding(
    evt: _BootEvent,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> tuple[float, Finding]:
    """Build one INFO standalone reboot finding from a boot event. Returns
    (sort_ts, finding). start_ts is tested with `is None`, NEVER truthiness - a
    0.0 epoch is a valid timestamp and falsy, so `or` would misclassify it as
    indeterminate."""
    sort_ts = evt.start_ts if evt.start_ts is not None else float("inf")
    reboot_ts = (
        None if evt.start_ts is None
        else datetime.fromtimestamp(evt.start_ts, tz=timezone.utc).isoformat()
    )
    finding = Finding(
        detector=DETECTOR_NAME,
        severity=Severity.INFO,
        title=evt.host,
        description="A reboot signal observed on this host.",
        evidence={
            "tier":         "reboot",
            "host":         evt.host,
            "reboot_ts":    reboot_ts,
            "signal_count": evt.signal_count,
            "label":        "rebooted",
        },
        next_steps=["Review system logs around the reboot time for pre-reboot anomalies"],
        ts_generated=now,
        data_window=data_window,
    )
    return (sort_ts, finding)


def _reconcile(
    boot_events: list[_BootEvent],
    burst_pairs: list[tuple[float, Finding]],
    *,
    gap_seconds: int,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> list[tuple[float, Finding]]:
    """Reconcile the two channels to exactly one representation per boot event.

    Each boot event either labels the NEAREST contemporaneous burst "rebooted"
    (in place, on the STORED Finding) or emits one standalone reboot finding -
    never both. Association tolerance is gap_seconds (burst_gap_seconds, 60s), NOT
    the wider clustering window: the kernel banner sits at the head of the dmesg
    storm, so a boot event and its storm-burst are contemporaneous, and 60s
    refuses to absorb an unrelated rare-line burst minutes later. Returns the
    combined UNSORTED pairs; run() owns the final sort.
    """
    out: list[tuple[float, Finding]] = list(burst_pairs)

    # Index the STORED burst Findings by host (a burst's title IS its host;
    # evidence carries no host key). Claiming the stored object - never a rebuilt
    # candidate - is what keeps id() identity meaningful: mutating evidence["label"]
    # in place is visible through the same reference held in `out`.
    bursts_by_host: dict[str, list[Finding]] = defaultdict(list)
    for _, finding in out:
        if finding.evidence.get("tier") == "burst":
            bursts_by_host[finding.title].append(finding)

    claimed: set[int] = set()

    # Deterministic order: host by first-seen index, then start_ts ascending with
    # the indeterminate (None) event last - do not rely on groupby insertion order.
    host_order: dict[str, int] = {}
    for evt in boot_events:
        host_order.setdefault(evt.host, len(host_order))

    def _order_key(evt: _BootEvent):
        return (
            host_order[evt.host],
            (evt.start_ts is None, evt.start_ts if evt.start_ts is not None else 0.0),
        )

    for evt in sorted(boot_events, key=_order_key):
        if evt.start_ts is None:          # indeterminate (NaN-ts) - matches no burst
            out.append(_reboot_finding(evt, now, data_window))
            continue

        bs, be = evt.start_ts, evt.end_ts
        candidates: list[tuple[float, float, Finding]] = []
        for finding in bursts_by_host.get(evt.host, []):
            if id(finding) in claimed:
                continue
            ss = finding.evidence["start_ts"]
            se = finding.evidence["end_ts"]
            # Contemporaneous within the burst gap (half-open interval overlap
            # extended by gap_seconds on each side).
            if bs <= se + gap_seconds and ss <= be + gap_seconds:
                candidates.append((abs(ss - bs), ss, finding))

        if candidates:
            candidates.sort(key=lambda c: (c[0], c[1]))   # nearest; tie -> smaller ss
            target = candidates[0][2]
            target.evidence["label"] = "rebooted"
            # The label and the prose move together: only a burst a boot event
            # actually claimed may be described as a reboot.
            target.description = (
                "A cluster of rare log lines on this host within a short "
                "window, coinciding with a reboot of this host."
            )
            claimed.add(id(target))
        else:
            out.append(_reboot_finding(evt, now, data_window))

    return out
