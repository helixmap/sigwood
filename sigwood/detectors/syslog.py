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
4. Privileged membership partition over the rare set: exact canonical ``program``
   tokens in the shipped/operator roster enter the MEDIUM channel; all other rare
   rows enter the LOW sieve channel.
5. Per-host temporal burst collapse over the sieve only: rare NON-reboot rows on one
   host that cluster within burst_gap_seconds fold into a single INFO burst.
6. Family fold per membership branch: rows sharing (host, program) fold into one
   review unit; a family of one remains a needle. Every rare NON-reboot row is
   represented exactly once across member family/needle, sieve burst/family/needle.
7. Reconciliation: reboot rows are clustered per host into boot events
   (reboot_cluster_seconds); each event either labels the nearest contemporaneous
   burst "rebooted" (within burst_gap_seconds) or emits one standalone INFO reboot
   finding - exactly one representation per boot event. run() owns the final
   cross-channel output sort.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterable, NamedTuple

import pandas as pd
from tqdm import tqdm

from sigwood.common.display import narration_active
from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity
from sigwood.parsers.syslog import REBOOT_SIGNALS_RE, parse_timestamp, strip_program

DETECTOR_NAME = "syslog"
STATUS = "available"
IN_DEFAULT_HUNT: bool = True

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
FAMILY_MIN_SIZE           = 2    # min isolated rows for one host/program review unit
LINE_TRIM_LIMIT           = 200  # max finding trim length
REBOOT_CLUSTER_SECONDS    = 600  # reboot signals on a host closer than this = one boot event

# Tool-shipped Drain3 calibration. Keep the specification as strings so importing
# this detector never imports optional runtime objects or compiles their regexes.
LONG_HEX_MASK_PATTERN = r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8,}(?![0-9A-Fa-f])"
LONG_HEX_MASK_NAME = "LONG_HEX"

_LONG_HEX_MASK_RE = re.compile(LONG_HEX_MASK_PATTERN)
_HEX_LETTER_RE = re.compile(r"[A-Fa-f]")
_IP_TOKEN_TRIM = "()[]{}<>.,;:'\""
_IP_COMPOUND_TRIM = "(){}<>.,;:'\""
_FRAGMENT_TEMPLATE_SCAN_LIMIT = 6
_FRAGMENT_LIMIT = 3
_FRAGMENT_LENGTH = 80

# Security-critical program identities. Membership is exact, case-sensitive
# equality against the canonical ``program`` column - never message matching.
PRIVILEGED_PROGRAMS: tuple[str, ...] = (
    # auth/session
    "sshd", "sshd-session", "sshd-auth", "login", "sulogin",
    # privilege/authorization
    "sudo", "su", "runuser", "doas", "pkexec", "polkitd",
    # accounts
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
    "passwd", "chpasswd", "chage", "gpasswd", "newusers", "chgpasswd",
    "groupmems", "chsh",
    # group switching
    "newgrp", "sg",
    # audit/logging
    "auditd", "audisp-syslog", "audispd",
    # crashes
    "systemd-coredump",
)

DEFAULT_CONFIG = {
    "rarity_pct":         10,
    "max_count":           1,
    "sim_thresh":          DRAIN_SIM_THRESH,
    "depth":               DRAIN_DEPTH,
    "parametrize_numeric": DRAIN_PARAMETRIZE_NUMERIC,
    "burst_gap_seconds":   BURST_GAP_SECONDS,
    "burst_min_size":      BURST_MIN_SIZE,
    "family_min_size":     FAMILY_MIN_SIZE,
    # Fresh copy: operator/config mutation must never alter the module constant.
    "privileged_programs": list(PRIVILEGED_PROGRAMS),
    "reboot_cluster_seconds": REBOOT_CLUSTER_SECONDS,
    "line_trim_limit":     LINE_TRIM_LIMIT,
}

DETECTOR_METHOD = MethodTag("drain3", named=True)


class MinedResult(NamedTuple):
    """Online assignments plus the final miner and mutation diagnostics."""
    template_ids: list[int]
    template_strs: list[str]
    miner: "TemplateMiner"
    template_changed_total: int
    clusters_changed: int


def _is_ip_token(token: str) -> bool:
    """True for a direct IP or the approved IP-and-port token forms."""
    candidate = token.strip(_IP_TOKEN_TRIM)
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return True

    if candidate.count(":") == 1:
        host, port = candidate.split(":", 1)
        if port.isdecimal():
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                if isinstance(address, ipaddress.IPv4Address):
                    return True

    compound = token.strip(_IP_COMPOUND_TRIM)
    if compound.startswith("[") and "]:" in compound:
        host, port = compound[1:].rsplit("]:", 1)
        if port.isdecimal():
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                return isinstance(address, ipaddress.IPv6Address)
    return False


def _contains_opaque_hex(token: str) -> bool:
    """True when a shipped-mask run contains an ASCII hex letter."""
    return any(_HEX_LETTER_RE.search(match.group(0)) for match in _LONG_HEX_MASK_RE.finditer(token))


def _truncate_fragment(fragment: str) -> str:
    """Fit a fragment to 80 characters, including its ellipsis when cut."""
    if len(fragment) <= _FRAGMENT_LENGTH:
        return fragment

    kept: list[str] = []
    for token in fragment.split():
        candidate = " ".join([*kept, token])
        if len(candidate) > _FRAGMENT_LENGTH - 1:
            break
        kept.append(token)
    if kept:
        return " ".join(kept) + "…"
    return fragment[:_FRAGMENT_LENGTH - 1] + "…"


def _distill_member_fragments(rows: Iterable[object]) -> list[str]:
    """Return up to three distinct, bounded fragments from ordered members."""
    seen_templates: set[object] = set()
    seen_fragments: set[str] = set()
    fragments: list[str] = []

    for row in rows:
        template_id = getattr(row, "template_id", None)
        message = getattr(row, "message", None)
        if template_id is None or message is None:
            continue
        if pd.isna(template_id) or pd.isna(message):
            continue
        if template_id in seen_templates:
            continue
        if len(seen_templates) >= _FRAGMENT_TEMPLATE_SCAN_LIMIT:
            break
        seen_templates.add(template_id)

        body = strip_program(str(message))
        kept = [
            token
            for token in body.split()
            if _is_ip_token(token) or not _contains_opaque_hex(token)
        ]
        distilled = " ".join(kept).strip()
        if not distilled:
            continue
        rendered = _truncate_fragment(distilled)
        if rendered in seen_fragments:
            continue
        seen_fragments.add(rendered)
        fragments.append(rendered)
        if len(fragments) >= _FRAGMENT_LIMIT:
            break
    return fragments


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
    temporal burst collapse, and per-program family review units."""
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
    family_min_size = cfg.get("family_min_size", DEFAULT_CONFIG["family_min_size"])
    privileged_programs = cfg.get(
        "privileged_programs", DEFAULT_CONFIG["privileged_programs"]
    )
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
    rare_df = df[df["is_anomaly"] & ~reboot_mask].copy()

    # The magnitude anchor is the FULL loaded population for each canonical
    # (host, program) identity, not the rare subset, family size, or sample cap.
    identity_df = _normalize_identity_columns(df)
    program_totals = {
        (host, program): int(len(group))
        for (host, program), group in identity_df.groupby(
            ["host", "program"], sort=False
        )
    }

    # One mask and its boolean complement over the RAW rare frame are the
    # exactly-once seam. Keep identity normalization local to its consumers so
    # the sieve reaches the unchanged burst pass with unit-A input semantics.
    # NaN never matches ``isin``; removing the literal also keeps ``unknown``
    # non-privileged if an operator accidentally lists it.
    eligible_programs = set(privileged_programs) - {"unknown"}
    programs = (
        rare_df["program"]
        if "program" in rare_df.columns
        else pd.Series(None, index=rare_df.index, dtype=object)
    )
    member_mask = programs.isin(eligible_programs)
    member_df = rare_df.loc[member_mask].copy()
    sieve_df = rare_df.loc[~member_mask].copy()

    burst_pairs, isolated_remainder = _collapse_bursts(
        sieve_df,
        gap_seconds=gap_seconds, min_size=min_size,
        now=now, data_window=context.data_window,
    )
    _decorate_burst_first_seen(burst_pairs)
    sieve_pairs = _collapse_families(
        isolated_remainder, freq, threshold,
        min_size=family_min_size, now=now, data_window=context.data_window,
        severity=Severity.LOW, privileged=False, program_totals=program_totals,
    )
    member_pairs = _collapse_families(
        member_df, freq, threshold,
        min_size=family_min_size, now=now, data_window=context.data_window,
        severity=Severity.MEDIUM, privileged=True, program_totals=program_totals,
    )
    pairs = _reconcile(
        boot_events, [*burst_pairs, *sieve_pairs, *member_pairs],
        gap_seconds=gap_seconds, now=now, data_window=context.data_window,
    )
    # run() owns the SINGLE final cross-channel output sort; the helpers keep their
    # own internal stable ts sorts but return unsorted pairs.
    pairs.sort(key=lambda pair: pair[0])
    return [f for _, f in pairs]


def _normalize_identity_columns(frame: pd.DataFrame) -> pd.DataFrame:
    """Copy ``frame`` and normalize missing host/program identities to ``unknown``.

    Values are otherwise byte/type-preserved: privileged membership remains exact
    canonical-token equality with no case folding, basename parsing, or coercion.
    """
    work = frame.copy()
    for column in ("host", "program"):
        if column not in work.columns:
            work[column] = "unknown"
        else:
            work[column] = work[column].fillna("unknown")
    return work


def _run_drain3(
    df: pd.DataFrame,
    sim_thresh: float,
    depth: int,
    parametrize_numeric: bool,
) -> pd.DataFrame:
    """Add template_id and template_str columns via drain3 log templating."""
    try:
        from drain3.masking import MaskingInstruction
    except ImportError:
        raise ImportError(
            "drain3 is required for syslog detection. Run: pip install drain3"
        )

    result = mine_templates(
        (str(msg) for msg in df["message"]),
        sim_thresh=sim_thresh,
        depth=depth,
        parametrize_numeric=parametrize_numeric,
        masking_instructions=[
            MaskingInstruction(LONG_HEX_MASK_PATTERN, LONG_HEX_MASK_NAME)
        ],
    )

    df = df.copy()
    df["template_id"]  = result.template_ids
    df["template_str"] = result.template_strs
    return df


def mine_templates(
    messages: Iterable[str],
    *,
    sim_thresh: float,
    depth: int,
    parametrize_numeric: bool,
    masking_instructions: list | None = None,
    show_progress: bool = True,
) -> MinedResult:
    """Mine string messages and return online assignments plus mutation counts."""
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
    if masking_instructions is not None:
        cfg.masking_instructions = masking_instructions

    miner = TemplateMiner(config=cfg)
    template_ids: list[int] = []
    template_strs: list[str] = []
    template_changed_total = 0
    changed_cluster_ids: set[int] = set()

    # leave=True + clean bar_format makes this the liveness narration for the
    # syslog detector phase (the runner deliberately skips its outer spinner
    # for syslog so the two writers don't fight for the same stderr line).
    # ``narration_active`` is the runner-set global gate (-q) + the stderr TTY
    # check: -q or a piped run disables the bar WITHOUT this detector reading a
    # quiet field, so the detectors-are-render-blind rail stays intact.
    for msg in tqdm(
        messages,
        desc="syslog: mining templates",
        unit=" lines",
        unit_scale=True,
        leave=True,
        bar_format="{desc}: {n_fmt} lines [{elapsed}]",
        disable=not (show_progress and narration_active(sys.stderr)),
    ):
        result = miner.add_log_message(msg)
        template_ids.append(result["cluster_id"])
        template_strs.append(result["template_mined"])
        if result["change_type"] == "cluster_template_changed":
            template_changed_total += 1
            changed_cluster_ids.add(result["cluster_id"])

    return MinedResult(
        template_ids=template_ids,
        template_strs=template_strs,
        miner=miner,
        template_changed_total=template_changed_total,
        clusters_changed=len(changed_cluster_ids),
    )


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
    *,
    gap_seconds: int,
    min_size: int,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> tuple[list[tuple[float, Finding]], pd.DataFrame]:
    """Per-host temporal burst collapse over the rare set.

    Pure: no I/O, no suppression. Reboot rows are excluded upstream (via
    ~reboot_mask in run()). Returns burst (sort_ts, Finding) pairs plus the exact
    row complement for the family pass. NaN-ts rows are always in that remainder;
    a 'rebooted' burst's line_count therefore counts non-reboot rare rows only.
    run() owns the final cross-channel sort.
    """
    if rare_df.empty:
        return [], rare_df.copy()

    # Defensive: pandas groupby drops NaN keys by default, which would silently
    # lose rows whose host failed to parse. Normalize to the "unknown" sentinel
    # (parse_host's own fallback) so every rare row survives the grouping.
    work = rare_df.copy().reset_index(drop=True)
    work["host"] = work["host"].fillna("unknown")

    timestamped: list[tuple[float, Finding]] = []
    burst_member = pd.Series(False, index=work.index, dtype=bool)

    for host, host_df in work.groupby("host", sort=False):
        # STABLE sort: rows sharing a ts (a ring-buffer flush at one second) must
        # keep input order so the chronological sample_raw cap is deterministic
        # and version-independent (default quicksort is unstable on ties).
        parseable = host_df[host_df["ts"].notna()].sort_values("ts", kind="stable")

        for group in _gap_cluster(parseable.itertuples(), gap_seconds):
            if len(group) >= min_size:
                burst_member.loc[[int(row.Index) for row in group]] = True
                timestamped.append(_burst_finding(str(host), group, now, data_window))

    # Boolean-complement construction makes the accounting seam explicit: rows
    # are never rebuilt from namedtuples, duplicate source indexes cannot expand
    # the result, and every unmarked timestamped/NaN-ts row survives once.
    return timestamped, work.loc[~burst_member].copy()


def _collapse_families(
    isolated_df: pd.DataFrame,
    freq: dict[int, int],
    threshold: int,
    *,
    min_size: int,
    now: datetime,
    data_window: tuple[datetime, datetime],
    severity: Severity,
    privileged: bool,
    program_totals: dict[tuple[object, object], int],
) -> list[tuple[float, Finding]]:
    """Fold isolated rare rows into one explicit membership/severity channel.

    Pure: no I/O, no suppression. Groups below ``min_size`` route through the
    existing isolated-needle builder. Returns unsorted pairs; run() owns the
    final cross-channel sort.
    """
    if isolated_df.empty:
        return []

    work = isolated_df.copy()
    if "program" not in work.columns:
        work["program"] = "unknown"
    else:
        work["program"] = work["program"].fillna("unknown")

    pairs: list[tuple[float, Finding]] = []
    for (host, program), family_df in work.groupby(["host", "program"], sort=False):
        if len(family_df) < min_size:
            for row in family_df.itertuples():
                pairs.append(
                    _isolated_finding(
                        str(host), row, freq, threshold, now, data_window,
                        severity=severity,
                        privileged=privileged,
                        program_total=program_totals.get((host, program), 0),
                    )
                )
            continue

        ordered = family_df.sort_values(
            "ts", kind="stable", na_position="last"
        )
        parseable = ordered[ordered["ts"].notna()]
        if parseable.empty:
            start_ts = end_ts = span_seconds = None
            sort_ts = float("inf")
        else:
            start_ts = float(parseable.iloc[0]["ts"])
            end_ts = float(parseable.iloc[-1]["ts"])
            span_seconds = end_ts - start_ts
            sort_ts = start_ts

        line_count = int(len(family_df))
        member_fragments = _distill_member_fragments(
            ordered.itertuples(index=False)
        )
        description = (
            "A set of rare log lines from a single program on this host, each "
            "at or below the rarity threshold."
        )
        if privileged:
            description += " This program is in sigwood's privileged class."
        evidence = {
            "tier": "family",
            "host": str(host),
            "program": str(program),
            "line_count": line_count,
            "program_total": program_totals.get((host, program), 0),
            "start_ts": start_ts,
            "end_ts": end_ts,
            "first_seen": _iso_utc(start_ts),
            "span_seconds": span_seconds,
            "sample_raw": [str(raw) for raw in ordered["raw"].iloc[:20]],
            "member_fragments": member_fragments,
            "label": None,
        }
        if privileged:
            evidence["privileged"] = True
        finding = Finding(
            detector=DETECTOR_NAME,
            severity=severity,
            title=str(host),
            description=description,
            evidence=evidence,
            next_steps=["Skim the sampled lines to confirm the cluster's cause"],
            ts_generated=now,
            data_window=data_window,
        )
        pairs.append((sort_ts, finding))

    return pairs


def _iso_utc(value: float | None) -> str | None:
    """Render a nullable float epoch as ISO-8601 UTC; preserve valid ``0.0``."""
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _decorate_burst_first_seen(
    burst_pairs: list[tuple[float, Finding]],
) -> None:
    """Add ``first_seen`` to stored burst evidence dictionaries IN PLACE.

    ``_reconcile`` claims the stored Finding by ``id()`` and mutates its reboot
    label. Rebuilding or copying a Finding here would break that association.
    """
    for _sort_ts, finding in burst_pairs:
        if finding.evidence.get("tier") == "burst":
            finding.evidence["first_seen"] = _iso_utc(
                finding.evidence.get("start_ts")
            )


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
    # to the "unknown" sentinel so a minimal frame never raises. Pinned shape:
    # list[[str, int]], top-3 by count
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
    member_fragments = _distill_member_fragments(group)

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
            "member_fragments": member_fragments,
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
    *,
    severity: Severity,
    privileged: bool,
    program_total: int,
) -> tuple[float, Finding]:
    """Classify a single rare NON-reboot row in one explicit membership channel.

    Returns (sort_ts, finding). Reboot rows are handled on the separate
    full-frame channel (run() excludes them via ~reboot_mask), so a reboot row
    never reaches here through the detector and is never a MEDIUM needle."""
    ts_sort = float("inf") if pd.isna(row.ts) else float(row.ts)
    program = getattr(row, "program", None)
    program = "unknown" if program is None or pd.isna(program) else str(program)

    description = "Rare log template observed at or below the rarity threshold."
    if privileged:
        description += " This program is in sigwood's privileged class."
    evidence = {
        "host":         host,
        "program":      program,
        "program_total": int(program_total),
        "template_id":  int(row.template_id),
        "template_str": row.template_str,
        "count":        int(freq[int(row.template_id)]),
        "threshold":    int(threshold),
        "first_seen":   _iso_utc(None if pd.isna(row.ts) else float(row.ts)),
        "self_stamped": parse_timestamp(str(row.raw)) is not None,
    }
    if privileged:
        evidence["privileged"] = True

    finding = Finding(
        detector=DETECTOR_NAME,
        severity=severity,
        title=str(row.raw)[:LINE_TRIM_LIMIT],
        description=description,
        evidence=evidence,
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
    collapsed_pairs: list[tuple[float, Finding]],
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
    out: list[tuple[float, Finding]] = list(collapsed_pairs)

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
