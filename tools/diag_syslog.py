#!/usr/bin/env python3
"""Measure syslog template fragmentation without changing detector behavior.

This reproducibility tool accepts ISO-8601 bounds. Naive bounds are read as UTC,
unlike the sigwood CLI, whose naive bounds follow the display timezone.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
import traceback
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, NoReturn

import pandas as pd

from sigwood.common.finding import Severity
from sigwood.common.loader import load_logs, load_syslog
from sigwood.detectors import syslog as detector
from sigwood.parsers.syslog import REBOOT_SIGNALS_RE


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
SHUFFLE_SEED = 3759
PASS_ORDER = ("masked", "order", "recount", "simple")
CSV_FORMULA_PREFIXES = "=+-@\t\r"

PUBLIC_PROGRAMS = frozenset({
    "sshd", "sudo", "su", "login", "useradd", "userdel", "usermod",
    "groupadd", "groupdel", "passwd", "chpasswd", "chage", "pkexec",
    "polkitd", "doas", "cron", "crond", "anacron", "kernel", "systemd",
    "systemd-udevd", "systemd-logind", "systemd-timesyncd",
    "systemd-resolved", "systemd-networkd", "dnsmasq", "dnsmasq-dhcp",
    "NetworkManager", "postfix/smtpd", "postfix/cleanup", "postfix/pickup",
    "postfix/qmgr", "postfix/local", "chronyd", "ntpd", "rsyslogd",
    "auditd", "sssd", "dbus-daemon", "avahi-daemon", "smartd", "dhclient",
    "pihole-FTL",
})


@dataclass(frozen=True)
class MaskSpec:
    """One conservative mask used by post-hoc and Drain3 measurements."""

    name: str
    pattern: str


_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])"
MASK_SPECS = (
    MaskSpec(
        "uuid",
        r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-"
        r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
        r"[0-9A-Fa-f]{12}(?![0-9A-Fa-f])",
    ),
    MaskSpec(
        "mac",
        r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}:){5}"
        r"[0-9A-Fa-f]{2}(?![0-9A-Fa-f])",
    ),
    MaskSpec(
        "ipv6",
        r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){3,7}"
        r"[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])",
    ),
    MaskSpec(
        "ipv4",
        rf"(?<![0-9.]){_OCTET}(?:\.{_OCTET}){{3}}(?![0-9.])",
    ),
    MaskSpec("ring_stamp", r"\[\s*[0-9]+\.[0-9]{3,}\]"),
    MaskSpec(
        "long_hex",
        r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8,}(?![0-9A-Fa-f])",
    ),
    MaskSpec(
        "number_with_unit",
        r"(?<![A-Za-z0-9_.])[0-9]+(?:\.[0-9]+)?"
        r"(?:ms|s|kB|KiB|MB|MiB|GB)(?![A-Za-z0-9_])",
    ),
)
MASK_NAMES = tuple(spec.name for spec in MASK_SPECS)
MASK_PATTERNS = {spec.name: re.compile(spec.pattern) for spec in MASK_SPECS}
IDENTITY_DISCLOSURE = (
    "post-hoc substitutions are an identity-only lower bound; "
    "similarity-merge effects are invisible"
)
PSEUDONYM_RE = re.compile(r"^prog_[0-9]{2,}$")

TOP_KEYS = frozenset({"schema_version", "resolved_settings", "passes"})
RESOLVED_KEYS = frozenset({
    "selected_passes", "requested_window", "effective_window", "feed_rows",
    "total_rows", "feed_order", "seed", "mask_order", "detector_settings",
    "template_identity",
})
WINDOW_KEYS = frozenset({"since", "until"})
FEED_ROWS_KEYS = frozenset({"flat", "zeek"})
SETTINGS_KEYS = frozenset({
    "sim_thresh", "depth", "parametrize_numeric", "rarity_pct", "max_count",
    "burst_gap_seconds", "burst_min_size", "reboot_cluster_seconds",
})
BASELINE_KEYS = frozenset({
    "population", "token_buckets", "adjacency_signature", "routing",
    "wildcards", "template_mutation", "needle_equivalent", "programs",
    "top3_program_singleton_share", "unmeasured",
})
POPULATION_KEYS = frozenset({
    "total_rows", "distinct_templates", "singleton_count", "singleton_share",
    "count_histogram",
})
COUNT_HISTOGRAM_KEYS = frozenset({"1", "2_5", "6_20", "21_plus"})
TOKEN_BUCKET_KEYS = frozenset({"templates", "singletons"})
ROUTING_KEYS = frozenset({
    "distinct_first_tokens", "singleton_first_token_variable_share",
})
WILDCARD_KEYS = frozenset({"histogram", "ceiling_saturated_count"})
WILDCARD_HISTOGRAM_KEYS = frozenset({"0", "0_0.25", "0.25_0.5", "0.5_1.0"})
MUTATION_KEYS = frozenset({"template_changed_total", "clusters_changed"})
PROGRAM_KEYS = frozenset({"program", "rows", "templates", "singletons"})
FORK_KEYS = frozenset({"fork_pairs", "pid_form_fork_count"})
MASKED_KEYS = frozenset({
    "identity_only_lower_bound", "posthoc", "remine", "combined",
})
POSTHOC_KEYS = frozenset({"templates_after", "singletons_after", "template_delta"})
REMINE_KEYS = frozenset({
    "distinct_templates_after", "singletons_after", "needle_equivalent_after",
    "needle_delta",
})
ORDER_KEYS = frozenset({"variants_run", "variants_skipped", "variants"})
ORDER_VARIANT_KEYS = frozenset({"partition_delta_rows", "singleton_count_delta"})
RECOUNT_KEYS = frozenset({
    "recount_divergent_rows", "recount_singleton_count", "recount_unmatched",
})
SIMPLE_KEYS = frozenset({
    "simple_distinct", "simple_singletons", "simple_needle_equivalent",
})


class SummaryRefusal(ValueError):
    """A fail-closed refusal for a structurally invalid safe summary."""


class DiagnosticFailure(RuntimeError):
    """An operational failure with a bounded terminal-safe message."""

    def __init__(self, safe_message: str) -> None:
        super().__init__(safe_message)
        self.safe_message = safe_message


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser whose failures never echo path-bearing arguments."""

    def error(self, message: str) -> NoReturn:
        del message
        self.exit(2, "diag-syslog: invalid arguments\n")


@dataclass
class MiningRun:
    """A mined frame with online assignments and final cluster templates."""

    frame: pd.DataFrame
    result: detector.MinedResult
    template_table: pd.DataFrame


def _build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--syslog-dir", type=Path)
    parser.add_argument("--zeek-dir", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--since",
        help="ISO-8601 lower bound; naive bounds are UTC, unlike the sigwood CLI",
    )
    parser.add_argument(
        "--until",
        help="ISO-8601 upper bound; naive bounds are UTC, unlike the sigwood CLI",
    )
    parser.add_argument(
        "--passes",
        default="",
        help="extra comma-separated passes: masked,order,recount,simple",
    )
    parser.add_argument("--verify-repeat", action="store_true")
    return parser


def _safe_error(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def _parse_bound(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_passes(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    tokens = value.split(",")
    if any(not token or token not in PASS_ORDER for token in tokens):
        raise ValueError("invalid pass list")
    if len(tokens) != len(set(tokens)):
        raise ValueError("duplicate pass")
    selected = set(tokens)
    return tuple(name for name in PASS_ORDER if name in selected)


def _prepare_bundle(raw_path: Path) -> Path:
    path = raw_path.expanduser().resolve()
    if path == REPO_ROOT or REPO_ROOT in path.parents:
        raise ValueError("bundle is inside repository")
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise ValueError("bundle is not a new empty directory")
    else:
        path.mkdir(parents=True, exist_ok=False)
    return path


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(timezone.utc).isoformat()


def _program_value(value: object) -> str:
    if value is None or pd.isna(value):
        return "unknown"
    return str(value)


def _majority_program(values: Iterable[object]) -> str:
    counts = Counter(_program_value(value) for value in values)
    highest = max(counts.values())
    return min(name for name, count in counts.items() if count == highest)


def _final_templates(miner: Any) -> dict[int, str]:
    return {
        int(cluster.cluster_id): str(cluster.get_template())
        for cluster in miner.drain.clusters
    }


def _template_table(frame: pd.DataFrame, final_templates: dict[int, str]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for template_id, group in frame.groupby("template_id", sort=True):
        template = final_templates[int(template_id)]
        tokens = template.split()
        rows.append({
            "template_id": int(template_id),
            "template_str": template,
            "count": int(len(group)),
            "token_count": len(tokens),
            "wildcard_fraction": (
                sum(token == "<*>" for token in tokens) / len(tokens) if tokens else 0.0
            ),
            "program": _majority_program(group["program"]),
            "feeds": ",".join(sorted(str(feed) for feed in group["feed"].unique())),
        })
    return pd.DataFrame(rows)


def _mine_frame(
    frame: pd.DataFrame,
    *,
    masking_instructions: list | None = None,
) -> MiningRun:
    messages = [str(value) for value in frame["message"]]
    result = detector.mine_templates(
        messages,
        sim_thresh=float(detector.DEFAULT_CONFIG["sim_thresh"]),
        depth=int(detector.DEFAULT_CONFIG["depth"]),
        parametrize_numeric=bool(detector.DEFAULT_CONFIG["parametrize_numeric"]),
        masking_instructions=masking_instructions,
        show_progress=False,
    )
    mined = frame.copy()
    mined["template_id"] = result.template_ids
    final_templates = _final_templates(result.miner)
    mined["template_str"] = mined["template_id"].map(final_templates)
    return MiningRun(mined, result, _template_table(mined, final_templates))


def _usable_window(frame: pd.DataFrame) -> tuple[datetime, datetime] | None:
    values: list[float] = []
    if "ts" in frame:
        for raw in frame["ts"].dropna():
            try:
                value = float(raw)
            except (TypeError, ValueError):
                continue
            if math.isfinite(value):
                values.append(value)
    if not values:
        return None
    return (
        datetime.fromtimestamp(min(values), timezone.utc),
        datetime.fromtimestamp(max(values), timezone.utc),
    )


def _needle_equivalent(frame: pd.DataFrame) -> int:
    scored, threshold, freq = detector._score_rarity(
        frame,
        int(detector.DEFAULT_CONFIG["rarity_pct"]),
        int(detector.DEFAULT_CONFIG["max_count"]),
    )
    reboot_mask = scored["message"].astype(str).str.contains(REBOOT_SIGNALS_RE, na=False)
    rare = scored[scored["is_anomaly"] & ~reboot_mask].copy()
    window = _usable_window(scored)
    if window is None:
        epoch = datetime.fromtimestamp(0, timezone.utc)
        window = (epoch, epoch)
    now = window[1]
    pairs = detector._collapse_bursts(
        rare,
        freq,
        threshold,
        gap_seconds=int(detector.DEFAULT_CONFIG["burst_gap_seconds"]),
        min_size=int(detector.DEFAULT_CONFIG["burst_min_size"]),
        now=now,
        data_window=window,
    )
    return sum(finding.severity is Severity.MEDIUM for _, finding in pairs)


def _count_histogram(counts: Iterable[int]) -> dict[str, int]:
    result = {key: 0 for key in ("1", "2_5", "6_20", "21_plus")}
    for count in counts:
        if count == 1:
            result["1"] += 1
        elif count <= 5:
            result["2_5"] += 1
        elif count <= 20:
            result["6_20"] += 1
        else:
            result["21_plus"] += 1
    return result


def _wildcard_histogram(values: Iterable[float]) -> dict[str, int]:
    result = {key: 0 for key in ("0", "0_0.25", "0.25_0.5", "0.5_1.0")}
    for value in values:
        if value == 0:
            result["0"] += 1
        elif value <= 0.25:
            result["0_0.25"] += 1
        elif value <= 0.5:
            result["0.25_0.5"] += 1
        else:
            result["0.5_1.0"] += 1
    return result


def _apply_masks(value: str, specs: Iterable[MaskSpec]) -> str:
    result = value
    for spec in specs:
        result = MASK_PATTERNS[spec.name].sub(f"<{spec.name.upper()}>", result)
    return result


def _program_projection(table: pd.DataFrame) -> tuple[list[dict[str, Any]], dict[str, str]]:
    stats: list[dict[str, Any]] = []
    for program, group in table.groupby("program", sort=False):
        stats.append({
            "raw": str(program),
            "rows": int(group["count"].sum()),
            "templates": int(len(group)),
            "singletons": int((group["count"] == 1).sum()),
        })
    stats.sort(key=lambda row: (-row["singletons"], -row["templates"], -row["rows"], row["raw"]))
    decode: dict[str, str] = {}
    projected: list[dict[str, Any]] = []
    anonymous_rank = 0
    for row in stats:
        raw = row["raw"]
        if raw in PUBLIC_PROGRAMS:
            safe = raw
        else:
            anonymous_rank += 1
            safe = f"prog_{anonymous_rank:02d}"
            decode[safe] = raw
        projected.append({
            "program": safe,
            "rows": row["rows"],
            "templates": row["templates"],
            "singletons": row["singletons"],
        })
    return projected, decode


def _feed_forks(run: MiningRun) -> dict[str, int] | None:
    if set(run.frame["feed"].unique()) != {"flat", "zeek"}:
        return None
    table = run.template_table.copy()
    table["masked_key"] = table["template_str"].map(
        lambda value: _apply_masks(str(value), MASK_SPECS)
    )
    fork_pairs = 0
    for _, group in table.groupby(["program", "masked_key"], sort=False):
        flat_ids = set(group[group["feeds"].str.contains("flat")]["template_id"])
        zeek_ids = set(group[group["feeds"].str.contains("zeek")]["template_id"])
        if flat_ids and zeek_ids and len(flat_ids | zeek_ids) > 1:
            fork_pairs += 1

    pid_forms: dict[str, dict[str, list[tuple[int, set[str]]]]] = {}
    for row in table.itertuples():
        template = str(row.template_str)
        first = template.split(maxsplit=1)[0] if template.split() else ""
        if first.endswith("[*]:"):
            base, form = first[:-4], "pid"
        elif first.endswith(":"):
            base, form = first[:-1], "plain"
        else:
            continue
        pid_forms.setdefault(base, {}).setdefault(form, []).append(
            (int(row.template_id), set(str(row.feeds).split(",")))
        )

    pid_form_forks = 0
    for forms in pid_forms.values():
        for plain_id, plain_feeds in forms.get("plain", []):
            for pid_id, pid_feeds in forms.get("pid", []):
                crosses_feed = any(
                    left != right for left in plain_feeds for right in pid_feeds
                )
                if plain_id != pid_id and crosses_feed:
                    pid_form_forks += 1
                    break
            else:
                continue
            break
    return {
        "fork_pairs": fork_pairs,
        "pid_form_fork_count": pid_form_forks,
    }


def _baseline(run: MiningRun) -> tuple[dict[str, Any], dict[str, str]]:
    table = run.template_table
    counts = [int(value) for value in table["count"]]
    distinct = len(table)
    singletons = int((table["count"] == 1).sum())
    token_buckets: dict[str, dict[str, int]] = {}
    for token_count, group in table.groupby("token_count", sort=True):
        token_buckets[str(int(token_count))] = {
            "templates": int(len(group)),
            "singletons": int((group["count"] == 1).sum()),
        }

    non_singleton_buckets: dict[str, set[int]] = {}
    for program, group in table[table["count"] > 1].groupby("program", sort=False):
        non_singleton_buckets[str(program)] = set(int(value) for value in group["token_count"])
    adjacency = 0
    for row in table[table["count"] == 1].itertuples():
        neighbors = non_singleton_buckets.get(str(row.program), set())
        if (int(row.token_count) - 1) in neighbors or (int(row.token_count) + 1) in neighbors:
            adjacency += 1

    first_tokens = [
        str(template).split(maxsplit=1)[0] if str(template).split() else ""
        for template in table["template_str"]
    ]
    first_counts = Counter(first_tokens)
    variable_singletons = 0
    for row, first in zip(table.itertuples(), first_tokens):
        if int(row.count) == 1 and not any(char.isdigit() for char in first) and first_counts[first] == 1:
            variable_singletons += 1

    programs, decode = _program_projection(table)
    top3_singletons = sum(row["singletons"] for row in programs[:3])
    feed_forks = _feed_forks(run)
    baseline: dict[str, Any] = {
        "population": {
            "total_rows": int(len(run.frame)),
            "distinct_templates": distinct,
            "singleton_count": singletons,
            "singleton_share": singletons / distinct if distinct else 0.0,
            "count_histogram": _count_histogram(counts),
        },
        "token_buckets": token_buckets,
        "adjacency_signature": adjacency,
        "routing": {
            "distinct_first_tokens": len(set(first_tokens)),
            "singleton_first_token_variable_share": (
                variable_singletons / singletons if singletons else 0.0
            ),
        },
        "wildcards": {
            "histogram": _wildcard_histogram(table["wildcard_fraction"]),
            "ceiling_saturated_count": int((
                table["wildcard_fraction"]
                > (1.0 - float(detector.DEFAULT_CONFIG["sim_thresh"]))
            ).sum()),
        },
        "template_mutation": {
            "template_changed_total": run.result.template_changed_total,
            "clusters_changed": run.result.clusters_changed,
        },
        "needle_equivalent": _needle_equivalent(run.frame),
        "programs": programs,
        "top3_program_singleton_share": top3_singletons / singletons if singletons else 0.0,
        "unmeasured": ["key_value_splitting", "host_port", "journal_feed"],
    }
    if feed_forks is not None:
        baseline["feed_forks"] = feed_forks
    return baseline, decode


def _masking_instructions(specs: Iterable[MaskSpec]) -> list:
    from drain3.masking import MaskingInstruction

    return [MaskingInstruction(spec.pattern, spec.name.upper()) for spec in specs]


def _posthoc(table: pd.DataFrame, spec: MaskSpec) -> dict[str, int]:
    grouped: dict[str, int] = Counter()
    pattern = MASK_PATTERNS[spec.name]
    for row in table.itertuples():
        key = pattern.sub(f"<{spec.name.upper()}>", str(row.template_str))
        grouped[key] += int(row.count)
    templates_after = len(grouped)
    return {
        "templates_after": templates_after,
        "singletons_after": sum(count == 1 for count in grouped.values()),
        "template_delta": int(len(table) - templates_after),
    }


def _remine_metrics(run: MiningRun, baseline_needles: int) -> dict[str, int]:
    singleton_count = int((run.template_table["count"] == 1).sum())
    needles = _needle_equivalent(run.frame)
    return {
        "distinct_templates_after": int(len(run.template_table)),
        "singletons_after": singleton_count,
        "needle_equivalent_after": needles,
        "needle_delta": needles - baseline_needles,
    }


def _masked_pass(
    frame: pd.DataFrame,
    baseline: MiningRun,
    tables: dict[str, pd.DataFrame],
) -> dict[str, Any]:
    baseline_needles = _needle_equivalent(baseline.frame)
    posthoc = {spec.name: _posthoc(baseline.template_table, spec) for spec in MASK_SPECS}
    remines: dict[str, dict[str, int]] = {}
    for spec in MASK_SPECS:
        run = _mine_frame(frame, masking_instructions=_masking_instructions([spec]))
        tables[f"masked-{spec.name}"] = run.template_table
        remines[spec.name] = _remine_metrics(run, baseline_needles)
    combined_run = _mine_frame(frame, masking_instructions=_masking_instructions(MASK_SPECS))
    tables["masked-combined"] = combined_run.template_table
    return {
        "identity_only_lower_bound": IDENTITY_DISCLOSURE,
        "posthoc": posthoc,
        "remine": remines,
        "combined": _remine_metrics(combined_run, baseline_needles),
    }


def _partition_delta(baseline_ids: pd.Series, variant_ids: pd.Series) -> float:
    conserved = 0
    pairs = pd.DataFrame({"baseline": baseline_ids, "variant": variant_ids})
    for _, group in pairs.groupby("baseline", sort=False):
        conserved += int(group["variant"].value_counts().max())
    return (len(pairs) - conserved) / len(pairs) if len(pairs) else 0.0


def _order_pass(
    frame: pd.DataFrame,
    baseline: MiningRun,
    tables: dict[str, pd.DataFrame],
) -> dict[str, Any]:
    variants: list[tuple[str, pd.DataFrame]] = [
        ("reverse", frame.iloc[::-1].copy()),
        ("shuffle_3759", frame.sample(frac=1, random_state=SHUFFLE_SEED).copy()),
    ]
    skipped: list[str] = []
    if set(frame["feed"].unique()) == {"flat", "zeek"}:
        variants.append((
            "zeek_first",
            pd.concat(
                [frame[frame["feed"] == "zeek"], frame[frame["feed"] == "flat"]],
                ignore_index=False,
            ),
        ))
    else:
        skipped.append("zeek_first")

    baseline_by_row = baseline.frame.set_index("_row_id")["template_id"].sort_index()
    baseline_singletons = int((baseline.template_table["count"] == 1).sum())
    metrics: dict[str, dict[str, float | int]] = {}
    run_names: list[str] = []
    for name, ordered in variants:
        run = _mine_frame(ordered)
        tables[f"order-{name}"] = run.template_table
        variant_by_row = run.frame.set_index("_row_id")["template_id"].reindex(baseline_by_row.index)
        metrics[name] = {
            "partition_delta_rows": _partition_delta(baseline_by_row, variant_by_row),
            "singleton_count_delta": (
                int((run.template_table["count"] == 1).sum()) - baseline_singletons
            ),
        }
        run_names.append(name)
    return {"variants_run": run_names, "variants_skipped": skipped, "variants": metrics}


def _recount_pass(baseline: MiningRun) -> dict[str, int]:
    assignments: list[int] = []
    unmatched = 0
    divergent = 0
    for message, online_id in zip(baseline.frame["message"], baseline.frame["template_id"]):
        cluster = baseline.result.miner.match(str(message), full_search_strategy="fallback")
        if cluster is None:
            unmatched += 1
            continue
        cluster_id = int(cluster.cluster_id)
        assignments.append(cluster_id)
        if cluster_id != int(online_id):
            divergent += 1
    counts = Counter(assignments)
    return {
        "recount_divergent_rows": divergent,
        "recount_singleton_count": sum(count == 1 for count in counts.values()),
        "recount_unmatched": unmatched,
    }


def _simple_pass(frame: pd.DataFrame) -> dict[str, int]:
    normalized = [_apply_masks(str(message), MASK_SPECS) for message in frame["message"]]
    identity: dict[str, int] = {}
    ids: list[int] = []
    for message in normalized:
        ids.append(identity.setdefault(message, len(identity) + 1))
    simple = frame.copy()
    simple["template_id"] = ids
    simple["template_str"] = normalized
    counts = Counter(ids)
    return {
        "simple_distinct": len(counts),
        "simple_singletons": sum(count == 1 for count in counts.values()),
        "simple_needle_equivalent": _needle_equivalent(simple),
    }


def _require_keys(value: dict[str, Any], expected: frozenset[str], path: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        raise SummaryRefusal(f"{path}: fields refused")


def _validate_summary(summary: dict[str, Any]) -> None:
    _require_keys(summary, TOP_KEYS, "summary")
    if summary["schema_version"] != SCHEMA_VERSION:
        raise SummaryRefusal("summary: schema version refused")
    resolved = summary["resolved_settings"]
    _require_keys(resolved, RESOLVED_KEYS, "resolved_settings")
    _require_keys(resolved["requested_window"], WINDOW_KEYS, "requested_window")
    _require_keys(resolved["effective_window"], WINDOW_KEYS, "effective_window")
    _require_keys(resolved["feed_rows"], FEED_ROWS_KEYS, "feed_rows")
    _require_keys(resolved["detector_settings"], SETTINGS_KEYS, "detector_settings")
    if resolved["feed_order"] != ["flat", "zeek"]:
        raise SummaryRefusal("resolved_settings: feed order refused")
    if resolved["mask_order"] != list(MASK_NAMES):
        raise SummaryRefusal("resolved_settings: mask order refused")
    if resolved["template_identity"] != "final" or resolved["seed"] != SHUFFLE_SEED:
        raise SummaryRefusal("resolved_settings: identity settings refused")
    for window_name in ("requested_window", "effective_window"):
        for value in resolved[window_name].values():
            if value is not None:
                try:
                    parsed = datetime.fromisoformat(value)
                except (TypeError, ValueError) as exc:
                    raise SummaryRefusal(f"{window_name}: value refused") from exc
                if parsed.tzinfo is None:
                    raise SummaryRefusal(f"{window_name}: naive value refused")

    passes = summary["passes"]
    allowed_passes = frozenset({"baseline", *PASS_ORDER})
    if "baseline" not in passes or not set(passes).issubset(allowed_passes):
        raise SummaryRefusal("passes: fields refused")
    expected_selected = ["baseline", *(name for name in PASS_ORDER if name in passes)]
    if resolved["selected_passes"] != expected_selected:
        raise SummaryRefusal("resolved_settings: selected passes refused")
    baseline = passes["baseline"]
    baseline_keys = frozenset(baseline)
    if baseline_keys not in (BASELINE_KEYS, BASELINE_KEYS | {"feed_forks"}):
        raise SummaryRefusal("baseline: fields refused")
    _require_keys(baseline["population"], POPULATION_KEYS, "baseline.population")
    _require_keys(
        baseline["population"]["count_histogram"],
        COUNT_HISTOGRAM_KEYS,
        "baseline.population.count_histogram",
    )
    for bucket, value in baseline["token_buckets"].items():
        if not bucket.isdigit():
            raise SummaryRefusal("baseline.token_buckets: key refused")
        _require_keys(value, TOKEN_BUCKET_KEYS, "baseline.token_buckets")
    _require_keys(baseline["routing"], ROUTING_KEYS, "baseline.routing")
    _require_keys(baseline["wildcards"], WILDCARD_KEYS, "baseline.wildcards")
    _require_keys(
        baseline["wildcards"]["histogram"],
        WILDCARD_HISTOGRAM_KEYS,
        "baseline.wildcards.histogram",
    )
    _require_keys(baseline["template_mutation"], MUTATION_KEYS, "baseline.template_mutation")
    for program in baseline["programs"]:
        _require_keys(program, PROGRAM_KEYS, "baseline.programs")
        safe_name = program["program"]
        if safe_name not in PUBLIC_PROGRAMS and not PSEUDONYM_RE.fullmatch(safe_name):
            raise SummaryRefusal("baseline.programs: program name refused")
    if baseline["unmeasured"] != ["key_value_splitting", "host_port", "journal_feed"]:
        raise SummaryRefusal("baseline.unmeasured: values refused")
    if "feed_forks" in baseline:
        _require_keys(baseline["feed_forks"], FORK_KEYS, "baseline.feed_forks")
    both_feeds = all(resolved["feed_rows"][name] > 0 for name in ("flat", "zeek"))
    if ("feed_forks" in baseline) != both_feeds:
        raise SummaryRefusal("baseline.feed_forks: presence refused")

    if "masked" in passes:
        masked = passes["masked"]
        _require_keys(masked, MASKED_KEYS, "masked")
        if masked["identity_only_lower_bound"] != IDENTITY_DISCLOSURE:
            raise SummaryRefusal("masked: disclosure refused")
        if set(masked["posthoc"]) != set(MASK_NAMES) or set(masked["remine"]) != set(MASK_NAMES):
            raise SummaryRefusal("masked: class fields refused")
        for value in masked["posthoc"].values():
            _require_keys(value, POSTHOC_KEYS, "masked.posthoc")
        for value in (*masked["remine"].values(), masked["combined"]):
            _require_keys(value, REMINE_KEYS, "masked.remine")
    if "order" in passes:
        order = passes["order"]
        _require_keys(order, ORDER_KEYS, "order")
        allowed_variants = {"reverse", "shuffle_3759", "zeek_first"}
        if (
            len(order["variants_run"]) != len(set(order["variants_run"]))
            or len(order["variants_skipped"]) != len(set(order["variants_skipped"]))
            or not set(order["variants_run"]).issubset(allowed_variants)
            or not set(order["variants_skipped"]).issubset(allowed_variants)
            or set(order["variants_run"]) & set(order["variants_skipped"])
            or set(order["variants_run"]) | set(order["variants_skipped"])
            != allowed_variants
        ):
            raise SummaryRefusal("order: variant vocabulary refused")
        if set(order["variants"]) != set(order["variants_run"]):
            raise SummaryRefusal("order: variants refused")
        for value in order["variants"].values():
            _require_keys(value, ORDER_VARIANT_KEYS, "order.variants")
    if "recount" in passes:
        _require_keys(passes["recount"], RECOUNT_KEYS, "recount")
    if "simple" in passes:
        _require_keys(passes["simple"], SIMPLE_KEYS, "simple")


def _resolved_settings(
    frame: pd.DataFrame,
    selected: tuple[str, ...],
    since: datetime | None,
    until: datetime | None,
    feed_rows: dict[str, int],
) -> dict[str, Any]:
    effective = _usable_window(frame)
    return {
        "selected_passes": ["baseline", *selected],
        "requested_window": {"since": _iso(since), "until": _iso(until)},
        "effective_window": {
            "since": _iso(effective[0]) if effective else None,
            "until": _iso(effective[1]) if effective else None,
        },
        "feed_rows": feed_rows,
        "total_rows": int(len(frame)),
        "feed_order": ["flat", "zeek"],
        "seed": SHUFFLE_SEED,
        "mask_order": list(MASK_NAMES),
        "detector_settings": {
            key: detector.DEFAULT_CONFIG[key]
            for key in (
                "sim_thresh", "depth", "parametrize_numeric", "rarity_pct",
                "max_count", "burst_gap_seconds", "burst_min_size",
                "reboot_cluster_seconds",
            )
        },
        "template_identity": "final",
    }


def _measure(
    frame: pd.DataFrame,
    selected: tuple[str, ...],
    since: datetime | None,
    until: datetime | None,
    feed_rows: dict[str, int],
) -> tuple[dict[str, Any], dict[str, pd.DataFrame], dict[str, str]]:
    tables: dict[str, pd.DataFrame] = {}
    baseline_run = _mine_frame(frame)
    tables["baseline"] = baseline_run.template_table
    baseline, decode = _baseline(baseline_run)
    passes: dict[str, Any] = {"baseline": baseline}
    if "masked" in selected:
        passes["masked"] = _masked_pass(frame, baseline_run, tables)
    if "order" in selected:
        passes["order"] = _order_pass(frame, baseline_run, tables)
    if "recount" in selected:
        passes["recount"] = _recount_pass(baseline_run)
    if "simple" in selected:
        passes["simple"] = _simple_pass(frame)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "resolved_settings": _resolved_settings(frame, selected, since, until, feed_rows),
        "passes": passes,
    }
    _validate_summary(summary)
    return summary, tables, decode


def _summary_text(summary: dict[str, Any]) -> str:
    _validate_summary(summary)
    resolved = summary["resolved_settings"]
    baseline = summary["passes"]["baseline"]
    population = baseline["population"]
    requested = resolved["requested_window"]
    effective = resolved["effective_window"]
    lines = [
        "syslog fragmentation diagnosis",
        f"passes: {', '.join(resolved['selected_passes'])}",
        (
            "requested window: "
            f"{requested['since'] or 'open'} to {requested['until'] or 'open'}"
        ),
        (
            "effective window: "
            f"{effective['since'] or 'unavailable'} to "
            f"{effective['until'] or 'unavailable'}"
        ),
        (
            "feed rows: "
            f"flat={resolved['feed_rows']['flat']}, zeek={resolved['feed_rows']['zeek']}"
        ),
        f"rows: {population['total_rows']}",
        f"templates: {population['distinct_templates']}",
        (
            f"singletons: {population['singleton_count']} "
            f"({population['singleton_share']:.6f} of templates)"
        ),
        (
            "count histogram: "
            + ", ".join(
                f"{key}={value}"
                for key, value in population["count_histogram"].items()
            )
        ),
        "token buckets:",
    ]
    for bucket, value in baseline["token_buckets"].items():
        lines.append(
            f"  {bucket}: {value['templates']} templates, {value['singletons']} singletons"
        )
    lines.extend([
        f"adjacency signature: {baseline['adjacency_signature']}",
        f"distinct first tokens: {baseline['routing']['distinct_first_tokens']}",
        (
            "singleton first-token variable share: "
            f"{baseline['routing']['singleton_first_token_variable_share']:.6f}"
        ),
        (
            "wildcard histogram: "
            + ", ".join(
                f"{key}={value}"
                for key, value in baseline["wildcards"]["histogram"].items()
            )
        ),
        f"ceiling-saturated templates: {baseline['wildcards']['ceiling_saturated_count']}",
        f"needle equivalent: {baseline['needle_equivalent']}",
        (
            "template mutations: "
            f"{baseline['template_mutation']['template_changed_total']} events across "
            f"{baseline['template_mutation']['clusters_changed']} clusters"
        ),
        (
            "top-three program singleton share: "
            f"{baseline['top3_program_singleton_share']:.6f}"
        ),
    ])
    if "feed_forks" in baseline:
        lines.append(
            "feed forks: "
            f"pairs={baseline['feed_forks']['fork_pairs']}, "
            f"pid_forms={baseline['feed_forks']['pid_form_fork_count']}"
        )
    if "masked" in summary["passes"]:
        lines.append("masked: identity-only post-hoc lower bound plus per-class re-mines")
        masked = summary["passes"]["masked"]
        for name in resolved["mask_order"]:
            posthoc = masked["posthoc"][name]
            remine = masked["remine"][name]
            lines.append(
                f"  {name}: posthoc templates={posthoc['templates_after']}, "
                f"posthoc singletons={posthoc['singletons_after']}, "
                f"remine templates={remine['distinct_templates_after']}, "
                f"remine singletons={remine['singletons_after']}, "
                f"remine needles={remine['needle_equivalent_after']}, "
                f"needle delta={remine['needle_delta']}"
            )
        combined = masked["combined"]
        lines.append(
            "masked combined: "
            f"{combined['distinct_templates_after']} templates, "
            f"{combined['singletons_after']} singletons, "
            f"{combined['needle_equivalent_after']} needles, "
            f"needle delta={combined['needle_delta']}"
        )
    if "order" in summary["passes"]:
        order = summary["passes"]["order"]
        lines.append("order variants: " + ", ".join(order["variants_run"]))
        for name in order["variants_run"]:
            value = order["variants"][name]
            lines.append(
                f"  {name}: partition delta={value['partition_delta_rows']:.6f}, "
                f"singleton delta={value['singleton_count_delta']}"
            )
        if order["variants_skipped"]:
            lines.append("order variants skipped: " + ", ".join(order["variants_skipped"]))
    if "recount" in summary["passes"]:
        recount = summary["passes"]["recount"]
        lines.append(
            "recount: "
            f"divergent={recount['recount_divergent_rows']}, "
            f"singletons={recount['recount_singleton_count']}, "
            f"unmatched={recount['recount_unmatched']}"
        )
    if "simple" in summary["passes"]:
        simple = summary["passes"]["simple"]
        lines.append(
            "simple: "
            f"templates={simple['simple_distinct']}, "
            f"singletons={simple['simple_singletons']}, "
            f"needle equivalent={simple['simple_needle_equivalent']}"
        )
    lines.append("programs:")
    for row in baseline["programs"]:
        lines.append(
            f"  {row['program']}: {row['rows']} rows, "
            f"{row['templates']} templates, {row['singletons']} singletons"
        )
    lines.append("unmeasured: " + ", ".join(baseline["unmeasured"]))
    return "\n".join(lines) + "\n"


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _write_csv(path: Path, columns: list[str], rows: Iterable[Iterable[Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL)
        writer.writerow(columns)
        writer.writerows(
            (
                "'" + value
                if isinstance(value, str) and value and value[0] in CSV_FORMULA_PREFIXES
                else value
                for value in row
            )
            for row in rows
        )


def _write_bundle(
    bundle: Path,
    summary: dict[str, Any],
    text: str,
    tables: dict[str, pd.DataFrame],
    decode: dict[str, str],
    warnings: list[str],
) -> None:
    _write_json(bundle / "resolved-settings.json", summary["resolved_settings"])
    _write_json(bundle / "summary.json", summary)
    (bundle / "summary.txt").write_text(text, encoding="utf-8")
    (bundle / "loader-warnings.txt").write_text(
        "" if not warnings else "\n".join(warnings) + "\n",
        encoding="utf-8",
    )
    _write_csv(
        bundle / "program-decode.csv",
        ["program", "raw_program"],
        ((safe, raw) for safe, raw in decode.items()),
    )
    columns = [
        "template_id", "template_str", "count", "token_count",
        "wildcard_fraction", "program", "feeds",
    ]
    for name, table in sorted(tables.items()):
        _write_csv(
            bundle / f"templates-{name}.csv",
            columns,
            (tuple(row) for row in table[columns].itertuples(index=False, name=None)),
        )


def _load_inputs(
    syslog_dir: Path | None,
    zeek_dir: Path | None,
    since: datetime | None,
    until: datetime | None,
) -> tuple[pd.DataFrame, dict[str, int], list[str]]:
    warnings: list[str] = []
    flat = pd.DataFrame()
    zeek = pd.DataFrame()
    if syslog_dir is not None:
        flat = load_syslog(
            syslog_dir,
            since=since,
            until=until,
            show_progress=False,
            _warnings=warnings,
        )
    if zeek_dir is not None:
        zeek = load_logs(
            zeek_dir,
            "syslog*.log*",
            since=since,
            until=until,
            show_progress=False,
            _warnings=warnings,
        )
    feed_rows = {"flat": int(len(flat)), "zeek": int(len(zeek))}
    frames: list[pd.DataFrame] = []
    for feed, candidate in (("flat", flat), ("zeek", zeek)):
        if not candidate.empty:
            tagged = candidate.copy()
            tagged["feed"] = feed
            frames.append(tagged)
    if not frames:
        raise DiagnosticFailure(
            "diag-syslog: no syslog rows loaded. Check the inputs and time bounds."
        )
    # Flat-before-Zeek mirrors syslog.run(); arrival order is part of template identity.
    frame = frames[0] if len(frames) == 1 else pd.concat(frames, ignore_index=True)
    frame = frame.reset_index(drop=True)
    frame["_row_id"] = range(len(frame))
    return frame, feed_rows, warnings


def _write_error(bundle: Path, exc: BaseException) -> None:
    try:
        (bundle / "diag-error.txt").write_text(
            "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            encoding="utf-8",
            errors="backslashreplace",
        )
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    """Run the selected fragmentation measurements and write a private bundle."""
    args = _build_parser().parse_args(argv)
    if args.syslog_dir is None and args.zeek_dir is None:
        return _safe_error("diag-syslog: provide --syslog-dir or --zeek-dir")
    try:
        selected = _parse_passes(args.passes)
        since = _parse_bound(args.since)
        until = _parse_bound(args.until)
        if since is not None and until is not None and since > until:
            raise ValueError("inverted bounds")
    except (TypeError, ValueError):
        return _safe_error("diag-syslog: invalid arguments")
    try:
        bundle = _prepare_bundle(args.out)
    except (OSError, ValueError):
        return _safe_error("diag-syslog: --out must be a new empty directory outside the repo")

    try:
        frame, feed_rows, warnings = _load_inputs(
            args.syslog_dir, args.zeek_dir, since, until
        )
        summary, tables, decode = _measure(frame, selected, since, until, feed_rows)
        if args.verify_repeat:
            repeated, _, _ = _measure(frame.copy(), selected, since, until, feed_rows)
            first_bytes = json.dumps(summary, sort_keys=True, allow_nan=False)
            repeated_bytes = json.dumps(repeated, sort_keys=True, allow_nan=False)
            if first_bytes != repeated_bytes:
                raise ValueError("repeat mismatch")
        text = _summary_text(summary)
        _write_bundle(bundle, summary, text, tables, decode, warnings)
    except DiagnosticFailure as exc:
        _write_error(bundle, exc)
        return _safe_error(exc.safe_message)
    except Exception as exc:
        _write_error(bundle, exc)
        return _safe_error("diag-syslog: measurement failed; details are in the bundle")

    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
