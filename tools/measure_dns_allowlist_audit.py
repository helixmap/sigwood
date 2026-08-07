#!/usr/bin/env python3
"""Audit the shipped DNS B16 below-gate promotion without changing product behavior.

This development-only tool runs the ordinary default hunt under four fixed arms:
one and seven days, each with the configured allowlist on and forced off.  It
observes the real DNS detector after runner-owned filtering, then emits only
safe aggregate counts.  It is an allowlist-dependence audit, not a precision
claim or a simulation of another operator's list.
"""

from __future__ import annotations

import argparse
import gc
import json
import math
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

import pandas as pd

from sigwood import runner
from sigwood.common import config as cfg
from sigwood.common.finding import DetectorContext, Finding, Severity
from sigwood.common.tld import TLD_EXTRACT
from sigwood.detectors import dns as detector
from sigwood.outputs._evidence import level_visible


_LEXICAL_THRESHOLD = 1.8
_MIN_CHILDREN = 5
_MIN_NXDOMAIN_FRACTION = 0.9
_MIN_CLUSTER_SIZE = 2_000
_PARENT_LIMIT = 7
_FRACTION_LIMIT = 0.13
_WINDOW_DAYS = (1, 7)
_INTERPRETATION = (
    "audit of the shipped B16 channel; configured-allowlist dependence is not "
    "precision and generalization to another operator list is unmeasured"
)


class MeasurementError(RuntimeError):
    """Raised when the runner cannot provide one trustworthy audit arm."""


class ToolUsageError(ValueError):
    """A bounded, path-free error caused by this tool's own arguments."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Keep command-line errors free of caller-supplied paths."""

    def error(self, message: str) -> None:
        del message
        self.exit(2, "measure-dns-b16-allowlist-audit: invalid arguments\n")


@dataclass(frozen=True)
class _Observation:
    funnel: dict[str, object]
    b16_parents: frozenset[str]
    b16_info_parent_count: int
    data_window: tuple[datetime, datetime]
    min_cluster_size: int
    clustering: dict[str, object]


@dataclass(frozen=True)
class _ArmMeasurement:
    record: dict[str, object]
    b16_parents: frozenset[str]


def _build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--zeek-dir", required=True, type=Path)
    parser.add_argument("--until", required=True)
    return parser


def _parse_until(value: str) -> datetime:
    """Parse the shared, explicitly-offset end instant for every arm."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolUsageError("invalid end time") from exc
    if parsed.tzinfo is None:
        raise ToolUsageError("an end-time timezone offset is required")
    return parsed.astimezone(timezone.utc)


def _b16_finding(finding: Finding) -> bool:
    return (
        finding.detector == "dns"
        and finding.evidence.get("tier") == "below_gate_group"
    )


def _query_parent(query: str) -> str:
    """Mirror B16's registrable-parent identity for private audit bookkeeping."""
    extracted = TLD_EXTRACT(query)
    parent = extracted.top_domain_under_public_suffix
    if parent:
        return str(parent)
    parts = [label for label in query.split(".") if label]
    return parts[-1] if parts else query


def _label_score(query: str) -> float:
    """Mirror the live max-subdomain score only for diagnostic funnel counts."""
    extracted = TLD_EXTRACT(query)
    parent = extracted.top_domain_under_public_suffix
    if parent:
        if query.endswith("." + parent):
            labels = [label for label in query[: -(len(parent) + 1)].split(".") if label]
        else:
            labels = [extracted.domain] if extracted.domain else []
    else:
        parts = [label for label in query.split(".") if label]
        labels = parts[:-1] or parts
    return max((detector.entropy(label) for label in labels), default=0.0)


def _nxdomain_fraction(values: pd.Series) -> float | None:
    """Return the detector-compatible raw NXDOMAIN fraction for one parent."""
    total = 0
    nxdomain = 0
    for raw_code, raw_count in values.value_counts().to_dict().items():
        try:
            count = float(raw_count)
        except (TypeError, ValueError, OverflowError):
            continue
        if not math.isfinite(count) or count < 0 or not count.is_integer():
            continue
        total += int(count)
        try:
            code = float(raw_code)
        except (TypeError, ValueError, OverflowError):
            continue
        if math.isfinite(code) and code == 3:
            nxdomain += int(count)
    return None if total == 0 else nxdomain / total


def _cluster_record(frame: pd.DataFrame, min_cluster_size: int) -> dict[str, object]:
    """Report the Zeek path's clustering input without instrumenting it."""
    if frame.empty or "query" not in frame.columns:
        eligible = pd.Series(False, index=frame.index, dtype=bool)
    else:
        queries = frame["query"]
        text = queries.map(lambda value: value if isinstance(value, str) else None)
        has_dot = text.str.count(r"\.").fillna(0) > 0
        has_domain = text.map(
            lambda value: bool(value is not None and TLD_EXTRACT(value).domain)
        )
        eligible = (has_dot & has_domain).astype(bool)
    row_count = int(eligible.sum())
    return {
        "status": "ran" if row_count else "abstained_no_cluster_input",
        "input_rows": row_count,
        "min_cluster_size": min_cluster_size,
        "meets_min_cluster_size": row_count >= min_cluster_size,
    }


def _returned_above_gate_parents(findings: tuple[Finding, ...]) -> set[str]:
    """Extract live above-gate parents from returned non-B16 DNS findings."""
    parents: set[str] = set()
    for finding in findings:
        if finding.detector != "dns" or _b16_finding(finding):
            continue
        evidence = finding.evidence
        if evidence.get("tier") == "scan_summary":
            continue
        parent = evidence.get("registrable_domain")
        if isinstance(parent, str) and parent:
            parents.add(parent)
            continue
        if evidence.get("source") == "zeek" and isinstance(finding.title, str):
            parents.add(_query_parent(finding.title))
    return parents


def _audit_funnel(
    frame: pd.DataFrame, findings: tuple[Finding, ...],
) -> tuple[dict[str, object], frozenset[str]]:
    """Build diagnostic four-gate aggregates and retain no identities in output.

    The returned B16 findings, not this reconstruction, decide the stop rule.
    The reconstruction exists only to expose where the live channel's population
    changes and carries a parity flag against the real returned channel.
    """
    returned = frozenset(
        str(finding.evidence["registrable_domain"])
        for finding in findings
        if _b16_finding(finding)
        and isinstance(finding.evidence.get("registrable_domain"), str)
    )
    if frame.empty or "query" not in frame.columns or "rcode" not in frame.columns:
        return {
            "below_lexical_gate_parents": 0,
            "distinct_child_floor_parents": 0,
            "nxdomain_gate_parents": 0,
            "already_above_gate_exclusions": 0,
            "returned_b16_parents": len(returned),
            "returned_funnel_parity": len(returned) == 0,
        }, returned

    valid = frame["query"].map(lambda value: isinstance(value, str))
    full = frame.loc[valid, ["query", "rcode"]].copy()
    if full.empty:
        return {
            "below_lexical_gate_parents": 0,
            "distinct_child_floor_parents": 0,
            "nxdomain_gate_parents": 0,
            "already_above_gate_exclusions": 0,
            "returned_b16_parents": len(returned),
            "returned_funnel_parity": len(returned) == 0,
        }, returned

    candidates: dict[str, list[str]] = {}
    for query in pd.unique(full["query"]):
        assert isinstance(query, str)
        parent = _query_parent(query)
        if query == parent or _label_score(query) >= _LEXICAL_THRESHOLD:
            continue
        candidates.setdefault(parent, []).append(query)

    child_floor = {
        parent for parent, queries in candidates.items() if len(queries) >= _MIN_CHILDREN
    }
    qualifying: set[str] = set()
    if child_floor:
        query_to_parent = {
            query: parent for parent, queries in candidates.items() for query in queries
        }
        below_rows = full[full["query"].isin(query_to_parent)].copy()
        below_rows["_parent"] = below_rows["query"].map(query_to_parent)
        for parent, rows in below_rows.groupby("_parent", sort=False):
            if parent not in child_floor:
                continue
            fraction = _nxdomain_fraction(rows["rcode"])
            if fraction is not None and fraction >= _MIN_NXDOMAIN_FRACTION:
                qualifying.add(str(parent))

    already_above = qualifying & _returned_above_gate_parents(findings)
    expected = qualifying - already_above
    return {
        "below_lexical_gate_parents": len(candidates),
        "distinct_child_floor_parents": len(child_floor),
        "nxdomain_gate_parents": len(qualifying),
        "already_above_gate_exclusions": len(already_above),
        "returned_b16_parents": len(returned),
        "returned_funnel_parity": expected == set(returned),
    }, returned


@contextmanager
def _observe_dns_run() -> Iterator[list[_Observation]]:
    """Observe exactly the runner-prepared DNS context while preserving dns.run."""
    original = detector.run
    observations: list[_Observation] = []

    def observed_run(context: DetectorContext) -> list[Finding]:
        findings = original(context)
        frame = context.logs.get("dns*.log*")
        returned_findings = tuple(findings)
        frame = pd.DataFrame() if frame is None else frame
        funnel, b16_parents = _audit_funnel(frame, returned_findings)
        b16_info_parent_count = sum(
            1
            for finding in returned_findings
            if _b16_finding(finding)
            and finding.severity == Severity.INFO
            and isinstance(finding.evidence.get("registrable_domain"), str)
        )
        observations.append(_Observation(
            funnel=funnel,
            b16_parents=b16_parents,
            b16_info_parent_count=b16_info_parent_count,
            data_window=context.data_window,
            min_cluster_size=int(context.config.get("min_cluster_size", _MIN_CLUSTER_SIZE)),
            clustering=_cluster_record(frame, int(
                context.config.get("min_cluster_size", _MIN_CLUSTER_SIZE),
            )),
        ))
        # The runner owns its DNS frame. Retain only the audit's safe, scalar
        # observations before later default detectors run.
        del frame
        del returned_findings
        return findings

    detector.run = observed_run
    try:
        yield observations
    finally:
        detector.run = original


def _visible_defaults_excluding_b16(payload: dict[str, object]) -> int:
    """Apply the existing default visibility policy to runner JSON metadata only."""
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        raise MeasurementError("runner report was not usable")
    visible = 0
    for raw in raw_findings:
        if not isinstance(raw, dict):
            raise MeasurementError("runner report was not usable")
        evidence = raw.get("evidence")
        if not isinstance(evidence, dict):
            raise MeasurementError("runner report was not usable")
        if raw.get("detector") == "dns" and evidence.get("tier") == "below_gate_group":
            continue
        detector_name = raw.get("detector")
        severity_name = raw.get("severity")
        if not isinstance(detector_name, str) or not isinstance(severity_name, str):
            raise MeasurementError("runner report was not usable")
        try:
            view = SimpleNamespace(
                detector=detector_name,
                severity=Severity[severity_name.upper()],
            )
        except KeyError as exc:
            raise MeasurementError("runner report was not usable") from exc
        if level_visible(view, 0):
            visible += 1
    return visible


def _run_arm(
    config: dict[str, Any], *, zeek_dir: Path, since: datetime, until: datetime,
    no_allowlist: bool,
) -> _ArmMeasurement:
    """Run one actual default hunt and reduce it to B16-safe aggregates."""
    with tempfile.TemporaryDirectory(prefix="sigwood-b16-audit-") as temp_dir:
        sink = Path(temp_dir) / "discarded-run.json"
        try:
            with _observe_dns_run() as observations:
                result = runner.run(
                    config,
                    detect="default",
                    zeek_dir=zeek_dir,
                    scope=frozenset({"zeek_dir"}),
                    since=since,
                    until=until,
                    output_format="json",
                    output_file=sink,
                    # Explicit since/until bounds own every arm; this is not an
                    # all-available-data run.
                    load_all=False,
                    no_allowlist=no_allowlist,
                    quiet=True,
                    syslog_source="off",
                )
            payload = json.loads(sink.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise MeasurementError("runner measurement did not complete") from exc
    if result != 0:
        raise MeasurementError("runner returned a nonzero result")
    if len(observations) != 1:
        raise MeasurementError("runner did not produce exactly one DNS observation")

    observation = observations[0]
    visible_without_b16 = _visible_defaults_excluding_b16(payload)
    return _ArmMeasurement(
        record={
            "requested_window": {
                "since": since.isoformat(),
                "until": until.isoformat(),
            },
            "runner_data_window": [
                observation.data_window[0].astimezone(timezone.utc).isoformat(),
                observation.data_window[1].astimezone(timezone.utc).isoformat(),
            ],
            "clustering": observation.clustering,
            "funnel": observation.funnel,
            "b16_parent_count": len(observation.b16_parents),
            "b16_info_parent_count": observation.b16_info_parent_count,
            "same_arm_visible_defaults_excluding_b16": visible_without_b16,
            "same_arm_combined_visible_defaults": (
                visible_without_b16 + len(observation.b16_parents)
            ),
        },
        b16_parents=observation.b16_parents,
    )


def _window_comparison(one_day: _ArmMeasurement, seven_day: _ArmMeasurement) -> dict[str, object]:
    """Report safe B16 overlap counts and conservative clustering comparability."""
    one_cluster = one_day.record["clustering"]
    seven_cluster = seven_day.record["clustering"]
    assert isinstance(one_cluster, dict) and isinstance(seven_cluster, dict)
    comparable = (
        one_cluster.get("status") == "ran"
        and seven_cluster.get("status") == "ran"
        and one_cluster.get("meets_min_cluster_size") is True
        and seven_cluster.get("meets_min_cluster_size") is True
    )
    return {
        "one_day_only": len(one_day.b16_parents - seven_day.b16_parents),
        "seven_day_only": len(seven_day.b16_parents - one_day.b16_parents),
        "both": len(one_day.b16_parents & seven_day.b16_parents),
        "status": "comparable" if comparable else "confounded",
        "reason": (
            "both_arms_ran_with_at_least_min_cluster_size_rows"
            if comparable
            else "one_or_more_arms_did_not_meet_the_clustering_population_floor"
        ),
    }


def _l4_record(primary: _ArmMeasurement) -> dict[str, object]:
    """Evaluate the preregistered no-allowlist attention stop rule uncapped."""
    additions = len(primary.b16_parents)
    denominator = primary.record["same_arm_visible_defaults_excluding_b16"]
    assert isinstance(denominator, int)
    fraction = None if denominator == 0 else additions / denominator
    ratio_passes = additions == 0 if denominator == 0 else fraction <= _FRACTION_LIMIT
    return {
        "primary_arm": "no_allowlist_7d",
        "additional_b16_parents": additions,
        "existing_default_visible_excluding_b16": denominator,
        "additional_fraction": fraction,
        "parent_limit": _PARENT_LIMIT,
        "fraction_limit": _FRACTION_LIMIT,
        "passes": additions <= _PARENT_LIMIT and ratio_passes,
        "excess_is_failure_not_cap": True,
        "denominator_is_whole_same_arm_default_hunt": True,
        "no_allowlist_moves_sibling_detector_populations": True,
    }


def observe_b16_audit(
    config: dict[str, Any], *, zeek_dir: Path, until: datetime,
) -> dict[str, object]:
    """Run the four preregistered live-channel audit arms."""
    if until.tzinfo is None:
        raise ToolUsageError("an end-time timezone offset is required")
    arms: dict[str, dict[str, _ArmMeasurement]] = {"configured_allowlist": {}, "no_allowlist": {}}
    # The unsuppressed primary arm can be materially larger than the configured
    # arm. Run it in the fresh process state, then collect each discarded runner
    # frame before moving to the next independent observation.
    for no_allowlist, label in ((True, "no_allowlist"), (False, "configured_allowlist")):
        for days in _WINDOW_DAYS:
            since = until - timedelta(days=days)
            arms[label][f"{days}d"] = _run_arm(
                config,
                zeek_dir=zeek_dir,
                since=since,
                until=until,
                no_allowlist=no_allowlist,
            )
            gc.collect()

    safe_arms = {
        label: {window: measurement.record for window, measurement in records.items()}
        for label, records in arms.items()
    }
    return {
        "kind": "dns_b16_allowlist_audit",
        "interpretation": _INTERPRETATION,
        "parameters": {
            "channel": "shipped_dns_below_gate_group",
            "lexical_gate": "label_score_lt_1.8",
            "distinct_child_floor": _MIN_CHILDREN,
            "nxdomain_fraction_floor": _MIN_NXDOMAIN_FRACTION,
            "already_above_gate_parent": "excluded",
            "windows": ["1d", "7d"],
            "allowlist_arms": ["configured_allowlist", "no_allowlist"],
        },
        "limitations": {
            "no_allowlist_is_empty_list_counterfactual": True,
            "precision_claimed": False,
            "other_operator_allowlist_generalization": "unmeasured",
        },
        "arms": safe_arms,
        "window_comparison": {
            label: _window_comparison(records["1d"], records["7d"])
            for label, records in arms.items()
        },
        "l4": _l4_record(arms["no_allowlist"]["7d"]),
    }


def main(argv: list[str] | None = None) -> int:
    """Run the audit and print one safe JSON record."""
    args = _build_parser().parse_args(argv)
    try:
        until = _parse_until(args.until)
    except ToolUsageError as exc:
        print(f"measure-dns-b16-allowlist-audit: {exc}", file=sys.stderr)
        return 2
    try:
        config = cfg.load(args.config)
    except (OSError, cfg.ConfigError):
        print("measure-dns-b16-allowlist-audit: could not read the config", file=sys.stderr)
        return 2
    try:
        record = observe_b16_audit(config, zeek_dir=args.zeek_dir, until=until)
    except (MeasurementError, ToolUsageError) as exc:
        print(f"measure-dns-b16-allowlist-audit: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(record, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
