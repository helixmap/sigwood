#!/usr/bin/env python3
"""Measure a preregistered, runner-observed syslog rate baseline.

This development-only tool observes the syslog detector's already filtered input
through the normal runner.  It does not change detector, configuration,
evidence, or rendering behavior.  Its JSON output contains safe aggregates only:
no hosts, programs, paths, raw log lines, or candidate timestamps.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

import numpy as np
import pandas as pd

from sigwood import runner
from sigwood.common import config as cfg
from sigwood.common.finding import DetectorContext, Finding
from sigwood.detectors import syslog as detector


_MIN_COMPLETE_BINS = 16
_MAD_FLOOR = 1.0
_DEVIATION_MULTIPLIER = 6.0
_RATIO_FLOOR = 4.0
_UNKNOWN_PROGRAM = "unknown"
_INTERPRETATION = (
    "deliberately conservative diagnostic constants, not a claimed production "
    "calibration"
)


@dataclass(frozen=True)
class _BinSpec:
    label: str
    seconds: int
    support_floor: int


_BIN_SPECS = (
    _BinSpec("15m", 15 * 60, 6),
    _BinSpec("60m", 60 * 60, 12),
)


@dataclass(frozen=True)
class _Episode:
    host: str
    program: str
    start: float
    end: float


@dataclass(frozen=True)
class _RunObservation:
    frame: pd.DataFrame
    window_start: float
    window_end: float
    findings: tuple[Finding, ...]


class MeasurementError(RuntimeError):
    """Raised when the runner did not yield one trustworthy observation."""


class ToolUsageError(ValueError):
    """A bounded, path-free error caused by this tool's own arguments."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Keep argument errors free of caller-supplied filesystem paths."""

    def error(self, message: str) -> None:
        del message
        self.exit(2, "measure-syslog-rate-baseline: invalid arguments\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--syslog-dir", type=Path)
    parser.add_argument("--zeek-dir", type=Path)
    parser.add_argument("--since")
    parser.add_argument("--until")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--no-allowlist", action="store_true")
    parser.add_argument(
        "--cohort",
        required=True,
        choices=("frozen-week", "heldback-host-day"),
        help="select the preregistered L-4 stop rule to evaluate",
    )
    return parser


def _parse_bound(value: str | None) -> datetime | None:
    """Parse an explicit-offset ISO-8601 instant for the runner call."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolUsageError("invalid time bound") from exc
    if parsed.tzinfo is None:
        raise ToolUsageError("a timezone offset is required")
    return parsed.astimezone(timezone.utc)


def _context_frame(logs: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Return the exact two syslog inputs the detector concatenates."""
    frames = [
        frame
        for pattern in ("*.log*", "syslog*.log*")
        if (frame := logs.get(pattern)) is not None and not frame.empty
    ]
    if not frames:
        return pd.DataFrame()
    return frames[0] if len(frames) == 1 else pd.concat(
        frames, ignore_index=True, copy=False
    )


@contextmanager
def _observe_runner_frame() -> Iterator[list[_RunObservation]]:
    """Observe the filtered detector context while preserving ``syslog.run``."""
    original = detector.run
    observations: list[_RunObservation] = []

    def observed_run(context: DetectorContext) -> list[Finding]:
        findings = original(context)
        # ``syslog.run`` copies before its Drain3/scoring columns are added, so
        # the runner-filtered context remains the exact pre-analysis frame after
        # the original call returns.  Capturing it here avoids retaining a second
        # full-frame copy while Drain3 is still live on large frozen corpora.
        frame = _context_frame(context.logs)
        observations.append(
            _RunObservation(
                frame=frame,
                window_start=context.data_window[0].timestamp(),
                window_end=context.data_window[1].timestamp(),
                findings=tuple(findings),
            )
        )
        return findings

    detector.run = observed_run
    try:
        yield observations
    finally:
        detector.run = original


def _valid_text(value: object) -> str | None:
    """Return a nonempty canonical identity string without coercing other types."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _eligible_frame(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, int]]:
    """Apply the preregistered identity and timestamp eligibility contract."""
    reasons = {
        "nonfinite_timestamp": 0,
        "missing_host": 0,
        "missing_program": 0,
        "unknown_program": 0,
    }
    if frame.empty:
        return pd.DataFrame(columns=["ts", "host", "program"]), reasons

    timestamp_values = frame.get("ts", pd.Series(index=frame.index, dtype=object))
    timestamps = pd.to_numeric(timestamp_values, errors="coerce")
    hosts = frame.get("host", pd.Series(index=frame.index, dtype=object)).map(_valid_text)
    programs = frame.get("program", pd.Series(index=frame.index, dtype=object)).map(_valid_text)
    finite = timestamps.map(lambda value: bool(pd.notna(value) and math.isfinite(value)))
    host_ok = hosts.notna()
    program_ok = programs.notna()
    known_program = programs.ne(_UNKNOWN_PROGRAM)

    reasons["nonfinite_timestamp"] = int((~finite).sum())
    reasons["missing_host"] = int((~host_ok).sum())
    reasons["missing_program"] = int((~program_ok).sum())
    reasons["unknown_program"] = int((program_ok & ~known_program).sum())

    accepted = finite & host_ok & program_ok & known_program
    return pd.DataFrame({
        "ts": timestamps.loc[accepted].astype(float),
        "host": hosts.loc[accepted],
        "program": programs.loc[accepted],
    }), reasons


def _complete_bin_indexes(
    *, start: float, end: float, seconds: int, origin: float,
) -> np.ndarray:
    """Return epoch-indexed bins wholly contained by the accepted data window."""
    first = math.ceil((start - origin) / seconds)
    last = math.floor((end - origin) / seconds) - 1
    if last < first:
        return np.array([], dtype=np.int64)
    return np.arange(first, last + 1, dtype=np.int64)


def _counts_for_stream(
    stream: pd.DataFrame,
    indexes: np.ndarray,
    *, seconds: int, origin: float,
) -> np.ndarray:
    """Materialize a complete zero-inclusive count series for one stream."""
    bins = np.floor((stream["ts"].to_numpy() - origin) / seconds).astype(np.int64)
    observed = pd.Series(bins).value_counts()
    counts = np.zeros(len(indexes), dtype=np.int64)
    positions = {int(index): pos for pos, index in enumerate(indexes)}
    for index, count in observed.items():
        position = positions.get(int(index))
        if position is not None:
            counts[position] = int(count)
    return counts


def _merge_episodes(episodes: Sequence[_Episode]) -> list[_Episode]:
    """Merge overlapping episodes only within one host/program stream."""
    merged: list[_Episode] = []
    for episode in sorted(episodes, key=lambda item: (
        item.host, item.program, item.start, item.end,
    )):
        if (
            merged
            and (merged[-1].host, merged[-1].program) == (episode.host, episode.program)
            and episode.start < merged[-1].end
        ):
            prior = merged[-1]
            merged[-1] = _Episode(
                host=prior.host,
                program=prior.program,
                start=prior.start,
                end=max(prior.end, episode.end),
            )
            continue
        merged.append(episode)
    return merged


def _intervals_overlap(left: _Episode, right: _Episode) -> bool:
    """Return true only for a nonempty temporal overlap on one stream."""
    return (
        (left.host, left.program) == (right.host, right.program)
        and max(left.start, right.start) < min(left.end, right.end)
    )


def _view_candidates(
    stream: pd.DataFrame,
    indexes: np.ndarray,
    spec: _BinSpec,
    *, origin: float,
) -> tuple[list[_Episode], dict[str, object]]:
    """Measure one origin of one stream without choosing a winning candidate."""
    counts = _counts_for_stream(stream, indexes, seconds=spec.seconds, origin=origin)
    median = float(np.median(counts))
    mad = float(np.median(np.abs(counts - median)))
    state: dict[str, object] = {
        "steady": mad < _MAD_FLOOR,
        "max_bars": 0,
        "max_deviation": None,
        "max_ratio": None,
        "zero_median_bins": 0,
        "candidates": [],
        "first_candidate_indexes": set(),
    }
    if mad < _MAD_FLOOR:
        return [], state

    first_nonempty = next((pos for pos, count in enumerate(counts) if count > 0), None)
    episodes: list[_Episode] = []
    candidate_indexes: set[int] = set()
    for position, count in enumerate(counts):
        deviation = (float(count) - median) / mad
        ratio = None if median == 0 else float(count) / median
        prior_deviation = state["max_deviation"]
        state["max_deviation"] = (
            deviation if prior_deviation is None else max(deviation, prior_deviation)
        )
        if ratio is None:
            state["zero_median_bins"] = int(state["zero_median_bins"]) + 1
        else:
            prior_ratio = state["max_ratio"]
            state["max_ratio"] = (
                ratio if prior_ratio is None else max(ratio, prior_ratio)
            )
        bars = sum((
            float(count) >= median + (_DEVIATION_MULTIPLIER * mad),
            float(count) >= _RATIO_FLOOR * median,
            int(count) >= spec.support_floor,
        ))
        state["max_bars"] = max(int(state["max_bars"]), bars)
        if bars != 3:
            continue
        index = int(indexes[position])
        candidate_indexes.add(index)
        episodes.append(_Episode(
            host=str(stream.iloc[0]["host"]),
            program=str(stream.iloc[0]["program"]),
            start=origin + index * spec.seconds,
            end=origin + (index + 1) * spec.seconds,
        ))
        if position == first_nonempty:
            state["first_candidate_indexes"].add(index)
    state["candidates"] = candidate_indexes
    return episodes, state


def _measure_scale(
    eligible: pd.DataFrame,
    *, window_start: float, window_end: float, spec: _BinSpec,
) -> tuple[list[_Episode], dict[str, object]]:
    """Run both preregistered origins for one bin scale."""
    streams = [
        group.copy()
        for _, group in eligible.groupby(["host", "program"], sort=False)
    ]
    origins = (0.0, spec.seconds / 2)
    indexes_by_origin = [
        _complete_bin_indexes(
            start=window_start, end=window_end, seconds=spec.seconds, origin=origin,
        )
        for origin in origins
    ]
    summary: dict[str, object] = {
        "complete_bins_by_origin": [int(len(indexes)) for indexes in indexes_by_origin],
        "candidate_episodes": 0,
        "abstentions": {
            "short_capture_streams": 0,
            "steady_or_zero_mad_streams": 0,
            "all_first_bin_streams": 0,
            "one_origin_only_streams": 0,
        },
        "near_miss": {
            "max_deviation": None,
            "max_ratio": None,
            "zero_median_bin_views": 0,
            "streams_clearing_one_bar": 0,
            "streams_clearing_two_bars": 0,
            "streams_clearing_all_three_bars": 0,
        },
    }
    if min(len(indexes) for indexes in indexes_by_origin) < _MIN_COMPLETE_BINS:
        summary["abstentions"]["short_capture_streams"] = len(streams)
        return [], summary

    scale_episodes: list[_Episode] = []
    for stream in streams:
        views = [
            _view_candidates(stream, indexes, spec, origin=origin)
            for origin, indexes in zip(origins, indexes_by_origin, strict=True)
        ]
        states = [state for _, state in views]
        max_bars = max(int(state["max_bars"]) for state in states)
        if max_bars == 1:
            summary["near_miss"]["streams_clearing_one_bar"] += 1
        elif max_bars == 2:
            summary["near_miss"]["streams_clearing_two_bars"] += 1
        elif max_bars == 3:
            summary["near_miss"]["streams_clearing_all_three_bars"] += 1
        for state in states:
            deviation = state["max_deviation"]
            ratio = state["max_ratio"]
            if deviation is not None:
                current = summary["near_miss"]["max_deviation"]
                summary["near_miss"]["max_deviation"] = (
                    deviation if current is None else max(deviation, current)
                )
            if ratio is not None:
                current = summary["near_miss"]["max_ratio"]
                summary["near_miss"]["max_ratio"] = (
                    ratio if current is None else max(ratio, current)
                )
            summary["near_miss"]["zero_median_bin_views"] += int(
                state["zero_median_bins"]
            )
        if any(bool(state["steady"]) for state in states):
            summary["abstentions"]["steady_or_zero_mad_streams"] += 1

        raw_left, raw_right = views[0][0], views[1][0]
        paired_raw = [
            _Episode(
                host=left.host,
                program=left.program,
                start=max(left.start, right.start),
                end=min(left.end, right.end),
            )
            for left in raw_left
            for right in raw_right
            if _intervals_overlap(left, right)
        ]
        if (raw_left or raw_right) and not paired_raw:
            summary["abstentions"]["one_origin_only_streams"] += 1
            continue

        first_indexes = [state["first_candidate_indexes"] for state in states]
        surviving = [
            episode
            for episode in paired_raw
            if not any(
                int(math.floor((episode.start - origin) / spec.seconds)) in first
                for origin, first in zip(origins, first_indexes, strict=True)
            )
        ]
        if paired_raw and not surviving:
            summary["abstentions"]["all_first_bin_streams"] += 1
            continue
        scale_episodes.extend(surviving)

    merged = _merge_episodes(scale_episodes)
    summary["candidate_episodes"] = len(merged)
    return merged, summary


def _finding_matches_episode(finding: Finding, episode: _Episode) -> bool:
    """Apply the preregistered same-host/program/interval L-3 matcher."""
    evidence = finding.evidence
    if evidence.get("host") != episode.host:
        return False
    programs = {evidence.get("program")}
    for entry in evidence.get("program_mix", []):
        if isinstance(entry, (list, tuple)) and entry:
            programs.add(entry[0])
    if episode.program not in programs:
        return False
    interval = _finding_interval(finding)
    if interval is None:
        return False
    return max(interval[0], episode.start) < min(interval[1], episode.end)


def _finding_interval(finding: Finding) -> tuple[float, float] | None:
    """Read a bounded existing-finding interval for the L-3 comparison only."""
    evidence = finding.evidence
    start, end = evidence.get("start_ts"), evidence.get("end_ts")
    try:
        if start is not None and end is not None:
            start_value, end_value = float(start), float(end)
            if math.isfinite(start_value) and math.isfinite(end_value):
                return start_value, end_value
    except (TypeError, ValueError):
        pass
    first_seen = evidence.get("first_seen")
    if first_seen is None:
        return None
    try:
        instant = datetime.fromisoformat(str(first_seen)).timestamp()
    except (TypeError, ValueError):
        return None
    return (instant, instant) if math.isfinite(instant) else None


def _measure_observation(
    observation: _RunObservation, *, cohort: str,
) -> dict[str, object]:
    """Build the privacy-safe pre-registered Lane A measurement record."""
    eligible, exclusions = _eligible_frame(observation.frame)
    input_rows = int(len(observation.frame))
    eligible_streams = (
        int(eligible.groupby(["host", "program"]).ngroups)
        if not eligible.empty
        else 0
    )
    scale_records: dict[str, object] = {}
    all_episodes: list[_Episode] = []
    for spec in _BIN_SPECS:
        episodes, record = _measure_scale(
            eligible,
            window_start=observation.window_start,
            window_end=observation.window_end,
            spec=spec,
        )
        scale_records[spec.label] = record
        all_episodes.extend(episodes)
    episodes = _merge_episodes(all_episodes)
    surfaced_streams = len({(episode.host, episode.program) for episode in episodes})
    visible_findings = tuple(observation.findings)
    unmatched = [
        episode
        for episode in episodes
        if not any(_finding_matches_episode(finding, episode) for finding in visible_findings)
    ]
    limit = 7 if cohort == "frozen-week" else 1
    return {
        "kind": "syslog_rate_baseline_measurement",
        "interpretation": _INTERPRETATION,
        "parameters": {
            "streams": "host_program",
            "bin_minutes": [15, 60],
            "origins": "epoch_and_half_bin",
            "minimum_complete_bins": _MIN_COMPLETE_BINS,
            "mad_floor": _MAD_FLOOR,
            "deviation_multiplier": _DEVIATION_MULTIPLIER,
            "ratio_floor": _RATIO_FLOOR,
            "support_floors": {"15m": 6, "60m": 12},
            "partial_edge_bins": "excluded",
            "first_nonempty_candidate_bin": "abstain",
            "origin_requirement": "both_origins",
        },
        "eligibility": {
            "input_rows": input_rows,
            "eligible_rows": int(len(eligible)),
            "excluded_rows": input_rows - int(len(eligible)),
            "exclusion_reason_counts": exclusions,
            "eligible_streams": eligible_streams,
        },
        "scales": scale_records,
        "l2": {
            "surfaced_streams": surfaced_streams,
            "eligible_streams": eligible_streams,
            "surface_fraction": (
                None if eligible_streams == 0 else surfaced_streams / eligible_streams
            ),
        },
        "l3": {
            "unmatched_episodes": len(unmatched),
            "passes_nonredundancy": bool(unmatched),
        },
        "l4": {
            "cohort": cohort,
            "existing_default_visible": len(visible_findings),
            "additional_episodes": len(episodes),
            "stop_rule_limit": limit,
            "passes": len(episodes) <= limit,
            "excess_is_failure_not_cap": True,
        },
    }


def observe_rate_baseline(
    config: dict[str, Any],
    *,
    syslog_dir: Path | None,
    zeek_dir: Path | None,
    since: datetime | None,
    until: datetime | None,
    load_all: bool,
    no_allowlist: bool,
    cohort: str,
) -> dict[str, object]:
    """Run the real syslog path and return only aggregate Lane A evidence."""
    source_scope = frozenset(
        key
        for key, value in (("syslog_dir", syslog_dir), ("zeek_dir", zeek_dir))
        if value is not None
    )
    if not source_scope:
        raise MeasurementError("an explicit source is required")
    source_mode = "files" if syslog_dir is not None else "off"
    with tempfile.TemporaryDirectory(prefix="sigwood-rate-baseline-") as temp_dir:
        sink = Path(temp_dir) / "discarded-run.json"
        try:
            with _observe_runner_frame() as observations:
                result = runner.run(
                    config,
                    detect="syslog",
                    syslog_dir=syslog_dir,
                    zeek_dir=zeek_dir,
                    scope=source_scope,
                    since=since,
                    until=until,
                    output_format="json",
                    output_file=sink,
                    load_all=load_all,
                    no_allowlist=no_allowlist,
                    quiet=True,
                    syslog_source=source_mode,
                )
        except (OSError, ValueError) as exc:
            raise MeasurementError("runner measurement did not complete") from exc
    if result != 0:
        raise MeasurementError("runner returned a nonzero result")
    if len(observations) != 1:
        raise MeasurementError("runner did not produce exactly one syslog observation")
    return _measure_observation(observations[0], cohort=cohort)


def _validate_args(args: argparse.Namespace) -> tuple[datetime | None, datetime | None]:
    if args.syslog_dir is None and args.zeek_dir is None:
        raise ToolUsageError("a source is required")
    if args.all and (args.since is not None or args.until is not None):
        raise ToolUsageError("all and explicit bounds conflict")
    since = _parse_bound(args.since)
    until = _parse_bound(args.until)
    if since is not None and until is not None and since > until:
        raise ToolUsageError("inverted bounds")
    return since, until


def main(argv: list[str] | None = None) -> int:
    """Run one rate-baseline measurement and print its safe JSON aggregate."""
    args = _build_parser().parse_args(argv)
    try:
        since, until = _validate_args(args)
    except ToolUsageError as exc:
        print(f"measure-syslog-rate-baseline: {exc}", file=sys.stderr)
        return 2
    try:
        config = cfg.load(args.config)
    except (OSError, cfg.ConfigError):
        print("measure-syslog-rate-baseline: could not read the config", file=sys.stderr)
        return 2
    try:
        result = observe_rate_baseline(
            config,
            syslog_dir=args.syslog_dir,
            zeek_dir=args.zeek_dir,
            since=since,
            until=until,
            load_all=bool(args.all),
            no_allowlist=bool(args.no_allowlist),
            cohort=args.cohort,
        )
    except MeasurementError as exc:
        print(f"measure-syslog-rate-baseline: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
