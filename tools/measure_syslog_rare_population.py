#!/usr/bin/env python3
"""Measure the runner-observed, non-reboot syslog rare-row population.

This is a development measurement tool, not a sigwood product surface.  It
invokes the normal runner and observes the detector's scored frame at the
single seam where ``is_anomaly`` exists.  It deliberately does not reproduce
loading, source arbitration, allowlisting, Drain3 configuration, or detector
analysis.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from sigwood import runner
from sigwood.common import config as cfg
from sigwood.detectors import syslog as detector
from sigwood.parsers.syslog import REBOOT_SIGNALS_RE


class MeasurementError(RuntimeError):
    """Raised when the runner did not yield one trustworthy observation."""


class ToolUsageError(ValueError):
    """A bounded, path-free error caused by this tool's own arguments."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Keep argument errors free of caller-supplied filesystem paths."""

    def error(self, message: str) -> None:
        del message
        self.exit(2, "measure-syslog-rare-population: invalid arguments\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--syslog-dir", type=Path)
    parser.add_argument("--zeek-dir", type=Path)
    parser.add_argument("--since")
    parser.add_argument("--until")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--no-allowlist", action="store_true")
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


@contextmanager
def _observe_scored_population() -> Iterator[list[int]]:
    """Observe the detector's existing scored frame for one runner invocation.

    ``_score_rarity`` returns the frame on which ``syslog.run`` immediately
    applies its reboot exclusion.  The tool repeats that existing expression
    with the parser-owned grammar constant; it does not define a second reboot
    classifier.  A future change to the detector's expression itself still
    requires the frozen-manifest residual-risk note and a tool review.
    """
    original = detector._score_rarity
    observations: list[int] = []

    def observed_score(
        frame: Any,
        rarity_pct: int,
        max_count: int,
    ) -> tuple[Any, int, dict[int, int]]:
        scored, threshold, frequencies = original(frame, rarity_pct, max_count)
        reboot_mask = scored["message"].astype(str).str.contains(
            REBOOT_SIGNALS_RE, na=False
        )
        observations.append(int((scored["is_anomaly"] & ~reboot_mask).sum()))
        return scored, threshold, frequencies

    detector._score_rarity = observed_score
    try:
        yield observations
    finally:
        detector._score_rarity = original


def observe_rare_non_reboot_rows(
    config: dict[str, Any],
    *,
    syslog_dir: Path | None,
    zeek_dir: Path | None,
    since: datetime | None,
    until: datetime | None,
    load_all: bool,
    no_allowlist: bool,
) -> int:
    """Run the real syslog path and return its single rare-row observation.

    The json report is directed to a private temporary file and removed with its
    directory.  Consequently the runner never writes a report into the CWD,
    configured report directory, or repository while this tool measures.
    """
    source_scope = frozenset(
        key
        for key, value in (("syslog_dir", syslog_dir), ("zeek_dir", zeek_dir))
        if value is not None
    )
    if not source_scope:
        raise MeasurementError("an explicit source is required")
    # An explicit files mode intentionally widens a Zeek-only CLI scope to the
    # configured local syslog source.  Select ``off`` for a Zeek-only probe so
    # this measurement cannot acquire ambient local logs through config fallback.
    source_mode = "files" if syslog_dir is not None else "off"

    with tempfile.TemporaryDirectory(prefix="sigwood-rare-population-") as temp_dir:
        sink = Path(temp_dir) / "discarded-run.json"
        try:
            with _observe_scored_population() as observations:
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
    return observations[0]


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
    """Run one measurement and print exactly its aggregate on stdout."""
    args = _build_parser().parse_args(argv)
    try:
        since, until = _validate_args(args)
    except ToolUsageError as exc:
        print(f"measure-syslog-rare-population: {exc}", file=sys.stderr)
        return 2

    try:
        config = cfg.load(args.config)
    except (OSError, cfg.ConfigError):
        print("measure-syslog-rare-population: could not read the config", file=sys.stderr)
        return 2

    try:
        count = observe_rare_non_reboot_rows(
            config,
            syslog_dir=args.syslog_dir,
            zeek_dir=args.zeek_dir,
            since=since,
            until=until,
            load_all=bool(args.all),
            no_allowlist=bool(args.no_allowlist),
        )
    except MeasurementError as exc:
        print(f"measure-syslog-rare-population: {exc}", file=sys.stderr)
        return 2

    print(f"rare_non_reboot_rows={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
