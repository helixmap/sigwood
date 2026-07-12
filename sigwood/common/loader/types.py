"""Loader metadata types and the cross-frame window helper (leaf module).

The dataclasses the loader returns to the runner (``LoadResult`` and the
disclosure records ``SourceCoverage`` / ``RotationSkipInfo``), the incremental
``CoverageTracker``, ``_data_window`` (pure ``logs dict → window``), and the
stream-mode empty-frame column constants. Imports stdlib + pandas only.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd


# Named log/compression suffixes stripped when deriving hostname from filename.
# All-numeric rotation suffixes (.1, .10, .42, etc.) are also stripped.
# Only log-related suffixes are removed so dotted hostnames (host1.example.com.log.gz) are preserved.
_LOG_SUFFIXES = frozenset({".gz", ".log"})

_PIHOLE_COLUMNS = [
    "ts", "src", "query", "event_type", "qtype",
    "dst", "answer", "validation", "host", "raw", "message",
]

# CloudTrail canonical row schema. The aws detector consumes frames with
# these columns in this order. parsers/cloudtrail.py is the single source of truth
# for what each column means.
_CLOUDTRAIL_COLUMNS = [
    "ts", "principal", "lane", "read_write",
    "event_source", "event_name", "identity_type",
    "source_ip", "error_code", "aws_region", "event_id", "raw",
]

# Stream-mode empty-frame columns. Module-level so the strategy table reads
# clean; values match the per-loader empty-shape.
_SYSLOG_COLUMNS = ["ts", "host", "program", "raw", "message"]


def _is_infinite_ts(ts: Any) -> bool:
    """Return whether ``ts`` is positive or negative infinity.

    Infinity is neither a usable timeline value nor the loader's "missing"
    timestamp sentinel. Keep-policy sources retain only missing (NaN) values;
    infinite values always leave the load before coverage or data-window
    accounting.
    """
    try:
        return math.isinf(ts)
    except (TypeError, ValueError, OverflowError):
        return False


def _coerce_usable_ts(ts: Any) -> float | None:
    """Return a finite UTC-datetime-representable timestamp or ``None``."""
    try:
        value = float(ts)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(value):
        return None
    try:
        datetime.fromtimestamp(value, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None
    return value


def _is_out_of_range_ts(ts: Any) -> bool:
    """Return whether a finite timestamp cannot become a UTC datetime.

    NaN remains the loader's missing-time sentinel and infinity has its own
    predicate. This class catches hostile finite magnitudes before coverage or
    data-window consumers can raise ``OverflowError``.
    """
    try:
        value = float(ts)
    except (TypeError, ValueError, OverflowError):
        return True
    if math.isnan(value) or math.isinf(value):
        return False
    return _coerce_usable_ts(value) is None


@dataclass(frozen=True)
class SourceCoverage:
    """Pre-window coverage for one loaded pattern. Drives the runner's
    "planned source contributed zero in-window rows" disclosure note.

    ``full_rows`` is tri-state and required:
      - ``None`` - NO files were read for this pattern (date-pruned dated
        Zeek). Drives the BARE note ("files found, 0 records in the selected
        window. Widen…").
      - ``0``    - files were read but ZERO valid-ts rows survived parsing
        (empty / header-only / unparseable timestamps - a PARSE gap, not a
        window gap). Drives NO note: telling the operator to widen the
        window on an empty file would mislead.
      - ``>0``   - N valid-ts rows the window excluded. Drives the SPAN
        note (count + span + widen suggestion).

    ``full_span`` is None when ``full_rows`` is None or 0.
    """

    full_rows: int | None
    full_span: tuple[datetime, datetime] | None


class CoverageTracker:
    """Builds a SourceCoverage incrementally as a loader reads a pattern.

    Single mechanism covering BOTH the streaming loaders (syslog / pihole /
    cloudtrail - observe ts per row) and the frame loader (Zeek - observe
    the parsed pre-filter frame per file). The runner's flat-Zeek
    default-window block also uses this tracker.

    Lifecycle (a single tracker per (pattern) load):
      - ``note_file_read()`` per file OPENED. Distinguishes
        "no files read"        (date-pruned)           → ``full_rows = None``
        from "files read, no valid-ts rows"            → ``full_rows = 0``.
      - Either ``observe(ts)`` per row pre-window-check (streaming) OR
        ``observe_frame(pre_df)`` per file pre-``_apply_ts_filter`` (Zeek).
        Both count VALID-ts rows only.
      - ``mark_kept()`` on row append (streaming) or non-empty post-window
        per-file frame (Zeek). Latches so subsequent ``observe`` /
        ``observe_frame`` calls short-circuit - ZERO normal-path cost.
      - ``coverage(frame_empty)`` returns a SourceCoverage or None.

    The tracker holds no references to the data it observed beyond running
    counts and min/max - safe to retain across the load.
    """

    def __init__(self) -> None:
        self._files_read = False
        self._kept = False
        self._valid_rows = 0
        self._min_ts: float | None = None
        self._max_ts: float | None = None

    def note_file_read(self) -> None:
        self._files_read = True

    def observe(self, ts: float | None) -> None:
        if self._kept:
            return
        if ts is None:
            return
        if _is_infinite_ts(ts) or _is_out_of_range_ts(ts):
            return
        # NaN-safe: math.isnan rejects NaN before it pollutes min/max.
        if isinstance(ts, float) and math.isnan(ts):
            return
        usable = _coerce_usable_ts(ts)
        if usable is None:
            return
        self._valid_rows += 1
        if self._min_ts is None or usable < self._min_ts:
            self._min_ts = usable
        if self._max_ts is None or usable > self._max_ts:
            self._max_ts = usable

    def observe_frame(self, pre_df: pd.DataFrame) -> None:
        if self._kept:
            return
        if pre_df is None or pre_df.empty or "ts" not in pre_df.columns:
            return
        valid = [
            normalized
            for value in pre_df["ts"].dropna().tolist()
            if (normalized := _coerce_usable_ts(value)) is not None
        ]
        if not valid:
            return
        self._valid_rows += len(valid)
        frame_min = min(valid)
        frame_max = max(valid)
        if self._min_ts is None or frame_min < self._min_ts:
            self._min_ts = frame_min
        if self._max_ts is None or frame_max > self._max_ts:
            self._max_ts = frame_max

    def mark_kept(self) -> None:
        self._kept = True

    def coverage(self, frame_empty: bool) -> SourceCoverage | None:
        """Return a SourceCoverage when disclosure is warranted; else None.

        - data survived (frame non-empty OR mark_kept fired) → None.
        - no files read                                       → (None, None).
        - files read but zero valid-ts rows                   → (0, None).
        - valid rows seen, all excluded by window             → (valid, span).
        """
        if not frame_empty or self._kept:
            return None
        if not self._files_read:
            return SourceCoverage(None, None)
        if self._valid_rows == 0:
            return SourceCoverage(0, None)
        span: tuple[datetime, datetime] | None = None
        if self._min_ts is not None and self._max_ts is not None:
            span = (
                datetime.fromtimestamp(self._min_ts, tz=timezone.utc),
                datetime.fromtimestamp(self._max_ts, tz=timezone.utc),
            )
        return SourceCoverage(self._valid_rows, span)


@dataclass(frozen=True)
class RotationSkipInfo:
    """Per-pattern result of flat-log rotation-peek windowing (syslog / pihole).

    The loader records this STRUCTURED metadata; the runner formats the prose
    note (``_rotation_skip_notes``) - the loader never imports the runner.

    ``fallback`` is data-true at the PATTERN level: when any rotation group's
    first-ts order is non-monotonic, ``_rotation_windowed_files`` disables
    pruning for the WHOLE pattern and returns every candidate file
    (``fallback=True``, ``skipped=0``, ``loaded=len(files)``). That keeps the
    runner's "read the full archive" note honest - a fallback can never coexist
    with a sibling group that was silently pruned.

    ``skipped_files`` carries ``(name, oldest_ts_or_None)`` for verbose
    per-file lines. The early-stopped older tail is never peeked, so its ts is
    ``None`` - the perf win is real and no timestamp is fabricated.
    """

    loaded: int
    skipped: int
    fallback: bool
    fallback_reason: str | None = None
    skipped_files: list[tuple[str, datetime | None]] = field(default_factory=list)


@dataclass(frozen=True)
class PermissionSkipInfo:
    """Per-pattern permission-denied read accounting for runner exit honesty."""

    discovered: int
    denied: int
    paths: tuple[Path, ...] = ()


@dataclass
class LoadResult:
    """Loaded log data and metadata needed by the runner."""

    logs: dict[str, pd.DataFrame]
    record_counts: dict[str, int]
    data_window: tuple[datetime, datetime] | None = None
    warnings: list[str] = field(default_factory=list)
    data_size_bytes: int = 0
    coverage: dict[str, SourceCoverage] = field(default_factory=dict)
    rotation_skips: dict[str, RotationSkipInfo] = field(default_factory=dict)
    permission_skips: dict[str, PermissionSkipInfo] = field(default_factory=dict)


def _data_window(logs: dict[str, pd.DataFrame]) -> tuple[datetime, datetime] | None:
    """Compute the min/max timestamp window across loaded DataFrames."""
    all_ts: list[float] = []
    for df in logs.values():
        if not df.empty and "ts" in df.columns:
            all_ts.extend(
                normalized
                for ts in df["ts"].dropna().tolist()
                if (normalized := _coerce_usable_ts(ts)) is not None
            )

    if not all_ts:
        return None

    return (
        datetime.fromtimestamp(min(all_ts), tz=timezone.utc),
        datetime.fromtimestamp(max(all_ts), tz=timezone.utc),
    )
