"""Timeframe filtering, boundedness, and the flat-source rotation-peek subsystem.

The ts predicate (``_missing_ts``) and frame filter (``_apply_ts_filter``), the
path-shape boundedness predicates (``is_bounded`` / ``is_zeek_bounded``), and the
whole rotation-peek windowing subsystem (filename classifier + per-group peek/
prune). ``_open_log`` is reached through the package facade for monkeypatch
parity; ``_safe_resolve`` is imported directly from ``io`` (not a patch seam).
"""

from __future__ import annotations

import gzip
import lzma
import math
import re
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

import sigwood.common.loader as _loader  # facade: _open_log patch-through (call-time only)
from sigwood.common.loader.io import _safe_resolve
from sigwood.common.loader.types import (
    CoverageTracker,
    LoadResult,
    RotationSkipInfo,
    _coerce_usable_ts,
    _data_window,
    _is_infinite_ts,
    _is_out_of_range_ts,
)
from sigwood.parsers.syslog import parse_timestamp as _parse_syslog_ts
from sigwood.common.sanitize import strip_control


@dataclass(frozen=True)
class LoadWindow:
    """Resolved default window for ONE source family - the single window-policy
    state object both ``run()`` and ``run_digest()`` derive everything from.

    Built by :func:`sigwood.common.loader.resolve_load_windows` (one per in-plan,
    configured, unbounded, eligible family). Every downstream consumer reads it: the
    ``source_windows`` load override, the pre-load stderr line, ``requested_span``,
    the post-load trim, the aws rider - so a family is never announced, windowed,
    trimmed, and disclosed inconsistently.

    Fields:
      - ``source``: the family this resolves for (dir key, e.g. ``"syslog_dir"``).
      - ``select_window``: the runner routes this by ``trim_span`` - a precise
        ``(since, until)`` for a dated-Zeek layout (``trim_span`` None) goes to
        ``source_windows`` (row filter + discovery); a conservative ``(floor, None)``
        for a peekable flat family (``trim_span`` set) goes to ``file_select_windows``
        (rotation-peek only); ``None`` loads the family full (flat/mixed Zeek,
        unpeekable flat fallback, the universal default for a declarationless
        source). Flat floors preserve the open-ended ``(floor, None)`` shape.
      - ``trim_span``: the precise post-load trim span, anchored on the family's own
        max-ts. ``None`` ONLY for the dated-Zeek path (its ``select_window`` already
        cut exactly at load); set for every load-full / conservative path.
      - ``keep_null``: the source's ts policy - keep-policy families (syslog/pihole)
        retain unparseable-ts rows through the implicit trim, exactly as through an
        explicit window.
    """

    source: str
    select_window: tuple[datetime, datetime | None] | None
    trim_span: timedelta | None
    keep_null: bool


def _missing_ts(ts: Any) -> bool:
    """Return True for the canonical "missing timestamp" shapes the loader
    recognises: ``None`` and ``float('nan')``.

    The ONE place that defines "missing" - used by ``run_load`` to dispatch
    the stream-mode keep/drop policy, by ``CoverageTracker.observe`` (which
    silently ignores missing-ts inputs), and indirectly by ``_apply_ts_filter``
    (which calls ``ts.notna()`` over a pandas Series - same predicate).
    """
    return ts is None or (isinstance(ts, float) and math.isnan(ts))


def _apply_ts_filter(
    df: pd.DataFrame,
    since: datetime | None,
    until: datetime | None,
    *,
    keep_null: bool = False,
) -> pd.DataFrame:
    """Drop null/infinite-ts rows and filter to [since, until] window.

    Default (``keep_null=False``): drops rows with NaN/None ts unconditionally -
    matches NDJSON behavior where records without ts are always skipped. This is
    the drop-policy behavior the frame-mode load path sees, byte-for-byte.

    ``keep_null=True``: retain rows where ts is NaN OR ts ∈ window. Used by the
    analyze post-load default-window trim for keep-policy families (syslog /
    pihole), whose stream loader deliberately retains unparseable-ts rows
    (an unfilterable line is a real event and must survive the implicit window,
    just as it bypasses the load-time window). Returns an empty DataFrame if the
    ts column is absent.
    """
    if df.empty:
        return df
    if "ts" not in df.columns:
        return pd.DataFrame(columns=df.columns)
    # Infinity and invalid finite magnitudes are invalid rather than missing.
    # Keep-policy callers retain only the established None/NaN missing shapes.
    invalid = df["ts"].map(_is_infinite_ts) | (
        ~df["ts"].map(_missing_ts) & df["ts"].map(_is_out_of_range_ts)
    )
    df = df[~invalid].copy()
    if df.empty:
        return df
    # Canonicalize valid numeric timestamp strings before any comparison.
    df["ts"] = df["ts"].map(_coerce_usable_ts)
    if df.empty:
        return df
    null_mask = df["ts"].isna()
    if not keep_null:
        df = df[~null_mask]
        null_mask = pd.Series(False, index=df.index)
    if df.empty or (since is None and until is None):
        return df
    since_ts = since.timestamp() if since else None
    until_ts = until.timestamp() if until else None
    window_mask = pd.Series(True, index=df.index)
    if since_ts is not None:
        window_mask &= df["ts"] >= since_ts
    if until_ts is not None:
        window_mask &= df["ts"] <= until_ts
    return df[window_mask | null_mask]


def is_bounded(paths: list[Path]) -> bool:
    """Return True when a source-input bucket is BOUNDED (no auto-window applies).

    Family-neutral bucket-level predicate: non-empty AND every input is a single
    regular file. Any directory in the bucket - or an empty bucket - is UNBOUNDED.
    Mirrors the single-input semantics under the multi-input wire shape: a
    one-element list of a file → True (degenerate single-input case); a
    one-element list of a directory → False; a list with any directory → False;
    an empty list → False (the runner gates on truthiness before calling, so this
    state rarely reaches the helper - but the predicate stays explicit).

    Boundedness is pure path-shape and identical for every family - the
    universal default window (analyze AND digest, both via
    ``resolve_load_windows``) reads this per family. ``is_zeek_bounded`` is a
    retained Zeek-named public alias of it: it has no internal caller after the
    window-model unification, kept for API stability.
    """
    return bool(paths) and all(p.is_file() for p in paths)


def is_zeek_bounded(paths: list[Path]) -> bool:
    """Retained Zeek-named public alias of :func:`is_bounded` (byte-identical).

    No internal caller after the window-model unification routed digest
    boundedness through ``resolve_load_windows``; kept for API stability.
    """
    return is_bounded(paths)


# Compression extensions stripped before reading a rotation ordinal, and the
# trailing ``.<digits>`` rotation-number matcher. ``pihole.log.2.gz`` → strip
# ``.gz`` → match ``.2`` → base ``pihole.log``, index 2. The active file
# (``pihole.log``) and a non-numeric tail (``server.log``) carry index 0.
_COMPRESSION_EXTS = (".gz", ".bz2", ".xz")
_ROTATION_NUM_RE = re.compile(r"\.(\d+)$")

# Date-aware ordering anchor: a newer date → a SMALLER age_rank, and any dated
# file (rank ~8e7) sorts AFTER the live/undated head (rank 0). Keeps ascending
# age_rank == strictly newest→oldest across numeric AND date-based rotations.
_DATE_RANK_BASE = 99_999_999

_PEEK_FAILURES = (
    OSError,
    EOFError,
    gzip.BadGzipFile,
    lzma.LZMAError,
    ValueError,
)

# Family 2 - sigwood's own exporter output (``exporters/__init__.py``
# ``_auto_filename``): an INFIX ``_{YYYYMMDD}`` start date followed by either
# ``_{N}d`` or ``_to_{YYYYMMDD}_{HH}h``, then the (optional) extension. A bare
# ``_{YYYYMMDD}`` with no window token, or a ``_partNN`` infix, fails this regex
# and falls to the singleton floor (loaded-not-pruned - safe).
_EXPORT_WINDOW_RE = re.compile(
    r"^(?P<base>.+?)_(?P<start>\d{8})_"
    r"(?:(?P<days>\d+)d|to_(?P<end>\d{8})_(?P<hours>\d{2})h)"
    r"(?P<ext>\..*)?$"
)


def _strip_compression_ext(name: str) -> str:
    """Strip ONE trailing compression extension (``.gz``/``.bz2``/``.xz``) if
    present, else return the name unchanged.

    The shared primitive behind rotation classification AND duplicate-slot
    detection: a genuine duplicate is the SAME logical file in two compressions
    (``.log`` + ``.log.gz``, ``.2`` + ``.2.gz``, ``.20240101`` + ``.gz``), so it
    strips to the same name - distinct files (``auth.log`` vs ``auth.log.0``,
    ``.02`` vs ``.2``) do not.
    """
    for ext in _COMPRESSION_EXTS:
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


def _classify_rotation_name(
    name: str,
) -> tuple[str, int, tuple[datetime, datetime] | None]:
    """Classify a discovered rotation filename into
    ``(group_base, age_rank, declared_window | None)``.

    The single classifier behind both ``_rotation_base_and_index`` (grouping +
    ordering) and the Family-2 structural overlap guard. A trailing compression
    extension (``.gz``/``.bz2``/``.xz``) is stripped first, then the four
    recognized forms in order:

    - **numeric ordinal** (existing): trailing ``.(\\d+)`` whose digits are NOT a
      valid 8-digit calendar date → ``(base, N, None)`` (live/undated head ``N=0``).
    - **dateext** (Family 1): trailing ``.(\\d{8})`` parsing as ``%Y%m%d`` →
      ``(base, _DATE_RANK_BASE - int, None)``. logrotate dateext rotations are
      non-overlapping by construction, so they carry NO declared window and rely on
      the monotonicity backstop like numeric ordinals.
    - **export window** (Family 2): an infix ``_{YYYYMMDD}`` + ``_{N}d`` /
      ``_to_{YYYYMMDD}_{HH}h`` → ``(base, _DATE_RANK_BASE - int(start), [start, end))``
      with NAIVE datetimes. The window feeds ONLY the intra-group overlap guard,
      NEVER prune gating.
    - **floor**: nothing matched → ``(stripped_name, 0, None)`` - today's singleton.

    AGE_RANK CONTRACT: within a homogeneous group, ascending age_rank sort =
    strictly newest→oldest. numeric age_rank == N keeps every existing numeric
    ordering test byte-green. An 8-digit token that is not a valid calendar date is
    a numeric ordinal; a real index that happens to parse as a date is
    astronomically unlikely and the peek's monotonicity check catches any resulting
    disorder → fallback.
    """
    name = _strip_compression_ext(name)

    m = _ROTATION_NUM_RE.search(name)
    if m:
        digits = m.group(1)
        base = name[: m.start()]
        if len(digits) == 8:
            try:
                datetime.strptime(digits, "%Y%m%d")
            except ValueError:
                pass  # 8-digit non-date (e.g. month 13) → numeric ordinal
            else:
                return base, _DATE_RANK_BASE - int(digits), None
        return base, int(digits), None

    em = _EXPORT_WINDOW_RE.match(name)
    if em:
        try:
            start = datetime.strptime(em.group("start"), "%Y%m%d")
            if em.group("days") is not None:
                # `_Nd` days is unbounded `\d+`; a huge count overflows the date
                # add → OverflowError, which the guard below catches → floor.
                end = start + timedelta(days=int(em.group("days")))
            else:
                # `_auto_filename` lossily encodes `until` as `_{HH}h` (min/sec
                # dropped), so the real until lies in [date+HH:00, date+(HH+1):00).
                # CEIL to the next hour so the reconstructed end is a guaranteed
                # SUPERSET (≥ real until) - the overlap guard is then never-miss.
                end = datetime.strptime(em.group("end"), "%Y%m%d") + timedelta(
                    hours=int(em.group("hours")) + 1
                )
        except (ValueError, OverflowError):
            pass  # date(s) don't parse OR the math overflows → floor (never raises)
        else:
            # A non-positive window (empty `_0d`, or an inverted `_to_` whose end
            # precedes its start) is malformed: an empty `[start, start)` reads as
            # DISJOINT under the half-open overlap test, so it would dodge both the
            # overlap predicate and the rank-tie fallback and silently skip a
            # same-start sibling. Floor it - it then carries no window (own base,
            # peeked independently) instead of a degenerate claimed one.
            if end > start:
                return em.group("base"), _DATE_RANK_BASE - int(em.group("start")), (start, end)

    return name, 0, None


def _rotation_base_and_index(name: str) -> tuple[str, int]:
    """Split a rotation filename into ``(base, age_rank)``.

    Thin wrapper over ``_classify_rotation_name`` - the public helper tests import.
    ``pihole.log.2.gz`` → ``("pihole.log", 2)``; ``router.log.1`` →
    ``("router.log", 1)``; ``server.log`` / ``pihole.log`` → ``(name, 0)``;
    date-based forms carry the date-aware age_rank. The declared window stays
    INTERNAL to the classifier - it never enters this helper's contract.
    Drives both rotation ordering (fixing lexical ``.1, .10, .2``) and per-family
    grouping in ``_rotation_windowed_files``.
    """
    base, age_rank, _ = _classify_rotation_name(name)
    return base, age_rank


def _peek_first_ts(path: Path) -> datetime | None:
    """Return the parsed timestamp of ``path``'s first non-blank, non-comment
    line - the file's OLDEST row (flat rotations are internally oldest→newest).

    Reuses ``_open_log`` (transparent gz/bz2/xz) and the shared
    ``parsers.syslog.parse_timestamp`` so the peek ts is IDENTICAL to the ts the
    loader filters on (clock parity - the same call for syslog and dnsmasq).
    A bounded read: returns on the first usable line. ``None`` when the file is
    empty, unpeekable, corrupt, or carries no parseable first-ts (caller treats
    that as conservative include).
    """
    try:
        with _loader._open_log(path) as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    return _parse_syslog_ts(s)
    except _PEEK_FAILURES:
        return None
    return None


def _select_group(
    group_sorted: list[Path],
    since: datetime | None,
    until: datetime | None,
) -> tuple[list[Path], list[tuple[str, datetime | None]], bool]:
    """Select the in-window files of ONE rotation family (already sorted
    newest→oldest by ordinal). Returns ``(selected, skipped, fell_back)``.

    Only DETECTS first-ts disorder (``fell_back=True``); it does NOT self-select
    all - the pattern-level aggregate (``_rotation_windowed_files``) owns the
    full-read decision so a fallback is data-true across the whole pattern.

    Conservative: an unpeekable / corrupt file is INCLUDED and skipped from the
    monotonic chain - the optimization never drops a file it could not vet.
    """
    selected: list[Path] = []
    skipped: list[tuple[str, datetime | None]] = []
    prev_ts: datetime | None = None
    for i, f in enumerate(group_sorted):  # newest → oldest
        try:
            ts = _peek_first_ts(f)
        except _PEEK_FAILURES:
            # Corrupt compressed file - let run_load's read-corruption rail warn
            # at read; never abort discovery. Conservative include.
            ts = None
        if ts is None:
            selected.append(f)  # empty / unpeekable → conservative include
            continue
        if prev_ts is not None and ts > prev_ts:
            # First-ts RISE against the newest→oldest order - gross disorder.
            # Signal a pattern-level fallback (the aggregate reads the full set).
            return selected, skipped, True
        prev_ts = ts
        if until is not None and ts > until:
            # Leading file entirely AFTER the window (its oldest row > until).
            skipped.append((f.name, ts))
            continue
        if since is not None and ts < since:
            # First file whose oldest row predates `since` - it STRADDLES the
            # lower bound (its newer tail may hold in-window rows), so include
            # it, then stop: every older file is wholly out of window. The tail
            # is never peeked → the perf win, and ts stays None (not fabricated).
            selected.append(f)
            skipped.extend((g.name, None) for g in group_sorted[i + 1:])
            break
        selected.append(f)
    return selected, skipped, False


def _group_order_conflict(
    classified: list[tuple[str, int, tuple[datetime, datetime] | None]],
    stripped_names: list[str],
) -> str | None:
    """Return the fallback REASON when a rotation group cannot be cleanly ordered,
    or ``None`` when the group is safe to peek-prune. ``classified`` is the group's
    ``(base, age_rank, window | None)`` tuples in group order; ``stripped_names``
    is the parallel list of compression-stripped filenames.

    Two un-orderable shapes the lower-bound straddle + strict-``>`` monotonicity
    check would otherwise silently mishandle - both fall back whole-pattern:

    - **Duplicate rotation slots (non-export schemes):** the SAME logical file in
      two compressions (``pihole.log.2`` + ``.2.gz``; ``auth.log.20240101`` + ``.gz``;
      a live ``.log`` + its ``.log.gz``) collapses to one ambiguous slot - equal
      first-ts doesn't trip the strict monotonicity check, so one would be
      straddle-kept and its in-window sibling silently skipped as the "older tail".
      Detected by a SHARED compression-stripped NAME - NOT an age_rank tie, which is
      overloaded (the live/floor head and a 0-indexed ``.0`` both rank 0; ``.02`` and
      ``.2`` both int-rank 2 - distinct files, not duplicates). Reason
      ``"duplicate rotation files"``.
    - **Family-2 export windows that overlap / duplicate / mix with unwindowed
      members under one base:** sigwood authored the names, so each declares its
      full ``[start, end)`` - checkable from filenames alone, ZERO extra reads. The
      half-open overlap test (``a0 < b1 and b0 < a1``, TRUE for equal windows)
      catches export ``.log`` + ``.log.gz`` duplicates too, so they NEVER reach the
      stripped-name branch. Reason ``"overlapping export windows"``.

    The declared window is used ONLY here; it is NEVER a prune gate (the peek's
    first-ts vs since/until stays the sole data gate, so the filename date's tz is
    irrelevant - windows are only compared to each other).
    """
    windows = [c[2] for c in classified]
    if all(w is None for w in windows):
        # numeric / dateext / floor: un-orderable iff two members are the same
        # logical file in two compressions → a shared stripped name.
        return (
            "duplicate rotation files"
            if len(set(stripped_names)) != len(stripped_names)
            else None
        )
    if len(classified) == 1:
        return None  # singleton declared window - the peek handles it
    if any(w is None for w in windows):
        return "overlapping export windows"  # mixed windowed + unwindowed
    for i in range(len(windows)):  # all members windowed → require pairwise disjoint
        for j in range(i + 1, len(windows)):
            (a0, a1), (b0, b1) = windows[i], windows[j]
            if a0 < b1 and b0 < a1:  # half-open; equal → overlap (duplicate)
                return "overlapping export windows"
    return None


def _rotation_windowed_files(
    files: list[Path],
    since: datetime | None,
    until: datetime | None,
    *,
    verbose: bool = False,
) -> tuple[list[Path], RotationSkipInfo]:
    """Peek-prune a flat rotation candidate list to the files a ``since``/
    ``until`` window can touch, PER ROTATION GROUP.

    The safety invariant (each file internally chronological, non-overlapping)
    holds only WITHIN one logrotate family, so files are grouped by
    ``(resolved parent, rotation base)`` - ``/a/pihole.log.*`` and
    ``/b/pihole.log.*`` are two groups; ``router.log.*`` and ``server.log.*`` in
    one dir are two groups. Within a group, files are read newest→oldest and the
    older out-of-window tail is skipped.

    Fallback is DATA-TRUE at the pattern level: if ANY group's first-ts order is
    non-monotonic, pruning is disabled for the WHOLE pattern - every candidate is
    returned with ``fallback=True``, ``skipped=0``. That keeps the runner's "read
    the full archive" note honest (no silently-pruned sibling group).
    """
    # Classify (and compression-strip) each discovered file ONCE; grouping, the
    # group sort key, and the order-conflict check all read from these maps (the
    # classifier is regex + up to two strptime - not worth re-running ~3× per file).
    classified = {p: _classify_rotation_name(p.name) for p in files}
    stripped = {p: _strip_compression_ext(p.name) for p in files}

    groups: dict[tuple[Path, str], list[Path]] = {}
    for p in files:
        base = classified[p][0]
        groups.setdefault((_safe_resolve(p).parent, base), []).append(p)

    selected_all: list[Path] = []
    skipped_all: list[tuple[str, datetime | None]] = []
    for key in sorted(groups, key=lambda k: (str(k[0]), k[1])):
        group_sorted = sorted(
            groups[key], key=lambda p: classified[p][1]
        )  # ascending age_rank = newest (rank 0) → oldest
        reason = _group_order_conflict(
            [classified[p] for p in group_sorted],
            [stripped[p] for p in group_sorted],
        )
        if reason is not None:
            # A group that can't be cleanly ordered (same-rank duplicate or
            # overlapping export windows) → full read for the entire pattern
            # (whole-pattern, data-true like the monotonic fallback).
            return list(files), RotationSkipInfo(
                loaded=len(files),
                skipped=0,
                fallback=True,
                fallback_reason=reason,
                skipped_files=[],
            )
        sel, skp, fell_back = _select_group(group_sorted, since, until)
        if fell_back:
            # Any disorder → full read for the entire pattern. Nothing skipped.
            return list(files), RotationSkipInfo(
                loaded=len(files),
                skipped=0,
                fallback=True,
                fallback_reason="rotation order not monotonic",
                skipped_files=[],
            )
        selected_all.extend(sel)
        skipped_all.extend(skp)

    if verbose:
        for name, _ts in skipped_all:
            print(f"skipped {strip_control(name)} (outside the window)", file=sys.stderr)

    return selected_all, RotationSkipInfo(
        loaded=len(selected_all),
        skipped=len(skipped_all),
        fallback=False,
        skipped_files=skipped_all,
    )


def apply_default_window(
    load_result: LoadResult,
    family_patterns: list[str],
    span: timedelta,
    *,
    keep_null: bool,
) -> LoadResult:
    """Trim one family's loaded frames to its own last-``span`` window (post-load).

    The single post-load trim for the universal default window, shared by ``run()``
    and ``run_digest()`` (relocated from the runner). Anchors on the family's OWN
    max-ts (combined across its patterns), filters each pattern with ``keep_null``
    wired from the source policy (keep-policy families retain unparseable-ts rows
    through the implicit window), rebuilds coverage for any pattern that went
    non-empty → empty (so its zero-in-window note still fires), and rebuilds via
    ``dataclasses.replace`` so ``warnings`` / ``data_size_bytes`` / ``rotation_skips``
    carry forward unchanged. Never mutates the passed-in ``LoadResult.logs``.
    """
    # Shallow-copy the dict so the per-pattern reassignment below never mutates the
    # passed-in LoadResult's logs.
    logs = dict(load_result.logs)
    subset = {p: logs[p] for p in family_patterns if p in logs and not logs[p].empty}
    window = _data_window(subset)
    if window is None:
        return load_result
    until = window[1]
    since = until - span
    merged_cov = dict(load_result.coverage)
    for p, pre_df in subset.items():
        post_df = _apply_ts_filter(pre_df, since, until, keep_null=keep_null)
        logs[p] = post_df
        if not pre_df.empty and post_df.empty:
            tracker = CoverageTracker()
            tracker.note_file_read()
            tracker.observe_frame(pre_df)
            # post is empty - mark_kept intentionally does NOT fire
            sc = tracker.coverage(True)
            if sc is not None:
                merged_cov[p] = sc
    return replace(
        load_result,
        logs=logs,
        record_counts={p: len(df) for p, df in logs.items() if not df.empty},
        data_window=_data_window(logs),
        coverage=merged_cov,
    )
