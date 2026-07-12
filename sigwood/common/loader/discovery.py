"""File discovery for each source family + the dated-Zeek default window.

Per-family discovery (Zeek flat/dated, syslog content-gated, pihole glob,
CloudTrail recursive), the hostname stem helper, and the per-strategy
default-window resolvers (``_zeek_resolve_window`` / ``_flat_resolve_window`` /
``_default_resolve_window`` - the ``SourceLoader.resolve_window`` bodies; the
dated-layout selection ``_zeek_dated_window`` reads ``_zeek_date_subdirs``).
Imports the rotation sort key + first-ts peek from ``windowing``, the union dedupe
from ``io``, and the syslog content gate from ``sniff``; none import discovery, so
the package stays acyclic.
"""

from __future__ import annotations

import fnmatch
import math
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sigwood.common.loader.io import _union_dedupe
from sigwood.common.loader.sniff import _looks_like_syslog
from sigwood.common.loader.types import _LOG_SUFFIXES
from sigwood.common.loader.windowing import _peek_first_ts, _rotation_base_and_index


def discover_files(directory: Path, pattern: str) -> list[Path]:
    """Return all files in directory matching the glob pattern, sorted by name."""
    return sorted(directory.glob(pattern))


# Matches YYYY-MM-DD at the start of a Zeek log-rotation directory name.
# Suffix (e.g. -TSVPRE) is ignored for date extraction; see discover_zeek_files.
_DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _zeek_date_subdirs(directory: Path) -> list[Path]:
    """Return immediate child directories whose names begin with YYYY-MM-DD, sorted."""
    result = []
    for child in directory.iterdir():
        if child.is_dir() and _DATE_DIR_RE.match(child.name):
            result.append(child)
    return sorted(result, key=lambda p: p.name)


def _file_matches_pattern(path: Path, pattern: str) -> bool:
    """Return True if path's basename matches the glob pattern (single-file Zeek mode)."""
    return fnmatch.fnmatch(path.name, pattern)


def _is_primary_zeek_name(name: str, pattern: str) -> bool:
    """Return True if name is the primary Zeek log for pattern (rotations included),
    not a derived sibling that merely shares the type prefix (conn-summary,
    conn_history). A primary log's stem before the first '.' equals the log type;
    Zeek rotation only ever inserts a '.' (conn.<ts>.log), never '-' or '_'.
    Directory discovery only - an explicitly named file loads ungated."""
    log_type = pattern.split("*", 1)[0]
    if not log_type:
        return True  # non-type-anchored pattern (defensive): no narrowing
    return name.split(".", 1)[0] == log_type


def _zeek_dated_window(
    paths: list[Path], span: timedelta
) -> tuple[datetime, datetime] | None:
    """Compute the default analysis window for a union of Zeek inputs.

    PURELY-DATED predicate: every input is a directory AND every directory has
    non-empty YYYY-MM-DD subdirs. When that predicate holds, generalizes the
    single-input selection across the union - gather every discovered date
    subdir across all inputs, dedupe by date prefix, sort by date, select the
    newest ``N = ceil(span_days)`` (min 1), and return ``00:00:00`` UTC of the
    earliest selected → ``23:59:59`` UTC of the newest selected.

    Returns ``None`` when ANY input is a file (file + dated-dir mix) or ANY
    directory is flat (mixed/flat present) - the caller falls through to the
    flat-layout default path, which computes the window post-load from the
    COMBINED loaded Zeek frame's max-ts.

    Single-input behavior is BYTE-IDENTICAL with the prior scalar helper: a
    one-element list of a single dated dir runs the same selection
    (``_zeek_date_subdirs(input)``, newest N, earliest-midnight →
    newest-23:59:59).

    Sparse archives behave correctly: subdirs ``[2026-01-01, 2026-01-05]``
    with span=2d → BOTH selected, window Jan 1 → Jan 5. Cross-input
    duplicate dates count once toward N (dedup by date prefix).
    """
    if not paths:
        return None
    all_date_dirs: list[Path] = []
    for p in paths:
        if not p.is_dir():
            return None
        date_dirs = _zeek_date_subdirs(p)
        if not date_dirs:
            return None
        all_date_dirs.extend(date_dirs)
    # Dedup by date prefix so N counts DISTINCT dates across the union, not
    # duplicates contributed by multiple inputs carrying the same day.
    seen: set[str] = set()
    unique_by_date: list[Path] = []
    for d in sorted(all_date_dirs, key=lambda p: p.name[:10]):
        prefix = d.name[:10]
        if prefix in seen:
            continue
        seen.add(prefix)
        unique_by_date.append(d)
    n = max(1, math.ceil(span.total_seconds() / 86400))
    selected = unique_by_date[-n:]
    earliest_date = date.fromisoformat(selected[0].name[:10])
    newest_date = date.fromisoformat(selected[-1].name[:10])
    since = datetime(earliest_date.year, earliest_date.month, earliest_date.day,
                     0, 0, 0, tzinfo=timezone.utc)
    until = datetime(newest_date.year, newest_date.month, newest_date.day,
                     23, 59, 59, tzinfo=timezone.utc)
    return since, until


# ─────────────────────────────────────────────────────────────────────────────
# Per-strategy default-window resolvers - the SourceLoader.resolve_window bodies.
#
# Signature is uniform: (strategy, dirs, pattern, span) -> (select_window,
# trim_span). resolve_load_windows (pipeline) loops eligible/unbounded/in-play
# families and calls each strategy's resolver (or _default_resolve_window when a
# strategy declares none). The owning ``strategy`` is passed so the flat resolver
# can reach ``strategy.discover`` for its candidate universe WITHOUT a source-name
# ladder or a registry import - that is why this hook takes ``strategy`` and the
# other strategy callables (parse/discover/should_skip) do not.
# ─────────────────────────────────────────────────────────────────────────────


def _default_resolve_window(
    strategy, dirs: list[Path], pattern: str, span: timedelta
) -> tuple[None, timedelta]:
    """Universal default for a source that declares no ``resolve_window``: load the
    family full and trim post-load to its own last-``span`` window. A new flat
    source inherits this with zero runner edits - mirroring today's
    ``default_window_eligible=True`` / ``window_select=None`` behavior.
    """
    return None, span


def _zeek_resolve_window(
    strategy, dirs: list[Path], pattern: str, span: timedelta
) -> tuple[tuple[datetime, datetime] | None, timedelta | None]:
    """Zeek strategy resolver. Dated layout → a precise ``(since, until)``
    ``select_window`` and NO post-load trim (the load-time window already cut
    exactly). Flat / mixed / file → ``(None, span)`` (load full, trim post-load).
    """
    dated = _zeek_dated_window(dirs, span)
    if dated is not None:
        return dated, None
    return None, span


def _flat_default_floor(
    strategy, dir_paths: list[Path], pattern: str, span: timedelta
) -> tuple[datetime, None] | None:
    """Conservative default-window floor for a flat family (syslog / pihole).

    Discovers the family's DIRECTORY candidates via the passed ``strategy.discover``
    over the ``is_dir()`` inputs (``_union_dedupe``d - the same universe as
    :func:`load_required_logs`, explicit files excluded) and peeks each candidate's
    first-ts (``_peek_first_ts`` - clock-parity with the loader's own filter).
    Returns ``(f_max − span, None)`` - the conservative select-window the
    rotation-peek prunes against (``until=None``; the precise cut is the post-load
    trim) - where ``f_max`` is the max parseable first-ts across candidates.
    Returns ``None`` when nothing is peekable (load-full fallback).
    """
    candidates = _union_dedupe(
        [strategy.discover(d, pattern, None, None) for d in dir_paths if d.is_dir()]
    )
    peeked = [ts for ts in (_peek_first_ts(p) for p in candidates) if ts is not None]
    if not peeked:
        return None
    return (max(peeked) - span, None)


def _flat_resolve_window(
    strategy, dirs: list[Path], pattern: str, span: timedelta
) -> tuple[tuple[datetime, None] | None, timedelta]:
    """Flat strategy resolver (syslog / pihole). Peek the directory candidates →
    conservative ``(floor, None)`` ``select_window`` + precise post-load
    ``trim_span``; unpeekable → ``(None, span)`` (load full, trim post-load).
    """
    return _flat_default_floor(strategy, dirs, pattern, span), span


def discover_zeek_files(
    directory: Path,
    pattern: str,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Path]:
    """Return Zeek log files matching pattern from a flat or dated-layout directory.

    Single-file mode (directory.is_file() True): returns [directory] when its basename
    matches the pattern, else []. Single-file zeek_dir is a bounded target.

    Flat layout (no YYYY-MM-DD immediate children): sorted(directory.glob(pattern)).
    Dated layout: one candidate universe for BOTH the windowed and no-window cases -
    YYYY-MM-DD subdirs plus every non-date child directory (current/, export/), deduped
    by realpath. A window prunes date dirs by name; non-date children cannot be dated
    from their names, so they are always candidates and their rows are window-filtered
    downstream. A non-date alias of a PRUNED date dir stays excluded: the pruned dirs'
    realpaths seed the dedupe set. This is structural inspection of a known zeek_dir -
    not generic format discovery.

    Mixed-root policy: if any immediate child is a YYYY-MM-DD directory, dated layout
    is used and root-level files are not included. Zeek does not produce root-level files
    alongside date subdirs; the hybrid is ambiguous and therefore unsupported.
    """
    if directory.is_file():
        return [directory] if _file_matches_pattern(directory, pattern) else []

    date_dirs = _zeek_date_subdirs(directory)

    if not date_dirs:
        # Flat layout. Keep only primary Zeek logs (conn.log, conn.<ts>.log.gz),
        # never derived siblings that share the type prefix (conn-summary).
        return [
            f for f in sorted(directory.glob(pattern))
            if f.is_file() and _is_primary_zeek_name(f.name, pattern)
        ]

    # Dated layout. Root-level FILES are never included (mixed-root policy);
    # non-date CHILD DIRS (current/, export/) join the candidate set in BOTH
    # branches - the live spool must stay discoverable under a window.
    non_date_children = [
        c for c in directory.iterdir()
        if c.is_dir() and not _DATE_DIR_RE.match(c.name)
    ]
    if since is not None or until is not None:
        # Prune date dirs by name. A non-date dir cannot be dated from its
        # name, so it is conservatively included and its rows are window-
        # filtered downstream - under a fully-past window it is read and
        # filtered to zero (accepted tradeoff: discovery cannot date a
        # nameless directory).
        since_date = since.date() if since else None
        until_date = until.date() if until else None
        included_dates: list[Path] = []
        excluded_dates: list[Path] = []
        for d in date_dirs:
            dir_date = date.fromisoformat(d.name[:10])
            if (since_date is not None and dir_date < since_date) or (
                until_date is not None and dir_date > until_date
            ):
                excluded_dates.append(d)
            else:
                included_dates.append(d)
        # Seed seen with the PRUNED date dirs' realpaths so an excluded date
        # dir is not read back in through a non-date alias (current -> pruned
        # day); reading it could only yield rows the row filter drops.
        seen: set[Path] = {d.resolve() for d in excluded_dates}
        candidates: list[Path] = included_dates + non_date_children
    else:
        seen = set()
        candidates = list(date_dirs) + non_date_children

    # Dedup by realpath - non-date children are often symlinks pointing to date dirs;
    # resolving prevents double-loading regardless of iteration order.
    included: list[Path] = []
    for d in sorted(candidates, key=lambda p: p.name):
        rp = d.resolve()
        if rp not in seen:
            seen.add(rp)
            included.append(d)

    files: list[Path] = []
    for d in included:
        files.extend(
            f for f in sorted(d.glob(pattern))
            if f.is_file() and _is_primary_zeek_name(f.name, pattern)
        )
    return files


def _syslog_files(path: Path, pattern: str = "*.log*") -> list[Path]:
    """Return flat-source files to process by FILENAME glob: ``[path]`` if a file,
    else files matching ``pattern`` in the directory - ``._``-prefixed AppleDouble
    sidecars dropped, numeric rotation order.

    Pi-hole's discovery helper (and the Pi-hole pattern-mismatch presence check).
    Syslog discovery is NOT this - it content-sniffs via ``_discover_syslog_files``
    (RHEL/Fedora streams carry no ``.log`` suffix, and ``dnf.log`` etc. would be
    mis-claimed by a filename glob). The ``pattern`` applies to DIRECTORY discovery
    ONLY (pihole passes ``pihole*.log*`` to avoid grabbing non-pihole files in a
    shared dir). An explicitly-named FILE always loads as named - the pattern is
    NOT applied to it, so a content-routed Pi-hole file like ``events.log`` still
    loads. The AppleDouble filter and numeric ordering apply to DIRECTORY discovery
    only: the junk filter targets glob noise, not operator intent.
    """
    if path.is_file():
        return [path]
    files = [p for p in discover_files(path, pattern) if not p.name.startswith("._")]
    return sorted(files, key=lambda p: _rotation_base_and_index(p.name))


def _discover_syslog_files(path: Path) -> list[Path]:
    """The SINGLE syslog discovery universe - content-gated.

    FILE input → ``[path]`` UNGATED (the explicit-named-file rail: an explicitly
    named file always loads regardless of name; ``_syslog_should_skip`` still
    guards a named NDJSON/Zeek-TSV at load). DIRECTORY input → all regular,
    non-AppleDouble files that pass ``_looks_like_syslog``, in rotation order.
    Non-recursive ``iterdir`` correctly skips the binary subdirs (``journal/``,
    ``audit/``, ``sa/``) - they are not regular files.
    """
    if path.is_file():
        return [path]
    files = [
        p for p in path.iterdir()
        if p.is_file() and not p.name.startswith("._") and _looks_like_syslog(p)
    ]
    return sorted(files, key=lambda p: _rotation_base_and_index(p.name))


def _dir_has_regular_files(path: Path) -> bool:
    """True iff ``path`` holds >=1 regular, non-AppleDouble file.

    Cheap ``iterdir`` presence check for the syslog zero-accepted disclosure -
    NO sniff, NO ``*.log*`` test, so an extensionless-only dir does not fall
    through the disclosure silently.
    """
    try:
        return any(p.is_file() and not p.name.startswith("._") for p in path.iterdir())
    except OSError:
        return False


def discover_cloudtrail_files(path: Path) -> list[Path]:
    """Discover CloudTrail event files for the loader and runner satisfiability check.

    File path → [path]. Directory → recursive sorted ``*.json*`` matches, excluding
    AppleDouble ``._*`` sidecars (the resource-fork junk macOS/SMB/USB volumes leave
    beside real files - the same drop the flat families apply) and any file whose path
    contains a ``CloudTrail-Digest`` component (integrity manifests, not events - the
    same exclusion the exporter applies on the S3 side).

    The ``*.json*`` glob covers ``.json``, ``.json.gz``, the exporter's ``.json.log``
    and its ``_partNN`` splits. Recursion is what makes a native
    ``AWSLogs/<acct>/CloudTrail/<region>/YYYY/MM/DD/`` tree work - users who pull
    logs their own way can point ``cloudtrail_dir`` at any level of that tree.
    """
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    files: list[Path] = []
    for candidate in sorted(path.rglob("*.json*")):
        if not candidate.is_file():
            continue
        if candidate.name.startswith("._"):
            continue
        if "CloudTrail-Digest" in candidate.parts:
            continue
        files.append(candidate)
    return files


def _stem_hostname(name: str) -> str:
    """Strip log-file suffixes from a filename to derive a hostname stem.

    Strips .log, .gz, and numeric rotation suffixes (.1, .42).
    Dotted hostnames are preserved: host1.example.com.log → host1.example.com.
    """
    stem = name
    while True:
        suffix = Path(stem).suffix
        if suffix in _LOG_SUFFIXES or (suffix and suffix[1:].isdigit()):
            stem = Path(stem).stem
        else:
            break
    return stem
