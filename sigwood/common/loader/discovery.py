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

import errno
import fnmatch
import math
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from sigwood.common.loader.io import _safe_resolve, _union_dedupe
from sigwood.common.loader.provenance import (
    is_reserved_provenance_path,
    reject_explicit_reserved_path,
)
from sigwood.common.loader.sniff import _looks_like_syslog
from sigwood.common.loader.types import (
    Admission,
    DirectoryEntry,
    DirectorySkipInfo,
    DiscoveryFact,
    DiscoveryFactKind,
    EntryKind,
    _LOG_SUFFIXES,
)
from sigwood.common.loader.windowing import _peek_first_ts, _rotation_base_and_index


def discover_files(directory: Path, pattern: str) -> list[Path]:
    """Return all files in directory matching the glob pattern, sorted by name."""
    return sorted(
        path for path in directory.glob(pattern)
        if not is_reserved_provenance_path(path)
    )


# Matches YYYY-MM-DD at the start of a Zeek log-rotation directory name.
# A trailing suffix (e.g. -archived) is ignored for date extraction; see
# discover_zeek_files.
_DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


class _DirectoryListingDenied(PermissionError):
    """Private control signal: directory listing failed with EACCES."""


_ZEEK_DATED_DENIED = object()


def _record_directory_skip(
    source_key: str,
    directory: Path,
    sink: dict[tuple[str, Path], DirectorySkipInfo] | None,
) -> None:
    """Record one source/directory denial in a caller-owned dedupe sink."""
    if sink is None:
        return
    resolved = _safe_resolve(directory)
    sink.setdefault(
        (source_key, resolved),
        DirectorySkipInfo(source_key=source_key, path=resolved),
    )


def _list_directory(
    directory: Path,
    source_key: str,
    sink: dict[tuple[str, Path], DirectorySkipInfo] | None,
) -> list[Path]:
    """List immediate children or raise the typed, already-recorded denial."""
    try:
        return [
            path for path in directory.iterdir()
            if not is_reserved_provenance_path(path)
        ]
    except PermissionError:
        _record_directory_skip(source_key, directory, sink)
        raise _DirectoryListingDenied from None


def _zeek_date_subdirs(
    directory: Path,
    *,
    _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
    _children: list[Path] | None = None,
) -> list[Path]:
    """Return dated child directories, or raise the typed listing-denial signal."""
    result = []
    children = (
        _children
        if _children is not None
        else _list_directory(directory, "zeek_dir", _directory_skips)
    )
    for child in children:
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


# ─────────────────────────────────────────────────────────────────────────────
# Observation: each built-in family enumerates one input ONCE (observe) and then
# chooses files from that record with a deterministic selection (select). The
# public discovery helpers below are select(observe(input)), so the analyze
# inventory and every other caller run the same selection code. An observation
# never writes to a caller's sink: the consumer decides which of its recorded
# denials and errors to apply, which is how the legacy helpers keep their
# historical error behavior while the inventory discloses more.
# ─────────────────────────────────────────────────────────────────────────────

_INPUT_FILE = "file"
_INPUT_DIRECTORY = "directory"
_INPUT_MISSING = "missing"
_INPUT_DENIED = "denied"
_INPUT_ERROR = "error"

_CLOUDTRAIL_PATTERN = "*.json*"


def _errno_name(exc: OSError) -> str:
    """Tool-derived cause token for an OSError: its errno name, never its text."""
    code = getattr(exc, "errno", None)
    if code is None:
        return type(exc).__name__
    return errno.errorcode.get(code, str(code))


def _is_link(path: Path) -> bool:
    """Whether ``path`` itself is a symbolic link; False when it cannot be read."""
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except OSError:
        return False


# A link whose stat fails with one of these resolves to nothing: its target is
# absent, sits beneath a non-directory, or loops. Any other failure (EACCES, EIO)
# leaves the target's existence unknown, which is an inspection failure.
_DANGLING_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ELOOP})


def _classify_entry(path: Path) -> DirectoryEntry:
    """Classify one listed entry with a single ``stat``, never opening it.

    The ``stat`` follows symbolic links, so a link to a regular file is
    REGULAR. Only when it fails is the entry itself examined: a link whose
    target verifiably does not resolve is BROKEN_LINK; every other failure,
    a link included, is ERROR with its errno, because what the entry is
    remains unknown.
    """
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        is_link = _is_link(path)
        dangling = is_link and getattr(exc, "errno", None) in _DANGLING_ERRNOS
        kind = EntryKind.BROKEN_LINK if dangling else EntryKind.ERROR
        return DirectoryEntry(path, kind, is_link, _errno_name(exc))
    if stat.S_ISREG(mode):
        return DirectoryEntry(path, EntryKind.REGULAR)
    if stat.S_ISDIR(mode):
        return DirectoryEntry(path, EntryKind.DIRECTORY, _is_link(path))
    return DirectoryEntry(path, EntryKind.NONREGULAR, _is_link(path))


def _scan_directory(
    directory: Path,
) -> tuple[tuple[DirectoryEntry, ...], OSError | None]:
    """List one directory's immediate children, sorted, reserved names excluded.

    Listing goes through ``Path.iterdir``, the same call the shipped discovery
    used. Iteration is all-or-empty: a failure part way through discards the
    partial listing and returns the error for the caller to account for.
    """
    try:
        children = list(directory.iterdir())
    except OSError as exc:
        return (), exc
    entries = [
        _classify_entry(path)
        for path in children
        if not is_reserved_provenance_path(path)
    ]
    entries.sort(key=lambda entry: entry.path)
    return tuple(entries), None


@dataclass
class InputObservation:
    """One input as its family enumerated it, plus what enumeration could not see.

    ``kind`` is the input itself: ``file``, ``directory``, or why it could not
    be listed (``missing`` / ``denied`` / ``error``, with ``error`` holding the
    original exception). ``entries`` are the immediate children of a directory.
    ``accepted`` holds a family's precomputed candidates where selection does
    not depend on the pattern (the syslog content gate, the CloudTrail walk).

    ``denied_dirs`` and ``facts`` record what was learned below the input:
    descendant directories whose listing was denied, and other coverage facts.
    Zeek child directories are listed lazily, the first time a selection needs
    one, so a windowed load never lists a pruned date directory first; the
    records accumulate as that happens.

    A recursive input carries a ``mode``: ``partition`` for a positional
    directory whose files were sorted into families, ``declared`` for a
    ``--<family>-dir`` walked under its family's own gate. Its ``entries`` are
    every non-directory entry the walk met (internal bookkeeping for coverage,
    not new inputs) and its Zeek view keeps one observation per logical Zeek
    root in ``logical``. ``admitted`` restricts a logical root's Zeek candidates
    to the files a positional partition gave to Zeek.
    """

    source_key: str
    path: Path
    kind: str
    entries: tuple[DirectoryEntry, ...] = ()
    error: OSError | None = None
    accepted: tuple[Path, ...] = ()
    denied_dirs: list[Path] = field(default_factory=list)
    facts: list[DiscoveryFact] = field(default_factory=list)
    _children: dict[Path, tuple[DirectoryEntry, ...]] = field(
        default_factory=dict, repr=False,
    )
    mode: str | None = None
    logical: tuple["InputObservation", ...] = ()
    admitted: frozenset[Path] | None = None

    def child_entries(self, child: Path) -> tuple[DirectoryEntry, ...]:
        """Return one child directory's listing, scanning it at most once."""
        cached = self._children.get(child)
        if cached is not None:
            return cached
        entries, exc = _scan_directory(child)
        if exc is not None:
            if isinstance(exc, PermissionError):
                self.denied_dirs.append(child)
            else:
                self.facts.append(DiscoveryFact(
                    DiscoveryFactKind.LISTING_ERROR,
                    self.source_key,
                    self.path,
                    (child,),
                    1,
                    _errno_name(exc),
                ))
        self._children[child] = entries
        return entries

    def listed_children(self) -> Mapping[Path, tuple[DirectoryEntry, ...]]:
        """Child directory listings scanned so far, keyed by child path."""
        return dict(self._children)


def _observe_root(source_key: str, path: Path) -> InputObservation:
    """Observe one input: a file, a listed directory, or why it was not listed."""
    if path.is_file():
        return InputObservation(source_key, path, _INPUT_FILE)
    entries, exc = _scan_directory(path)
    if exc is None:
        return InputObservation(source_key, path, _INPUT_DIRECTORY, entries)
    if isinstance(exc, PermissionError):
        kind = _INPUT_DENIED
    elif isinstance(exc, FileNotFoundError):
        kind = _INPUT_MISSING
    else:
        kind = _INPUT_ERROR
    return InputObservation(source_key, path, kind, error=exc)


Listing = tuple[tuple[DirectoryEntry, ...], OSError | None]


@dataclass(frozen=True)
class TreeListing:
    """One complete walk of a directory tree, with everything it could not see.

    ``directories`` holds every directory the walk listed, with its sorted
    entries, in walk order; entry paths are spelled under the walked root.
    ``visited`` holds their resolved identities. ``denied`` and
    ``listing_errors`` are directories whose listing failed (by permission, or
    with another errno), and ``linked`` the discovered directory links the walk
    did not descend. ``error`` is set when the root itself could not be listed.
    """

    root: Path
    error: OSError | None = None
    directories: tuple[tuple[Path, tuple[DirectoryEntry, ...]], ...] = ()
    visited: frozenset[Path] = frozenset()
    denied: tuple[Path, ...] = ()
    listing_errors: tuple[tuple[Path, str], ...] = ()
    linked: tuple[Path, ...] = ()

    @property
    def complete(self) -> bool:
        """Whether every directory beneath the root was listed and searched."""
        return (
            self.error is None
            and not self.denied
            and not self.listing_errors
            and not self.linked
        )


def _cached_listing(directory: Path, listings: dict[Path, Listing]) -> Listing:
    """One directory's listing, scanned at most once per resolved identity.

    A cached listing reached through another spelling of the same directory is
    re-rooted under ``directory``, so every caller sees paths in its own terms.
    """
    key = _safe_resolve(directory)
    cached = listings.get(key)
    if cached is None:
        cached = _scan_directory(directory)
        listings[key] = cached
    entries, exc = cached
    if entries and entries[0].path.parent != directory:
        entries = tuple(
            replace(entry, path=directory / entry.path.name) for entry in entries
        )
    return entries, exc


def walk_directory_tree(
    root: Path,
    *,
    _listings: dict[Path, Listing] | None = None,
) -> TreeListing:
    """Walk every directory below ``root`` once, deterministically, without a cap.

    The walk descends real subdirectories in sorted order and never follows a
    discovered directory link, so it cannot loop through one; a supplied root
    that is itself a link is listed through it. Resolved identities prevent a
    second traversal of any directory reached twice. Reserved provenance names
    never appear, because listings exclude them before any descent. A listing
    that fails is recorded with its cause and the rest of the tree continues.
    ``_listings`` is a caller-owned cache keyed by resolved directory, so walks
    of overlapping roots list each physical directory once.
    """
    listings = _listings if _listings is not None else {}
    entries, exc = _cached_listing(root, listings)
    if exc is not None:
        return TreeListing(root, error=exc)
    visited = {_safe_resolve(root)}
    directories: list[tuple[Path, tuple[DirectoryEntry, ...]]] = []
    denied: list[Path] = []
    errors: list[tuple[Path, str]] = []
    linked: list[Path] = []
    stack: list[tuple[Path, tuple[DirectoryEntry, ...]]] = [(root, entries)]
    while stack:
        directory, listed = stack.pop()
        directories.append((directory, listed))
        children: list[tuple[Path, tuple[DirectoryEntry, ...]]] = []
        for entry in listed:
            if entry.kind is not EntryKind.DIRECTORY:
                continue
            if entry.is_symlink:
                linked.append(entry.path)
                continue
            identity = _safe_resolve(entry.path)
            if identity in visited:
                continue
            visited.add(identity)
            child_entries, child_exc = _cached_listing(entry.path, listings)
            if child_exc is None:
                children.append((entry.path, child_entries))
            elif isinstance(child_exc, PermissionError):
                denied.append(entry.path)
            else:
                errors.append((entry.path, _errno_name(child_exc)))
        stack.extend(reversed(children))
    return TreeListing(
        root,
        directories=tuple(directories),
        visited=frozenset(visited),
        denied=tuple(sorted(denied)),
        listing_errors=tuple(sorted(errors)),
        linked=tuple(sorted(linked)),
    )


def tree_entries(tree: TreeListing) -> tuple[DirectoryEntry, ...]:
    """Every non-directory entry a walk met, in walk order."""
    return tuple(
        entry
        for _directory, entries in tree.directories
        for entry in entries
        if entry.kind is not EntryKind.DIRECTORY
    )


def tree_walk_facts(source_key: str, tree: TreeListing) -> list[DiscoveryFact]:
    """A declared family's facts for the parts of its walk it could not search.

    Denied directories are not facts: they are ``DirectorySkipInfo`` records,
    carried in an observation's ``denied_dirs``.
    """
    facts = [
        DiscoveryFact(
            DiscoveryFactKind.LISTING_ERROR, source_key, tree.root, (path,), 1, cause,
        )
        for path, cause in tree.listing_errors
    ]
    if tree.linked:
        facts.append(DiscoveryFact(
            DiscoveryFactKind.LINKED_DIRECTORY_OMITTED, source_key, tree.root,
            tree.linked, len(tree.linked),
        ))
    return facts


def _apply_legacy_root(
    obs: InputObservation,
    sink: dict[tuple[str, Path], DirectorySkipInfo] | None,
    *,
    raise_errors: bool,
) -> None:
    """Give a legacy helper exactly its historical root behavior.

    A root listing denial is recorded in the caller's sink, as before. Where the
    helper listed with ``iterdir`` (Zeek, syslog), any other listing failure
    re-raises the original exception, as before; the glob-based helpers
    (Pi-hole, CloudTrail) historically collapsed it to no matches and still do.
    Below-root denials and facts are not applied: those helpers never reported
    them.
    """
    if obs.kind == _INPUT_DENIED:
        _record_directory_skip(obs.source_key, obs.path, sink)
    elif raise_errors and obs.error is not None:
        raise obs.error


def apply_observation_denials(
    obs: InputObservation,
    sink: dict[tuple[str, Path], DirectorySkipInfo] | None,
) -> None:
    """Record every directory-listing denial an observation holds.

    The root denial and any denied descendant directories are each a real
    listing denial, so they share ``DirectorySkipInfo`` and its renderer. Used
    by the analyze inventory and by the loader when it consumes observations.
    """
    if obs.kind == _INPUT_DENIED:
        _record_directory_skip(obs.source_key, obs.path, sink)
    for denied in obs.denied_dirs:
        _record_directory_skip(obs.source_key, denied, sink)


def _observed_date_dirs(obs: InputObservation) -> list[Path]:
    """Dated (``YYYY-MM-DD``-prefixed) child directories, sorted by name."""
    return sorted(
        (
            entry.path for entry in obs.entries
            if entry.kind is EntryKind.DIRECTORY
            and _DATE_DIR_RE.match(entry.path.name)
        ),
        key=lambda path: path.name,
    )


def _is_zeek_candidate(entry: DirectoryEntry, pattern: str) -> bool:
    """A regular, pattern-matching, primary (not derived-sibling) Zeek log."""
    name = entry.path.name
    return (
        entry.kind is EntryKind.REGULAR
        and fnmatch.fnmatchcase(name, pattern)
        and _is_primary_zeek_name(name, pattern)
    )


def _zeek_entry_admitted(
    obs: InputObservation, entry: DirectoryEntry, pattern: str,
) -> bool:
    """A Zeek candidate for ``pattern`` that this observation may read.

    A positional partition's logical root reads only the files the partition
    gave to Zeek; every other observation reads by the name rule alone.
    """
    if not _is_zeek_candidate(entry, pattern):
        return False
    return obs.admitted is None or entry.path in obs.admitted


def observe_zeek_input(path: Path) -> InputObservation:
    """Observe one Zeek input. Child directories are listed on first selection."""
    return _observe_root("zeek_dir", path)


def select_zeek_files(
    obs: InputObservation,
    pattern: str,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Path]:
    """Choose Zeek logs from an observation: the flat, dated and file layouts.

    The selection rules are those ``discover_zeek_files`` documents: a flat
    directory keeps its primary logs; a dated directory reads its date children
    plus every non-date child (the live ``current`` spool), prunes date
    directories by name under a window, seeds the realpath dedupe with the
    pruned directories so an alias of a pruned day stays excluded, and never
    reads root-level files.
    """
    if obs.kind == _INPUT_FILE:
        return [obs.path] if _file_matches_pattern(obs.path, pattern) else []
    if obs.kind != _INPUT_DIRECTORY:
        return []
    if obs.mode is not None:
        # A recursive input reads through its logical Zeek roots, each with the
        # flat or dated selection below; a file two roots reach counts once.
        return _union_dedupe([
            select_zeek_files(view, pattern, since, until) for view in obs.logical
        ])
    date_dirs = _observed_date_dirs(obs)
    if not date_dirs:
        # Flat layout. Keep only primary Zeek logs (conn.log, conn.<ts>.log.gz),
        # never derived siblings that share the type prefix (conn-summary).
        return [
            entry.path for entry in obs.entries
            if _zeek_entry_admitted(obs, entry, pattern)
        ]

    # Dated layout. Root-level FILES are never included (mixed-root policy);
    # non-date CHILD DIRS (current/, export/) join the candidate set in BOTH
    # branches - the live spool must stay discoverable under a window.
    non_date_children = [
        entry.path for entry in obs.entries
        if entry.kind is EntryKind.DIRECTORY
        and not _DATE_DIR_RE.match(entry.path.name)
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
        # An excluded date directory must not return through a non-date alias
        # (current -> pruned day): reading it could only yield filtered rows.
        seen: set[Path] = {d.resolve() for d in excluded_dates}
        candidates: list[Path] = included_dates + non_date_children
    else:
        seen = set()
        candidates = list(date_dirs) + non_date_children

    # Non-date children are often links to date directories; dedupe by realpath.
    included: list[Path] = []
    for d in sorted(candidates, key=lambda p: p.name):
        rp = d.resolve()
        if rp not in seen:
            seen.add(rp)
            included.append(d)

    files: list[Path] = []
    for d in included:
        files.extend(
            entry.path for entry in obs.child_entries(d)
            if _zeek_entry_admitted(obs, entry, pattern)
        )
    return files


def observe_syslog_input(path: Path) -> InputObservation:
    """Observe one syslog input and run the content gate once per candidate."""
    obs = _observe_root("syslog_dir", path)
    if obs.kind == _INPUT_DIRECTORY:
        obs.accepted = tuple(sorted(
            (
                entry.path for entry in obs.entries
                if entry.kind is EntryKind.REGULAR
                and _is_syslog_directory_candidate_name(entry.path.name)
                and _looks_like_syslog(entry.path)
            ),
            key=lambda p: _rotation_base_and_index(p.name),
        ))
    return obs


def select_syslog_files(
    obs: InputObservation,
    pattern: str = "*.log*",
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Path]:
    """Syslog candidates: a named file as-is, else the content-gated listing."""
    if obs.kind == _INPUT_FILE:
        return [obs.path]
    if obs.kind != _INPUT_DIRECTORY:
        return []
    return list(obs.accepted)


def observe_pihole_input(path: Path) -> InputObservation:
    """Observe one Pi-hole input; the filename pattern applies at selection."""
    return _observe_root("pihole_dir", path)


def select_pihole_files(
    obs: InputObservation,
    pattern: str = "*.log*",
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Path]:
    """Pi-hole candidates: regular files matching ``pattern``, rotation order.

    Only REGULAR entries qualify. A directory, FIFO or other non-regular entry
    whose name matches is never a candidate, so it is never opened.
    """
    if obs.kind == _INPUT_FILE:
        return [obs.path]
    if obs.kind != _INPUT_DIRECTORY:
        return []
    if obs.mode is not None:
        # A recursive input keeps its admitted files in walk-independent order.
        return [
            path for path in obs.accepted
            if fnmatch.fnmatchcase(path.name, pattern)
            and not path.name.startswith("._")
        ]
    files = [
        entry.path for entry in obs.entries
        if entry.kind is EntryKind.REGULAR
        and fnmatch.fnmatchcase(entry.path.name, pattern)
        and not entry.path.name.startswith("._")
    ]
    return sorted(files, key=lambda p: _rotation_base_and_index(p.name))


def _is_cloudtrail_candidate_path(path: Path) -> bool:
    """CloudTrail's filename grammar and exclusions, applied to one path."""
    return (
        fnmatch.fnmatchcase(path.name, _CLOUDTRAIL_PATTERN)
        and not is_reserved_provenance_path(path)
        and not path.name.startswith("._")
        and "CloudTrail-Digest" not in path.parts
    )


def observe_cloudtrail_input(path: Path) -> InputObservation:
    """Walk one CloudTrail input completely, accounting for what it cannot read.

    The walk lists every directory below the root and does not follow a
    directory symbolic link (the shipped recursive glob never did either); file
    links are followed. A denied descendant is recorded in ``denied_dirs``;
    another listing failure, a linked directory left unfollowed, and a
    grammar-matching entry that is not a regular file each become a fact.
    """
    if path.is_file():
        return InputObservation("cloudtrail_dir", path, _INPUT_FILE)
    if not path.is_dir():
        # Neither a file nor a directory: absent, or present but not listable as
        # a directory. Only the first is "missing"; the second carries no errno
        # because nothing was attempted that could fail.
        kind = _INPUT_ERROR if os.path.lexists(path) else _INPUT_MISSING
        return InputObservation("cloudtrail_dir", path, kind)
    obs = _observe_root("cloudtrail_dir", path)
    if obs.kind != _INPUT_DIRECTORY:
        return obs
    # The root is already listed; the walk reuses that listing.
    tree = walk_directory_tree(
        path, _listings={_safe_resolve(path): (obs.entries, None)},
    )
    accepted: list[Path] = []
    nonregular: list[Path] = []
    broken: list[Path] = []
    entry_errors: list[tuple[Path, str]] = []
    for entry in tree_entries(tree):
        if entry.kind is EntryKind.ERROR:
            # Its type is unknown: it may be a file the grammar admits or a
            # directory owning a subtree, so it is counted before any gate.
            entry_errors.append((entry.path, entry.error or ""))
            continue
        if not _is_cloudtrail_candidate_path(entry.path):
            continue
        if entry.kind is EntryKind.REGULAR:
            accepted.append(entry.path)
        elif entry.kind is EntryKind.BROKEN_LINK:
            broken.append(entry.path)
        else:
            nonregular.append(entry.path)
    obs.accepted = tuple(sorted(accepted))
    obs.denied_dirs.extend(tree.denied)
    for kind, paths in (
        (DiscoveryFactKind.LINKED_DIRECTORY_OMITTED, list(tree.linked)),
        (DiscoveryFactKind.NONREGULAR_MATCH, sorted(nonregular)),
        (DiscoveryFactKind.BROKEN_LINK, sorted(broken)),
    ):
        if paths:
            obs.facts.append(DiscoveryFact(
                kind, "cloudtrail_dir", path, tuple(paths), len(paths),
            ))
    for kind, items in (
        (DiscoveryFactKind.LISTING_ERROR, list(tree.listing_errors)),
        (DiscoveryFactKind.ENTRY_ERROR, sorted(entry_errors)),
    ):
        for item_path, cause in items:
            obs.facts.append(DiscoveryFact(
                kind, "cloudtrail_dir", path, (item_path,), 1, cause,
            ))
    return obs


def select_cloudtrail_files(
    obs: InputObservation,
    pattern: str = _CLOUDTRAIL_PATTERN,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Path]:
    """CloudTrail candidates: a named file as-is, else the walked, sorted files."""
    if obs.kind == _INPUT_FILE:
        return [obs.path]
    if obs.kind != _INPUT_DIRECTORY:
        return []
    return list(obs.accepted)


# ─────────────────────────────────────────────────────────────────────────────
# Coverage: what each family's own selection left unread in one observation.
# The family that decides selection is the one that names its omissions, so
# these sit beside the selections and are registered on the same strategy.
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ObservedCoverage:
    """What one family's traversal of one directory input did not use.

    ``unsearched`` are child directories the family's selection never enters.
    ``facts`` are entries it met but could not use: an entry whose inspection
    failed (whatever its name, because its type is unknown), and a name-matching
    entry that is a non-regular file or a dangling link, plus anything recorded
    below the input. ``regular_files`` are the regular, non-AppleDouble files a
    family would have judged directly under the input. ``silent_miss_covered``
    says whether the loader's silent-miss warning, when it fires for this
    family, states this input's content.
    """

    unsearched: tuple[Path, ...] = ()
    facts: tuple[DiscoveryFact, ...] = ()
    regular_files: tuple[Path, ...] = ()
    silent_miss_covered: bool = False


def _observed_has_regular_files(obs: InputObservation) -> bool:
    """The ``_dir_has_regular_files`` predicate, read from an observation."""
    return obs.kind == _INPUT_DIRECTORY and any(
        entry.kind is EntryKind.REGULAR and not entry.path.name.startswith("._")
        for entry in obs.entries
    )


def _child_directories(obs: InputObservation) -> tuple[Path, ...]:
    return tuple(e.path for e in obs.entries if e.kind is EntryKind.DIRECTORY)


def _regular_files(obs: InputObservation) -> tuple[Path, ...]:
    return tuple(
        e.path for e in obs.entries
        if e.kind is EntryKind.REGULAR and not e.path.name.startswith("._")
    )


def _unusable_entry_facts(
    source_key: str,
    root: Path,
    entries: tuple[DirectoryEntry, ...],
    name_admits: Callable[[str], bool] | None,
) -> list[DiscoveryFact]:
    """Facts about listed entries a selection met but could not use.

    An entry whose inspection failed is reported whatever its name. A
    non-regular entry or a dangling link is reported only when ``name_admits``
    says the family would have taken it; a content-gated family passes None,
    since a FIFO or a dangling link can never be content it reads.
    """
    nonregular: list[Path] = []
    broken: list[Path] = []
    facts: list[DiscoveryFact] = []
    for entry in entries:
        if entry.kind is EntryKind.ERROR:
            facts.append(DiscoveryFact(
                DiscoveryFactKind.ENTRY_ERROR, source_key, root, (entry.path,), 1,
                entry.error or None,
            ))
        elif name_admits is None or not name_admits(entry.path.name):
            continue
        elif entry.kind is EntryKind.NONREGULAR:
            nonregular.append(entry.path)
        elif entry.kind is EntryKind.BROKEN_LINK:
            broken.append(entry.path)
    if nonregular:
        facts.append(DiscoveryFact(
            DiscoveryFactKind.NONREGULAR_MATCH, source_key, root,
            tuple(nonregular), len(nonregular),
        ))
    if broken:
        facts.append(DiscoveryFact(
            DiscoveryFactKind.BROKEN_LINK, source_key, root, tuple(broken), len(broken),
        ))
    return facts


def zeek_coverage(obs: InputObservation, patterns: Sequence[str]) -> ObservedCoverage:
    """Zeek: a flat directory leaves its children unsearched; a dated one does not.

    A dated layout reads every child one level deep and never reads root
    files, so it reports no unsearched children and no root files to judge, but
    an uninspectable root entry (possibly a date directory) still counts.
    """
    if obs.kind != _INPUT_DIRECTORY:
        return ObservedCoverage()

    def admits(name: str) -> bool:
        return any(
            fnmatch.fnmatchcase(name, pattern) and _is_primary_zeek_name(name, pattern)
            for pattern in patterns
        )

    facts = list(obs.facts)
    if obs.mode == "partition":
        # A positional partition's walk facts belong to its root; only the
        # family's own layout decisions are Zeek's to state.
        return ObservedCoverage(facts=tuple(facts))
    if obs.mode == "declared":
        # The whole tree was searched; its unusable entries are the family's.
        facts.extend(_unusable_entry_facts("zeek_dir", obs.path, obs.entries, admits))
        return ObservedCoverage(facts=tuple(facts), regular_files=_regular_files(obs))
    if _observed_date_dirs(obs):
        facts.extend(_unusable_entry_facts("zeek_dir", obs.path, obs.entries, lambda _n: False))
        for entries in obs.listed_children().values():
            facts.extend(_unusable_entry_facts("zeek_dir", obs.path, entries, admits))
        return ObservedCoverage(facts=tuple(facts))
    facts.extend(_unusable_entry_facts("zeek_dir", obs.path, obs.entries, admits))
    return ObservedCoverage(
        unsearched=_child_directories(obs),
        facts=tuple(facts),
        regular_files=_regular_files(obs),
    )


def syslog_coverage(obs: InputObservation, patterns: Sequence[str]) -> ObservedCoverage:
    """Syslog: one level, content-gated, so only uninspectable entries are facts."""
    if obs.kind != _INPUT_DIRECTORY:
        return ObservedCoverage()
    facts = [*obs.facts, *_unusable_entry_facts("syslog_dir", obs.path, obs.entries, None)]
    return ObservedCoverage(
        unsearched=_child_directories(obs),
        facts=tuple(facts),
        regular_files=_regular_files(obs),
        silent_miss_covered=_observed_has_regular_files(obs),
    )


def pihole_coverage(obs: InputObservation, patterns: Sequence[str]) -> ObservedCoverage:
    """Pi-hole: one level, filename-gated; a matching directory is a child."""
    if obs.kind != _INPUT_DIRECTORY:
        return ObservedCoverage()

    def admits(name: str) -> bool:
        return not name.startswith("._") and any(
            fnmatch.fnmatchcase(name, pattern) for pattern in patterns
        )

    facts = [*obs.facts, *_unusable_entry_facts("pihole_dir", obs.path, obs.entries, admits)]
    return ObservedCoverage(
        unsearched=_child_directories(obs),
        facts=tuple(facts),
        regular_files=_regular_files(obs),
        silent_miss_covered=bool(select_pihole_files(obs, "*.log*")),
    )


def cloudtrail_coverage(obs: InputObservation, patterns: Sequence[str]) -> ObservedCoverage:
    """CloudTrail: the walk is complete, so only what it recorded is a fact.

    Its root files are not judged here: the existing "no CloudTrail JSON logs
    found" skip reason states that outcome for this family.
    """
    if obs.kind != _INPUT_DIRECTORY:
        return ObservedCoverage()
    return ObservedCoverage(facts=tuple(obs.facts))


def _zeek_dated_window(
    paths: list[Path],
    span: timedelta,
    *,
    _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
    _observations: Mapping[Path, InputObservation] | None = None,
) -> tuple[datetime, datetime | None] | object | None:
    """Compute the default analysis window for a union of Zeek inputs.

    PURELY-DATED predicate: every READABLE input is a directory with non-empty
    YYYY-MM-DD subdirs. Denied inputs are omitted from inference rather than
    represented as empty. When the predicate holds, generalizes the single-input
    selection across the union - gather every discovered date subdir, dedupe by
    date prefix, sort by date, select the newest ``N = ceil(span_days)`` (min 1),
    and return ``00:00:00`` UTC of the earliest selected with an open upper
    bound. The floor implements the dated default; the open ceiling admits the
    live ``current/`` spool and deliberately treats future-stamped rows like
    flat defaults and ``--all`` rather than inventing an ``until=now`` cap.

    Returns ``None`` when ANY readable input is a file (file + dated-dir mix) or
    any readable directory is flat (mixed/flat present). Returns the private
    denial sentinel only when no readable input remains. The resolver maps that
    sentinel to the universal post-load trim without claiming a flat layout.

    Single-input behavior is BYTE-IDENTICAL with the prior scalar helper: a
    one-element list of a single dated dir runs the same selection
    (``_zeek_date_subdirs(input)``, newest N, earliest-midnight → open end).

    Sparse archives behave correctly: subdirs ``[2026-01-01, 2026-01-05]``
    with span=2d → BOTH selected, floor Jan 1 with an open end. Cross-input
    duplicate dates count once toward N (dedup by date prefix).

    ``_observations`` supplies already-observed inputs by path. An observed
    input that could not be listed, for any reason, is omitted from layout
    inference exactly as a denied one is, because it carries no layout.
    """
    if not paths:
        return None
    all_date_dirs: list[Path] = []
    readable_inputs = 0
    denied_input = False
    for p in paths:
        obs = _observations.get(p) if _observations is not None else None
        # An observed input keeps its observed kind, so a directory that
        # disappears after discovery keeps the layout it was observed with.
        if obs is None:
            if not p.is_dir():
                return None
        elif obs.kind in (_INPUT_FILE, _INPUT_MISSING):
            return None
        if obs is not None and obs.mode is not None:
            # A recursive input carries only its contributing logical roots.
            # With none it cannot change the family window; any flat one sends
            # the family to the load-full-then-trim policy.
            apply_observation_denials(obs, _directory_skips)
            if not obs.logical:
                continue
            for view in obs.logical:
                view_dates = _observed_date_dirs(view)
                if not view_dates:
                    return None
                all_date_dirs.extend(view_dates)
            readable_inputs += 1
            continue
        if obs is not None:
            apply_observation_denials(obs, _directory_skips)
            if obs.kind != _INPUT_DIRECTORY:
                denied_input = True
                continue
            date_dirs = _observed_date_dirs(obs)
        else:
            try:
                date_dirs = _zeek_date_subdirs(
                    p, _directory_skips=_directory_skips,
                )
            except _DirectoryListingDenied:
                denied_input = True
                continue
        readable_inputs += 1
        if not date_dirs:
            return None
        all_date_dirs.extend(date_dirs)
    if denied_input and readable_inputs == 0:
        return _ZEEK_DATED_DENIED
    if readable_inputs == 0:
        # Every input was a recursive one contributing no logical root: no
        # layout exists to select from, and the universal trim is inert.
        return None
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
    since = datetime(earliest_date.year, earliest_date.month, earliest_date.day,
                     0, 0, 0, tzinfo=timezone.utc)
    return since, None


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
    strategy,
    dirs: list[Path],
    pattern: str,
    span: timedelta,
    *,
    _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
    _observations: Mapping[Path, InputObservation] | None = None,
) -> tuple[tuple[datetime, datetime | None] | None, timedelta | None]:
    """Zeek strategy resolver. Dated layout → a lower-bounded ``(since, None)``
    ``select_window`` and NO post-load trim (date-directory selection and the
    load-time floor own that default). Flat / mixed / file and
    all-denied/unclassifiable → ``(None, span)`` (load full, trim post-load); the
    latter has no rows for the trim to affect.
    """
    dated = _zeek_dated_window(
        dirs,
        span,
        _directory_skips=_directory_skips,
        _observations=_observations,
    )
    if dated is _ZEEK_DATED_DENIED:
        # No readable input exists from which to infer layout. Preserve the
        # universal default-window invariant (trim_span is None only when a
        # dated select_window already owns the load-time default); an empty load makes
        # this post-load trim behaviorally inert.
        return None, span
    if dated is not None:
        assert isinstance(dated, tuple)
        return dated, None
    return None, span


def _flat_default_floor(
    strategy,
    dir_paths: list[Path],
    pattern: str,
    span: timedelta,
    *,
    _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
    _observations: Mapping[Path, InputObservation] | None = None,
) -> tuple[datetime, None] | None:
    """Conservative default-window floor for a flat family (syslog / pihole).

    Discovers the family's DIRECTORY candidates via ``strategy.discover_paths``
    over the ``is_dir()`` inputs (``_union_dedupe``d - the same universe as
    :func:`load_required_logs`, explicit files excluded) and peeks each candidate's
    first-ts (``_peek_first_ts`` - clock-parity with the loader's own filter).
    Returns ``(f_max − span, None)`` - the conservative select-window the
    rotation-peek prunes against (``until=None``; the precise cut is the post-load
    trim) - where ``f_max`` is the max parseable first-ts across candidates.
    Returns ``None`` when nothing is peekable (load-full fallback).
    With ``_observations`` the candidates come from the observed inputs through
    the strategy's ``select_observed``, the same universe without a re-listing.
    """
    def _candidates(d: Path) -> list[Path]:
        obs = _observations.get(d) if _observations is not None else None
        if obs is None:
            return strategy.discover_paths(
                d, pattern, None, None, _directory_skips=_directory_skips,
            )
        files = strategy.select_observed(obs, pattern, None, None)
        apply_observation_denials(obs, _directory_skips)
        return files

    def _directory_input(d: Path) -> bool:
        obs = _observations.get(d) if _observations is not None else None
        if obs is None:
            return d.is_dir()
        return obs.kind not in (_INPUT_FILE, _INPUT_MISSING)

    candidates = _union_dedupe([_candidates(d) for d in dir_paths if _directory_input(d)])
    peeked = [ts for ts in (_peek_first_ts(p) for p in candidates) if ts is not None]
    if not peeked:
        return None
    return (max(peeked) - span, None)


def _flat_resolve_window(
    strategy,
    dirs: list[Path],
    pattern: str,
    span: timedelta,
    *,
    _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
    _observations: Mapping[Path, InputObservation] | None = None,
) -> tuple[tuple[datetime, None] | None, timedelta]:
    """Flat strategy resolver (syslog / pihole). Peek the directory candidates →
    conservative ``(floor, None)`` ``select_window`` + precise post-load
    ``trim_span``; unpeekable → ``(None, span)`` (load full, trim post-load).
    """
    return (
        _flat_default_floor(
            strategy,
            dirs,
            pattern,
            span,
            _directory_skips=_directory_skips,
            _observations=_observations,
        ),
        span,
    )


def discover_zeek_files(
    directory: Path,
    pattern: str,
    since: datetime | None = None,
    until: datetime | None = None,
    *,
    _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
) -> list[Path]:
    """Return Zeek log files matching pattern from a flat or dated-layout directory.

    Single-file mode (directory.is_file() True): returns [directory] when its basename
    matches the pattern, else []. Single-file zeek_dir is a bounded target.

    Flat layout (no YYYY-MM-DD immediate children): the directory's primary logs in
    sorted order. Dated layout: one candidate universe for BOTH the windowed and
    no-window cases - YYYY-MM-DD subdirs plus every non-date child directory
    (current/, export/), deduped by realpath. A window prunes date dirs by name;
    non-date children cannot be dated from their names, so they are always
    candidates and their rows are window-filtered downstream. A non-date alias of a
    PRUNED date dir stays excluded: the pruned dirs' realpaths seed the dedupe set.
    This is structural inspection of a known zeek_dir - not generic format discovery.

    Mixed-root policy: if any immediate child is a YYYY-MM-DD directory, dated layout
    is used and root-level files are not included. Zeek does not produce root-level files
    alongside date subdirs; the hybrid is ambiguous and therefore unsupported.

    A directory-listing denial returns no candidates for that input and records
    the omission when a caller-owned sink is supplied; it never enters the flat arm.
    Any other failure to list the input raises, and a child directory that cannot
    be listed contributes nothing. Selection is ``select_zeek_files``.
    """
    reject_explicit_reserved_path(directory)
    obs = observe_zeek_input(directory)
    _apply_legacy_root(obs, _directory_skips, raise_errors=True)
    return select_zeek_files(obs, pattern, since, until)


def _syslog_files(
    path: Path,
    pattern: str = "*.log*",
    *,
    _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
) -> list[Path]:
    """Return flat-source files to process by FILENAME glob: ``[path]`` if a file,
    else regular files matching ``pattern`` in the directory - ``._``-prefixed
    AppleDouble sidecars dropped, numeric rotation order.

    Pi-hole's discovery helper (and the Pi-hole pattern-mismatch presence check).
    Syslog discovery is NOT this - it content-sniffs via ``_discover_syslog_files``
    (RHEL/Fedora streams carry no ``.log`` suffix, and ``dnf.log`` etc. would be
    mis-claimed by a filename glob). The ``pattern`` applies to DIRECTORY discovery
    ONLY (pihole passes ``pihole*.log*`` to avoid grabbing non-pihole files in a
    shared dir). An explicitly-named FILE always loads as named - the pattern is
    NOT applied to it, so a content-routed Pi-hole file like ``events.log`` still
    loads. A matching directory, FIFO or other non-regular entry is never a
    candidate, so it is never opened. The AppleDouble filter and numeric ordering
    apply to DIRECTORY discovery only: the junk filter targets glob noise, not
    operator intent. A listing failure other than a denial yields no candidates.
    Selection is ``select_pihole_files``.
    """
    reject_explicit_reserved_path(path)
    obs = observe_pihole_input(path)
    _apply_legacy_root(obs, _directory_skips, raise_errors=False)
    return select_pihole_files(obs, pattern)


_UTMP_FAMILY_NAMES = frozenset({"btmp", "wtmp", "utmp", "lastlog", "faillog"})


def _is_syslog_directory_candidate_name(name: str) -> bool:
    """Whether a directory child name may proceed to syslog content sniffing.

    AppleDouble sidecars and the fixed utmp-family database names are
    known-never-syslog. First-dot stem matching excludes rotations without
    turning filenames into an inclusion rule. Explicit file inputs bypass this
    predicate at ``_discover_syslog_files``'s early return.
    """
    return (
        not name.startswith("._")
        and name.split(".", 1)[0] not in _UTMP_FAMILY_NAMES
    )


# ─────────────────────────────────────────────────────────────────────────────
# Recursive admission: each family's existing directory gate, answering for one
# file a recursive walk met. ``sniff`` is the file's detailed sniff when its
# content decided the family, else None (a declared walk, or a name-claiming
# family offered an unclassified file). The registry declares these per family,
# so the partition that consults them never names a family itself.
# ─────────────────────────────────────────────────────────────────────────────


def zeek_recursive_admit(
    path: Path, sniff: object | None, patterns: Sequence[str],
) -> Admission:
    """Zeek: a primary log name for a pattern this run reads.

    A file whose content sniffed as a Zeek log type no pattern names is a Zeek
    log this run does not read (``OUTSIDE``), not a misnamed one.
    """
    name = path.name
    named = any(
        fnmatch.fnmatchcase(name, pattern) and _is_primary_zeek_name(name, pattern)
        for pattern in patterns
    )
    schema = getattr(sniff, "schema", None) if sniff is not None else None
    if schema is not None and schema not in {p.split("*", 1)[0] for p in patterns}:
        return Admission.OUTSIDE
    return Admission.ADMIT if named else Admission.REJECT


def syslog_recursive_admit(
    path: Path, sniff: object | None, patterns: Sequence[str],
) -> Admission:
    """Syslog: the directory name rule and the content gate, as one level reads.

    The content gate keeps a file it cannot read, as directory discovery does.
    """
    if not _is_syslog_directory_candidate_name(path.name):
        return Admission.REJECT
    return Admission.ADMIT if _looks_like_syslog(path) else Admission.REJECT


def pihole_recursive_admit(
    path: Path, sniff: object | None, patterns: Sequence[str],
) -> Admission:
    """Pi-hole: its filename pattern, AppleDouble excluded."""
    name = path.name
    if not name.startswith("._") and any(
        fnmatch.fnmatchcase(name, pattern) for pattern in patterns
    ):
        return Admission.ADMIT
    return Admission.REJECT


def cloudtrail_recursive_admit(
    path: Path, sniff: object | None, patterns: Sequence[str],
) -> Admission:
    """CloudTrail: its own filename grammar and exclusions."""
    if _is_cloudtrail_candidate_path(path):
        return Admission.ADMIT
    return Admission.REJECT


def syslog_recursive_excludes(path: Path) -> bool:
    """A utmp-family database: binary login records, never a log to read."""
    return path.name.split(".", 1)[0] in _UTMP_FAMILY_NAMES


def cloudtrail_recursive_excludes(path: Path) -> bool:
    """A CloudTrail integrity digest: a manifest, never events."""
    return "CloudTrail-Digest" in path.parts


def _discover_syslog_files(
    path: Path,
    *,
    _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
) -> list[Path]:
    """The SINGLE syslog discovery universe - content-gated.

    FILE input → ``[path]`` UNGATED (the explicit-named-file rail: an explicitly
    named file always loads regardless of name; ``_syslog_should_skip`` still
    guards a named NDJSON/Zeek-TSV at load). DIRECTORY input → all regular files
    whose names are neither AppleDouble nor utmp-family databases and whose
    content passes ``_looks_like_syslog``, in rotation order.
    Non-recursive listing correctly skips the binary subdirs (``journal/``,
    ``audit/``, ``sa/``) - they are not regular files.
    A listing denial yields no candidates and records the source directory when
    a caller-owned sink is supplied; any other listing failure raises. Selection
    is ``select_syslog_files`` over ``observe_syslog_input``.
    """
    reject_explicit_reserved_path(path)
    obs = observe_syslog_input(path)
    _apply_legacy_root(obs, _directory_skips, raise_errors=True)
    return select_syslog_files(obs)


def _dir_has_regular_files(path: Path) -> bool:
    """True iff ``path`` holds >=1 regular, non-AppleDouble file.

    Cheap ``iterdir`` presence check for the syslog zero-accepted disclosure -
    NO sniff, NO ``*.log*`` test, so an extensionless-only dir does not fall
    through the disclosure silently.
    """
    try:
        return any(
            p.is_file()
            and not p.name.startswith("._")
            and not is_reserved_provenance_path(p)
            for p in path.iterdir()
        )
    except OSError:
        return False


def discover_cloudtrail_files(
    path: Path,
    *,
    _directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None = None,
) -> list[Path]:
    """Discover CloudTrail event files for the loader and runner satisfiability check.

    File path → [path]. Directory → every ``*.json*`` file below it, sorted,
    excluding AppleDouble ``._*`` sidecars (the resource-fork junk macOS/SMB/USB
    volumes leave beside real files - the same drop the flat families apply) and
    any file whose path contains a ``CloudTrail-Digest`` component (integrity
    manifests, not events - the same exclusion the exporter applies on the S3 side).

    The ``*.json*`` grammar covers ``.json``, ``.json.gz``, the exporter's
    ``.json.log`` and its ``_partNN`` splits. Recursion is what makes a native
    ``AWSLogs/<acct>/CloudTrail/<region>/YYYY/MM/DD/`` tree work - users who pull
    logs their own way can point ``cloudtrail_dir`` at any level of that tree.
    Directory links are not followed. This helper records only a denied input
    root; descendants it cannot read contribute nothing. The walk itself is
    ``observe_cloudtrail_input``, which keeps those descendant facts for callers
    that disclose them.
    """
    reject_explicit_reserved_path(path)
    obs = observe_cloudtrail_input(path)
    _apply_legacy_root(obs, _directory_skips, raise_errors=False)
    return select_cloudtrail_files(obs)


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
