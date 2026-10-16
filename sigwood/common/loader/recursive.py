"""Recursive discovery for one analyze invocation: walks, partition and views.

Directories supplied on an analyze invocation under ``--recursive`` are walked
once each by the shared walker in ``discovery``, and overlapping walks share
every listing. A positional directory's regular files are then partitioned:
each goes to at most one family, decided by the registered strategies' recursive
fields in a fixed order - the family the file's content sniffed as, then the
families that claim unclassified content by name, then the content-fallthrough
families. A ``--<family>-dir`` directory is a family declaration, so that
family's own gate judges every file beneath it.

Zeek's dated layout is resolved once, across every walk of the invocation, after
all of them are complete. A directory with a date-named child directory is a
dated root (the structural rule ``discovery`` applies to one directory); the
outermost one owns its children's whole subtrees and reads them one level deep,
following its linked children as the dated layout always has. A directory
outside every owned subtree that holds Zeek files directly is a flat root.
Ownership therefore never depends on the order of a walk.

The results are views: for one family and one input, an ``InputObservation``
that family's existing selection, coverage and window hooks read. A recursive
input stays one logical directory input; nothing here turns it into files.

Layering: imports discovery, sniff, types and the registry. Only the inventory
imports this module.
"""

from __future__ import annotations

import gzip
import lzma
import os
import stat
import zlib
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from sigwood.common.loader.discovery import (
    _DATE_DIR_RE,
    _INPUT_DENIED,
    _INPUT_DIRECTORY,
    _INPUT_ERROR,
    _INPUT_MISSING,
    InputObservation,
    Listing,
    TreeListing,
    _cached_listing,
    _errno_name,
    _observed_date_dirs,
    tree_entries,
    tree_walk_facts,
    walk_directory_tree,
)
from sigwood.common.loader.io import _safe_resolve
from sigwood.common.loader.pipeline import _SOURCE_LOADERS
from sigwood.common.loader.provenance import reject_explicit_reserved_path
from sigwood.common.loader.sniff import sniff_format_detailed
from sigwood.common.loader.types import (
    Admission,
    DirectoryEntry,
    DiscoveryFact,
    DiscoveryFactKind,
    EntryKind,
    FileOutcome,
    FileOutcomeKind,
    RootFact,
    RootFactKind,
)
from sigwood.common.loader.windowing import _rotation_base_and_index

# The dated layout below is Zeek's own directory policy, the one ``discovery``
# applies to a single Zeek input; this is the only family it concerns.
_ZEEK_SOURCE = "zeek_dir"

PARTITION = "partition"
DECLARED = "declared"

# A file whose content cannot be read fails with one of these; the same set the
# loader's corruption rail treats as unreadable content, plus a corrupt deflate
# stream, which surfaces as zlib.error rather than an OSError.
_READ_FAILURES: tuple[type[BaseException], ...] = (
    OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError, zlib.error,
)


def failure_token(exc: BaseException) -> str:
    """A tool-derived cause token for a failed read: never the exception text."""
    if isinstance(exc, OSError) and getattr(exc, "errno", None) is not None:
        return _errno_name(exc)
    cls = type(exc)
    return f"{cls.__module__}.{cls.__name__}" if cls.__name__ == "error" else cls.__name__


def _ask(strategy, path: Path, sniff: object | None, patterns: Sequence[str]) -> Admission:
    """One family gate's answer; a gate that itself cannot read admits nothing.

    A content gate's own include-on-read-error rule covers the failures it
    handles. Anything that escapes it leaves the file without an admission, so
    the partition never hands the load a file no gate accepted.
    """
    try:
        return strategy.recursive_admit(path, sniff, patterns)
    except _READ_FAILURES:
        return Admission.REJECT


def _offered(
    permitted: Mapping[str, tuple[str, ...]], flag: str,
) -> Iterator[tuple[str, object]]:
    """Permitted strategies that declare ``flag``, in registry order."""
    for key, strategy in _SOURCE_LOADERS.items():
        if (
            key in permitted
            and strategy.recursive_admit is not None
            and getattr(strategy, flag)
        ):
            yield key, strategy


@dataclass(frozen=True)
class FileContent:
    """One physical file's detailed sniff, or the cause it could not be read.

    Content belongs to the file, so every spelling of it shares one read; which
    family admits it depends on the spelling's name, and is decided per name.
    """

    sniff: object | None = None
    cause: str | None = None


def read_content(path: Path) -> FileContent:
    """Sniff one file once, keeping a read failure's cause instead of its text."""
    try:
        return FileContent(sniff_format_detailed(path))
    except _READ_FAILURES as exc:
        return FileContent(cause=failure_token(exc))


def _name_excluded(path: Path) -> bool:
    """A never-a-log name: no family reads it, so no read is spent on it."""
    return path.name.startswith("._") or any(
        strategy.recursive_excludes is not None and strategy.recursive_excludes(path)
        for strategy in _SOURCE_LOADERS.values()
    )


def _rank(stage: int, key: str) -> tuple[int, int]:
    """An admission's precedence: the earlier partition stage, then registry order."""
    return (stage, list(_SOURCE_LOADERS).index(key))


Rank = tuple[int, int]


def admit_spelling(
    path: Path,
    resolved: Path,
    permitted: Mapping[str, tuple[str, ...]],
    content: Callable[[], FileContent],
) -> tuple[FileOutcome, Rank | None]:
    """Decide which family, if any, one spelling of a file would go to.

    The order is the accepted partition rule: a never-a-log name; then the
    detailed sniff, whose recognized family's gate is asked first; for
    unclassified content only, the families claiming it by name; then, for any
    file still unplaced, the content-fallthrough gates. A file that cannot be
    read keeps its cause, and only a content gate's own include-on-read-error
    rule can still retain it: it never becomes a successful sniff or a name
    candidate. The returned rank orders admissions of one file reached through
    several names; ``content`` is called only for a name worth reading.
    """
    if _name_excluded(path):
        return FileOutcome(path, resolved, FileOutcomeKind.EXCLUDED), None
    found = content()
    if found.cause is not None:
        for key, strategy in _offered(permitted, "content_fallthrough"):
            if _ask(strategy, path, None, permitted[key]) is Admission.ADMIT:
                return (
                    FileOutcome(path, resolved, FileOutcomeKind.ADMITTED, key, found.cause),
                    _rank(2, key),
                )
        return FileOutcome(path, resolved, FileOutcomeKind.UNREADABLE, None, found.cause), None
    sniff = found.sniff
    if getattr(sniff, "state", None) == "empty":
        return FileOutcome(path, resolved, FileOutcomeKind.EMPTY), None

    origin_name = getattr(sniff, "origin", None)
    origin = f"{origin_name}_dir" if origin_name else None
    if origin is not None and origin not in _SOURCE_LOADERS:
        origin = None
    rejected_by: str | None = None
    if origin is not None:
        strategy = _SOURCE_LOADERS[origin]
        if origin in permitted and strategy.recursive_admit is not None:
            answer = _ask(strategy, path, sniff, permitted[origin])
            if answer is Admission.ADMIT:
                return (
                    FileOutcome(path, resolved, FileOutcomeKind.ADMITTED, origin),
                    _rank(0, origin),
                )
            if answer is Admission.REJECT:
                rejected_by = origin
    else:
        for key, strategy in _offered(permitted, "claims_unclassified"):
            if _ask(strategy, path, None, permitted[key]) is Admission.ADMIT:
                return (
                    FileOutcome(path, resolved, FileOutcomeKind.ADMITTED, key),
                    _rank(1, key),
                )
    for key, strategy in _offered(permitted, "content_fallthrough"):
        if key == rejected_by:
            continue  # its gate already answered for this file
        if _ask(strategy, path, None, permitted[key]) is Admission.ADMIT:
            return (
                FileOutcome(path, resolved, FileOutcomeKind.ADMITTED, key),
                _rank(2, key),
            )
    if origin is None:
        return FileOutcome(path, resolved, FileOutcomeKind.UNRECOGNIZED), None
    if rejected_by is not None:
        return FileOutcome(path, resolved, FileOutcomeKind.REJECTED, rejected_by), None
    return FileOutcome(path, resolved, FileOutcomeKind.OUTSIDE, origin), None


def partition_file(
    path: Path,
    permitted: Mapping[str, tuple[str, ...]],
    *,
    resolved: Path | None = None,
) -> FileOutcome:
    """The partition's answer for one spelling of one file, considered alone."""
    if resolved is None:
        resolved = _safe_resolve(path)
    return admit_spelling(path, resolved, permitted, lambda: read_content(path))[0]


@dataclass
class RecursiveRoot:
    """One directory this invocation supplied and recursion walked."""

    raw: str
    path: Path
    resolved: Path
    mode: str
    source: str | None
    tree: TreeListing
    order: int
    spellings: dict[Path, Path] = field(default_factory=dict)

    def regular_files(self) -> list[DirectoryEntry]:
        """Every regular file the walk met, in walk order."""
        return [
            entry for entry in tree_entries(self.tree)
            if entry.kind is EntryKind.REGULAR
        ]


@dataclass
class _DatedRoot:
    """A Zeek dated root: its owned children and what its layout leaves out."""

    resolved: Path
    entries: tuple[DirectoryEntry, ...]
    children: dict[Path, tuple[DirectoryEntry, ...]] = field(default_factory=dict)
    root_files: list[Path] = field(default_factory=list)
    deeper: list[Path] = field(default_factory=list)
    linked_failures: list[tuple[Path, OSError]] = field(default_factory=list)
    linked_only: list[DirectoryEntry] = field(default_factory=list)
    followed: set[Path] = field(default_factory=set)


@dataclass(frozen=True)
class LayoutContribution:
    """Which logical roots of one family add files no earlier input supplied.

    ``dated`` and ``flat`` are the contributing roots' display paths, in the
    order the contribution was decided; ``identities`` their resolved paths.
    """

    identities: frozenset[Path] = frozenset()
    dated: tuple[Path, ...] = ()
    flat: tuple[Path, ...] = ()


class RecursiveIndex:
    """Every recursive walk of one invocation, its partition and its views.

    Roots are registered while the CLI routes its inputs; ``close`` then
    resolves Zeek's layout across all of them, and only afterwards are views
    built. ``permitted`` holds the families and patterns the selected detectors
    read, restricted to strategies that declare recursive admission.
    """

    def __init__(self, declared_patterns: Mapping[str, Sequence[str]]) -> None:
        self.permitted: dict[str, tuple[str, ...]] = {
            key: tuple(patterns)
            for key, patterns in declared_patterns.items()
            if key in _SOURCE_LOADERS
            and _SOURCE_LOADERS[key].recursive_admit is not None
        }
        self.roots: list[RecursiveRoot] = []
        self._listings: dict[Path, Listing] = {}
        # Content is read once per physical file; admission is decided per
        # spelled name, and the one family a file goes to after every walk.
        self._contents: dict[Path, FileContent] = {}
        self._candidates: dict[Path, tuple[FileOutcome, Rank | None]] = {}
        self._spellings: dict[Path, list[Path]] = {}
        self._final: dict[Path, FileOutcome] = {}
        self._walk_spellings: set[Path] = set()
        self._linked_spellings: set[Path] = set()
        self._supplied: set[Path] = set()
        self._declared: dict[int, tuple[tuple[Path, ...], list[DiscoveryFact]]] = {}
        self._walked_files: set[Path] = set()
        self._dated: dict[Path, _DatedRoot] = {}
        self._flat: dict[Path, tuple[DirectoryEntry, ...]] = {}
        self._views: dict[tuple[str, Path], InputObservation] = {}
        self._contributions: dict[tuple, LayoutContribution] = {}
        self._resolved: dict[Path, Path] = {}
        self._closed = False

    def resolve(self, path: Path) -> Path:
        """``path``'s resolved identity, computed once per spelling.

        A path that is not itself a link resolves to its parent's identity plus
        its name, so a walked file costs one ``lstat`` rather than one per
        component; a link, or a path that cannot be inspected, takes the full
        resolution.
        """
        hit = self._resolved.get(path)
        if hit is not None:
            return hit
        parent = path.parent
        try:
            is_link = stat.S_ISLNK(os.lstat(path).st_mode)
        except OSError:
            is_link = True
        if is_link or parent == path:
            hit = _safe_resolve(path)
        else:
            hit = self.resolve(parent) / path.name
        self._resolved[path] = hit
        return hit

    # ── registration ────────────────────────────────────────────────────────

    def register(
        self, raw: str, path: Path, *, mode: str, source: str | None = None,
    ) -> RecursiveRoot | None:
        """Walk one supplied directory; a declaration for an unread family is inert."""
        if self._closed:
            raise RuntimeError("recursive roots are registered before views are built")
        if mode == DECLARED and source not in self.permitted:
            return None
        reject_explicit_reserved_path(path)
        tree = walk_directory_tree(path, _listings=self._listings)
        root = RecursiveRoot(
            str(raw), path, self.resolve(path), mode, source, tree, len(self.roots),
        )
        for directory, _entries in tree.directories:
            root.spellings.setdefault(self.resolve(directory), directory)
        self.roots.append(root)
        for entry in root.regular_files():
            resolved = self.resolve(entry.path)
            self._walked_files.add(resolved)
            self._walk_spellings.add(entry.path)
            if mode == PARTITION:
                self._candidate(entry.path, resolved)
        if mode == DECLARED:
            self._declare(root)
        return root

    def register_supplied(self, path: Path) -> None:
        """Note an explicit file of this run: its content is read under its own name."""
        self._supplied.add(self.resolve(path))

    def _candidate(self, spelled: Path, resolved: Path) -> None:
        """One spelling's admission, reading the file's content at most once."""
        if spelled in self._candidates:
            return

        def content() -> FileContent:
            found = self._contents.get(resolved)
            if found is None:
                found = read_content(spelled)
                self._contents[resolved] = found
            return found

        self._candidates[spelled] = admit_spelling(
            spelled, resolved, self.permitted, content,
        )
        self._spellings.setdefault(resolved, []).append(spelled)

    def _declare(self, root: RecursiveRoot) -> None:
        """A declared family's own gate over every file of its walk, once."""
        strategy = _SOURCE_LOADERS[root.source]  # type: ignore[index]
        patterns = self.permitted[root.source]  # type: ignore[index]
        accepted: list[Path] = []
        failures: list[DiscoveryFact] = []
        for entry in root.regular_files():
            try:
                answer = strategy.recursive_admit(entry.path, None, patterns)
            except _READ_FAILURES as exc:
                failures.append(DiscoveryFact(
                    DiscoveryFactKind.ENTRY_ERROR, root.source, root.path,  # type: ignore[arg-type]
                    (entry.path,), 1, failure_token(exc),
                ))
                continue
            if answer is Admission.ADMIT:
                accepted.append(entry.path)
                self._supplied.add(self.resolve(entry.path))
        self._declared[root.order] = (_ordered(root.source, accepted), failures)  # type: ignore[arg-type]

    def outcome(self, path: Path) -> FileOutcome | None:
        """One spelling's outcome: final once the index is closed."""
        if path in self._final:
            return self._final[path]
        candidate = self._candidates.get(path)
        return candidate[0] if candidate is not None else None

    def _finalize(self) -> None:
        """Give each physical file to the family of its best-ranked admission.

        Every spelling of a file is known by now, walks and dated-link listings
        alike, so the choice cannot depend on which spelling came first. A
        spelling reached only through Zeek's link exception may win for Zeek
        alone. Every other spelling of an admitted file, and any spelling whose
        content an explicit file or a declaration supplies, is ``SUPPLIED``.
        """
        for resolved, spellings in self._spellings.items():
            eligible = [
                (rank, outcome.family)
                for spelled in spellings
                for outcome, rank in (self._candidates[spelled],)
                if outcome.kind is FileOutcomeKind.ADMITTED
                and rank is not None
                and (
                    spelled not in self._linked_spellings
                    or outcome.family == _ZEEK_SOURCE
                )
            ]
            winner = min(eligible)[1] if eligible else None
            for spelled in spellings:
                outcome, _rank_value = self._candidates[spelled]
                if winner is not None:
                    keeps = (
                        outcome.kind is FileOutcomeKind.ADMITTED
                        and outcome.family == winner
                        and (spelled not in self._linked_spellings or winner == _ZEEK_SOURCE)
                    )
                    final = outcome if keeps else FileOutcome(
                        spelled, resolved, FileOutcomeKind.SUPPLIED, winner,
                    )
                elif resolved in self._supplied:
                    final = FileOutcome(spelled, resolved, FileOutcomeKind.SUPPLIED)
                else:
                    final = outcome
                self._final[spelled] = final

    def close(self) -> None:
        """Resolve Zeek's layout across every registered walk."""
        if self._closed:
            return
        self._closed = True
        zeek_patterns = self.permitted.get(_ZEEK_SOURCE)
        if not zeek_patterns:
            self._finalize()
            return
        roots = [
            root for root in self.roots
            if root.tree.error is None
            and (root.mode == PARTITION or root.source == _ZEEK_SOURCE)
        ]
        walked, visitors = self._zeek_dated_roots(roots)
        self._finalize()
        self._classify_zeek_directories(walked, visitors, zeek_patterns)

    # ── Zeek layout ─────────────────────────────────────────────────────────

    def _zeek_admissible(
        self, entry: DirectoryEntry, visitors: Sequence[RecursiveRoot],
        patterns: Sequence[str],
    ) -> bool:
        """Whether a walked root holding this file would read it as Zeek."""
        if entry.kind is not EntryKind.REGULAR:
            return False
        for root in visitors:
            if root.mode == PARTITION:
                if self._admitted_as(entry.path, _ZEEK_SOURCE):
                    return True
            elif _SOURCE_LOADERS[_ZEEK_SOURCE].recursive_admit(
                entry.path, None, patterns,
            ) is Admission.ADMIT:
                return True
        return False

    def _zeek_dated_roots(
        self, roots: Sequence[RecursiveRoot],
    ) -> tuple[dict[Path, tuple[DirectoryEntry, ...]], dict[Path, list[RecursiveRoot]]]:
        """Find the dated roots, and list and partition what their links reach."""
        walked: dict[Path, tuple[DirectoryEntry, ...]] = {}
        visitors: dict[Path, list[RecursiveRoot]] = {}
        for root in roots:
            for directory, entries in root.tree.directories:
                identity = self.resolve(directory)
                walked.setdefault(identity, entries)
                visitors.setdefault(identity, []).append(root)

        # Dated roots: the structural rule, outermost first. A date-named child
        # directory establishes the layout whatever its content; whether the
        # root contributes is decided later, against the run's patterns.
        owned_by: dict[Path, Path] = {}
        candidates = sorted(
            (
                identity for identity, entries in walked.items()
                if any(
                    entry.kind is EntryKind.DIRECTORY
                    and _DATE_DIR_RE.match(entry.path.name)
                    for entry in entries
                )
            ),
            key=lambda identity: (len(identity.parts), str(identity)),
        )
        for identity in candidates:
            if _owner_of(identity, owned_by) is not None:
                continue  # inside an outer dated root's owned subtree
            dated = _DatedRoot(identity, walked[identity])
            self._dated[identity] = dated
            for entry in dated.entries:
                if entry.kind is EntryKind.DIRECTORY:
                    owned_by.setdefault(self.resolve(entry.path), identity)

        # Owned children read one level deep. A child no walk listed is a link
        # the dated layout follows: list it once and partition what it holds, so
        # a file reached this way meets the same rule as one the walk reached.
        partitioned = any(root.mode == PARTITION for root in roots)
        for dated in self._dated.values():
            for entry in dated.entries:
                if entry.kind is not EntryKind.DIRECTORY:
                    continue
                child = self.resolve(entry.path)
                if entry.is_symlink:
                    # The dated layout reads a linked child, so the walk's own
                    # decision not to follow it is no omission for Zeek.
                    dated.followed.add(entry.path)
                if child in walked:
                    dated.children[child] = walked[child]
                    continue
                if not entry.is_symlink:
                    continue  # a real child the walk could not list; it said so
                listed, exc = _cached_listing(entry.path, self._listings)
                if exc is not None:
                    dated.linked_failures.append((entry.path, exc))
                    continue
                dated.children[child] = listed
                for item in listed:
                    if item.kind is not EntryKind.REGULAR:
                        continue
                    resolved = self.resolve(item.path)
                    if partitioned and item.path not in self._walk_spellings:
                        self._linked_spellings.add(item.path)
                        self._candidate(item.path, resolved)
                    if resolved not in self._walked_files:
                        dated.linked_only.append(item)
        return walked, visitors

    def _classify_zeek_directories(
        self,
        walked: Mapping[Path, tuple[DirectoryEntry, ...]],
        visitors: Mapping[Path, list[RecursiveRoot]],
        patterns: Sequence[str],
    ) -> None:
        """Every walked directory outside the dated roots' reading of their children.

        Runs after ownership of every file is final, so a flat root is one that
        really holds Zeek files its walks give to Zeek.
        """
        owned_by: dict[Path, Path] = {}
        for identity, dated in self._dated.items():
            for entry in dated.entries:
                if entry.kind is EntryKind.DIRECTORY:
                    owned_by.setdefault(self.resolve(entry.path), identity)

        # Every other walked directory: a dated root's own files are excluded,
        # files deeper than an owned child are layout omissions, and a directory
        # outside every owned subtree that holds Zeek files is a flat root.
        for identity, entries in walked.items():
            seen_by = visitors[identity]
            admissible = [
                entry.path for entry in entries
                if self._zeek_admissible(entry, seen_by, patterns)
            ]
            if identity in self._dated:
                self._dated[identity].root_files.extend(admissible)
                continue
            owner = _owner_of(identity, owned_by)
            if owner is not None:
                if identity not in owned_by:
                    self._dated[owner].deeper.extend(admissible)
                continue
            if admissible:
                self._flat[identity] = tuple(
                    entry for entry in entries if entry.kind is not EntryKind.DIRECTORY
                )

    def _admitted_as(self, path: Path, family: str) -> bool:
        """Whether this spelling's file was given to ``family`` under this name.

        A view may spell a listing through another directory name (a dated
        root's ``current`` link to a spool the walk also reached); the name is
        what admission depends on, so that spelling shares the outcome of the
        registered spelling of the same file with the same name.
        """
        outcome = self._final.get(path)
        if outcome is None:
            for spelled in self._spellings.get(self.resolve(path), ()):
                if spelled.name == path.name:
                    outcome = self._final.get(spelled)
                    break
        return (
            outcome is not None
            and outcome.kind is FileOutcomeKind.ADMITTED
            and outcome.family == family
        )

    def _zeek_admitted(self, entries: Sequence[DirectoryEntry]) -> frozenset[Path]:
        return frozenset(
            entry.path for entry in entries
            if entry.kind is EntryKind.REGULAR
            and self._admitted_as(entry.path, _ZEEK_SOURCE)
        )

    def _logical_views(self, root: RecursiveRoot) -> list[InputObservation]:
        """Root's logical Zeek roots as observations, in its own spelling."""
        views: list[tuple[str, InputObservation]] = []
        for identity, dated in self._dated.items():
            spelled = root.spellings.get(identity)
            if spelled is None:
                continue
            entries = _respell(dated.entries, spelled)
            children: dict[Path, tuple[DirectoryEntry, ...]] = {}
            for entry in entries:
                if entry.kind is not EntryKind.DIRECTORY:
                    continue
                listed = dated.children.get(self.resolve(entry.path), ())
                children[entry.path] = _respell(listed, entry.path)
            admitted = (
                self._zeek_admitted([e for listed in children.values() for e in listed])
                if root.mode == PARTITION else None
            )
            views.append((str(identity), InputObservation(
                _ZEEK_SOURCE, spelled, _INPUT_DIRECTORY, entries,
                _children=children, admitted=admitted,
            )))
        for identity, entries in self._flat.items():
            spelled = root.spellings.get(identity)
            if spelled is None:
                continue
            files = _respell(entries, spelled)
            admitted = self._zeek_admitted(files) if root.mode == PARTITION else None
            views.append((str(identity), InputObservation(
                _ZEEK_SOURCE, spelled, _INPUT_DIRECTORY, files, admitted=admitted,
            )))
        views.sort(key=lambda item: item[0])
        return [view for _key, view in views]

    def _layout_facts(self, root: RecursiveRoot) -> list[DiscoveryFact]:
        """The layout facts of every dated root ``root`` is the first to reach."""
        facts: list[DiscoveryFact] = []
        for identity, dated in self._dated.items():
            if self._first_visitor(identity) is not root:
                continue
            spelled = root.spellings[identity]
            for kind, paths in (
                (DiscoveryFactKind.ZEEK_ROOT_FILES_EXCLUDED, dated.root_files),
                (DiscoveryFactKind.ZEEK_DEEPER_THAN_LAYOUT, dated.deeper),
            ):
                if paths:
                    ordered = tuple(sorted(self._respell_one(p, root) for p in paths))
                    facts.append(DiscoveryFact(
                        kind, _ZEEK_SOURCE, spelled, ordered, len(ordered),
                    ))
        return facts

    def _first_visitor(self, identity: Path) -> RecursiveRoot | None:
        for root in self.roots:
            if identity in root.spellings and (
                root.mode == PARTITION or root.source == _ZEEK_SOURCE
            ):
                return root
        return None

    # ── views ───────────────────────────────────────────────────────────────

    def _root_for(self, source: str, path: Path) -> RecursiveRoot | None:
        declared = next(
            (r for r in self.roots if r.mode == DECLARED and r.source == source
             and r.path == path),
            None,
        )
        if declared is not None:
            return declared
        return next(
            (r for r in self.roots if r.mode == PARTITION and r.path == path), None,
        )

    def view(self, source: str, path: Path) -> InputObservation | None:
        """The recursive view of one input for one family, or None if not recursive."""
        root = self._root_for(source, path)
        if root is None:
            return None
        key = (source, path)
        cached = self._views.get(key)
        if cached is None:
            cached = self._build_view(source, root)
            self._views[key] = cached
        return cached

    def _build_view(self, source: str, root: RecursiveRoot) -> InputObservation:
        self.close()
        tree = root.tree
        if tree.error is not None:
            kind = (
                _INPUT_DENIED if isinstance(tree.error, PermissionError)
                else _INPUT_MISSING if isinstance(tree.error, FileNotFoundError)
                else _INPUT_ERROR
            )
            return InputObservation(source, root.path, kind, error=tree.error, mode=root.mode)
        if source == _ZEEK_SOURCE:
            return self._zeek_view(root)
        if root.mode == PARTITION:
            accepted = [
                entry.path for entry in root.regular_files()
                if (outcome := self._final.get(entry.path)) is not None
                and outcome.kind is FileOutcomeKind.ADMITTED
                and outcome.family == source
            ]
            return InputObservation(
                source, root.path, _INPUT_DIRECTORY,
                accepted=_ordered(source, accepted), mode=PARTITION,
            )
        accepted, failures = self._declared[root.order]
        return InputObservation(
            source, root.path, _INPUT_DIRECTORY, tree_entries(tree),
            accepted=accepted,
            denied_dirs=list(tree.denied),
            facts=[*tree_walk_facts(source, tree), *failures],
            mode=DECLARED,
        )

    def _zeek_view(self, root: RecursiveRoot) -> InputObservation:
        facts = self._layout_facts(root)
        if root.mode == PARTITION:
            return InputObservation(
                _ZEEK_SOURCE, root.path, _INPUT_DIRECTORY, facts=facts,
                mode=PARTITION, logical=tuple(self._logical_views(root)),
            )
        tree = root.tree
        followed = self._followed_spellings(root)
        linked = tuple(path for path in tree.linked if path not in followed)
        walk = replace(tree, linked=linked)
        denied = list(tree.denied)
        for identity, dated in self._dated.items():
            if self._first_visitor(identity) is not root:
                continue
            for path, exc in dated.linked_failures:
                if isinstance(exc, PermissionError):
                    denied.append(path)
                else:
                    facts.append(DiscoveryFact(
                        DiscoveryFactKind.LISTING_ERROR, _ZEEK_SOURCE, root.path,
                        (path,), 1, _errno_name(exc),
                    ))
        return InputObservation(
            _ZEEK_SOURCE, root.path, _INPUT_DIRECTORY, tree_entries(tree),
            denied_dirs=denied,
            facts=[*tree_walk_facts(_ZEEK_SOURCE, walk), *facts],
            mode=DECLARED, logical=tuple(self._logical_views(root)),
        )

    def _followed_spellings(self, root: RecursiveRoot) -> set[Path]:
        """Root's own spellings of the links Zeek's dated layout follows."""
        out: set[Path] = set()
        for identity, dated in self._dated.items():
            spelled = root.spellings.get(identity)
            if spelled is None:
                continue
            out.update(spelled / path.name for path in dated.followed)
        return out

    # ── family membership and contribution ─────────────────────────────────

    def families(self, path: Path) -> tuple[str, ...]:
        """The families a partitioned root supplies files to, in registry order."""
        self.close()
        root = next(
            (r for r in self.roots if r.mode == PARTITION and r.path == path), None,
        )
        if root is None or root.tree.error is not None:
            return ()
        found: set[str] = set()
        for entry in root.regular_files():
            outcome = self._final.get(entry.path)
            if outcome is not None and outcome.kind is FileOutcomeKind.ADMITTED:
                found.add(outcome.family)  # type: ignore[arg-type]
        if _ZEEK_SOURCE not in found and any(
            view.admitted for view in self._logical_views(root)
        ):
            found.add(_ZEEK_SOURCE)
        return tuple(key for key in _SOURCE_LOADERS if key in found)

    def partition_files(self, source: str) -> tuple[Path, ...]:
        """Every file a positional partition gave to ``source``, once, in walk order."""
        out: dict[Path, Path] = {}
        for root in self.roots:
            if root.mode != PARTITION:
                continue
            for entry in root.regular_files():
                outcome = self._final.get(entry.path)
                if outcome is not None and outcome.kind is FileOutcomeKind.ADMITTED \
                        and outcome.family == source:
                    out.setdefault(outcome.resolved, entry.path)
        return tuple(out.values())

    def contribution(
        self,
        views: Sequence[InputObservation],
        seed: set[Path],
        patterns: Sequence[str],
        select: Callable[..., list[Path]],
    ) -> LayoutContribution:
        """Which logical roots add a file that no explicit file or earlier root did.

        ``seed`` holds the resolved files the family's other inputs supply.
        Dated roots are decided before flat ones, each in resolved-path order,
        so a flat alias of a dated day can never claim the full-read policy.
        """
        by_identity: dict[Path, list[InputObservation]] = {}
        for view in views:
            for logical in view.logical:
                by_identity.setdefault(self.resolve(logical.path), []).append(logical)
        ordered = sorted(
            by_identity.items(),
            key=lambda item: (
                0 if _observed_date_dirs(item[1][0]) else 1, str(item[0]),
            ),
        )
        seen = set(seed)
        identities: set[Path] = set()
        dated: list[Path] = []
        flat: list[Path] = []
        for identity, logicals in ordered:
            files = {
                self.resolve(path)
                for logical in logicals
                for pattern in patterns
                for path in select(logical, pattern, None, None)
            }
            if not files - seen:
                continue
            seen |= files
            identities.add(identity)
            first = logicals[0]
            (dated if _observed_date_dirs(first) else flat).append(first.path)
        return LayoutContribution(frozenset(identities), tuple(dated), tuple(flat))

    # ── coverage owned by positional roots ──────────────────────────────────

    def _covered(self, root: RecursiveRoot) -> bool:
        """Whether another positional root's walk already reached this root."""
        for other in self.roots:
            if other is root or other.mode != PARTITION or other.tree.error is not None:
                continue
            if root.resolved not in other.tree.visited:
                continue
            mutual = other.resolved in root.tree.visited
            if not mutual or other.order < root.order:
                return True
        return False

    def root_facts(self) -> list[RootFact]:
        """Family-neutral coverage facts for every top positional root, in order.

        A root another positional walk reached states nothing of its own: the
        outer root's facts already cover it, and a repeated or nested root is an
        overlap rather than an empty input.
        """
        self.close()
        facts: list[RootFact] = []
        for root in self.roots:
            if root.mode != PARTITION or self._covered(root):
                continue
            facts.extend(self._facts_for(root))
        return facts

    def _facts_for(self, root: RecursiveRoot) -> list[RootFact]:
        tree = root.tree
        path = root.path
        if tree.error is not None:
            return [RootFact(
                RootFactKind.ROOT_UNLISTABLE, path, (path,), 1,
                cause=_errno_name(tree.error) if isinstance(tree.error, OSError) else None,
                permission_denied=isinstance(tree.error, PermissionError),
            )]
        facts: list[RootFact] = []
        denied = list(tree.denied)
        errors = list(tree.listing_errors)
        for identity, dated in self._dated.items():
            if self._first_visitor(identity) is not root:
                continue
            spelled = root.spellings[identity]
            for failed, exc in dated.linked_failures:
                failed_path = spelled / failed.name
                if isinstance(exc, PermissionError):
                    denied.append(failed_path)
                else:
                    errors.append((failed_path, _errno_name(exc)))
        if denied:
            ordered = tuple(sorted(denied))
            facts.append(RootFact(
                RootFactKind.SUBDIRS_UNLISTABLE, path, ordered, len(ordered),
                cause="EACCES", permission_denied=True,
            ))
        for cause, group in _grouped(errors):
            facts.append(RootFact(
                RootFactKind.SUBDIRS_UNLISTABLE, path, group, len(group), cause=cause,
            ))

        entries = tree_entries(tree)
        entry_errors = [(e.path, e.error or "") for e in entries if e.kind is EntryKind.ERROR]
        for cause, group in _grouped(entry_errors):
            facts.append(RootFact(
                RootFactKind.ENTRY_ERROR, path, group, len(group), cause=cause,
            ))

        # One physical file is counted once per outcome, under the first name
        # its walk met: two names for one file are never two omissions.
        outcomes = _one_per_file(self._final[e.path] for e in root.regular_files())
        linked_only = list({
            self.resolve(item.path): item
            for identity, dated in self._dated.items()
            if self._first_visitor(identity) is root
            for item in dated.linked_only
        }.values())
        linked_outcomes = _one_per_file(
            self._final[e.path] for e in linked_only if e.path in self._final
        )

        unreadable: list[tuple[Path, str]] = []
        retained: dict[tuple[str, str], list[Path]] = {}
        for outcome in outcomes:
            if outcome.cause is None:
                continue
            if outcome.kind is FileOutcomeKind.ADMITTED and outcome.family is not None:
                retained.setdefault((outcome.cause, outcome.family), []).append(outcome.path)
            else:
                unreadable.append((outcome.path, outcome.cause))
        for outcome in linked_outcomes:
            # A Zeek-only link exception never widens another family, so a file
            # reached only through it that could not be read is simply unread.
            if outcome.cause is not None:
                unreadable.append((self._respell_one(outcome.path, root), outcome.cause))
        for cause, group in _grouped(unreadable):
            facts.append(RootFact(
                RootFactKind.UNREADABLE_FILES, path, group, len(group), cause=cause,
            ))
        for (cause, family), group in retained.items():
            ordered = tuple(sorted(group))
            facts.append(RootFact(
                RootFactKind.UNREADABLE_FILES, path, ordered, len(ordered),
                cause=cause, family=family,
            ))

        followed = self._followed_spellings(root)
        linked = tuple(p for p in tree.linked if p not in followed)
        if linked:
            facts.append(RootFact(
                RootFactKind.LINKED_DIRECTORY_OMITTED, path, linked, len(linked),
            ))
        for kind, entry_kind in (
            (RootFactKind.BROKEN_LINK, EntryKind.BROKEN_LINK),
            (RootFactKind.NONREGULAR_MATCH, EntryKind.NONREGULAR),
        ):
            named = tuple(sorted(
                e.path for e in entries
                if e.kind is entry_kind and self._name_admitted(e.path)
            ))
            if named:
                facts.append(RootFact(kind, path, named, len(named)))

        unrecognized = tuple(sorted(
            o.path for o in outcomes if o.kind is FileOutcomeKind.UNRECOGNIZED
        ))
        if unrecognized:
            facts.append(RootFact(
                RootFactKind.UNRECOGNIZED_FILES, path, unrecognized, len(unrecognized),
            ))
        rejected: dict[str, list[Path]] = {}
        for outcome in outcomes:
            if outcome.kind is FileOutcomeKind.REJECTED and outcome.family is not None:
                rejected.setdefault(outcome.family, []).append(outcome.path)
        for family in _SOURCE_LOADERS:
            if family in rejected:
                ordered = tuple(sorted(rejected[family]))
                facts.append(RootFact(
                    RootFactKind.REJECTED_FILES, path, ordered, len(ordered),
                    family=family, patterns=self.permitted.get(family, ()),
                ))
        not_zeek = tuple(sorted(
            self._respell_one(o.path, root) for o in linked_outcomes
            if o.cause is None
            and o.kind not in (
                FileOutcomeKind.EMPTY, FileOutcomeKind.EXCLUDED, FileOutcomeKind.SUPPLIED,
            )
            and not (o.kind is FileOutcomeKind.ADMITTED and o.family == _ZEEK_SOURCE)
        ))
        if not_zeek:
            facts.append(RootFact(
                RootFactKind.LINKED_LAYOUT_NOT_READ, path, not_zeek, len(not_zeek),
                family=_ZEEK_SOURCE,
            ))

        if self.families(root.path) or any(
            outcome.kind is FileOutcomeKind.SUPPLIED for outcome in outcomes
        ):
            # The root supplies a family, or its content is already read
            # through another name or input: an overlap, never an empty root.
            return facts
        incomplete = not tree.complete or bool(entry_errors)
        if not outcomes:
            facts.append(RootFact(RootFactKind.NO_FILES, path, incomplete=incomplete))
            return facts
        counts: dict[FileOutcomeKind, int] = {}
        for outcome in outcomes:
            counts[outcome.kind] = counts.get(outcome.kind, 0) + 1
        parts = tuple(
            (kind, counts[kind]) for kind in _OUTCOME_ORDER if counts.get(kind)
        )
        facts.append(RootFact(
            RootFactKind.NOTHING_READ, path, count=len(outcomes), parts=parts,
            incomplete=incomplete,
        ))
        return facts

    def _respell_one(self, path: Path, root: RecursiveRoot) -> Path:
        """One path spelled under ``root``'s walk, when its directory was walked."""
        spelled = root.spellings.get(self.resolve(path.parent))
        return spelled / path.name if spelled is not None else path

    def _name_admitted(self, path: Path) -> bool:
        """Whether a permitted family's name rule would take this entry.

        A content-fallthrough gate reads the file, so it never judges an entry
        that cannot be opened: only name rules decide here.
        """
        for key, patterns in self.permitted.items():
            strategy = _SOURCE_LOADERS[key]
            if strategy.content_fallthrough or strategy.recursive_admit is None:
                continue
            if _ask(strategy, path, None, patterns) is Admission.ADMIT:
                return True
        return False


_OUTCOME_ORDER = (
    FileOutcomeKind.OUTSIDE,
    FileOutcomeKind.EMPTY,
    FileOutcomeKind.EXCLUDED,
    FileOutcomeKind.UNRECOGNIZED,
    FileOutcomeKind.REJECTED,
    FileOutcomeKind.UNREADABLE,
)


def _one_per_file(outcomes) -> list[FileOutcome]:
    """Outcomes with one entry per (physical file, outcome kind), first name kept."""
    seen: set[tuple[Path, FileOutcomeKind]] = set()
    out: list[FileOutcome] = []
    for outcome in outcomes:
        key = (outcome.resolved, outcome.kind)
        if key not in seen:
            seen.add(key)
            out.append(outcome)
    return out


def _owner_of(identity: Path, owned_by: Mapping[Path, Path]) -> Path | None:
    """The dated root owning ``identity``'s subtree, if any."""
    if identity in owned_by:
        return owned_by[identity]
    for parent in identity.parents:
        if parent in owned_by:
            return owned_by[parent]
    return None


def _respell(
    entries: Sequence[DirectoryEntry], directory: Path,
) -> tuple[DirectoryEntry, ...]:
    """Entries spelled under ``directory``, the caller's view of that listing."""
    return tuple(
        entry if entry.path.parent == directory
        else replace(entry, path=directory / entry.path.name)
        for entry in entries
    )


def _ordered(source: str, paths: Sequence[Path]) -> tuple[Path, ...]:
    """Admitted files in walk-independent order: rotation groups by parent."""
    if _SOURCE_LOADERS[source].window_select is not None:
        return tuple(sorted(
            paths, key=lambda p: (str(p.parent), _rotation_base_and_index(p.name)),
        ))
    return tuple(sorted(paths))


def _grouped(items: Sequence[tuple[Path, str]]) -> list[tuple[str, tuple[Path, ...]]]:
    """Paths grouped by cause, causes and paths each in sorted order."""
    groups: dict[str, list[Path]] = {}
    for path, cause in items:
        groups.setdefault(cause, []).append(path)
    return [(cause, tuple(sorted(groups[cause]))) for cause in sorted(groups)]
