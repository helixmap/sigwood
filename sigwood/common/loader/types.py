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
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import pandas as pd

from sigwood.common.loader.limits import (
    MAX_CHUNK_DECODED_BYTES,
    MAX_CHUNK_ROWS,
    MAX_FILE_DELTA_BYTES,
    MAX_DECLARED_FILE_DELTA_BYTES,
    MAX_LOGICAL_DOCUMENT_BYTES,
    MAX_LOGICAL_RECORD_BYTES,
)


# Named log/compression suffixes stripped when deriving hostname from filename.
# All-numeric rotation suffixes (.1, .10, .42, etc.) are also stripped.
# Only log-related suffixes are removed so dotted hostnames (host1.example.com.log.gz) are preserved.
_LOG_SUFFIXES = frozenset({".gz", ".log"})

_PIHOLE_COLUMNS = [
    "ts", "src", "query", "event_type", "qtype",
    "host",
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
    runner's "read the full archive" note accurate - a fallback can never coexist
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
    """Per-pattern permission-denied read accounting for runner exit reporting."""

    discovered: int
    denied: int
    paths: tuple[Path, ...] = ()


@dataclass(frozen=True)
class DirectorySkipInfo:
    """One source directory whose immediate children could not be listed.

    This is plan/discovery metadata, distinct from ``PermissionSkipInfo``:
    no file candidates exist yet, so no file-level ``LoadResult`` accounting
    can represent the omission accurately.
    """

    source_key: str
    path: Path


class EntryKind(str, Enum):
    """What inspecting one directory entry established about it.

    A broken symbolic link and a successfully inspected non-regular entry (a
    FIFO, socket or device) are different facts, and an entry whose inspection
    itself failed is a third: it keeps the cause rather than being guessed into
    either of the others.
    """

    REGULAR = "regular"
    DIRECTORY = "directory"
    NONREGULAR = "nonregular"
    BROKEN_LINK = "broken_link"
    ERROR = "error"


@dataclass(frozen=True)
class DirectoryEntry:
    """One immediate child of a listed directory, classified once.

    ``kind`` follows symbolic links, so a link to a regular file is
    ``REGULAR`` and a link to a directory is ``DIRECTORY`` with
    ``is_symlink`` set. ``error`` carries the errno name when the entry's
    inspection failed (``ERROR``) or its link target could not be reached
    (``BROKEN_LINK``).
    """

    path: Path
    kind: EntryKind
    is_symlink: bool = False
    error: str | None = None


class DiscoveryFactKind(str, Enum):
    """Coverage facts the analyze inventory discloses beside the shipped owners.

    Directory listing denials are deliberately absent: they are
    ``DirectorySkipInfo`` records with their own renderer.
    """

    EMPTY_DIRECTORY = "empty_directory"
    UNSUPPORTED_FILES = "unsupported_files"
    UNSEARCHED_CHILDREN = "unsearched_children"
    MISSING_INPUT = "missing_input"
    LISTING_ERROR = "listing_error"
    ENTRY_ERROR = "entry_error"
    NONREGULAR_MATCH = "nonregular_match"
    BROKEN_LINK = "broken_link"
    LINKED_DIRECTORY_OMITTED = "linked_directory_omitted"
    ZEEK_DEEPER_THAN_LAYOUT = "zeek_deeper_than_layout"
    ZEEK_ROOT_FILES_EXCLUDED = "zeek_root_files_excluded"


@dataclass(frozen=True)
class DiscoveryFact:
    """One coverage fact about one input root: paths and counts, never content.

    ``paths`` holds the affected entries or child directories in deterministic
    order; ``count`` is the complete number even when a renderer abbreviates
    ``paths``. ``detail`` is a tool-derived token such as an errno name.
    ``also_selected`` and ``contains_selected`` qualify an unsearched-children
    fact: how many listed children are themselves inputs of this run, and how
    many contain one, without claiming either was searched.
    """

    kind: DiscoveryFactKind
    source_key: str
    root: Path
    paths: tuple[Path, ...] = ()
    count: int = 0
    detail: str | None = None
    also_selected: int = 0
    contains_selected: int = 0


class Admission(str, Enum):
    """A family gate's answer for one file met by a recursive walk.

    ``OUTSIDE`` says the file belongs to the family but to a log type this run
    does not read; ``REJECT`` says the family recognizes the content but its own
    name rule refuses the file.
    """

    ADMIT = "admit"
    OUTSIDE = "outside"
    REJECT = "reject"


class FileOutcomeKind(str, Enum):
    """What a recursive positional partition decided for one spelling of a file.

    ``SUPPLIED`` is a spelling whose content another spelling, an explicit file
    or a family declaration already supplies: it is read once, elsewhere, and is
    neither an omission nor an empty input.
    """

    ADMITTED = "admitted"
    SUPPLIED = "supplied"
    EMPTY = "empty"
    EXCLUDED = "excluded"
    UNREADABLE = "unreadable"
    OUTSIDE = "outside"
    REJECTED = "rejected"
    UNRECOGNIZED = "unrecognized"


@dataclass(frozen=True)
class FileOutcome:
    """One spelling's partition outcome: at most one family per file, and why.

    ``path`` is the entry as a walk spelled it and ``resolved`` the physical
    file's identity, so two spellings of one file keep their own names.
    ``family`` is the admitting family for ``ADMITTED``, the family reading the
    content for ``SUPPLIED`` (absent when an explicit file or a declaration
    supplies it), the rejecting family for ``REJECTED`` and the recognized
    family for ``OUTSIDE``. ``cause`` is the tool-derived token of a failed read
    (an errno or exception type name); a file that could not be read keeps it
    even when a family gate retained the file.
    """

    path: Path
    resolved: Path
    kind: FileOutcomeKind
    family: str | None = None
    cause: str | None = None


class RootFactKind(str, Enum):
    """Coverage facts owned by a recursive positional root, before any family.

    A partition walk can fail or omit content before a file has a family, so
    these facts belong to the root the operator supplied rather than to a
    family's ``DiscoveryFact`` or ``DirectorySkipInfo``.
    """

    ROOT_UNLISTABLE = "root_unlistable"
    SUBDIRS_UNLISTABLE = "subdirs_unlistable"
    ENTRY_ERROR = "entry_error"
    UNREADABLE_FILES = "unreadable_files"
    LINKED_DIRECTORY_OMITTED = "linked_directory_omitted"
    BROKEN_LINK = "broken_link"
    NONREGULAR_MATCH = "nonregular_match"
    UNRECOGNIZED_FILES = "unrecognized_files"
    REJECTED_FILES = "rejected_files"
    LINKED_LAYOUT_NOT_READ = "linked_layout_not_read"
    NO_FILES = "no_files"
    NOTHING_READ = "nothing_read"


@dataclass(frozen=True)
class RootFact:
    """One family-neutral coverage fact about one recursive positional root.

    ``paths`` and ``count`` follow ``DiscoveryFact``: deterministic order and a
    complete count. ``cause`` is a read or listing failure token, with
    ``permission_denied`` marking a denial. ``family`` names the family a
    ``REJECTED_FILES`` fact concerns, the family whose conservative gate kept an
    unreadable file, or the family whose directory layout followed the links a
    ``LINKED_LAYOUT_NOT_READ`` fact names. ``parts`` holds the observed outcome counts a
    ``NOTHING_READ`` fact reports, and ``incomplete`` says part of the tree could
    not be searched.
    """

    kind: RootFactKind
    root: Path
    paths: tuple[Path, ...] = ()
    count: int = 0
    cause: str | None = None
    permission_denied: bool = False
    family: str | None = None
    patterns: tuple[str, ...] = ()
    parts: tuple[tuple[FileOutcomeKind, int], ...] = ()
    incomplete: bool = False


@dataclass(frozen=True)
class CandidatePopulation:
    """One pattern's discovered population, published after source arbitration.

    ``source`` must equal the plan's source for the pattern, and ``inputs``
    must name exactly the run's inputs for that source; the loader refuses a
    mismatch rather than load a population built for another provider. Each
    input carries the observation its family's selection reads, so the loader
    skips enumeration only: windowed selection, rotation selection, parsing
    and accounting still run.
    """

    source: str
    inputs: tuple[tuple[Path, Any], ...]


class WindowPolicyReason(str, Enum):
    """Why one planned source family has the time policy it has.

    The window resolver records one reason per planned family, in its own check
    order, so a caller can report the resolver's decision instead of deriving it
    again.
    """

    EXPLICIT = "explicit"  # an explicit --since or --until bounds every family
    ALL = "all"  # --all reads every family in full
    DEFAULT_DISABLED = "default_disabled"  # default_window is empty or "all"
    PRE_RESOLVED = "pre_resolved"  # a producer supplied the family's window
    NOT_CONFIGURED = "not_configured"  # the family has no inputs this run
    NAMED_FILES = "named_files"  # every input is a file, so it is read in full
    EXEMPT = "exempt"  # the family declares no default window
    RESOLVED = "resolved"  # a default LoadWindow was built


@dataclass(frozen=True)
class PatternPreview:
    """One pattern's discovered and selected files, chosen without reading content.

    ``discovered`` is every candidate before time selection. ``selected`` is what
    the run's windows select, from the same selector the load uses, so the two
    cannot disagree about which files a run reads. ``rotation_skip`` is that
    selection's rotation result, and ``warnings`` the selection warnings the
    load would print.
    """

    source: str
    discovered: tuple[Path, ...]
    selected: tuple[Path, ...]
    rotation_skip: RotationSkipInfo | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class PopulationEstimate:
    """Bounded pre-read count and the independent proven plain-file size bound."""

    records: int
    records_basis: str
    uncounted_files: int
    upper_bound_bytes: int | None
    on_disk_bytes: int
    selected_files: int


@dataclass(frozen=True)
class FileSpan:
    """Finite report timestamp extrema before optional candidate selection."""

    path: Path
    first_ts: float
    last_ts: float


class PreparedState(str, Enum):
    """Runner-visible state for one independent sink channel."""

    READY = "READY"
    ABSTAINED = "ABSTAINED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class PreparedStatus:
    """Bounded status for one sink; partial reducer state never rides here."""

    state: PreparedState
    cause: str = ""


class FoldAbstention(RuntimeError):
    """A reducer-owned hard admission refusal with no partial result."""


class AvailabilityState(str, Enum):
    """Trust state for one selected data object's export availability."""

    TRUSTED = "TRUSTED"
    UNKNOWN = "UNKNOWN"


class AvailabilityReason(str, Enum):
    """Bounded downgrade vocabulary for provenance validation."""

    TRUSTED = "trusted"
    MANIFEST_MISSING = "manifest_missing"
    MANIFEST_MALFORMED = "manifest_malformed"
    MANIFEST_UNREADABLE = "manifest_unreadable"
    ENTRY_MISSING = "entry_missing"
    INCOMPLETE = "incomplete"
    BINDING_MISMATCH = "binding_mismatch"
    UNREADABLE = "unreadable"
    RESOURCE_LIMIT = "resource_limit"


@dataclass(frozen=True)
class ExportAvailability:
    """Content-bound availability fact for one selected data object."""

    path: Path
    state: AvailabilityState
    reason: AvailabilityReason
    interval: tuple[datetime, datetime] | None = None
    manifest_generation: int | None = None
    backend: str | None = None
    request_zone: str | None = None
    tzdata_version: str | None = None


class CoverageLane(str, Enum):
    """Runner coverage lane selected from typed availability facts."""

    STRONG = "strong"
    WEAK = "weak"


class CoverageDecisionReason(str, Enum):
    """Why the runner selected a coverage lane."""

    COMPLETE = "complete"
    INTERVAL_UNBOUNDED = "interval_unbounded"
    NO_OBJECTS = "no_objects"
    OBJECT_UNKNOWN = "object_unknown"
    INTERVAL_GAP = "interval_gap"


@dataclass(frozen=True)
class CoverageDecision:
    """Conservative runner decision over one pattern's selected objects."""

    lane: CoverageLane
    reason: CoverageDecisionReason
    report_interval: tuple[datetime, datetime] | None
    trusted_intervals: tuple[tuple[datetime, datetime], ...] = ()


@dataclass(frozen=True)
class SourceFileQuality:
    """Aggregate-only quality facts for one planned file."""

    decoded_records: int = 0
    decoded_bytes: int = 0
    skipped_oversize: int = 0


@dataclass(frozen=True)
class SnapshotFile:
    """One immutable file entry in a content-stable multi-pass snapshot."""

    path: Path
    resolved_path: Path
    source: str
    device: int
    inode: int
    compressed: bool
    stat_bytes: int
    mtime_ns: int
    readable_bytes: int
    content_sha256: str
    scan_interval: tuple[datetime | None, datetime | None] = (None, None)
    quality: SourceFileQuality = SourceFileQuality()


@dataclass(frozen=True)
class SourceSnapshot:
    """Ordered, deduped, content-bound input plan for fold/multi-pass work."""

    source: str
    files: tuple[SnapshotFile, ...]
    identity_sha256: str
    content_identity_sha256: str
    selection: RotationSkipInfo | None = None


@dataclass(frozen=True)
class DualWindow:
    """Runner-owned report interval plus strictly earlier optional context."""

    report_interval: tuple[datetime, datetime]
    context_interval: tuple[datetime, datetime] | None = None

    def __post_init__(self) -> None:
        report_start, report_end = self.report_interval
        if report_start > report_end:
            raise ValueError("report interval start must not follow its end")
        if self.context_interval is None:
            return
        context_start, context_end = self.context_interval
        if context_start > context_end:
            raise ValueError("context interval start must not follow its end")
        if context_end >= report_start:
            raise ValueError("context interval must end strictly before report start")

    def membership(self, ts: float) -> tuple[bool, bool]:
        """Return inclusive report/context membership for one finite epoch."""
        instant = datetime.fromtimestamp(ts, tz=timezone.utc)
        report_start, report_end = self.report_interval
        in_report = report_start <= instant <= report_end
        in_context = False
        if self.context_interval is not None:
            context_start, context_end = self.context_interval
            in_context = context_start <= instant <= context_end
        return in_report, in_context


@dataclass(frozen=True)
class PositionalMask:
    """A duplicate-index-safe keep vector aligned to chunk row positions."""

    keep: tuple[bool, ...]


@dataclass(frozen=True)
class DecodedChunk:
    """One canonical chunk bounded by row count and decoded input bytes."""

    frame: pd.DataFrame
    decoded_bytes: int
    report_mask: tuple[bool, ...]
    context_mask: tuple[bool, ...]
    first_ordinal: int
    file_key: str = ""

    def __post_init__(self) -> None:
        rows = len(self.frame)
        if rows > MAX_CHUNK_ROWS:
            raise ValueError("decoded chunk exceeds the row limit")
        if self.decoded_bytes > MAX_CHUNK_DECODED_BYTES:
            raise ValueError("decoded chunk exceeds the byte limit")
        if self.decoded_bytes < 0:
            raise ValueError("decoded chunk bytes must be non-negative")
        if len(self.report_mask) != rows or len(self.context_mask) != rows:
            raise ValueError("chunk membership masks must align by position")


@dataclass(frozen=True)
class FoldDelta:
    """Pure file-local reducer value with an explicit resident-byte measure."""

    value: Any
    resident_bytes: int

    def __post_init__(self) -> None:
        if self.resident_bytes < 0:
            raise ValueError("fold delta bytes must be non-negative")


@dataclass(frozen=True)
class FoldSink:
    """Neutral pure-reducer callbacks for one independent folded channel."""

    channel: str
    seed_file: Callable[[], FoldDelta]
    consume: Callable[[FoldDelta, DecodedChunk, PositionalMask], FoldDelta]
    seed_run: Callable[[], Any]
    commit_file: Callable[[Any, FoldDelta], Any]
    mask: Callable[[pd.DataFrame], PositionalMask]
    abort_file: Callable[[Any], Any] | None = None
    max_file_delta_bytes: int | None = None

    def __post_init__(self) -> None:
        limit = self.max_file_delta_bytes
        if limit is not None and (
            type(limit) is not int or not 0 < limit <= MAX_DECLARED_FILE_DELTA_BYTES
        ):
            raise ValueError("declared file delta limit must be a positive integer at most 2 GiB")


@dataclass(frozen=True)
class AdmitSink:
    """Ordered report-row selection with a declared empty-result schema."""

    channel: str
    admit: Callable[[DecodedChunk], pd.DataFrame]
    columns: tuple[str, ...]

    def __post_init__(self) -> None:
        if len(self.columns) != len(set(self.columns)):
            raise ValueError("admission columns must be unique")


@dataclass(frozen=True)
class PopulationFacts:
    """Committed report population before candidate selection."""

    rows: int
    window: tuple[datetime, datetime] | None


@dataclass(frozen=True)
class SinkPlan:
    """Independent folded channels and optional report-frame admission."""

    folds: tuple[FoldSink, ...] = ()
    preserve_frame: bool = True
    admit: AdmitSink | None = None

    def __post_init__(self) -> None:
        channels = [sink.channel for sink in self.folds]
        if self.admit is not None:
            channels.append(self.admit.channel)
        if len(channels) != len(set(channels)):
            raise ValueError("sink channels must be unique")

    @property
    def requires_snapshot(self) -> bool:
        return bool(self.folds) or self.admit is not None


@dataclass
class LoadQuality:
    """Structured aggregate quality for a pattern load."""

    attempted_files: int = 0
    committed_files: int = 0
    decoded_records: int = 0
    decoded_bytes: int = 0
    skipped_oversize: int = 0


@dataclass(frozen=True)
class PatternContribution:
    """Selected source bytes and ordered warnings owned by one pattern."""

    data_size_bytes: int
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class FileOutcomes:
    """Explicit snapshot file transactions, keyed by resolved file identity."""

    committed: frozenset[str] = frozenset()
    aborted: frozenset[str] = frozenset()


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
    file_spans: dict[str, tuple[FileSpan, ...]] = field(default_factory=dict)
    quality: dict[str, LoadQuality] = field(default_factory=dict)
    snapshots: dict[str, SourceSnapshot] = field(default_factory=dict)
    fold_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    prepared_status: dict[str, PreparedStatus] = field(default_factory=dict)
    availability: dict[str, tuple[ExportAvailability, ...]] = field(
        default_factory=dict,
    )
    population: dict[str, PopulationFacts] = field(default_factory=dict)
    contributions: dict[str, PatternContribution] = field(default_factory=dict)
    file_outcomes: dict[str, FileOutcomes] = field(default_factory=dict)


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


def _population_metadata(
    logs: dict[str, pd.DataFrame],
    population: dict[str, PopulationFacts],
) -> tuple[dict[str, int], tuple[datetime, datetime] | None]:
    """Combine retained ordinary frames with pre-selection population facts."""
    ordinary = {p: df for p, df in logs.items() if p not in population}
    counts = {p: len(df) for p, df in ordinary.items() if not df.empty}
    counts.update({p: facts.rows for p, facts in population.items() if facts.rows})
    windows = [facts.window for facts in population.values() if facts.window is not None]
    ordinary_window = _data_window(ordinary)
    if ordinary_window is not None:
        windows.append(ordinary_window)
    window = (
        (min(w[0] for w in windows), max(w[1] for w in windows))
        if windows else None
    )
    return counts, window
