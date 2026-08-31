"""Deterministic archive planning for era.

The planner owns archive dates, inventory and work estimates.  It delegates
file discovery to the registered loader seam, so its inventory cannot quietly
drift from the files the product loader would read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable

from sigwood.common.loader import discover_for_source_key


_DATE_DIRECTORY = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2})$")
UTC = timezone.utc

# These are loader-family patterns, not an era-local glob vocabulary.  Their
# resolution is always delegated to ``discover_for_source_key`` below.
ERA_FAMILIES: tuple[tuple[str, str], ...] = (
    ("conn", "conn*.log*"),
    ("dns", "dns*.log*"),
    ("stats", "stats*.log*"),
    ("capture_loss", "capture_loss*.log*"),
)


class InventoryState(str, Enum):
    """A family inventory result; empty is never silently treated as absent."""

    PRESENT = "present"
    EMPTY = "empty"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ArchiveDateGroup:
    """One canonical UTC source partition and all directories that supply it."""

    canonical_date: date
    directories: tuple[Path, ...]

    @property
    def interval(self) -> tuple[datetime, datetime]:
        start = datetime.combine(self.canonical_date, datetime.min.time(), tzinfo=UTC)
        return start, start + timedelta(days=1)


@dataclass(frozen=True)
class FamilyInventory:
    """Loader-discovered files and their compressed on-disk work estimate."""

    family: str
    files: tuple[Path, ...]
    compressed_bytes: int
    state: InventoryState
    issue: str | None = None
    successful_stat_files: int = 0


@dataclass(frozen=True)
class WorkEstimate:
    """Typed estimate handed to the runner-owned confirmation seam later."""

    compressed_bytes: int
    files: int

    @property
    def human_bytes(self) -> str:
        value = float(self.compressed_bytes)
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if value < 1024 or unit == "TiB":
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1024
        raise AssertionError("unreachable")


@dataclass(frozen=True)
class BaselineReconciliation:
    """Comparison with a caller-supplied baseline calendar.

    The planner never refreshes or invents a baseline. With no baseline
    supplied, every comparison field is empty: an archive planned as found has
    nothing to be missing from.
    """

    expected_dates: frozenset[date]
    present_dates: frozenset[date]
    missing_dates: tuple[date, ...]
    post_baseline_dates: tuple[date, ...]


@dataclass(frozen=True)
class ArchivePlan:
    """Immutable planner result, ordered only by canonical source date."""

    groups: tuple[ArchiveDateGroup, ...]
    inventory: tuple[tuple[date, tuple[FamilyInventory, ...]], ...]
    work_estimate: WorkEstimate
    reconciliation: BaselineReconciliation

    @property
    def span(self) -> tuple[datetime, datetime] | None:
        if not self.groups:
            return None
        return self.groups[0].interval[0], self.groups[-1].interval[1]

    @property
    def families(self) -> tuple[str, ...]:
        return tuple(name for name, _ in ERA_FAMILIES)


def canonical_date_group(directory: Path) -> date | None:
    """Return the canonical date for one exactly date-named archive directory.

    Only an exact ``YYYY-MM-DD`` name is a date group; suffixed names do not
    become dates by prefix accident.
    """
    match = _DATE_DIRECTORY.fullmatch(directory.name)
    if match is None:
        return None
    try:
        return date.fromisoformat(match.group("date"))
    except ValueError:
        return None


class ArchivePlanner:
    """Build an era archive plan from a root containing dated source directories."""

    def __init__(self, root: Path, *, baseline_dates: Iterable[date] = ()):
        self.root = Path(root)
        self.baseline_dates = frozenset(baseline_dates)

    def _groups(self) -> tuple[ArchiveDateGroup, ...]:
        candidates: dict[date, list[Path]] = {}
        try:
            children = sorted(self.root.iterdir(), key=lambda child: child.name)
        except PermissionError:
            return ()
        except FileNotFoundError:
            return ()
        for child in children:
            try:
                if not child.is_dir():
                    continue
            except OSError:
                continue
            canonical = canonical_date_group(child)
            if canonical is None:
                continue
            candidates.setdefault(canonical, []).append(child)
        return tuple(
            ArchiveDateGroup(
                canonical_date=canonical,
                directories=tuple(entries),
            )
            for canonical, entries in sorted(candidates.items())
        )

    @staticmethod
    def _inventory_group(group: ArchiveDateGroup) -> tuple[FamilyInventory, ...]:
        inventories: list[FamilyInventory] = []
        for family, pattern in ERA_FAMILIES:
            files: list[Path] = []
            issue: str | None = None
            for directory in group.directories:
                directory_skips: dict = {}
                try:
                    files.extend(
                        discover_for_source_key(
                            "zeek_dir",
                            directory,
                            pattern,
                            _directory_skips=directory_skips,
                        )
                    )
                    if directory_skips:
                        issue = "directory denied"
                except PermissionError:
                    issue = "directory denied"
                except OSError as exc:
                    issue = f"inventory error: {type(exc).__name__}"
            unique = tuple(sorted(set(files), key=lambda path: str(path)))
            size = 0
            successful_stat_files = 0
            for path in unique:
                try:
                    size += path.stat().st_size
                    successful_stat_files += 1
                except OSError:
                    issue = "file stat unavailable"
            if issue == "directory denied":
                state = InventoryState.DENIED
            elif issue is not None:
                state = InventoryState.UNAVAILABLE
            elif unique:
                state = InventoryState.PRESENT
            else:
                state = InventoryState.EMPTY
            inventories.append(
                FamilyInventory(
                    family, unique, size, state, issue, successful_stat_files
                )
            )
        return tuple(inventories)

    def plan(self) -> ArchivePlan:
        """Inventory dates and loader-owned files without loading a row or gzip member."""
        groups = self._groups()
        inventory = tuple((group.canonical_date, self._inventory_group(group)) for group in groups)
        files = sum(len(family.files) for _, families in inventory for family in families)
        compressed_bytes = sum(
            family.compressed_bytes for _, families in inventory for family in families
        )
        present = frozenset(group.canonical_date for group in groups)
        reconciled = BaselineReconciliation(
            expected_dates=self.baseline_dates,
            present_dates=present,
            missing_dates=tuple(sorted(self.baseline_dates - present)),
            post_baseline_dates=(
                tuple(sorted(present - self.baseline_dates)) if self.baseline_dates else ()
            ),
        )
        return ArchivePlan(groups, inventory, WorkEstimate(compressed_bytes, files), reconciled)
