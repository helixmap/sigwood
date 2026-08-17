"""UTC-partition eligibility projected onto display calendar days."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Iterable
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class SourcePartition:
    """One UTC source partition's availability and usable-row floor facts."""

    start: datetime
    end: datetime
    present: bool
    usable_ts_floor_met: bool

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None or self.end <= self.start:
            raise ValueError("source partition must be a positive aware interval")
        if self.start.utcoffset() != timedelta(0) or self.end.utcoffset() != timedelta(0):
            raise ValueError("source partitions must be UTC")

    @property
    def eligible(self) -> bool:
        return self.present and self.usable_ts_floor_met


@dataclass(frozen=True)
class DisplayDayEligibility:
    """Projected display-day eligibility with the contributing UTC partitions."""

    day: date
    eligible: bool
    partition_count: int
    failed_partitions: tuple[SourcePartition, ...]
    committed_usable_rows: int


def _display_interval(day: date, zone: ZoneInfo) -> tuple[datetime, datetime]:
    start = datetime.combine(day, datetime.min.time(), tzinfo=zone)
    return start, start + timedelta(days=1)


def eligible_display_day(
    day: date,
    *,
    zone: ZoneInfo,
    partitions: Iterable[SourcePartition],
    committed_usable_timestamps: Iterable[datetime],
) -> DisplayDayEligibility:
    """Project source partitions onto one display day.

    Every overlapping partition must meet its floor.  A committed usable
    timestamp must also land inside the display interval, so a present but
    empty display-day projection does not become eligible by directory shape.
    """
    start, end = _display_interval(day, zone)
    overlapping = tuple(
        partition
        for partition in partitions
        if partition.start < end and partition.end > start
    )
    timestamps = tuple(
        timestamp
        for timestamp in committed_usable_timestamps
        if timestamp.tzinfo is not None and start <= timestamp.astimezone(zone) < end
    )
    failed = tuple(partition for partition in overlapping if not partition.eligible)
    return DisplayDayEligibility(
        day=day,
        eligible=bool(overlapping) and not failed and bool(timestamps),
        partition_count=len(overlapping),
        failed_partitions=failed,
        committed_usable_rows=len(timestamps),
    )


def eligible_iso_weeks(days: Iterable[DisplayDayEligibility]) -> tuple[tuple[int, int], ...]:
    """Return ISO weeks with seven supplied display days and at least six eligible."""
    grouped: dict[tuple[int, int], list[DisplayDayEligibility]] = {}
    for result in days:
        iso = result.day.isocalendar()
        grouped.setdefault((iso.year, iso.week), []).append(result)
    return tuple(
        week
        for week, values in sorted(grouped.items())
        if len({value.day for value in values}) == 7 and sum(value.eligible for value in values) >= 6
    )
