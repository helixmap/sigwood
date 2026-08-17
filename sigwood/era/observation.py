"""Layered observation facts for era's archive calendar.

Availability, parse usability, and sensor-reported completeness are different
facts.  This module keeps them separate and deliberately refuses cross-peer
capture-loss arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterable


class Availability(str, Enum):
    ABSENT = "absent"
    PRESENT = "present"
    DENIED = "denied"


class ParseUsability(str, Enum):
    UNKNOWN = "unknown"
    USABLE = "usable"
    UNUSABLE = "unusable"


class Completeness(str, Enum):
    """Sensor completeness is never inferred from missing telemetry."""

    UNKNOWN = "completeness-unknown"
    THIN = "thin-telemetry"
    REPORTED = "sensor-reported"


@dataclass(frozen=True)
class CaptureLossInterval:
    """One sensor-reported loss interval for one stable peer or stream."""

    peer: str
    start: datetime
    end: datetime
    gaps: int
    acks: int

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None or self.end <= self.start:
            raise ValueError("capture-loss interval must be a positive aware interval")
        if self.gaps < 0 or self.acks < 0:
            raise ValueError("capture-loss counters cannot be negative")


@dataclass(frozen=True)
class PeerLossSummary:
    """Per-peer loss arithmetic; totals from different peers are intentionally absent."""

    peer: str
    interval_count: int
    interval_covered_seconds: float
    gaps: int
    acks: int
    weighted_loss_percent: float | None


@dataclass(frozen=True)
class FamilyDayObservation:
    """Independent day facts consumed by later era cards."""

    availability: Availability
    parse_usability: ParseUsability
    completeness: Completeness
    committed_usable_rows: int
    peer_loss: tuple[PeerLossSummary, ...] = ()

    def __post_init__(self) -> None:
        if self.committed_usable_rows < 0:
            raise ValueError("committed rows cannot be negative")
        if self.availability is Availability.ABSENT and self.parse_usability is ParseUsability.USABLE:
            raise ValueError("absent data cannot be usable")


def summarize_capture_loss(intervals: Iterable[CaptureLossInterval]) -> tuple[PeerLossSummary, ...]:
    """Summarize loss only within each peer/stream, never across peers."""
    grouped: dict[str, list[CaptureLossInterval]] = {}
    for interval in intervals:
        grouped.setdefault(interval.peer, []).append(interval)
    summaries: list[PeerLossSummary] = []
    for peer in sorted(grouped):
        values = grouped[peer]
        gaps = sum(value.gaps for value in values)
        acks = sum(value.acks for value in values)
        denominator = gaps + acks
        summaries.append(
            PeerLossSummary(
                peer=peer,
                interval_count=len(values),
                interval_covered_seconds=sum((value.end - value.start).total_seconds() for value in values),
                gaps=gaps,
                acks=acks,
                weighted_loss_percent=(100.0 * gaps / denominator) if denominator else None,
            )
        )
    return tuple(summaries)
