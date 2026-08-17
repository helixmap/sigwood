"""Honest D34 memory-measurement receipts for the U3 reducer route.

The measurement runner is deliberately separate from card rendering.  A route
that is not available records ``NOT_MEASURED`` with its precise precondition;
it never supplies an inferred cap ratification.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass
from enum import Enum


D34_RSS_LIMIT_BYTES = 4 * 1024**3


class D34Outcome(str, Enum):
    PASS = "PASS"
    COMPLETED_RSS_OVER_LIMIT = "COMPLETED_RSS_OVER_LIMIT"
    NOT_MEASURED = "NOT_MEASURED"


_MISSING_PRECONDITIONS = frozenset({
    "corpus-unreachable",
    "route-unavailable",
    "measurement-harness-failed",
})


def normalized_maxrss_bytes(raw_maxrss: int, *, system: str | None = None) -> int:
    """Normalize ``getrusage``'s Darwin-byte and Linux-KiB conventions."""
    if raw_maxrss < 0:
        raise ValueError("ru_maxrss cannot be negative")
    return raw_maxrss if (system or platform.system()) == "Darwin" else raw_maxrss * 1024


@dataclass(frozen=True)
class D34Receipt:
    """Aggregate/provenance-only D34 result; no source path or raw row survives."""

    outcome: D34Outcome
    route_identity: str
    archive_content_identity: str
    candidate_cap: int
    platform: str
    raw_maxrss: int | None
    normalized_maxrss_bytes: int | None
    rss_limit_bytes: int
    elapsed_seconds: float | None
    missing_precondition: str | None = None
    code_identity: str = "unavailable"

    def __post_init__(self) -> None:
        if self.outcome is D34Outcome.NOT_MEASURED:
            if self.missing_precondition not in _MISSING_PRECONDITIONS:
                raise ValueError("NOT_MEASURED requires a named missing precondition")
            if self.raw_maxrss is not None or self.normalized_maxrss_bytes is not None:
                raise ValueError("NOT_MEASURED cannot carry a measured RSS value")
        elif self.missing_precondition is not None:
            raise ValueError("measured D34 receipts cannot carry a missing precondition")


def not_measured_d34(
    *,
    route_identity: str,
    archive_content_identity: str,
    candidate_cap: int,
    missing_precondition: str,
    code_identity: str = "unavailable",
) -> D34Receipt:
    """Create an explicit non-ratification receipt for an unavailable route."""
    return D34Receipt(
        outcome=D34Outcome.NOT_MEASURED,
        route_identity=route_identity,
        archive_content_identity=archive_content_identity,
        candidate_cap=candidate_cap,
        platform=platform.platform(),
        raw_maxrss=None,
        normalized_maxrss_bytes=None,
        rss_limit_bytes=D34_RSS_LIMIT_BYTES,
        elapsed_seconds=None,
        missing_precondition=missing_precondition,
        code_identity=code_identity,
    )
