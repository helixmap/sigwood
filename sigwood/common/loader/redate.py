"""Shared RFC 3164 re-dating policy for selection and load diagnostics.

This bottom leaf deliberately imports no loader sibling.  Rotation selection
and the row pipeline consume the same strict comparator so their boundary
cannot drift.
"""

from __future__ import annotations


_REDATE_MARGIN_SECONDS = 172_800


def is_redate_suspect(observed: float, mtime: float) -> bool:
    """Return whether ``observed`` is strictly beyond the re-date margin."""
    return (observed - mtime) > _REDATE_MARGIN_SECONDS


def redate_days(observed: float, mtime: float) -> int:
    """Return the non-overstating whole-day gap (floor, never round)."""
    return int((observed - mtime) // 86_400)
