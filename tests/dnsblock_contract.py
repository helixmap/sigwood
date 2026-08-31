"""Executable dnsblock contracts shared across the suite.

Two contracts live here so tests can enforce them against real runner output:
the identity-free note grammar (every dnsblock summary note must full-match a
frozen template - no address, name, or path may reach a note), and the
survivor-grid union that acts as an independent reference implementation for
the detector's calibration-survivor membership masks.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Sequence

from sigwood import runner


NOTE_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"these logs cannot prove how complete each day is, so counts use the days that carry data; burst and recurring activity were not evaluated",
        r"dnsblock: first-activity reporting needs [0-9]+ earlier days of history and this window has [0-9]+; nothing is wrong, it will report once the archive is longer",
        r"dnsblock: [0-9]+ candidate (?:pair|pairs) not reported: not enough earlier history in this window to call them new",
        r"dnsblock: first-activity reporting needs [0-9]+ (?:covered days|days with data) and this window has [0-9]+",
        r"dnsblock: burst reporting needs [0-9]+ covered days and this window has [0-9]+",
        r"dnsblock: recurring reporting needs every day of the report fully covered; [0-9]+ of [0-9]+ were not",
        r"dnsblock: [0-9]+ first (?:appearance|appearances) not reported: [0-9]+ addresses reached the same group in one day, so the arrival is not distinctive to any one of them",
        r"dnsblock: your allowlist removed [0-9]+ blocked-query (?:row|rows) before analysis, and [0-9]+ from the earlier history",
        r"dnsblock: this window contains no Pi-hole query rows at all",
        r"dnsblock: Pi-hole logged no blocked names in this window, so there was nothing to analyse",
        r"dnsblock: every blocked-name row in this window was removed by your allowlist before analysis",
        r"dnsblock: blocked-name activity was examined and nothing met the reporting bar",
    )
)


def validate_summary_notes(payload: dict) -> None:
    """Reject any artifact note outside dnsblock's identity-free frozen grammar."""
    notes = payload.get("summary_notes")
    if not isinstance(notes, list):
        raise ValueError("dnsblock artifact summary_notes must be a list")
    cap_lines = {
        f"dnsblock: analysis stopped: {axis} exceeded its bound ({limit}); no findings emitted this run"
        for _token, axis, limit in runner._DNSBLOCK_CAP_NOTES
    }
    for line in notes:
        if not isinstance(line, str) or "\n" in line:
            raise ValueError("dnsblock artifact contains an unsafe summary note")
        if line in cap_lines:
            continue
        if not any(pattern.fullmatch(line) for pattern in NOTE_PATTERNS):
            raise ValueError("dnsblock artifact contains a non-template summary note")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class GridSurvivorAccumulator:
    """In-memory survivor union that releases only counts and set digests."""

    def __init__(self, cell_count: int) -> None:
        if isinstance(cell_count, bool) or not isinstance(cell_count, int) or cell_count <= 0:
            raise ValueError("survivor grid size must be a positive integer")
        self._cell_count = cell_count
        self._cells: list[set[str]] = [set() for _index in range(cell_count)]

    def ingest(self, memberships: Sequence[tuple[str, int]]) -> None:
        seen: set[str] = set()
        for identity, mask in memberships:
            if (
                not isinstance(identity, str)
                or "\0" not in identity
                or identity in seen
            ):
                raise ValueError("survivor membership identity is malformed or repeated")
            if (
                isinstance(mask, bool)
                or not isinstance(mask, int)
                or mask <= 0
                or mask >= (1 << self._cell_count)
            ):
                raise ValueError("survivor membership mask is outside the grid")
            seen.add(identity)
            remaining = mask
            while remaining:
                least_bit = remaining & -remaining
                index = least_bit.bit_length() - 1
                self._cells[index].add(identity)
                remaining ^= least_bit

    def aggregate(self) -> tuple[dict[str, int | str], ...]:
        rows = []
        for index, identities in enumerate(self._cells):
            encoded = json.dumps(
                tuple(sorted(identities)), separators=(",", ":")
            ).encode("utf-8")
            rows.append(
                {
                    "cell_index": index,
                    "qualifying_pairs": len(identities),
                    "identity_digest": _sha256_bytes(encoded),
                }
            )
        return tuple(rows)

    def clear(self) -> None:
        self._cells = [set() for _index in range(self._cell_count)]
