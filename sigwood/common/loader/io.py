"""Low-level filesystem primitives for the loader package (leaf module).

Decompression-transparent file opening plus the path-normalization helpers
(``_safe_resolve`` / ``_union_dedupe``). These are the lowest leaf: every other
loader submodule may import from here, and this module imports nothing from the
package. ``_open_log`` is the SINGLE chokepoint every source flows through.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
from pathlib import Path
from typing import Iterable, Iterator

from sigwood.common.loader.limits import MAX_LOGICAL_RECORD_BYTES


class BoundedLogicalRecordReader(Iterator[str]):
    """Common decoded-record admission gate for ordinary and folded reads.

    Line-oriented sources get one logical record per line. A document parser
    may call :meth:`collect_document` after consuming its first fragment; that
    method bounds the complete multi-line logical document while draining an
    oversize value without retaining it.

    ``max_document_bytes`` is the DOCUMENT ceiling, declared only by a source
    family whose legitimate shape is one multi-megabyte logical document (a
    CloudTrail delivery is a single ``{"Records":[...]}`` line). While no
    non-blank record has been yielded, per-record admission uses the document
    ceiling so a one-line document reaches the strategy's sniff at all; after
    the first non-blank yield the ordinary per-line limit resumes, keeping the
    tight bound on NDJSON tails. ``collect_document`` bounds the assembled
    document at the same ceiling. Unset, both fall back to
    ``max_record_bytes`` and every family behaves identically to a reader
    without the parameter.
    """

    def __init__(
        self,
        source: Iterable[str],
        *,
        max_record_bytes: int = MAX_LOGICAL_RECORD_BYTES,
        max_document_bytes: int | None = None,
    ) -> None:
        self._source = iter(source)
        self.max_record_bytes = max_record_bytes
        self.max_document_bytes = max_document_bytes
        self._document_candidate = max_document_bytes is not None
        self.decoded_bytes = 0
        self.decoded_records = 0
        self.skipped_oversize = 0
        self.last_record_bytes = 0

    @staticmethod
    def _decoded_size(text: str) -> int:
        return len(text.encode("utf-8", errors="replace"))

    @staticmethod
    def _human_limit(n: int) -> str:
        mib = 1024 * 1024
        return f"{n // mib} MiB" if n >= mib and n % mib == 0 else f"{n} bytes"

    @property
    def limit_note(self) -> str:
        """Parenthetical naming the admission limits actually in force.

        The oversize disclosure must never assert a limit the skip did not
        use: a family with a document ceiling skips against two bounds, so its
        note names both.
        """
        line = self._human_limit(self.max_record_bytes)
        if self.max_document_bytes is None:
            return f"limit {line}"
        doc = self._human_limit(self.max_document_bytes)
        return f"limits {doc} per document, {line} per record"

    def __iter__(self) -> "BoundedLogicalRecordReader":
        return self

    def __next__(self) -> str:
        while True:
            text = next(self._source)
            size = self._decoded_size(text)
            self.decoded_bytes += size
            self.last_record_bytes = size
            limit = (
                self.max_document_bytes
                if self._document_candidate and self.max_document_bytes is not None
                else self.max_record_bytes
            )
            if size > limit:
                self.skipped_oversize += 1
                continue
            if self._document_candidate and text.strip():
                self._document_candidate = False
            self.decoded_records += 1
            return text

    def collect_document(self, first_fragment: str) -> str | None:
        """Collect the rest as one bounded document, draining on overflow."""
        document_limit = (
            self.max_document_bytes
            if self.max_document_bytes is not None
            else self.max_record_bytes
        )
        parts = [first_fragment]
        total = self._decoded_size(first_fragment)
        oversize = total > document_limit
        for text in self._source:
            size = self._decoded_size(text)
            self.decoded_bytes += size
            total += size
            if not oversize and total <= document_limit:
                parts.append(text)
            else:
                oversize = True
        self.last_record_bytes = total
        if oversize:
            # The first fragment was provisionally counted when yielded; the
            # complete logical document is rejected as one record.
            self.decoded_records = max(0, self.decoded_records - 1)
            self.skipped_oversize += 1
            return None
        return "".join(parts)


def _open_log(path: Path):
    """Open a plain, gzip-, bzip2-, or xz-compressed log file for reading.

    Suffix-gated (NOT magic-authoritative - the blob profiler is the magic-sniff
    context; the loader routes by suffix, keeping the two contexts distinct).
    `_open_log` is the SINGLE chokepoint every source flows through, so adding a
    new format here closes the gap across conn/dns/syslog/pihole/cloudtrail/sniff
    in one place.
    """
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.suffix == ".bz2":
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if path.suffix == ".xz":
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _safe_resolve(p: Path) -> Path:
    """``p.resolve()``, falling back to ``p`` on ``OSError``.

    The single realpath-normalization primitive the loader uses for dedupe,
    the rotation-windowing explicit-file partition, and rotation grouping -
    one consistent notion of "same path" across all three.
    """
    try:
        return p.resolve()
    except OSError:
        return p


def _union_dedupe(per_input_files: list[list[Path]]) -> list[Path]:
    """Concat per-input discovery results; dedupe by ``.resolve()`` preserving
    first-seen order.

    Single-ownership union point - the loader is the only place file lists
    from multiple source-dir inputs are concatenated under one family. Dedup
    by realpath catches:

    - the same file appearing in two inputs (positional pointing at a file
      that's ALSO inside a positional directory);
    - symlink farms (a non-date child of a Zeek dated dir that resolves to a
      date dir already in the list).

    First-seen order preservation keeps user-visible file ordering predictable
    (positionals before flag-supplied dirs, mirrors CLI bucket order).
    Returns the deduped list; downstream accounting (``data_size_bytes`` sums,
    warnings, ``load_*`` iteration) runs over this list so duplicates never
    double-count.
    """
    seen: set[Path] = set()
    out: list[Path] = []
    for files in per_input_files:
        for p in files:
            key = _safe_resolve(p)
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
    return out
