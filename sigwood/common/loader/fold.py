"""Content-stable snapshot and bounded transactional fold primitives.

The module is deliberately source-neutral. Pipeline adapters turn parsed input
into :class:`DecodedChunk` objects; this layer owns snapshot stability,
file-local commit/discard, independent sink containment, and hard admission
bounds. Ordinary frame-only loading never enters this module.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import math
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

import pandas as pd

from sigwood.common.loader.io import _safe_resolve, _union_dedupe
from sigwood.common.loader.types import (
    DecodedChunk,
    DualWindow,
    FoldDelta,
    MAX_CHUNK_DECODED_BYTES,
    MAX_CHUNK_ROWS,
    MAX_FILE_DELTA_BYTES,
    PositionalMask,
    PreparedState,
    PreparedStatus,
    SinkPlan,
    SnapshotFile,
    SourceFileQuality,
    SourceSnapshot,
)
from sigwood.common.sanitize import strip_control

_COMPRESSED_SUFFIXES = frozenset({".gz", ".bz2", ".xz"})


class SnapshotMutationError(RuntimeError):
    """A planned file no longer matches its content-stable snapshot."""


@dataclass
class FoldExecution:
    """Independent fold outcomes plus an optional transactionally kept frame."""

    frame: pd.DataFrame
    results: dict[str, Any] = field(default_factory=dict)
    statuses: dict[str, PreparedStatus] = field(default_factory=dict)
    file_errors: tuple[str, ...] = ()
    file_quality: dict[Path, SourceFileQuality] = field(default_factory=dict)
    file_spans: dict[Path, tuple[float, float]] = field(default_factory=dict)
    observed_valid_rows: int = 0
    observed_span: tuple[float, float] | None = None
    attempted_files: int = 0
    committed_files: int = 0


def _bounded_reason(exc: BaseException) -> str:
    first = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    return strip_control(first)[:240]


def _hash_prefix(path: Path, length: int) -> str:
    digest = hashlib.sha256()
    remaining = length
    with path.open("rb") as handle:
        while remaining:
            block = handle.read(min(1024 * 1024, remaining))
            if not block:
                raise SnapshotMutationError(f"{path.name}: truncated during snapshot")
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def _plain_readable_boundary(path: Path, size: int, source: str) -> int:
    """Capture the last complete line prefix without buffering file content."""
    if size == 0:
        return 0
    last_newline = -1
    offset = 0
    final_byte = b""
    remaining = size
    with path.open("rb") as handle:
        while remaining and (block := handle.read(min(1024 * 1024, remaining))):
            found = block.rfind(b"\n")
            if found >= 0:
                last_newline = offset + found
            final_byte = block[-1:]
            offset += len(block)
            remaining -= len(block)
    if final_byte == b"\n":
        return size
    if last_newline < 0:
        # Line-oriented live files have no proven complete record yet. A
        # CloudTrail file may be one complete JSON document without a newline;
        # its common-reader document gate remains the bounded validator.
        return size if source == "cloudtrail_dir" else 0
    return last_newline + 1


def build_source_snapshot(
    files: Iterable[Path],
    source: str,
    *,
    scan_interval: tuple[datetime | None, datetime | None] = (None, None),
) -> SourceSnapshot:
    """Build an ordered/deduped snapshot with byte-stable content identity."""
    planned: list[SnapshotFile] = []
    for path in _union_dedupe([[Path(p) for p in files]]):
        resolved = _safe_resolve(path)
        info = path.stat()
        compressed = path.suffix.lower() in _COMPRESSED_SUFFIXES
        readable = (
            info.st_size
            if compressed
            else _plain_readable_boundary(path, info.st_size, source)
        )
        planned.append(
            SnapshotFile(
                path=path,
                resolved_path=resolved,
                source=source,
                device=info.st_dev,
                inode=info.st_ino,
                compressed=compressed,
                stat_bytes=info.st_size,
                mtime_ns=info.st_mtime_ns,
                readable_bytes=readable,
                content_sha256=_hash_prefix(path, readable),
                scan_interval=scan_interval,
            )
        )
        verify_snapshot_file(planned[-1])
    identity_payload = [
        {
            "resolved": str(item.resolved_path),
            "source": item.source,
            "device": item.device,
            "inode": item.inode,
            "compressed": item.compressed,
            "stat_bytes": item.stat_bytes,
            "mtime_ns": item.mtime_ns,
            "readable_bytes": item.readable_bytes,
            "sha256": item.content_sha256,
            "scan": [
                value.isoformat() if value is not None else None
                for value in item.scan_interval
            ],
        }
        for item in planned
    ]
    identity = hashlib.sha256(
        json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return SourceSnapshot(source=source, files=tuple(planned), identity_sha256=identity)


def verify_snapshot_file(item: SnapshotFile) -> None:
    """Refuse replacement/truncation/content drift; permit plain-file append."""
    info = item.path.stat()
    if info.st_dev != item.device or info.st_ino != item.inode:
        raise SnapshotMutationError(f"{item.path.name}: file identity changed")
    if item.compressed:
        if info.st_size != item.stat_bytes or info.st_mtime_ns != item.mtime_ns:
            raise SnapshotMutationError(f"{item.path.name}: compressed member changed")
    elif info.st_size < item.readable_bytes:
        raise SnapshotMutationError(f"{item.path.name}: file truncated")
    if _hash_prefix(item.path, item.readable_bytes) != item.content_sha256:
        raise SnapshotMutationError(f"{item.path.name}: captured content changed")


def verify_source_snapshot(snapshot: SourceSnapshot) -> None:
    for item in snapshot.files:
        verify_snapshot_file(item)


class _BoundedRaw(io.RawIOBase):
    def __init__(self, raw: io.BufferedReader, length: int) -> None:
        self._raw = raw
        self._remaining = length

    def readable(self) -> bool:
        return True

    def readinto(self, target: bytearray) -> int:
        if self._remaining <= 0:
            return 0
        view = memoryview(target)[: self._remaining]
        count = self._raw.readinto(view)
        if not count:
            return 0
        self._remaining -= count
        return count

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


@contextmanager
def open_snapshot_text(item: SnapshotFile) -> Iterator[io.TextIOBase]:
    """Open exactly the planned bytes; compressed members remain whole/stable."""
    verify_snapshot_file(item)
    if item.compressed:
        opener = {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open}[item.path.suffix.lower()]
        with opener(item.path, "rt", encoding="utf-8", errors="replace") as handle:
            yield handle
        return
    raw = item.path.open("rb")
    bounded = _BoundedRaw(raw, item.readable_bytes)
    buffered = io.BufferedReader(bounded)
    text = io.TextIOWrapper(buffered, encoding="utf-8", errors="replace")
    try:
        yield text
    finally:
        text.close()


def chunks_from_rows(
    rows: Iterable[tuple[dict[str, Any], int]],
    *,
    columns: list[str] | None,
    window: DualWindow,
    keep_null: bool = False,
) -> Iterator[DecodedChunk]:
    """Bound canonical rows simultaneously by count and decoded input bytes."""
    buffered: list[dict[str, Any]] = []
    report: list[bool] = []
    context: list[bool] = []
    decoded = 0
    first_ordinal = 0
    next_ordinal = 0

    def emit() -> DecodedChunk:
        frame = pd.DataFrame(buffered, columns=columns).reset_index(drop=True)
        return DecodedChunk(
            frame=frame,
            decoded_bytes=decoded,
            report_mask=tuple(report),
            context_mask=tuple(context),
            first_ordinal=first_ordinal,
        )

    for row, row_bytes in rows:
        if row_bytes < 0 or row_bytes > MAX_CHUNK_DECODED_BYTES:
            raise ValueError("one decoded row cannot fit in a bounded chunk")
        if buffered and (
            len(buffered) >= MAX_CHUNK_ROWS
            or decoded + row_bytes > MAX_CHUNK_DECODED_BYTES
        ):
            yield emit()
            buffered = []
            report = []
            context = []
            decoded = 0
            first_ordinal = next_ordinal
        try:
            value = row["ts"]
            if keep_null and pd.isna(value):
                in_report, in_context = True, False
            else:
                in_report, in_context = window.membership(float(value))
        except (KeyError, TypeError, ValueError, OverflowError, OSError):
            in_report, in_context = False, False
        buffered.append(row)
        report.append(in_report)
        context.append(in_context)
        decoded += row_bytes
        next_ordinal += 1
    if buffered:
        yield emit()


def execute_sink_plan(
    snapshot: SourceSnapshot,
    plan: SinkPlan,
    chunk_source: Callable[[SnapshotFile], Iterable[DecodedChunk]],
) -> FoldExecution:
    """Execute independent sinks with clean-EOF, file-local transactions."""
    run_states = {sink.channel: sink.seed_run() for sink in plan.folds}
    statuses = {
        sink.channel: PreparedStatus(PreparedState.READY) for sink in plan.folds
    }
    frames: list[pd.DataFrame] = []
    errors: list[str] = []
    file_spans: dict[Path, tuple[float, float]] = {}
    observed_valid_rows = 0
    observed_min: float | None = None
    observed_max: float | None = None
    attempted_files = 0
    committed_files = 0

    for item in snapshot.files:
        attempted_files += 1
        file_frames: list[pd.DataFrame] = []
        file_valid_rows = 0
        file_observed_min: float | None = None
        file_observed_max: float | None = None
        file_deltas = {
            sink.channel: sink.seed_file()
            for sink in plan.folds
            if statuses[sink.channel].state is PreparedState.READY
        }
        try:
            verify_snapshot_file(item)
            for chunk in chunk_source(item):
                if "ts" in chunk.frame.columns:
                    for value in chunk.frame["ts"].tolist():
                        try:
                            numeric = float(value)
                        except (TypeError, ValueError, OverflowError):
                            continue
                        if not math.isfinite(numeric):
                            continue
                        file_valid_rows += 1
                        file_observed_min = (
                            numeric
                            if file_observed_min is None
                            else min(file_observed_min, numeric)
                        )
                        file_observed_max = (
                            numeric
                            if file_observed_max is None
                            else max(file_observed_max, numeric)
                        )
                if plan.preserve_frame:
                    report_positions = [
                        index for index, keep in enumerate(chunk.report_mask) if keep
                    ]
                    if report_positions:
                        file_frames.append(
                            chunk.frame.iloc[report_positions].reset_index(drop=True).copy()
                        )
                for sink in plan.folds:
                    if statuses[sink.channel].state is not PreparedState.READY:
                        continue
                    try:
                        mask = sink.mask(chunk.frame.reset_index(drop=True))
                        if len(mask.keep) != len(chunk.frame):
                            raise ValueError("positional mask length mismatch")
                        delta = sink.consume(file_deltas[sink.channel], chunk, mask)
                        if not isinstance(delta, FoldDelta):
                            raise TypeError("fold callback must return FoldDelta")
                        if delta.resident_bytes > MAX_FILE_DELTA_BYTES:
                            statuses[sink.channel] = PreparedStatus(
                                PreparedState.ABSTAINED,
                                "file delta exceeds 256 MiB",
                            )
                            run_states.pop(sink.channel, None)
                            file_deltas.pop(sink.channel, None)
                            continue
                        file_deltas[sink.channel] = delta
                    except Exception as exc:
                        statuses[sink.channel] = PreparedStatus(
                            PreparedState.FAILED,
                            f"reducer error - {_bounded_reason(exc)}",
                        )
                        run_states.pop(sink.channel, None)
                        file_deltas.pop(sink.channel, None)
            verify_snapshot_file(item)
        except SnapshotMutationError as exc:
            errors.append(f"{strip_control(item.path.name)}: {_bounded_reason(exc)}")
            for sink in plan.folds:
                if statuses[sink.channel].state is PreparedState.READY:
                    statuses[sink.channel] = PreparedStatus(
                        PreparedState.FAILED,
                        "snapshot mutation",
                    )
            run_states.clear()
            break
        except Exception as exc:
            errors.append(f"{strip_control(item.path.name)}: {_bounded_reason(exc)}")
            continue

        if plan.preserve_frame and file_frames:
            frames.extend(file_frames)
            finite_report: list[float] = []
            for frame in file_frames:
                if "ts" not in frame.columns:
                    continue
                for value in frame["ts"].tolist():
                    try:
                        numeric = float(value)
                    except (TypeError, ValueError, OverflowError):
                        continue
                    if math.isfinite(numeric):
                        finite_report.append(numeric)
            if finite_report:
                file_spans[item.path] = (min(finite_report), max(finite_report))
        observed_valid_rows += file_valid_rows
        committed_files += 1
        if file_observed_min is not None and file_observed_max is not None:
            observed_min = (
                file_observed_min
                if observed_min is None
                else min(observed_min, file_observed_min)
            )
            observed_max = (
                file_observed_max
                if observed_max is None
                else max(observed_max, file_observed_max)
            )
        for sink in plan.folds:
            if statuses[sink.channel].state is not PreparedState.READY:
                continue
            try:
                run_states[sink.channel] = sink.commit_file(
                    run_states[sink.channel], file_deltas[sink.channel]
                )
            except Exception as exc:
                statuses[sink.channel] = PreparedStatus(
                    PreparedState.FAILED,
                    f"commit error - {_bounded_reason(exc)}",
                )
                run_states.pop(sink.channel, None)

    frame = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    results = {
        channel: value
        for channel, value in run_states.items()
        if statuses[channel].state is PreparedState.READY
    }
    observed_span = (
        (observed_min, observed_max)
        if observed_min is not None and observed_max is not None
        else None
    )
    return FoldExecution(
        frame=frame,
        results=results,
        statuses=statuses,
        file_errors=tuple(errors),
        file_spans=file_spans,
        observed_valid_rows=observed_valid_rows,
        observed_span=observed_span,
        attempted_files=attempted_files,
        committed_files=committed_files,
    )
