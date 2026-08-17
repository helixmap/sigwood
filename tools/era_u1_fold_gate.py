#!/usr/bin/env python3
"""Run era U1's bounded-fold calibration gate over Zeek connection input.

This is a U1 gate instrument, deliberately outside ``sigwood.era``.  The
eventual package and report model belong to U2; this tool measures whether the
already-landed neutral fold foundation carries a deliberately heavy, fixed-width
per-record state without retaining a frame.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import sigwood.common.loader as loader


UTC = timezone.utc
CHANNEL = "era_u1_calibration"
# Three unsigned 64-bit slots per observed row: an intentionally per-record,
# fixed-width ledger.  Real era reducers aggregate into periods or capped entity
# sets; retaining every observed row is the plausible cardinality-dominant shape.
SLOTS_PER_RECORD = 3
SLOT_BYTES = 8
BYTES_PER_RECORD = SLOTS_PER_RECORD * SLOT_BYTES
MAX_CALIBRATION_RECORDS = loader.MAX_FILE_DELTA_BYTES // BYTES_PER_RECORD
D34_RSS_BYTES = 4 * 1024**3


@dataclass(frozen=True)
class CalibrationResult:
    records: int
    resident_bytes: int
    report_window_records: int


@dataclass(frozen=True)
class CalibrationState:
    """Immutable per-file slots, segmented so each chunk keeps prior bytes intact."""

    parts: tuple[bytes, ...] = ()
    records: int = 0
    report_window_records: int = 0


def _can_admit(existing_records: int, incoming_records: int) -> bool:
    """Return whether the per-file state can admit rows without allocating them."""
    if existing_records < 0 or incoming_records < 0:
        raise ValueError("calibration record counts must be non-negative")
    return existing_records + incoming_records <= MAX_CALIBRATION_RECORDS


def _payload_for(chunk: loader.DecodedChunk, record_count: int) -> bytes:
    """Create fixed-width, non-identifying calibration slots for one chunk."""
    size = record_count * BYTES_PER_RECORD
    seed = f"{chunk.first_ordinal}:{record_count}".encode("ascii")
    return hashlib.shake_256(seed).digest(size)


def _consume(
    delta: loader.FoldDelta, chunk: loader.DecodedChunk, mask: loader.PositionalMask
) -> loader.FoldDelta:
    if not isinstance(delta.value, CalibrationState):
        raise TypeError("era calibration state must be CalibrationState")
    existing_records = delta.value.records
    incoming_records = sum(mask.keep)
    if not _can_admit(existing_records, incoming_records):
        raise loader.FoldAbstention("era calibration state exceeds 256 MiB file cap")
    payload = _payload_for(chunk, incoming_records)
    # ``bytes + bytes`` constructed a progressively larger replacement buffer
    # for every chunk.  On the spike corpus, released historical buffers stayed
    # resident and dominated RSS.  Tuple concatenation copies only references;
    # each fixed-width slot buffer is allocated once and every prior buffer is
    # retained unchanged, preserving the callback's pure FoldDelta contract.
    value = CalibrationState(
        parts=delta.value.parts + (payload,),
        records=existing_records + incoming_records,
        report_window_records=(
            delta.value.report_window_records + sum(chunk.report_mask)
        ),
    )
    return loader.FoldDelta(value, delta.resident_bytes + len(payload))


def _mask(frame: Any) -> loader.PositionalMask:
    return loader.PositionalMask(tuple(True for _ in range(len(frame))))


def calibration_sink() -> loader.FoldSink:
    """Build the pure, frame-free U1 calibration sink."""
    return loader.FoldSink(
        channel=CHANNEL,
        seed_file=lambda: loader.FoldDelta(CalibrationState(), 0),
        consume=_consume,
        seed_run=lambda: CalibrationResult(0, 0, 0),
        commit_file=lambda run, delta: CalibrationResult(
            run.records + delta.value.records,
            run.resident_bytes + delta.resident_bytes,
            run.report_window_records + delta.value.report_window_records,
        ),
        mask=_mask,
    )


def _rss_bytes() -> int:
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return raw if sys.platform == "darwin" else raw * 1024


def _window_for_day(day: str) -> tuple[datetime, datetime]:
    start = datetime.fromisoformat(day).replace(tzinfo=UTC)
    return start, start + timedelta(days=1) - timedelta(microseconds=1)


def run_gate(corpus: Path, *, day: str) -> dict[str, Any]:
    """Run one content-bound folded calibration over an explicit conn file."""
    start, end = _window_for_day(day)
    pattern = "conn*.log*"
    started = time.monotonic()
    loaded = loader.load_required_logs(
        {pattern: "zeek_dir"},
        {"zeek_dir": [corpus]},
        since=start,
        until=end,
        show_progress=False,
        sink_plans={pattern: loader.SinkPlan((calibration_sink(),), preserve_frame=False)},
        dual_windows={pattern: loader.DualWindow((start, end))},
    )
    status = loaded.prepared_status[CHANNEL]
    result = loaded.fold_results.get(pattern, {}).get(CHANNEL)
    completed = status.state is loader.PreparedState.READY and isinstance(
        result, CalibrationResult
    )
    peak_rss = _rss_bytes()
    if completed and peak_rss <= D34_RSS_BYTES:
        gate_b = "PASS"
    elif completed:
        gate_b = "COMPLETED_RSS_OVER_LIMIT"
    elif status.state is loader.PreparedState.ABSTAINED:
        gate_b = "NOT_REACHED_CAP_ABSTAINED"
    else:
        gate_b = "NOT_REACHED_OR_FAILED"
    quality = loaded.quality[pattern]
    return {
        "schema_version": 1,
        "gate": "era_u1_gate_b",
        "gate_b_determination": gate_b,
        "completed": completed,
        "status": {"state": status.state.value, "cause": status.cause},
        "d34_rss_limit_bytes": D34_RSS_BYTES,
        "peak_rss_bytes": peak_rss,
        "elapsed_seconds": time.monotonic() - started,
        "input": {"path": str(corpus), "compressed_bytes": corpus.stat().st_size},
        "fold": (
            {
                "records": result.records,
                "report_window_records": result.report_window_records,
                "resident_bytes": result.resident_bytes,
            }
            if isinstance(result, CalibrationResult)
            else None
        ),
        "loader_quality": {
            "attempted_files": quality.attempted_files,
            "committed_files": quality.committed_files,
            "decoded_records": quality.decoded_records,
            "decoded_bytes": quality.decoded_bytes,
            "skipped_oversize": quality.skipped_oversize,
        },
        "warnings": loaded.warnings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--day", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = run_gate(args.corpus.resolve(), day=args.day)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["gate_b_determination"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
