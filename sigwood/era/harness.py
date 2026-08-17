"""Private, aggregate-only fold callbacks for the runner-owned era harness.

This module never discovers or reads files.  The runner passes it already
selected loader chunks and owns the corresponding SinkPlan and loader call.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

import pandas as pd

from sigwood.common.loader import DecodedChunk, FoldDelta, FoldSink, PositionalMask
from sigwood.era.report import EraReducer


UTC = timezone.utc


@dataclass
class EraFoldState:
    """One bounded reducer shard plus scalar selected-row accounting."""

    reducer: EraReducer
    rows: int = 0
    earliest: datetime | None = None
    latest: datetime | None = None


def _timestamps(frame: pd.DataFrame) -> tuple[tuple[int, datetime], ...]:
    values = pd.to_numeric(frame.get("ts"), errors="coerce")
    result: list[tuple[int, datetime]] = []
    for position, value in enumerate(values.tolist()):
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(numeric):
            result.append((position, datetime.fromtimestamp(numeric, tz=UTC)))
    return tuple(result)


def make_era_fold_sink(
    family: str,
    *,
    reducer_factory: Callable[[], EraReducer],
) -> FoldSink:
    """Return a raw-population fold sink; it retains only reducer aggregates."""
    if family not in {"conn", "dns", "stats", "capture_loss"}:
        raise ValueError(f"unsupported era family {family!r}")

    def consume(
        delta: FoldDelta, chunk: DecodedChunk, mask: PositionalMask
    ) -> FoldDelta:
        state: EraFoldState = delta.value
        frame = chunk.frame
        kept = mask.keep
        selected_positions: list[int] = []
        selected_timestamps: list[datetime] = []
        for position, timestamp in _timestamps(frame):
            if position >= len(kept) or not kept[position]:
                continue
            selected_positions.append(position)
            selected_timestamps.append(timestamp)
        if not selected_positions:
            return FoldDelta(state, 256)
        selected = frame.take(selected_positions).copy()
        selected["timestamp"] = selected_timestamps
        state.rows += len(selected)
        state.earliest = min(selected_timestamps) if state.earliest is None else min(
            state.earliest, min(selected_timestamps)
        )
        state.latest = max(selected_timestamps) if state.latest is None else max(
            state.latest, max(selected_timestamps)
        )
        if family == "conn":
            state.reducer.add_conn_batch(selected)
        elif family == "dns":
            for timestamp, query in selected[["timestamp", "query"]].itertuples(index=False, name=None):
                state.reducer.add_dns_query(timestamp, query)
        return FoldDelta(state, 256)

    def commit(run: EraFoldState, delta: FoldDelta) -> EraFoldState:
        part: EraFoldState = delta.value
        run.reducer = run.reducer.merge(part.reducer)
        run.rows += part.rows
        if part.earliest is not None:
            run.earliest = part.earliest if run.earliest is None else min(run.earliest, part.earliest)
        if part.latest is not None:
            run.latest = part.latest if run.latest is None else max(run.latest, part.latest)
        return run

    return FoldSink(
        f"era.harness.{family}",
        lambda: FoldDelta(EraFoldState(reducer_factory()), 256),
        consume,
        lambda: EraFoldState(reducer_factory()),
        commit,
        lambda frame: PositionalMask((True,) * len(frame)),
    )
