"""Bounded preflight population for the planned Pi-hole dnsblock detector.

U2b deliberately emits no findings.  The runner owns files, windows,
suppression, coverage selection, and ordered snapshot passes; this module owns
only pure reducers and typed population facts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Mapping

import numpy as np
import pandas as pd

from sigwood.common.finding import DetectorContext, Finding
from sigwood.common.loader import (
    CoverageDecision,
    CoverageLane,
    DecodedChunk,
    DualWindow,
    FoldAbstention,
    FoldDelta,
    FoldSink,
    PositionalMask,
    PreparedState,
    PreparedStatus,
)
from sigwood.common.tld import roll_domain

DETECTOR_NAME = "dnsblock"
STATUS = "planned"

REQUIRED_LOGS = [{"source": "pihole_dir", "pattern": "pihole*.log*"}]
OPTIONAL_LOGS: list[dict] = []
DEFAULT_CONFIG: dict = {}

_CHANNEL_ANCHOR = "dnsblock.anchor"
_CHANNEL_BLOCKS = "dnsblock.blocks"
_CHANNEL_POPULATION = "dnsblock.population"
_BLOCK_EVENTS = frozenset({"gravity_blocked", "regex_blocked"})
_HANDLING_EVENTS = frozenset({"forwarded", "cached"})
_GRID_DAYS = (2, 3, 4, 5)
_GRID_CHANNEL = (7, 14, 21)
_DAY_SECONDS = 86_400.0


@dataclass(frozen=True)
class DnsblockLimits:
    association_cells: int = 10_000_000
    address_name_pairs: int = 500_000
    pair_period_cells: int = 5_000_000
    name_date_cells: int = 2_000_000
    address_date_cells: int = 1_000_000
    names: int = 100_000
    addresses: int = 20_000
    families: int = 50_000
    coverage_spans: int = 100_000
    worklist: int = 50_000
    per_window_routes: int = 1_000_000
    string_bytes: int = 256 * 1024 * 1024
    temp_bytes: int = 1024 * 1024 * 1024


LIMITS = DnsblockLimits()


class DropReason(str, Enum):
    INVALID_TIMESTAMP = "invalid_timestamp"
    INVALID_NAME = "invalid_name"
    NAME_TOO_LONG = "name_too_long"
    CONTROL_IN_NAME = "control_in_name"
    INVALID_ADDRESS = "invalid_address"
    OUTSIDE_WINDOW = "outside_window"


class NameRoute(str, Enum):
    QUALIFYING = "qualifying"
    PRIOR_HANDLING = "prior_handling_excluded"
    SAME_DAY_AMBIGUOUS = "same_day_ambiguous"
    PRIOR_ADDRESS_QUERY = "prior_address_query"
    INELIGIBLE_NAME = "ineligible_name"


class PairRoute(str, Enum):
    NO_QUALIFYING_NAME = "NO_QUALIFYING_NAME"
    INSUFFICIENT_HISTORY = "insufficient_history"
    NO_PRIOR_ADDRESS_ACTIVITY = "no_prior_address_activity"
    INSUFFICIENT_ACTIVE_PERIODS = "insufficient_active_periods"
    SYNC_WITHHELD = "sync_withheld"
    QUALIFYING = "qualifying"


@dataclass
class AnchorFacts:
    minimum_ts: float | None = None
    maximum_ts: float | None = None
    usable_rows: int = 0
    event_counts: Counter[str] = field(default_factory=Counter)


@dataclass
class BlockInventory:
    names: set[str] = field(default_factory=set)
    block_dates: dict[str, set[date]] = field(default_factory=dict)
    event_counts: Counter[str] = field(default_factory=Counter)
    drops: Counter[str] = field(default_factory=Counter)
    string_bytes: int = 0
    name_date_cells: int = 0


@dataclass
class BlockCellInventory:
    names: set[str] = field(default_factory=set)
    cells: dict[tuple[str, date], AssocCell] = field(default_factory=dict)
    drops: Counter[str] = field(default_factory=Counter)
    string_bytes: int = 0


@dataclass
class AnchorBlockFacts:
    anchor: AnchorFacts = field(default_factory=AnchorFacts)
    blocks: BlockCellInventory = field(default_factory=BlockCellInventory)


@dataclass
class AssocCell:
    count: int = 0
    first_ts: float = math.inf
    last_ts: float = -math.inf

    def add(self, ts: float) -> None:
        self.count += 1
        self.first_ts = min(self.first_ts, ts)
        self.last_ts = max(self.last_ts, ts)


@dataclass
class PopulationState:
    rows_seen: int = 0
    rows_kept: int = 0
    rows_suppressed: int = 0
    event_counts: Counter[str] = field(default_factory=Counter)
    drops: Counter[str] = field(default_factory=Counter)
    addresses: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    association: dict[tuple[str, str, date], AssocCell] = field(default_factory=dict)
    pair_period: dict[tuple[str, str, int], AssocCell] = field(default_factory=dict)
    pair_first: dict[tuple[str, str], float] = field(default_factory=dict)
    address_first: dict[str, float] = field(default_factory=dict)
    address_dates: set[tuple[str, date]] = field(default_factory=set)
    handling_dates: dict[str, set[date]] = field(default_factory=dict)
    handling_date_cells: int = 0
    query_periods: set[int] = field(default_factory=set)
    report_pairs: set[tuple[str, str]] = field(default_factory=set)
    a1_rows: int = 0
    a2_rows: int = 0
    string_bytes: int = 0


@dataclass(frozen=True)
class GridFacts:
    days_required: int
    history_required: int
    route_counts: tuple[tuple[str, int], ...]
    qualifying_pairs: int
    identity_digest: str


@dataclass(frozen=True)
class DnsblockPreflight:
    state: PreparedState
    cause: str
    snapshot_identity: str
    report_interval: tuple[datetime, datetime]
    context_interval: tuple[datetime, datetime] | None
    coverage_lane: CoverageLane
    coverage_reason: str
    coverage_union: tuple[tuple[datetime, datetime], ...]
    raw_event_counts: tuple[tuple[str, int], ...]
    drop_counts: tuple[tuple[str, int], ...]
    rows_kept: int
    rows_suppressed: int
    a1_rows: int
    a2_rows: int
    association_cells: int
    address_name_pairs: int
    name_routes: tuple[tuple[str, int], ...]
    grids: tuple[GridFacts, ...]
    resident_bytes: int
    pass_wall_seconds: tuple[tuple[str, float], ...] = ()


@dataclass(frozen=True)
class DnsblockPrepared:
    preflight: DnsblockPreflight


def _finite_ts(value: Any) -> float | None:
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(numeric):
        return None
    try:
        datetime.fromtimestamp(numeric, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None
    return numeric


def normalize_name(value: Any) -> tuple[str | None, DropReason | None]:
    if not isinstance(value, str):
        return None, DropReason.INVALID_NAME
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None, DropReason.CONTROL_IN_NAME
    normalized = value.lower().rstrip(".")
    if not normalized or "." not in normalized:
        return None, DropReason.INVALID_NAME
    if len(normalized.encode("utf-8")) > 253:
        return None, DropReason.NAME_TOO_LONG
    return normalized, None


def normalize_address(value: Any) -> tuple[str | None, DropReason | None]:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None, DropReason.INVALID_ADDRESS
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address), None


def _family(name: str) -> tuple[str, bool]:
    rolled = roll_domain(name, "domain")
    # A PSL miss returns the normalized input; keep it as an honest fallback.
    return rolled, rolled == name and name.count(".") == 1


def _utc_date(ts: float) -> date:
    return datetime.fromtimestamp(ts, tz=timezone.utc).date()


def _period_index(ts: float, window: DualWindow) -> int | None:
    report_start, report_end = window.report_interval
    instant = datetime.fromtimestamp(ts, tz=timezone.utc)
    if instant > report_end:
        return None
    history_start = (
        window.context_interval[0]
        if window.context_interval is not None
        else report_start
    )
    if instant < history_start or instant == report_start:
        return None
    distance = (report_end - instant).total_seconds()
    index = max(0, int(math.floor(distance / _DAY_SECONDS)))
    period_start = report_end - timedelta(days=index + 1)
    period_end = report_end - timedelta(days=index)
    if not (period_start < instant <= period_end):
        return None
    if period_start < history_start:
        return None
    return index


def _full_report_periods(window: DualWindow) -> int:
    start, end = window.report_interval
    return max(0, int((end - start).total_seconds() // _DAY_SECONDS))


def _resident_block(state: BlockInventory) -> int:
    return state.string_bytes + sum(len(values) for values in state.block_dates.values()) * 24


def _resident_block_cells(state: BlockCellInventory) -> int:
    return state.string_bytes + len(state.cells) * 56


def _resident_population(state: PopulationState) -> int:
    return (
        state.string_bytes
        + len(state.association) * 72
        + len(state.pair_period) * 64
        + len(state.pair_first) * 48
        + len(state.address_first) * 32
        + len(state.address_dates) * 32
        + state.handling_date_cells * 24
        + len(state.query_periods) * 16
    )


def _bounded_add_string(state: Any, value: str, limits: DnsblockLimits) -> None:
    size = len(value.encode("utf-8"))
    if state.string_bytes + size > limits.string_bytes:
        raise FoldAbstention("dnsblock retained strings exceed 256 MiB")
    state.string_bytes += size


def _merge_counter(target: Counter[str], source: Mapping[str, int]) -> None:
    target.update(source)


def make_anchor_sink() -> FoldSink:
    def consume(delta: FoldDelta, chunk: DecodedChunk, mask: PositionalMask) -> FoldDelta:
        state: AnchorFacts = delta.value
        numeric = pd.to_numeric(chunk.frame.get("ts"), errors="coerce")
        numeric = numeric[numeric.notna() & np.isfinite(numeric)]
        if not numeric.empty:
            minimum = float(numeric.min())
            maximum = float(numeric.max())
            state.minimum_ts = minimum if state.minimum_ts is None else min(state.minimum_ts, minimum)
            state.maximum_ts = maximum if state.maximum_ts is None else max(state.maximum_ts, maximum)
            state.usable_rows += len(numeric)
        state.event_counts.update(
            {
                str(key): int(value)
                for key, value in chunk.frame["event_type"].value_counts(dropna=False).items()
            }
        )
        return FoldDelta(state, 256 + len(state.event_counts) * 64)

    def commit(run: AnchorFacts, delta: FoldDelta) -> AnchorFacts:
        part: AnchorFacts = delta.value
        if part.minimum_ts is not None:
            run.minimum_ts = part.minimum_ts if run.minimum_ts is None else min(run.minimum_ts, part.minimum_ts)
        if part.maximum_ts is not None:
            run.maximum_ts = part.maximum_ts if run.maximum_ts is None else max(run.maximum_ts, part.maximum_ts)
        run.usable_rows += part.usable_rows
        run.event_counts.update(part.event_counts)
        return run

    return FoldSink(
        _CHANNEL_ANCHOR,
        lambda: FoldDelta(AnchorFacts(), 0),
        consume,
        AnchorFacts,
        commit,
        lambda frame: PositionalMask((True,) * len(frame)),
    )


def _add_block_cells(
    state: BlockCellInventory,
    frame: pd.DataFrame,
    *,
    limits: DnsblockLimits,
) -> None:
    blocked = frame[frame["event_type"].isin(_BLOCK_EVENTS)].copy()
    if blocked.empty:
        return
    blocked["numeric_ts"] = pd.to_numeric(blocked["ts"], errors="coerce")
    finite = blocked["numeric_ts"].notna() & np.isfinite(blocked["numeric_ts"])
    state.drops[DropReason.INVALID_TIMESTAMP.value] += int((~finite).sum())
    blocked = blocked[finite]
    if blocked.empty:
        return
    name_map = {
        value: normalize_name(value)
        for value in blocked["query"].drop_duplicates().tolist()
    }
    blocked["normalized_name"] = blocked["query"].map(
        {value: result[0] for value, result in name_map.items()}
    )
    invalid = blocked["normalized_name"].isna()
    for value, count in blocked.loc[invalid, "query"].value_counts(dropna=False).items():
        reason = name_map[value][1] or DropReason.INVALID_NAME
        state.drops[reason.value] += int(count)
    blocked = blocked[~invalid]
    if blocked.empty:
        return
    blocked["block_date"] = pd.to_datetime(
        blocked["numeric_ts"], unit="s", utc=True
    ).dt.date
    grouped = blocked.groupby(
        ["normalized_name", "block_date"], sort=False, dropna=False
    )["numeric_ts"].agg(["count", "min", "max"])
    for (name_value, day), count, first_ts, last_ts in zip(
        grouped.index,
        grouped["count"].to_numpy(),
        grouped["min"].to_numpy(),
        grouped["max"].to_numpy(),
    ):
        name = str(name_value)
        if name not in state.names:
            if len(state.names) >= limits.names:
                raise FoldAbstention("dnsblock names exceed 100,000")
            _bounded_add_string(state, name, limits)
            state.names.add(name)
        key = (name, day)
        if key not in state.cells:
            if len(state.cells) >= limits.name_date_cells:
                raise FoldAbstention("dnsblock name-date cells exceed 2,000,000")
            state.cells[key] = AssocCell()
        cell = state.cells[key]
        cell.count += int(count)
        cell.first_ts = min(cell.first_ts, float(first_ts))
        cell.last_ts = max(cell.last_ts, float(last_ts))


def _merge_block_cells(
    run: BlockCellInventory,
    part: BlockCellInventory,
    *,
    limits: DnsblockLimits,
) -> None:
    for name in part.names:
        if name not in run.names:
            if len(run.names) >= limits.names:
                raise FoldAbstention("dnsblock names exceed 100,000")
            _bounded_add_string(run, name, limits)
            run.names.add(name)
    for key, incoming in part.cells.items():
        if key not in run.cells and len(run.cells) >= limits.name_date_cells:
            raise FoldAbstention("dnsblock name-date cells exceed 2,000,000")
        cell = run.cells.setdefault(key, AssocCell())
        cell.count += incoming.count
        cell.first_ts = min(cell.first_ts, incoming.first_ts)
        cell.last_ts = max(cell.last_ts, incoming.last_ts)
    _merge_counter(run.drops, part.drops)


def make_anchor_block_sink(
    mask: Callable[[pd.DataFrame], PositionalMask],
    *,
    limits: DnsblockLimits = LIMITS,
) -> FoldSink:
    """Collect the all-event anchor and bounded block cells in one parse."""

    def consume(delta: FoldDelta, chunk: DecodedChunk, keep_mask: PositionalMask) -> FoldDelta:
        state: AnchorBlockFacts = delta.value
        numeric = chunk.frame["ts"].to_numpy(dtype=float, na_value=np.nan)
        numeric = numeric[np.isfinite(numeric)]
        if numeric.size:
            minimum = float(numeric.min())
            maximum = float(numeric.max())
            state.anchor.minimum_ts = minimum if state.anchor.minimum_ts is None else min(state.anchor.minimum_ts, minimum)
            state.anchor.maximum_ts = maximum if state.anchor.maximum_ts is None else max(state.anchor.maximum_ts, maximum)
            state.anchor.usable_rows += len(numeric)
        kept = np.asarray(keep_mask.keep, dtype=bool)
        blocked = chunk.frame["event_type"].isin(_BLOCK_EVENTS).to_numpy()
        _add_block_cells(
            state.blocks,
            chunk.frame.loc[kept & blocked],
            limits=limits,
        )
        resident = 256 + _resident_block_cells(state.blocks)
        return FoldDelta(state, resident)

    def commit(run: AnchorBlockFacts, delta: FoldDelta) -> AnchorBlockFacts:
        part: AnchorBlockFacts = delta.value
        if part.anchor.minimum_ts is not None:
            run.anchor.minimum_ts = part.anchor.minimum_ts if run.anchor.minimum_ts is None else min(run.anchor.minimum_ts, part.anchor.minimum_ts)
        if part.anchor.maximum_ts is not None:
            run.anchor.maximum_ts = part.anchor.maximum_ts if run.anchor.maximum_ts is None else max(run.anchor.maximum_ts, part.anchor.maximum_ts)
        run.anchor.usable_rows += part.anchor.usable_rows
        run.anchor.event_counts.update(part.anchor.event_counts)
        _merge_block_cells(run.blocks, part.blocks, limits=limits)
        return run

    return FoldSink(
        "dnsblock.anchor_blocks",
        lambda: FoldDelta(AnchorBlockFacts(), 0),
        consume,
        AnchorBlockFacts,
        commit,
        mask,
    )


def finalize_block_inventory(
    cells: BlockCellInventory,
    report_interval: tuple[datetime, datetime],
    *,
    limits: DnsblockLimits = LIMITS,
) -> BlockInventory:
    """Finalize exact report-side block existence from bounded UTC-date cells."""
    report_start, report_end = report_interval
    start_epoch = report_start.timestamp()
    end_epoch = report_end.timestamp()
    inventory = BlockInventory(drops=Counter(cells.drops))
    for (name, day), cell in cells.cells.items():
        if cell.last_ts < start_epoch or cell.first_ts > end_epoch:
            continue
        if name not in inventory.names:
            if len(inventory.names) >= limits.names:
                raise FoldAbstention("dnsblock names exceed 100,000")
            _bounded_add_string(inventory, name, limits)
            inventory.names.add(name)
        dates = inventory.block_dates.setdefault(name, set())
        if day not in dates:
            if inventory.name_date_cells >= limits.name_date_cells:
                raise FoldAbstention("dnsblock name-date cells exceed 2,000,000")
            dates.add(day)
            inventory.name_date_cells += 1
    return inventory


def make_block_sink(
    mask: Callable[[pd.DataFrame], PositionalMask],
    *,
    limits: DnsblockLimits = LIMITS,
) -> FoldSink:
    def consume(delta: FoldDelta, chunk: DecodedChunk, keep_mask: PositionalMask) -> FoldDelta:
        state: BlockInventory = delta.value
        positions = [
            pos
            for pos, (kept, report)
            in enumerate(zip(keep_mask.keep, chunk.report_mask))
            if kept and report
        ]
        selected = chunk.frame.iloc[positions]
        state.event_counts.update(
            {
                str(key): int(value)
                for key, value in selected["event_type"].value_counts(dropna=False).items()
            }
        )
        blocked = selected[selected["event_type"].isin(_BLOCK_EVENTS)]
        for row in blocked.itertuples(index=False):
            event = str(getattr(row, "event_type", ""))
            ts = _finite_ts(getattr(row, "ts", None))
            if ts is None:
                state.drops[DropReason.INVALID_TIMESTAMP.value] += 1
                continue
            name, reason = normalize_name(getattr(row, "query", None))
            if name is None:
                state.drops[reason.value if reason else DropReason.INVALID_NAME.value] += 1
                continue
            if name not in state.names:
                if len(state.names) >= limits.names:
                    raise FoldAbstention("dnsblock names exceed 100,000")
                _bounded_add_string(state, name, limits)
                state.names.add(name)
            dates = state.block_dates.setdefault(name, set())
            value = _utc_date(ts)
            if value not in dates:
                if state.name_date_cells >= limits.name_date_cells:
                    raise FoldAbstention("dnsblock name-date cells exceed 2,000,000")
                dates.add(value)
                state.name_date_cells += 1
        return FoldDelta(state, _resident_block(state))

    def commit(run: BlockInventory, delta: FoldDelta) -> BlockInventory:
        part: BlockInventory = delta.value
        for name in part.names:
            if name not in run.names:
                if len(run.names) >= limits.names:
                    raise FoldAbstention("dnsblock names exceed 100,000")
                _bounded_add_string(run, name, limits)
                run.names.add(name)
            target = run.block_dates.setdefault(name, set())
            incoming = part.block_dates.get(name, set()) - target
            if run.name_date_cells + len(incoming) > limits.name_date_cells:
                raise FoldAbstention("dnsblock name-date cells exceed 2,000,000")
            target.update(incoming)
            run.name_date_cells += len(incoming)
        _merge_counter(run.event_counts, part.event_counts)
        _merge_counter(run.drops, part.drops)
        return run

    return FoldSink(
        _CHANNEL_BLOCKS,
        lambda: FoldDelta(BlockInventory(), 0),
        consume,
        BlockInventory,
        commit,
        mask,
    )


def make_population_sink(
    inventory: BlockInventory,
    window: DualWindow,
    mask: Callable[[pd.DataFrame], PositionalMask],
    *,
    limits: DnsblockLimits = LIMITS,
) -> FoldSink:
    block_names = frozenset(inventory.names)
    block_dates = {name: frozenset(values) for name, values in inventory.block_dates.items()}
    block_membership = frozenset(
        (name, day) for name, days in block_dates.items() for day in days
    )

    def add_name(state: PopulationState, name: str) -> None:
        if name in state.names:
            return
        if len(state.names) >= limits.names:
            raise FoldAbstention("dnsblock names exceed 100,000")
        _bounded_add_string(state, name, limits)
        state.names.add(name)

    def add_address(state: PopulationState, address: str) -> None:
        if address in state.addresses:
            return
        if len(state.addresses) >= limits.addresses:
            raise FoldAbstention("dnsblock addresses exceed 20,000")
        _bounded_add_string(state, address, limits)
        state.addresses.add(address)

    def consume(delta: FoldDelta, chunk: DecodedChunk, keep_mask: PositionalMask) -> FoldDelta:
        state: PopulationState = delta.value
        state.rows_seen += len(chunk.frame)
        kept_positions = [pos for pos, kept in enumerate(keep_mask.keep) if kept]
        state.rows_kept += len(kept_positions)
        state.rows_suppressed += len(chunk.frame) - len(kept_positions)
        selected = chunk.frame.iloc[kept_positions].copy()
        selected["chunk_pos"] = kept_positions
        state.event_counts.update(
            {
                str(key): int(value)
                for key, value in selected["event_type"].value_counts(dropna=False).items()
            }
        )
        relevant = selected[
            selected["event_type"].isin(("query", "forwarded", "cached"))
        ].copy()
        relevant["in_report"] = relevant["chunk_pos"].map(
            lambda pos: chunk.report_mask[int(pos)]
        )
        relevant["in_context"] = relevant["chunk_pos"].map(
            lambda pos: chunk.context_mask[int(pos)]
        )
        relevant["numeric_ts"] = pd.to_numeric(relevant["ts"], errors="coerce")
        finite = relevant["numeric_ts"].notna() & np.isfinite(relevant["numeric_ts"])
        state.drops[DropReason.INVALID_TIMESTAMP.value] += int((~finite).sum())
        relevant = relevant[finite]
        in_window = relevant["in_report"] | relevant["in_context"]
        state.drops[DropReason.OUTSIDE_WINDOW.value] += int((~in_window).sum())
        relevant = relevant[in_window]

        queries = relevant[relevant["event_type"] == "query"].copy()
        if not queries.empty:
            address_map = {
                value: normalize_address(value)
                for value in queries["src"].drop_duplicates().tolist()
            }
            queries["address"] = queries["src"].map(
                {value: result[0] for value, result in address_map.items()}
            )
            invalid_addresses = queries["address"].isna()
            state.drops[DropReason.INVALID_ADDRESS.value] += int(
                invalid_addresses.sum()
            )
            queries = queries[~invalid_addresses]

        if not queries.empty:
            name_map = {
                value: normalize_name(value)
                for value in queries["query"].drop_duplicates().tolist()
            }
            queries["normalized_name"] = queries["query"].map(
                {value: result[0] for value, result in name_map.items()}
            )
            for value, count in queries.loc[
                queries["normalized_name"].isna(), "query"
            ].value_counts(dropna=False).items():
                reason = name_map[value][1] or DropReason.INVALID_NAME
                state.drops[reason.value] += int(count)

            for address, first_ts in queries.groupby("address")["numeric_ts"].min().items():
                add_address(state, address)
                numeric = float(first_ts)
                state.address_first[address] = min(
                    state.address_first.get(address, numeric), numeric
                )
            query_dates = pd.to_datetime(
                queries["numeric_ts"], unit="s", utc=True
            ).dt.date
            incoming_address_dates = set(zip(queries["address"], query_dates))
            if len(state.address_dates | incoming_address_dates) > limits.address_date_cells:
                raise FoldAbstention("dnsblock address-date cells exceed 1,000,000")
            state.address_dates.update(incoming_address_dates)

            report_end_epoch = window.report_interval[1].timestamp()
            history_start_epoch = (
                window.context_interval[0].timestamp()
                if window.context_interval is not None
                else window.report_interval[0].timestamp()
            )
            period_values = ((report_end_epoch - queries["numeric_ts"]) // _DAY_SECONDS).astype(int)
            period_starts = report_end_epoch - (period_values + 1) * _DAY_SECONDS
            valid_period = (
                (queries["numeric_ts"] <= report_end_epoch)
                & (queries["numeric_ts"] > history_start_epoch)
                & (queries["numeric_ts"] != window.report_interval[0].timestamp())
                & (period_starts >= history_start_epoch)
            )
            state.query_periods.update(
                int(value) for value in period_values[valid_period].unique()
            )
            queries["period"] = period_values
            queries["period_valid"] = valid_period
            queries["query_day"] = query_dates
            blocked_queries = queries[
                queries["normalized_name"].isin(block_names)
            ]
            if not blocked_queries.empty:
                for name in blocked_queries["normalized_name"].unique():
                    add_name(state, str(name))
                first_by_pair = blocked_queries.groupby(
                    ["address", "normalized_name"], sort=False
                )["numeric_ts"].min()
                for (address, name), first_ts in first_by_pair.items():
                    key = (str(address), str(name))
                    if key not in state.pair_first and len(state.pair_first) >= limits.address_name_pairs:
                        raise FoldAbstention("dnsblock address-name pairs exceed 500,000")
                    numeric = float(first_ts)
                    state.pair_first[key] = min(state.pair_first.get(key, numeric), numeric)

                report_queries = blocked_queries[blocked_queries["in_report"]].copy()
                state.report_pairs.update(
                    (str(address), str(name))
                    for address, name in zip(
                        report_queries["address"], report_queries["normalized_name"]
                    )
                )
                associations = report_queries.groupby(
                    ["address", "normalized_name", "query_day"], sort=False
                )["numeric_ts"].agg(["count", "min", "max"])
                for (address, name, day), count, first_ts, last_ts in zip(
                    associations.index,
                    associations["count"].to_numpy(),
                    associations["min"].to_numpy(),
                    associations["max"].to_numpy(),
                ):
                    key = (str(address), str(name), day)
                    if key not in state.association and len(state.association) >= limits.association_cells:
                        raise FoldAbstention("dnsblock association cells exceed 10,000,000")
                    cell = state.association.setdefault(key, AssocCell())
                    cell.count += int(count)
                    cell.first_ts = min(cell.first_ts, float(first_ts))
                    cell.last_ts = max(cell.last_ts, float(last_ts))
                state.a2_rows += len(report_queries)

                membership = pd.MultiIndex.from_arrays(
                    [report_queries["normalized_name"], report_queries["query_day"]]
                ).isin(block_membership)
                a1_queries = report_queries[membership]
                state.a1_rows += len(a1_queries)
                period_queries = a1_queries[a1_queries["period_valid"]]
                periods = period_queries.groupby(
                    ["address", "normalized_name", "period"], sort=False
                )["numeric_ts"].agg(["count", "min", "max"])
                for (address, name, period), count, first_ts, last_ts in zip(
                    periods.index,
                    periods["count"].to_numpy(),
                    periods["min"].to_numpy(),
                    periods["max"].to_numpy(),
                ):
                    key = (str(address), str(name), int(period))
                    if key not in state.pair_period and len(state.pair_period) >= limits.pair_period_cells:
                        raise FoldAbstention("dnsblock pair-period cells exceed 5,000,000")
                    cell = state.pair_period.setdefault(key, AssocCell())
                    cell.count += int(count)
                    cell.first_ts = min(cell.first_ts, float(first_ts))
                    cell.last_ts = max(cell.last_ts, float(last_ts))

        handling = relevant[relevant["event_type"].isin(_HANDLING_EVENTS)].copy()
        if not handling.empty:
            handling_map = {
                value: normalize_name(value)
                for value in handling["query"].drop_duplicates().tolist()
            }
            handling["normalized_name"] = handling["query"].map(
                {value: result[0] for value, result in handling_map.items()}
            )
            for value, count in handling.loc[
                handling["normalized_name"].isna(), "query"
            ].value_counts(dropna=False).items():
                reason = handling_map[value][1] or DropReason.INVALID_NAME
                state.drops[reason.value] += int(count)
            handling = handling[handling["normalized_name"].isin(block_names)]
            handling["handling_day"] = pd.to_datetime(
                handling["numeric_ts"], unit="s", utc=True
            ).dt.date
            for name, days in handling.groupby("normalized_name")["handling_day"]:
                add_name(state, name)
                values = state.handling_dates.setdefault(name, set())
                incoming = set(days) - values
                if state.handling_date_cells + len(incoming) > limits.name_date_cells:
                    raise FoldAbstention("dnsblock name-date cells exceed 2,000,000")
                values.update(incoming)
                state.handling_date_cells += len(incoming)
        return FoldDelta(state, _resident_population(state))

    def commit(run: PopulationState, delta: FoldDelta) -> PopulationState:
        part: PopulationState = delta.value
        # Reuse the same checked operations so per-file limits cannot multiply.
        for value in part.addresses:
            add_address(run, value)
        for value in part.names:
            add_name(run, value)
        for key, cell in part.association.items():
            if key not in run.association and len(run.association) >= limits.association_cells:
                raise FoldAbstention("dnsblock association cells exceed 10,000,000")
            target = run.association.setdefault(key, AssocCell())
            target.count += cell.count
            target.first_ts = min(target.first_ts, cell.first_ts)
            target.last_ts = max(target.last_ts, cell.last_ts)
        for key, cell in part.pair_period.items():
            if key not in run.pair_period and len(run.pair_period) >= limits.pair_period_cells:
                raise FoldAbstention("dnsblock pair-period cells exceed 5,000,000")
            target = run.pair_period.setdefault(key, AssocCell())
            target.count += cell.count
            target.first_ts = min(target.first_ts, cell.first_ts)
            target.last_ts = max(target.last_ts, cell.last_ts)
        for key, value in part.pair_first.items():
            if key not in run.pair_first and len(run.pair_first) >= limits.address_name_pairs:
                raise FoldAbstention("dnsblock address-name pairs exceed 500,000")
            run.pair_first[key] = min(run.pair_first.get(key, value), value)
        for key, value in part.address_first.items():
            run.address_first[key] = min(run.address_first.get(key, value), value)
        if len(run.address_dates) + len(part.address_dates - run.address_dates) > limits.address_date_cells:
            raise FoldAbstention("dnsblock address-date cells exceed 1,000,000")
        run.address_dates.update(part.address_dates)
        for name, values in part.handling_dates.items():
            target = run.handling_dates.setdefault(name, set())
            incoming = values - target
            if run.handling_date_cells + len(incoming) > limits.name_date_cells:
                raise FoldAbstention("dnsblock name-date cells exceed 2,000,000")
            target.update(incoming)
            run.handling_date_cells += len(incoming)
        run.query_periods.update(part.query_periods)
        run.report_pairs.update(part.report_pairs)
        run.rows_seen += part.rows_seen
        run.rows_kept += part.rows_kept
        run.rows_suppressed += part.rows_suppressed
        run.a1_rows += part.a1_rows
        run.a2_rows += part.a2_rows
        _merge_counter(run.event_counts, part.event_counts)
        _merge_counter(run.drops, part.drops)
        return run

    return FoldSink(
        _CHANNEL_POPULATION,
        lambda: FoldDelta(PopulationState(), 0),
        consume,
        PopulationState,
        commit,
        mask,
    )


def _covered_periods(
    window: DualWindow,
    decision: CoverageDecision,
    data_periods: Iterable[int],
) -> set[int]:
    report_end = window.report_interval[1]
    history_start = window.context_interval[0] if window.context_interval else window.report_interval[0]
    total = max(0, int((report_end - history_start).total_seconds() // _DAY_SECONDS))
    if decision.lane is CoverageLane.WEAK:
        return set(data_periods)
    eligible: set[int] = set()
    for index in range(total):
        start = report_end - timedelta(days=index + 1)
        end = report_end - timedelta(days=index)
        if any(c_start <= start and c_end >= end for c_start, c_end in decision.trusted_intervals):
            eligible.add(index)
    return eligible


def _population_facts(
    state: PopulationState,
    window: DualWindow,
    decision: CoverageDecision,
    limits: DnsblockLimits,
) -> tuple[Counter[str], tuple[GridFacts, ...]]:
    full_report = _full_report_periods(window)
    eligible = _covered_periods(window, decision, state.query_periods)
    by_pair: dict[tuple[str, str], dict[str, Any]] = {}
    families: set[str] = set()
    periods_by_name_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
    first_by_name_period: dict[tuple[str, str, int], float] = {}
    for key, cell in state.pair_period.items():
        address, name, period = key
        periods_by_name_pair[(address, name)].add(period)
        first_by_name_period[key] = cell.first_ts

    for address, name in state.report_pairs:
        family, _unknown = _family(name)
        families.add(family)
        if len(families) > limits.families:
            raise FoldAbstention("dnsblock families exceed 50,000")
        item = by_pair.setdefault((address, family), {"names": set(), "periods": set()})
        if len(by_pair) > limits.worklist:
            raise FoldAbstention("dnsblock worklist exceeds 50,000")
        item["names"].add(name)
        item["periods"].update(
            period
            for period in periods_by_name_pair.get((address, name), ())
            if period < full_report
        )

    name_routes: Counter[str] = Counter()
    grids: list[GridFacts] = []
    for days_required in _GRID_DAYS:
        for history_required in _GRID_CHANNEL:
            routes: Counter[str] = Counter()
            qualified_ids: list[str] = []
            provisional: list[tuple[tuple[str, str], int]] = []
            for pair, item in sorted(by_pair.items()):
                address, family = pair
                qualifying_names: list[str] = []
                candidate_periods: list[int] = []
                for name in sorted(item["names"]):
                    periods = sorted(
                        period
                        for period in periods_by_name_pair.get((address, name), ())
                        if period < full_report
                    )
                    if not periods:
                        if days_required == _GRID_DAYS[0] and history_required == _GRID_CHANNEL[0]:
                            name_routes[NameRoute.INELIGIBLE_NAME.value] += 1
                        continue
                    candidate = max(periods)  # oldest associated report period
                    candidate_start = window.report_interval[1] - timedelta(days=candidate + 1)
                    first_associated = first_by_name_period[(address, name, candidate)]
                    candidate_day = _utc_date(first_associated)
                    handling = state.handling_dates.get(name, set())
                    if any(day < candidate_day for day in handling):
                        if days_required == _GRID_DAYS[0] and history_required == _GRID_CHANNEL[0]:
                            name_routes[NameRoute.PRIOR_HANDLING.value] += 1
                        continue
                    if candidate_day in handling:
                        if days_required == _GRID_DAYS[0] and history_required == _GRID_CHANNEL[0]:
                            name_routes[NameRoute.SAME_DAY_AMBIGUOUS.value] += 1
                        continue
                    first_pair = state.pair_first.get((address, name), math.inf)
                    if first_pair < first_associated:
                        if days_required == _GRID_DAYS[0] and history_required == _GRID_CHANNEL[0]:
                            name_routes[NameRoute.PRIOR_ADDRESS_QUERY.value] += 1
                        continue
                    if days_required == _GRID_DAYS[0] and history_required == _GRID_CHANNEL[0]:
                        name_routes[NameRoute.QUALIFYING.value] += 1
                    qualifying_names.append(name)
                    candidate_periods.append(candidate)
                if not qualifying_names:
                    routes[PairRoute.NO_QUALIFYING_NAME.value] += 1
                    continue
                candidate = max(candidate_periods)
                candidate_start = window.report_interval[1] - timedelta(days=candidate + 1)
                history_count = sum(1 for period in eligible if period > candidate)
                if history_count < history_required:
                    routes[PairRoute.INSUFFICIENT_HISTORY.value] += 1
                    continue
                if state.address_first.get(address, math.inf) >= candidate_start.timestamp():
                    routes[PairRoute.NO_PRIOR_ADDRESS_ACTIVITY.value] += 1
                    continue
                active = {period for period in item["periods"] if period in eligible}
                if len(active) < days_required:
                    routes[PairRoute.INSUFFICIENT_ACTIVE_PERIODS.value] += 1
                    continue
                provisional.append((pair, candidate))

            sync_groups: Counter[tuple[str, int]] = Counter(
                (family, candidate) for (_address, family), candidate in provisional
            )
            for (address, family), candidate in provisional:
                if sync_groups[(family, candidate)] >= 3:
                    routes[PairRoute.SYNC_WITHHELD.value] += 1
                else:
                    routes[PairRoute.QUALIFYING.value] += 1
                    qualified_ids.append(f"{address}\0{family}")
            if sum(routes.values()) > limits.per_window_routes:
                raise FoldAbstention("dnsblock per-window routes exceed 1,000,000")
            digest = hashlib.sha256(
                json.dumps(sorted(qualified_ids), separators=(",", ":")).encode()
            ).hexdigest()
            grids.append(
                GridFacts(
                    days_required,
                    history_required,
                    tuple(sorted(routes.items())),
                    len(qualified_ids),
                    digest,
                )
            )
    return name_routes, tuple(grids)


def build_prepared(
    *,
    snapshot_identity: str,
    window: DualWindow,
    coverage: CoverageDecision,
    block_status: PreparedStatus,
    population_status: PreparedStatus,
    blocks: BlockInventory | None,
    population: PopulationState | None,
    pass_wall_seconds: tuple[tuple[str, float], ...] = (),
    limits: DnsblockLimits = LIMITS,
) -> DnsblockPrepared:
    status = population_status
    retained_coverage = coverage.trusted_intervals
    if block_status.state is not PreparedState.READY:
        status = block_status
    if (
        status.state is PreparedState.READY
        and len(coverage.trusted_intervals) > limits.coverage_spans
    ):
        status = PreparedStatus(
            PreparedState.ABSTAINED,
            "dnsblock coverage spans exceed 100,000",
        )
        retained_coverage = ()
    if status.state is not PreparedState.READY or blocks is None or population is None:
        facts = DnsblockPreflight(
            status.state,
            status.cause or "dnsblock preparation unavailable",
            snapshot_identity,
            window.report_interval,
            window.context_interval,
            coverage.lane,
            coverage.reason.value,
            retained_coverage,
            (), (), 0, 0, 0, 0, 0, 0, (), (), 0, pass_wall_seconds,
        )
        return DnsblockPrepared(facts)
    if population.a1_rows > population.a2_rows:
        raise ValueError("dnsblock A1 population is not a subset of A2")
    try:
        name_routes, grids = _population_facts(population, window, coverage, limits)
    except FoldAbstention as exc:
        facts = DnsblockPreflight(
            PreparedState.ABSTAINED,
            str(exc),
            snapshot_identity,
            window.report_interval,
            window.context_interval,
            coverage.lane,
            coverage.reason.value,
            retained_coverage,
            tuple(sorted(population.event_counts.items())),
            tuple(sorted(population.drops.items())),
            population.rows_kept,
            population.rows_suppressed,
            population.a1_rows,
            population.a2_rows,
            len(population.association),
            len(population.pair_first),
            (), (), _resident_population(population), pass_wall_seconds,
        )
        return DnsblockPrepared(facts)
    facts = DnsblockPreflight(
        PreparedState.READY,
        "",
        snapshot_identity,
        window.report_interval,
        window.context_interval,
        coverage.lane,
        coverage.reason.value,
        retained_coverage,
        tuple(sorted(population.event_counts.items())),
        tuple(sorted(population.drops.items())),
        population.rows_kept,
        population.rows_suppressed,
        population.a1_rows,
        population.a2_rows,
        len(population.association),
        len(population.pair_first),
        tuple(sorted(name_routes.items())),
        grids,
        _resident_population(population) + _resident_block(blocks),
        pass_wall_seconds,
    )
    return DnsblockPrepared(facts)


def run(
    context: DetectorContext,
    *,
    _prepared: DnsblockPrepared | None = None,
) -> list[Finding]:
    """Validate the runner-prepared U2b carrier; findings begin in U3."""
    if not isinstance(_prepared, DnsblockPrepared):
        raise ValueError("dnsblock requires runner-prepared preflight")
    return []
