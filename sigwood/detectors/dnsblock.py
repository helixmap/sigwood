"""Bounded analysis for the planned Pi-hole dnsblock detector.

The runner owns files, windows, suppression, coverage selection, and ordered
snapshot passes. This module owns pure reducers, typed analytical facts,
candidate routing, cadence statistics, and finding construction.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Mapping

import numpy as np
import pandas as pd

from sigwood.common.finding import DetectorContext, Finding, Severity
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
_BURST_GRID_ABS = (25, 50, 100, 200, 400)
_BURST_GRID_MULT = (4, 6, 8, 12, 16)
_BURST_GRID_ACTIVE = (2, 3, 4)
_DAY_SECONDS = 86_400.0
_CADENCE_MAX_GAP_SECONDS = 6 * 60 * 60

# Arrival construction constants. These are deliberately non-ratified: C1 owns
# the only transition from a construction vector to shipped calibration.
ARRIVAL_DAYS = 3
ARRIVAL_HISTORY = 14
ARRIVAL_VECTOR_RATIFIED = False
SYNC_ADDRESSES = 3
FOLD_MIN_MEMBERS = 4
BURST_ABS = 100
BURST_MULT = 8
BURST_ACTIVE = 3
BURST_VECTOR_RATIFIED = False
RECURRING_PERIODS = 4


@dataclass(frozen=True)
class DnsblockCalibrationVector:
    """Private C1 materialization choice over the already-frozen grids."""

    arrival_days: int = ARRIVAL_DAYS
    arrival_history: int = ARRIVAL_HISTORY
    burst_absolute: int = BURST_ABS
    burst_multiple: int = BURST_MULT
    burst_active: int = BURST_ACTIVE
    burst_enabled: bool = True

    def __post_init__(self) -> None:
        if self.arrival_days not in _GRID_DAYS:
            raise ValueError("dnsblock calibration arrival days are outside the frozen grid")
        if self.arrival_history not in _GRID_CHANNEL:
            raise ValueError("dnsblock calibration arrival history is outside the frozen grid")
        if self.burst_absolute not in _BURST_GRID_ABS:
            raise ValueError("dnsblock calibration burst absolute is outside the frozen grid")
        if self.burst_multiple not in _BURST_GRID_MULT:
            raise ValueError("dnsblock calibration burst multiple is outside the frozen grid")
        if self.burst_active not in _BURST_GRID_ACTIVE:
            raise ValueError("dnsblock calibration burst active is outside the frozen grid")


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
    cadence_gaps: int = 10_000
    prior_addresses: int = 100
    fold_members: int = 100
    disposition_days: int = 62
    findings: int = 1_000


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


class BurstRoute(str, Enum):
    INSUFFICIENT_ACTIVE_PERIODS = "insufficient_active_periods"
    BELOW_ABSOLUTE_PEAK = "below_absolute_peak"
    BELOW_PEAK_MULTIPLE = "below_peak_multiple"
    QUALIFYING = "qualifying"


class ChannelStatus(str, Enum):
    READY = "READY"
    ABSTAINED = "ABSTAINED"


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
    report_first_ts: float | None = None
    report_last_ts: float | None = None
    event_counts: Counter[str] = field(default_factory=Counter)
    drops: Counter[str] = field(default_factory=Counter)
    addresses: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    association: dict[tuple[str, str, date], AssocCell] = field(default_factory=dict)
    pair_period: dict[tuple[str, str, int], AssocCell] = field(default_factory=dict)
    a1_pair: dict[tuple[str, str], AssocCell] = field(default_factory=dict)
    pair_first: dict[tuple[str, str], float] = field(default_factory=dict)
    address_first: dict[str, float] = field(default_factory=dict)
    address_dates: set[tuple[str, date]] = field(default_factory=set)
    handling_dates: dict[str, set[date]] = field(default_factory=dict)
    block_first_dates: dict[str, date] = field(default_factory=dict)
    handling_date_cells: int = 0
    query_periods: set[int] = field(default_factory=set)
    report_pairs: set[tuple[str, str]] = field(default_factory=set)
    a1_rows: int = 0
    a2_rows: int = 0
    report_query_rows: int = 0
    report_query_rows_by_address: Counter[str] = field(default_factory=Counter)
    a1_rows_by_address: Counter[str] = field(default_factory=Counter)
    disposition: dict[tuple[str, date], Counter[str]] = field(default_factory=dict)
    disposition_date_cells: int = 0
    raw_window_rows: int = 0
    filtered_window_rows: int = 0
    raw_query_rows: int = 0
    raw_block_report_rows: int = 0
    raw_block_context_rows: int = 0
    filtered_block_report_rows: int = 0
    filtered_block_context_rows: int = 0
    string_bytes: int = 0


@dataclass(frozen=True)
class GridFacts:
    days_required: int
    history_required: int
    route_counts: tuple[tuple[str, int], ...]
    qualifying_pairs: int
    identity_digest: str


@dataclass(frozen=True)
class DispositionFacts:
    gravity_blocked: int
    regex_blocked: int
    forwarded: int
    cached: int
    by_day: tuple[tuple[str, int, int, int, int], ...]
    by_day_omitted: int


@dataclass(frozen=True)
class CadenceFacts:
    cadence_available: bool
    gap_count: int | None
    gap_cv: float | None
    gap_median_s: float | None


@dataclass(frozen=True)
class ArrivalCandidate:
    address: str
    family_key: str
    unknown_suffix: bool
    qualifying_names: tuple[str, ...]
    attributed_query_count: int
    qualifying_name_count: int
    active_periods: int
    eligible_periods: int
    first_associated_ts: float
    prior_other_address_count: int
    prior_other_address_count_at_cap: bool
    disposition: DispositionFacts


@dataclass(frozen=True)
class ArrivalSubsetFacts:
    novelty_noun: str
    first_associated_ts: float
    active_periods: int
    eligible_periods: int
    prior_other_address_count: int
    prior_other_address_count_at_cap: bool
    arrival_attributed_query_count: int
    arrival_qualifying_name_count: int


@dataclass(frozen=True)
class BurstCandidate:
    address: str
    family_key: str
    unknown_suffix: bool
    peak_count: int
    peak_period_start: float
    baseline_median_twice: int
    active_periods: int
    eligible_periods: int
    attributed_query_count: int
    disposition: DispositionFacts
    association_names: tuple[str, ...]
    arrival_subset: ArrivalSubsetFacts | None = None


@dataclass(frozen=True)
class BurstGridFacts:
    absolute_required: int
    multiple_required: int
    active_required: int
    route_counts: tuple[tuple[str, int], ...]
    qualifying_pairs: int
    identity_digest: str


@dataclass(frozen=True)
class ChannelFacts:
    status: ChannelStatus
    cause: str
    periods_required: int
    eligible_periods: int


@dataclass(frozen=True)
class RecurringFacts:
    status: ChannelStatus
    cause: str
    periods_required: int
    periods_total: int
    eligible_periods: int
    missing_periods: int
    pair_count: int
    family_count: int
    address_count: int


@dataclass(frozen=True)
class DnsblockNoteFacts:
    coverage_lane: CoverageLane
    arrival_days_required: int
    arrival_history_required: int
    insufficient_history_pairs: int = 0
    insufficient_context_periods: int | None = None
    insufficient_arrival_coverage: int | None = None
    burst_status: ChannelStatus = ChannelStatus.READY
    burst_cause: str = ""
    burst_active_required: int = BURST_ACTIVE
    burst_eligible_periods: int = 0
    recurring_status: ChannelStatus = ChannelStatus.READY
    recurring_cause: str = ""
    recurring_periods_required: int = RECURRING_PERIODS
    recurring_periods_total: int = 0
    recurring_missing_periods: int = 0
    synchronized_pairs: int = 0
    synchronized_addresses: int = 0
    raw_window_rows: int = 0
    filtered_window_rows: int = 0
    raw_query_rows: int = 0
    raw_block_report_rows: int = 0
    raw_block_context_rows: int = 0
    filtered_block_report_rows: int = 0
    filtered_block_context_rows: int = 0
    entity_findings: int = 0
    context_findings: int = 0
    cap_cause: str = ""


@dataclass(frozen=True)
class AnalysisFacts:
    arrivals: tuple[ArrivalCandidate, ...]
    bursts: tuple[BurstCandidate, ...]
    burst_grids: tuple[BurstGridFacts, ...]
    burst_channel: ChannelFacts
    recurring: RecurringFacts
    final_shape_routes: tuple[tuple[str, int], ...]
    withheld_arrival_burst_pairs: int
    cadence_worklist: tuple[tuple[str, str], ...]
    cadence_query_event_upper_bounds: tuple[tuple[str, str, int], ...]
    pair_routes: tuple[tuple[str, int], ...]
    prior_handling_names: int
    prior_handling_memberships: int
    report_query_rows: int
    report_query_rows_by_address: tuple[tuple[str, int], ...]
    a1_rows: int
    a1_rows_by_address: tuple[tuple[str, int], ...]
    notes: DnsblockNoteFacts


@dataclass
class CadenceState:
    first_ts: float | None = None
    last_ts: float | None = None
    included_gaps: list[float] = field(default_factory=list)


@dataclass
class CadenceBatchState:
    """Independent per-pair cadence reducers sharing one physical scan."""

    states: dict[tuple[str, str], CadenceState] = field(default_factory=dict)


@dataclass(frozen=True)
class _RoutingResult:
    name_routes: Counter[str]
    pair_routes: Counter[str]
    arrivals: tuple[ArrivalCandidate, ...]
    qualified_ids: tuple[str, ...]
    prior_handling_names: frozenset[str]
    prior_handling_memberships: frozenset[tuple[str, str]]
    max_history_periods: int
    synchronized_pairs: int
    synchronized_addresses: int


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
    observed_data_window: tuple[datetime, datetime] | None = None
    data_size_bytes: int = 0


@dataclass(frozen=True)
class DnsblockPrepared:
    preflight: DnsblockPreflight
    analysis: AnalysisFacts | None = None
    cadence: tuple[tuple[str, str, CadenceFacts], ...] = ()
    cadence_complete: bool = False
    calibration_survivors: CalibrationSurvivorFacts | None = None


@dataclass(frozen=True)
class CalibrationSurvivorFacts:
    """Private in-memory grid memberships; never written to C1 artifacts."""

    arrival_memberships: tuple[tuple[str, int], ...]
    burst_memberships: tuple[tuple[str, int], ...]


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
    suffix = roll_domain(name, "tld")
    # A PSL miss returns the normalized input for both requested levels.  An
    # ordinary registrable apex also equals ``rolled``, so the tld-level probe is
    # what distinguishes that valid apex from the shared owner's fallback.
    return rolled, suffix == name


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
        + len(state.a1_pair) * 56
        + len(state.pair_first) * 48
        + len(state.address_first) * 32
        + len(state.address_dates) * 32
        + state.handling_date_cells * 24
        + len(state.block_first_dates) * 32
        + len(state.query_periods) * 16
        + len(state.report_query_rows_by_address) * 32
        + len(state.a1_rows_by_address) * 32
        + state.disposition_date_cells * 96
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
    channel: str = "dnsblock.anchor_blocks",
    limits: DnsblockLimits = LIMITS,
) -> FoldSink:
    """Collect the all-event anchor and bounded block cells in one parse."""

    def consume(delta: FoldDelta, chunk: DecodedChunk, keep_mask: PositionalMask) -> FoldDelta:
        state: AnchorBlockFacts = delta.value
        if chunk.frame.empty:
            return FoldDelta(state, 256 + _resident_block_cells(state.blocks))
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
        channel,
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
    channel: str = _CHANNEL_POPULATION,
    sink_local_window: bool = False,
    capture_summary_window: bool = False,
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
        if chunk.frame.empty or "ts" not in chunk.frame.columns:
            return FoldDelta(state, _resident_population(state))
        kept_array = np.asarray(keep_mask.keep, dtype=bool)
        if sink_local_window:
            report_array, context_array = _sink_membership_masks(chunk, window)
        else:
            report_array = np.asarray(chunk.report_mask, dtype=bool)
            context_array = np.asarray(chunk.context_mask, dtype=bool)
        window_array = report_array | context_array
        if sink_local_window and not bool(window_array.any()):
            return FoldDelta(state, _resident_population(state))
        if "event_type" not in chunk.frame.columns:
            raise ValueError("dnsblock population chunk is missing event_type")
        state.rows_seen += int(window_array.sum()) if sink_local_window else len(chunk.frame)
        block_array = chunk.frame["event_type"].isin(_BLOCK_EVENTS).to_numpy()
        query_array = (chunk.frame["event_type"] == "query").to_numpy()
        state.raw_window_rows += int(window_array.sum())
        if capture_summary_window and bool(report_array.any()):
            report_ts = pd.to_numeric(
                chunk.frame.loc[report_array, "ts"], errors="coerce"
            ).to_numpy(dtype=float)
            finite_ts = report_ts[np.isfinite(report_ts)]
            if finite_ts.size:
                first_ts = float(finite_ts.min())
                last_ts = float(finite_ts.max())
                state.report_first_ts = (
                    first_ts
                    if state.report_first_ts is None
                    else min(state.report_first_ts, first_ts)
                )
                state.report_last_ts = (
                    last_ts
                    if state.report_last_ts is None
                    else max(state.report_last_ts, last_ts)
                )
        state.filtered_window_rows += int((kept_array & window_array).sum())
        state.raw_query_rows += int((query_array & window_array).sum())
        state.raw_block_report_rows += int((block_array & report_array).sum())
        state.raw_block_context_rows += int((block_array & context_array).sum())
        state.filtered_block_report_rows += int(
            (block_array & report_array & kept_array).sum()
        )
        state.filtered_block_context_rows += int(
            (block_array & context_array & kept_array).sum()
        )
        kept_positions = [
            pos
            for pos, kept in enumerate(keep_mask.keep)
            if kept and (bool(window_array[pos]) if sink_local_window else True)
        ]
        state.rows_kept += len(kept_positions)
        state.rows_suppressed += (
            int(window_array.sum()) - len(kept_positions)
            if sink_local_window
            else len(chunk.frame) - len(kept_positions)
        )
        selected = chunk.frame.iloc[kept_positions].copy()
        selected["chunk_pos"] = kept_positions
        selected_in_window = selected[
            selected["chunk_pos"].map(lambda pos: bool(window_array[int(pos)]))
        ]
        state.event_counts.update(
            {
                str(key): int(value)
                for key, value in selected_in_window["event_type"].value_counts(dropna=False).items()
            }
        )
        relevant = selected[
            selected["event_type"].isin(("query", "forwarded", "cached"))
        ].copy()
        relevant["in_report"] = relevant["chunk_pos"].map(
            lambda pos: bool(report_array[int(pos)])
        )
        relevant["in_context"] = relevant["chunk_pos"].map(
            lambda pos: bool(context_array[int(pos)])
        )
        relevant["numeric_ts"] = pd.to_numeric(relevant["ts"], errors="coerce")
        finite = relevant["numeric_ts"].notna() & np.isfinite(relevant["numeric_ts"])
        state.drops[DropReason.INVALID_TIMESTAMP.value] += int((~finite).sum())
        relevant = relevant[finite]
        in_window = relevant["in_report"] | relevant["in_context"]
        state.drops[DropReason.OUTSIDE_WINDOW.value] += int((~in_window).sum())
        relevant = relevant[in_window]

        mechanisms = selected[
            selected["event_type"].isin(_BLOCK_EVENTS | _HANDLING_EVENTS)
        ].copy()
        if not mechanisms.empty:
            mechanisms["in_window"] = mechanisms["chunk_pos"].map(
                lambda pos: bool(window_array[int(pos)])
            )
            mechanisms = mechanisms[mechanisms["in_window"]]
        if not mechanisms.empty:
            mechanisms["numeric_ts"] = pd.to_numeric(
                mechanisms["ts"], errors="coerce"
            )
            mechanisms = mechanisms[
                mechanisms["numeric_ts"].notna()
                & np.isfinite(mechanisms["numeric_ts"])
            ]
        if not mechanisms.empty:
            disposition_name_map = {
                value: normalize_name(value)
                for value in mechanisms["query"].drop_duplicates().tolist()
            }
            mechanisms["normalized_name"] = mechanisms["query"].map(
                {value: result[0] for value, result in disposition_name_map.items()}
            )
            mechanisms = mechanisms[
                mechanisms["normalized_name"].isin(block_names)
            ]
        if not mechanisms.empty:
            mechanisms["event_day"] = pd.to_datetime(
                mechanisms["numeric_ts"], unit="s", utc=True
            ).dt.date
            grouped_disposition = mechanisms.groupby(
                ["normalized_name", "event_day", "event_type"],
                sort=False,
            ).size()
            for (name_value, day, event), count in grouped_disposition.items():
                name = str(name_value)
                add_name(state, name)
                key = (name, day)
                if key not in state.disposition:
                    if (
                        state.disposition_date_cells
                        + state.handling_date_cells
                        >= limits.name_date_cells
                    ):
                        raise FoldAbstention(
                            "dnsblock name-date cells exceed 2,000,000"
                        )
                    state.disposition[key] = Counter()
                    state.disposition_date_cells += 1
                state.disposition[key][str(event)] += int(count)

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
            queries = queries[queries["normalized_name"].notna()]

            valid_report_queries = queries[queries["in_report"]]
            state.report_query_rows += len(valid_report_queries)
            state.report_query_rows_by_address.update(
                {
                    str(address): int(count)
                    for address, count in valid_report_queries["address"]
                    .value_counts()
                    .items()
                }
            )

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
                    normalized = str(name)
                    add_name(state, normalized)
                    dates = block_dates.get(normalized, ())
                    if dates:
                        state.block_first_dates[normalized] = min(dates)
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
                state.a1_rows_by_address.update(
                    {
                        str(address): int(count)
                        for address, count in a1_queries["address"]
                        .value_counts()
                        .items()
                    }
                )
                a1_pairs = a1_queries.groupby(
                    ["address", "normalized_name"], sort=False
                )["numeric_ts"].agg(["count", "min", "max"])
                for (address, name), count, first_ts, last_ts in zip(
                    a1_pairs.index,
                    a1_pairs["count"].to_numpy(),
                    a1_pairs["min"].to_numpy(),
                    a1_pairs["max"].to_numpy(),
                ):
                    key = (str(address), str(name))
                    if (
                        key not in state.a1_pair
                        and len(state.a1_pair) >= limits.address_name_pairs
                    ):
                        raise FoldAbstention(
                            "dnsblock address-name pairs exceed 500,000"
                        )
                    cell = state.a1_pair.setdefault(key, AssocCell())
                    cell.count += int(count)
                    cell.first_ts = min(cell.first_ts, float(first_ts))
                    cell.last_ts = max(cell.last_ts, float(last_ts))
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
                if (
                    state.handling_date_cells
                    + state.disposition_date_cells
                    + len(incoming)
                    > limits.name_date_cells
                ):
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
        for key, cell in part.a1_pair.items():
            if key not in run.a1_pair and len(run.a1_pair) >= limits.address_name_pairs:
                raise FoldAbstention(
                    "dnsblock address-name pairs exceed 500,000"
                )
            target = run.a1_pair.setdefault(key, AssocCell())
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
            if (
                run.handling_date_cells
                + run.disposition_date_cells
                + len(incoming)
                > limits.name_date_cells
            ):
                raise FoldAbstention("dnsblock name-date cells exceed 2,000,000")
            target.update(incoming)
            run.handling_date_cells += len(incoming)
        for name, first_day in part.block_first_dates.items():
            run.block_first_dates[name] = min(
                run.block_first_dates.get(name, first_day), first_day
            )
        for key, counts in part.disposition.items():
            if key not in run.disposition:
                if (
                    run.disposition_date_cells
                    + run.handling_date_cells
                    >= limits.name_date_cells
                ):
                    raise FoldAbstention(
                        "dnsblock name-date cells exceed 2,000,000"
                    )
                run.disposition[key] = Counter()
                run.disposition_date_cells += 1
            run.disposition[key].update(counts)
        run.query_periods.update(part.query_periods)
        run.report_pairs.update(part.report_pairs)
        run.rows_seen += part.rows_seen
        run.rows_kept += part.rows_kept
        run.rows_suppressed += part.rows_suppressed
        if part.report_first_ts is not None:
            run.report_first_ts = (
                part.report_first_ts
                if run.report_first_ts is None
                else min(run.report_first_ts, part.report_first_ts)
            )
        if part.report_last_ts is not None:
            run.report_last_ts = (
                part.report_last_ts
                if run.report_last_ts is None
                else max(run.report_last_ts, part.report_last_ts)
            )
        run.a1_rows += part.a1_rows
        run.a2_rows += part.a2_rows
        run.report_query_rows += part.report_query_rows
        run.report_query_rows_by_address.update(part.report_query_rows_by_address)
        run.a1_rows_by_address.update(part.a1_rows_by_address)
        run.raw_window_rows += part.raw_window_rows
        run.filtered_window_rows += part.filtered_window_rows
        run.raw_query_rows += part.raw_query_rows
        run.raw_block_report_rows += part.raw_block_report_rows
        run.raw_block_context_rows += part.raw_block_context_rows
        run.filtered_block_report_rows += part.filtered_block_report_rows
        run.filtered_block_context_rows += part.filtered_block_context_rows
        _merge_counter(run.event_counts, part.event_counts)
        _merge_counter(run.drops, part.drops)
        return run

    return FoldSink(
        channel,
        lambda: FoldDelta(PopulationState(), 0),
        consume,
        PopulationState,
        commit,
        mask,
    )


def _sink_membership_masks(
    chunk: DecodedChunk,
    window: DualWindow,
) -> tuple[np.ndarray, np.ndarray]:
    """Classify one sink's exact intervals inside a broad physical read."""
    numeric = pd.to_numeric(chunk.frame["ts"], errors="coerce").to_numpy(dtype=float)
    finite = np.isfinite(numeric)
    report_start, report_end = window.report_interval
    report = (
        finite
        & (numeric >= report_start.timestamp())
        & (numeric <= report_end.timestamp())
    )
    context = np.zeros(len(chunk.frame), dtype=bool)
    if window.context_interval is not None:
        context_start, context_end = window.context_interval
        context = (
            finite
            & (numeric >= context_start.timestamp())
            & (numeric <= context_end.timestamp())
        )
    return report, context


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


def _disposition_facts(
    state: PopulationState,
    names: Iterable[str],
    limits: DnsblockLimits,
) -> DispositionFacts:
    wanted = frozenset(names)
    totals: Counter[str] = Counter()
    daily: dict[date, Counter[str]] = defaultdict(Counter)
    for (name, day), counts in state.disposition.items():
        if name not in wanted:
            continue
        totals.update(counts)
        daily[day].update(counts)
    ordered = sorted(daily.items())
    omitted = max(0, len(ordered) - limits.disposition_days)
    kept = ordered[omitted:]
    by_day = tuple(
        (
            day.isoformat(),
            int(counts["gravity_blocked"]),
            int(counts["regex_blocked"]),
            int(counts["forwarded"]),
            int(counts["cached"]),
        )
        for day, counts in kept
    )
    return DispositionFacts(
        int(totals["gravity_blocked"]),
        int(totals["regex_blocked"]),
        int(totals["forwarded"]),
        int(totals["cached"]),
        by_day,
        omitted,
    )


def _route_population(
    state: PopulationState,
    window: DualWindow,
    decision: CoverageDecision,
    limits: DnsblockLimits,
    *,
    days_required: int,
    history_required: int,
    materialize: bool,
) -> _RoutingResult:
    full_report = _full_report_periods(window)
    eligible = _covered_periods(window, decision, state.query_periods)
    eligible_report = {period for period in eligible if period < full_report}
    periods_by_name_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
    first_by_name_period: dict[tuple[str, str, int], float] = {}
    for key, cell in state.pair_period.items():
        address, name, period = key
        periods_by_name_pair[(address, name)].add(period)
        first_by_name_period[key] = cell.first_ts

    by_pair: dict[tuple[str, str], set[str]] = {}
    families: set[str] = set()
    for address, name in state.report_pairs:
        family, _unknown = _family(name)
        families.add(family)
        if len(families) > limits.families:
            raise FoldAbstention("dnsblock families exceed 50,000")
        by_pair.setdefault((address, family), set()).add(name)
        if len(by_pair) > limits.worklist:
            raise FoldAbstention("dnsblock worklist exceeds 50,000")

    name_routes: Counter[str] = Counter()
    pair_routes: Counter[str] = Counter()
    prior_names: set[str] = set()
    prior_memberships: set[tuple[str, str]] = set()
    provisional: list[
        tuple[tuple[str, str], int, tuple[str, ...], set[int], bool]
    ] = []
    max_history = 0
    for pair, pair_names in sorted(by_pair.items()):
        address, family = pair
        qualifying_names: list[str] = []
        candidate_periods: list[int] = []
        unknown_suffix = False
        for name in sorted(pair_names):
            _family_key, name_unknown = _family(name)
            unknown_suffix = unknown_suffix or name_unknown
            periods = sorted(
                period
                for period in periods_by_name_pair.get((address, name), ())
                if period < full_report
            )
            if not periods:
                name_routes[NameRoute.INELIGIBLE_NAME.value] += 1
                continue
            candidate = max(periods)
            first_associated = first_by_name_period[(address, name, candidate)]
            candidate_day = state.block_first_dates.get(
                name, _utc_date(first_associated)
            )
            handling = state.handling_dates.get(name, set())
            if any(day < candidate_day for day in handling):
                name_routes[NameRoute.PRIOR_HANDLING.value] += 1
                prior_names.add(name)
                prior_memberships.add((address, name))
                continue
            if candidate_day in handling:
                name_routes[NameRoute.SAME_DAY_AMBIGUOUS.value] += 1
                continue
            if state.pair_first.get((address, name), math.inf) < first_associated:
                name_routes[NameRoute.PRIOR_ADDRESS_QUERY.value] += 1
                continue
            name_routes[NameRoute.QUALIFYING.value] += 1
            qualifying_names.append(name)
            candidate_periods.append(candidate)
        if not qualifying_names:
            pair_routes[PairRoute.NO_QUALIFYING_NAME.value] += 1
            continue
        candidate = max(candidate_periods)
        candidate_start = window.report_interval[1] - timedelta(days=candidate + 1)
        history_count = sum(1 for period in eligible if period > candidate)
        max_history = max(max_history, history_count)
        if history_count < history_required:
            pair_routes[PairRoute.INSUFFICIENT_HISTORY.value] += 1
            continue
        if state.address_first.get(address, math.inf) >= candidate_start.timestamp():
            pair_routes[PairRoute.NO_PRIOR_ADDRESS_ACTIVITY.value] += 1
            continue
        active = {
            period
            for name in qualifying_names
            for period in periods_by_name_pair.get((address, name), ())
            if period in eligible_report
        }
        if len(active) < days_required:
            pair_routes[PairRoute.INSUFFICIENT_ACTIVE_PERIODS.value] += 1
            continue
        provisional.append(
            (pair, candidate, tuple(qualifying_names), active, unknown_suffix)
        )

    sync_groups: Counter[tuple[str, int]] = Counter(
        (family, candidate)
        for (_address, family), candidate, _names, _active, _unknown in provisional
    )
    arrivals: list[ArrivalCandidate] = []
    qualified_ids: list[str] = []
    sync_pairs = 0
    sync_addresses = 0
    first_addresses_by_name: dict[str, list[tuple[str, float]]] = defaultdict(list)
    if materialize:
        for (seen_address, seen_name), first_ts in state.pair_first.items():
            first_addresses_by_name[seen_name].append((seen_address, first_ts))
    for pair, candidate, qualifying_names, active, unknown_suffix in provisional:
        address, family = pair
        group_size = sync_groups[(family, candidate)]
        if group_size >= SYNC_ADDRESSES:
            pair_routes[PairRoute.SYNC_WITHHELD.value] += 1
            sync_pairs += 1
            sync_addresses = max(sync_addresses, group_size)
            continue
        pair_routes[PairRoute.QUALIFYING.value] += 1
        qualified_ids.append(f"{address}\0{family}")
        if not materialize:
            continue
        cells = [
            state.a1_pair[(address, name)]
            for name in qualifying_names
            if (address, name) in state.a1_pair
        ]
        attributed = sum(cell.count for cell in cells)
        first_associated = min(cell.first_ts for cell in cells)
        candidate_start = window.report_interval[1] - timedelta(days=candidate + 1)
        other_addresses: set[str] = set()
        for name in qualifying_names:
            for other_address, first_ts in first_addresses_by_name.get(name, ()):
                if (
                    other_address != address
                    and first_ts < candidate_start.timestamp()
                ):
                    other_addresses.add(other_address)
                    if len(other_addresses) >= limits.prior_addresses:
                        break
            if len(other_addresses) >= limits.prior_addresses:
                break
        at_cap = len(other_addresses) >= limits.prior_addresses
        arrivals.append(
            ArrivalCandidate(
                address=address,
                family_key=family,
                unknown_suffix=unknown_suffix,
                qualifying_names=qualifying_names,
                attributed_query_count=attributed,
                qualifying_name_count=len(qualifying_names),
                active_periods=len(active),
                eligible_periods=len(eligible_report),
                first_associated_ts=first_associated,
                prior_other_address_count=min(
                    len(other_addresses), limits.prior_addresses
                ),
                prior_other_address_count_at_cap=at_cap,
                disposition=_disposition_facts(state, qualifying_names, limits),
            )
        )
    if sum(pair_routes.values()) > limits.per_window_routes:
        raise FoldAbstention("dnsblock per-window routes exceed 1,000,000")
    if sum(pair_routes.values()) != len(by_pair):
        raise ValueError("dnsblock pair routing did not conserve its worklist")
    return _RoutingResult(
        name_routes,
        pair_routes,
        tuple(arrivals),
        tuple(sorted(qualified_ids)),
        frozenset(prior_names),
        frozenset(prior_memberships),
        max_history,
        sync_pairs,
        sync_addresses,
    )


def _population_facts(
    state: PopulationState,
    window: DualWindow,
    decision: CoverageDecision,
    limits: DnsblockLimits,
    *,
    selected_days: int = ARRIVAL_DAYS,
    selected_history: int = ARRIVAL_HISTORY,
    calibration_memberships: dict[str, int] | None = None,
) -> tuple[Counter[str], tuple[GridFacts, ...]]:
    actual_routes: Counter[str] = Counter()
    grids: list[GridFacts] = []
    cell_index = 0
    for days_required in _GRID_DAYS:
        for history_required in _GRID_CHANNEL:
            routed = _route_population(
                state,
                window,
                decision,
                limits,
                days_required=days_required,
                history_required=history_required,
                materialize=False,
            )
            if (
                days_required == selected_days
                and history_required == selected_history
            ):
                actual_routes = routed.name_routes
            if calibration_memberships is not None:
                bit = 1 << cell_index
                for identity in routed.qualified_ids:
                    calibration_memberships[identity] = (
                        calibration_memberships.get(identity, 0) | bit
                    )
            digest = hashlib.sha256(
                json.dumps(routed.qualified_ids, separators=(",", ":")).encode()
            ).hexdigest()
            grids.append(
                GridFacts(
                    days_required,
                    history_required,
                    tuple(sorted(routed.pair_routes.items())),
                    len(routed.qualified_ids),
                    digest,
                )
            )
            cell_index += 1
    return actual_routes, tuple(grids)


def _median_twice(values: Iterable[int]) -> int:
    ordered = sorted(int(value) for value in values)
    if not ordered:
        raise ValueError("dnsblock burst baseline is empty")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return 2 * ordered[middle]
    return ordered[middle - 1] + ordered[middle]


def _report_family_names(
    state: PopulationState,
    limits: DnsblockLimits,
) -> dict[tuple[str, str], set[str]]:
    grouped: dict[tuple[str, str], set[str]] = {}
    for address, name in state.report_pairs:
        pair = (address, _family(name)[0])
        grouped.setdefault(pair, set()).add(name)
        if len(grouped) > limits.worklist:
            raise FoldAbstention("dnsblock worklist exceeds 50,000")
    return grouped


def _burst_route(
    period_counts: Mapping[int, int],
    eligible_periods: set[int],
    *,
    absolute_required: int,
    multiple_required: int,
    active_required: int,
) -> tuple[BurstRoute, tuple[int, int, int] | None]:
    active = {
        period: int(period_counts.get(period, 0))
        for period in eligible_periods
        if int(period_counts.get(period, 0)) > 0
    }
    if len(active) < active_required:
        return BurstRoute.INSUFFICIENT_ACTIVE_PERIODS, None
    peak_count = max(active.values())
    # Period zero is newest.  The largest tied index is therefore the earliest
    # instant in wall-clock time, independent of dictionary/input orientation.
    peak_period = max(
        period for period, count in active.items() if count == peak_count
    )
    baseline_twice = _median_twice(
        count for period, count in active.items() if period != peak_period
    )
    facts = (peak_period, peak_count, baseline_twice)
    if peak_count < absolute_required:
        return BurstRoute.BELOW_ABSOLUTE_PEAK, facts
    if 2 * peak_count < multiple_required * baseline_twice:
        return BurstRoute.BELOW_PEAK_MULTIPLE, facts
    return BurstRoute.QUALIFYING, facts


def _build_burst_facts(
    state: PopulationState,
    window: DualWindow,
    coverage: CoverageDecision,
    limits: DnsblockLimits,
    *,
    selected_absolute: int = BURST_ABS,
    selected_multiple: int = BURST_MULT,
    selected_active: int = BURST_ACTIVE,
    materialize: bool = True,
    calibration_memberships: dict[str, int] | None = None,
) -> tuple[tuple[BurstGridFacts, ...], tuple[BurstCandidate, ...], ChannelFacts]:
    full_report = _full_report_periods(window)
    eligible_report = {
        period
        for period in _covered_periods(window, coverage, state.query_periods)
        if period < full_report
    }
    if coverage.lane is CoverageLane.WEAK:
        return (
            (),
            (),
            ChannelFacts(
                ChannelStatus.ABSTAINED,
                "weak_coverage",
                selected_active,
                len(eligible_report),
            ),
        )

    pair_names = _report_family_names(state, limits)
    counts: dict[tuple[str, str], Counter[int]] = {
        pair: Counter() for pair in pair_names
    }
    association_names: dict[tuple[str, str], set[str]] = defaultdict(set)
    for (address, name), _cell in state.a1_pair.items():
        association_names[(address, _family(name)[0])].add(name)
    for (address, name, period), cell in state.pair_period.items():
        pair = (address, _family(name)[0])
        if pair in counts and period < full_report:
            counts[pair][period] += cell.count

    grids: list[BurstGridFacts] = []
    candidates: list[BurstCandidate] = []
    channel = ChannelFacts(
        (
            ChannelStatus.READY
            if len(eligible_report) >= selected_active
            else ChannelStatus.ABSTAINED
        ),
        "" if len(eligible_report) >= selected_active else "insufficient_coverage",
        selected_active,
        len(eligible_report),
    )
    cell_index = 0
    for absolute_required in _BURST_GRID_ABS:
        for multiple_required in _BURST_GRID_MULT:
            for active_required in _BURST_GRID_ACTIVE:
                routes: Counter[str] = Counter()
                qualified: list[str] = []
                for pair in sorted(pair_names):
                    route, route_facts = _burst_route(
                        counts[pair],
                        eligible_report,
                        absolute_required=absolute_required,
                        multiple_required=multiple_required,
                        active_required=active_required,
                    )
                    routes[route.value] += 1
                    if route is not BurstRoute.QUALIFYING:
                        continue
                    address, family = pair
                    qualified.append(f"{address}\0{family}")
                    if (
                        not materialize
                        or absolute_required != selected_absolute
                        or multiple_required != selected_multiple
                        or active_required != selected_active
                        or channel.status is not ChannelStatus.READY
                    ):
                        continue
                    assert route_facts is not None
                    peak_period, peak_count, baseline_twice = route_facts
                    names = tuple(sorted(association_names.get(pair, ())))
                    candidates.append(
                        BurstCandidate(
                            address=address,
                            family_key=family,
                            unknown_suffix=any(_family(name)[1] for name in names),
                            peak_count=peak_count,
                            peak_period_start=(
                                window.report_interval[1]
                                - timedelta(days=peak_period + 1)
                            ).timestamp(),
                            baseline_median_twice=baseline_twice,
                            active_periods=sum(
                                1
                                for period in eligible_report
                                if counts[pair].get(period, 0) > 0
                            ),
                            eligible_periods=len(eligible_report),
                            attributed_query_count=sum(
                                state.a1_pair[(address, name)].count
                                for name in names
                                if (address, name) in state.a1_pair
                            ),
                            disposition=_disposition_facts(state, names, limits),
                            association_names=names,
                        )
                    )
                if calibration_memberships is not None:
                    bit = 1 << cell_index
                    for identity in qualified:
                        calibration_memberships[identity] = (
                            calibration_memberships.get(identity, 0) | bit
                        )
                if sum(routes.values()) != len(pair_names):
                    raise ValueError("dnsblock burst routing did not conserve its worklist")
                digest = hashlib.sha256(
                    json.dumps(tuple(qualified), separators=(",", ":")).encode()
                ).hexdigest()
                grids.append(
                    BurstGridFacts(
                        absolute_required,
                        multiple_required,
                        active_required,
                        tuple((route.value, routes[route.value]) for route in BurstRoute),
                        len(qualified),
                        digest,
                    )
                )
                cell_index += 1
    if len(grids) != 75:
        raise ValueError("dnsblock burst grid did not evaluate all 75 cells")
    return tuple(grids), tuple(candidates), channel


def _build_recurring_facts(
    state: PopulationState,
    window: DualWindow,
    coverage: CoverageDecision,
    surfaced: set[tuple[str, str]],
    limits: DnsblockLimits,
) -> RecurringFacts:
    full_report = _full_report_periods(window)
    eligible_report = {
        period
        for period in _covered_periods(window, coverage, state.query_periods)
        if period < full_report
    }
    if coverage.lane is CoverageLane.WEAK:
        return RecurringFacts(
            ChannelStatus.ABSTAINED,
            "weak_coverage",
            RECURRING_PERIODS,
            full_report,
            len(eligible_report),
            max(0, full_report - len(eligible_report)),
            0,
            0,
            0,
        )
    if full_report < RECURRING_PERIODS:
        return RecurringFacts(
            ChannelStatus.ABSTAINED,
            "insufficient_report_span",
            RECURRING_PERIODS,
            full_report,
            len(eligible_report),
            max(0, full_report - len(eligible_report)),
            0,
            0,
            0,
        )
    missing = len(set(range(full_report)) - eligible_report)
    if missing:
        return RecurringFacts(
            ChannelStatus.ABSTAINED,
            "incomplete_strong_coverage",
            RECURRING_PERIODS,
            full_report,
            len(eligible_report),
            missing,
            0,
            0,
            0,
        )

    active: dict[tuple[str, str], set[int]] = defaultdict(set)
    report_pairs = _report_family_names(state, limits)
    for (address, name, period), cell in state.pair_period.items():
        pair = (address, _family(name)[0])
        if pair in report_pairs and period < full_report and cell.count > 0:
            active[pair].add(period)
    recurring = {
        pair
        for pair, periods in active.items()
        if pair not in surfaced and len(periods) >= RECURRING_PERIODS
    }
    return RecurringFacts(
        ChannelStatus.READY,
        "",
        RECURRING_PERIODS,
        full_report,
        len(eligible_report),
        0,
        len(recurring),
        len({family for _address, family in recurring}),
        len({address for address, _family_key in recurring}),
    )


def _build_analysis(
    state: PopulationState,
    window: DualWindow,
    coverage: CoverageDecision,
    limits: DnsblockLimits,
    vector: DnsblockCalibrationVector,
    *,
    burst_calibration_memberships: dict[str, int] | None = None,
) -> AnalysisFacts:
    routed = _route_population(
        state,
        window,
        coverage,
        limits,
        days_required=vector.arrival_days,
        history_required=vector.arrival_history,
        materialize=True,
    )
    burst_grids, raw_bursts, burst_channel = _build_burst_facts(
        state,
        window,
        coverage,
        limits,
        selected_absolute=vector.burst_absolute,
        selected_multiple=vector.burst_multiple,
        selected_active=vector.burst_active,
        materialize=vector.burst_enabled,
        calibration_memberships=burst_calibration_memberships,
    )
    arrivals_by_pair = {
        (item.address, item.family_key): item for item in routed.arrivals
    }
    bursts: list[BurstCandidate] = []
    burst_pairs: set[tuple[str, str]] = set()
    for burst in raw_bursts:
        pair = (burst.address, burst.family_key)
        burst_pairs.add(pair)
        arrival = arrivals_by_pair.get(pair)
        if arrival is None:
            bursts.append(burst)
            continue
        bursts.append(
            replace(
                burst,
                arrival_subset=ArrivalSubsetFacts(
                    "first_available_history",
                    arrival.first_associated_ts,
                    arrival.active_periods,
                    arrival.eligible_periods,
                    arrival.prior_other_address_count,
                    arrival.prior_other_address_count_at_cap,
                    arrival.attributed_query_count,
                    arrival.qualifying_name_count,
                ),
            )
        )
    pure_arrivals = tuple(
        item
        for item in routed.arrivals
        if (item.address, item.family_key) not in burst_pairs
    )
    pure_arrival_pairs = {
        (item.address, item.family_key) for item in pure_arrivals
    }
    all_pairs = set(_report_family_names(state, limits))
    final_routes: Counter[str] = Counter()
    for pair in all_pairs:
        arrival = pair in arrivals_by_pair
        burst = pair in burst_pairs
        if arrival and burst:
            final_routes["overlap_burst_wins"] += 1
        elif burst:
            final_routes["burst_only"] += 1
        elif arrival:
            final_routes["arrival_only"] += 1
        else:
            final_routes["neither"] += 1
    if sum(final_routes.values()) != len(all_pairs):
        raise ValueError("dnsblock final primary-shape routing did not conserve its worklist")

    arrivals_by_address: Counter[str] = Counter(
        item.address for item in pure_arrivals
    )
    entity_count = len(bursts) + sum(
        1 if count >= FOLD_MIN_MEMBERS else count
        for count in arrivals_by_address.values()
    )
    surfaced = burst_pairs | pure_arrival_pairs
    recurring = _build_recurring_facts(
        state, window, coverage, surfaced, limits
    )
    # The measured recurring context row is always constructed.  Reading
    # surfaces hide a no-entity row at the default level.
    recurring_row = bool(recurring.pair_count)
    context_count = int(bool(routed.prior_handling_names)) + int(recurring_row)
    if entity_count + context_count > limits.findings:
        raise FoldAbstention("dnsblock findings exceed 1,000")
    full_report = _full_report_periods(window)
    eligible_report = {
        period
        for period in _covered_periods(window, coverage, state.query_periods)
        if period < full_report
    }
    pair_routes = routed.pair_routes
    insufficient_history = int(
        pair_routes[PairRoute.INSUFFICIENT_HISTORY.value]
    )
    insufficient_context = None
    if insufficient_history and routed.max_history_periods < vector.arrival_history:
        # The whole-channel form is reserved for a truly degenerate prefix.  If
        # any pair got beyond history, the per-candidate count remains honest.
        beyond_history = sum(
            count
            for route, count in pair_routes.items()
            if route
            not in {
                PairRoute.NO_QUALIFYING_NAME.value,
                PairRoute.INSUFFICIENT_HISTORY.value,
            }
        )
        if beyond_history == 0:
            insufficient_context = routed.max_history_periods
            insufficient_history = 0
    notes = DnsblockNoteFacts(
        coverage_lane=coverage.lane,
        arrival_days_required=vector.arrival_days,
        arrival_history_required=vector.arrival_history,
        insufficient_history_pairs=insufficient_history,
        insufficient_context_periods=insufficient_context,
        insufficient_arrival_coverage=(
            len(eligible_report)
            if state.report_pairs and len(eligible_report) < vector.arrival_days
            else None
        ),
        burst_status=burst_channel.status,
        burst_cause=burst_channel.cause,
        burst_active_required=burst_channel.periods_required,
        burst_eligible_periods=burst_channel.eligible_periods,
        recurring_status=recurring.status,
        recurring_cause=recurring.cause,
        recurring_periods_required=recurring.periods_required,
        recurring_periods_total=recurring.periods_total,
        recurring_missing_periods=recurring.missing_periods,
        synchronized_pairs=routed.synchronized_pairs,
        synchronized_addresses=routed.synchronized_addresses,
        raw_window_rows=state.raw_window_rows,
        filtered_window_rows=state.filtered_window_rows,
        raw_query_rows=state.raw_query_rows,
        raw_block_report_rows=state.raw_block_report_rows,
        raw_block_context_rows=state.raw_block_context_rows,
        filtered_block_report_rows=state.filtered_block_report_rows,
        filtered_block_context_rows=state.filtered_block_context_rows,
        entity_findings=entity_count,
        context_findings=context_count,
    )
    return AnalysisFacts(
        arrivals=pure_arrivals,
        bursts=tuple(bursts),
        burst_grids=burst_grids,
        burst_channel=burst_channel,
        recurring=recurring,
        final_shape_routes=tuple(
            (route, final_routes[route])
            for route in (
                "burst_only",
                "arrival_only",
                "overlap_burst_wins",
                "neither",
            )
        ),
        withheld_arrival_burst_pairs=sum(
            1 for pair in burst_pairs if pair not in arrivals_by_pair
        ),
        cadence_worklist=tuple(sorted(surfaced)),
        cadence_query_event_upper_bounds=tuple(
            (
                address,
                family,
                int(state.report_query_rows_by_address.get(address, 0)),
            )
            for address, family in sorted(surfaced)
        ),
        pair_routes=tuple(sorted(pair_routes.items())),
        prior_handling_names=len(routed.prior_handling_names),
        prior_handling_memberships=len(routed.prior_handling_memberships),
        report_query_rows=state.report_query_rows,
        report_query_rows_by_address=tuple(
            sorted(state.report_query_rows_by_address.items())
        ),
        a1_rows=state.a1_rows,
        a1_rows_by_address=tuple(sorted(state.a1_rows_by_address.items())),
        notes=notes,
    )


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
    calibration_vector: DnsblockCalibrationVector | None = None,
    summary_population: PopulationState | None = None,
    data_size_bytes: int = 0,
    limits: DnsblockLimits = LIMITS,
) -> DnsblockPrepared:
    vector = calibration_vector or DnsblockCalibrationVector()
    if not isinstance(vector, DnsblockCalibrationVector):
        raise ValueError("dnsblock calibration vector has the wrong type")
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
        return DnsblockPrepared(facts, cadence_complete=True)
    if population.a1_rows > population.a2_rows:
        raise ValueError("dnsblock A1 population is not a subset of A2")
    try:
        arrival_memberships = {} if calibration_vector is not None else None
        burst_memberships = {} if calibration_vector is not None else None
        name_routes, grids = _population_facts(
            population,
            window,
            coverage,
            limits,
            selected_days=vector.arrival_days,
            selected_history=vector.arrival_history,
            calibration_memberships=arrival_memberships,
        )
        analysis = _build_analysis(
            population,
            window,
            coverage,
            limits,
            vector,
            burst_calibration_memberships=burst_memberships,
        )
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
        return DnsblockPrepared(facts, cadence_complete=True)
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
        (
            (
                datetime.fromtimestamp(summary_population.report_first_ts, timezone.utc),
                datetime.fromtimestamp(summary_population.report_last_ts, timezone.utc),
            )
            if summary_population is not None
            and summary_population.report_first_ts is not None
            and summary_population.report_last_ts is not None
            else None
        ),
        data_size_bytes,
    )
    return DnsblockPrepared(
        facts,
        analysis=analysis,
        cadence_complete=not analysis.cadence_worklist,
        calibration_survivors=(
            CalibrationSurvivorFacts(
                tuple(sorted(arrival_memberships.items())),
                tuple(sorted(burst_memberships.items())),
            )
            if arrival_memberships is not None and burst_memberships is not None
            else None
        ),
    )


def make_cadence_sink(
    pair: tuple[str, str],
    inventory: BlockInventory,
    mask: Callable[[pd.DataFrame], PositionalMask],
    *,
    window: DualWindow | None = None,
    channel: str = "dnsblock.cadence",
    limits: DnsblockLimits = LIMITS,
) -> FoldSink:
    """Collect exact included gaps for one surfaced address-family pair."""
    address_wanted, family_wanted = pair
    block_membership = frozenset(
        (name, day)
        for name, days in inventory.block_dates.items()
        for day in days
    )

    def append_gap(state: CadenceState, gap: float) -> None:
        if not (0 <= gap < _CADENCE_MAX_GAP_SECONDS):
            return
        if len(state.included_gaps) >= limits.cadence_gaps:
            raise FoldAbstention("dnsblock cadence gaps exceed 10,000")
        state.included_gaps.append(gap)

    def consume(
        delta: FoldDelta,
        chunk: DecodedChunk,
        keep_mask: PositionalMask,
    ) -> FoldDelta:
        state: CadenceState = delta.value
        if chunk.frame.empty:
            return FoldDelta(state, 64 + len(state.included_gaps) * 8)
        report_mask = (
            _sink_membership_masks(chunk, window)[0]
            if window is not None
            else np.asarray(chunk.report_mask, dtype=bool)
        )
        selected_positions = [
            pos
            for pos, (kept, report) in enumerate(
                zip(keep_mask.keep, report_mask)
            )
            if kept and report
        ]
        selected = chunk.frame.iloc[selected_positions]
        selected = selected[selected["event_type"] == "query"].copy()
        if selected.empty:
            return FoldDelta(state, 64 + len(state.included_gaps) * 8)
        selected["numeric_ts"] = pd.to_numeric(selected["ts"], errors="coerce")
        selected = selected[
            selected["numeric_ts"].notna() & np.isfinite(selected["numeric_ts"])
        ]
        if selected.empty:
            return FoldDelta(state, 64 + len(state.included_gaps) * 8)
        address_map = {
            value: normalize_address(value)
            for value in selected["src"].drop_duplicates().tolist()
        }
        name_map = {
            value: normalize_name(value)
            for value in selected["query"].drop_duplicates().tolist()
        }
        selected["address"] = selected["src"].map(
            {value: result[0] for value, result in address_map.items()}
        )
        selected["name"] = selected["query"].map(
            {value: result[0] for value, result in name_map.items()}
        )
        selected = selected[
            (selected["address"] == address_wanted) & selected["name"].notna()
        ]
        if selected.empty:
            return FoldDelta(state, 64 + len(state.included_gaps) * 8)
        selected["day"] = pd.to_datetime(
            selected["numeric_ts"], unit="s", utc=True
        ).dt.date
        selected = selected[
            [
                (str(name), day) in block_membership
                and _family(str(name))[0] == family_wanted
                for name, day in zip(selected["name"], selected["day"])
            ]
        ]
        for ts in sorted(float(value) for value in selected["numeric_ts"]):
            if state.last_ts is not None:
                if ts < state.last_ts:
                    raise ValueError("dnsblock cadence rows are not chronological within a file")
                append_gap(state, ts - state.last_ts)
            if state.first_ts is None:
                state.first_ts = ts
            state.last_ts = ts
        return FoldDelta(state, 64 + len(state.included_gaps) * 8)

    def commit(run: CadenceState, delta: FoldDelta) -> CadenceState:
        part: CadenceState = delta.value
        if part.first_ts is None:
            return run
        if run.first_ts is None:
            run.first_ts = part.first_ts
            run.last_ts = part.last_ts
            run.included_gaps.extend(part.included_gaps)
            return run
        assert part.last_ts is not None and run.first_ts is not None
        if part.last_ts > run.first_ts:
            raise ValueError("dnsblock cadence source files overlap or are out of order")
        combined = list(part.included_gaps)
        boundary = run.first_ts - part.last_ts
        if 0 <= boundary < _CADENCE_MAX_GAP_SECONDS:
            if len(combined) + len(run.included_gaps) >= limits.cadence_gaps:
                raise FoldAbstention("dnsblock cadence gaps exceed 10,000")
            combined.append(boundary)
        if len(combined) + len(run.included_gaps) > limits.cadence_gaps:
            raise FoldAbstention("dnsblock cadence gaps exceed 10,000")
        combined.extend(run.included_gaps)
        run.first_ts = part.first_ts
        run.included_gaps = combined
        return run

    return FoldSink(
        channel,
        lambda: FoldDelta(CadenceState(), 0),
        consume,
        CadenceState,
        commit,
        mask,
    )


def make_cadence_batch_sink(
    pairs: tuple[tuple[str, str], ...],
    inventory: BlockInventory,
    mask: Callable[[pd.DataFrame], PositionalMask],
    *,
    window: DualWindow | None = None,
    channel: str = "dnsblock.cadence_batch",
    limits: DnsblockLimits = LIMITS,
) -> FoldSink:
    """Collect cadence for a bounded pair batch in one physical source scan.

    The runner admits a batch only when the sum of its query-event upper bounds
    is at most ``limits.cadence_gaps``.  This reducer independently enforces the
    existing per-pair cap and the same total in-flight cap as a second line of
    defense; it never combines one pair's gap series with another's.
    """
    ordered_pairs = tuple(sorted(pairs))
    if not ordered_pairs or len(ordered_pairs) != len(set(ordered_pairs)):
        raise ValueError("dnsblock cadence batch pairs must be unique and non-empty")
    wanted = frozenset(ordered_pairs)
    wanted_addresses = frozenset(address for address, _family_key in ordered_pairs)
    block_membership = frozenset(
        (name, day)
        for name, days in inventory.block_dates.items()
        for day in days
    )

    def resident(state: CadenceBatchState) -> int:
        return 64 * len(state.states) + 8 * sum(
            len(item.included_gaps) for item in state.states.values()
        )

    def enforce_total(state: CadenceBatchState) -> None:
        if sum(len(item.included_gaps) for item in state.states.values()) > limits.cadence_gaps:
            raise FoldAbstention("dnsblock cadence gaps exceed 10,000")

    def append_gap(state: CadenceState, gap: float) -> None:
        if not (0 <= gap < _CADENCE_MAX_GAP_SECONDS):
            return
        if len(state.included_gaps) >= limits.cadence_gaps:
            raise FoldAbstention("dnsblock cadence gaps exceed 10,000")
        state.included_gaps.append(gap)

    def consume(
        delta: FoldDelta,
        chunk: DecodedChunk,
        keep_mask: PositionalMask,
    ) -> FoldDelta:
        batch: CadenceBatchState = delta.value
        if chunk.frame.empty:
            return FoldDelta(batch, resident(batch))
        report_mask = (
            _sink_membership_masks(chunk, window)[0]
            if window is not None
            else np.asarray(chunk.report_mask, dtype=bool)
        )
        positions = [
            pos
            for pos, (kept, report) in enumerate(
                zip(keep_mask.keep, report_mask)
            )
            if kept and report
        ]
        selected = chunk.frame.iloc[positions]
        selected = selected[selected["event_type"] == "query"].copy()
        if selected.empty:
            return FoldDelta(batch, resident(batch))
        selected["numeric_ts"] = pd.to_numeric(selected["ts"], errors="coerce")
        selected = selected[
            selected["numeric_ts"].notna() & np.isfinite(selected["numeric_ts"])
        ]
        if selected.empty:
            return FoldDelta(batch, resident(batch))
        address_map = {
            value: normalize_address(value)
            for value in selected["src"].drop_duplicates().tolist()
        }
        name_map = {
            value: normalize_name(value)
            for value in selected["query"].drop_duplicates().tolist()
        }
        selected["address"] = selected["src"].map(
            {value: result[0] for value, result in address_map.items()}
        )
        selected["name"] = selected["query"].map(
            {value: result[0] for value, result in name_map.items()}
        )
        selected = selected[
            selected["address"].isin(wanted_addresses) & selected["name"].notna()
        ]
        if selected.empty:
            return FoldDelta(batch, resident(batch))
        selected["day"] = pd.to_datetime(
            selected["numeric_ts"], unit="s", utc=True
        ).dt.date
        selected["family"] = selected["name"].map(lambda value: _family(str(value))[0])
        selected = selected[
            [
                (str(address), str(family)) in wanted
                and (str(name), day) in block_membership
                for address, family, name, day in zip(
                    selected["address"],
                    selected["family"],
                    selected["name"],
                    selected["day"],
                )
            ]
        ]
        for (address, family), frame in selected.groupby(
            ["address", "family"], sort=False
        ):
            key = (str(address), str(family))
            state = batch.states.setdefault(key, CadenceState())
            for ts in sorted(float(value) for value in frame["numeric_ts"]):
                if state.last_ts is not None:
                    if ts < state.last_ts:
                        raise ValueError(
                            "dnsblock cadence rows are not chronological within a file"
                        )
                    append_gap(state, ts - state.last_ts)
                if state.first_ts is None:
                    state.first_ts = ts
                state.last_ts = ts
        enforce_total(batch)
        return FoldDelta(batch, resident(batch))

    def commit(run: CadenceBatchState, delta: FoldDelta) -> CadenceBatchState:
        part: CadenceBatchState = delta.value
        for pair, incoming in part.states.items():
            if incoming.first_ts is None:
                continue
            state = run.states.setdefault(pair, CadenceState())
            if state.first_ts is None:
                state.first_ts = incoming.first_ts
                state.last_ts = incoming.last_ts
                state.included_gaps.extend(incoming.included_gaps)
                continue
            assert incoming.last_ts is not None and state.first_ts is not None
            if incoming.last_ts > state.first_ts:
                raise ValueError(
                    "dnsblock cadence source files overlap or are out of order"
                )
            combined = list(incoming.included_gaps)
            boundary = state.first_ts - incoming.last_ts
            if 0 <= boundary < _CADENCE_MAX_GAP_SECONDS:
                if len(combined) + len(state.included_gaps) >= limits.cadence_gaps:
                    raise FoldAbstention("dnsblock cadence gaps exceed 10,000")
                combined.append(boundary)
            if len(combined) + len(state.included_gaps) > limits.cadence_gaps:
                raise FoldAbstention("dnsblock cadence gaps exceed 10,000")
            combined.extend(state.included_gaps)
            state.first_ts = incoming.first_ts
            state.included_gaps = combined
        enforce_total(run)
        return run

    return FoldSink(
        channel,
        lambda: FoldDelta(CadenceBatchState(), 0),
        consume,
        CadenceBatchState,
        commit,
        mask,
    )


def _cadence_facts(state: CadenceState) -> CadenceFacts:
    gaps = np.asarray(state.included_gaps, dtype=float)
    if gaps.size < 20:
        return CadenceFacts(False, None, None, None)
    mean = float(gaps.mean())
    cv = 0.0 if mean == 0 else float(gaps.std(ddof=0) / mean)
    return CadenceFacts(True, int(gaps.size), cv, float(np.median(gaps)))


def finalize_cadence(
    prepared: DnsblockPrepared,
    *,
    status: PreparedStatus,
    results: Mapping[tuple[str, str], CadenceState],
    pass_wall_seconds: tuple[tuple[str, float], ...],
) -> DnsblockPrepared:
    if prepared.analysis is None or prepared.preflight.state is not PreparedState.READY:
        return replace(prepared, cadence_complete=True)
    updated_preflight = replace(
        prepared.preflight,
        pass_wall_seconds=pass_wall_seconds,
    )
    if status.state is not PreparedState.READY:
        updated_preflight = replace(
            updated_preflight,
            state=status.state,
            cause=status.cause or "dnsblock cadence preparation unavailable",
            name_routes=(),
            grids=(),
        )
        return DnsblockPrepared(
            updated_preflight,
            cadence_complete=True,
            calibration_survivors=prepared.calibration_survivors,
        )
    missing = set(prepared.analysis.cadence_worklist) - set(results)
    if missing:
        raise ValueError("dnsblock cadence enrichment did not conserve its worklist")
    cadence = tuple(
        (address, family, _cadence_facts(results[(address, family)]))
        for address, family in prepared.analysis.cadence_worklist
    )
    return DnsblockPrepared(
        updated_preflight,
        analysis=prepared.analysis,
        cadence=cadence,
        cadence_complete=True,
        calibration_survivors=prepared.calibration_survivors,
    )


def _disposition_evidence(
    disposition: DispositionFacts,
    grain: str,
) -> dict[str, Any]:
    return {
        "gravity_blocked": disposition.gravity_blocked,
        "regex_blocked": disposition.regex_blocked,
        "forwarded": disposition.forwarded,
        "cached": disposition.cached,
        "disposition_grain": grain,
        "disposition_by_day": [
            {
                "date": day,
                "gravity_blocked": gravity,
                "regex_blocked": regex,
                "forwarded": forwarded,
                "cached": cached,
            }
            for day, gravity, regex, forwarded, cached in disposition.by_day
        ],
        "disposition_by_day_omitted": disposition.by_day_omitted,
    }


def _cadence_evidence(facts: CadenceFacts) -> dict[str, Any]:
    return {
        "cadence_available": facts.cadence_available,
        "gap_count": facts.gap_count,
        "gap_cv": facts.gap_cv,
        "gap_median_s": facts.gap_median_s,
    }


def _merge_dispositions(
    candidates: Iterable[ArrivalCandidate],
    *,
    day_limit: int,
) -> DispositionFacts:
    totals: Counter[str] = Counter()
    days: dict[str, Counter[str]] = defaultdict(Counter)
    for candidate in candidates:
        facts = candidate.disposition
        totals.update(
            {
                "gravity_blocked": facts.gravity_blocked,
                "regex_blocked": facts.regex_blocked,
                "forwarded": facts.forwarded,
                "cached": facts.cached,
            }
        )
        for day, gravity, regex, forwarded, cached in facts.by_day:
            days[day].update(
                {
                    "gravity_blocked": gravity,
                    "regex_blocked": regex,
                    "forwarded": forwarded,
                    "cached": cached,
                }
            )
    ordered = sorted(days.items())
    omitted = max(0, len(ordered) - day_limit)
    return DispositionFacts(
        totals["gravity_blocked"],
        totals["regex_blocked"],
        totals["forwarded"],
        totals["cached"],
        tuple(
            (
                day,
                counts["gravity_blocked"],
                counts["regex_blocked"],
                counts["forwarded"],
                counts["cached"],
            )
            for day, counts in ordered[omitted:]
        ),
        omitted,
    )


def run(
    context: DetectorContext,
    *,
    _prepared: DnsblockPrepared | None = None,
) -> list[Finding]:
    """Construct burst, arrival/fold, and identity-free context findings."""
    if not isinstance(_prepared, DnsblockPrepared):
        raise ValueError("dnsblock requires runner-prepared preflight")
    if _prepared.preflight.state is PreparedState.ABSTAINED:
        return []
    if _prepared.preflight.state is PreparedState.FAILED:
        raise ValueError(_prepared.preflight.cause)
    if _prepared.analysis is None:
        return []
    if not _prepared.cadence_complete:
        raise ValueError("dnsblock requires runner-prepared cadence enrichment")

    analysis = _prepared.analysis
    cadence = {
        (address, family): facts
        for address, family, facts in _prepared.cadence
    }
    report_counts = dict(analysis.report_query_rows_by_address)
    a1_counts = dict(analysis.a1_rows_by_address)
    distinct_report_addresses = sum(1 for count in report_counts.values() if count > 0)
    now = datetime.now(timezone.utc)
    window = _prepared.preflight.report_interval

    def iso(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def cadence_for(candidate: ArrivalCandidate | BurstCandidate) -> CadenceFacts:
        try:
            return cadence[(candidate.address, candidate.family_key)]
        except KeyError as exc:
            raise ValueError("dnsblock cadence facts missing for surfaced pair") from exc

    def next_steps(address: str, family: str, first: str) -> list[str]:
        return [
            f"Identify the address owner or forwarder behind {address}",
            f"Inspect this address's blocked queries grouped under {family} around {first}",
            "If this activity is expected, review `sigwood allowlist` and add only the exact name patterns you intend to suppress",
        ]

    ordered: list[tuple[float, str, str, Finding]] = []
    burst_ordered: list[tuple[int, float, str, str, Finding]] = []
    for candidate in analysis.bursts:
        peak_iso = iso(candidate.peak_period_start)
        if candidate.baseline_median_twice % 2:
            median_text = f"{candidate.baseline_median_twice // 2}.5"
        else:
            median_text = str(candidate.baseline_median_twice // 2)
        evidence: dict[str, Any] = {
            "kind": "burst",
            "coverage_lane": CoverageLane.STRONG.value,
            "address": candidate.address,
            "family_key": candidate.family_key,
            "peak_count": candidate.peak_count,
            "peak_period_start": peak_iso,
            "baseline_median_twice": candidate.baseline_median_twice,
            "multiplier_numerator": candidate.peak_count,
            "multiplier_denominator_twice": candidate.baseline_median_twice,
            "active_periods": candidate.active_periods,
            "eligible_periods": candidate.eligible_periods,
            "attributed_query_count": candidate.attributed_query_count,
            "arrival_qualified": candidate.arrival_subset is not None,
        }
        if candidate.unknown_suffix:
            evidence["unknown_suffix"] = True
        if candidate.arrival_subset is not None:
            subset = candidate.arrival_subset
            evidence["arrival_subset"] = {
                "novelty_noun": subset.novelty_noun,
                "first_associated_period": iso(subset.first_associated_ts),
                "active_periods": subset.active_periods,
                "eligible_periods": subset.eligible_periods,
                "prior_other_address_count": subset.prior_other_address_count,
                "prior_other_address_count_at_cap": (
                    subset.prior_other_address_count_at_cap
                ),
                "arrival_attributed_query_count": (
                    subset.arrival_attributed_query_count
                ),
                "arrival_qualifying_name_count": (
                    subset.arrival_qualifying_name_count
                ),
            }
        evidence.update(
            _disposition_evidence(
                candidate.disposition,
                "global_events_over_association_qualified_names",
            )
        )
        evidence.update(_cadence_evidence(cadence_for(candidate)))
        finding = Finding(
            detector=DETECTOR_NAME,
            severity=Severity.LOW,
            title=f"{candidate.address} → {candidate.family_key}",
            description=(
                "Queries for blocked-logged names from this address peaked at "
                f"{candidate.peak_count} in one 24-hour period against a median "
                f"of {median_text} across its other active periods."
            ),
            evidence=evidence,
            next_steps=next_steps(
                candidate.address, candidate.family_key, peak_iso
            ),
            ts_generated=now,
            data_window=window,
        )
        burst_ordered.append(
            (
                -candidate.peak_count,
                candidate.peak_period_start,
                candidate.address,
                candidate.family_key,
                finding,
            )
        )
    by_address: dict[str, list[ArrivalCandidate]] = defaultdict(list)
    for candidate in analysis.arrivals:
        by_address[candidate.address].append(candidate)

    for address, candidates in sorted(by_address.items()):
        candidates = sorted(
            candidates,
            key=lambda item: (item.first_associated_ts, item.family_key),
        )
        if len(candidates) >= FOLD_MIN_MEMBERS:
            first_ts = min(item.first_associated_ts for item in candidates)
            first_iso = iso(first_ts)
            kept = candidates[:LIMITS.fold_members]
            members = []
            for member in kept:
                member_evidence: dict[str, Any] = {
                    "family_key": member.family_key,
                    "first_associated_period": iso(member.first_associated_ts),
                    "attributed_query_count": member.attributed_query_count,
                    "qualifying_name_count": member.qualifying_name_count,
                    "cadence": _cadence_evidence(cadence_for(member)),
                }
                if member.unknown_suffix:
                    member_evidence["unknown_suffix"] = True
                members.append(member_evidence)
            shares_available = (
                distinct_report_addresses >= 2
                and analysis.a1_rows > 0
                and analysis.report_query_rows > 0
            )
            evidence: dict[str, Any] = {
                "kind": "arrival_fold",
                "coverage_lane": _prepared.preflight.coverage_lane.value,
                "address": address,
                "member_count": len(candidates),
                "earliest_first_associated_period": first_iso,
                "members": members,
                "members_omitted": len(candidates) - len(kept),
                "attributed_share_num": a1_counts.get(address) if shares_available else None,
                "attributed_share_den": analysis.a1_rows if shares_available else None,
                "query_share_num": report_counts.get(address) if shares_available else None,
                "query_share_den": analysis.report_query_rows if shares_available else None,
                "distinct_report_addresses": distinct_report_addresses,
                "shares_available": shares_available,
            }
            evidence.update(
                _disposition_evidence(
                    _merge_dispositions(candidates, day_limit=LIMITS.disposition_days),
                    "global_events_over_fold_member_arrival_qualifying_names",
                )
            )
            finding = Finding(
                detector=DETECTOR_NAME,
                severity=Severity.LOW,
                title=address,
                description=(
                    f"{len(candidates)} family-keyed qualifying-name arrivals for "
                    "this address were folded to one row."
                ),
                evidence=evidence,
                next_steps=[
                    f"Identify the address owner or forwarder behind {address}",
                    "Inspect this address's blocked queries in the Pi-hole query log "
                    f"around {first_iso}",
                    "If this activity is expected, review `sigwood allowlist` and add only the exact name patterns you intend to suppress",
                ],
                ts_generated=now,
                data_window=window,
            )
            ordered.append((first_ts, address, "", finding))
            continue

        for candidate in candidates:
            first_iso = iso(candidate.first_associated_ts)
            lane = _prepared.preflight.coverage_lane
            if lane is CoverageLane.STRONG:
                novelty_noun = "first_available_history"
                description = (
                    "This was the first available-history activity for this address "
                    "and qualifying names grouped under this family key. "
                    f"Those queries appeared in {candidate.active_periods} of "
                    f"{candidate.eligible_periods} covered export periods."
                )
            else:
                novelty_noun = "first_observed_available_rows"
                description = (
                    "These qualifying names were first observed for this address in "
                    "the available rows. "
                    f"Those queries appeared in {candidate.active_periods} of "
                    f"{candidate.eligible_periods} data-bearing 24-hour report periods."
                )
            evidence = {
                "kind": "arrival",
                "coverage_lane": lane.value,
                "address": candidate.address,
                "family_key": candidate.family_key,
                "novelty_noun": novelty_noun,
                "attributed_query_count": candidate.attributed_query_count,
                "qualifying_name_count": candidate.qualifying_name_count,
                "active_periods": candidate.active_periods,
                "eligible_periods": candidate.eligible_periods,
                "first_associated_period": first_iso,
                "prior_other_address_count": candidate.prior_other_address_count,
                "prior_other_address_count_at_cap": (
                    candidate.prior_other_address_count_at_cap
                ),
            }
            if candidate.unknown_suffix:
                evidence["unknown_suffix"] = True
            evidence.update(
                _disposition_evidence(
                    candidate.disposition,
                    "global_events_over_arrival_qualifying_names",
                )
            )
            evidence.update(_cadence_evidence(cadence_for(candidate)))
            finding = Finding(
                detector=DETECTOR_NAME,
                severity=Severity.LOW,
                title=f"{candidate.address} → {candidate.family_key}",
                description=description,
                evidence=evidence,
                next_steps=next_steps(
                    candidate.address, candidate.family_key, first_iso
                ),
                ts_generated=now,
                data_window=window,
            )
            ordered.append(
                (
                    candidate.first_associated_ts,
                    candidate.address,
                    candidate.family_key,
                    finding,
                )
            )

    findings = [item[4] for item in sorted(burst_ordered, key=lambda item: item[:4])]
    findings.extend(item[3] for item in sorted(ordered, key=lambda item: item[:3]))
    if analysis.prior_handling_names:
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                severity=Severity.INFO,
                title="names withheld from novelty because Pi-hole logged earlier handling",
                description=(
                    f"{analysis.prior_handling_names} names "
                    f"({analysis.prior_handling_memberships} address-name memberships) "
                    "were withheld because forwarded or cached handling was logged "
                    "on an earlier day."
                ),
                evidence={
                    "kind": "prior_handling_exclusions",
                    "withheld_name_count": analysis.prior_handling_names,
                    "withheld_membership_count": analysis.prior_handling_memberships,
                },
                next_steps=[],
                ts_generated=now,
                data_window=window,
            )
        )
    recurring = analysis.recurring
    if recurring.pair_count:
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                severity=Severity.INFO,
                title="recurring blocked-name activity",
                description=(
                    f"{recurring.pair_count} otherwise-unsurfaced address-family "
                    f"pairs were active in at least {recurring.periods_required} of "
                    f"{recurring.periods_total} covered export periods."
                ),
                evidence={
                    "kind": "recurring_activity",
                    "coverage_lane": CoverageLane.STRONG.value,
                    "pair_count": recurring.pair_count,
                    "family_count": recurring.family_count,
                    "address_count": recurring.address_count,
                    "periods_required": recurring.periods_required,
                    "periods_total": recurring.periods_total,
                },
                next_steps=[],
                ts_generated=now,
                data_window=window,
            )
        )
    return findings
