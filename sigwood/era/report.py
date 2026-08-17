"""Aggregate-only era reducers, card facts, and text rendering.

This module consumes rows only after the loader and planner have selected them.
It deliberately retains no raw connection or DNS row in its report state.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import shlex
import statistics
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import pandas as pd

from sigwood import __version__
from sigwood.common.display import fmt_compact_span, fmt_timestamp, human_bytes, plural
from sigwood.common.sanitize import strip_control
from sigwood.common.topology import classify_address
from sigwood.era.domains import DOMAIN_CAP, DomainLedger, DomainLedgerFacts
from sigwood.era.observation import FamilyDayObservation
from sigwood.era.planner import ArchivePlan


UTC = timezone.utc
EXTERNAL_ADDRESS_CAP = 2_000_000
DURATION_REVIEW_THRESHOLDS_SECONDS = (86_400, 604_800, 1_209_600)
MASTHEAD_MIN_ELIGIBLE_WEEKS = 12


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be UTC and timezone-aware")
    return value


def _is_port_443(value: object) -> bool:
    """Match the scalar transport conversion exactly for batch aggregation."""
    try:
        return int(value) == 443
    except (TypeError, ValueError):
        return False


@dataclass(frozen=True)
class ReportInterval:
    """Absolute half-open report interval used for committed population."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        _utc(self.start, field_name="report start")
        _utc(self.end, field_name="report end")
        if self.end <= self.start:
            raise ValueError("report interval must be positive")


@dataclass(frozen=True)
class EraShard:
    """One complete UTC-midnight source shard inside a report interval."""

    start: datetime
    end: datetime
    conn_records: int
    dns_query_rows: int


@dataclass(frozen=True)
class ExternalAddressFact:
    """Exact only when classification succeeded and the fixed cap was not crossed."""

    count: int | None
    reason: str | None
    retained_distinct_count: int


@dataclass(frozen=True)
class EraSlot:
    """A visibly ordered report line and its safe operator inspection command."""

    when: str
    inspect_command: str


@dataclass(frozen=True)
class InspectHandoff:
    """A paste-safe command or an explicit reason that no command is safe."""

    command: str | None
    refusal_reason: str | None = None

    def __post_init__(self) -> None:
        if (self.command is None) == (self.refusal_reason is None):
            raise ValueError("handoff must contain exactly one of command or refusal reason")


_IDENTITY_PATH_COMPONENT = re.compile(
    r"(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9-]+\.[a-z]{2,}\b)", re.IGNORECASE
)


def compose_inspect_handoff(
    *,
    target: str,
    provenance_dir: object,
    start: datetime,
    end: datetime,
    rediscoverable: bool,
) -> InspectHandoff:
    """Compose one verified-source inspect command, otherwise fail closed.

    The provenance path is attacker-derivable, so controls are removed before
    its required ``shlex.quote(str(value))`` composition.  This is the terminal
    emit seam; callers never pass a prebuilt command.
    """
    if target not in {"graph-conn", "exfil"}:
        return InspectHandoff(None, "unsupported inspect target")
    if (
        start.tzinfo is None
        or end.tzinfo is None
        or start.utcoffset() != timedelta(0)
        or end.utcoffset() != timedelta(0)
        or end <= start
    ):
        return InspectHandoff(None, "unexpressible inspect window")
    path_text = strip_control(provenance_dir)
    path = Path(path_text)
    if not path.is_absolute() or not path.is_dir():
        return InspectHandoff(None, "unavailable provenance directory")
    if not rediscoverable:
        return InspectHandoff(None, "selected source is not rediscoverable by target")
    if any(_IDENTITY_PATH_COMPONENT.search(part) for part in path.parts):
        return InspectHandoff(None, "provenance directory cannot be placed in shell history")
    quoted = shlex.quote(str(path))
    since = start.astimezone(UTC).isoformat(timespec="seconds")
    until = end.astimezone(UTC).isoformat(timespec="seconds")
    if target == "graph-conn":
        command = f"sigwood graph conn --zeek-dir={quoted} --since={since} --until={until}"
    else:
        command = f"sigwood exfil {quoted} --since={since} --until={until}"
    return InspectHandoff(command)


def compose_planned_inspect_handoff(
    *,
    target: str,
    plan: ArchivePlan,
    winner_timestamp: datetime,
    start: datetime,
    end: datetime,
    rediscoverable: bool,
) -> InspectHandoff:
    """Compose from the winner's exact planner partition, never a filesystem glob."""
    if winner_timestamp.tzinfo is None or winner_timestamp.utcoffset() != timedelta(0):
        return InspectHandoff(None, "winner provenance is not a UTC instant")
    groups = [
        group
        for group in plan.groups
        if group.interval[0] <= winner_timestamp < group.interval[1]
    ]
    if len(groups) != 1:
        return InspectHandoff(None, "winner provenance partition is unavailable")
    directories = groups[0].directories
    if len(directories) != 1:
        return InspectHandoff(None, "winner provenance is not one rediscoverable directory")
    return compose_inspect_handoff(
        target=target,
        provenance_dir=directories[0],
        start=start,
        end=end,
        rediscoverable=rediscoverable,
    )


@dataclass(frozen=True)
class EraCard:
    """A renderer-ready era card built from already-measured aggregate facts."""

    title: str
    facts: tuple[tuple[str, str], ...]
    slots: tuple[EraSlot, ...] = ()


@dataclass(frozen=True)
class SpanHonesty:
    """Tool-authored deck-level horizon disclosure from family eligibility."""

    conn_eligible_weeks: int
    dns_eligible_weeks: int
    horizon_abstaining_cards: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if self.conn_eligible_weeks < 0 or self.dns_eligible_weeks < 0:
            raise ValueError("eligible-week spans cannot be negative")
        if tuple(sorted(set(self.horizon_abstaining_cards))) != self.horizon_abstaining_cards:
            raise ValueError("horizon abstaining cards must be sorted and unique")


@dataclass(frozen=True)
class TemporalSelectionEvidence:
    """Private, aggregate-only evidence for a score-ranked temporal selection."""

    winner_score: float | None
    runner_up_score: float | None
    admissible_candidates: int
    refused_candidates: int
    tie: bool


@dataclass(frozen=True)
class DomainArrivalEvidence:
    """Aggregate-only Card 10 facts, including its ruled horizon disclosure."""

    span_weeks: int
    maturity: int | None
    reason: str | None
    ledger: DomainLedgerFacts


@dataclass(frozen=True)
class FootprintFact:
    """One family footprint with its successful-stat coverage stated."""

    family: str
    compressed_bytes: int
    files_summed: int
    files_present: int
    inventory_state: str


@dataclass
class _ShardTotals:
    conn_records: int = 0
    dns_query_rows: int = 0


class EraReducer:
    """Reduce already-loaded rows into deterministic UTC shards and card-2 facts."""

    def __init__(
        self,
        interval: ReportInterval,
        *,
        home_net: list[str],
        address_cap: int = EXTERNAL_ADDRESS_CAP,
        domain_cap: int = DOMAIN_CAP,
        source_shards: Iterable[datetime] | None = None,
    ) -> None:
        if address_cap <= 0:
            raise ValueError("address cap must be positive")
        self.interval = interval
        self.home_net = tuple(home_net)
        self.address_cap = address_cap
        self.domain_cap = domain_cap
        self._shards: dict[datetime, _ShardTotals] = {}
        self._external_addresses: set[str] = set()
        self._address_reason: str | None = None
        self._minute_counts: dict[datetime, int] = {}
        self._telemetry_eligible_minutes: int | None = None
        self._duration_total = 0
        self._duration_eligible = 0
        self._duration_winner: tuple[float, datetime] | None = None
        self._duration_missing = 0
        self._duration_tail_counts: dict[int, int] = {
            threshold: 0 for threshold in DURATION_REVIEW_THRESHOLDS_SECONDS
        }
        self._outbound_eligible = 0
        self._outbound_winner: tuple[float, datetime] | None = None
        self._outbound_reason: str | None = None
        self._conn_day_counts: dict[date, int] = {}
        self._conn_day_observations: dict[date, tuple[bool, bool]] = {}
        self._dns_day_observations: dict[date, tuple[bool, bool]] = {}
        self._transport_weeks: dict[tuple[int, int], list[int]] = {}
        self._domain_ledger = DomainLedger(cap=domain_cap)
        self._source_shards = frozenset(
            self._validate_source_shard(start) for start in (source_shards or ())
        )

    @classmethod
    def from_archive_plan(
        cls,
        plan: ArchivePlan,
        interval: ReportInterval,
        *,
        home_net: list[str],
        address_cap: int = EXTERNAL_ADDRESS_CAP,
        domain_cap: int = DOMAIN_CAP,
    ) -> "EraReducer":
        """Bind a reducer to the planner's canonical UTC source groups."""
        return cls(
            interval,
            home_net=home_net,
            address_cap=address_cap,
            domain_cap=domain_cap,
            source_shards=(group.interval[0] for group in plan.groups),
        )

    def _validate_source_shard(self, start: datetime) -> datetime:
        _utc(start, field_name="source shard")
        if start != start.replace(hour=0, minute=0, second=0, microsecond=0):
            raise ValueError("source shard must start at UTC midnight")
        if start < self.interval.start or start + timedelta(days=1) > self.interval.end:
            raise ValueError("source shard must lie wholly inside the report interval")
        return start

    def _shard_start(self, timestamp: datetime) -> datetime:
        _utc(timestamp, field_name="timestamp")
        if not self.interval.start <= timestamp < self.interval.end:
            raise ValueError("timestamp is outside the absolute report interval")
        start = timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        if start < self.interval.start or end > self.interval.end:
            raise ValueError("timestamp does not belong to a complete UTC report shard")
        if self._source_shards and start not in self._source_shards:
            raise ValueError("timestamp belongs to an unplanned source shard")
        return start

    def add_conn(self, timestamp: datetime, destination: object) -> None:
        """Record one committed connection and classify only its destination."""
        start = self._shard_start(timestamp)
        self._shards.setdefault(start, _ShardTotals()).conn_records += 1
        topology = classify_address(destination, self.home_net)
        if topology is None:
            self._address_reason = self._address_reason or "destination-unclassifiable"
            return
        if not topology.external or self._address_reason is not None:
            return
        self._external_addresses.add(str(topology.address))
        if len(self._external_addresses) > self.address_cap:
            self._address_reason = "external-address-cap-exceeded"

    def add_conn_batch(self, frame: pd.DataFrame) -> None:
        """Fold one ordered, normalized conn chunk without retaining its rows.

        The bulk path owns only count/bin/duration/transport aggregation.  It
        deliberately leaves topology classification on the scalar owner until
        its first-encounter cap and reason semantics have their own vector
        contract.
        """
        if frame.empty:
            return
        timestamps = pd.DatetimeIndex(frame["timestamp"])
        days = timestamps.normalize()
        for day, count in pd.Series(days).value_counts(sort=False).items():
            start = day.to_pydatetime()
            self._shard_start(start)
            self._shards.setdefault(start, _ShardTotals()).conn_records += int(count)
        for minute, count in pd.Series(timestamps.floor("min")).value_counts(sort=False).items():
            value = minute.to_pydatetime()
            self._minute_counts[value] = self._minute_counts.get(value, 0) + int(count)
        for day, count in pd.Series(timestamps.date).value_counts(sort=False).items():
            self._conn_day_counts[day] = self._conn_day_counts.get(day, 0) + int(count)

        ports = frame.get("port", pd.Series(index=frame.index, dtype=object))
        is_443 = ports.map(_is_port_443)
        protocols = frame.get("proto", pd.Series(index=frame.index, dtype=object)).map(
            lambda value: str(value).lower()
        )
        for protocol, slot in (("udp", 0), ("tcp", 1)):
            selected = timestamps[(is_443 & (protocols == protocol)).to_numpy()]
            if selected.empty:
                continue
            weeks = pd.Series(list(zip(selected.isocalendar().year, selected.isocalendar().week)))
            for week, count in weeks.value_counts(sort=False).items():
                values = self._transport_weeks.setdefault((int(week[0]), int(week[1])), [0, 0])
                values[slot] += int(count)

        durations = pd.to_numeric(
            frame.get("duration", pd.Series(index=frame.index, dtype=object)), errors="coerce"
        )
        eligible = durations.notna() & durations.map(lambda value: math.isfinite(float(value)) and value >= 0)
        self._duration_total += len(durations)
        self._duration_eligible += int(eligible.sum())
        self._duration_missing += int((~eligible).sum())
        values = durations[eligible]
        for threshold in DURATION_REVIEW_THRESHOLDS_SECONDS:
            self._duration_tail_counts[threshold] += int((values >= threshold).sum())
        if not values.empty:
            maximum = float(values.max())
            position = int((eligible & (durations == maximum)).to_numpy().nonzero()[0][0])
            candidate = (maximum, timestamps[position].to_pydatetime())
            if self._duration_winner is None or candidate[0] > self._duration_winner[0]:
                self._duration_winner = candidate

        topology_rows = frame.reindex(columns=["timestamp", "src", "dst", "bytes"])
        for timestamp, origin, destination, sent in topology_rows.itertuples(index=False, name=None):
            topology = classify_address(destination, self.home_net)
            if topology is None:
                self._address_reason = self._address_reason or "destination-unclassifiable"
            elif topology.external and self._address_reason is None:
                self._external_addresses.add(str(topology.address))
                if len(self._external_addresses) > self.address_cap:
                    self._address_reason = "external-address-cap-exceeded"
            source = classify_address(origin, self.home_net)
            target = topology
            if source is None or target is None:
                self._outbound_reason = self._outbound_reason or "direction-unclassifiable"
                continue
            if not source.local or not target.external:
                continue
            try:
                value = float(sent)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(value) or value < 0:
                continue
            self._outbound_eligible += 1
            instant = timestamp.to_pydatetime() if hasattr(timestamp, "to_pydatetime") else timestamp
            candidate = (value, instant)
            if self._outbound_winner is None or candidate[0] > self._outbound_winner[0]:
                self._outbound_winner = candidate

    def add_dns_query(self, timestamp: datetime, query: object = None) -> None:
        """Record one committed DNS query row without retaining the query text."""
        start = self._shard_start(timestamp)
        self._shards.setdefault(start, _ShardTotals()).dns_query_rows += 1
        if query is not None:
            iso = timestamp.date().isocalendar()
            self._domain_ledger.add(query, (iso.year, iso.week))

    def add_conn_transport(self, timestamp: datetime, responder_port: object, proto: object) -> None:
        """Record the Card 8 responder-port-443 transport counters."""
        self._shard_start(timestamp)
        try:
            port = int(responder_port)
        except (TypeError, ValueError):
            return
        protocol = str(proto).lower()
        if port != 443 or protocol not in {"udp", "tcp"}:
            return
        iso = timestamp.date().isocalendar()
        counts = self._transport_weeks.setdefault((iso.year, iso.week), [0, 0])
        counts[0 if protocol == "udp" else 1] += 1

    def add_conn_start(self, timestamp: datetime) -> None:
        """Record a committed usable connection start for card 3."""
        self._shard_start(timestamp)
        minute = timestamp.replace(second=0, microsecond=0)
        self._minute_counts[minute] = self._minute_counts.get(minute, 0) + 1
        self._conn_day_counts[timestamp.date()] = self._conn_day_counts.get(timestamp.date(), 0) + 1

    def set_conn_day_observation(self, day: date, *, present: bool, usable: bool) -> None:
        """Bind one canonical conn source day to typed availability/parse facts."""
        start = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
        self._validate_source_shard(start)
        if usable and not present:
            raise ValueError("unavailable conn day cannot be usable")
        value = (present, usable)
        existing = self._conn_day_observations.get(day)
        if existing is not None and existing != value:
            raise ValueError("conn day observation is inconsistent")
        self._conn_day_observations[day] = value

    def set_dns_day_observation(self, day: date, *, present: bool, usable: bool) -> None:
        """Bind one canonical DNS source day to typed availability/parse facts."""
        start = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
        self._validate_source_shard(start)
        if usable and not present:
            raise ValueError("unavailable DNS day cannot be usable")
        value = (present, usable)
        existing = self._dns_day_observations.get(day)
        if existing is not None and existing != value:
            raise ValueError("DNS day observation is inconsistent")
        self._dns_day_observations[day] = value

    def _dns_source_weeks(self) -> tuple[tuple[int, int], ...]:
        return tuple(sorted({(start.date().isocalendar().year, start.date().isocalendar().week) for start in self._source_shards}))

    def set_telemetry_eligible_minutes(self, minutes: int | None) -> None:
        """Set only a telemetry-established, zero-inclusive minute population."""
        if minutes is not None and minutes < 0:
            raise ValueError("eligible minutes cannot be negative")
        self._telemetry_eligible_minutes = minutes

    def add_connection_duration(self, timestamp: datetime, duration: object) -> None:
        """Record card-4 eligibility without retaining a connection row."""
        self._shard_start(timestamp)
        self._duration_total += 1
        try:
            value = float(duration)
        except (TypeError, ValueError):
            value = math.nan
        if not math.isfinite(value) or value < 0:
            self._duration_missing += 1
            return
        self._duration_eligible += 1
        for threshold in DURATION_REVIEW_THRESHOLDS_SECONDS:
            if value >= threshold:
                self._duration_tail_counts[threshold] += 1
        candidate = (value, timestamp)
        if self._duration_winner is None or candidate[0] > self._duration_winner[0]:
            self._duration_winner = candidate

    def add_outbound_connection(
        self,
        timestamp: datetime,
        *,
        origin: object,
        destination: object,
        orig_bytes: object,
        resp_bytes: object,
    ) -> None:
        """Record card-5 candidates through the shared topology owner only."""
        self._shard_start(timestamp)
        source = classify_address(origin, self.home_net)
        target = classify_address(destination, self.home_net)
        if source is None or target is None:
            self._outbound_reason = self._outbound_reason or "direction-unclassifiable"
            return
        if not source.local or not target.external:
            return
        try:
            sent, received = float(orig_bytes), float(resp_bytes)
        except (TypeError, ValueError):
            return
        if not math.isfinite(sent) or not math.isfinite(received) or sent < 0 or received < 0:
            return
        self._outbound_eligible += 1
        candidate = (sent, timestamp)
        if self._outbound_winner is None or candidate[0] > self._outbound_winner[0]:
            self._outbound_winner = candidate

    @property
    def shards(self) -> tuple[EraShard, ...]:
        return tuple(
            EraShard(
                start=start,
                end=start + timedelta(days=1),
                conn_records=totals.conn_records,
                dns_query_rows=totals.dns_query_rows,
            )
            for start in sorted(set(self._shards) | self._source_shards)
            for totals in (self._shards.get(start, _ShardTotals()),)
        )

    @property
    def committed_conn_records(self) -> int:
        return sum(shard.conn_records for shard in self.shards)

    @property
    def committed_dns_query_rows(self) -> int:
        return sum(shard.dns_query_rows for shard in self.shards)

    @property
    def external_destination_addresses(self) -> ExternalAddressFact:
        reason = self._address_reason
        return ExternalAddressFact(
            count=None if reason else len(self._external_addresses),
            reason=reason,
            retained_distinct_count=len(self._external_addresses),
        )

    def merge(self, other: "EraReducer") -> "EraReducer":
        """Merge compatible aggregate reducers in deterministic source-shard order."""
        if (self.interval, self.home_net, self.address_cap, self.domain_cap, self._source_shards) != (
            other.interval, other.home_net, other.address_cap, other.domain_cap, other._source_shards,
        ):
            raise ValueError("reducers must share interval, home network, and cap")
        merged = EraReducer(
            self.interval,
            home_net=list(self.home_net),
            address_cap=self.address_cap,
            domain_cap=self.domain_cap,
            source_shards=self._source_shards,
        )
        for reducer in (self, other):
            for start, totals in reducer._shards.items():
                result = merged._shards.setdefault(start, _ShardTotals())
                result.conn_records += totals.conn_records
                result.dns_query_rows += totals.dns_query_rows
            merged._external_addresses.update(reducer._external_addresses)
            merged._address_reason = merged._address_reason or reducer._address_reason
            for minute, count in reducer._minute_counts.items():
                merged._minute_counts[minute] = (
                    merged._minute_counts.get(minute, 0) + count
                )
            for day, count in reducer._conn_day_counts.items():
                merged._conn_day_counts[day] = merged._conn_day_counts.get(day, 0) + count
            for day, observation in reducer._conn_day_observations.items():
                existing = merged._conn_day_observations.get(day)
                if existing is not None and existing != observation:
                    raise ValueError("conn day observation is inconsistent")
                merged._conn_day_observations[day] = observation
            for day, observation in reducer._dns_day_observations.items():
                existing = merged._dns_day_observations.get(day)
                if existing is not None and existing != observation:
                    raise ValueError("DNS day observation is inconsistent")
                merged._dns_day_observations[day] = observation
            for week, counts in reducer._transport_weeks.items():
                target = merged._transport_weeks.setdefault(week, [0, 0])
                target[0] += counts[0]
                target[1] += counts[1]
            merged._domain_ledger = merged._domain_ledger.merge(reducer._domain_ledger)
            merged._duration_total += reducer._duration_total
            merged._duration_eligible += reducer._duration_eligible
            merged._duration_missing += reducer._duration_missing
            for threshold, count in reducer._duration_tail_counts.items():
                merged._duration_tail_counts[threshold] += count
            merged._outbound_eligible += reducer._outbound_eligible
            merged._outbound_reason = (
                merged._outbound_reason or reducer._outbound_reason
            )
            for name in ("_duration_winner", "_outbound_winner"):
                candidate = getattr(reducer, name)
                incumbent = getattr(merged, name)
                if candidate is not None and (
                    incumbent is None
                    or candidate[0] > incumbent[0]
                    or (candidate[0] == incumbent[0] and candidate[1] < incumbent[1])
                ):
                    setattr(merged, name, candidate)
        if (
            self._telemetry_eligible_minutes is not None
            and other._telemetry_eligible_minutes is not None
        ):
            merged._telemetry_eligible_minutes = (
                self._telemetry_eligible_minutes + other._telemetry_eligible_minutes
            )
        if len(merged._external_addresses) > merged.address_cap:
            merged._address_reason = "external-address-cap-exceeded"
        return merged

    def aggregate_review_evidence(
        self, *, peak_radius_minutes: int = 5
    ) -> tuple[datetime | None, tuple[int, ...], tuple[tuple[int, int], ...], tuple[float, datetime] | None]:
        """Return bounded, identity-free aggregates for a harness review.

        This deliberately does not classify a busy minute as good or bad. It
        exposes adjacent aggregate minute counts and duration-tail counts so
        the private harness can characterize an outlier without retaining
        rows, addresses, or connection identity.
        """
        if peak_radius_minutes < 0:
            raise ValueError("peak radius cannot be negative")
        peak: datetime | None = None
        profile: tuple[int, ...] = ()
        if self._minute_counts:
            peak, _count = min(
                self._minute_counts.items(), key=lambda item: (-item[1], item[0])
            )
            profile = tuple(
                self._minute_counts.get(peak + timedelta(minutes=offset), 0)
                for offset in range(-peak_radius_minutes, peak_radius_minutes + 1)
            )
        tails = tuple(
            (threshold, self._duration_tail_counts[threshold])
            for threshold in DURATION_REVIEW_THRESHOLDS_SECONDS
        )
        return peak, profile, tails, self._duration_winner

    def temporal_daily_counts(self) -> tuple[tuple[date, int], ...]:
        """Return only UTC-day conn-start aggregates, never source timestamps."""
        return tuple(sorted(self._conn_day_counts.items()))


def weekday_shape_card(reducer: EraReducer) -> EraCard | None:
    """Card 6: median conn starts by weekday, only for eight eligible instances."""
    by_weekday: dict[int, list[int]] = {weekday: [] for weekday in range(7)}
    for day, count in reducer.temporal_daily_counts():
        # When planner source facts are bound, eligibility is conn-scoped:
        # a day must be present and parsed usable as well as carrying a
        # committed start.  Standalone reducers retain their aggregate-only
        # test surface, where a positive day count is the available fact.
        observed = reducer._conn_day_observations.get(day)
        if count > 0 and (not reducer._source_shards or observed == (True, True)):
            by_weekday[day.weekday()].append(count)
    names = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
    facts = tuple(
        (
            names[weekday],
            f"{statistics.median(values):,.0f} median connection starts"
            f" across {len(values)} eligible {plural(len(values), 'day')}",
        )
        for weekday, values in sorted(by_weekday.items())
        if len(values) >= 8
    )
    return EraCard("6. shape of the week", facts) if facts else None


def footprint_card(facts: Iterable[FootprintFact]) -> EraCard:
    """Card 7: compressed on-disk storage, with metadata coverage visible."""
    return EraCard(
        "7. archive footprint",
        tuple(
            (
                fact.family,
                f"{fact.compressed_bytes:,} compressed bytes; "
                f"{fact.files_summed:,} {plural(fact.files_summed, 'file')} summed / "
                f"{fact.files_present:,} {plural(fact.files_present, 'file')} present; "
                f"inventory={fact.inventory_state}",
            )
            for fact in sorted(facts, key=lambda item: item.family)
        ),
    )


def _eligible_weeks(
    reducer: EraReducer, *, family: str
) -> tuple[tuple[tuple[int, int], int], ...]:
    """Return full source weeks and their eligible-day denominators.

    This stays deliberately source-calendar based.  Cards never infer a
    seven-day denominator from the presence of records alone.
    """
    observations = (
        reducer._conn_day_observations if family == "conn" else reducer._dns_day_observations
    )
    source: dict[tuple[int, int], set[date]] = {}
    for start in reducer._source_shards:
        day = start.date()
        iso = day.isocalendar()
        source.setdefault((iso.year, iso.week), set()).add(day)
    result: list[tuple[tuple[int, int], int]] = []
    for week, days in sorted(source.items()):
        if len(days) != 7:
            continue
        # Standalone reducers are a narrow test surface; archive-bound reducers
        # must carry an explicit availability/parse observation for every day.
        eligible_days = (
            sum(observations.get(day) == (True, True) for day in days)
            if observations
            else len(days)
        )
        if eligible_days >= 6:
            result.append((week, eligible_days))
    return tuple(result)


def eligible_week_count(reducer: EraReducer, *, family: str) -> int:
    """Expose a family-layer eligible-week denominator for private receipts."""
    return len(_eligible_weeks(reducer, family=family))


def transport_share_card(
    reducer: EraReducer,
) -> tuple[EraCard | None, TemporalSelectionEvidence]:
    """Card 8: weekly UDP/443 share, with a fixed 100-record floor."""
    speaking: list[tuple[tuple[int, int], float]] = []
    sub_floor = 0
    eligible = {week for week, _days in _eligible_weeks(reducer, family="conn")}
    for week in sorted(eligible):
        udp, tcp = reducer._transport_weeks.get(week, (0, 0))
        total = udp + tcp
        if total < 100:
            sub_floor += 1
            continue
        speaking.append((week, udp / total))
    if len(speaking) < 2:
        return None, TemporalSelectionEvidence(None, None, len(speaking), sub_floor, False)
    moves = [
        (abs(after - before), after_week, after - before)
        for (before_week, before), (after_week, after) in zip(speaking, speaking[1:])
    ]
    ranked_moves = sorted(moves, key=lambda item: (-item[0], item[1]))
    magnitude, moved_week, signed = ranked_moves[0]
    runner_up = ranked_moves[1][0] if len(ranked_moves) > 1 else None
    tie = len(ranked_moves) > 1 and runner_up == magnitude
    first_week, first = speaking[0]
    last_week, last = speaking[-1]
    return EraCard(
        "8. port-443 transport over time",
        (
            ("first speaking week", f"{first_week[0]}-W{first_week[1]:02d}: {_rate(first * 100)}% UDP/443"),
            ("last speaking week", f"{last_week[0]}-W{last_week[1]:02d}: {_rate(last * 100)}% UDP/443"),
            ("largest week-over-week move", f"{'+' if signed >= 0 else ''}{_rate(signed * 100)} points"
             f" in {moved_week[0]}-W{moved_week[1]:02d}"),
            ("runner-up move", "not available" if runner_up is None else f"{_rate(runner_up * 100)} points"),
            ("largest-move tie", "yes (earliest week selected)" if tie else "no"),
            ("series coverage", f"{len(speaking)} speaking eligible {plural(len(speaking), 'week')}; "
             f"{sub_floor} eligible {plural(sub_floor, 'week')} omitted below 100 port-443 records"),
        ),
    ), TemporalSelectionEvidence(
        winner_score=magnitude * 100,
        runner_up_score=None if runner_up is None else runner_up * 100,
        admissible_candidates=len(speaking),
        refused_candidates=sub_floor,
        tie=tie,
    )


def _maturity_for_span(span_weeks: int) -> int | None:
    if span_weeks < 12:
        return None
    if span_weeks <= 21:
        return 4
    if span_weeks <= 28:
        return 6
    return 8


def _presence_class(observed_weeks: int, eligible_weeks: int) -> str:
    """Apply Card 10's mutually exclusive mature-presence boundaries."""
    if observed_weeks == 1:
        return "single-week"
    if observed_weeks / eligible_weeks < 0.75:
        return "intermittent"
    return "regular"


def _rate(value: float) -> str:
    """Render a rate at one decimal, dropping a trailing zero.

    A rate carried six decimals implies precision the measurement lacks, but a
    whole number wearing a false decimal (`19.0`) is its own small dishonesty.
    One rule covers both: round to a tenth, then show the tenth only when it
    says something.
    """
    rounded = round(float(value), 1)
    return f"{rounded:.0f}" if rounded == int(rounded) else f"{rounded:.1f}"


def domain_arrival_card(
    reducer: EraReducer,
) -> tuple[EraCard | None, DomainArrivalEvidence]:
    """Card 10's D20-bounded arrival and mature-presence facts.

    The ledger is exact only below its fixed cap; neither identities nor an
    identity-derived sample survive this renderer seam.
    """
    facts = reducer._domain_ledger.facts
    eligible = _eligible_weeks(reducer, family="dns")
    weeks = tuple(week for week, _days in eligible)
    maturity = _maturity_for_span(len(weeks))
    if not facts.psl_available:
        return EraCard("10. domain arrivals", (("domain arrivals", "abstain (public suffix list unavailable)"),)), DomainArrivalEvidence(len(weeks), maturity, "psl-unavailable", facts)
    if facts.cap_exceeded:
        return EraCard("10. domain arrivals", (("domain arrivals", f"abstain (exact {facts.cap}-domain ledger cap exceeded)"),)), DomainArrivalEvidence(len(weeks), maturity, "domain-cap-exceeded", facts)
    if maturity is None:
        return EraCard(
            "10. domain arrivals",
            (("domain arrivals", f"abstain (requires 12 eligible DNS weeks; analyzed span is {len(weeks)})"),),
        ), DomainArrivalEvidence(len(weeks), None, "requires-12-eligible-dns-weeks", facts)
    index = {week: position for position, week in enumerate(weeks)}
    burn_in = set(weeks[:2])
    arrivals: dict[tuple[int, int], int] = {week: 0 for week in weeks[2:]}
    single = intermittent = regular = 0
    cohort_total = cohort_soon = cohort_late = 0
    early = 0
    for history in reducer._domain_ledger.histories:
        seen = tuple(week for week in weeks if week in history.weeks)
        if not seen:
            continue
        arrival = seen[0]
        arrival_index = index[arrival]
        if arrival in burn_in:
            early += 1
            continue
        arrivals[arrival] += 1
        subsequent = weeks[arrival_index + 1:]
        if len(subsequent) >= maturity:
            observed = sum(week in history.weeks for week in weeks[arrival_index:])
            presence = _presence_class(observed, len(subsequent) + 1)
            if presence == "single-week":
                single += 1
            elif presence == "intermittent":
                intermittent += 1
            else:
                regular += 1
        if len(subsequent) >= 8:
            cohort_total += 1
            if any(week in history.weeks for week in subsequent[:4]):
                cohort_soon += 1
            if any(week in history.weeks for week in subsequent[7:]):
                cohort_late += 1
    rates = [arrivals[week] / days for week, days in eligible if week in arrivals]
    median_rate = statistics.median(rates) if rates else 0.0
    peak_week, peak_rate = min(
        ((week, arrivals[week] / days) for week, days in eligible if week in arrivals),
        key=lambda item: (-item[1], item[0]),
        default=(None, 0.0),
    )
    excluded = ", ".join(f"{reason}={count:,}" for reason, count in facts.excluded) or "none"
    card_facts: list[tuple[str, str]] = [
        ("maturity in effect", f"{maturity} follow-up eligible weeks (reasoned default; analyzed DNS span {len(weeks)} eligible weeks)"),
        ("arrival rate", f"median {_rate(median_rate)} registrable-domain arrivals per eligible DNS day after burn-in"),
        ("peak arrival week", f"{peak_week[0]}-W{peak_week[1]:02d}: {_rate(peak_rate)} arrivals per eligible DNS day" if peak_week else "no post-burn-in arrival week"),
        ("burn-in", f"{early:,} {plural(early, 'domain')} present since early archive; "
         f"first 2 eligible DNS weeks excluded from arrival counting"),
        ("mature presence", f"single-week={single}; intermittent={intermittent}; regular={regular}; domains without {maturity} follow-up eligible weeks are right-censored"),
        ("cohort", f"{cohort_soon}/{cohort_total} seen again within the next four eligible weeks; {cohort_late}/{cohort_total} seen again eight or more eligible weeks later (fixed cohort horizon: 8 subsequent eligible weeks)"),
        ("excluded names", excluded),
        ("visibility", "DNS resolved off-sensor or inside encrypted channels is invisible here"),
    ]
    return EraCard("10. domain arrivals", tuple(card_facts)), DomainArrivalEvidence(len(weeks), maturity, None, facts)


def sustained_shift_card(reducer: EraReducer) -> tuple[EraCard | None, TemporalSelectionEvidence]:
    """Card 9's frozen UTC/conn-scoped candidate arithmetic.

    This private harness surface stores day totals only.  Availability/parse
    refusal is introduced by the runner once it has typed per-day observations;
    absent such a refusal, candidates are the eligible ISO-week boundaries.
    """
    by_week: dict[tuple[int, int], list[int]] = {}
    source_days_by_week: dict[tuple[int, int], set[date]] = {}
    refused_days: set[date] = set()
    for day in (start.date() for start in reducer._source_shards):
        iso = day.isocalendar()
        source_days_by_week.setdefault((iso.year, iso.week), set()).add(day)
        if reducer._conn_day_observations.get(day) != (True, True):
            refused_days.add(day)
    for day, count in reducer.temporal_daily_counts():
        if count > 0:
            iso = day.isocalendar()
            by_week.setdefault((iso.year, iso.week), []).append(count)
    weeks = [
        week
        for week in sorted(by_week)
        if len(source_days_by_week.get(week, ())) == 7 and len(by_week[week]) >= 6
    ]
    if len(weeks) < 12:
        return None, TemporalSelectionEvidence(None, None, 0, 0, False)
    weekly = {week: statistics.median(by_week[week]) for week in weeks}
    candidates: list[tuple[float, tuple[int, int], float, float, int]] = []
    refused_candidates = 0
    for index in range(4, len(weeks) - 4):
        boundary = weeks[index]
        window_weeks = weeks[index - 4:index + 4]
        window_days = {
            day for week in window_weeks for day in source_days_by_week[week]
        }
        if window_days & refused_days:
            refused_candidates += 1
            continue
        before_values = [weekly[week] for week in weeks[index - 4:index]]
        after_values = [weekly[week] for week in weeks[index:index + 4]]
        before = statistics.median(before_values)
        after = statistics.median(after_values)
        # Conn-scoped eligibility makes zero structurally unreachable.
        if before <= 0 or after <= 0:
            continue
        score = abs(math.log2(after / before))
        hold = 0
        for week in weeks[index:]:
            value = weekly[week]
            if abs(value - after) < abs(value - before):
                hold += 1
            else:
                break
        candidates.append((score, boundary, before, after, hold))
    if not candidates:
        return None, TemporalSelectionEvidence(None, None, 0, refused_candidates, False)
    ranked = sorted(candidates, key=lambda item: (-item[0], item[1]))
    winner = ranked[0]
    tied = len(ranked) > 1 and ranked[1][0] == winner[0]
    # Keep the numerical runner-up even on a tie.  The explicit marker below
    # prevents a deterministic boundary ordering from implying separation.
    runner_up = ranked[1][0] if len(ranked) > 1 else None
    card = EraCard(
        "9. largest sustained shift",
        (
            ("boundary", f"{winner[1][0]}-W{winner[1][1]:02d}"),
            ("observed committed connection records per day", f"{winner[2]:g} before; {winner[3]:g} after; score {winner[0]:g}"),
            ("selected boundary score", f"{winner[0]:g}"),
            ("runner-up candidate score", "not available" if runner_up is None else f"{runner_up:g}"),
            ("admissible candidate boundaries", str(len(candidates))),
            ("top-score tie", "yes" if tied else "no"),
            ("hold in eligible weeks", str(winner[4])),
        ),
    )
    return card, TemporalSelectionEvidence(
        winner_score=winner[0],
        runner_up_score=runner_up,
        admissible_candidates=len(candidates),
        refused_candidates=refused_candidates,
        tie=tied,
    )


def calendar_card(observations: Mapping[str, FamilyDayObservation]) -> EraCard:
    """Render independent availability, parse, and completeness layers by family."""
    facts = tuple(
        (
            family,
            "availability=" + observation.availability.value
            + "; parse=" + observation.parse_usability.value
            + "; completeness=" + observation.completeness.value,
        )
        for family, observation in sorted(observations.items())
    )
    return EraCard("1. data-bearing calendar", facts)


def activity_card(reducer: EraReducer) -> EraCard:
    """Render card 2 while keeping its independently measured subfacts separate."""
    addresses = reducer.external_destination_addresses
    address_value = (
        f"{addresses.count:,}"
        if addresses.count is not None
        else "not measured (" + (addresses.reason or "classification unavailable") + ")"
    )
    return EraCard(
        "2. committed activity",
        (
            ("conn records", f"{reducer.committed_conn_records:,}"),
            ("DNS query rows", f"{reducer.committed_dns_query_rows:,}"),
            ("distinct external destination IPs", address_value),
        ),
    )


def _handoff_slot(
    when: datetime, handoff: InspectHandoff | None
) -> tuple[EraSlot, ...]:
    """Render a typed command or a typed refusal without accepting raw shell text."""
    if handoff is None:
        return ()
    command = handoff.command
    if command is None:
        command = "inspect unavailable (" + strip_control(handoff.refusal_reason) + ")"
    return (EraSlot(fmt_timestamp(when), command),)


def busiest_minute_card(
    reducer: EraReducer, *, inspect_handoff: InspectHandoff | None = None
) -> EraCard | None:
    """Render card 3; telemetry-free input never invents a median comparison."""
    if not reducer._minute_counts:
        return None
    ranked = sorted(reducer._minute_counts.items(), key=lambda item: (-item[1], item[0]))
    minute, count = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else None
    # Deterministic selection, disclosed margin. Ordering by (-count, minute)
    # resolves a tie to the earliest minute, but earliest is not evidence of
    # separation: a winner one start clear of rank-2 and one thousand clear read
    # identically without the runner-up beside it. Cards 8 and 9 already state
    # theirs, in this vocabulary.
    facts: list[tuple[str, str]] = [
        (
            "busiest minute",
            f"{fmt_timestamp(minute)} ({count:,} {plural(count, 'connection start')})",
        ),
        (
            "runner-up minute",
            "not available"
            if runner_up is None
            else f"{runner_up:,} {plural(runner_up, 'connection start')}",
        ),
        (
            "top-count tie",
            "yes (earliest minute selected)" if runner_up == count else "no",
        ),
    ]
    eligible = reducer._telemetry_eligible_minutes
    if eligible is not None and eligible >= len(reducer._minute_counts) and eligible > 0:
        values = sorted(reducer._minute_counts.values())
        # Missing minutes are telemetry-known zeros, not an inferred denominator.
        values = [0] * max(eligible - len(values), 0) + values
        median = statistics.median(values)
        if median > 0:
            facts.append(("comparison", f"{count / median:.1f}x the median minute"))
    return EraCard(
        "3. busiest minute", tuple(facts), _handoff_slot(minute, inspect_handoff)
    )


def longest_connection_card(
    reducer: EraReducer,
    *,
    edge_censored: bool = False,
    inspect_handoff: InspectHandoff | None = None,
) -> EraCard | None:
    """Render card 4 with its partial-population denominator always visible."""
    winner = reducer._duration_winner
    if winner is None:
        return None
    value, _when = winner
    prefix = "at least " if edge_censored else ""
    span = fmt_compact_span(timedelta(seconds=float(value)))
    facts = [("longest connection", f"{prefix}{span} among {reducer._duration_eligible:,} {plural(reducer._duration_eligible, 'record')}")]
    if reducer._duration_missing:
        facts.append(("duration coverage", f"{reducer._duration_eligible:,} eligible / {reducer._duration_total:,} committed"))
    return EraCard("4. longest connection", tuple(facts), _handoff_slot(_when, inspect_handoff))


def largest_outbound_card(
    reducer: EraReducer, *, inspect_handoff: InspectHandoff | None = None
) -> EraCard:
    """Render card 5; unavailable classification is an abstention, never zero."""
    if reducer._outbound_reason:
        return EraCard("5. largest outbound connection", (("largest outbound", f"abstain ({reducer._outbound_reason})"),))
    if reducer._outbound_winner is None:
        return EraCard("5. largest outbound connection", (("largest outbound", "no direction-eligible complete counters"),))
    value, _when = reducer._outbound_winner
    return EraCard(
        "5. largest outbound connection",
        (("largest outbound", f"{human_bytes(float(value))} originator bytes among {reducer._outbound_eligible:,} {plural(reducer._outbound_eligible, 'record')}"),),
        _handoff_slot(_when, inspect_handoff),
    )


def canonical_identity_payload(
    *,
    archive_content_identity: Mapping[str, Any],
    resolved_config: Mapping[str, Any],
    cli_options: Mapping[str, Any],
    display_timezone: str,
    partition_zone: str,
    tldextract_version: str,
    effective_psl_snapshot: bytes,
) -> bytes:
    """Return D19's canonical closure payload, excluding volatile render fields."""
    payload = {
        "archive_content_identity": dict(archive_content_identity),
        "cli_options": dict(cli_options),
        "display_timezone": display_timezone,
        "effective_psl_snapshot_sha256": hashlib.sha256(effective_psl_snapshot).hexdigest(),
        "partition_zone": partition_zone,
        "resolved_config": dict(resolved_config),
        "sigwood_version": __version__,
        "tldextract_version": tldextract_version,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def render_text_report(
    cards: tuple[EraCard, ...], *, family: str, span_honesty: SpanHonesty | None = None
) -> str:
    """Render already-measured cards in fixed card and slot order."""
    lines = [f"era / {strip_control(family)}"]
    if span_honesty is not None:
        lines.append(
            "analyzed span: "
            f"{span_honesty.conn_eligible_weeks} eligible conn weeks; "
            f"{span_honesty.dns_eligible_weeks} eligible DNS weeks"
        )
        if min(span_honesty.conn_eligible_weeks, span_honesty.dns_eligible_weeks) < MASTHEAD_MIN_ELIGIBLE_WEEKS:
            cards_text = (
                "cards " + ", ".join(str(card) for card in span_honesty.horizon_abstaining_cards)
                if span_honesty.horizon_abstaining_cards
                else "no cards"
            )
            lines.append(
                "horizon-limited "
                f"(reasoned default: {MASTHEAD_MIN_ELIGIBLE_WEEKS} eligible weeks): {cards_text} abstain due to span"
            )
    for card in cards:
        lines.append(strip_control(card.title))
        lines.extend(
            f"  {strip_control(label)}: {strip_control(value)}" for label, value in card.facts
        )
        lines.extend(
            f"  {strip_control(slot.when)}: {strip_control(slot.inspect_command)}"
            for slot in card.slots
        )
    return "\n".join(lines)


def utc_shard_label(shard: EraShard) -> str:
    """Render a shard through the shared display timezone policy."""
    return f"{fmt_timestamp(shard.start)} to {fmt_timestamp(shard.end)}"
