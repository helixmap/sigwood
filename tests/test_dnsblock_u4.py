from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from sigwood import runner
from sigwood.common.finding import DetectorContext, Severity
from sigwood.common.loader import (
    CoverageDecision,
    CoverageDecisionReason,
    CoverageLane,
    DualWindow,
    PreparedState,
    PreparedStatus,
)
from sigwood.detectors import dnsblock
from tests.dnsblock_contract import GridSurvivorAccumulator, validate_summary_notes


UTC = timezone.utc


def _window(days: int = 5) -> DualWindow:
    end = datetime(2026, 2, 1, tzinfo=UTC)
    start = end - timedelta(days=days)
    return DualWindow(
        (start, end),
        (start - timedelta(days=25), start - timedelta(microseconds=1)),
    )


def _coverage(window: DualWindow, *, weak: bool = False) -> CoverageDecision:
    if weak:
        return CoverageDecision(
            CoverageLane.WEAK,
            CoverageDecisionReason.OBJECT_UNKNOWN,
            window.report_interval,
        )
    assert window.context_interval is not None
    return CoverageDecision(
        CoverageLane.STRONG,
        CoverageDecisionReason.COMPLETE,
        window.report_interval,
        ((window.context_interval[0], window.report_interval[1]),),
    )


def _add_pair(
    state: dnsblock.PopulationState,
    window: DualWindow,
    address: str,
    name: str,
    counts: dict[int, int],
    *,
    prior_handling: bool = False,
) -> None:
    first = float("inf")
    last = float("-inf")
    total = 0
    for period, count in counts.items():
        ts = (window.report_interval[1] - timedelta(days=period, hours=1)).timestamp()
        cell = dnsblock.AssocCell(count, ts, ts)
        state.pair_period[(address, name, period)] = cell
        state.disposition[(name, datetime.fromtimestamp(ts, tz=UTC).date())] = Counter(
            {"gravity_blocked": count}
        )
        first = min(first, ts)
        last = max(last, ts)
        total += count
    state.a1_pair[(address, name)] = dnsblock.AssocCell(total, first, last)
    state.pair_first[(address, name)] = first
    state.report_pairs.add((address, name))
    state.addresses.add(address)
    state.names.add(name)
    state.address_first[address] = (window.report_interval[0] - timedelta(days=20)).timestamp()
    state.a1_rows += total
    state.a2_rows += total
    state.report_query_rows += total
    state.a1_rows_by_address[address] += total
    state.report_query_rows_by_address[address] += total
    if prior_handling:
        state.handling_dates[name] = {
            datetime.fromtimestamp(first, tz=UTC).date() - timedelta(days=1)
        }


def _population(window: DualWindow) -> dnsblock.PopulationState:
    state = dnsblock.PopulationState(query_periods=set(range(30)))
    # Arrival + burst overlap; equal peaks prove the earlier wall-clock period wins.
    _add_pair(
        state,
        window,
        "192.0.2.7",
        "burst.example.com",
        {0: 5, 1: 100, 2: 100, 3: 5},
    )
    # Arrival is withheld by earlier handling, but the independently qualifying
    # burst survives and is counted by the explicit control ledger.
    _add_pair(
        state,
        window,
        "192.0.2.8",
        "withheld.example.net",
        {0: 5, 1: 5, 2: 100, 3: 5},
        prior_handling=True,
    )
    # Otherwise-unsurfaced steady pair qualifies only for recurring context.
    _add_pair(
        state,
        window,
        "192.0.2.9",
        "steady.example.org",
        {0: 10, 1: 10, 2: 10, 3: 10},
        prior_handling=True,
    )
    state.raw_window_rows = state.report_query_rows
    state.filtered_window_rows = state.report_query_rows
    state.raw_query_rows = state.report_query_rows
    state.raw_block_report_rows = len(state.report_pairs)
    state.filtered_block_report_rows = len(state.report_pairs)
    state.disposition_date_cells = len(state.disposition)
    return state


def _prepared(*, weak: bool = False, days: int = 5):
    window = _window(days)
    prepared = dnsblock.build_prepared(
        snapshot_identity="b" * 64,
        window=window,
        coverage=_coverage(window, weak=weak),
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=dnsblock.BlockInventory(),
        population=_population(window),
        # U4's route fixtures exercise the original grid cell explicitly;
        # shipped defaults are pinned separately against the sealed decision.
        calibration_vector=dnsblock.DnsblockCalibrationVector(
            arrival_days=3,
            arrival_history=14,
            burst_absolute=100,
            burst_multiple=8,
            burst_active=3,
        ),
    )
    results = {
        pair: dnsblock.CadenceState(included_gaps=[60.0] * 20)
        for pair in prepared.analysis.cadence_worklist
    }
    return dnsblock.finalize_cadence(
        prepared,
        status=PreparedStatus(PreparedState.READY),
        results=results,
        pass_wall_seconds=(),
    )


def test_private_burst_vector_and_arrival_only_arm_keep_complete_grid(tmp_path):
    window = _window()
    population = _population(window)
    strict = dnsblock.build_prepared(
        snapshot_identity="b" * 64,
        window=window,
        coverage=_coverage(window),
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=dnsblock.BlockInventory(),
        population=population,
        calibration_vector=dnsblock.DnsblockCalibrationVector(
            burst_absolute=200,
            burst_multiple=8,
            burst_active=3,
        ),
    )
    arrival_only = dnsblock.build_prepared(
        snapshot_identity="b" * 64,
        window=window,
        coverage=_coverage(window),
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=dnsblock.BlockInventory(),
        population=population,
        calibration_vector=dnsblock.DnsblockCalibrationVector(
            burst_enabled=False,
        ),
    )
    assert len(strict.analysis.burst_grids) == 75
    assert strict.analysis.bursts == ()
    assert strict.calibration_survivors is not None
    assert strict.calibration_survivors.arrival_memberships
    assert strict.calibration_survivors.burst_memberships
    assert all(
        0 < mask < (1 << 12)
        for _identity, mask in strict.calibration_survivors.arrival_memberships
    )
    assert all(
        0 < mask < (1 << 75)
        for _identity, mask in strict.calibration_survivors.burst_memberships
    )
    arrival_union = GridSurvivorAccumulator(12)
    arrival_union.ingest(strict.calibration_survivors.arrival_memberships)
    assert [row["identity_digest"] for row in arrival_union.aggregate()] == [
        cell.identity_digest for cell in strict.preflight.grids
    ]
    burst_union = GridSurvivorAccumulator(75)
    burst_union.ingest(strict.calibration_survivors.burst_memberships)
    assert [row["identity_digest"] for row in burst_union.aggregate()] == [
        cell.identity_digest for cell in strict.analysis.burst_grids
    ]
    assert len(arrival_only.analysis.burst_grids) == 75
    assert arrival_only.analysis.bursts == ()
    assert arrival_only.analysis.notes.burst_active_required == dnsblock.BURST_ACTIVE
    aggregate = tmp_path / "aggregate.json"
    runner._write_dnsblock_preflight_artifact(aggregate, strict)
    payload = json.loads(aggregate.read_text(encoding="utf-8"))
    assert "calibration_survivors" not in payload
    assert payload["burden"] == {
        "entity_findings": strict.analysis.notes.entity_findings,
        "context_findings": strict.analysis.notes.context_findings,
    }

    cadence = {
        pair: dnsblock.CadenceState(included_gaps=[60.0] * 20)
        for pair in strict.analysis.cadence_worklist
    }
    finalized = dnsblock.finalize_cadence(
        strict,
        status=PreparedStatus(PreparedState.READY),
        results=cadence,
        pass_wall_seconds=(),
    )
    assert finalized.calibration_survivors == strict.calibration_survivors


def test_burst_grid_routes_all_pairs_once_and_uses_earliest_wall_clock_argmax():
    prepared = _prepared()
    analysis = prepared.analysis
    assert len(analysis.burst_grids) == 75
    assert all(sum(dict(cell.route_counts).values()) == 3 for cell in analysis.burst_grids)
    assert len(analysis.bursts) == 2
    overlap = next(item for item in analysis.bursts if item.address == "192.0.2.7")
    expected = prepared.preflight.report_interval[1] - timedelta(days=3)
    assert datetime.fromtimestamp(overlap.peak_period_start, tz=UTC) == expected
    assert overlap.baseline_median_twice == 10
    assert overlap.arrival_subset is not None
    assert dict(analysis.final_shape_routes) == {
        "burst_only": 1,
        "arrival_only": 0,
        "neither": 1,
        "overlap_burst_wins": 1,
    }
    assert analysis.withheld_arrival_burst_pairs == 1


@pytest.mark.parametrize(
    ("counts", "absolute", "multiple", "route", "median_twice"),
    [
        ({0: 5, 1: 5, 2: 100}, 100, 20, "qualifying", 10),
        ({0: 5, 1: 5, 2: 99}, 100, 8, "below_absolute_peak", 10),
        ({0: 20, 1: 20, 2: 100}, 100, 6, "below_peak_multiple", 40),
        ({0: 4, 1: 6, 2: 100, 3: 8}, 100, 8, "qualifying", 12),
    ],
)
def test_burst_thresholds_are_integer_exact(counts, absolute, multiple, route, median_twice):
    result, facts = dnsblock._burst_route(
        counts,
        set(counts),
        absolute_required=absolute,
        multiple_required=multiple,
        active_required=3,
    )
    assert result.value == route
    assert facts is not None
    assert facts[2] == median_twice


def test_weak_lane_refuses_burst_and_recurring_without_grid_evaluation():
    analysis = _prepared(weak=True).analysis
    assert analysis.burst_grids == ()
    assert analysis.bursts == ()
    assert analysis.burst_channel.status is dnsblock.ChannelStatus.ABSTAINED
    assert analysis.burst_channel.cause == "weak_coverage"
    assert analysis.recurring.status is dnsblock.ChannelStatus.ABSTAINED
    notes = runner._format_dnsblock_summary_notes(_prepared(weak=True))
    assert notes[0].startswith("these logs cannot prove how complete each day is")
    assert not any("burst reporting needs" in line for line in notes)


def test_steady_partial_capture_does_not_clear_burst_and_missing_strong_period_speaks():
    route, _facts = dnsblock._burst_route(
        {0: 100, 1: 100, 2: 100, 3: 900},
        {0, 1, 2},  # the apparent partial-period spike is not eligible
        absolute_required=100,
        multiple_required=8,
        active_required=3,
    )
    assert route is dnsblock.BurstRoute.BELOW_PEAK_MULTIPLE

    window = _window()
    assert window.context_interval is not None
    incomplete = CoverageDecision(
        CoverageLane.STRONG,
        CoverageDecisionReason.COMPLETE,
        window.report_interval,
        ((window.context_interval[0], window.report_interval[1] - timedelta(days=1)),),
    )
    prepared = dnsblock.build_prepared(
        snapshot_identity="c" * 64,
        window=window,
        coverage=incomplete,
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=dnsblock.BlockInventory(),
        population=_population(window),
    )
    assert prepared.analysis.recurring.cause == "incomplete_strong_coverage"
    assert prepared.analysis.recurring.missing_periods == 1
    assert any(
        line == (
            "dnsblock: recurring reporting needs every day of the report fully "
            "covered; 1 of 5 were not"
        )
        for line in runner._format_dnsblock_summary_notes(prepared)
    )


def test_recurring_state_and_row_survive_overlap_resolution_and_stay_context_last():
    prepared = _prepared()
    recurring = prepared.analysis.recurring
    assert recurring.status is dnsblock.ChannelStatus.READY
    assert (recurring.pair_count, recurring.family_count, recurring.address_count) == (1, 1, 1)
    findings = dnsblock.run(
        DetectorContext.unsuppressed({}, data_window=prepared.preflight.report_interval),
        _prepared=prepared,
    )
    bursts = [item for item in findings if item.evidence["kind"] == "burst"]
    assert len(bursts) == 2
    assert bursts[0].severity is Severity.LOW
    assert bursts[0].evidence["disposition_grain"] == (
        "global_events_over_association_qualified_names"
    )
    assert findings[-1].evidence["kind"] == "recurring_activity"


def test_arrival_only_shape_and_burst_overlap_do_not_inflate_arrival_fold():
    window = _window()
    state = dnsblock.PopulationState(query_periods=set(range(30)))
    address = "192.0.2.20"
    for name in ("a.alpha.com", "a.beta.net", "a.gamma.org"):
        _add_pair(state, window, address, name, {0: 1, 1: 1, 2: 1, 3: 1})
    _add_pair(
        state,
        window,
        address,
        "a.delta.io",
        {0: 5, 1: 5, 2: 100, 3: 5},
    )
    state.raw_query_rows = state.report_query_rows
    state.raw_block_report_rows = len(state.report_pairs)
    state.filtered_block_report_rows = len(state.report_pairs)
    prepared = dnsblock.build_prepared(
        snapshot_identity="d" * 64,
        window=window,
        coverage=_coverage(window),
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=dnsblock.BlockInventory(),
        population=state,
        calibration_vector=dnsblock.DnsblockCalibrationVector(
            arrival_days=3,
            arrival_history=14,
            burst_absolute=100,
            burst_multiple=8,
            burst_active=3,
        ),
    )
    prepared = dnsblock.finalize_cadence(
        prepared,
        status=PreparedStatus(PreparedState.READY),
        results={
            pair: dnsblock.CadenceState(included_gaps=[60.0] * 20)
            for pair in prepared.analysis.cadence_worklist
        },
        pass_wall_seconds=(),
    )
    assert dict(prepared.analysis.final_shape_routes) == {
        "burst_only": 0,
        "arrival_only": 3,
        "overlap_burst_wins": 1,
        "neither": 0,
    }
    findings = dnsblock.run(
        DetectorContext.unsuppressed({}, data_window=window.report_interval),
        _prepared=prepared,
    )
    kinds = [item.evidence["kind"] for item in findings]
    assert kinds.count("burst") == 1
    assert kinds.count("arrival") == 3
    assert "arrival_fold" not in kinds


def test_short_report_span_keeps_silent_typed_recurring_abstention():
    prepared = _prepared(days=3)
    assert prepared.analysis.recurring.cause == "insufficient_report_span"
    assert not any(
        "recurring analysis" in line
        for line in runner._format_dnsblock_summary_notes(prepared)
    )


def test_note_grammar_rejects_identity_or_non_template_prose():
    with pytest.raises(ValueError, match="non-template"):
        validate_summary_notes(
            {"summary_notes": ["dnsblock: 192.0.2.7 was noisy"]}
        )
    validate_summary_notes(
        {
            "summary_notes": [
                "dnsblock: burst reporting needs 3 covered days and this window has 2",
                "dnsblock: recurring reporting needs every day of the report fully covered; 1 of 5 were not",
            ]
        }
    )
    for seeded in (
        "dnsblock: burst reporting needs 192.0.2.7 covered days and this window has 2",
        "dnsblock: burst reporting needs x.example covered days and this window has 2",
    ):
        with pytest.raises(ValueError, match="non-template"):
            validate_summary_notes(
                {"summary_notes": [seeded]}
            )


def test_recurring_typed_state_is_constructed_without_entity_for_u5_projection():
    prepared = _prepared()
    analysis = prepared.analysis
    hidden = replace(
        analysis,
        bursts=(),
        arrivals=(),
        cadence_worklist=(),
        notes=replace(analysis.notes, entity_findings=0, context_findings=0),
    )
    hidden_prepared = replace(prepared, analysis=hidden, cadence=())
    findings = dnsblock.run(
        DetectorContext.unsuppressed({}, data_window=prepared.preflight.report_interval),
        _prepared=hidden_prepared,
    )
    assert hidden.recurring.pair_count == 1
    assert [item.evidence["kind"] for item in findings] == [
        "prior_handling_exclusions",
        "recurring_activity",
    ]


def test_burst_grid_and_candidates_are_deterministic_under_state_permutation():
    window = _window()
    first = _population(window)
    second = _population(window)
    second.report_pairs = set(reversed(sorted(second.report_pairs)))
    second.pair_period = dict(reversed(list(second.pair_period.items())))
    second.a1_pair = dict(reversed(list(second.a1_pair.items())))
    a = dnsblock._build_burst_facts(first, window, _coverage(window), dnsblock.LIMITS)
    b = dnsblock._build_burst_facts(second, window, _coverage(window), dnsblock.LIMITS)
    assert a == b
