from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

import sigwood.common.loader as loader
from sigwood.common.finding import DetectorContext
from sigwood.common.loader import (
    CoverageDecision,
    CoverageDecisionReason,
    CoverageLane,
    DecodedChunk,
    DualWindow,
    FoldAbstention,
    PreparedState,
    PreparedStatus,
)
from sigwood.detectors import dnsblock


UTC = timezone.utc


def test_shipped_calibration_matches_the_selected_vector():
    """Literal pins keep default drift visible to the vector-flip test."""
    vector = dnsblock.DnsblockCalibrationVector()

    assert (dnsblock.ARRIVAL_DAYS, dnsblock.ARRIVAL_HISTORY) == (5, 21)
    assert (dnsblock.BURST_ABS, dnsblock.BURST_MULT, dnsblock.BURST_ACTIVE) == (
        400,
        12,
        4,
    )
    assert dnsblock.ARRIVAL_VECTOR_SHIPPED is True
    assert dnsblock.BURST_VECTOR_SHIPPED is True
    assert (
        vector.arrival_days,
        vector.arrival_history,
        vector.burst_absolute,
        vector.burst_multiple,
        vector.burst_active,
        vector.burst_enabled,
    ) == (5, 21, 400, 12, 4, True)


def _run_sink(sink, frame, report, context=None):
    context = context or [False] * len(frame)
    chunk = DecodedChunk(
        frame.reset_index(drop=True),
        100,
        tuple(report),
        tuple(context),
        0,
    )
    delta = sink.seed_file()
    delta = sink.consume(delta, chunk, sink.mask(chunk.frame))
    return sink.commit_file(sink.seed_run(), delta)


def _keep(frame):
    from sigwood.common.loader import PositionalMask
    return PositionalMask((True,) * len(frame))


def _execute_sink_once(tmp_path, sink, frame, report, context=None):
    path = tmp_path / "one.log"
    path.write_text("one\n", encoding="utf-8")
    snapshot = loader.build_source_snapshot([path], "flat")
    context = context or [False] * len(frame)
    chunk = DecodedChunk(
        frame.reset_index(drop=True),
        100,
        tuple(report),
        tuple(context),
        0,
    )
    return loader.execute_sink_plan(
        snapshot,
        loader.SinkPlan((sink,), preserve_frame=False),
        lambda _item: [chunk],
    )


def _history_prepared(
    *, context_interval: tuple[datetime, datetime] | None
) -> dnsblock.DnsblockPrepared:
    end = datetime(2026, 1, 10, tzinfo=UTC)
    report_interval = (end - timedelta(days=2), end)
    disposition = dnsblock.DispositionFacts(0, 0, 0, 0, (), 0)
    cadence = dnsblock.CadenceFacts(True, 0, 0.0, 3600.0)

    def arrival(address: str, family: str, hours: int) -> dnsblock.ArrivalCandidate:
        return dnsblock.ArrivalCandidate(
            address=address,
            family_key=family,
            unknown_suffix=False,
            qualifying_names=(f"x.{family}",),
            attributed_query_count=3,
            qualifying_name_count=1,
            active_periods=2,
            eligible_periods=5,
            first_associated_ts=(end - timedelta(hours=hours)).timestamp(),
            prior_other_address_count=0,
            prior_other_address_count_at_cap=False,
            disposition=disposition,
        )

    arrivals = (
        arrival("192.0.2.7", "single.test", 3),
        arrival("192.0.2.8", "a.test", 7),
        arrival("192.0.2.8", "b.test", 6),
        arrival("192.0.2.8", "c.test", 5),
        arrival("192.0.2.8", "d.test", 4),
    )
    preflight = dnsblock.DnsblockPreflight(
        state=PreparedState.READY,
        cause="",
        snapshot_identity="a" * 64,
        report_interval=report_interval,
        context_interval=context_interval,
        coverage_lane=CoverageLane.STRONG,
        coverage_reason="fixture",
        coverage_union=tuple(
            interval
            for interval in (context_interval, report_interval)
            if interval is not None
        ),
        raw_event_counts=(),
        drop_counts=(),
        rows_kept=5,
        rows_suppressed=0,
        a1_rows=5,
        a2_rows=0,
        association_cells=5,
        address_name_pairs=5,
        name_routes=(),
        grids=(),
        resident_bytes=0,
    )
    analysis = dnsblock.AnalysisFacts(
        arrivals=arrivals,
        bursts=(),
        burst_grids=(),
        burst_channel=dnsblock.ChannelFacts(
            dnsblock.ChannelStatus.READY, "", 4, 5
        ),
        recurring=dnsblock.RecurringFacts(
            dnsblock.ChannelStatus.READY, "", 4, 5, 5, 0, 0, 0, 0
        ),
        final_shape_routes=(),
        withheld_arrival_burst_pairs=0,
        cadence_worklist=tuple(
            (item.address, item.family_key) for item in arrivals
        ),
        cadence_query_event_upper_bounds=(),
        pair_routes=(),
        prior_handling_names=0,
        prior_handling_memberships=0,
        report_query_rows=15,
        report_query_rows_by_address=(("192.0.2.7", 3), ("192.0.2.8", 12)),
        a1_rows=15,
        a1_rows_by_address=(("192.0.2.7", 3), ("192.0.2.8", 12)),
        notes=dnsblock.DnsblockNoteFacts(CoverageLane.STRONG, 3, 14),
    )
    return dnsblock.DnsblockPrepared(
        preflight=preflight,
        analysis=analysis,
        cadence=tuple(
            (item.address, item.family_key, cadence) for item in arrivals
        ),
        cadence_complete=True,
    )


@pytest.mark.parametrize("with_context", [False, True])
def test_arrival_history_is_the_single_consulted_span_and_exactly_additive(
    with_context,
):
    end = datetime(2026, 1, 10, tzinfo=UTC)
    context_interval = (
        (end - timedelta(days=21), end - timedelta(days=2, microseconds=1))
        if with_context
        else None
    )
    prepared = _history_prepared(context_interval=context_interval)
    findings = dnsblock.run(
        DetectorContext.unsuppressed(
            {}, data_window=prepared.preflight.report_interval
        ),
        _prepared=prepared,
    )
    arrivals = [
        finding
        for finding in findings
        if finding.evidence["kind"] in {"arrival", "arrival_fold"}
    ]
    expected_seconds = float((21 if with_context else 2) * 24 * 60 * 60)
    assert [finding.evidence["kind"] for finding in arrivals] == [
        "arrival_fold",
        "arrival",
    ]
    assert {finding.evidence["history_seconds"] for finding in arrivals} == {
        expected_seconds
    }

    qualifier = (
        f"First is measured against the {21 if with_context else 2}d of history "
        "this run consulted."
    )
    assert all(finding.description.endswith(qualifier) for finding in arrivals)

    ordinary_old = {
        "kind", "coverage_lane", "address", "family_key", "novelty_noun",
        "attributed_query_count", "qualifying_name_count", "active_periods",
        "eligible_periods", "first_associated_period",
        "prior_other_address_count", "prior_other_address_count_at_cap",
        "gravity_blocked", "regex_blocked", "forwarded", "cached",
        "disposition_grain", "disposition_by_day", "disposition_by_day_omitted",
        "cadence_available", "gap_count", "gap_cv", "gap_median_s",
    }
    fold_old = {
        "kind", "coverage_lane", "address", "member_count",
        "earliest_first_associated_period", "members", "members_omitted",
        "attributed_share_num", "attributed_share_den", "query_share_num",
        "query_share_den", "distinct_report_addresses", "shares_available",
        "gravity_blocked", "regex_blocked", "forwarded", "cached",
        "disposition_grain", "disposition_by_day", "disposition_by_day_omitted",
    }
    by_kind = {finding.evidence["kind"]: finding for finding in arrivals}
    assert set(by_kind["arrival"].evidence) == ordinary_old | {"history_seconds"}
    assert set(by_kind["arrival_fold"].evidence) == fold_old | {"history_seconds"}


def test_normalization_is_bounded_and_ipv4_mapped_is_canonical():
    assert dnsblock.normalize_name("A.Example.") == ("a.example", None)
    assert dnsblock.normalize_name("single")[0] is None
    assert dnsblock.normalize_name("bad\x00.example")[1] is dnsblock.DropReason.CONTROL_IN_NAME
    assert dnsblock.normalize_address("::ffff:192.0.2.7") == ("192.0.2.7", None)


def test_name_cap_abstains_without_partial_inventory():
    start = datetime(2026, 1, 1, tzinfo=UTC).timestamp()
    frame = pd.DataFrame(
        {
            "ts": [start, start + 1],
            "src": [None, None],
            "query": ["a.example", "b.example"],
            "event_type": ["gravity_blocked", "regex_blocked"],
            "qtype": [None, None],
            "host": ["", ""],
        }
    )
    sink = dnsblock.make_block_sink(
        _keep,
        limits=dnsblock.DnsblockLimits(names=1),
    )
    with pytest.raises(FoldAbstention, match="names exceed"):
        _run_sink(sink, frame, [True, True])


@pytest.mark.parametrize(
    ("axis", "limit", "cause"),
    [
        ("association_cells", 1, "association cells exceed"),
        ("address_name_pairs", 1, "address-name pairs exceed"),
        ("pair_period_cells", 1, "pair-period cells exceed"),
        ("address_date_cells", 1, "address-date cells exceed"),
        ("addresses", 1, "addresses exceed"),
        ("names", 1, "names exceed"),
        ("string_bytes", 1, "retained strings exceed"),
    ],
)
def test_population_cap_table_abstains_without_partial_state(
    tmp_path, axis, limit, cause
):
    end = datetime(2026, 1, 10, 12, tzinfo=UTC)
    window = DualWindow((end - timedelta(days=3), end))
    instants = [end - timedelta(hours=1), end - timedelta(days=1, hours=1)]
    names = ["x.example", "y.example"]
    frame = pd.DataFrame(
        {
            "ts": [instant.timestamp() for instant in instants],
            "src": ["192.0.2.7", "192.0.2.8"],
            "query": names,
            "event_type": ["query", "query"],
            "qtype": ["A", "A"],
            "host": ["", ""],
        }
    )
    blocks = dnsblock.BlockInventory(
        names=set(names),
        block_dates={
            name: {instant.date()} for name, instant in zip(names, instants)
        },
    )
    limits = replace(dnsblock.LIMITS, **{axis: limit})
    sink = dnsblock.make_population_sink(blocks, window, _keep, limits=limits)
    result = _execute_sink_once(tmp_path, sink, frame, [True, True])
    assert result.statuses[sink.channel].state is PreparedState.ABSTAINED
    assert cause in result.statuses[sink.channel].cause
    assert sink.channel not in result.results


def test_name_date_cap_abstains_without_partial_state(tmp_path):
    start = datetime(2026, 1, 1, 12, tzinfo=UTC)
    frame = pd.DataFrame(
        {
            "ts": [start.timestamp(), (start + timedelta(days=1)).timestamp()],
            "src": [None, None],
            "query": ["x.example", "x.example"],
            "event_type": ["gravity_blocked", "gravity_blocked"],
            "qtype": [None, None],
            "host": ["", ""],
        }
    )
    limits = replace(dnsblock.LIMITS, name_date_cells=1)
    sink = dnsblock.make_block_sink(_keep, limits=limits)
    result = _execute_sink_once(tmp_path, sink, frame, [True, True])
    assert result.statuses[sink.channel].state is PreparedState.ABSTAINED
    assert "name-date cells exceed" in result.statuses[sink.channel].cause
    assert sink.channel not in result.results


def test_finalized_block_inventory_matches_dedicated_pass_on_straddling_start_date():
    report_start = datetime(2026, 1, 10, 12, tzinfo=UTC)
    report_end = datetime(2026, 1, 11, tzinfo=UTC)
    frame = pd.DataFrame(
        {
            "ts": [
                (report_start - timedelta(hours=2)).timestamp(),
                (report_start + timedelta(hours=1)).timestamp(),
                (report_start - timedelta(hours=3)).timestamp(),
                (report_start - timedelta(hours=1)).timestamp(),
            ],
            "src": [None] * 4,
            "query": ["straddle.example", "straddle.example", "context.example", "context.example"],
            "event_type": ["gravity_blocked"] * 4,
            "qtype": [None] * 4,
            "host": [""] * 4,
        }
    )
    report_mask = [False, True, False, False]
    dedicated = _run_sink(
        dnsblock.make_block_sink(_keep), frame, report_mask
    )
    combined = _run_sink(
        dnsblock.make_anchor_block_sink(_keep), frame, report_mask
    )
    straddling = combined.blocks.cells[
        ("straddle.example", report_start.date())
    ]
    assert straddling.count == 2
    assert straddling.first_ts < report_start.timestamp() <= straddling.last_ts
    finalized = dnsblock.finalize_block_inventory(
        combined.blocks, (report_start, report_end)
    )
    assert finalized.names == dedicated.names == {"straddle.example"}
    assert finalized.block_dates == dedicated.block_dates


def test_population_preflight_has_all_twelve_grid_cells_and_a1_subset():
    report_end = datetime(2026, 1, 31, tzinfo=UTC)
    report_start = report_end - timedelta(days=10)
    window = DualWindow(
        (report_start, report_end),
        (report_start - timedelta(days=25), report_start - timedelta(microseconds=1)),
    )
    block_ts = (report_end - timedelta(days=2, hours=1)).timestamp()
    blocks_frame = pd.DataFrame(
        {
            "ts": [block_ts], "src": [None], "query": ["x.example"],
            "event_type": ["gravity_blocked"], "qtype": [None], "host": [""],
        }
    )
    blocks = _run_sink(dnsblock.make_block_sink(_keep), blocks_frame, [True])
    rows = []
    report_mask = []
    context_mask = []
    for days in range(20, 0, -1):
        ts = (report_start - timedelta(days=days, hours=1)).timestamp()
        rows.append((ts, "192.0.2.7", "other.example", "query", "A", ""))
        report_mask.append(False)
        context_mask.append(True)
    rows.extend(
        [
            (block_ts, "192.0.2.7", "x.example", "query", "A", ""),
            ((report_end - timedelta(days=1, hours=1)).timestamp(), "192.0.2.7", "x.example", "query", "A", ""),
        ]
    )
    report_mask.extend([True, True])
    context_mask.extend([False, False])
    frame = pd.DataFrame(rows, columns=["ts", "src", "query", "event_type", "qtype", "host"])
    population = _run_sink(
        dnsblock.make_population_sink(blocks, window, _keep),
        frame,
        report_mask,
        context_mask,
    )
    coverage = CoverageDecision(
        CoverageLane.WEAK,
        CoverageDecisionReason.OBJECT_UNKNOWN,
        window.report_interval,
    )
    prepared = dnsblock.build_prepared(
        snapshot_identity="a" * 64,
        window=window,
        coverage=coverage,
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=blocks,
        population=population,
    )
    assert prepared.preflight.state is PreparedState.READY
    assert prepared.preflight.a1_rows <= prepared.preflight.a2_rows
    assert len(prepared.preflight.grids) == 12


def test_run_rejects_missing_prepared_carrier_with_actionable_valueerror():
    context = DetectorContext.unsuppressed(
        {}, data_window=(datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 2, tzinfo=UTC))
    )
    with pytest.raises(ValueError, match="requires runner-prepared preflight"):
        dnsblock.run(context)


def _manual_population(window, *, history_periods, address_first, pair_first):
    address = "192.0.2.7"
    name = "x.example"
    first = (window.report_interval[1] - timedelta(hours=1)).timestamp()
    cell = dnsblock.AssocCell(2, first, first + 1)
    state = dnsblock.PopulationState(
        addresses={address},
        names={name},
        association={(address, name, datetime.fromtimestamp(first, tz=UTC).date()): cell},
        pair_period={(address, name, 0): cell},
        pair_first={(address, name): pair_first},
        address_first={address: address_first},
        query_periods=set(history_periods),
        report_pairs={(address, name)},
        a1_rows=2,
        a2_rows=2,
    )
    return state


def _weak(window):
    return CoverageDecision(
        CoverageLane.WEAK,
        CoverageDecisionReason.OBJECT_UNKNOWN,
        window.report_interval,
    )


def test_period_boundaries_match_scalar_and_vectorized_paths():
    report_end = datetime(2026, 1, 10, 12, tzinfo=UTC)
    report_start = report_end - timedelta(days=2)
    history_start = report_end - timedelta(days=3, hours=12)
    window = DualWindow(
        (report_start, report_end),
        (history_start, report_start - timedelta(microseconds=1)),
    )
    right_closed = report_end - timedelta(days=1)
    leading_partial = report_end - timedelta(days=3, hours=6)

    assert dnsblock._period_index(right_closed.timestamp(), window) == 1
    assert dnsblock._period_index(report_start.timestamp(), window) is None
    assert dnsblock._period_index(leading_partial.timestamp(), window) is None

    instants = [right_closed, report_start, leading_partial]
    frame = pd.DataFrame(
        {
            "ts": [instant.timestamp() for instant in instants],
            "src": ["192.0.2.7"] * 3,
            "query": ["x.example"] * 3,
            "event_type": ["query"] * 3,
            "qtype": ["A"] * 3,
            "host": [""] * 3,
        }
    )
    blocks = dnsblock.BlockInventory(
        names={"x.example"},
        block_dates={"x.example": {instant.date() for instant in instants}},
    )
    population = _run_sink(
        dnsblock.make_population_sink(blocks, window, _keep),
        frame,
        [True, True, False],
        [False, False, True],
    )
    assert population.rows_kept == 3
    assert population.a2_rows == 2
    assert population.query_periods == {1}
    assert {period for _address, _name, period in population.pair_period} == {1}


@pytest.mark.parametrize(
    ("axis", "coverage", "cause"),
    [
        ("families", None, "families exceed"),
        ("worklist", None, "worklist exceeds"),
        ("per_window_routes", None, "per-window routes exceed"),
        ("coverage_spans", "strong", "coverage spans exceed"),
    ],
)
def test_postfold_cap_table_abstains_without_partial_prepared_state(
    axis, coverage, cause
):
    end = datetime(2026, 2, 1, tzinfo=UTC)
    window = DualWindow((end - timedelta(days=2), end))
    address = "192.0.2.7"
    name = "x.example"
    instant = end - timedelta(hours=1)
    cell = dnsblock.AssocCell(1, instant.timestamp(), instant.timestamp())
    population = dnsblock.PopulationState(
        addresses={address},
        names={name},
        pair_period={(address, name, 0): cell},
        pair_first={(address, name): instant.timestamp()},
        address_first={address: (end - timedelta(days=10)).timestamp()},
        query_periods={0},
        report_pairs={(address, name)},
        a1_rows=1,
        a2_rows=1,
    )
    decision = (
        CoverageDecision(
            CoverageLane.STRONG,
            CoverageDecisionReason.COMPLETE,
            window.report_interval,
            trusted_intervals=(window.report_interval,),
        )
        if coverage == "strong"
        else _weak(window)
    )
    limits = replace(dnsblock.LIMITS, **{axis: 0})
    prepared = dnsblock.build_prepared(
        snapshot_identity="a" * 64,
        window=window,
        coverage=decision,
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=dnsblock.BlockInventory(),
        population=population,
        limits=limits,
    )
    assert prepared.preflight.state is PreparedState.ABSTAINED
    assert cause in prepared.preflight.cause
    if axis == "coverage_spans":
        assert prepared.preflight.coverage_union == ()
    assert prepared.preflight.name_routes == ()
    assert prepared.preflight.grids == ()


def test_readiness_negatives_keep_positive_observations_outside_lane_one():
    end = datetime(2026, 2, 1, tzinfo=UTC)
    window = DualWindow(
        (end - timedelta(days=2), end),
        (end - timedelta(days=30), end - timedelta(days=2, microseconds=1)),
    )
    candidate_start = end - timedelta(days=1)
    first_assoc = (end - timedelta(hours=1)).timestamp()

    thirteen = _manual_population(
        window,
        history_periods=range(1, 14),
        address_first=(end - timedelta(days=20)).timestamp(),
        pair_first=first_assoc,
    )
    _names, grids = dnsblock._population_facts(
        thirteen, window, _weak(window), dnsblock.LIMITS
    )
    cell_14 = next(g for g in grids if g.days_required == 2 and g.history_required == 14)
    assert dict(cell_14.route_counts)["insufficient_history"] == 1

    same_period = _manual_population(
        window,
        history_periods=range(1, 23),
        address_first=(candidate_start + timedelta(hours=1)).timestamp(),
        pair_first=first_assoc,
    )
    _names, grids = dnsblock._population_facts(
        same_period, window, _weak(window), dnsblock.LIMITS
    )
    cell_7 = next(g for g in grids if g.days_required == 2 and g.history_required == 7)
    assert dict(cell_7.route_counts)["no_prior_address_activity"] == 1

    ineligible_prior = _manual_population(
        window,
        history_periods=range(1, 23),
        address_first=(end - timedelta(days=20)).timestamp(),
        pair_first=(end - timedelta(days=4)).timestamp(),
    )
    names, _grids = dnsblock._population_facts(
        ineligible_prior, window, _weak(window), dnsblock.LIMITS
    )
    assert names["prior_address_query"] == 1


def test_detector_population_code_never_opens_paths(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("detector must not open a path")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    assert dnsblock.normalize_name("safe.example") == ("safe.example", None)
    dnsblock.make_anchor_sink()
    dnsblock.make_block_sink(_keep)


def test_future_row_outside_dual_window_cannot_change_grid_digests():
    end = datetime(2026, 2, 1, tzinfo=UTC)
    window = DualWindow((end - timedelta(days=10), end))
    block_ts = (end - timedelta(days=1)).timestamp()
    block_frame = pd.DataFrame(
        [(block_ts, None, "x.example", "gravity_blocked", None, "")],
        columns=["ts", "src", "query", "event_type", "qtype", "host"],
    )
    blocks = _run_sink(dnsblock.make_block_sink(_keep), block_frame, [True])
    base_frame = pd.DataFrame(
        [(block_ts, "192.0.2.7", "x.example", "query", "A", "")],
        columns=["ts", "src", "query", "event_type", "qtype", "host"],
    )
    base = _run_sink(
        dnsblock.make_population_sink(blocks, window, _keep),
        base_frame,
        [True],
    )
    future_frame = pd.concat(
        [
            base_frame,
            pd.DataFrame(
                [((end + timedelta(days=1)).timestamp(), "192.0.2.9", "x.example", "query", "A", "")],
                columns=base_frame.columns,
            ),
        ],
        ignore_index=True,
    )
    with_future = _run_sink(
        dnsblock.make_population_sink(blocks, window, _keep),
        future_frame,
        [True, False],
    )
    base_grids = dnsblock._population_facts(base, window, _weak(window), dnsblock.LIMITS)[1]
    future_grids = dnsblock._population_facts(
        with_future, window, _weak(window), dnsblock.LIMITS
    )[1]
    assert [cell.identity_digest for cell in base_grids] == [
        cell.identity_digest for cell in future_grids
    ]
