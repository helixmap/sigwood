from __future__ import annotations

import ast
from collections import Counter
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from sigwood import runner
from sigwood.common.finding import DetectorContext, Severity
from sigwood.common.loader import (
    CoverageDecision,
    CoverageDecisionReason,
    CoverageLane,
    DecodedChunk,
    DualWindow,
    FoldAbstention,
    PositionalMask,
    PreparedState,
    PreparedStatus,
)
from sigwood.detectors import dnsblock


UTC = timezone.utc


def _keep(frame):
    return PositionalMask((True,) * len(frame))


def _run_sink(sink, frame):
    chunk = DecodedChunk(
        frame.reset_index(drop=True),
        100,
        (True,) * len(frame),
        (False,) * len(frame),
        0,
    )
    delta = sink.seed_file()
    delta = sink.consume(delta, chunk, sink.mask(chunk.frame))
    return sink.commit_file(sink.seed_run(), delta)


def _window():
    end = datetime(2026, 2, 1, tzinfo=UTC)
    start = end - timedelta(days=4)
    return DualWindow(
        (start, end),
        (start - timedelta(days=25), start - timedelta(microseconds=1)),
    )


def _weak(window):
    return CoverageDecision(
        CoverageLane.WEAK,
        CoverageDecisionReason.OBJECT_UNKNOWN,
        window.report_interval,
    )


def _strong(window):
    assert window.context_interval is not None
    return CoverageDecision(
        CoverageLane.STRONG,
        CoverageDecisionReason.COMPLETE,
        window.report_interval,
        ((window.context_interval[0], window.report_interval[1]),),
    )


def _arrival_population(names=("a.example.com",), *, prior_handling=False):
    window = _window()
    end = window.report_interval[1]
    address = "192.0.2.7"
    pair_period = {}
    a1_pair = {}
    pair_first = {}
    report_pairs = set()
    disposition = {}
    for offset, name in enumerate(names):
        cells = []
        for period in (0, 1, 2):
            ts = (end - timedelta(days=period, hours=1, seconds=offset)).timestamp()
            cell = dnsblock.AssocCell(1, ts, ts)
            pair_period[(address, name, period)] = cell
            cells.append(cell)
            day = datetime.fromtimestamp(ts, tz=UTC).date()
            disposition[(name, day)] = Counter(
                {"gravity_blocked": 1, "forwarded": 1}
            )
        first = min(cell.first_ts for cell in cells)
        a1_pair[(address, name)] = dnsblock.AssocCell(3, first, max(c.last_ts for c in cells))
        pair_first[(address, name)] = first
        report_pairs.add((address, name))
    handling_dates = {}
    handling_cells = 0
    if prior_handling:
        name = names[0]
        handling_dates[name] = {
            datetime.fromtimestamp(a1_pair[(address, name)].first_ts, tz=UTC).date()
            - timedelta(days=1)
        }
        handling_cells = 1
    a1_rows = 3 * len(names)
    return window, dnsblock.PopulationState(
        addresses={address, "192.0.2.99"},
        names=set(names),
        pair_period=pair_period,
        a1_pair=a1_pair,
        pair_first=pair_first,
        address_first={address: (end - timedelta(days=28)).timestamp()},
        handling_dates=handling_dates,
        handling_date_cells=handling_cells,
        query_periods=set(range(21)),
        report_pairs=report_pairs,
        a1_rows=a1_rows,
        a2_rows=a1_rows,
        report_query_rows=a1_rows + 3,
        report_query_rows_by_address=Counter({address: a1_rows, "192.0.2.99": 3}),
        a1_rows_by_address=Counter({address: a1_rows}),
        disposition=disposition,
        disposition_date_cells=len(disposition),
        raw_window_rows=50,
        filtered_window_rows=50,
        raw_query_rows=a1_rows + 3,
        raw_block_report_rows=len(names) * 3,
        filtered_block_report_rows=len(names) * 3,
    )


def _prepared(
    names=("a.example.com",),
    *,
    prior_handling=False,
    strong=False,
):
    window, population = _arrival_population(
        names, prior_handling=prior_handling
    )
    prepared = dnsblock.build_prepared(
        snapshot_identity="a" * 64,
        window=window,
        coverage=_strong(window) if strong else _weak(window),
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=dnsblock.BlockInventory(),
        population=population,
        # These U3 mechanics fixtures were authored against the historical
        # construction cell; keep that instrument explicit after ratification.
        calibration_vector=dnsblock.DnsblockCalibrationVector(
            arrival_days=3,
            arrival_history=14,
        ),
    )
    results = {
        pair: dnsblock.CadenceState(included_gaps=[60.0] * 19)
        for pair in prepared.analysis.cadence_worklist
    }
    return dnsblock.finalize_cadence(
        prepared,
        status=PreparedStatus(PreparedState.READY),
        results=results,
        pass_wall_seconds=(("anchor_block", 1.0), ("cadence", 1.0), ("population", 1.0)),
    )


def test_cadence_gap_bound_is_pair_scoped_and_uses_adjacent_day_runs():
    address = "192.0.2.7"
    other_address = "192.0.2.8"
    day0 = datetime(2026, 1, 1, tzinfo=UTC).date()
    day1 = day0 + timedelta(days=1)
    day3 = day0 + timedelta(days=3)
    state = dnsblock.PopulationState(
        association={
            (address, "a.example.com", day0): dnsblock.AssocCell(count=2),
            (address, "b.example.com", day1): dnsblock.AssocCell(count=3),
            (address, "a.example.com", day3): dnsblock.AssocCell(count=4),
            (address, "other.test", day0): dnsblock.AssocCell(count=100),
            (other_address, "a.example.com", day0): dnsblock.AssocCell(count=100),
        }
    )
    blocks = dnsblock.BlockInventory(
        block_dates={
            "a.example.com": {day0, day3},
            "b.example.com": {day1},
            "other.test": {day0},
        }
    )

    assert dnsblock._cadence_retained_gap_upper_bounds(
        state,
        blocks,
        {(address, "example.com")},
    ) == ((address, "example.com", 7),)


def test_cadence_gap_bound_filters_a2_cells_to_exact_block_membership():
    address = "192.0.2.7"
    day0 = datetime(2026, 1, 1, tzinfo=UTC).date()
    day1 = day0 + timedelta(days=1)
    state = dnsblock.PopulationState(
        association={
            (address, "a.example.com", day0): dnsblock.AssocCell(count=2),
            (address, "a.example.com", day1): dnsblock.AssocCell(count=50),
        }
    )
    blocks = dnsblock.BlockInventory(
        block_dates={"a.example.com": {day0}}
    )

    assert dnsblock._cadence_retained_gap_upper_bounds(
        state,
        blocks,
        {(address, "example.com")},
    ) == ((address, "example.com", 1),)


def _context(prepared):
    return DetectorContext.unsuppressed(
        {}, data_window=prepared.preflight.report_interval
    )


def test_u3_arrival_uses_frozen_voice_evidence_and_cadence_floor():
    prepared = _prepared()
    findings = dnsblock.run(_context(prepared), _prepared=prepared)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.LOW
    assert finding.title == "192.0.2.7 → example.com"
    assert "first observed for this address in the available rows" in finding.description
    assert finding.evidence["novelty_noun"] == "first_observed_available_rows"
    assert finding.evidence["active_periods"] == 3
    assert finding.evidence["eligible_periods"] == 4
    assert finding.evidence["cadence_available"] is False
    assert finding.evidence["gap_count"] is None
    assert "unknown_suffix" not in finding.evidence
    assert finding.next_steps[-1].endswith(
        "add only the exact name patterns you intend to suppress"
    )
    assert "a.example.com" not in repr(finding.evidence)


def test_private_arrival_vectors_materialize_one_frozen_grid_cell_only():
    window, population = _arrival_population()
    historical = dnsblock.build_prepared(
        snapshot_identity="a" * 64,
        window=window,
        coverage=_weak(window),
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=dnsblock.BlockInventory(),
        population=population,
        calibration_vector=dnsblock.DnsblockCalibrationVector(
            arrival_days=3,
            arrival_history=14,
        ),
    )
    selected = dnsblock.build_prepared(
        snapshot_identity="a" * 64,
        window=window,
        coverage=_weak(window),
        block_status=PreparedStatus(PreparedState.READY),
        population_status=PreparedStatus(PreparedState.READY),
        blocks=dnsblock.BlockInventory(),
        population=population,
        calibration_vector=dnsblock.DnsblockCalibrationVector(
            arrival_days=4,
            arrival_history=14,
        ),
    )
    assert len(historical.preflight.grids) == len(selected.preflight.grids) == 12
    assert historical.preflight.grids == selected.preflight.grids
    assert len(historical.analysis.arrivals) == 1
    assert selected.analysis.arrivals == ()
    assert selected.analysis.notes.arrival_days_required == 4
    assert selected.analysis.notes.arrival_history_required == 14


def test_private_calibration_vector_rejects_values_outside_frozen_grids():
    with pytest.raises(ValueError, match="outside the frozen grid"):
        dnsblock.DnsblockCalibrationVector(arrival_days=6)


def test_u3_strong_arrival_uses_available_history_voice():
    prepared = _prepared(strong=True)
    finding = dnsblock.run(_context(prepared), _prepared=prepared)[0]
    assert finding.description == (
        "This was the first available-history activity for this address and "
        "qualifying names grouped under this family key. Those queries appeared "
        "in 3 of 4 covered export periods. First is measured against the 29d of "
        "history this run consulted."
    )
    assert finding.evidence["coverage_lane"] == "strong"
    assert finding.evidence["novelty_noun"] == "first_available_history"


def test_u3_fold_conserves_members_and_report_only_share_facts():
    prepared = _prepared(
        ("a.example.com", "b.example.net", "c.example.org", "d.example.edu")
    )
    findings = dnsblock.run(_context(prepared), _prepared=prepared)
    assert len(findings) == 1
    fold = findings[0]
    assert fold.evidence["kind"] == "arrival_fold"
    assert fold.evidence["member_count"] == 4
    assert len(fold.evidence["members"]) == 4
    assert fold.evidence["members_omitted"] == 0
    assert fold.evidence["shares_available"] is True
    assert fold.evidence["attributed_share_num"] == 12
    assert fold.evidence["attributed_share_den"] == 12
    assert fold.evidence["query_share_num"] == 12
    assert fold.evidence["query_share_den"] == 15
    assert fold.evidence["disposition_grain"] == (
        "global_events_over_fold_member_arrival_qualifying_names"
    )


def test_context_one_is_dual_grain_identity_free_and_last():
    prepared = _prepared(prior_handling=True)
    findings = dnsblock.run(_context(prepared), _prepared=prepared)
    assert len(findings) == 1
    context = findings[-1]
    assert context.severity is Severity.INFO
    assert context.evidence == {
        "kind": "prior_handling_exclusions",
        "withheld_name_count": 1,
        "withheld_membership_count": 1,
    }
    assert "a.example.com" not in context.title + context.description


def test_cadence_reducer_uses_included_gaps_and_population_cv():
    start = datetime(2026, 1, 20, tzinfo=UTC)
    instants = [start + timedelta(minutes=index) for index in range(22)]
    frame = pd.DataFrame(
        {
            "ts": [instant.timestamp() for instant in instants],
            "src": ["192.0.2.7"] * len(instants),
            "query": ["a.example.com"] * len(instants),
            "event_type": ["query"] * len(instants),
            "qtype": ["A"] * len(instants),
            "host": [""] * len(instants),
        }
    )
    inventory = dnsblock.BlockInventory(
        names={"a.example.com"},
        block_dates={"a.example.com": {start.date()}},
    )
    state = _run_sink(
        dnsblock.make_cadence_sink(
            ("192.0.2.7", "example.com"), inventory, _keep
        ),
        frame,
    )
    facts = dnsblock._cadence_facts(state)
    assert facts == dnsblock.CadenceFacts(True, 21, 0.0, 60.0)

    with pytest.raises(FoldAbstention, match="cadence gaps exceed"):
        _run_sink(
            dnsblock.make_cadence_sink(
                ("192.0.2.7", "example.com"),
                inventory,
                _keep,
                limits=replace(dnsblock.LIMITS, cadence_gaps=1),
            ),
            frame.iloc[:3],
        )


def test_cadence_reducer_excludes_six_hour_gap_and_allows_exact_cap():
    start = datetime(2026, 1, 20, tzinfo=UTC)
    instants = [start, start + timedelta(hours=1), start + timedelta(hours=7)]
    frame = pd.DataFrame(
        {
            "ts": [instant.timestamp() for instant in instants],
            "src": ["192.0.2.7"] * 3,
            "query": ["a.example.com"] * 3,
            "event_type": ["query"] * 3,
            "qtype": ["A"] * 3,
            "host": [""] * 3,
        }
    )
    inventory = dnsblock.BlockInventory(
        names={"a.example.com"},
        block_dates={"a.example.com": {start.date()}},
    )
    state = _run_sink(
        dnsblock.make_cadence_sink(
            ("192.0.2.7", "example.com"),
            inventory,
            _keep,
            limits=replace(dnsblock.LIMITS, cadence_gaps=1),
        ),
        frame,
    )
    assert state.included_gaps == [3600.0]


def test_cadence_batch_matches_independent_pair_reducers():
    start = datetime(2026, 1, 20, tzinfo=UTC)
    rows = []
    for address, name, offset in (
        ("192.0.2.7", "a.example.com", 0),
        ("192.0.2.8", "b.example.net", 15),
    ):
        for index in range(22):
            rows.append(
                {
                    "ts": (start + timedelta(seconds=offset, minutes=index)).timestamp(),
                    "src": address,
                    "query": name,
                    "event_type": "query",
                    "qtype": "A",
                    "host": "",
                }
            )
    frame = pd.DataFrame(rows).sort_values("ts").reset_index(drop=True)
    inventory = dnsblock.BlockInventory(
        names={"a.example.com", "b.example.net"},
        block_dates={
            "a.example.com": {start.date()},
            "b.example.net": {start.date()},
        },
    )
    pairs = (("192.0.2.7", "example.com"), ("192.0.2.8", "example.net"))
    batch = _run_sink(
        dnsblock.make_cadence_batch_sink(pairs, inventory, _keep), frame
    )
    for pair in pairs:
        independent = _run_sink(
            dnsblock.make_cadence_sink(pair, inventory, _keep), frame
        )
        assert batch.states[pair] == independent


def test_cadence_batch_enforces_total_in_flight_gap_cap():
    start = datetime(2026, 1, 20, tzinfo=UTC)
    frame = pd.DataFrame(
        {
            "ts": [
                start.timestamp(),
                (start + timedelta(minutes=1)).timestamp(),
                (start + timedelta(seconds=30)).timestamp(),
                (start + timedelta(minutes=1, seconds=30)).timestamp(),
            ],
            "src": ["192.0.2.7", "192.0.2.7", "192.0.2.8", "192.0.2.8"],
            "query": ["a.example.com", "a.example.com", "b.example.net", "b.example.net"],
            "event_type": ["query"] * 4,
            "qtype": ["A"] * 4,
            "host": [""] * 4,
        }
    )
    inventory = dnsblock.BlockInventory(
        names={"a.example.com", "b.example.net"},
        block_dates={
            "a.example.com": {start.date()},
            "b.example.net": {start.date()},
        },
    )
    with pytest.raises(FoldAbstention, match="cadence gaps exceed"):
        _run_sink(
            dnsblock.make_cadence_batch_sink(
                (("192.0.2.7", "example.com"), ("192.0.2.8", "example.net")),
                inventory,
                _keep,
                limits=replace(dnsblock.LIMITS, cadence_gaps=1),
            ),
            frame,
        )


def test_sink_local_window_classification_overrides_broad_physical_masks():
    report_start = datetime(2026, 1, 2, tzinfo=UTC)
    report_end = datetime(2026, 1, 3, tzinfo=UTC)
    context_start = datetime(2026, 1, 1, tzinfo=UTC)
    context_end = report_start - timedelta(microseconds=1)
    instants = (
        context_start,
        context_end,
        report_start,
        report_end,
        report_end + timedelta(microseconds=1),
    )
    frame = pd.DataFrame(
        {
            "ts": [instant.timestamp() for instant in instants],
            "src": ["192.0.2.7"] * len(instants),
            "query": ["a.example.com"] * len(instants),
            "event_type": ["query"] * len(instants),
            "qtype": ["A"] * len(instants),
            "host": [""] * len(instants),
        }
    )
    chunk = DecodedChunk(
        frame,
        100,
        (True,) * len(frame),
        (False,) * len(frame),
        0,
    )
    report, context = dnsblock._sink_membership_masks(
        chunk,
        DualWindow((report_start, report_end), (context_start, context_end)),
    )
    assert report.tolist() == [False, False, True, True, False]
    assert context.tolist() == [True, True, False, False, False]


def test_cadence_batch_uses_each_sink_local_report_interval():
    start = datetime(2026, 1, 20, tzinfo=UTC)
    frame = pd.DataFrame(
        {
            "ts": [
                (start - timedelta(minutes=1)).timestamp(),
                start.timestamp(),
                (start + timedelta(minutes=1)).timestamp(),
            ],
            "src": ["192.0.2.7"] * 3,
            "query": ["a.example.com"] * 3,
            "event_type": ["query"] * 3,
            "qtype": ["A"] * 3,
            "host": [""] * 3,
        }
    )
    inventory = dnsblock.BlockInventory(
        names={"a.example.com"},
        block_dates={"a.example.com": {start.date()}},
    )
    pair = ("192.0.2.7", "example.com")
    batch = _run_sink(
        dnsblock.make_cadence_batch_sink(
            (pair,),
            inventory,
            _keep,
            window=DualWindow((start, start + timedelta(minutes=1))),
        ),
        frame,
    )
    assert batch.states[pair].included_gaps == [60.0]


def test_cadence_floor_even_median_and_ddof_zero_are_exact():
    assert dnsblock._cadence_facts(
        dnsblock.CadenceState(included_gaps=[60.0] * 19)
    ) == dnsblock.CadenceFacts(False, None, None, None)

    gaps = [float(value) for value in range(1, 21)]
    facts = dnsblock._cadence_facts(dnsblock.CadenceState(included_gaps=gaps))
    mean = sum(gaps) / len(gaps)
    expected_cv = (
        sum((value - mean) ** 2 for value in gaps) / len(gaps)
    ) ** 0.5 / mean
    assert facts.cadence_available is True
    assert facts.gap_count == 20
    assert facts.gap_median_s == 10.5
    assert facts.gap_cv == pytest.approx(expected_cv)


def test_note_projector_is_fixed_order_and_suppression_conserves():
    prepared = _prepared()
    facts = replace(
        prepared.analysis.notes,
        insufficient_history_pairs=2,
        synchronized_pairs=1,
        synchronized_addresses=3,
        raw_block_report_rows=5,
        filtered_block_report_rows=4,
        raw_block_context_rows=2,
        filtered_block_context_rows=0,
    )
    prepared = replace(
        prepared,
        analysis=replace(prepared.analysis, notes=facts),
    )
    notes = runner._format_dnsblock_summary_notes(prepared)
    assert notes[0].startswith("period coverage is not verifiable")
    assert notes[1] == (
        "dnsblock: 2 candidate pairs withheld \N{EM DASH} not enough prior history "
        "in the loaded window"
    )
    assert notes[2].startswith("dnsblock: 1 synchronized first appearance withheld")
    assert notes[3] == (
        "dnsblock: the allowlist removed 1 block-outcome row from the report interval and 2 from context"
    )


def test_note_projector_uses_detector_owned_vector_facts():
    prepared = _prepared()
    facts = replace(
        prepared.analysis.notes,
        arrival_days_required=4,
        arrival_history_required=9,
        insufficient_context_periods=8,
        insufficient_arrival_coverage=2,
    )
    notes = runner._format_dnsblock_summary_notes(
        replace(prepared, analysis=replace(prepared.analysis, notes=facts))
    )
    assert "arrival analysis needs at least 9 prior periods" in notes[1]
    assert "first-activity analysis needs 4 eligible periods" in notes[2]


def test_note_projector_hides_nonconserving_suppression_state():
    prepared = _prepared()
    facts = replace(
        prepared.analysis.notes,
        raw_block_report_rows=0,
        filtered_block_report_rows=1,
    )
    notes = runner._format_dnsblock_summary_notes(
        replace(prepared, analysis=replace(prepared.analysis, notes=facts))
    )
    assert not any("allowlist removed" in note for note in notes)


def test_cap_note_table_is_lockstep_with_every_detector_cap_cause():
    tree = ast.parse(Path(dnsblock.__file__).read_text(encoding="utf-8"))
    causes = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("dnsblock ")
        and " exceed" in node.value
    }
    assert causes
    matched_tokens = set()
    for cause in causes:
        matches = [
            entry for entry in runner._DNSBLOCK_CAP_NOTES if entry[0] in cause
        ]
        assert len(matches) == 1, cause
        matched_tokens.add(matches[0][0])
        assert runner._dnsblock_cap_note(cause) is not None
    assert matched_tokens == {entry[0] for entry in runner._DNSBLOCK_CAP_NOTES}
    assert runner._dnsblock_cap_note("dnsblock unmatched cap cause") is None


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        (
            {
                "raw_query_rows": 0,
                "raw_block_report_rows": 0,
                "filtered_block_report_rows": 0,
            },
            "dnsblock: no Pi-hole query rows in the window",
        ),
        (
            {
                "raw_query_rows": 2,
                "raw_block_report_rows": 0,
                "filtered_block_report_rows": 0,
            },
            "dnsblock: no blocked-name outcomes logged in the window",
        ),
        (
            {
                "raw_query_rows": 2,
                "raw_block_report_rows": 1,
                "filtered_block_report_rows": 0,
            },
            "dnsblock: all block-outcome rows were removed by the allowlist",
        ),
        (
            {
                "raw_query_rows": 2,
                "raw_block_report_rows": 1,
                "filtered_block_report_rows": 1,
            },
            "dnsblock: blocked-name activity found, but nothing met the reporting thresholds",
        ),
    ],
)
def test_note_projector_zero_cause_precedence_uses_query_population(
    overrides,
    expected,
):
    prepared = _prepared()
    facts = replace(
        prepared.analysis.notes,
        entity_findings=0,
        context_findings=0,
        **overrides,
    )
    notes = runner._format_dnsblock_summary_notes(
        replace(prepared, analysis=replace(prepared.analysis, notes=facts))
    )
    assert notes[-1] == expected


def test_family_fallback_distinguishes_real_psl_apex_from_unknown_suffix():
    assert dnsblock._family("example.com") == ("example.com", False)
    family, unknown = dnsblock._family("host.invalid-sigwood-suffix")
    assert family == "host.invalid-sigwood-suffix"
    assert unknown is True


def test_actual_pair_routes_conserve_the_complete_frozen_vocabulary():
    def route(state):
        window = _window()
        return dnsblock._route_population(
            state,
            window,
            _weak(window),
            dnsblock.LIMITS,
            # This vocabulary fixture exercises the historical qualifying
            # route, not the shipped default pinned in test_dnsblock_detector.
            days_required=3,
            history_required=14,
            materialize=False,
        ).pair_routes

    _window_value, baseline = _arrival_population()
    assert route(baseline) == Counter({dnsblock.PairRoute.QUALIFYING.value: 1})

    no_name = copy.deepcopy(baseline)
    name = "a.example.com"
    first_day = datetime.fromtimestamp(
        no_name.a1_pair[("192.0.2.7", name)].first_ts, tz=UTC
    ).date()
    no_name.handling_dates[name] = {first_day - timedelta(days=1)}
    assert route(no_name) == Counter(
        {dnsblock.PairRoute.NO_QUALIFYING_NAME.value: 1}
    )

    short = copy.deepcopy(baseline)
    short.query_periods = set(range(14))
    assert route(short) == Counter(
        {dnsblock.PairRoute.INSUFFICIENT_HISTORY.value: 1}
    )

    unready = copy.deepcopy(baseline)
    unready.address_first["192.0.2.7"] = (
        _window().report_interval[1] - timedelta(days=2)
    ).timestamp()
    assert route(unready) == Counter(
        {dnsblock.PairRoute.NO_PRIOR_ADDRESS_ACTIVITY.value: 1}
    )

    inactive = copy.deepcopy(baseline)
    inactive.pair_period.pop(("192.0.2.7", name, 1))
    assert route(inactive) == Counter(
        {dnsblock.PairRoute.INSUFFICIENT_ACTIVE_PERIODS.value: 1}
    )

    synchronized = copy.deepcopy(baseline)
    source_address = "192.0.2.7"
    for address in ("192.0.2.8", "192.0.2.9"):
        for (seen_address, seen_name, period), cell in list(
            baseline.pair_period.items()
        ):
            if seen_address == source_address:
                synchronized.pair_period[(address, seen_name, period)] = copy.deepcopy(cell)
        synchronized.a1_pair[(address, name)] = copy.deepcopy(
            baseline.a1_pair[(source_address, name)]
        )
        synchronized.pair_first[(address, name)] = baseline.pair_first[
            (source_address, name)
        ]
        synchronized.report_pairs.add((address, name))
        synchronized.address_first[address] = baseline.address_first[source_address]
    sync_routes = route(synchronized)
    assert sync_routes == Counter({dnsblock.PairRoute.SYNC_WITHHELD.value: 3})
    assert sum(sync_routes.values()) == len(synchronized.report_pairs)
