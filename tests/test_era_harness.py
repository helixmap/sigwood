"""Private era harness fold and receipt contracts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect

import pandas as pd

from sigwood.common import loader
from sigwood.era.harness import make_era_fold_sink
from sigwood.era.planner import (
    ArchiveDateGroup,
    ArchivePlan,
    BaselineReconciliation,
    FamilyInventory,
    InventoryState,
    WorkEstimate,
)
from sigwood.era.report import EraReducer, ReportInterval
import sigwood.runner as runner
from sigwood.runner import EraHarnessReceipt, _run_era_harness, _run_era_u7_oracle


UTC = timezone.utc


def _instant(day: int) -> datetime:
    return datetime(2026, 8, day, tzinfo=UTC)


def test_era_fold_is_raw_and_retains_only_aggregate_reducer_state() -> None:
    sink = make_era_fold_sink(
        "conn",
        reducer_factory=lambda: EraReducer(
            ReportInterval(_instant(1), _instant(2)), home_net=["10.0.0.0/8"]
        ),
    )
    frame = pd.DataFrame({
        "ts": [_instant(1).timestamp()],
        "src": ["10.0.0.8"],
        "dst": ["198.51.100.8"],
        "duration": [2.0],
        "bytes": [42],
    })
    chunk = loader.DecodedChunk(frame, 64, (True,), (True,), 0)

    # The harness owns no allowlist mask: every registered-loader row reaches
    # the raw measurement fold.
    mask = sink.mask(frame)
    state = sink.consume(sink.seed_file(), chunk, mask).value

    assert mask.keep == (True,)
    assert state.rows == 1
    assert state.reducer.committed_conn_records == 1
    assert not hasattr(state, "frame")


def test_era_conn_fold_uses_canonical_port_for_transport_counts() -> None:
    """The fold sink receives normalized frames, never Zeek-native field names."""
    start = _instant(1)
    sink = make_era_fold_sink(
        "conn",
        reducer_factory=lambda: EraReducer(
            ReportInterval(start, start + timedelta(days=1)), home_net=[]
        ),
    )
    frame = pd.DataFrame({
        "ts": [start.timestamp()] * 100,
        "src": ["10.0.0.8"] * 100,
        "dst": ["198.51.100.8"] * 100,
        "port": [443] * 100,
        "proto": ["udp"] * 100,
        "duration": [1.0] * 100,
        "bytes": [42] * 100,
    })
    chunk = loader.DecodedChunk(frame, 64, (True,) * 100, (True,) * 100, 0)

    state = sink.consume(sink.seed_file(), chunk, sink.mask(frame)).value

    assert state.reducer._transport_weeks == {(2026, 31): [100, 0]}


def test_era_conn_fold_batches_scalar_semantics_without_positional_iloc() -> None:
    """The optimized path keeps the scalar reducer's order-sensitive facts."""
    start = _instant(1)
    frame = pd.DataFrame({
        "ts": [start.timestamp(), (start + timedelta(minutes=1)).timestamp(), float("nan")],
        "src": ["10.0.0.8", "not-an-address", "10.0.0.8"],
        "dst": ["198.51.100.8", "198.51.100.9", "198.51.100.10"],
        "port": [443, "443", 443],
        "proto": ["tcp", "udp", "tcp"],
        "duration": [5.0, "not-a-number", 10.0],
        "bytes": [100, 200, 300],
    })
    sink = make_era_fold_sink(
        "conn",
        reducer_factory=lambda: EraReducer(
            ReportInterval(start, start + timedelta(days=1)), home_net=["10.0.0.0/8"]
        ),
    )
    state = sink.consume(
        sink.seed_file(), loader.DecodedChunk(frame, 64, (True,) * 3, (True,) * 3, 0), sink.mask(frame)
    ).value

    scalar = EraReducer(ReportInterval(start, start + timedelta(days=1)), home_net=["10.0.0.0/8"])
    for timestamp, row in zip((start, start + timedelta(minutes=1)), frame.iloc[:2].to_dict("records")):
        scalar.add_conn(timestamp, row["dst"])
        scalar.add_conn_transport(timestamp, row["port"], row["proto"])
        scalar.add_conn_start(timestamp)
        scalar.add_connection_duration(timestamp, row["duration"])
        scalar.add_outbound_connection(timestamp, origin=row["src"], destination=row["dst"], orig_bytes=row["bytes"], resp_bytes=0)

    assert state.reducer.shards == scalar.shards
    assert state.reducer.external_destination_addresses == scalar.external_destination_addresses
    assert state.reducer.aggregate_review_evidence() == scalar.aggregate_review_evidence()
    assert state.reducer._transport_weeks == scalar._transport_weeks
    assert state.reducer._outbound_reason == scalar._outbound_reason
    assert state.reducer._outbound_eligible == scalar._outbound_eligible
    assert "frame.iloc[position]" not in inspect.getsource(make_era_fold_sink)


def test_era_review_evidence_is_aggregate_only_and_merges_duration_tails() -> None:
    interval = ReportInterval(_instant(1), _instant(2))
    left = EraReducer(interval, home_net=[])
    right = EraReducer(interval, home_net=[])
    peak = _instant(1).replace(hour=12, minute=0)
    for _ in range(4):
        left.add_conn_start(peak)
    left.add_conn_start(peak - timedelta(minutes=1))
    right.add_conn_start(peak.replace(minute=1))
    left.add_connection_duration(peak, 86_400)
    right.add_connection_duration(peak, 1_209_600)

    when, profile, tails, winner = left.merge(right).aggregate_review_evidence(
        peak_radius_minutes=1
    )

    assert when == peak
    assert profile == (1, 4, 1)
    assert tails == ((86_400, 2), (604_800, 1), (1_209_600, 1))
    assert winner == (1_209_600.0, peak)


def test_era_harness_names_the_missing_ratified_root_precondition() -> None:
    receipt = _run_era_harness({"sigwood": {}}, archive_root_candidates=[])

    assert receipt.outcome == "NOT_MEASURED"
    assert receipt.population_basis == "raw_pre_allowlist"
    assert receipt.missing_precondition == "ratified-archive-root-unreachable"
    assert receipt.rendered_cards is None


def test_u7_oracle_receipt_hashes_rendered_deck_without_retaining_paths(monkeypatch) -> None:
    deck = "era / zeek\n  inspect: /private/operator-path"
    harness = EraHarnessReceipt(
        outcome="MEASURED",
        population_basis="raw_pre_allowlist",
        record_counts=(("conn", 1),),
        consumed_span=None,
        missing_baseline_dates=(),
        post_baseline_dates=(),
        collapsed_alias_dates=(),
        cards_present=(1,),
        rendered_cards=deck,
        frozen_input_identity="fixture-identity",
    )
    monkeypatch.setattr(runner, "_run_era_harness", lambda *_args, **_kwargs: harness)

    receipt = _run_era_u7_oracle(
        {"sigwood": {}},
        archive_root_candidates=[],
        cli_options={"private": True},
        display_timezone="UTC",
        partition_zone="UTC",
        tldextract_version="fixture",
        effective_psl_snapshot=b"fixture",
    )

    assert receipt.rendered_deck_sha256 is not None
    assert receipt.rendered_deck_byte_length == len(deck.encode("utf-8"))
    assert not hasattr(receipt, "rendered_cards")
    assert "/private/operator-path" not in repr(receipt)


def test_u7_warning_census_uses_path_free_cause_classes() -> None:
    assert runner._era_warning_class("/private/archive: unexpected end of file") == "read-corruption"
    assert runner._era_warning_class("/private/archive: permission denied") == "permission-denied"
    assert runner._era_warning_class("/private/archive: malformed rows") == "parse-contained"


def test_u7_closure_omits_only_loader_provenance_sidecar() -> None:
    config = {"sigwood": {"home_net": []}, "__user_set__": {"sigwood"}}

    assert runner._era_closure_config(config) == {"sigwood": {"home_net": []}}


def test_masthead_derives_only_card_nine_and_ten_span_abstentions() -> None:
    assert runner._era_horizon_abstaining_cards(11, 12) == (9,)
    assert runner._era_horizon_abstaining_cards(12, 11) == (10,)
    assert runner._era_horizon_abstaining_cards(11, 11) == (9, 10)
    # Card 9 can also abstain when its candidates are refused.  At a mature
    # span that is not a horizon cause and must stay out of the masthead.
    assert runner._era_horizon_abstaining_cards(12, 12) == ()


def test_private_runner_route_owns_sink_plan_and_bypasses_confirmation(monkeypatch, tmp_path) -> None:
    group = ArchiveDateGroup(_instant(1).date(), (tmp_path,), False)
    plan = ArchivePlan(
        groups=(group,),
        inventory=(
            (
                group.canonical_date,
                tuple(
                    FamilyInventory(family, (), 0, InventoryState.EMPTY)
                    for family in ("conn", "dns", "stats", "capture_loss")
                ),
            ),
        ),
        work_estimate=WorkEstimate(0, 0),
        reconciliation=BaselineReconciliation(
            expected_dates=frozenset({_instant(1).date()}),
            present_dates=frozenset({_instant(1).date()}),
            missing_dates=(),
            post_baseline_dates=(),
            collapsed_tsvpre_dates=(),
            baseline_source_directory_absent=(),
        ),
    )
    calls: list[tuple[object, object]] = []
    confirms: list[tuple[int, bool]] = []

    class FakePlanner:
        def __init__(self, _root, *, baseline_dates) -> None:
            assert baseline_dates

        def plan(self):
            return plan

    def fake_load(needed_logs, _source_dirs, *_window, **kwargs):
        pattern = next(iter(needed_logs))
        sink_plan = kwargs["sink_plans"][pattern]
        calls.append((sink_plan, kwargs["dual_windows"][pattern]))
        return loader.LoadResult(
            logs={pattern: pd.DataFrame()},
            record_counts={},
            # The real loader has no fold channel when a selected family has
            # no routed rows.  That is a valid empty population, not an
            # execution failure for the aggregate-only harness.
            fold_results={pattern: {}},
        )

    monkeypatch.setattr(loader, "load_required_logs", fake_load)
    monkeypatch.setattr(
        runner,
        "_confirm_large_dataset",
        lambda total, _cfg, *, skip_confirm: confirms.append((total, skip_confirm)),
    )

    receipt = _run_era_harness(
        {"sigwood": {}}, archive_root_candidates=[tmp_path], _planner_factory=FakePlanner
    )

    assert len(calls) == 4
    assert all(not sink_plan.preserve_frame for sink_plan, _window in calls)
    assert all(window.report_interval == group.interval for _sink_plan, window in calls)
    assert confirms == [(0, True)]
    assert receipt.outcome == "MEASURED"
    assert receipt.population_basis == "raw_pre_allowlist"
