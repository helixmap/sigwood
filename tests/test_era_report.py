"""Tests for era's aggregate-only report facts and text cards."""

from __future__ import annotations

import hashlib
import json
import shlex
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import pytest

import sigwood.cli as cli
import sigwood.runner as runner
from sigwood.era import (
    ArchivePlanner,
    Availability,
    Completeness,
    EraCard,
    EraReducer,
    EraSlot,
    FamilyDayObservation,
    ParseUsability,
    ReportInterval,
    DomainLedger,
    activity_card,
    busiest_minute_card,
    calendar_card,
    canonical_identity_payload,
    compose_inspect_handoff,
    compose_planned_inspect_handoff,
    largest_outbound_card,
    longest_connection_card,
    render_text_report,
    registrable_domain,
)
from sigwood.era.domains import effective_psl_snapshot_bytes
from sigwood.era.report import (
    FootprintFact,
    SpanHonesty,
    _presence_class,
    domain_arrival_card,
    footprint_card,
    sustained_shift_card,
    transport_share_card,
    weekday_shape_card,
)


UTC = timezone.utc


def _instant(day: int, hour: int = 0) -> datetime:
    return datetime(2026, 8, day, hour, tzinfo=UTC)


def _reducer(*, cap: int = 10) -> EraReducer:
    return EraReducer(
        ReportInterval(_instant(1), _instant(4)),
        home_net=["10.0.0.0/8"],
        address_cap=cap,
    )


def test_reducer_uses_complete_utc_shards_and_half_open_edges() -> None:
    reducer = _reducer()
    reducer.add_conn(_instant(1), "198.51.100.20")
    reducer.add_dns_query(_instant(2, 23))

    assert [(shard.start, shard.end, shard.conn_records, shard.dns_query_rows) for shard in reducer.shards] == [
        (_instant(1), _instant(2), 1, 0),
        (_instant(2), _instant(3), 0, 1),
    ]
    with pytest.raises(ValueError, match="outside"):
        reducer.add_conn(_instant(4), "198.51.100.21")


@pytest.mark.parametrize(
    ("query", "reason"),
    (("1.1.1.1", "ip-literal"), ("host", "single-label"), ("host.local", "mdns-local"), ("4.3.2.1.in-addr.arpa", "ptr-arpa"), ("co.uk", "public-suffix-only")),
)
def test_d20_exclusions_are_counted_without_retaining_the_query(query: str, reason: str) -> None:
    key, actual = registrable_domain(query)
    assert key is None
    assert actual == reason


def test_d20_ledger_is_exact_to_cap_then_stickily_abstains() -> None:
    ledger = DomainLedger(cap=1)
    ledger.add("first.example.com", (2026, 1))
    ledger.add("second.example.net", (2026, 2))

    assert ledger.facts.retained_domains == 1
    assert ledger.facts.cap_exceeded is True


def test_d20_marks_psl_unavailability_without_a_fallback_suffix_guess() -> None:
    key, reason = registrable_domain("safe.example.com", extractor=lambda _name: (_ for _ in ()).throw(RuntimeError("offline")))

    assert key is None
    assert reason == "psl-unavailable"


def test_d19_psl_snapshot_is_a_deterministic_offline_input() -> None:
    snapshot = effective_psl_snapshot_bytes()

    assert snapshot == effective_psl_snapshot_bytes()
    assert snapshot
    assert b"\n" in snapshot


def test_reducer_requires_complete_midnight_shards_inside_absolute_interval() -> None:
    reducer = EraReducer(
        ReportInterval(_instant(1, 12), _instant(3, 12)), home_net=["10.0.0.0/8"]
    )
    with pytest.raises(ValueError, match="complete UTC"):
        reducer.add_conn(_instant(1, 13), "198.51.100.20")


def test_card_two_keeps_measured_rows_when_address_count_abstains() -> None:
    reducer = _reducer(cap=1)
    reducer.add_conn(_instant(1), "198.51.100.20")
    reducer.add_conn(_instant(1), "203.0.113.20")
    reducer.add_dns_query(_instant(1))

    assert reducer.external_destination_addresses.count is None
    assert reducer.external_destination_addresses.reason == "external-address-cap-exceeded"
    assert activity_card(reducer).facts == (
        ("conn records", "2"),
        ("DNS query rows", "1"),
        ("distinct external destination IPs", "not measured (external-address-cap-exceeded)"),
    )


def test_unclassifiable_destination_abstains_without_conflating_public_and_external() -> None:
    reducer = _reducer()
    reducer.add_conn(_instant(1), "100.64.0.20")
    reducer.add_conn(_instant(1), "not-an-address")

    assert reducer.committed_conn_records == 2
    assert reducer.external_destination_addresses.count is None
    assert reducer.external_destination_addresses.reason == "destination-unclassifiable"


def test_merge_is_deterministic_and_merges_aggregate_shards_only() -> None:
    left = _reducer()
    right = _reducer()
    left.add_conn(_instant(1), "198.51.100.20")
    right.add_conn(_instant(1), "203.0.113.20")
    right.add_dns_query(_instant(2))

    merged = left.merge(right)
    assert [(shard.start, shard.conn_records, shard.dns_query_rows) for shard in merged.shards] == [
        (_instant(1), 2, 0), (_instant(2), 0, 1),
    ]
    assert merged.external_destination_addresses.count == 2


def test_reducer_uses_planner_canonical_groups_and_discloses_empty_shards(tmp_path) -> None:
    (tmp_path / "2026-08-01").mkdir()
    (tmp_path / "2026-08-02-TSVPRE").mkdir()
    plan = ArchivePlanner(tmp_path, baseline_dates=()).plan()
    reducer = EraReducer.from_archive_plan(
        plan, ReportInterval(_instant(1), _instant(4)), home_net=["10.0.0.0/8"]
    )
    reducer.add_conn(_instant(1), "198.51.100.20")

    assert [(shard.start, shard.conn_records) for shard in reducer.shards] == [
        (_instant(1), 1), (_instant(2), 0),
    ]
    with pytest.raises(ValueError, match="unplanned"):
        reducer.add_conn(_instant(3), "198.51.100.21")


def test_calendar_card_keeps_all_three_quality_layers_and_unknown_completeness() -> None:
    card = calendar_card({
        "conn": FamilyDayObservation(
            Availability.PRESENT, ParseUsability.USABLE, Completeness.UNKNOWN, 4
        )
    })
    assert card.facts == ((
        "conn", "availability=present; parse=usable; completeness=completeness-unknown"
    ),)


def test_d19_identity_is_stable_and_excludes_volatile_render_metadata() -> None:
    common = dict(
        archive_content_identity={"archive": "sha256:fixture"},
        resolved_config={"era": {"cap": 2_000_000}},
        cli_options={"utc": True},
        display_timezone="UTC",
        partition_zone="UTC",
        tldextract_version="5.1.2",
        effective_psl_snapshot=b"fixture snapshot",
    )
    first = canonical_identity_payload(**common)
    second = canonical_identity_payload(**common)
    assert first == second
    assert b"generated_at" not in first
    assert b"output_name" not in first


def test_d19_identity_has_the_exact_canonical_wire_contract() -> None:
    payload = canonical_identity_payload(
        archive_content_identity={"archive": "sha256:fixture"},
        resolved_config={"era": {"cap": 2_000_000}},
        cli_options={"utc": True},
        display_timezone="America/Chicago",
        partition_zone="UTC",
        tldextract_version="5.1.2",
        effective_psl_snapshot=b"fixture snapshot",
    )

    decoded = json.loads(payload.decode("utf-8"))

    assert payload == json.dumps(decoded, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    assert set(decoded) == {
        "archive_content_identity",
        "cli_options",
        "display_timezone",
        "effective_psl_snapshot_sha256",
        "partition_zone",
        "resolved_config",
        "sigwood_version",
        "tldextract_version",
    }
    assert decoded["effective_psl_snapshot_sha256"] == hashlib.sha256(b"fixture snapshot").hexdigest()
    assert b"fixture snapshot" not in payload


@pytest.mark.parametrize(
    "field, replacement",
    [
        ("archive_content_identity", {"archive": "sha256:changed"}),
        ("resolved_config", {"era": {"cap": 7}}),
        ("cli_options", {"utc": False}),
        ("display_timezone", "UTC"),
        ("partition_zone", "America/Chicago"),
        ("tldextract_version", "5.3.2"),
        ("effective_psl_snapshot", b"changed snapshot"),
    ],
)
def test_d19_identity_is_sensitive_to_every_nonvolatile_input(field, replacement) -> None:
    common = dict(
        archive_content_identity={"archive": "sha256:fixture"},
        resolved_config={"era": {"cap": 2_000_000}},
        cli_options={"utc": True},
        display_timezone="America/Chicago",
        partition_zone="UTC",
        tldextract_version="5.3.1",
        effective_psl_snapshot=b"fixture snapshot",
    )
    first = canonical_identity_payload(**common)
    common[field] = replacement

    assert canonical_identity_payload(**common) != first


def test_card_six_requires_eight_conn_scoped_eligible_weekdays_and_uses_median() -> None:
    interval = ReportInterval(_instant(1), datetime(2026, 10, 5, tzinfo=UTC))
    reducer = EraReducer(interval, home_net=[])
    # Nine Mondays: an outlier proves this is a median, not a mean.
    for week, starts in enumerate((1, 2, 3, 4, 5, 6, 7, 8, 100)):
        when = datetime(2026, 8, 3, 12, tzinfo=UTC) + timedelta(days=week * 7)
        for _ in range(starts):
            reducer.add_conn_start(when)
    card = weekday_shape_card(reducer)
    assert card is not None
    assert card.facts == (("Monday", "5 median connection starts across 9 eligible days"),)


def test_card_six_keeps_utc_source_day_when_local_display_day_differs() -> None:
    interval = ReportInterval(_instant(1), datetime(2026, 10, 5, tzinfo=UTC))
    reducer = EraReducer(interval, home_net=[])
    chicago = ZoneInfo("America/Chicago")
    for week in range(8):
        # Midnight UTC is still Monday in Chicago, but Card 6's source-day
        # contract deliberately groups the committed timestamp as Tuesday.
        local = datetime(2026, 8, 3, 19, tzinfo=chicago) + timedelta(days=week * 7)
        reducer.add_conn_start(local.astimezone(UTC))
    card = weekday_shape_card(reducer)
    assert card is not None
    assert card.facts == (("Tuesday", "1 median connection starts across 8 eligible days"),)


def test_card_nine_uses_score_hold_and_does_not_suppress_small_scores() -> None:
    interval = ReportInterval(datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 5, 5, tzinfo=UTC))
    reducer = EraReducer(
        interval,
        home_net=[],
        source_shards=(
            datetime(2026, 1, 5, tzinfo=UTC) + timedelta(days=index)
            for index in range(17 * 7)
        ),
    )
    # Seventeen full weeks with a modest but positive step after week eight.
    start = datetime(2026, 1, 5, 12, tzinfo=UTC)
    for day_offset in range(17 * 7):
        count = 10 if day_offset < 8 * 7 else 11
        day = (start + timedelta(days=day_offset)).date()
        if day_offset == 60:
            reducer.set_conn_day_observation(day, present=False, usable=False)
            continue
        reducer.set_conn_day_observation(day, present=True, usable=True)
        for _ in range(count):
            reducer.add_conn_start(start + timedelta(days=day_offset))
    card, evidence = sustained_shift_card(reducer)
    assert card is not None
    assert any(label == "hold in eligible weeks" for label, _value in card.facts)
    # The only non-refused candidate is stable; it must still speak rather
    # than be suppressed for a score that looks uninteresting.
    assert evidence.winner_score == 0.0
    assert evidence.admissible_candidates > 0
    assert evidence.refused_candidates > 0


def test_card_nine_marks_an_exact_top_score_tie_without_hiding_runner_up() -> None:
    interval = ReportInterval(datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 5, 5, tzinfo=UTC))
    starts = tuple(
        datetime(2026, 1, 5, tzinfo=UTC) + timedelta(days=index)
        for index in range(17 * 7)
    )
    reducer = EraReducer(interval, home_net=[], source_shards=starts)
    for start in starts:
        reducer.set_conn_day_observation(start.date(), present=True, usable=True)
        reducer.add_conn_start(start + timedelta(hours=12))
    card, evidence = sustained_shift_card(reducer)
    assert card is not None
    assert evidence.tie is True
    assert evidence.winner_score == evidence.runner_up_score == 0.0
    assert ("runner-up candidate score", "0") in card.facts
    assert ("top-score tie", "yes") in card.facts


def test_card_nine_hold_stops_when_the_post_boundary_level_reverts() -> None:
    interval = ReportInterval(datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 5, 5, tzinfo=UTC))
    starts = tuple(
        datetime(2026, 1, 5, tzinfo=UTC) + timedelta(days=index)
        for index in range(17 * 7)
    )
    reducer = EraReducer(interval, home_net=[], source_shards=starts)
    for day_index, start in enumerate(starts):
        week = day_index // 7
        # The elevated level holds for six weeks, then reverts.  The selected
        # boundary's remaining eligible weeks therefore outnumber its hold.
        count = 20 if 8 <= week < 14 else 10
        reducer.set_conn_day_observation(start.date(), present=True, usable=True)
        for _ in range(count):
            reducer.add_conn_start(start + timedelta(hours=12))
    card, _evidence = sustained_shift_card(reducer)
    assert card is not None
    facts = dict(card.facts)
    assert facts["selected boundary score"] == "1"
    assert facts["hold in eligible weeks"] == "0"
    # Positional tie-breaking selects week 7 (hold 0), while tied week 8 holds 6;
    # a predicate-free implementation would count every remaining week here.
    assert int(facts["hold in eligible weeks"]) < 17 - 7


def _weekly_reducer(weeks: int = 12) -> tuple[EraReducer, tuple[datetime, ...]]:
    starts = tuple(
        datetime(2026, 1, 5, tzinfo=UTC) + timedelta(days=index)
        for index in range(weeks * 7)
    )
    reducer = EraReducer(
        ReportInterval(starts[0], starts[-1] + timedelta(days=1)),
        home_net=[],
        source_shards=starts,
    )
    for start in starts:
        reducer.set_conn_day_observation(start.date(), present=True, usable=True)
        reducer.set_dns_day_observation(start.date(), present=True, usable=True)
    return reducer, starts


def test_card_eight_uses_the_port_floor_and_reports_named_largest_move() -> None:
    reducer, starts = _weekly_reducer()
    for week in range(12):
        day = starts[week * 7]
        for _ in range(100):
            reducer.add_conn_transport(day, 443, "udp" if week != 6 else "tcp")
    card, evidence = transport_share_card(reducer)

    assert card is not None
    facts = dict(card.facts)
    assert facts["largest week-over-week move"] == "-100 points in 2026-W08"
    assert facts["runner-up move"] == "100 points"
    assert facts["largest-move tie"] == "yes (earliest week selected)"
    assert evidence.admissible_candidates == 12
    assert evidence.refused_candidates == 0
    assert evidence.tie is True


def test_card_ten_keeps_burnin_literal_and_maturity_boundaries_exact() -> None:
    reducer, starts = _weekly_reducer()
    for week in range(12):
        day = starts[week * 7]
        # The early member must never be counted as an arrival, but its
        # left-censoring wording is required on the rendered card.
        reducer.add_dns_query(day, "early.example.com")
        if week >= 2:
            reducer.add_dns_query(day, "regular.example.net")
        if week == 2:
            reducer.add_dns_query(day, "single.example.org")
    card, evidence = domain_arrival_card(reducer)

    assert card is not None
    assert evidence.maturity == 4
    facts = dict(card.facts)
    assert "present since early archive" in facts["burn-in"]
    assert "single-week=1" in facts["mature presence"]
    assert "regular=1" in facts["mature presence"]
    assert "fixed cohort horizon: 8 subsequent eligible weeks" in facts["cohort"]


@pytest.mark.parametrize(("weeks", "maturity"), ((12, 4), (21, 4), (22, 6), (28, 6), (29, 8)))
def test_card_ten_maturity_ladder_boundaries(weeks: int, maturity: int) -> None:
    reducer, _starts = _weekly_reducer(weeks)
    card, evidence = domain_arrival_card(reducer)

    assert card is not None
    assert evidence.maturity == maturity


def test_card_ten_below_minimum_span_states_the_required_horizon() -> None:
    reducer, _starts = _weekly_reducer(11)
    card, evidence = domain_arrival_card(reducer)

    assert card is not None
    assert evidence.reason == "requires-12-eligible-dns-weeks"
    assert card.facts == (("domain arrivals", "abstain (requires 12 eligible DNS weeks; analyzed span is 11)"),)


def test_card_ten_presence_threshold_keeps_74_9_below_75_0() -> None:
    assert _presence_class(749, 1_000) == "intermittent"
    assert _presence_class(750, 1_000) == "regular"


def test_card_seven_keeps_stat_coverage_with_unavailable_metadata() -> None:
    card = footprint_card((
        FootprintFact("conn", 8, 1, 2, "unavailable"),
        FootprintFact("dns", 4, 1, 1, "present"),
    ))
    assert card.facts == (
        ("conn", "8 compressed bytes; 1 file summed / 2 files present; inventory=unavailable"),
        ("dns", "4 compressed bytes; 1 file summed / 1 file present; inventory=present"),
    )


def test_renderer_owns_one_family_masthead_and_preserves_card_slot_order() -> None:
    text = render_text_report((
        EraCard("1. calendar", (("conn", "present"),)),
        EraCard("2. activity", (("conn records", "1"),), (EraSlot("2026-08-01", "inspect conn"),)),
    ), family="zeek")
    assert text.splitlines() == [
        "era / zeek",
        "1. calendar",
        "  conn: present",
        "2. activity",
        "  conn records: 1",
        "  2026-08-01: inspect conn",
    ]


def test_renderer_names_only_span_caused_abstentions_in_horizon_masthead() -> None:
    text = render_text_report(
        (
            EraCard("5. largest outbound", (("largest outbound", "abstain (destination unclassifiable)"),)),
            EraCard("10. domain arrivals", (("domain arrivals", "abstain (requires 12 eligible DNS weeks; analyzed span is 3)"),)),
        ),
        family="zeek",
        span_honesty=SpanHonesty(3, 3, (10,)),
    )

    assert text.splitlines()[:3] == [
        "era / zeek",
        "analyzed span: 3 eligible conn weeks; 3 eligible DNS weeks",
        "horizon-limited (reasoned default: 12 eligible weeks): cards 10 abstain due to span",
    ]
    assert "cards 5" not in text
    assert "destination unclassifiable" in text


def test_short_span_masthead_is_honest_when_no_card_abstains_for_span() -> None:
    text = render_text_report(
        (EraCard("1. calendar", (("conn", "present"),)),),
        family="zeek",
        span_honesty=SpanHonesty(3, 3),
    )

    assert "horizon-limited (reasoned default: 12 eligible weeks): no cards abstain due to span" in text


def test_graph_inspect_handoff_uses_the_cli_legal_family_flag_shape(tmp_path) -> None:
    provenance = tmp_path / "2026-08-01"
    provenance.mkdir()

    handoff = compose_inspect_handoff(
        target="graph-conn",
        provenance_dir=provenance,
        start=_instant(1),
        end=_instant(2),
        rediscoverable=True,
    )

    assert handoff.refusal_reason is None
    assert handoff.command is not None
    assert "graph conn --zeek-dir=" in handoff.command
    assert str(provenance) in handoff.command
    assert "--since=2026-08-01T00:00:00+00:00" in handoff.command


def test_inspect_handoff_quotes_hostile_directory_as_one_cli_argument(tmp_path: Path) -> None:
    provenance = tmp_path / "safe ; $(not-run) `also-not` 'quotes' dir"
    provenance.mkdir()

    handoff = compose_inspect_handoff(
        target="graph-conn",
        provenance_dir=provenance,
        start=_instant(1),
        end=_instant(2),
        rediscoverable=True,
    )

    assert handoff.command is not None
    tokens = shlex.split(handoff.command)
    assert tokens == [
        "sigwood", "graph", "conn", f"--zeek-dir={provenance}",
        "--since=2026-08-01T00:00:00+00:00", "--until=2026-08-02T00:00:00+00:00",
    ]
    assert "$(not-run)" in tokens[3]
    assert "`also-not`" in tokens[3]


def test_inspect_handoff_refuses_control_and_identity_risk_without_command(tmp_path) -> None:
    path = tmp_path / "host\x1b[2J.example"
    path.mkdir()

    handoff = compose_inspect_handoff(
        target="exfil",
        provenance_dir=path,
        start=_instant(1),
        end=_instant(2),
        rediscoverable=True,
    )

    assert handoff.command is None
    assert handoff.refusal_reason is not None
    assert "\x1b" not in handoff.refusal_reason


def test_planned_handoff_selects_the_winner_partition_not_a_display_day(tmp_path: Path) -> None:
    early = tmp_path / "2026-08-01"
    winner = tmp_path / "2026-08-21"
    early.mkdir()
    winner.mkdir()
    plan = ArchivePlanner(tmp_path, baseline_dates=()).plan()

    handoff = compose_planned_inspect_handoff(
        target="exfil",
        plan=plan,
        winner_timestamp=_instant(21, 3),
        start=_instant(1),
        end=_instant(22),
        rediscoverable=True,
    )

    assert handoff.command is not None
    assert str(winner) in handoff.command
    assert str(early) not in handoff.command


@pytest.mark.parametrize(
    ("target", "provenance", "rediscoverable", "start", "end", "reason"),
    [
        ("unsupported", "/tmp", True, _instant(1), _instant(2), "unsupported"),
        ("exfil", "/not-present", True, _instant(1), _instant(2), "unavailable"),
        ("exfil", "/tmp", False, _instant(1), _instant(2), "not rediscoverable"),
        ("exfil", "/tmp", True, _instant(2), _instant(1), "unexpressible"),
    ],
)
def test_inspect_handoff_refusals_never_emit_a_plausible_command(
    target: str,
    provenance: str,
    rediscoverable: bool,
    start: datetime,
    end: datetime,
    reason: str,
) -> None:
    handoff = compose_inspect_handoff(
        target=target,
        provenance_dir=provenance,
        start=start,
        end=end,
        rediscoverable=rediscoverable,
    )

    assert handoff.command is None
    assert reason in (handoff.refusal_reason or "")


def test_refused_windows_and_terminal_risks_would_otherwise_reach_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refusals protect a real route; they are not redundant parser validation."""
    safe = tmp_path / "safe"
    identity = tmp_path / "host.example"
    control = tmp_path / "control\x1b directory"
    for provenance in (safe, identity, control):
        provenance.mkdir()
        (provenance / "conn.log").write_text(
            '{"_path":"conn","ts":1779750000.0,"id.orig_h":"192.0.2.10",'
            '"id.resp_h":"198.51.100.20"}\n', encoding="utf-8",
        )
    config = {
        "sigwood": {"default_window": "all", "warn_above": 10_000_000},
        "graph": {},
    }
    monkeypatch.setattr(cli.cfg, "load", lambda _path: config)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        runner,
        "run_graph",
        lambda _config, **kw: calls.append(kw) or tmp_path / "graph.html",
    )

    for provenance in (identity, control):
        refused = compose_inspect_handoff(
            target="graph-conn",
            provenance_dir=provenance,
            start=_instant(1),
            end=_instant(2),
            rediscoverable=True,
        )
        assert refused.command is None
        otherwise_plausible = (
            "sigwood graph conn "
            f"--zeek-dir={shlex.quote(str(provenance))} "
            "--since=2026-08-01T00:00:00+00:00 "
            "--until=2026-08-02T00:00:00+00:00 -q"
        )
        assert cli._main(shlex.split(otherwise_plausible)[1:]) == 0

    inverted = compose_inspect_handoff(
        target="graph-conn",
        provenance_dir=safe,
        start=_instant(2),
        end=_instant(1),
        rediscoverable=True,
    )
    assert inverted.command is None
    otherwise_plausible = (
        "sigwood graph conn "
        f"--zeek-dir={shlex.quote(str(safe))} "
        "--since=2026-08-02T00:00:00+00:00 "
        "--until=2026-08-01T00:00:00+00:00 -q"
    )
    assert cli._main(shlex.split(otherwise_plausible)[1:]) == 0
    assert calls[-1]["since"] == _instant(2)
    assert calls[-1]["until"] == _instant(1)


def test_nonrefused_commands_reach_the_real_cli_routes_with_their_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    provenance = tmp_path / "zeek source"
    provenance.mkdir()
    (provenance / "conn.log").write_text(
        '{"_path":"conn","ts":1779750000.0,"id.orig_h":"192.0.2.10",'
        '"id.resp_h":"198.51.100.20"}\n', encoding="utf-8",
    )
    graph = compose_inspect_handoff(
        target="graph-conn", provenance_dir=provenance,
        start=_instant(1), end=_instant(2), rediscoverable=True,
    )
    exfil = compose_inspect_handoff(
        target="exfil", provenance_dir=provenance,
        start=_instant(1), end=_instant(2), rediscoverable=True,
    )
    assert graph.command is not None and exfil.command is not None
    config = {"sigwood": {"default_window": "all", "warn_above": 10_000_000}, "graph": {}}
    monkeypatch.setattr(cli.cfg, "load", lambda _path: config)
    graph_calls: list[dict[str, object]] = []
    detector_calls: list[dict[str, object]] = []
    monkeypatch.setattr(runner, "run_graph", lambda _config, **kw: graph_calls.append(kw) or tmp_path / "graph.html")
    monkeypatch.setattr(runner, "run", lambda **kw: detector_calls.append(kw) or 0)

    assert cli._main(shlex.split(graph.command)[1:]) == 0
    assert cli._main(shlex.split(exfil.command)[1:]) == 0

    assert graph_calls[0]["kind"] == "conn"
    assert graph_calls[0]["since"] == _instant(1)
    assert graph_calls[0]["until"] == _instant(2)
    assert detector_calls[0]["detect"] == "exfil"
    assert detector_calls[0]["zeek_dir"] == str(provenance)
    assert detector_calls[0]["since"] == _instant(1)
    assert detector_calls[0]["until"] == _instant(2)


def test_peak_cards_keep_tie_coverage_and_topology_contracts() -> None:
    reducer = _reducer()
    reducer.add_conn_start(_instant(1, 2))
    reducer.add_conn_start(_instant(1, 1))
    reducer.set_telemetry_eligible_minutes(120)
    reducer.add_connection_duration(_instant(1), 12)
    reducer.add_connection_duration(_instant(1), None)
    reducer.add_outbound_connection(
        _instant(1), origin="10.0.0.2", destination="100.64.0.2", orig_bytes=50, resp_bytes=2
    )

    assert busiest_minute_card(reducer).facts[0][1].startswith("2026-08-01 01:00")
    assert longest_connection_card(reducer).facts[-1] == ("duration coverage", "1 eligible / 2 committed")
    assert largest_outbound_card(reducer).facts == (("largest outbound", "50 B originator bytes among 1 record"),)


def test_peak_cards_keep_zero_minutes_partial_denominators_and_typed_slots(tmp_path: Path) -> None:
    reducer = _reducer()
    reducer.add_conn_start(_instant(1, 1))
    reducer.add_conn_start(_instant(1, 1))
    reducer.add_conn_start(_instant(1, 2))
    reducer.set_telemetry_eligible_minutes(4)
    reducer.add_connection_duration(_instant(1, 2), float("nan"))
    reducer.add_connection_duration(_instant(1, 1), 9)
    reducer.add_outbound_connection(
        _instant(1, 1), origin="10.0.0.2", destination="198.51.100.2", orig_bytes=1, resp_bytes=0,
    )
    provenance = tmp_path / "source"
    provenance.mkdir()
    handoff = compose_inspect_handoff(
        target="graph-conn", provenance_dir=provenance,
        start=_instant(1), end=_instant(2), rediscoverable=True,
    )
    exfil_handoff = compose_inspect_handoff(
        target="exfil", provenance_dir=provenance,
        start=_instant(1), end=_instant(2), rediscoverable=True,
    )

    busiest = busiest_minute_card(reducer, inspect_handoff=handoff)
    longest = longest_connection_card(reducer, edge_censored=True, inspect_handoff=handoff)
    outbound = largest_outbound_card(reducer, inspect_handoff=exfil_handoff)
    assert busiest is not None and longest is not None
    assert busiest.facts == (
        ("busiest minute", "2026-08-01 01:00 local (2 connection starts)"),
        ("runner-up minute", "1 connection start"),
        ("top-count tie", "no"),
        ("comparison", "4.0x the median minute"),
    )
    assert busiest.slots[0].inspect_command == handoff.command
    assert longest.facts == (
        ("longest connection", "at least 9s among 1 record"),
        ("duration coverage", "1 eligible / 2 committed"),
    )
    assert longest.slots[0].inspect_command == handoff.command
    assert outbound.slots[0].inspect_command == exfil_handoff.command


def test_merge_preserves_peak_aggregate_state_without_retaining_rows() -> None:
    left = _reducer()
    right = _reducer()
    left.add_conn_start(_instant(1, 1))
    right.add_conn_start(_instant(1, 1))
    right.add_conn_start(_instant(1, 2))
    left.set_telemetry_eligible_minutes(2)
    right.set_telemetry_eligible_minutes(2)
    left.add_connection_duration(_instant(1, 1), 3)
    right.add_connection_duration(_instant(1, 2), 4)
    left.add_outbound_connection(
        _instant(1, 1), origin="10.0.0.2", destination="198.51.100.2", orig_bytes=1, resp_bytes=0,
    )
    right.add_outbound_connection(
        _instant(1, 2), origin="10.0.0.3", destination="198.51.100.3", orig_bytes=2, resp_bytes=0,
    )

    merged = left.merge(right)

    assert busiest_minute_card(merged).facts[0][1].endswith("(2 connection starts)")
    assert longest_connection_card(merged).facts == (("longest connection", "4s among 2 records"),)
    assert largest_outbound_card(merged).facts == (("largest outbound", "2 B originator bytes among 2 records"),)


def test_largest_outbound_abstains_when_direction_is_unclassifiable() -> None:
    reducer = _reducer()
    reducer.add_outbound_connection(
        _instant(1), origin="not-an-address", destination="198.51.100.20", orig_bytes=50, resp_bytes=2
    )

    assert "abstain" in largest_outbound_card(reducer).facts[0][1]


def test_renderer_neutralizes_controls_at_its_terminal_emit_seam() -> None:
    text = render_text_report(
        (EraCard("3. peak\x1b[2J", (("fact", "value\x07"),), (EraSlot("when\x1b", "cmd\x00"),)),),
        family="zeek\x1b",
    )

    assert "\x1b" not in text
    assert "\x00" not in text
    assert "\x07" not in text


def test_rendered_deck_carries_no_internal_decision_identifiers() -> None:
    """A rendered card must never show an internal design-decision identifier.

    Source-text scanning does not cover this class: the token reaches the operator
    through a card LABEL, so only rendering the deck and reading the result catches
    it. Guards the failure mode where internal vocabulary is shipped to a reader who
    has no way to resolve it.
    """
    import re

    reducer, starts = _weekly_reducer()
    for week in range(12):
        day = starts[week * 7]
        reducer.add_dns_query(day, "regular.example.net")
        reducer.add_dns_query(day, "192.0.2.10")
        reducer.add_dns_query(day, "localhost")
        reducer.add_dns_query(day, "printer.local")
    card, _evidence = domain_arrival_card(reducer)
    assert card is not None

    text = render_text_report((card,), family="zeek")

    leaked = sorted(set(re.findall(r"\bD\d{1,3}\b", text)))
    assert not leaked, f"internal decision identifiers reached rendered output: {leaked}"


def test_deck_numbers_render_for_a_reader_not_a_machine() -> None:
    """Deck magnitudes route through the renderers sigwood already owns.

    Guards the failure mode where a duration reaches the operator as
    `1.87372e+06s` and a byte mass as `2.13368e+09`: technically exact and
    unreadable to anyone. The magnitudes here are REAL-CORPUS scale on purpose:
    a small fixture renders identically under `%g` and would make this test
    vacuous, guarding nothing while appearing to pass.
    """
    reducer, starts = _weekly_reducer()
    when = starts[0]
    reducer._outbound_winner = (2_133_680_000, when)
    reducer._outbound_eligible = 1_234_567
    reducer._outbound_reason = None
    reducer._duration_winner = (1_873_720.0, when)
    reducer._duration_eligible = 1_234_567
    reducer._duration_missing = 0

    outbound = largest_outbound_card(reducer).facts[0][1]
    duration = longest_connection_card(reducer).facts[0][1]

    # The old `%g` rendering of these exact values.
    assert "2.13368e+09" not in outbound
    assert "1.87372e+06" not in duration
    # What a reader gets instead.
    assert outbound.startswith("2.0 GB originator bytes")
    assert duration.startswith("21.7d among")
    assert "1,234,567 records" in outbound and "1,234,567 records" in duration


def _conn_aggregate_state(reducer: EraReducer) -> dict[str, object]:
    """Snapshot every conn-derived aggregate the two fold paths both own.

    Enumerated explicitly rather than sampled: a partial comparison would let a
    field diverge while the test still passed.
    """
    return {
        "shards": {k: (v.conn_records, v.dns_query_rows) for k, v in reducer._shards.items()},
        "minute_counts": dict(reducer._minute_counts),
        "conn_day_counts": dict(reducer._conn_day_counts),
        "transport_weeks": {k: list(v) for k, v in reducer._transport_weeks.items()},
        "duration_total": reducer._duration_total,
        "duration_eligible": reducer._duration_eligible,
        "duration_missing": reducer._duration_missing,
        "duration_tail_counts": dict(reducer._duration_tail_counts),
        "duration_winner": reducer._duration_winner,
        "external_addresses": set(reducer._external_addresses),
        "address_reason": reducer._address_reason,
    }


def test_vectorized_conn_fold_matches_the_scalar_reference_exactly() -> None:
    """The production fold path must agree with the reference the card tests use.

    `harness.py` folds real archives through `add_conn_batch` ONLY, while every
    other era card test drives the scalar `add_conn*` methods. Nothing otherwise
    asserts the two agree, so a defect reachable only through the vectorized path
    is invisible to the rest of the suite. Covers duration ties, ineligible
    duration shapes, both port-443 transports, and destination classification.
    """
    day0 = datetime(2026, 5, 4, tzinfo=UTC)
    day1 = datetime(2026, 5, 5, tzinfo=UTC)
    shards = (day0, day1)
    interval = ReportInterval(day0, day1 + timedelta(days=1))
    base = day0 + timedelta(hours=12)
    rows = [
        # (offset_seconds, dst, port, proto, duration)
        (0, "203.0.113.10", 443, "udp", 5.0),
        (30, "203.0.113.11", 443, "tcp", 900.0),
        (61, "203.0.113.10", 443, "TCP", 90000.0),    # ties the MAXIMUM with the row below
        (3600, "192.168.1.5", 443, "udp", 90000.0),   # internal dst; tied max, crosses a tail threshold
        (7200, "203.0.113.12", 80, "tcp", -1.0),      # non-443; negative duration is ineligible
        (86_400, "203.0.113.13", 443, "udp", float("nan")),   # NaN duration
        (90_000, "203.0.113.14", 443, "sctp", None),  # unsupported proto; None duration
    ]
    frame = pd.DataFrame(
        [
            {
                "timestamp": base + timedelta(seconds=off),
                "src": "192.168.1.2",
                "dst": dst,
                "port": port,
                "proto": proto,
                "duration": dur,
                "bytes": 10,
            }
            for off, dst, port, proto, dur in rows
        ]
    )

    vector = EraReducer(interval, home_net=["192.168.0.0/16"], source_shards=shards)
    vector.add_conn_batch(frame)

    scalar = EraReducer(interval, home_net=["192.168.0.0/16"], source_shards=shards)
    for row in frame.to_dict("records"):
        scalar.add_conn(row["timestamp"], row["dst"])
        scalar.add_conn_start(row["timestamp"])
        scalar.add_conn_transport(row["timestamp"], row["port"], row["proto"])
        scalar.add_connection_duration(row["timestamp"], row["duration"])

    assert _conn_aggregate_state(vector) == _conn_aggregate_state(scalar)
    # The tie must resolve to the EARLIER row in both paths, not merely to equal values.
    assert vector._duration_winner == (90000.0, base + timedelta(seconds=61))


def test_sharded_vector_folds_merge_to_the_same_state_as_one_fold() -> None:
    """Splitting a chunk across shards and merging must not change the aggregate.

    The reducer merges in deterministic source-shard order, so a fold split
    across shard boundaries has to reconstruct exactly what one fold produces.
    A divergence here would make a deck depend on how the archive happened to be
    chunked rather than on what it contains.
    """
    day0 = datetime(2026, 5, 4, tzinfo=UTC)
    day1 = datetime(2026, 5, 5, tzinfo=UTC)
    shards = (day0, day1)
    interval = ReportInterval(day0, day1 + timedelta(days=1))
    rows = [
        (0, "203.0.113.10", 443, "udp", 5.0),
        (30, "203.0.113.11", 443, "tcp", 900.0),
        (86_400, "203.0.113.12", 443, "udp", 7.5),
        (90_000, "203.0.113.13", 443, "tcp", 12.0),
    ]
    frame = pd.DataFrame(
        [
            {
                "timestamp": day0 + timedelta(hours=12) + timedelta(seconds=off),
                "src": "192.168.1.2",
                "dst": dst,
                "port": port,
                "proto": proto,
                "duration": dur,
                "bytes": 10,
            }
            for off, dst, port, proto, dur in rows
        ]
    )

    whole = EraReducer(interval, home_net=["192.168.0.0/16"], source_shards=shards)
    whole.add_conn_batch(frame)

    first = EraReducer(interval, home_net=["192.168.0.0/16"], source_shards=shards)
    first.add_conn_batch(frame.iloc[:2].reset_index(drop=True))
    second = EraReducer(interval, home_net=["192.168.0.0/16"], source_shards=shards)
    second.add_conn_batch(frame.iloc[2:].reset_index(drop=True))
    merged = first.merge(second)

    assert _conn_aggregate_state(merged) == _conn_aggregate_state(whole)


def test_rate_shows_a_tenth_only_when_it_says_something() -> None:
    """One rule for both dishonesties: false precision and a false decimal.

    Six decimals imply precision the measurement lacks; `19.0` implies a
    fractional part a whole number does not have.
    """
    from sigwood.era.report import _rate

    assert _rate(38.857142857) == "38.9"
    assert _rate(19.0) == "19"
    assert _rate(19.04) == "19"
    assert _rate(0.0) == "0"
    assert _rate(7.5) == "7.5"


def test_busiest_minute_discloses_a_tied_runner_up() -> None:
    """Deterministic selection must not read as separation.

    Ordering resolves a tie to the earliest minute, which is reproducible but is
    not evidence that the winner stood apart. A reader seeing only the winner
    cannot tell a one-start margin from a thousand-start one.
    """
    reducer = _reducer()
    reducer.add_conn_start(_instant(1, 1))
    reducer.add_conn_start(_instant(1, 1))
    reducer.add_conn_start(_instant(2, 1))
    reducer.add_conn_start(_instant(2, 1))

    card = busiest_minute_card(reducer)

    assert card is not None
    facts = dict(card.facts)
    assert facts["runner-up minute"] == "2 connection starts"
    assert facts["top-count tie"] == "yes (earliest minute selected)"


def test_era_cards_use_real_plurals_at_one() -> None:
    """A count of one must not read as a plural on any card.

    The voice rail requires plural(n, noun) rather than a bare 's'. These cards
    each reach one legitimately: a single eligible record, a single summed file.
    """
    day0 = datetime(2026, 5, 4, tzinfo=UTC)
    reducer = EraReducer(
        ReportInterval(day0, day0 + timedelta(days=1)),
        home_net=["192.168.0.0/16"],
        source_shards=(day0,),
    )
    when = day0 + timedelta(hours=1)
    reducer.add_connection_duration(when, 9.0)
    reducer.add_outbound_connection(
        when,
        origin="192.168.1.2",
        destination="203.0.113.9",
        orig_bytes=50,
        resp_bytes=10,
    )

    longest = dict(longest_connection_card(reducer).facts)["longest connection"]
    outbound = dict(largest_outbound_card(reducer).facts)["largest outbound"]

    assert "1 record" in longest and "1 records" not in longest
    assert "1 record" in outbound and "1 records" not in outbound

    footprint = dict(
        footprint_card([FootprintFact("conn", 8, 1, 1, "present")]).facts
    )["conn"]
    assert "1 file summed / 1 file present" in footprint
