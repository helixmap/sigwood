"""Product-core regressions for authentication producer counting."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigwood.detectors import auth_core as core
from sigwood.parsers.syslog import parse_line


_FIXTURES = Path(__file__).parent / "fixtures" / "auth"


def _canonical_lines(lines: list[str], *, name: str) -> tuple[core.CanonicalRow, ...]:
    rows: list[core.CanonicalRow] = []
    for index, raw in enumerate(lines, start=1):
        parsed = parse_line(raw)
        assert parsed is not None
        rows.append(
            core.CanonicalRow(
                record_id=("synthetic", name, index),
                ts=parsed["ts"].timestamp(),
                host=parsed["host"],
                program=parsed["program"],
                raw=parsed["raw"],
                message=parsed["message"],
            )
        )
    return tuple(rows)


def _fixture_rows(name: str) -> tuple[core.CanonicalRow, ...]:
    lines = (_FIXTURES / name).read_text(encoding="utf-8").splitlines()
    return _canonical_lines(lines, name=name)


def _paired_rows(attempts: int) -> tuple[core.CanonicalRow, ...]:
    lines: list[str] = []
    for attempt in range(attempts):
        minute = attempt
        lines.extend(
            [
                f"Aug  4 00:{minute:02d}:10 host.example.test sshd[{1000 + attempt}]: "
                "pam_unix(sshd:auth): authentication failure; "
                "rhost=192.0.2.10 user=alice",
                f"Aug  4 00:{minute:02d}:10 host.example.test sshd[{1000 + attempt}]: "
                "Failed password for alice from 192.0.2.10 "
                f"port {41000 + attempt} ssh2",
            ]
        )
    lines.extend(
        [
            "Aug  4 00:20:10 host.example.test sshd[2000]: "
            "Accepted publickey for alice from 192.0.2.10 port 42000 ssh2",
            "Aug  4 00:21:10 host.example.test cron[2001]: ordinary host activity",
        ]
    )
    return _canonical_lines(lines, name=f"paired-{attempts}.log")


def _window(rows: tuple[core.CanonicalRow, ...]) -> core.Window:
    timestamps = [row.ts for row in rows]
    return core.Window(min(timestamps), max(timestamps) + 1.0)


def _decision(
    number: int,
    *,
    producer: core.Producer,
    host: str = "host.example.test",
    gate: str = "sshd",
    outcome: str = "denied",
    ts: float | None = None,
    actor_namespace: str | None = "unix_user",
    actor: str | None = "alice",
    source: str | None = "192.0.2.10",
    audit_type: str | None = None,
    audit_event_id: str | None = None,
) -> core.DecisionRow:
    return core.DecisionRow(
        record_id=("synthetic", "manual.log", number),
        ts=float(number if ts is None else ts),
        host=host,
        producer=producer,
        gate=gate,
        outcome=outcome,
        actor_namespace=actor_namespace,
        actor=actor,
        target=None,
        source=source,
        audit_type=audit_type,
        audit_event_id=audit_event_id,
    )


def _canonical_decisions(
    decisions: tuple[core.DecisionRow, ...],
) -> tuple[core.CanonicalRow, ...]:
    return tuple(
        core.CanonicalRow(
            record_id=decision.record_id,
            ts=decision.ts,
            host=decision.host,
            program="sshd",
            raw="synthetic",
            message="synthetic",
        )
        for decision in decisions
    )


def _entity(
    result: core.LensResult,
    lens: core.EntityLens,
    key: tuple[str, ...],
) -> core.EntityResult | None:
    return next(
        (
            entity
            for entity in result.entity_results
            if entity.lens is lens and entity.key == key
        ),
        None,
    )


def test_three_paired_denials_then_grant_are_silent_with_record_near_miss_six() -> None:
    rows = _paired_rows(3)
    decisions = core.project_decisions(rows)

    assert len(decisions) == 7
    result = core.run_lenses(decisions, rows, _window(rows))

    assert result.landing_keys == frozenset()
    assert result.landing_transitions == ()
    assert result.concentration_near_miss == 6
    assert result.eligible_count == 7


def test_eight_paired_denials_then_grant_establish_exact_run_length() -> None:
    rows = _paired_rows(8)
    decisions = core.project_decisions(rows)
    result = core.run_lenses(decisions, rows, _window(rows))

    assert len(result.landing_keys) == 1
    assert [entry["status"] for entry in result.landing_transitions] == [
        "established"
    ]
    assert [entry["run_length"] for entry in result.landing_transitions] == [8]
    assert result.eligible_count == 17


def test_concentration_facts_exclude_colocated_grant_records() -> None:
    decisions = tuple(
        _decision(
            index,
            producer=core.Producer.SSHD_TEXT,
            ts=float(index),
        )
        for index in range(1, 101)
    ) + (
        _decision(
            101,
            producer=core.Producer.SSHD_TEXT,
            outcome="granted",
            ts=101.0,
        ),
    )

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 102.0),
    )
    concentration = next(
        episode
        for episode in result.episode_results
        if episode.lens is core.EpisodeLens.CONCENTRATION
    )

    assert result.eligible_count == 101
    assert concentration.decision_record_count == 100
    assert concentration.denial_count == 100


def test_partial_observer_coverage_is_unioned_before_concentration() -> None:
    sshd = tuple(
        _decision(
            index,
            producer=core.Producer.SSHD_TEXT,
            ts=float(index),
        )
        for index in range(1, 61)
    )
    audit = tuple(
        _decision(
            100 + index,
            producer=core.Producer.AUDISP_TYPE,
            ts=float(60 + index),
            audit_type="USER_AUTH",
        )
        for index in range(1, 71)
    )
    decisions = (*sshd, *audit)

    counted = core.counted_decisions(decisions)
    keys, _near, _fidelity = core.concentration(
        counted,
        core.Window(0.0, 131.0),
    )

    assert len(counted) == 130
    assert len(keys) == 1


def test_landing_floor_counts_exact_audit_events_not_type_records() -> None:
    def run(attempts: int) -> core.LensResult:
        decisions: list[core.DecisionRow] = []
        for index in range(1, attempts + 1):
            event_id = f"1785819600.000:{index}"
            decisions.extend(
                [
                    _decision(
                        index * 2,
                        producer=core.Producer.AUDISP_TYPE,
                        ts=float(index),
                        audit_type="USER_AUTH",
                        audit_event_id=event_id,
                    ),
                    _decision(
                        index * 2 + 1,
                        producer=core.Producer.AUDISP_TYPE,
                        ts=float(index),
                        audit_type="USER_LOGIN",
                        audit_event_id=event_id,
                    ),
                ]
            )
        decisions.append(
            _decision(
                100,
                producer=core.Producer.AUDISP_TYPE,
                outcome="granted",
                ts=float(attempts + 1),
                audit_type="USER_LOGIN",
                audit_event_id="1785819600.000:100",
            )
        )
        frozen = tuple(decisions)
        return core.run_lenses(
            frozen,
            _canonical_decisions(frozen),
            core.Window(0.0, float(attempts + 2)),
        )

    below = run(3)
    firing = run(6)

    assert below.landing_keys == frozenset()
    assert [item["run_length"] for item in firing.landing_transitions] == [6]


def test_four_producer_fixture_union_keeps_all_records_and_pam_exclusive() -> None:
    rows = _fixture_rows("synth-4x-120.txt")
    decisions = core.project_decisions(rows)
    seed = next(
        decision
        for decision in decisions
        if decision.producer is core.Producer.PAM_TEXT
    )
    exclusive = core.DecisionRow(
        record_id=("synthetic", "pam-exclusive.log", 1),
        ts=max(decision.ts for decision in decisions) + 1.0,
        host=seed.host,
        producer=seed.producer,
        gate=seed.gate,
        outcome=seed.outcome,
        actor_namespace=seed.actor_namespace,
        actor=seed.actor,
        target=seed.target,
        source=seed.source,
        audit_type=seed.audit_type,
        audit_event_id=seed.audit_event_id,
    )

    assert len(decisions) == 480
    counted = core.counted_decisions((*decisions, exclusive))
    assert len(counted) == 481
    assert counted[-1] is exclusive

    result = core.run_lenses(decisions, rows, _window(rows))
    assert result.eligible_count == 480
    assert len(result.concentration_keys) == 1


def test_four_producer_floor_fixture_splits_25_records_from_six_event_run() -> None:
    rows = _fixture_rows("synth-4x-6.txt")
    decisions = core.project_decisions(rows)
    result = core.run_lenses(decisions, rows, _window(rows))

    assert len(decisions) == 25
    assert result.eligible_count == 25
    assert [entry["run_length"] for entry in result.landing_transitions] == [6]


def test_lower_precedence_only_pair_preserves_decision_objects() -> None:
    decisions = (
        _decision(1, producer=core.Producer.PAM_TEXT),
        _decision(2, producer=core.Producer.PAM_TEXT, outcome="granted"),
    )

    counted = core.counted_decisions(decisions)

    assert counted == decisions
    assert all(after is before for after, before in zip(counted, decisions))


def test_single_producer_run_lenses_matches_each_direct_lens() -> None:
    decisions = tuple(
        _decision(number, producer=core.Producer.PAM_TEXT)
        for number in range(1, 7)
    ) + (
        _decision(
            7,
            producer=core.Producer.PAM_TEXT,
            outcome="granted",
        ),
    )
    canonical = tuple(
        core.CanonicalRow(
            record_id=decision.record_id,
            ts=decision.ts,
            host=decision.host,
            program="sshd",
            raw="synthetic",
            message="synthetic",
        )
        for decision in decisions
    ) + (
        core.CanonicalRow(
            record_id=("synthetic", "manual.log", 8),
            ts=8.0,
            host="host.example.test",
            program="cron",
            raw="synthetic",
            message="synthetic",
        ),
    )
    window = core.Window(0.0, 9.0)

    concentration_keys, concentration_near, _fidelity = core.concentration(
        decisions, window
    )
    landing_keys, transitions, tie_count = core.landing(
        decisions, canonical, window
    )
    fanout_entities, source_near, account_near = core.fanout(decisions, window)
    live = core.live_accounts(decisions, window)
    entities = (
        *core.volume_entities(
            decisions,
            window,
            concentration_keys=concentration_keys,
            live=live,
        ),
        *core.host_spread_entities(decisions, window, live=live),
    )
    episodes = core._episode_results(
        decisions,
        window,
        concentration_keys=concentration_keys,
        landing_keys=landing_keys,
        landing_transitions=transitions,
        live=live,
    )

    assert core.run_lenses(decisions, canonical, window) == core.LensResult(
        concentration_keys=concentration_keys,
        concentration_near_miss=concentration_near,
        landing_keys=landing_keys,
        landing_transitions=transitions,
        landing_tie_unresolved=tie_count,
        fanout_entities=fanout_entities,
        fanout_source_near_miss=source_near,
        fanout_account_near_miss=account_near,
        eligible_count=7,
        entity_results=entities,
        live_accounts=live,
        episode_results=episodes,
    )


def test_landing_uses_lower_observer_when_higher_has_no_transition() -> None:
    high_grant = _decision(
        1,
        producer=core.Producer.SSHD_TEXT,
        outcome="granted",
        ts=20.0,
    )
    audit = tuple(
        _decision(
            10 + index,
            producer=core.Producer.AUDISP_TYPE,
            ts=float(index),
            audit_type="USER_AUTH",
        )
        for index in range(1, 7)
    ) + (
        _decision(
            20,
            producer=core.Producer.AUDISP_TYPE,
            outcome="granted",
            ts=7.0,
            audit_type="USER_LOGIN",
        ),
    )
    decisions = (high_grant, *audit)

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 21.0),
    )

    assert len(result.landing_keys) == 1
    assert [item["status"] for item in result.landing_transitions] == [
        "established"
    ]
    landing_result = next(
        item
        for item in result.episode_results
        if item.lens is core.EpisodeLens.LANDING
    )
    assert landing_result.decision_record_count == 7


def test_higher_rank_tie_owns_bundle_over_lower_rank_establishment() -> None:
    sshd = tuple(
        _decision(index, producer=core.Producer.SSHD_TEXT, ts=float(index))
        for index in range(1, 7)
    ) + (
        _decision(7, producer=core.Producer.SSHD_TEXT, ts=7.0),
        _decision(
            8,
            producer=core.Producer.SSHD_TEXT,
            outcome="granted",
            ts=7.0,
        ),
    )
    audit = tuple(
        _decision(
            20 + index,
            producer=core.Producer.AUDISP_TYPE,
            ts=float(index),
            audit_type="USER_AUTH",
        )
        for index in range(1, 7)
    ) + (
        _decision(
            27,
            producer=core.Producer.AUDISP_TYPE,
            outcome="granted",
            ts=7.0,
            audit_type="USER_LOGIN",
        ),
    )
    decisions = (*sshd, *audit)

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 8.0),
    )

    assert result.landing_keys == frozenset()
    assert result.landing_tie_unresolved == 1
    assert [item["status"] for item in result.landing_transitions] == [
        "tie-unresolved"
    ]


def test_sudo_and_su_single_producer_gates_are_unchanged() -> None:
    decisions = (
        _decision(1, producer=core.Producer.PAM_TEXT, gate="sudo"),
        _decision(2, producer=core.Producer.PAM_TEXT, gate="su"),
    )

    counted = core.counted_decisions(decisions)

    assert counted == decisions
    assert all(after is before for after, before in zip(counted, decisions))


def test_union_preserves_every_observer_row_in_original_order() -> None:
    high = _decision(1, producer=core.Producer.SSHD_TEXT)
    lower_unique = _decision(2, producer=core.Producer.PAM_TEXT)
    other_host = _decision(
        3,
        producer=core.Producer.PAM_TEXT,
        host="other.example.test",
    )

    counted = core.counted_decisions((high, lower_unique, other_host))

    assert counted == (high, lower_unique, other_host)
    assert counted[0] is high
    assert counted[1] is lower_unique
    assert counted[2] is other_host


def test_mixed_audit_encodings_share_rank_and_preserve_all_events() -> None:
    rows = _canonical_lines(
        [
            "Aug  4 01:00:00 host.example.test audisp-syslog[3000]: "
            "type=USER_LOGIN msg=audit(1785819600.000:200): "
            'acct="alice" exe="/usr/sbin/sshd" '
            "addr=192.0.2.10 res=failed",
            "Aug  4 01:01:00 host.example.test audit[3001]: "
            "AUDIT1112 pid=3001 acct=alice exe=\"/usr/sbin/sshd\" "
            "addr=192.0.2.10 res=success",
        ],
        name="mixed-audit-encodings.log",
    )
    decisions = core.project_decisions(rows)

    assert [decision.producer for decision in decisions] == [
        core.Producer.AUDISP_TYPE,
        core.Producer.AUDIT_TYPELESS,
    ]
    assert [decision.gate for decision in decisions] == ["sshd", "sshd"]

    counted = core.counted_decisions(decisions)

    assert counted == decisions
    assert all(after is before for after, before in zip(counted, decisions))


def test_missing_audit_executable_falls_back_to_audit_service() -> None:
    rows = _canonical_lines(
        [
            "Aug  4 01:00:00 host.example.test audisp-syslog[3000]: "
            "type=USER_LOGIN msg=audit(1785819600.000:200): "
            'acct="alice" addr=192.0.2.10 res=failed'
        ],
        name="audit-fallback.log",
    )

    decisions = core.project_decisions(rows)

    assert len(decisions) == 1
    assert decisions[0].gate == "audit"


def test_accepted_login_does_not_erase_denials_for_the_same_service() -> None:
    grant = _decision(1, producer=core.Producer.SSHD_TEXT, outcome="granted")
    denials = tuple(
        _decision(
            index,
            producer=core.Producer.AUDISP_TYPE,
            outcome="denied",
            source="198.51.100.7",
            ts=float(10 + index),
            audit_type="USER_AUTH",
        )
        for index in range(2, 102)
    )

    counted = core.counted_decisions((grant, *denials))

    assert sum(row.outcome == "denied" for row in counted) == 100


def test_diverging_service_names_share_one_concentration_key() -> None:
    decisions: list[core.DecisionRow] = []
    for index in range(100):
        decisions.append(
            _decision(index * 2, producer=core.Producer.SSHD_TEXT, ts=float(index))
        )
        decisions.append(
            _decision(
                index * 2 + 1,
                producer=core.Producer.AUDISP_TYPE,
                gate="sshd-session",
                ts=float(index),
                audit_type="USER_AUTH",
            )
        )

    counted = core.counted_decisions(tuple(decisions))
    keys, _near, _fidelity = core.concentration(
        counted,
        core.Window(0.0, 100.0, right_closed=True),
    )

    assert len(counted) == 200
    assert len(keys) == 1
    assert {
        core.episode_key(row)[1]
        for row in decisions
        if core.episode_key(row) is not None
    } == {"ssh"}


def test_real_parser_projector_canonicalizes_sshd_and_sshd_session() -> None:
    rows = _canonical_lines(
        [
            "Aug  4 01:00:00 host.example.test sshd[3000]: "
            "Failed password for alice from 192.0.2.10 port 40000 ssh2",
            "Aug  4 01:00:00 host.example.test audisp-syslog[3001]: "
            "type=USER_AUTH msg=audit(1785819600.000:200): "
            'acct="alice" exe="/usr/libexec/openssh/sshd-session" '
            "addr=192.0.2.10 res=failed",
        ],
        name="sshd-session-mirror.log",
    )
    decisions = core.project_decisions(rows)

    assert [row.gate for row in decisions] == ["sshd", "sshd-session"]
    assert [row.audit_event_id for row in decisions] == [
        None,
        "1785819600.000:200",
    ]
    assert len(core.counted_decisions(decisions)) == 2
    assert {core.episode_key(decision)[:2] for decision in decisions} == {(
        "host.example.test",
        "ssh",
    )}


def test_audit_record_shipped_under_two_identifiers_counts_once() -> None:
    rows = _canonical_lines(
        [
            "Aug  4 01:00:00 host.example.test audisp-syslog[3000]: "
            "type=USER_LOGIN msg=audit(1785819600.000:200): "
            'acct="alice" exe="/usr/sbin/sshd" '
            "addr=192.0.2.10 res=success",
            "Aug  4 01:00:00 host.example.test audit[3001]: "
            'AUDIT1112 pid=3001 acct=alice exe="/usr/sbin/sshd" '
            "addr=192.0.2.10 res=success",
        ],
        name="duplicate-shipped-audit.log",
    )
    decisions = core.project_decisions(rows)

    assert len(decisions) == 2
    assert [row.audit_event_id for row in decisions] == [
        "1785819600.000:200",
        None,
    ]
    assert len(core.counted_decisions(decisions)) == 1


def test_repeated_denials_from_one_producer_all_survive() -> None:
    denials = tuple(
        _decision(
            index,
            producer=core.Producer.AUDISP_TYPE,
            outcome="denied",
            ts=float(100 + index),
            audit_type="USER_AUTH",
        )
        for index in range(100)
    )

    assert len(core.counted_decisions(denials)) == 100


def test_distinct_audit_record_types_both_survive() -> None:
    decisions = (
        _decision(
            1,
            producer=core.Producer.AUDISP_TYPE,
            audit_type="USER_AUTH",
            audit_event_id="1700000000.000:1",
        ),
        _decision(
            2,
            producer=core.Producer.AUDISP_TYPE,
            audit_type="USER_LOGIN",
            audit_event_id="1700000000.000:1",
        ),
    )

    assert core.counted_decisions(decisions) == decisions


def test_exact_full_audit_event_id_dedups_but_missing_ids_never_do() -> None:
    exact = (
        _decision(
            1,
            producer=core.Producer.AUDISP_TYPE,
            audit_type="USER_AUTH",
            audit_event_id="1700000000.000:42",
        ),
        _decision(
            2,
            producer=core.Producer.AUDISP_TYPE,
            audit_type="USER_AUTH",
            audit_event_id="1700000000.000:42",
        ),
    )
    reused_serial = _decision(
        3,
        producer=core.Producer.AUDISP_TYPE,
        audit_type="USER_AUTH",
        audit_event_id="1700003600.000:42",
    )
    idless = (
        _decision(4, producer=core.Producer.AUDISP_TYPE, audit_type="USER_AUTH"),
        _decision(5, producer=core.Producer.AUDISP_TYPE, audit_type="USER_AUTH"),
    )

    counted = core.counted_decisions((*exact, reused_serial, *idless))

    assert counted == (exact[0], reused_serial, *idless)


def test_exact_audit_event_id_never_dedups_across_hosts() -> None:
    shared_id = "1700000000.000:42"
    decisions = (
        _decision(
            1,
            producer=core.Producer.AUDISP_TYPE,
            host="host-a.example.test",
            audit_type="USER_AUTH",
            audit_event_id=shared_id,
        ),
        _decision(
            2,
            producer=core.Producer.AUDISP_TYPE,
            host="host-b.example.test",
            audit_type="USER_AUTH",
            audit_event_id=shared_id,
        ),
    )

    assert core._dedupe_audit_event_ids(decisions) == decisions


def test_mirror_collapse_does_not_depend_on_timestamp_distance() -> None:
    def survivors(offset: float) -> int:
        pair = (
            _decision(
                1,
                producer=core.Producer.AUDISP_TYPE,
                ts=0.0,
                audit_type="USER_AUTH",
            ),
            _decision(
                2,
                producer=core.Producer.AUDIT_TYPELESS,
                ts=offset,
                audit_type="AUDIT1100",
            ),
        )
        return len(core.counted_decisions(pair))

    assert survivors(0.0) == survivors(3600.0) == 1


def test_larger_dialect_candidate_retains_its_unmatched_record() -> None:
    audisp = tuple(
        _decision(
            index,
            producer=core.Producer.AUDISP_TYPE,
            audit_type="USER_AUTH",
        )
        for index in range(1, 3)
    )
    typeless = tuple(
        _decision(
            index,
            producer=core.Producer.AUDIT_TYPELESS,
            audit_type="AUDIT1100",
        )
        for index in range(3, 6)
    )

    assert core.counted_decisions((*audisp, *typeless)) == typeless


@pytest.mark.parametrize("overlapping", [False, True], ids=["disjoint", "overlapping"])
def test_counting_keeps_both_distinct_audit_types_at_firing_scale(
    overlapping: bool,
) -> None:
    decisions: list[core.DecisionRow] = []
    for index in range(60):
        first_serial = index
        second_serial = index if overlapping else index + 1000
        decisions.extend(
            [
                _decision(
                    index * 2,
                    producer=core.Producer.AUDISP_TYPE,
                    audit_type="USER_AUTH",
                    audit_event_id=f"1700000000.000:{first_serial}",
                ),
                _decision(
                    index * 2 + 1,
                    producer=core.Producer.AUDISP_TYPE,
                    audit_type="USER_LOGIN",
                    audit_event_id=f"1700000000.000:{second_serial}",
                ),
            ]
        )

    counted = core.counted_decisions(decisions)
    keys, _near, _fidelity = core.concentration(
        counted,
        core.Window(0.0, 121.0),
    )

    assert len(counted) == 120
    assert len(keys) == 1


@pytest.mark.parametrize("producer", tuple(core.Producer))
def test_counting_preserves_single_producer_identity(
    producer: core.Producer,
) -> None:
    decision = _decision(1, producer=producer)
    assert core.counted_decisions((decision,)) == (decision,)


@pytest.mark.parametrize(
    ("duration", "denial_count", "expected"),
    [
        (60.0, 17, False),
        (60.0, 18, True),
        (86_400.0, 17, False),
        (86_400.0, 18, True),
        (1.1 * 86_400.0, 19, False),
        (1.1 * 86_400.0, 20, True),
        (7 * 86_400.0, 125, False),
        (7 * 86_400.0, 126, True),
        (14 * 86_400.0, 251, False),
        (14 * 86_400.0, 252, True),
    ],
)
def test_source_volume_floor_has_one_day_minimum_and_scales_linearly(
    duration: float,
    denial_count: int,
    expected: bool,
) -> None:
    decisions = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            ts=duration * number / (denial_count + 1),
            actor=f"actor-{number}",
        )
        for number in range(1, denial_count + 1)
    )

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, duration),
    )

    assert (
        _entity(result, core.EntityLens.SOURCE_VOLUME, ("192.0.2.10",))
        is not None
    ) is expected


@pytest.mark.parametrize("window", [core.Window(0.0, 0.0), core.Window(1.0, 0.0)])
def test_non_positive_window_produces_no_volume_entities(
    window: core.Window,
) -> None:
    decisions = tuple(
        _decision(number, producer=core.Producer.SSHD_TEXT, ts=0.0)
        for number in range(1, 19)
    )

    result = core.run_lenses(decisions, _canonical_decisions(decisions), window)

    assert not {
        entity
        for entity in result.entity_results
        if entity.lens
        in {core.EntityLens.SOURCE_VOLUME, core.EntityLens.ACCOUNT_VOLUME}
    }


def test_source_volume_evidence_partitions_accounts_and_live_join_exactly() -> None:
    actors = (
        ("unix_user", "alice"),
        ("unix_auid", "1000"),
        ("preauth_username", "ghost"),
        ("service_principal", "robot"),
    )
    denials = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            ts=float(number),
            actor_namespace=actors[(number - 1) % len(actors)][0],
            actor=actors[(number - 1) % len(actors)][1],
        )
        for number in range(1, 19)
    )
    grants = (
        _decision(
            19,
            producer=core.Producer.SSHD_TEXT,
            outcome="granted",
            ts=19.0,
            actor_namespace="unix_user",
            actor="alice",
        ),
        _decision(
            20,
            producer=core.Producer.SSHD_TEXT,
            outcome="granted",
            ts=20.0,
            host="other.example.test",
            actor_namespace="unix_auid",
            actor="1000",
        ),
        _decision(
            21,
            producer=core.Producer.SSHD_TEXT,
            outcome="granted",
            ts=21.0,
            actor_namespace="unix_user",
            actor="1000",
        ),
    )
    decisions = (*denials, *grants)

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 22.0),
    )

    source = _entity(
        result, core.EntityLens.SOURCE_VOLUME, ("192.0.2.10",)
    )
    assert source == core.EntityResult(
        lens=core.EntityLens.SOURCE_VOLUME,
        key=("192.0.2.10",),
        denial_count=18,
        real_account_count=2,
        nonexistent_account_count=1,
        unknown_account_count=1,
        live_account_count=1,
        host_count=1,
        decision_record_count=21,
        first_ts=1.0,
        last_ts=21.0,
        span_seconds=20.0,
        window_coverage_pct=90.909091,
        window_spanning=False,
    )
    assert result.live_accounts == frozenset(
        {
            ("host.example.test", "unix_user", "alice"),
            ("other.example.test", "unix_auid", "1000"),
            ("host.example.test", "unix_user", "1000"),
        }
    )


def test_account_volume_groups_namespaced_actor_across_sources() -> None:
    decisions = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            ts=float(number),
            source=f"192.0.2.{number}",
        )
        for number in range(1, 19)
    )

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 20.0),
    )

    account = _entity(
        result, core.EntityLens.ACCOUNT_VOLUME, ("unix_user", "alice")
    )
    assert account is not None
    assert account.denial_count == 18
    assert account.real_account_count == 1
    assert account.nonexistent_account_count == 0
    assert account.unknown_account_count == 0


def test_volume_lenses_do_not_invent_missing_grouping_identities() -> None:
    source_only = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            actor_namespace=None,
            actor=None,
        )
        for number in range(1, 19)
    )
    actor_only = tuple(
        _decision(
            20 + number,
            producer=core.Producer.SSHD_TEXT,
            actor="bob",
            source=None,
        )
        for number in range(1, 19)
    )
    decisions = (*source_only, *actor_only)

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 40.0),
    )

    source = _entity(
        result, core.EntityLens.SOURCE_VOLUME, ("192.0.2.10",)
    )
    account = _entity(
        result, core.EntityLens.ACCOUNT_VOLUME, ("unix_user", "bob")
    )
    assert source is not None and source.real_account_count == 0
    assert account is not None and account.denial_count == 18
    assert all(
        entity.lens is not core.EntityLens.HOST_SPREAD
        for entity in result.entity_results
    )


def test_host_spread_has_no_volume_floor_and_fires_at_three_hosts() -> None:
    two_hosts = (
        _decision(1, producer=core.Producer.SSHD_TEXT, host="a.example.test"),
        _decision(2, producer=core.Producer.SSHD_TEXT, host="b.example.test"),
    )
    three_hosts = (
        *two_hosts,
        _decision(3, producer=core.Producer.SSHD_TEXT, host="c.example.test"),
    )

    silent = core.run_lenses(
        two_hosts,
        _canonical_decisions(two_hosts),
        core.Window(0.0, 4.0),
    )
    firing = core.run_lenses(
        three_hosts,
        _canonical_decisions(three_hosts),
        core.Window(0.0, 4.0),
    )

    key = ("192.0.2.10", "unix_user", "alice")
    assert _entity(silent, core.EntityLens.HOST_SPREAD, key) is None
    assert _entity(firing, core.EntityLens.HOST_SPREAD, key) == core.EntityResult(
        lens=core.EntityLens.HOST_SPREAD,
        key=key,
        denial_count=3,
        real_account_count=1,
        nonexistent_account_count=0,
        unknown_account_count=0,
        live_account_count=0,
        host_count=3,
        decision_record_count=3,
        first_ts=1.0,
        last_ts=3.0,
        span_seconds=2.0,
        window_coverage_pct=50.0,
        window_spanning=False,
    )


def test_four_producer_floor_fixture_crosses_record_volume_floor() -> None:
    rows = _fixture_rows("synth-4x-6.txt")
    decisions = core.project_decisions(rows)

    assert sum(decision.outcome == "denied" for decision in decisions) == 24
    result = core.run_lenses(decisions, rows, _window(rows))

    assert [(entity.lens, entity.denial_count) for entity in result.entity_results] == [
        (core.EntityLens.SOURCE_VOLUME, 24),
        (core.EntityLens.ACCOUNT_VOLUME, 24),
    ]


def test_four_producer_large_fixture_volume_evidence_uses_all_480_rows() -> None:
    rows = _fixture_rows("synth-4x-120.txt")
    decisions = core.project_decisions(rows)
    counted = core.counted_decisions(decisions)
    live = core.live_accounts(counted, _window(rows))

    entities = core.volume_entities(
        counted,
        _window(rows),
        concentration_keys=frozenset(),
        live=live,
    )

    assert [(entity.lens, entity.denial_count) for entity in entities] == [
        (core.EntityLens.SOURCE_VOLUME, 480),
        (core.EntityLens.ACCOUNT_VOLUME, 480),
    ]


def test_concentration_deduplicates_matching_volume_entities() -> None:
    decisions = tuple(
        _decision(number, producer=core.Producer.SSHD_TEXT)
        for number in range(1, 101)
    )

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 101.0),
    )

    assert len(result.concentration_keys) == 1
    assert result.entity_results == ()


def test_degraded_concentration_key_suppresses_only_identity_it_carries() -> None:
    source_only = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            actor_namespace=None,
            actor=None,
        )
        for number in range(1, 101)
    )
    actor_rows = tuple(
        _decision(
            100 + number,
            producer=core.Producer.SSHD_TEXT,
            source="192.0.2.20",
        )
        for number in range(1, 19)
    )
    decisions = (*source_only, *actor_rows)

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 120.0),
    )

    assert _entity(
        result,
        core.EntityLens.SOURCE_VOLUME,
        ("192.0.2.10",),
    ) is None
    assert _entity(
        result,
        core.EntityLens.ACCOUNT_VOLUME,
        ("unix_user", "alice"),
    ) is not None


def test_actor_only_concentration_does_not_suppress_source_volume() -> None:
    actor_only = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            source=None,
        )
        for number in range(1, 101)
    )
    source_rows = tuple(
        _decision(
            100 + number,
            producer=core.Producer.SSHD_TEXT,
            actor="bob",
            source="192.0.2.20",
        )
        for number in range(1, 19)
    )
    decisions = (*actor_only, *source_rows)

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 120.0),
    )

    assert _entity(
        result,
        core.EntityLens.ACCOUNT_VOLUME,
        ("unix_user", "alice"),
    ) is None
    assert _entity(
        result,
        core.EntityLens.SOURCE_VOLUME,
        ("192.0.2.20",),
    ) is not None


def test_concentration_never_suppresses_cross_host_spread() -> None:
    concentrated = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            host="a.example.test",
        )
        for number in range(1, 101)
    )
    spread = (
        _decision(101, producer=core.Producer.SSHD_TEXT, host="b.example.test"),
        _decision(102, producer=core.Producer.SSHD_TEXT, host="c.example.test"),
    )
    decisions = (*concentrated, *spread)

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 103.0),
    )

    assert len(result.concentration_keys) == 1
    spread_result = _entity(
        result,
        core.EntityLens.HOST_SPREAD,
        ("192.0.2.10", "unix_user", "alice"),
    )
    assert spread_result is not None
    assert spread_result.denial_count == 102
    assert spread_result.host_count == 3


def test_live_account_window_respects_open_and_closed_right_edge() -> None:
    denials = tuple(
        _decision(number, producer=core.Producer.SSHD_TEXT, ts=float(number))
        for number in range(1, 19)
    )
    grant = _decision(
        19,
        producer=core.Producer.SSHD_TEXT,
        outcome="granted",
        ts=20.0,
    )
    decisions = (*denials, grant)
    canonical = _canonical_decisions(decisions)

    open_result = core.run_lenses(
        decisions, canonical, core.Window(0.0, 20.0)
    )
    closed_result = core.run_lenses(
        decisions, canonical, core.Window(0.0, 20.0, right_closed=True)
    )

    open_source = _entity(
        open_result, core.EntityLens.SOURCE_VOLUME, ("192.0.2.10",)
    )
    closed_source = _entity(
        closed_result, core.EntityLens.SOURCE_VOLUME, ("192.0.2.10",)
    )
    assert open_source is not None and open_source.live_account_count == 0
    assert closed_source is not None and closed_source.live_account_count == 1


def test_entity_results_have_stable_lens_then_key_order() -> None:
    decisions = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            source="192.0.2.20",
        )
        for number in range(1, 19)
    ) + tuple(
        _decision(
            20 + number,
            producer=core.Producer.SSHD_TEXT,
            host=f"host-{number}.example.test",
            actor="bob",
            source="192.0.2.10",
        )
        for number in range(1, 19)
    )

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 40.0),
    )

    assert [(entity.lens, entity.key) for entity in result.entity_results] == [
        (core.EntityLens.SOURCE_VOLUME, ("192.0.2.10",)),
        (core.EntityLens.SOURCE_VOLUME, ("192.0.2.20",)),
        (core.EntityLens.ACCOUNT_VOLUME, ("unix_user", "alice")),
        (core.EntityLens.ACCOUNT_VOLUME, ("unix_user", "bob")),
        (
            core.EntityLens.HOST_SPREAD,
            ("192.0.2.10", "unix_user", "bob"),
        ),
    ]


def test_run_lenses_exposes_uniform_typed_firing_facts() -> None:
    decisions = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            host="host-a.example.test",
            ts=float(number),
        )
        for number in range(1, 7)
    ) + (
        _decision(
            20,
            producer=core.Producer.SSHD_TEXT,
            host="host-b.example.test",
            ts=2.5,
        ),
        _decision(
            21,
            producer=core.Producer.SSHD_TEXT,
            host="host-c.example.test",
            ts=3.5,
        ),
        _decision(
            22,
            producer=core.Producer.SSHD_TEXT,
            host="host-a.example.test",
            outcome="granted",
            ts=7.0,
        ),
    )

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(0.0, 10.0, right_closed=True),
    )

    landing = next(
        episode
        for episode in result.episode_results
        if episode.lens is core.EpisodeLens.LANDING
    )
    assert landing.decision_record_count == 7
    assert landing.denial_count == 6
    assert landing.real_account_count == 1
    assert landing.nonexistent_account_count == 0
    assert landing.unknown_account_count == 0
    assert landing.live_account_count == 1
    assert landing.host_count == 1
    assert landing.first_ts == 1.0
    assert landing.last_ts == 7.0
    assert landing.span_seconds == 6.0
    assert landing.window_coverage_pct == 60.0
    assert landing.window_spanning is False

    spread = _entity(
        result,
        core.EntityLens.HOST_SPREAD,
        ("192.0.2.10", "unix_user", "alice"),
    )
    assert spread is not None
    assert spread.decision_record_count == 9
    assert spread.denial_count == 8
    assert spread.host_count == 3
    assert spread.first_ts == 1.0
    assert spread.last_ts == 7.0
    assert spread.span_seconds == 6.0
    assert spread.window_coverage_pct == 60.0
    assert spread.window_spanning is False


def test_landing_episode_owns_typed_transition_without_raw_record_ids() -> None:
    decisions = tuple(
        _decision(number, producer=core.Producer.SSHD_TEXT)
        for number in range(1, 7)
    ) + (
        _decision(
            7,
            producer=core.Producer.SSHD_TEXT,
            outcome="granted",
        ),
    )

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(1.0, 7.0, right_closed=True),
    )

    landing = next(
        episode
        for episode in result.episode_results
        if episode.lens is core.EpisodeLens.LANDING
    )
    assert landing.window_coverage_pct == 100.0
    assert landing.window_spanning is True
    assert len(landing.transitions) == 1
    transition = landing.transitions[0]
    assert transition.episode_key == landing.key
    assert transition.failure_count == 6
    assert transition.first_failure_ts == 1.0
    assert transition.success_ts == 7.0
    assert type(transition.transition_id) is str
    assert len(transition.transition_id) == 20
    assert not hasattr(transition, "record_ids")


def test_nonpositive_window_coverage_is_explicitly_unavailable() -> None:
    decisions = tuple(
        _decision(
            number,
            producer=core.Producer.SSHD_TEXT,
            host=f"host-{number}.example.test",
            ts=5.0,
        )
        for number in range(1, 4)
    )

    result = core.run_lenses(
        decisions,
        _canonical_decisions(decisions),
        core.Window(5.0, 5.0, right_closed=True),
    )

    spread = _entity(
        result,
        core.EntityLens.HOST_SPREAD,
        ("192.0.2.10", "unix_user", "alice"),
    )
    assert spread is not None
    assert spread.span_seconds == 0.0
    assert spread.window_coverage_pct is None
    assert spread.window_spanning is True
