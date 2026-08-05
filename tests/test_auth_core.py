"""Product-core regressions for authentication producer arbitration."""

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
) -> core.DecisionRow:
    return core.DecisionRow(
        record_id=("synthetic", "manual.log", number),
        ts=float(number if ts is None else ts),
        host=host,
        producer=producer,
        gate=gate,
        outcome=outcome,
        actor_namespace="unix_user",
        actor="alice",
        target=None,
        source="192.0.2.10",
        audit_type=None,
    )


def test_three_paired_denials_then_grant_are_silent_with_near_miss_three() -> None:
    rows = _paired_rows(3)
    decisions = core.project_decisions(rows)

    assert len(decisions) == 7
    result = core.run_lenses(decisions, rows, _window(rows))

    assert result.landing_keys == frozenset()
    assert result.landing_transitions == ()
    assert result.concentration_near_miss == 3
    assert result.eligible_count == 4


def test_eight_paired_denials_then_grant_establish_exact_run_length() -> None:
    rows = _paired_rows(8)
    decisions = core.project_decisions(rows)
    result = core.run_lenses(decisions, rows, _window(rows))

    assert len(result.landing_keys) == 1
    assert [entry["status"] for entry in result.landing_transitions] == [
        "established"
    ]
    assert [entry["run_length"] for entry in result.landing_transitions] == [8]
    assert result.eligible_count == 9


def test_four_producer_fixture_collapses_to_attempt_count_and_one_key() -> None:
    rows = _fixture_rows("synth-4x-120.txt")
    decisions = core.project_decisions(rows)

    assert len(decisions) == 480
    assert len(core.arbitrate_producers(decisions)) == 120

    result = core.run_lenses(decisions, rows, _window(rows))
    assert result.eligible_count == 120
    assert len(result.concentration_keys) == 1


def test_four_producer_floor_fixture_preserves_exact_six_attempt_run() -> None:
    rows = _fixture_rows("synth-4x-6.txt")
    decisions = core.project_decisions(rows)
    result = core.run_lenses(decisions, rows, _window(rows))

    assert len(decisions) == 25
    assert result.eligible_count == 7
    assert [entry["run_length"] for entry in result.landing_transitions] == [6]


def test_lower_precedence_only_pair_preserves_decision_objects() -> None:
    decisions = (
        _decision(1, producer=core.Producer.PAM_TEXT),
        _decision(2, producer=core.Producer.PAM_TEXT, outcome="granted"),
    )

    arbitrated = core.arbitrate_producers(decisions)

    assert arbitrated == decisions
    assert all(after is before for after, before in zip(arbitrated, decisions))


def test_single_producer_run_lenses_matches_each_unarbitrated_lens() -> None:
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
    )


def test_sudo_and_su_single_producer_gates_are_unchanged() -> None:
    decisions = (
        _decision(1, producer=core.Producer.PAM_TEXT, gate="sudo"),
        _decision(2, producer=core.Producer.PAM_TEXT, gate="su"),
    )

    arbitrated = core.arbitrate_producers(decisions)

    assert arbitrated == decisions
    assert all(after is before for after, before in zip(arbitrated, decisions))


def test_pair_wide_precedence_is_not_event_level_deduplication() -> None:
    high = _decision(1, producer=core.Producer.SSHD_TEXT)
    lower_unique = _decision(2, producer=core.Producer.PAM_TEXT)
    other_host = _decision(
        3,
        producer=core.Producer.PAM_TEXT,
        host="other.example.test",
    )

    arbitrated = core.arbitrate_producers((high, lower_unique, other_host))

    assert arbitrated == (high, other_host)
    assert arbitrated[0] is high
    assert arbitrated[1] is other_host


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

    arbitrated = core.arbitrate_producers(decisions)

    assert arbitrated == decisions
    assert all(after is before for after, before in zip(arbitrated, decisions))


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


@pytest.mark.parametrize("producer", tuple(core.Producer))
def test_arbitration_preserves_single_producer_identity(
    producer: core.Producer,
) -> None:
    decision = _decision(1, producer=producer)
    assert core.arbitrate_producers((decision,)) == (decision,)
