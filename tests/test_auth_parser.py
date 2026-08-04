"""Pure authentication-decision grammar contract."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

import sigwood.parsers.auth as auth_parser
from sigwood.detectors import auth as auth_detector
from sigwood.parsers.auth import AuthDecision, AuthOutcome, extract_decision


def _decision(
    outcome: AuthOutcome,
    gate: str,
    **overrides: str | None,
) -> AuthDecision:
    values: dict[str, object] = {
        "outcome": outcome,
        "gate": gate,
        "actor": None,
        "actor_namespace": None,
        "target": None,
        "source": None,
        "auid": None,
        "terminal": None,
        "exe": None,
        "audit_type": None,
        "res": None,
        "session": None,
        "serial": None,
    }
    values.update(overrides)
    return AuthDecision(**values)  # type: ignore[arg-type]


def test_decision_type_contract_is_exact_frozen_and_slotted() -> None:
    assert [field.name for field in fields(AuthDecision)] == [
        "outcome",
        "gate",
        "actor",
        "actor_namespace",
        "target",
        "source",
        "auid",
        "terminal",
        "exe",
        "audit_type",
        "res",
        "session",
        "serial",
    ]
    assert AuthDecision.__slots__ == tuple(field.name for field in fields(AuthDecision))
    assert [outcome.value for outcome in AuthOutcome] == [
        "granted",
        "denied",
        "indeterminate",
    ]
    assert str(AuthOutcome.GRANTED) == "granted"

    decision = _decision(AuthOutcome.GRANTED, "sshd")
    assert decision.is_eligible_decision is True
    with pytest.raises(FrozenInstanceError):
        decision.gate = "sudo"  # type: ignore[misc]
    # Slotting is proved by the declared __slots__ above and by the absent
    # instance dict here. Assigning an UNKNOWN attribute proves neither: a
    # frozen dataclass refuses every assignment before slots are consulted,
    # so an unslotted class refuses it too, and which exception that path
    # raises is not stable across the supported interpreter range.
    assert not hasattr(decision, "__dict__")

    assert _decision(
        AuthOutcome.INDETERMINATE,
        "sshd",
    ).is_eligible_decision is False


def test_dispatch_and_emitted_gate_vocabularies_are_exact() -> None:
    assert auth_parser._RECOGNIZED_PROGRAMS == {
        "sshd",
        "sshd-session",
        "dropbear",
        "sudo",
        "su",
        "runuser",
        "audisp-syslog",
        "audit",
    }
    assert auth_parser._GATE_TOKENS == {
        "sshd",
        "dropbear",
        "sudo",
        "su",
        "runuser",
        "audit",
    }


@pytest.mark.parametrize(
    ("program", "message", "expected"),
    [
        (
            "sshd",
            "sshd[*]: Accepted password for admin from 192.0.2.10 port 2201 ssh2",
            _decision(
                AuthOutcome.GRANTED,
                "sshd",
                actor="admin",
                actor_namespace="unix_user",
                source="192.0.2.10",
            ),
        ),
        (
            "sshd-session",
            "sshd-session[*]: Accepted publickey for analyst from 192.0.2.11 port 2202 ssh2",
            _decision(
                AuthOutcome.GRANTED,
                "sshd",
                actor="analyst",
                actor_namespace="unix_user",
                source="192.0.2.11",
            ),
        ),
        (
            "sshd",
            "sshd[*]: Failed password for invalid user probe from 198.51.100.4 port 2203 ssh2",
            _decision(
                AuthOutcome.DENIED,
                "sshd",
                actor="probe",
                actor_namespace="preauth_username",
                source="198.51.100.4",
            ),
        ),
        (
            "sshd",
            "sshd[*]: Failed password for admin from 198.51.100.5 port 2204 ssh2",
            _decision(
                AuthOutcome.DENIED,
                "sshd",
                actor="admin",
                actor_namespace="unix_user",
                source="198.51.100.5",
            ),
        ),
        (
            "sshd",
            "sshd[*]: Invalid user probe from 198.51.100.6 port 2205",
            _decision(
                AuthOutcome.INDETERMINATE,
                "sshd",
                actor="probe",
                actor_namespace="preauth_username",
                source="198.51.100.6",
            ),
        ),
        (
            "sshd",
            "sshd[*]: error: maximum authentication attempts exceeded for "
            "admin from 198.51.100.7 port 2206 ssh2 [preauth]",
            _decision(
                AuthOutcome.DENIED,
                "sshd",
                actor="admin",
                actor_namespace="unix_user",
                source="198.51.100.7",
            ),
        ),
        (
            "sshd",
            "sshd[*]: Connection closed by 203.0.113.8 port 2207 [preauth]",
            _decision(
                AuthOutcome.INDETERMINATE,
                "sshd",
                source="203.0.113.8",
            ),
        ),
        (
            "sshd",
            "sshd[*]: error: kex_exchange_identification: Connection closed by "
            "203.0.113.9 port 2208",
            _decision(
                AuthOutcome.INDETERMINATE,
                "sshd",
                source="203.0.113.9",
            ),
        ),
        (
            "dropbear",
            "dropbear[*]: Exit before auth from <192.0.2.20:42001>: Exited normally",
            _decision(
                AuthOutcome.INDETERMINATE,
                "dropbear",
                source="192.0.2.20",
            ),
        ),
        (
            "dropbear",
            "dropbear[*]: Child connection from 192.0.2.21:42002",
            _decision(
                AuthOutcome.INDETERMINATE,
                "dropbear",
                source="192.0.2.21",
            ),
        ),
        (
            "dropbear",
            'dropbear[*]: Pubkey auth succeeded for "admin" from 192.0.2.22:42003',
            _decision(
                AuthOutcome.GRANTED,
                "dropbear",
                actor="admin",
                actor_namespace="unix_user",
                source="192.0.2.22",
            ),
        ),
        (
            "sudo",
            "sudo[*]: pam_unix(sudo:session): session opened for user "
            "root(uid=0) by admin(uid=1000)",
            _decision(
                AuthOutcome.GRANTED,
                "sudo",
                actor="admin",
                actor_namespace="unix_user",
                target="root",
            ),
        ),
        (
            "sudo",
            "sudo[*]: pam_unix(sudo:session): session closed for user root",
            _decision(
                AuthOutcome.INDETERMINATE,
                "sudo",
                target="root",
            ),
        ),
        (
            "sudo",
            "sudo[*]: admin : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/true",
            _decision(
                AuthOutcome.GRANTED,
                "sudo",
                actor="admin",
                actor_namespace="unix_user",
                target="root",
                terminal="pts/0",
            ),
        ),
        (
            "sudo",
            "sudo[*]: admin : user NOT in sudoers ; TTY=pts/1 ; "
            "PWD=/tmp ; USER=root ; COMMAND=/bin/true",
            _decision(
                AuthOutcome.DENIED,
                "sudo",
                actor="admin",
                actor_namespace="unix_user",
                terminal="pts/1",
            ),
        ),
        (
            "sudo",
            "sudo[*]: admin : 3 incorrect password attempts ; TTY=pts/2 ; "
            "PWD=/tmp ; USER=root ; COMMAND=/bin/true",
            _decision(
                AuthOutcome.DENIED,
                "sudo",
                actor="admin",
                actor_namespace="unix_user",
                terminal="pts/2",
            ),
        ),
        (
            "su",
            "su[*]: FAILED SU (to root) admin on pts/3",
            _decision(
                AuthOutcome.DENIED,
                "su",
                actor="admin",
                actor_namespace="unix_user",
                target="root",
                terminal="pts/3",
            ),
        ),
        (
            "su",
            "su[*]: pam_unix(su:session): session opened for user "
            "root(uid=0) by admin(uid=1000)",
            _decision(
                AuthOutcome.GRANTED,
                "su",
                actor="admin",
                actor_namespace="unix_user",
                target="root",
            ),
        ),
        (
            "runuser",
            "runuser[*]: pam_unix(runuser:session): session closed for user service",
            _decision(
                AuthOutcome.INDETERMINATE,
                "runuser",
                target="service",
            ),
        ),
        (
            "sshd",
            "sshd[*]: pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= "
            "rhost=198.51.100.25 user=admin",
            _decision(
                AuthOutcome.DENIED,
                "sshd",
                actor="admin",
                actor_namespace="unix_user",
                source="198.51.100.25",
            ),
        ),
    ],
)
def test_text_grammar_matrix(
    program: str,
    message: str,
    expected: AuthDecision,
) -> None:
    assert extract_decision(message, program=program) == expected


def test_missing_session_initiator_is_not_fabricated() -> None:
    decision = extract_decision(
        "sudo[*]: pam_unix(sudo:session): session opened for user "
        "root(uid=0) by (uid=0)",
        program="sudo",
    )

    assert decision == _decision(
        AuthOutcome.GRANTED,
        "sudo",
        actor=None,
        actor_namespace=None,
        target="root",
    )


def test_invalid_and_attested_accounts_do_not_merge_namespaces() -> None:
    invalid = extract_decision(
        "sshd[*]: Failed password for invalid user shared from 192.0.2.30 port 22",
        program="sshd",
    )
    attested = extract_decision(
        "sshd[*]: Failed password for shared from 192.0.2.30 port 22",
        program="sshd",
    )

    assert invalid is not None and attested is not None
    assert invalid.actor == attested.actor == "shared"
    assert invalid.actor_namespace == "preauth_username"
    assert attested.actor_namespace == "unix_user"


def test_sudo_command_keeps_initiator_and_target_and_discards_command() -> None:
    message = (
        'sudo[*]: "admin" : TTY="pts/4" ; PWD=/tmp ; '
        'USER="root" ; COMMAND=/bin/echo secret'
    )
    decision = extract_decision(message, program="sudo")

    assert decision == _decision(
        AuthOutcome.GRANTED,
        "sudo",
        actor="admin",
        actor_namespace="unix_user",
        target="root",
        terminal="pts/4",
    )
    assert "secret" not in repr(decision)


def test_session_and_command_target_spellings_converge() -> None:
    messages = (
        (
            "sudo[*]: pam_unix(sudo:session): session opened for user "
            "root(uid=0) by admin(uid=1000)"
        ),
        "sudo[*]: pam_unix(sudo:session): session closed for user root",
        "sudo[*]: admin : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/true",
    )

    decisions = [extract_decision(message, program="sudo") for message in messages]
    assert all(decision is not None for decision in decisions)
    assert {decision.target for decision in decisions if decision is not None} == {
        "root"
    }


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("192.0.2.40", "192.0.2.40"),
        ("192.0.2.40:41001", "192.0.2.40"),
        ("192.0.2.40:51001", "192.0.2.40"),
        ("[2001:db8::1]:41002", "2001:db8::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:db8::1:oops", "2001:db8::1:oops"),
    ],
)
def test_dropbear_source_is_address_not_endpoint(
    endpoint: str,
    expected: str,
) -> None:
    decision = extract_decision(
        f"dropbear[*]: Child connection from {endpoint}",
        program="dropbear",
    )

    assert decision is not None
    assert decision.source == expected


@pytest.mark.parametrize(
    "message",
    [
        "sshd[*]: Connection closed by remote host",
        "sshd[*]: Connection closed by dead port 22",
        "sshd[*]: error: kex_exchange_identification: Connection closed by remote host",
        "dropbear[*]: Exit before auth: Exited normally",
    ],
)
def test_closure_observations_require_a_source(message: str) -> None:
    program = "dropbear" if message.startswith("dropbear") else "sshd"
    assert extract_decision(message, program=program) is None


_AUDIT_A_TYPES = (
    "USER_LOGIN",
    "USER_START",
    "USER_END",
    "USER_ACCT",
    "USER_CMD",
    "USER_ROLE_CHANGE",
    "CRED_ACQ",
    "CRED_DISP",
)


@pytest.mark.parametrize("audit_type", _AUDIT_A_TYPES)
def test_audisp_accepts_the_exact_record_type_inventory(audit_type: str) -> None:
    decision = extract_decision(
        f"audisp-syslog[*]: type={audit_type} "
        "msg=audit(1700000000.125:42): acct=admin res=success",
        program="audisp-syslog",
    )

    assert decision == _decision(
        AuthOutcome.GRANTED,
        "audit",
        actor="admin",
        actor_namespace="unix_user",
        audit_type=audit_type,
        res="success",
        serial="42",
    )


def test_audisp_nested_payload_fills_only_missing_outer_fields() -> None:
    decision = extract_decision(
        "audisp-syslog[*]: type=USER_LOGIN "
        "msg=audit(1700000000.125:77): acct=\"outer\" auid=1000 "
        "ses=? terminal=pts/0 "
        "msg='acct=\"inner\" addr=192.0.2.50 terminal=ssh "
        "exe=\"/usr/bin/login\" res=success'",
        program="audisp-syslog",
    )

    assert decision == _decision(
        AuthOutcome.GRANTED,
        "audit",
        actor="outer",
        actor_namespace="unix_user",
        source="192.0.2.50",
        auid="1000",
        terminal="pts/0",
        exe="/usr/bin/login",
        audit_type="USER_LOGIN",
        res="success",
        session="?",
        serial="77",
    )


@pytest.mark.parametrize("acct", ['acct="admin"', "acct=admin"])
def test_audit_quotes_do_not_split_one_actor(acct: str) -> None:
    decision = extract_decision(
        "audisp-syslog[*]: type=USER_LOGIN "
        f"msg=audit(1700000000.125:81): {acct} res=failed",
        program="audisp-syslog",
    )

    assert decision is not None
    assert decision.actor == "admin"
    assert decision.actor_namespace == "unix_user"


def test_unbalanced_audit_quote_is_preserved_verbatim() -> None:
    decision = extract_decision(
        "audisp-syslog[*]: type=USER_LOGIN "
        'msg=audit(1700000000.125:811): acct="admin res=failed',
        program="audisp-syslog",
    )

    assert decision is not None
    assert decision.actor == '"admin'


def test_audit_non_sentinel_auid_is_textual_fallback_actor() -> None:
    decision = extract_decision(
        "audisp-syslog[*]: type=CRED_ACQ "
        "msg=audit(1700000000.125:82): auid=1000 ses=? res=failed",
        program="audisp-syslog",
    )

    assert decision == _decision(
        AuthOutcome.DENIED,
        "audit",
        actor="1000",
        actor_namespace="unix_auid",
        auid="1000",
        audit_type="CRED_ACQ",
        res="failed",
        session="?",
        serial="82",
    )


def test_audit_identity_sentinels_do_not_manufacture_a_decision() -> None:
    decision = extract_decision(
        "audit[*]: AUDIT1138 pid=123 auid=4294967295 ses=4294967295 "
        "addr=? terminal=? msg='exe=2F7573722F62696E2F74657374 res=success'",
        program="audit",
    )

    assert decision is None


def test_sentinel_acct_falls_through_to_real_auid() -> None:
    decision = extract_decision(
        "audisp-syslog[*]: type=USER_LOGIN "
        "msg=audit(1700000000.125:83): acct=? auid=1000 res=success",
        program="audisp-syslog",
    )

    assert decision is not None
    assert decision.actor == "1000"
    assert decision.actor_namespace == "unix_auid"
    assert decision.auid == "1000"


@pytest.mark.parametrize(
    ("suffix", "expected_outcome", "expected_res"),
    [
        ("res=success", AuthOutcome.GRANTED, "success"),
        ("res=failed", AuthOutcome.DENIED, "failed"),
        ("res=maybe", AuthOutcome.INDETERMINATE, "maybe"),
        ("", AuthOutcome.INDETERMINATE, None),
    ],
)
def test_audisp_outcome_mapping_is_total(
    suffix: str,
    expected_outcome: AuthOutcome,
    expected_res: str | None,
) -> None:
    decision = extract_decision(
        "audisp-syslog[*]: type=USER_LOGIN "
        f"msg=audit(1700000000.125:90): acct=admin {suffix}",
        program="audisp-syslog",
    )

    assert decision is not None
    assert decision.outcome is expected_outcome
    assert decision.res == expected_res


def test_audisp_rejects_a_record_type_outside_the_inventory() -> None:
    assert extract_decision(
        "audisp-syslog[*]: type=SYSCALL "
        "msg=audit(1700000000.125:91): acct=admin res=success",
        program="audisp-syslog",
    ) is None


_AUDIT_B_HEADS = (
    "AUDIT1138",
    "BPF",
    "SERVICE_START",
    "SERVICE_STOP",
    "NETFILTER_CFG",
    "MAC_POLICY_LOAD",
    "SYSCALL",
)


@pytest.mark.parametrize("head", _AUDIT_B_HEADS)
def test_type_less_audit_accepts_exact_heads_only_with_result(head: str) -> None:
    decision = extract_decision(
        f"audit[*]: {head} pid=123 acct=admin res=failed",
        program="audit",
    )

    assert decision == _decision(
        AuthOutcome.DENIED,
        "audit",
        actor="admin",
        actor_namespace="unix_user",
        audit_type=head,
        res="failed",
    )


def test_type_less_audit_checks_nested_result_after_merge_and_keeps_hex() -> None:
    decision = extract_decision(
        "audit[*]: AUDIT1138 pid=123 auid=4294967295 ses=4294967295 "
        "addr=? terminal=? "
        "msg='acct=\"admin\" exe=2F7573722F62696E2F74657374 res=success'",
        program="audit",
    )

    assert decision == _decision(
        AuthOutcome.GRANTED,
        "audit",
        actor="admin",
        actor_namespace="unix_user",
        source=None,
        auid="4294967295",
        terminal="?",
        exe="2F7573722F62696E2F74657374",
        audit_type="AUDIT1138",
        res="success",
        session="4294967295",
    )


def test_type_less_audit_absent_result_is_not_a_decision() -> None:
    assert extract_decision(
        "audit[*]: AUDIT1138 pid=123 acct=admin",
        program="audit",
    ) is None


def test_type_less_audit_unfamiliar_result_is_indeterminate() -> None:
    decision = extract_decision(
        "audit[*]: AUDIT1138 pid=123 acct=admin res=unknown",
        program="audit",
    )

    assert decision is not None
    assert decision.outcome is AuthOutcome.INDETERMINATE
    assert decision.res == "unknown"


def test_program_dispatch_has_three_structural_arms(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unexpected(*_args: object, **_kwargs: object) -> AuthDecision | None:
        raise AssertionError("known-other tags must not reach a grammar choke point")

    monkeypatch.setattr(auth_parser, "_extract_known", _unexpected)
    monkeypatch.setattr(auth_parser, "_extract_untagged", _unexpected)

    assert extract_decision(
        "dnf[*]: Permission denied while updating metadata",
        program="dnf",
    ) is None


@pytest.mark.parametrize(
    "message",
    [
        "pihole-web [12:00 99] Authentication required, redirecting to /admin/login",
        "polkit-kde-authentication-agent package update Failed to refresh",
        "Failed password for admin from 192.0.2.60 port 22",
        "Permission denied",
    ],
)
def test_untagged_extraction_gap_is_explicit(message: str) -> None:
    assert extract_decision(message, program="unknown") is None


def test_stub_metadata_mirrors_the_syslog_lane_without_becoming_available() -> None:
    assert auth_detector.STATUS == "planned"
    assert auth_detector.REQUIRED_LOGS == []
    assert auth_detector.OPTIONAL_LOGS == [
        {"source": "syslog_dir", "pattern": "*.log*"},
        {"source": "journal", "pattern": "*.log*"},
        {"source": "zeek_dir", "pattern": "syslog*.log*"},
    ]
    assert auth_detector.REQUIRES_ONE_OF_OPTIONAL is True
    assert auth_detector.REQUIRES_ONE_OF_OPTIONAL_REASON == (
        "no syslog source found (need a readable system journal, syslog files, "
        "or Zeek syslog.log)"
    )


def test_parser_has_no_heavy_or_cross_boundary_imports() -> None:
    path = Path(auth_parser.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = {
        "pandas",
        "numpy",
        "loader",
        "runner",
        "detectors",
        "outputs",
        "config",
    }
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            parts = node.module.split(".")
            imported.add(parts[0])
            if len(parts) > 1 and parts[0] == "sigwood":
                imported.add(parts[1])

    assert imported.isdisjoint(forbidden)
