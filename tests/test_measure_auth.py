"""Contract tests for the private authentication measurement instrument."""

from __future__ import annotations

import gzip
import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigwood.common.loader import load_syslog
from sigwood.parsers import syslog as syslog_parser
from tools import measure_auth as measure


def _rid(number: int) -> measure.RecordId:
    return "synthetic", "placeholder.log", number


def _decision(
    number: int,
    ts: float,
    outcome: str,
    *,
    host: str = "HOST.EXAMPLE",
    gate: str = "sshd",
    namespace: str | None = "unix_user",
    actor: str | None = "alice",
    target: str | None = None,
    source: str | None = "192.0.2.10",
) -> measure.DecisionRow:
    return measure.DecisionRow(
        record_id=_rid(number),
        ts=ts,
        host=host,
        gate=gate,
        outcome=outcome,
        actor_namespace=namespace,
        actor=actor,
        target=target,
        source=source,
    )


def _canonical(
    number: int,
    ts: float,
    *,
    host: str = "host.example",
    message: str = "sshd: placeholder",
) -> measure.CanonicalRow:
    return measure.CanonicalRow(
        record_id=_rid(number),
        ts=ts,
        host=host,
        program="sshd",
        raw=message,
        message=message,
    )


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_episode_key_uses_host_gate_edge_and_exact_degraded_forms() -> None:
    full = _decision(1, 1.0, "denied", target="ignored-target")
    changed_target = _decision(2, 1.0, "denied", target="different-target")
    source_only = _decision(3, 1.0, "denied", actor=None, namespace=None)
    actor_only = _decision(4, 1.0, "denied", source=None)

    assert measure.episode_key(full) == (
        "host.example",
        "sshd",
        "edge",
        "unix_user",
        "alice",
        "192.0.2.10",
    )
    assert measure.episode_key(full) == measure.episode_key(changed_target)
    assert measure.episode_key(source_only) == (
        "host.example",
        "sshd",
        "source",
        "192.0.2.10",
    )
    assert measure.episode_key(actor_only) == (
        "host.example",
        "sshd",
        "actor",
        "unix_user",
        "alice",
    )


def test_actor_namespace_separates_otherwise_identical_episode_keys() -> None:
    unix = _decision(1, 1.0, "denied", namespace="unix_user")
    audit = _decision(2, 1.0, "denied", namespace="unix_auid")
    assert measure.episode_key(unix) != measure.episode_key(audit)


def test_structural_classifier_reuses_quoted_identity_grammar() -> None:
    row = measure.CanonicalRow(
        record_id=_rid(1),
        ts=1.0,
        host="host.example",
        program="sshd",
        raw="placeholder",
        message=(
            'sshd: Failed password for invalid user "alice example" '
            "from 192.0.2.10 port 22"
        ),
    )
    assert measure.classify_structure(row) == (
        "sshd-text",
        "failed-invalid-user",
    )


def test_program_arm_uses_parser_owned_successor_roster() -> None:
    for program in (
        "sshd(pam_unix)",
        "kscreenlocker_greet",
        "gdm-password]",
        "--",
    ):
        assert measure._program_arm(program) == program
    assert measure._program_arm("gdm-password") == "other-tag"


@pytest.mark.parametrize(
    ("program", "message", "expected"),
    [
        (
            "sshd(pam_unix)",
            "sshd(pam_unix)[*]: authentication failure; "
            "rhost=192.0.2.70 user=admin",
            ("pam-text", "authentication-failure"),
        ),
        (
            "sshd(pam_unix)",
            "sshd(pam_unix)[*]: 7 more authentication failures; "
            "rhost=192.0.2.71 user=admin",
            ("pam-text", "authentication-failure-summary"),
        ),
        (
            "sshd",
            "sshd[*]: PAM 5 more authentication failures; "
            "rhost=198.51.100.71 user=admin",
            ("pam-text", "authentication-failure-summary"),
        ),
        (
            "su",
            "su[*]: (to root) admin on pts/5",
            ("pam-text", "su-grant"),
        ),
        (
            "--",
            "-- root[*]: ROOT LOGIN ON tty2",
            ("pam-text", "root-login-grant"),
        ),
    ],
)
def test_successor_structural_types_precede_broad_fallbacks(
    program: str, message: str, expected: tuple[str, str]
) -> None:
    row = measure.CanonicalRow(
        record_id=_rid(1),
        ts=1.0,
        host="host.example",
        program=program,
        raw="placeholder",
        message=message,
    )
    assert measure.classify_structure(row) == expected


@pytest.mark.parametrize(
    ("program", "message"),
    [
        (
            "sshd(pam_unix)",
            "sshd(pam_unix)[*]: 7 more authentication failures; "
            "rhost=192.0.2.72 user=root",
        ),
        (
            "sshd",
            "sshd[*]: PAM 5 more authentication failures; "
            "rhost=198.51.100.72 user=root",
        ),
    ],
)
def test_authentication_failure_summaries_are_visible_but_not_decisions(
    program: str, message: str
) -> None:
    row = measure.CanonicalRow(
        record_id=_rid(1),
        ts=1.0,
        host="host.example",
        program=program,
        raw="placeholder",
        message=message,
    )
    taxonomy = {
        measure._taxonomy_pair(
            "pam-text", "authentication-failure-summary"
        ): "INELIGIBLE"
    }

    assert measure.classify_structure(row) == (
        "pam-text",
        "authentication-failure-summary",
    )
    assert measure.extract_decision(row.message, program=row.program) is None
    assert measure._decision_row(row, taxonomy) is None


def test_audit_record_type_owns_its_lens_gate() -> None:
    row = measure.CanonicalRow(
        record_id=_rid(1),
        ts=1.0,
        host="host.example",
        program="audisp-syslog",
        raw="placeholder",
        message=(
            "audisp-syslog[*]: type=USER_LOGIN "
            "msg=audit(1700000000.125:77): acct=alice addr=192.0.2.10 "
            "res=failed"
        ),
    )
    taxonomy = {
        measure._taxonomy_pair("audisp-type", "USER_LOGIN"): "COUNT"
    }
    decision = measure._decision_row(row, taxonomy)
    assert decision is not None
    assert decision.gate == "audit:USER_LOGIN"


@pytest.mark.parametrize(
    ("record_type", "res", "expected_outcome"),
    [
        ("USER_AUTH", "success", "granted"),
        ("USER_ERR", "failed", "denied"),
    ],
)
def test_audisp_auth_and_error_count_rows_reach_distinct_lens_gates(
    record_type: str, res: str, expected_outcome: str
) -> None:
    row = measure.CanonicalRow(
        record_id=_rid(1),
        ts=1.0,
        host="host.example",
        program="audisp-syslog",
        raw="placeholder",
        message=(
            f"audisp-syslog[*]: type={record_type} "
            "msg=audit(1700000000.125:77): acct=alice addr=192.0.2.10 "
            f"op=PAM:authentication res={res}"
        ),
    )
    taxonomy = {
        measure._taxonomy_pair("audisp-type", record_type): "COUNT"
    }

    decision = measure._decision_row(row, taxonomy)

    assert decision is not None
    assert decision.gate == f"audit:{record_type}"
    assert decision.outcome == expected_outcome


def test_ineligible_user_cmd_is_rejected_even_when_parser_extracts_it() -> None:
    row = measure.CanonicalRow(
        record_id=_rid(1),
        ts=1.0,
        host="host.example",
        program="audisp-syslog",
        raw="placeholder",
        message=(
            "audisp-syslog[*]: type=USER_CMD "
            "msg=audit(1700000000.125:77): acct=alice addr=192.0.2.10 "
            "res=success"
        ),
    )
    taxonomy = {
        measure._taxonomy_pair("audisp-type", "USER_CMD"): "INELIGIBLE"
    }

    assert measure.extract_decision(row.message, program=row.program) is not None
    assert measure._decision_row(row, taxonomy) is None


def test_pam_setcred_is_structurally_named_but_taxonomy_ineligible() -> None:
    row = measure.CanonicalRow(
        record_id=_rid(1),
        ts=1.0,
        host="host.example",
        program="audisp-syslog",
        raw="placeholder",
        message=(
            "audisp-syslog[*]: type=CRED_ACQ "
            "msg=audit(1700000000.125:78): op=PAM:setcred acct=alice "
            "addr=203.0.113.78 res=success"
        ),
    )
    taxonomy = {
        measure._taxonomy_pair("audisp-type", "CRED_ACQ"): "INELIGIBLE"
    }

    assert measure.classify_structure(row) == ("audisp-type", "CRED_ACQ")
    assert measure.extract_decision(row.message, program=row.program) is not None
    assert measure._decision_row(row, taxonomy) is None


def test_known_declared_gap_labels_only_unrepresented_count_rows() -> None:
    assert (
        measure._known_declared_gap("audisp-type", "AVC", "COUNT", None)
        == "AVC"
    )
    assert (
        measure._known_declared_gap("audisp-type", "USER_AUTH", "COUNT", None)
        == "USER_AUTH"
    )
    assert (
        measure._known_declared_gap("audisp-type", "AVC", "INELIGIBLE", None)
        is None
    )


def test_enrich_edge_absence_is_not_failure_but_one_sided_edge_is() -> None:
    assert measure._edge_metrics([], [], ["serial"])["verdict"] == "ABSENT"
    assert measure._edge_metrics([{"serial": "1"}], [], ["serial"])[
        "verdict"
    ] == "FAIL"


def test_concentration_floor_and_near_miss() -> None:
    decisions = [_decision(index, float(index), "denied") for index in range(1, 101)]
    other = [
        _decision(
            200 + index,
            float(index),
            "denied",
            actor="bob",
            source="198.51.100.20",
        )
        for index in range(99)
    ]
    findings, near_miss, fidelity = measure.concentration(
        decisions + other, measure.Window(0.0, 200.0, right_closed=True)
    )
    assert len(findings) == 1
    assert near_miss == 99
    assert fidelity == {"edge": 1}


def test_landing_requires_six_ordinal_denials_and_same_host_aliveness() -> None:
    decisions = [_decision(index, float(index), "denied") for index in range(1, 7)]
    decisions.append(_decision(7, 7.0, "granted"))
    rows = [_canonical(index, float(index)) for index in range(1, 9)]

    keys, transitions, ties = measure.landing(
        decisions, rows, measure.Window(0.0, 9.0, right_closed=True)
    )

    assert len(keys) == 1
    assert len(transitions) == 1
    assert transitions[0]["status"] == "established"
    assert transitions[0]["run_length"] == 6
    assert transitions[0]["cessation"] is True
    assert ties == 0


def test_landing_cannot_claim_cessation_without_later_same_host_row() -> None:
    decisions = [_decision(index, float(index), "denied") for index in range(1, 7)]
    decisions.append(_decision(7, 7.0, "granted"))
    rows = [_canonical(index, float(index)) for index in range(1, 8)]
    rows.append(_canonical(8, 8.0, host="other.example"))
    _keys, transitions, _ties = measure.landing(
        decisions, rows, measure.Window(0.0, 9.0, right_closed=True)
    )
    assert transitions[0]["cessation"] is False


def test_landing_later_key_denial_withholds_cessation() -> None:
    decisions = [_decision(index, float(index), "denied") for index in range(1, 7)]
    decisions.extend([_decision(7, 7.0, "granted"), _decision(8, 8.0, "denied")])
    rows = [_canonical(index, float(index)) for index in range(1, 10)]
    _keys, transitions, _ties = measure.landing(
        decisions, rows, measure.Window(0.0, 10.0, right_closed=True)
    )
    assert transitions[0]["cessation"] is False


def test_landing_equal_timestamp_fails_closed() -> None:
    decisions = [_decision(index, float(index), "denied") for index in range(1, 6)]
    decisions.append(_decision(6, 7.0, "denied"))
    decisions.append(_decision(7, 7.0, "granted"))
    rows = [_canonical(index, float(index)) for index in range(1, 9)]
    keys, transitions, ties = measure.landing(
        decisions, rows, measure.Window(0.0, 9.0, right_closed=True)
    )
    assert not keys
    assert transitions[0]["status"] == "tie-unresolved"
    assert ties == 1


def test_landing_tie_result_does_not_depend_on_ingestion_order() -> None:
    decisions = [_decision(index, float(index), "denied") for index in range(1, 6)]
    decisions.extend(
        [
            _decision(7, 7.0, "granted"),
            _decision(6, 7.0, "denied"),
        ]
    )
    rows = [_canonical(index, float(index)) for index in range(1, 9)]
    keys, transitions, ties = measure.landing(
        decisions, rows, measure.Window(0.0, 9.0, right_closed=True)
    )
    assert not keys
    assert transitions[0]["status"] == "tie-unresolved"
    assert ties == 1


def test_landing_reconciles_multiple_transitions_to_one_finding() -> None:
    decisions = []
    number = 1
    for offset in (0.0, 20.0):
        for index in range(6):
            decisions.append(_decision(number, offset + index + 1, "denied"))
            number += 1
        decisions.append(_decision(number, offset + 7, "granted"))
        number += 1
    rows = [_canonical(index, float(index)) for index in range(1, 40)]
    keys, transitions, _ties = measure.landing(
        decisions, rows, measure.Window(0.0, 40.0, right_closed=True)
    )
    assert len(keys) == 1
    assert len(transitions) == 2


def test_fanout_uses_tagged_union_namespaces_and_excludes_target() -> None:
    decisions = [
        _decision(
            index,
            float(index),
            "denied",
            actor=f"user-{index}",
            namespace="unix_user" if index < 5 else "unix_auid",
            target=f"target-{index}",
            source="203.0.113.9",
        )
        for index in range(1, 6)
    ]
    decisions.extend(
        _decision(
            20 + index,
            float(20 + index),
            "denied",
            actor="shared",
            source=f"192.0.2.{index}",
            target="never-an-axis",
        )
        for index in range(1, 6)
    )
    entities, source_near, account_near = measure.fanout(
        decisions, measure.Window(0.0, 100.0, right_closed=True)
    )
    assert ("source", ("203.0.113.9",)) in entities
    assert ("account", ("unix_user", "shared")) in entities
    assert all("target" not in repr(entity) for entity in entities)
    assert source_near >= 1
    assert account_near >= 1


def test_f7_suppresses_only_concentration_overlap() -> None:
    key = ("host", "sshd", "edge", "unix_user", "alice", "192.0.2.1")
    result = measure.LensResult(
        concentration_keys=frozenset({key}),
        concentration_near_miss=0,
        landing_keys=frozenset({key}),
        landing_transitions=(),
        landing_tie_unresolved=0,
        fanout_entities=frozenset({("source", ("192.0.2.1",))}),
        fanout_source_near_miss=0,
        fanout_account_near_miss=0,
        eligible_count=500,
    )
    assert measure.f7_inputs(result) == {
        "landing": 1,
        "concentration": 0,
        "fanout": 1,
    }


@pytest.mark.parametrize(
    ("counts", "evaluable", "expected"),
    [
        ([0, 1, 1, 1, 1], [True] * 5, "FAIL"),
        ([0, 0, 0, 0, 0], [True] * 5, "UNMEASURABLE"),
        ([2, 2, 2, 2, 2], [True, True, True, True, False], "UNMEASURABLE"),
        ([1, 2, 2, 3, 3], [True] * 5, "PASS"),
        ([1, 1, 1, 1, 4], [True] * 5, "FAIL"),
    ],
)
def test_b4_frozen_branches(
    counts: list[int], evaluable: list[bool], expected: str
) -> None:
    assert measure.b4_verdict(counts, evaluable) == expected


def test_sliding_windows_are_anchored_at_midpoint_without_rebalancing() -> None:
    boundary = {
        "t_first_epoch": 0.0,
        "t_mid_epoch": 14.2 * 86400.0,
    }
    windows = measure.sliding_windows(boundary)
    assert len(windows) == 8
    assert windows[0].end == boundary["t_mid_epoch"]
    assert all(window.end - window.start == 7 * 86400 for window in windows)


def test_ordinal_sampling_is_identical_to_sorted_record_id_sampling() -> None:
    record_ids = [
        ("estate", f"host-{index // 10}.log", index + 1) for index in range(100)
    ]
    expected = __import__("random").Random(measure.SAMPLE_SEED).sample(
        sorted(record_ids), 25
    )
    ordinals = measure.sample_ordinals(len(record_ids), 25)
    actual = measure.retrieve_ordinal_sample(iter(sorted(record_ids)), ordinals)
    assert actual == expected


def test_canonical_iterator_matches_real_loader_for_flat_and_compressed(tmp_path: Path) -> None:
    flat = tmp_path / "fallback.example.log"
    compressed = tmp_path / "other.example.log.gz"
    _write(
        flat,
        "\n# comment\n"
        "2026-08-01T00:00:00Z host.example sshd[7]: Failed password for alice from 192.0.2.1 port 22\r\n"
        "2026-08-01T00:00:01Z host.example other-program: placeholder\n",
    )
    with gzip.open(compressed, "wt", encoding="utf-8") as handle:
        handle.write(
            "2026-08-01T00:00:02Z host.example cron[1]: completed placeholder\n"
        )
    manifest = {
        "corpora": {
            "estate": {
                "files": [
                    {"relative_path": flat.name, "path": str(flat)},
                    {"relative_path": compressed.name, "path": str(compressed)},
                ]
            }
        }
    }
    actual = list(
        measure.iter_canonical_rows(
            manifest, "estate", boundary=None, openssh_scope="full"
        )
    )
    expected = load_syslog(
        tmp_path, _files=[flat, compressed], show_progress=False
    ).to_dict("records")
    assert len(actual) == len(expected)
    for row, reference in zip(actual, expected, strict=True):
        assert row.ts == reference["ts"] or (
            math.isnan(row.ts) and math.isnan(reference["ts"])
        )
        assert row.host == reference["host"]
        assert row.program == reference["program"]
        assert row.raw == reference["raw"]
        assert row.message == reference["message"]
    assert actual[1].program == "other-program"


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: ANN001
        value = cls(2026, 8, 4, 12, 0, 0)
        return value.replace(tzinfo=tz) if tz is not None else value


class _LaterDatetime(datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: ANN001
        value = cls(2027, 8, 4, 12, 0, 0)
        return value.replace(tzinfo=tz) if tz is not None else value


def _simple_corpora(tmp_path: Path, *, yearless_openssh: bool = False) -> tuple[Path, Path, Path]:
    estate = tmp_path / "estate.log"
    openssh = tmp_path / "openssh.log"
    linux = tmp_path / "linux.log"
    _write(
        estate,
        "2026-07-01T00:00:00Z estate.example sshd[1]: Failed password for alice from 192.0.2.1 port 22\n",
    )
    if yearless_openssh:
        _write(
            openssh,
            "Dec 10 00:00:00 openssh.example sshd[1]: Failed password for alice from 192.0.2.1 port 22\n"
            "Jan  7 00:00:00 openssh.example sshd[1]: Accepted password for alice from 192.0.2.1 port 22\n",
        )
    else:
        _write(
            openssh,
            "2026-01-01T00:00:00Z openssh.example sshd[1]: Failed password for alice from 192.0.2.1 port 22\n"
            "2026-01-29T00:00:00Z openssh.example sshd[1]: Accepted password for alice from 192.0.2.1 port 22\n",
        )
    _write(
        linux,
        "2026-02-01T00:00:00Z linux.example sshd[1]: Failed password for alice from 192.0.2.1 port 22\n",
    )
    return estate, openssh, linux


def _init(tmp_path: Path, **kwargs) -> Path:  # noqa: ANN003
    estate, openssh, linux = _simple_corpora(tmp_path, **kwargs)
    bundle = tmp_path / "bundle"
    measure.init_bundle(
        bundle,
        charter=measure.DEFAULT_CHARTER,
        estate=estate,
        openssh=openssh,
        linux=linux,
    )
    return bundle


def test_frozen_charter_and_parser_hashes_match_declared_files() -> None:
    assert (
        measure._sha256_path(measure.DEFAULT_CHARTER)
        == measure.FROZEN_CHARTER_SHA256
    )
    assert (
        measure._sha256_path(Path(measure.auth_parser.__file__))
        == measure.FROZEN_PARSER_SHA256
    )


def test_bundle_is_outside_repo_private_and_hash_pinned(tmp_path: Path) -> None:
    bundle = _init(tmp_path)
    assert os.stat(bundle).st_mode & 0o777 == 0o700
    assert os.stat(bundle / "manifest.json").st_mode & 0o777 == 0o600
    assert measure._read_receipt(bundle, "init")["manifest_sha256"]
    with pytest.raises(measure.MeasurementError, match="new"):
        measure.init_bundle(
            bundle,
            charter=measure.DEFAULT_CHARTER,
            estate=tmp_path / "estate.log",
            openssh=tmp_path / "openssh.log",
            linux=tmp_path / "linux.log",
        )


def test_init_can_pin_an_explicit_static_estate_file_set(tmp_path: Path) -> None:
    estate, openssh, linux = _simple_corpora(tmp_path)
    second = tmp_path / "estate-second.log"
    excluded = tmp_path / "estate-newer.log"
    _write(
        second,
        "2026-07-02T00:00:00Z estate.example cron[1]: placeholder\n",
    )
    _write(
        excluded,
        "2026-08-03T00:00:00Z estate.example cron[1]: outside frozen slice\n",
    )
    bundle = tmp_path / "bundle-explicit"
    manifest = measure.init_bundle(
        bundle,
        charter=measure.DEFAULT_CHARTER,
        estate=[estate, second],
        openssh=openssh,
        linux=linux,
    )
    assert len(manifest["corpora"]["estate"]["files"]) == 2
    assert all(
        entry["path"] != str(excluded.resolve())
        for entry in manifest["corpora"]["estate"]["files"]
    )


def test_static_file_set_records_calendar_gaps_without_imputation(
    tmp_path: Path,
) -> None:
    files = []
    for stamp in ("20260101", "20260102", "20260105", "20260107"):
        path = tmp_path / f"syslog_{stamp}_placeholder.log"
        _write(
            path,
            f"2026-01-01T00:00:00Z host.example cron[1]: placeholder {stamp}\n",
        )
        files.append(path)
    entry = measure._corpus_entry(files)
    assert entry["calendar_coverage"] == {
        "daily_files": 4,
        "first_date": "2026-01-01",
        "last_date": "2026-01-07",
        "calendar_days": 7,
        "missing_days": 3,
        "missing_runs": [2, 1],
        "longest_gap_days": 2,
    }


def test_bundle_refuses_repository_target(tmp_path: Path) -> None:
    estate, openssh, linux = _simple_corpora(tmp_path)
    with pytest.raises(measure.MeasurementError, match="outside"):
        measure.init_bundle(
            measure.REPO_ROOT / "private" / "forbidden-measurement-bundle",
            charter=measure.DEFAULT_CHARTER,
            estate=estate,
            openssh=openssh,
            linux=linux,
        )


def test_cli_failure_does_not_echo_private_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_path = tmp_path / "private-hostname-and-account"
    assert measure.main(["boundary", "--bundle", str(secret_path)]) == 2
    captured = capsys.readouterr()
    assert str(secret_path) not in captured.err
    assert "phase failed" in captured.err


def test_corpus_fingerprint_change_refuses_next_phase(tmp_path: Path) -> None:
    bundle = _init(tmp_path)
    estate = tmp_path / "estate.log"
    estate.write_text(estate.read_text(encoding="utf-8") + "changed\n", encoding="utf-8")
    with pytest.raises(measure.MeasurementError, match="fingerprint"):
        measure.compute_boundary(bundle)


def test_boundary_uses_shipped_yearless_parser_across_december_to_january(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(syslog_parser, "datetime", _FrozenDatetime)
    bundle = _init(tmp_path, yearless_openssh=True)
    receipt = measure.compute_boundary(bundle)
    assert datetime.fromisoformat(receipt["t_first"]).year == 2025
    assert datetime.fromisoformat(receipt["t_last"]).year == 2026
    assert receipt["t_first_epoch"] < receipt["t_mid_epoch"] < receipt["t_last_epoch"]
    monkeypatch.setattr(syslog_parser, "datetime", _LaterDatetime)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    rows = list(
        measure.iter_canonical_rows(
            manifest, "openssh", boundary=receipt, openssh_scope="full"
        )
    )
    assert datetime.fromtimestamp(rows[0].ts, timezone.utc).year == 2025
    assert datetime.fromtimestamp(rows[-1].ts, timezone.utc).year == 2026


def test_boundary_fails_closed_on_unassignable_physical_row(tmp_path: Path) -> None:
    bundle = _init(tmp_path)
    openssh = tmp_path / "openssh.log"
    openssh.write_text(openssh.read_text(encoding="utf-8") + "unassignable\n", encoding="utf-8")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["corpora"]["openssh"]["files"][0]
    stat = openssh.stat()
    entry["size"] = stat.st_size
    entry["mtime_ns"] = stat.st_mtime_ns
    entry["sha256"] = measure._sha256_path(openssh)
    (bundle / "manifest.json").write_bytes(measure._json_bytes(manifest))
    (bundle / "manifest.sha256").write_text(
        measure._sha256_path(bundle / "manifest.json") + "\n", encoding="ascii"
    )
    with pytest.raises(measure.MeasurementError, match="unassignable"):
        measure.compute_boundary(bundle)
    assert measure._read_receipt(bundle, "boundary-divergence")[
        "unassignable_timestamps"
    ] == 1


def test_boundary_asserts_and_records_an_external_exact_baseline(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    first_root.mkdir()
    first = measure.compute_boundary(_init(first_root))
    expected_path = tmp_path / "expected-boundary.json"
    _write(
        expected_path,
        json.dumps(
            {
                "schema": measure.SCHEMA_VERSION,
                **{
                    field: first[field]
                    for field in measure.BOUNDARY_BASELINE_FIELDS
                },
            },
            sort_keys=True,
        ),
    )
    second_root = tmp_path / "second"
    second_root.mkdir()

    second = measure.compute_boundary(
        _init(second_root), expected_baseline=expected_path
    )

    assert second["baseline_assertion"] == {
        "verdict": "PASS",
        "baseline_sha256": measure._sha256_path(expected_path),
        "fields": list(measure.BOUNDARY_BASELINE_FIELDS),
        "mismatches": [],
    }
    assert second["calibration_rows"] == first["calibration_rows"]


def test_boundary_baseline_mismatch_fails_before_writing_boundary(
    tmp_path: Path,
) -> None:
    root = tmp_path / "mismatch"
    root.mkdir()
    bundle = _init(root)
    expected_path = tmp_path / "wrong-boundary.json"
    _write(
        expected_path,
        json.dumps(
            {
                "schema": measure.SCHEMA_VERSION,
                "physical_rows": 999,
                "unassignable_timestamps": 0,
                "calibration_rows": 1,
                "t_first_epoch": 0.0,
                "t_mid_epoch": 1.0,
                "t_last_epoch": 2.0,
            },
            sort_keys=True,
        ),
    )

    with pytest.raises(measure.MeasurementError, match="baseline assertion"):
        measure.compute_boundary(bundle, expected_baseline=expected_path)

    assert not (bundle / "receipts" / "boundary.json").exists()
    divergence = measure._read_receipt(bundle, "boundary-divergence")
    assert divergence["verdict"] == "FAIL"
    assert "physical_rows" in divergence["mismatches"]


def test_validation_marker_survives_worker_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "receipts").mkdir(parents=True)
    parser_hash = measure._sha256_path(Path(measure.auth_parser.__file__))
    manifest = {"tool": {"sha256": "tool"}}
    frozen = {
        "parser_sha256": parser_hash,
        "taxonomy_manifest_sha256": "taxonomy",
        "tool_sha256": "tool",
    }

    monkeypatch.setattr(measure, "_load_bundle", lambda _path: (bundle, manifest))
    monkeypatch.setattr(measure, "_require_receipts", lambda *_args: None)
    monkeypatch.setattr(
        measure,
        "_read_receipt",
        lambda _bundle, name: frozen if name == "instrument-frozen" else {"taxonomy_manifest_sha256": "taxonomy"},
    )
    monkeypatch.setattr(
        measure,
        "_run_worker",
        lambda *_args: (_ for _ in ()).throw(measure.MeasurementError("crash")),
    )
    with pytest.raises(measure.MeasurementError, match="crash"):
        measure.heldback_phase(bundle)
    assert (bundle / "validation-spent.json").exists()
    assert measure._read_json(bundle / "receipts" / "heldback-failure.json")[
        "retry_permitted"
    ] is False


def test_synthetic_cli_end_to_end_keeps_validation_one_shot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    estate = tmp_path / "estate.log"
    openssh = tmp_path / "openssh.log"
    linux = tmp_path / "linux.log"
    _write(
        estate,
        "2026-07-01T00:00:00Z estate.example sshd[1]: Failed password for alice from 192.0.2.1 port 22\n"
        "2026-07-02T00:00:00Z estate.example sshd[1]: Accepted password for alice from 192.0.2.1 port 22\n"
        "2026-07-03T00:00:00Z estate.example cron[1]: completed placeholder task\n",
    )
    _write(
        openssh,
        "2026-01-01T00:00:00Z openssh.example sshd[1]: Failed password for alice from 198.51.100.2 port 22\n"
        "2026-01-10T00:00:00Z openssh.example sshd[1]: Accepted password for alice from 198.51.100.2 port 22\n"
        "2026-01-20T00:00:00Z openssh.example sshd[1]: Failed password for bob from 203.0.113.3 port 22\n"
        "2026-01-29T00:00:00Z openssh.example sshd[1]: Accepted password for bob from 203.0.113.3 port 22\n",
    )
    _write(
        linux,
        "2026-02-01T00:00:00Z linux.example sshd[1]: Failed password for alice from 192.0.2.4 port 22\n"
        "2026-02-02T00:00:00Z linux.example cron[1]: completed placeholder task\n",
    )
    bundle = tmp_path / "bundle"
    assert measure.main(
        [
            "init",
            "--bundle",
            str(bundle),
            "--estate",
            str(estate),
            "--openssh",
            str(openssh),
            "--linux",
            str(linux),
        ]
    ) == 0
    assert measure.main(["boundary", "--bundle", str(bundle)]) == 0
    assert measure.main(["taxonomy-inventory", "--bundle", str(bundle)]) == 0

    inventory = measure._read_receipt(bundle, "taxonomy-inventory")
    inventory_hash = measure._sha256_path(
        bundle / "receipts" / "taxonomy-inventory.json"
    )
    pairs = sorted(
        {(row["dialect"], row["record_type"]) for row in inventory["table"]}
    )
    declaration = tmp_path / "taxonomy.json"
    declaration.write_text(
        json.dumps(
            {
                "schema": measure.SCHEMA_VERSION,
                "inventory_receipt_sha256": inventory_hash,
                "record_types": [
                    {
                        "dialect": dialect,
                        "record_type": record_type,
                        "class": (
                            "COUNT"
                            if (dialect, record_type)
                            in {
                                ("sshd-text", "accepted"),
                                ("sshd-text", "failed-password"),
                            }
                            else "INELIGIBLE"
                        ),
                    }
                    for dialect, record_type in pairs
                ],
                "enrich_edges": [],
                "rationale_notes": [
                    {
                        "id": "synthetic-contract",
                        "text": "Synthetic taxonomy rationale is hash-bound.",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    assert measure.main(
        [
            "taxonomy-evaluate",
            "--bundle",
            str(bundle),
            "--manifest",
            str(declaration),
        ]
    ) == 0
    taxonomy_hash = measure._sha256_path(declaration)
    assert measure.main(
        [
            "honesty",
            "--bundle",
            str(bundle),
            "--accepted-taxonomy-sha256",
            taxonomy_hash,
        ]
    ) == 0
    samples = measure._read_jsonl(bundle / "raw" / "honesty-samples.jsonl")
    honesty_adjudications = tmp_path / "honesty-adjudications.jsonl"
    _write_jsonl(
        honesty_adjudications,
        [{"sample_id": row["sample_id"], "error": False} for row in samples],
    )
    assert measure.main(
        [
            "honesty",
            "--bundle",
            str(bundle),
            "--accepted-taxonomy-sha256",
            taxonomy_hash,
            "--adjudications",
            str(honesty_adjudications),
        ]
    ) == 0

    assert measure.main(["calibration", "--bundle", str(bundle)]) == 0
    empty = tmp_path / "empty-adjudications.jsonl"
    empty.write_text("", encoding="utf-8")
    assert measure.main(
        [
            "calibration",
            "--bundle",
            str(bundle),
            "--adjudications",
            str(empty),
        ]
    ) == 0
    assert measure.main(["estate", "--bundle", str(bundle)]) == 0
    assert measure.main(
        [
            "estate",
            "--bundle",
            str(bundle),
            "--adjudications",
            str(empty),
        ]
    ) == 0
    assert measure.main(["heldback", "--bundle", str(bundle)]) == 0
    assert measure._read_json(bundle / "validation-spent.json")["schema"] == 1
    assert measure.main(["heldback", "--bundle", str(bundle)]) == 2

    fake_repo = tmp_path / "aggregate-repo"
    output_dir = fake_repo / "private" / "credible"
    output_dir.mkdir(parents=True)
    monkeypatch.setattr(measure, "REPO_ROOT", fake_repo)
    output = output_dir / "AUTH-MEASUREMENT-RESULTS-2026-08-04.md"
    assert measure.main(
        [
            "finalize",
            "--bundle",
            str(bundle),
            "--heldback-adjudications",
            str(empty),
            "--output",
            str(output),
        ]
    ) == 0
    text = output.read_text(encoding="utf-8")
    assert "UNMEASURABLE is reported as a support limitation" in text
    assert "Synthetic taxonomy rationale is hash-bound." in text
    assert "Accepted taxonomy classes:" in text
    assert "192.0.2." not in text
    assert measure._read_receipt(bundle, "finalize")["validation_spent"] is True
