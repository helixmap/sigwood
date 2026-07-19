"""Tests for the private-bundle syslog fragmentation diagnosis tool."""

from __future__ import annotations

import copy
import csv
import json
from pathlib import Path

import pandas as pd
import pytest

from drain3.masking import MaskingInstruction
from tools import diag_syslog as diag


def _frame(messages: list[str], *, feeds: list[str] | None = None) -> pd.DataFrame:
    feed_values = feeds or ["flat"] * len(messages)
    return pd.DataFrame([
        {
            "ts": float(index),
            "host": "host.example",
            "program": message.split(":", 1)[0].replace("[*]", ""),
            "raw": message,
            "message": message,
            "feed": feed,
            "_row_id": index,
        }
        for index, (message, feed) in enumerate(zip(messages, feed_values))
    ])


def _write_flat_corpus(directory: Path, secret_program: str = "sshd") -> None:
    directory.mkdir()
    (directory / "messages.log").write_text(
        "\n".join([
            f"<134>Jul 18 12:00:00 host.example {secret_program}[101]: event alpha",
            f"<134>Jul 18 12:00:01 host.example {secret_program}[102]: event beta",
            "<134>Jul 18 12:00:02 host.example kernel: device ready",
        ]) + "\n",
        encoding="utf-8",
    )


def _write_zeek_corpus(directory: Path) -> None:
    directory.mkdir()
    records = [
        {
            "_path": "syslog",
            "ts": 1779750000.0 + index,
            "uid": f"CEX{index}",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 41514,
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 514,
            "proto": "udp",
            "facility": "DAEMON",
            "severity": "INFO",
            "message": f"Jun 11 12:00:0{index} host.example sshd[12{index}]: event alpha",
        }
        for index in range(2)
    ]
    (directory / "syslog.log").write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


def test_mine_templates_pins_config_and_creation_is_not_mutation() -> None:
    result = diag.detector.mine_templates(
        ["svc: alpha beta", "svc: alpha gamma", "svc: alpha delta"],
        sim_thresh=0.5,
        depth=4,
        parametrize_numeric=True,
        show_progress=False,
    )

    assert result.miner.config.drain_sim_th == 0.5
    assert result.miner.config.drain_depth == 4
    assert result.miner.config.parametrize_numeric_tokens is True
    assert result.miner.config.masking_instructions == []
    assert result.template_changed_total == 1
    assert result.clusters_changed == 1


def test_wrapper_owns_string_coercion() -> None:
    class Message:
        def __str__(self) -> str:
            return "svc: coerced message"

    frame = _frame(["placeholder"])
    frame["message"] = [Message()]
    result = diag.detector._run_drain3(
        frame, sim_thresh=0.5, depth=4, parametrize_numeric=True
    )

    assert result["template_str"].tolist() == ["svc: coerced message"]


def test_mine_progress_requires_both_call_and_narration_gates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disabled: list[bool] = []

    def fake_tqdm(values, **kwargs):
        disabled.append(kwargs["disable"])
        return values

    monkeypatch.setattr(diag.detector, "tqdm", fake_tqdm)
    monkeypatch.setattr(diag.detector, "narration_active", lambda stream: stream is not None)
    for show_progress in (False, True):
        diag.detector.mine_templates(
            ["svc: event"],
            sim_thresh=0.5,
            depth=4,
            parametrize_numeric=True,
            show_progress=show_progress,
        )

    assert disabled == [True, False]


def test_real_miner_discriminates_half_from_library_default() -> None:
    messages = [
        "svc: anchor alpha beta gamma",
        "svc: anchor delta epsilon zeta",
    ]
    tight = diag.detector.mine_templates(
        messages,
        sim_thresh=0.5,
        depth=4,
        parametrize_numeric=True,
        show_progress=False,
    )
    loose = diag.detector.mine_templates(
        messages,
        sim_thresh=0.4,
        depth=4,
        parametrize_numeric=True,
        show_progress=False,
    )

    assert len(set(tight.template_ids)) == 2
    assert len(set(loose.template_ids)) == 1


def test_masking_seam_is_live_by_template_string() -> None:
    message = "svc: request 123e4567-e89b-12d3-a456-426614174000 complete"
    plain = diag.detector.mine_templates(
        [message],
        sim_thresh=0.5,
        depth=4,
        parametrize_numeric=True,
        show_progress=False,
    )
    masked = diag.detector.mine_templates(
        [message],
        sim_thresh=0.5,
        depth=4,
        parametrize_numeric=True,
        masking_instructions=[MaskingInstruction(diag.MASK_SPECS[0].pattern, "UUID")],
        show_progress=False,
    )

    assert plain.template_strs != masked.template_strs
    assert "<UUID>" in masked.template_strs[0]


def test_final_cluster_template_is_measurement_identity() -> None:
    run = diag._mine_frame(_frame(["svc: alpha beta", "svc: alpha gamma"]))

    assert run.result.template_strs[0] == "svc: alpha beta"
    assert run.template_table.iloc[0]["template_str"] == "svc: alpha <*>"
    assert set(run.frame["template_str"]) == {"svc: alpha <*>"}


def test_mask_set_and_order_are_pinned() -> None:
    assert diag.MASK_NAMES == (
        "uuid", "mac", "ipv6", "ipv4", "ring_stamp", "long_hex",
        "number_with_unit",
    )
    clock_and_mac = "at 12:34:56 from aa:bb:cc:dd:ee:ff"
    masked = diag._apply_masks(clock_and_mac, diag.MASK_SPECS)
    assert "12:34:56" in masked
    assert "<MAC>" in masked

    all_classes = diag._apply_masks(
        "id 123e4567-e89b-12d3-a456-426614174000 "
        "mac aa:bb:cc:dd:ee:ff ip6 2001:db8:abcd:1:2:3:4:5 "
        "ip4 192.0.2.10 ring [ 1234.567890] hex deadbeefcafebabe size 12KiB",
        diag.MASK_SPECS,
    )
    for marker in (
        "<UUID>", "<MAC>", "<IPV6>", "<IPV4>", "<RING_STAMP>",
        "<LONG_HEX>", "<NUMBER_WITH_UNIT>",
    ):
        assert marker in all_classes


def test_posthoc_math_uses_constructed_template_table() -> None:
    table = pd.DataFrame([
        {"template_str": "svc: peer 192.0.2.1", "count": 1},
        {"template_str": "svc: peer 192.0.2.2", "count": 2},
        {"template_str": "svc: ready", "count": 1},
    ])
    ipv4 = next(spec for spec in diag.MASK_SPECS if spec.name == "ipv4")

    assert diag._posthoc(table, ipv4) == {
        "templates_after": 2,
        "singletons_after": 1,
        "template_delta": 1,
    }


def test_template_program_majority_ties_lexicographically() -> None:
    frame = _frame(["svc: event", "svc: event"])
    frame["program"] = ["zeta-private", "alpha-private"]
    frame["template_id"] = [1, 1]

    table = diag._template_table(frame, {1: "svc: event"})

    assert table.iloc[0]["program"] == "alpha-private"


def test_partition_delta_known_answer() -> None:
    baseline = pd.Series([1, 1, 1, 2, 2])
    variant = pd.Series([8, 8, 9, 8, 9])

    assert diag._partition_delta(baseline, variant) == pytest.approx(0.4)


def test_histogram_boundaries_are_exact() -> None:
    assert diag._count_histogram([1, 2, 5, 6, 20, 21]) == {
        "1": 1,
        "2_5": 2,
        "6_20": 2,
        "21_plus": 1,
    }
    assert diag._wildcard_histogram([0, 0.25, 0.5, 0.75]) == {
        "0": 1,
        "0_0.25": 1,
        "0.25_0.5": 1,
        "0.5_1.0": 1,
    }


def test_baseline_known_answer_and_reboot_exclusion() -> None:
    run = diag._mine_frame(_frame([
        "sshd: repeated event",
        "sshd: repeated event",
        "kernel: Linux version 6 placeholder",
        "custom: one-off notice",
    ]))
    baseline, _ = diag._baseline(run)

    assert baseline["population"]["total_rows"] == 4
    assert baseline["population"]["count_histogram"]["1"] == 2
    assert baseline["needle_equivalent"] == 1
    assert baseline["unmeasured"] == [
        "key_value_splitting", "host_port", "journal_feed",
    ]
    assert "feed_forks" not in baseline


def test_adjacency_and_wildcard_ceiling_known_answers() -> None:
    frame = _frame([
        "svc: singleton ready",
        "svc: repeated event one",
        "svc: repeated event two",
    ])
    frame["template_id"] = [1, 2, 2]
    frame["template_str"] = [
        "svc: <*>",
        "svc: <*> <*>",
        "svc: <*> <*>",
    ]
    table = pd.DataFrame([
        {
            "template_id": 1,
            "template_str": "svc: <*>",
            "count": 1,
            "token_count": 2,
            "wildcard_fraction": 0.5,
            "program": "svc",
            "feeds": "flat",
        },
        {
            "template_id": 2,
            "template_str": "svc: <*> <*>",
            "count": 2,
            "token_count": 3,
            "wildcard_fraction": 2 / 3,
            "program": "svc",
            "feeds": "flat",
        },
    ])
    result = diag.detector.MinedResult([], [], None, 0, 0)

    baseline, _ = diag._baseline(diag.MiningRun(frame, result, table))

    assert baseline["adjacency_signature"] == 1
    assert baseline["wildcards"]["ceiling_saturated_count"] == 1
    assert baseline["routing"] == {
        "distinct_first_tokens": 1,
        "singleton_first_token_variable_share": 0.0,
    }


def test_masked_pass_invokes_nine_total_mines(monkeypatch: pytest.MonkeyPatch) -> None:
    frame = _frame(["svc: event alpha", "svc: event beta"])
    calls = 0
    real = diag.detector.mine_templates

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(diag.detector, "mine_templates", counted)
    diag._measure(frame, ("masked",), None, None, {"flat": 2, "zeek": 0})

    assert calls == 9


def test_order_single_feed_discloses_skipped_variant() -> None:
    frame = _frame(["svc: event alpha", "svc: event beta"])
    summary, _, _ = diag._measure(
        frame, ("order",), None, None, {"flat": 2, "zeek": 0}
    )
    order = summary["passes"]["order"]

    assert order["variants_run"] == ["reverse", "shuffle_3759"]
    assert order["variants_skipped"] == ["zeek_first"]
    assert "zeek_first" not in order["variants"]


def test_dual_feed_runs_zeek_first_and_emits_fork_block() -> None:
    frame = _frame(
        ["sshd: event alpha", "sshd[*]: event alpha"],
        feeds=["flat", "zeek"],
    )
    summary, _, _ = diag._measure(
        frame, ("order",), None, None, {"flat": 1, "zeek": 1}
    )

    assert "zeek_first" in summary["passes"]["order"]["variants_run"]
    assert summary["passes"]["baseline"]["feed_forks"] is not None
    assert summary["passes"]["baseline"]["feed_forks"]["pid_form_fork_count"] == 1


def test_pid_form_pair_must_cross_feeds() -> None:
    frame = _frame(
        ["sshd: event alpha", "sshd[*]: event alpha", "kernel: ready"],
        feeds=["flat", "flat", "zeek"],
    )
    summary, _, _ = diag._measure(
        frame, (), None, None, {"flat": 2, "zeek": 1}
    )

    assert summary["passes"]["baseline"]["feed_forks"]["pid_form_fork_count"] == 0


def test_feed_fork_pair_uses_full_masked_template_key() -> None:
    frame = _frame(
        ["svc: peer 192.0.2.1", "svc: peer 192.0.2.2"],
        feeds=["flat", "zeek"],
    )
    frame["template_id"] = [1, 2]
    table = pd.DataFrame([
        {
            "template_id": 1,
            "template_str": "svc: peer 192.0.2.1",
            "count": 1,
            "token_count": 3,
            "wildcard_fraction": 0.0,
            "program": "svc",
            "feeds": "flat",
        },
        {
            "template_id": 2,
            "template_str": "svc: peer 192.0.2.2",
            "count": 1,
            "token_count": 3,
            "wildcard_fraction": 0.0,
            "program": "svc",
            "feeds": "zeek",
        },
    ])
    result = diag.detector.MinedResult([], [], None, 0, 0)

    assert diag._feed_forks(diag.MiningRun(frame, result, table)) == {
        "fork_pairs": 1,
        "pid_form_fork_count": 0,
    }


def test_recount_and_simple_blocks_have_exact_fields() -> None:
    summary, _, _ = diag._measure(
        _frame(["svc: event alpha", "svc: event beta"]),
        ("recount", "simple"),
        None,
        None,
        {"flat": 2, "zeek": 0},
    )

    assert set(summary["passes"]["recount"]) == diag.RECOUNT_KEYS
    assert set(summary["passes"]["simple"]) == diag.SIMPLE_KEYS
    assert summary["passes"]["recount"]["recount_unmatched"] == 0


def test_unknown_summary_field_is_refused() -> None:
    summary, _, _ = diag._measure(
        _frame(["svc: event alpha"]), (), None, None, {"flat": 1, "zeek": 0}
    )
    hostile = copy.deepcopy(summary)
    hostile["passes"]["baseline"]["secret"] = "must not pass"

    with pytest.raises(diag.SummaryRefusal):
        diag._validate_summary(hostile)

    leaked_name = copy.deepcopy(summary)
    leaked_name["passes"]["baseline"]["programs"][0]["program"] = "private-token"
    with pytest.raises(diag.SummaryRefusal):
        diag._validate_summary(leaked_name)


def test_summary_surfaces_contain_no_raw_template_host_or_path(tmp_path: Path) -> None:
    frame = _frame(["svc: message-private-token"])
    frame["host"] = "host-private-token.example"
    summary, _, _ = diag._measure(
        frame, (), None, None, {"flat": 1, "zeek": 0}
    )
    rendered_json = json.dumps(summary, sort_keys=True)
    rendered_text = diag._summary_text(summary)

    for token in (
        "message-private-token",
        "host-private-token.example",
        str(tmp_path),
    ):
        assert token not in rendered_json
        assert token not in rendered_text


def test_time_bounds_are_utc_and_inversion_is_rejected(tmp_path: Path, capsys) -> None:
    naive = diag._parse_bound("2026-07-18T12:00:00")
    aware = diag._parse_bound("2026-07-18T07:00:00-05:00")
    assert naive == aware

    rc = diag.main([
        "--syslog-dir", str(tmp_path / "logs"),
        "--out", str(tmp_path / "bundle"),
        "--since", "2026-07-19",
        "--until", "2026-07-18",
    ])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert captured.err == "diag-syslog: invalid arguments\n"
    assert str(tmp_path) not in captured.err


def test_help_discloses_naive_bound_divergence() -> None:
    help_text = diag._build_parser().format_help()
    assert "Naive bounds are read as UTC" in help_text
    assert "unlike the sigwood CLI" in help_text


def test_real_flat_loader_route_writes_bundle_and_repeat_is_stable(
    tmp_path: Path, capsys
) -> None:
    logs = tmp_path / "logs"
    bundle = tmp_path / "bundle"
    _write_flat_corpus(logs)

    rc = diag.main([
        "--syslog-dir", str(logs),
        "--out", str(bundle),
        "--passes", "masked,order,recount,simple",
        "--verify-repeat",
    ])
    captured = capsys.readouterr()

    assert rc == 0
    assert captured.err == ""
    assert captured.out == (bundle / "summary.txt").read_text(encoding="utf-8")
    payload = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))
    assert payload["resolved_settings"]["template_identity"] == "final"
    assert payload["resolved_settings"]["feed_rows"] == {"flat": 3, "zeek": 0}
    assert set(payload["passes"]) == {"baseline", "masked", "order", "recount", "simple"}
    assert (bundle / "templates-baseline.csv").exists()
    assert (bundle / "program-decode.csv").exists()


def test_real_zeek_only_route_is_legal(tmp_path: Path, capsys) -> None:
    logs = tmp_path / "zeek"
    bundle = tmp_path / "bundle"
    _write_zeek_corpus(logs)

    assert diag.main(["--zeek-dir", str(logs), "--out", str(bundle)]) == 0
    captured = capsys.readouterr()
    payload = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))

    assert captured.err == ""
    assert payload["resolved_settings"]["feed_rows"] == {"flat": 0, "zeek": 2}
    assert "feed_forks" not in payload["passes"]["baseline"]


def test_skipped_pass_blocks_are_absent(tmp_path: Path, capsys) -> None:
    logs = tmp_path / "logs"
    bundle = tmp_path / "bundle"
    _write_flat_corpus(logs)

    assert diag.main(["--syslog-dir", str(logs), "--out", str(bundle)]) == 0
    capsys.readouterr()
    payload = json.loads((bundle / "summary.json").read_text(encoding="utf-8"))
    assert set(payload["passes"]) == {"baseline"}


def test_zero_rows_has_one_actionable_path_free_error(tmp_path: Path, capsys) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    bundle = tmp_path / "bundle"

    rc = diag.main(["--syslog-dir", str(logs), "--out", str(bundle)])
    captured = capsys.readouterr()

    assert rc == 2
    assert captured.out == ""
    assert captured.err == (
        "diag-syslog: no syslog rows loaded. Check the inputs and time bounds.\n"
    )
    assert str(tmp_path) not in captured.err


@pytest.mark.parametrize("program", ["private-token-one", "systemd-private-token-two"])
def test_unknown_program_names_are_decode_only(
    tmp_path: Path, capsys, program: str
) -> None:
    logs = tmp_path / "logs"
    bundle = tmp_path / "bundle"
    _write_flat_corpus(logs, secret_program=program)

    assert diag.main(["--syslog-dir", str(logs), "--out", str(bundle)]) == 0
    captured = capsys.readouterr()
    summary_json = (bundle / "summary.json").read_text(encoding="utf-8")
    summary_text = (bundle / "summary.txt").read_text(encoding="utf-8")
    decode = (bundle / "program-decode.csv").read_text(encoding="utf-8")

    assert "prog_" in summary_json
    assert "prog_" in summary_text
    assert program not in summary_json
    assert program not in summary_text
    assert program not in captured.out
    assert program not in captured.err
    assert program in decode


def test_forced_error_never_echoes_secret(tmp_path: Path, capsys, monkeypatch) -> None:
    logs = tmp_path / "logs"
    bundle = tmp_path / "bundle"
    _write_flat_corpus(logs, secret_program="private-error-token")

    def fail(*args, **kwargs):
        del args, kwargs
        raise ValueError("private-error-token")

    monkeypatch.setattr(diag, "_measure", fail)
    rc = diag.main(["--syslog-dir", str(logs), "--out", str(bundle)])
    captured = capsys.readouterr()

    assert rc == 2
    assert captured.out == ""
    assert "private-error-token" not in captured.err
    assert str(tmp_path) not in captured.err
    assert "private-error-token" in (bundle / "diag-error.txt").read_text(encoding="utf-8")


def test_in_repo_out_is_refused_without_echoing_path(capsys) -> None:
    target = diag.REPO_ROOT / "scratch" / "forbidden-diag-bundle"
    rc = diag.main([
        "--syslog-dir", str(diag.REPO_ROOT / "scratch"),
        "--out", str(target),
    ])
    captured = capsys.readouterr()

    assert rc == 2
    assert captured.out == ""
    assert captured.err == (
        "diag-syslog: --out must be a new empty directory outside the repo\n"
    )
    assert str(target) not in captured.err
    assert not target.exists()


def test_loader_calls_are_quiet_and_capture_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool, list[str]]] = []

    def fake_flat(path, **kwargs):
        del path
        kwargs["_warnings"].append("private flat warning")
        calls.append(("flat", kwargs["show_progress"], kwargs["_warnings"]))
        return _frame(["svc: flat"]).drop(columns=["feed", "_row_id"])

    def fake_zeek(path, pattern, **kwargs):
        del path
        assert pattern == "syslog*.log*"
        kwargs["_warnings"].append("private zeek warning")
        calls.append(("zeek", kwargs["show_progress"], kwargs["_warnings"]))
        return _frame(["svc: zeek"]).drop(columns=["feed", "_row_id"])

    monkeypatch.setattr(diag, "load_syslog", fake_flat)
    monkeypatch.setattr(diag, "load_logs", fake_zeek)
    frame, feed_rows, warnings = diag._load_inputs(Path("flat"), Path("zeek"), None, None)

    assert feed_rows == {"flat": 1, "zeek": 1}
    assert list(frame["feed"]) == ["flat", "zeek"]
    assert all(show_progress is False for _, show_progress, _ in calls)
    assert warnings == ["private flat warning", "private zeek warning"]


def test_bundle_csv_cells_neutralize_spreadsheet_formulas(tmp_path: Path) -> None:
    target = tmp_path / "table.csv"
    diag._write_csv(target, ["value"], [["=private-formula"]])

    with target.open(encoding="utf-8", newline="") as handle:
        assert list(csv.reader(handle)) == [["value"], ["'=private-formula"]]


def test_pass_parser_rejects_unknowns_and_duplicates() -> None:
    assert diag._parse_passes("simple,masked") == ("masked", "simple")
    with pytest.raises(ValueError):
        diag._parse_passes("masked,masked")
    with pytest.raises(ValueError):
        diag._parse_passes("masked,other")
