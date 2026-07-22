"""System-log intent, scope, provider, and dry-probe arbitration tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

import sigwood.runner as runner

from sigwood.common.journal_probe import JournalProbeCode, JournalProbeResult
from sigwood.common.loader import (
    JournalCaptureOutcome,
    JournalExecutableMissingError,
    JournalProcessError,
    LoadResult,
    PermissionSkipInfo,
    PreparedJournalCapture,
    RotationSkipInfo,
    SourceCoverage,
)
from sigwood.common.sources import (
    SyslogDecisionReason,
    SyslogProvider,
    arbitrate_syslog_capture,
    arbitrate_syslog_probe,
    resolve_analyze_sources,
)
from sigwood.common.syslog_mode import SyslogMode


def _config(path: Path, *, mode: str | None = "auto") -> dict:
    sigwood = {"root": "", "syslog_dir": str(path)}
    if mode is not None:
        sigwood["syslog_source"] = mode
    return {"sigwood": sigwood}


def _resolve(
    config: dict,
    *,
    source: object | None = None,
    path: object | None = None,
    scope: frozenset[str] | None = None,
    selected: bool = True,
):
    return resolve_analyze_sources(
        config,
        overrides={"syslog_dir": path},
        scope=scope,
        syslog_source=source,
        syslog_selected=selected,
    )


def _capture(
    path: Path,
    outcome: JournalCaptureOutcome,
    *,
    warnings: tuple[str, ...] = (),
) -> PreparedJournalCapture:
    return PreparedJournalCapture(
        capture_path=path,
        load_window=None,
        outcome=outcome,
        has_usable_rows=outcome is JournalCaptureOutcome.READY,
        warnings=warnings,
        reason_codes=(),
    )


def test_raw_mapping_without_mode_preserves_truthy_files_compat(tmp_path: Path) -> None:
    resolved = _resolve(_config(tmp_path, mode=None))
    assert resolved.syslog.mode is SyslogMode.FILES
    assert resolved.syslog.flat_paths == (tmp_path,)


def test_raw_mapping_with_builtin_key_is_auto(tmp_path: Path) -> None:
    resolved = _resolve(_config(tmp_path, mode="auto"))
    assert resolved.syslog.mode is SyslogMode.AUTO
    assert resolved.syslog.configured.legacy_migrated is False


def test_disk_omitted_mode_is_migrated_auto(tmp_path: Path) -> None:
    config = _config(tmp_path, mode="auto")
    config["__user_set__"] = {"sigwood": {"syslog_dir"}}
    resolved = _resolve(config)
    assert resolved.syslog.mode is SyslogMode.AUTO
    assert resolved.syslog.configured.legacy_migrated is True


def test_explicit_auto_does_not_claim_legacy_migration(tmp_path: Path) -> None:
    config = _config(tmp_path, mode="auto")
    config["__user_set__"] = {"sigwood": {"syslog_dir"}}
    intent = _resolve(config, source="auto").syslog
    decision = arbitrate_syslog_capture(
        intent,
        capture=_capture(tmp_path / "capture", JournalCaptureOutcome.READY),
    )
    assert decision.provider is SyslogProvider.JOURNAL
    assert decision.legacy_migrated is False


def test_disk_explicit_empty_dir_without_mode_is_off(tmp_path: Path) -> None:
    config = _config(tmp_path, mode="auto")
    config["sigwood"]["syslog_dir"] = ""
    config["__user_set__"] = {"sigwood": {"syslog_dir"}}
    resolved = _resolve(config)
    assert resolved.syslog.mode is SyslogMode.OFF
    assert resolved.syslog.flat_paths == ()


def test_explicit_path_overrides_configured_off(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit"
    resolved = _resolve(_config(tmp_path, mode="off"), path=explicit)
    assert resolved.syslog.mode is SyslogMode.FILES
    assert resolved.syslog.explicit_path is True
    assert resolved.syslog.flat_paths == (explicit,)


@pytest.mark.parametrize("mode", ["journal", "off"])
def test_explicit_forced_mode_conflicts_with_explicit_path(
    tmp_path: Path, mode: str
) -> None:
    with pytest.raises(ValueError, match="conflicts with an explicit syslog path"):
        _resolve(_config(tmp_path), source=mode, path=tmp_path / "explicit")


def test_config_auto_does_not_widen_zeek_positional_scope(tmp_path: Path) -> None:
    resolved = _resolve(_config(tmp_path), scope=frozenset({"zeek_dir"}))
    assert resolved.syslog.local_lane_eligible is False
    assert resolved.syslog.flat_paths == ()
    assert "syslog_dir" not in resolved.syslog.adjusted_scope


@pytest.mark.parametrize("mode", ["auto", "journal", "files"])
def test_explicit_mode_widens_before_single_path_resolution(
    tmp_path: Path, mode: str
) -> None:
    resolved = _resolve(
        _config(tmp_path), source=mode, scope=frozenset({"zeek_dir"})
    )
    assert resolved.syslog.local_lane_eligible is True
    assert resolved.syslog.flat_paths == (tmp_path,)
    assert "syslog_dir" in resolved.syslog.adjusted_scope


def test_explicit_off_does_not_widen_scoped_run(tmp_path: Path) -> None:
    resolved = _resolve(
        _config(tmp_path), source="off", scope=frozenset({"zeek_dir"})
    )
    assert resolved.syslog.report_local_lane is False
    assert resolved.syslog.flat_paths == ()


@pytest.mark.parametrize("mode", ["auto", "journal", "files"])
def test_explicit_active_mode_requires_syslog_selection(
    tmp_path: Path, mode: str
) -> None:
    with pytest.raises(ValueError, match="requires the syslog detector"):
        _resolve(_config(tmp_path), source=mode, selected=False)


def test_explicit_off_is_legal_without_syslog_selection(tmp_path: Path) -> None:
    resolved = _resolve(_config(tmp_path), source="off", selected=False)
    assert resolved.syslog.syslog_selected is False


def test_auto_ready_selects_journal_and_never_files(tmp_path: Path) -> None:
    intent = _resolve(_config(tmp_path)).syslog
    decision = arbitrate_syslog_capture(
        intent,
        capture=_capture(tmp_path / "capture", JournalCaptureOutcome.READY),
    )
    assert decision.provider is SyslogProvider.JOURNAL
    assert decision.reason is SyslogDecisionReason.AUTO_JOURNAL


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (JournalCaptureOutcome.CLEAN_EMPTY, SyslogDecisionReason.AUTO_CLEAN_EMPTY),
        (JournalCaptureOutcome.NO_USABLE, SyslogDecisionReason.AUTO_NO_USABLE),
    ],
)
def test_auto_unsuitable_capture_selects_files(
    tmp_path: Path,
    outcome: JournalCaptureOutcome,
    reason: SyslogDecisionReason,
) -> None:
    intent = _resolve(_config(tmp_path)).syslog
    decision = arbitrate_syslog_capture(
        intent, capture=_capture(tmp_path / "capture", outcome)
    )
    assert decision.provider is SyslogProvider.FILES
    assert decision.reason is reason


def test_auto_missing_is_neutral_but_spawn_failure_has_diagnostic(tmp_path: Path) -> None:
    intent = _resolve(_config(tmp_path)).syslog
    missing = arbitrate_syslog_capture(
        intent, error=JournalExecutableMissingError("journalctl not found")
    )
    failed = arbitrate_syslog_capture(
        intent, error=JournalProcessError("journalctl failed - denied")
    )
    assert missing.reason is SyslogDecisionReason.AUTO_MISSING
    assert missing.diagnostic is None
    assert failed.reason is SyslogDecisionReason.AUTO_FAILURE
    assert failed.diagnostic == "journalctl failed - denied"


def test_forced_journal_propagates_declared_failure(tmp_path: Path) -> None:
    intent = _resolve(_config(tmp_path), source="journal").syslog
    error = JournalProcessError("journalctl failed")
    with pytest.raises(JournalProcessError) as caught:
        arbitrate_syslog_capture(intent, error=error)
    assert caught.value is error


@pytest.mark.parametrize(
    "outcome",
    [JournalCaptureOutcome.CLEAN_EMPTY, JournalCaptureOutcome.NO_USABLE],
)
def test_forced_journal_retains_successful_empty_outcome(
    tmp_path: Path,
    outcome: JournalCaptureOutcome,
) -> None:
    intent = _resolve(_config(tmp_path), source="journal").syslog
    decision = arbitrate_syslog_capture(
        intent, capture=_capture(tmp_path / "capture", outcome)
    )
    assert decision.provider is SyslogProvider.JOURNAL
    assert decision.capture_outcome is outcome


def test_auto_probe_ready_is_virtual_candidate(tmp_path: Path) -> None:
    intent = _resolve(_config(tmp_path)).syslog
    decision = arbitrate_syslog_probe(
        intent, JournalProbeResult(JournalProbeCode.READY)
    )
    assert decision.provider is SyslogProvider.JOURNAL
    assert decision.virtual_sources == frozenset({("journal", "*.log*")})


def test_auto_probe_failure_sanitizes_and_caps_child_detail(tmp_path: Path) -> None:
    intent = _resolve(_config(tmp_path)).syslog
    result = JournalProbeResult(
        JournalProbeCode.EXIT_NONZERO,
        stderr=(b"denied\x1b[31m" + b"x" * 800 + b"\nignored"),
        returncode=1,
    )
    decision = arbitrate_syslog_probe(intent, result)
    assert decision.reason is SyslogDecisionReason.PROBE_AUTO_FAILURE
    assert decision.diagnostic is not None
    assert "\x1b" not in decision.diagnostic
    assert "ignored" not in decision.diagnostic
    assert len(decision.diagnostic) <= 512


def test_forced_probe_failure_raises_actionable_error(tmp_path: Path) -> None:
    intent = _resolve(_config(tmp_path), source="journal").syslog
    with pytest.raises(JournalProcessError, match=r"journalctl failed \(exit 7\)"):
        arbitrate_syslog_probe(
            intent,
            JournalProbeResult(
                JournalProbeCode.EXIT_NONZERO,
                stderr=b"permission denied",
                returncode=7,
            ),
        )


def test_virtual_journal_capability_satisfies_plan_without_fake_path() -> None:
    detector = SimpleNamespace(
        REQUIRED_LOGS=[],
        OPTIONAL_LOGS=[{"source": "journal", "pattern": "*.log*"}],
        REQUIRES_ONE_OF_OPTIONAL=True,
        REQUIRES_ONE_OF_OPTIONAL_REASON="no source",
    )
    selection = runner.DetectorSelection({"syslog": detector}, ["syslog"], {})
    plan = runner.build_run_plan(
        "syslog",
        selection=selection,
        virtual_sources=frozenset({("journal", "*.log*")}),
    )
    assert plan.will_run == ["syslog"]
    assert plan.needed_logs == {"*.log*": "journal"}


def test_different_source_same_pattern_collision_fails_actionably(
    tmp_path: Path,
) -> None:
    flat = tmp_path / "messages"
    flat.write_text(
        "Jun  6 12:00:00 host.example sshd[1]: placeholder\n",
        encoding="utf-8",
    )
    detector = SimpleNamespace(
        REQUIRED_LOGS=[],
        OPTIONAL_LOGS=[
            {"source": "syslog_dir", "pattern": "*.log*"},
            {"source": "journal", "pattern": "*.log*"},
        ],
        REQUIRES_ONE_OF_OPTIONAL=True,
        REQUIRES_ONE_OF_OPTIONAL_REASON="no source",
    )
    selection = runner.DetectorSelection({"syslog": detector}, ["syslog"], {})
    with pytest.raises(
        ValueError,
        match=r"pattern '\*\.log\*' is claimed by both syslog_dir and journal",
    ):
        runner.build_run_plan(
            "syslog",
            syslog_dir=flat,
            selection=selection,
            virtual_sources=frozenset({("journal", "*.log*")}),
        )


def test_same_source_pattern_claims_dedupe(tmp_path: Path) -> None:
    conn = tmp_path / "conn.log"
    conn.write_text(
        '{"_path":"conn","ts":1717675200.0,"uid":"C1",'
        '"id.orig_h":"192.0.2.10","id.orig_p":50000,'
        '"id.resp_h":"198.51.100.20","id.resp_p":443,"proto":"tcp"}\n',
        encoding="utf-8",
    )
    detector = SimpleNamespace(
        REQUIRED_LOGS=[{"source": "zeek_dir", "pattern": "conn*.log*"}],
        OPTIONAL_LOGS=[],
    )
    selection = runner.DetectorSelection(
        {"beacon": detector, "scan": detector},
        ["beacon", "scan"],
        {},
    )
    plan = runner.build_run_plan(
        "beacon,scan", zeek_dir=conn, selection=selection
    )
    assert plan.needed_logs == {"conn*.log*": "zeek_dir"}


def test_provider_path_disclosure_is_control_safe_and_bounded() -> None:
    paths = tuple(
        Path(f"/placeholder/path-{index}\x1b[31m")
        for index in range(5)
    )
    rendered = runner._compact_syslog_paths(paths)
    assert "\x1b" not in rendered
    assert "path-0[31m" in rendered
    assert "path-2[31m" in rendered
    assert "path-3" not in rendered
    assert rendered.endswith("(+2 more)")


# Cross-feed arbitration -----------------------------------------------------

_EVENT_DT = datetime(2026, 7, 21, 12, 0, 0, tzinfo=timezone.utc)
_EVENT_TS = _EVENT_DT.timestamp()


def _frame(hosts: list[object]) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "ts": [_EVENT_TS + index for index in range(len(hosts))],
            "host": hosts,
            "program": ["sshd"] * len(hosts),
            "raw": [f"sshd[{index + 1}]: placeholder" for index in range(len(hosts))],
            "message": [f"sshd: placeholder {index + 1}" for index in range(len(hosts))],
        }
    )


def _result(
    *, local: pd.DataFrame | None = None, zeek: pd.DataFrame | None = None
) -> LoadResult:
    logs: dict[str, pd.DataFrame] = {}
    if local is not None:
        logs["*.log*"] = local
    if zeek is not None:
        logs["syslog*.log*"] = zeek
    return LoadResult(
        logs=logs,
        record_counts={name: len(frame) for name, frame in logs.items()},
    )


def test_cross_feed_arbitration_drops_only_folded_local_hosts() -> None:
    load_result = _result(
        local=_frame(["Router", "unknown", float("nan")]),
        zeek=_frame(["router", "zeek-only", "unknown", float("nan")]),
    )

    arbitrated, facts = runner._arbitrate_cross_feed_syslog(load_result)

    assert facts == (2, 2)
    assert arbitrated is not load_result
    assert arbitrated.logs is not load_result.logs
    assert arbitrated.logs["*.log*"] is load_result.logs["*.log*"]
    assert arbitrated.logs["syslog*.log*"]["host"].tolist() == [
        "zeek-only",
        "unknown",
    ]


@pytest.mark.parametrize(
    "case",
    [
        "absent-local",
        "empty-local",
        "unknown-only-local",
        "absent-zeek",
        "empty-zeek",
        "local-without-host",
        "zeek-without-host",
        "zero-overlap",
    ],
)
def test_cross_feed_arbitration_noop_preserves_identity(case: str) -> None:
    local: pd.DataFrame | None = _frame(["local-only"])
    zeek: pd.DataFrame | None = _frame(["zeek-only"])
    if case == "absent-local":
        local = None
    elif case == "empty-local":
        local = _frame([])
    elif case == "unknown-only-local":
        local = _frame(["unknown"])
    elif case == "absent-zeek":
        zeek = None
    elif case == "empty-zeek":
        zeek = _frame([])
    elif case == "local-without-host":
        local = _frame(["local-only"]).drop(columns=["host"])
    elif case == "zeek-without-host":
        zeek = _frame(["zeek-only"]).drop(columns=["host"])

    load_result = _result(local=local, zeek=zeek)
    arbitrated, facts = runner._arbitrate_cross_feed_syslog(load_result)

    assert arbitrated is load_result
    assert facts is None


def test_cross_feed_arbitration_empty_result_retains_columns() -> None:
    zeek = _frame(["router", "ROUTER"])
    load_result = _result(local=_frame(["Router"]), zeek=zeek)

    arbitrated, facts = runner._arbitrate_cross_feed_syslog(load_result)

    assert facts == (1, 2)
    assert arbitrated.logs["syslog*.log*"].empty
    assert list(arbitrated.logs["syslog*.log*"].columns) == list(zeek.columns)


def test_cross_feed_arbitration_replace_preserves_loader_metadata() -> None:
    window = (_EVENT_DT, _EVENT_DT)
    record_counts = {"*.log*": 1, "syslog*.log*": 1}
    warnings = ["placeholder warning"]
    coverage = {"*.log*": SourceCoverage(2, window)}
    rotation_skips = {
        "*.log*": RotationSkipInfo(loaded=2, skipped=1, fallback=False)
    }
    permission_skips = {
        "*.log*": PermissionSkipInfo(discovered=2, denied=1)
    }
    load_result = LoadResult(
        logs={"*.log*": _frame(["router"]), "syslog*.log*": _frame(["router"])},
        record_counts=record_counts,
        data_window=window,
        warnings=warnings,
        data_size_bytes=1234,
        coverage=coverage,
        rotation_skips=rotation_skips,
        permission_skips=permission_skips,
    )

    arbitrated, facts = runner._arbitrate_cross_feed_syslog(load_result)

    assert facts == (1, 1)
    assert arbitrated.record_counts is record_counts
    assert arbitrated.data_window is window
    assert arbitrated.warnings is warnings
    assert arbitrated.data_size_bytes == 1234
    assert arbitrated.coverage is coverage
    assert arbitrated.rotation_skips is rotation_skips
    assert arbitrated.permission_skips is permission_skips


def _syslog_line(
    host: str,
    message: str,
    *,
    program: str = "sshd",
    pid: int = 101,
) -> str:
    return f"Jul 21 12:00:00 {host} {program}[{pid}]: {message}"


def _zeek_record(line: str, *, uid: str, ts: float = _EVENT_TS) -> dict:
    return {
        "_path": "syslog",
        "ts": ts,
        "uid": uid,
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 40001,
        "id.resp_h": "198.51.100.20",
        "id.resp_p": 514,
        "proto": "udp",
        "facility": "DAEMON",
        "severity": "INFO",
        "message": line,
    }


def _write_feeds(
    root: Path,
    *,
    local_lines: list[str],
    zeek_lines: list[str],
    host_pattern: str | None = None,
) -> tuple[dict, Path, Path]:
    flat = root / "flat"
    flat.mkdir(parents=True)
    (flat / "system.log").write_text(
        "".join(f"{line}\n" for line in local_lines), encoding="utf-8"
    )
    zeek = root / "zeek"
    zeek.mkdir()
    if zeek_lines:
        (zeek / "syslog.log").write_text(
            "".join(
                json.dumps(_zeek_record(line, uid=f"C{index + 1}")) + "\n"
                for index, line in enumerate(zeek_lines)
            ),
            encoding="utf-8",
        )
    allowlist_dir = root / "allowlist.d"
    allowlist_dir.mkdir()
    if host_pattern is not None:
        (allowlist_dir / "hosts").write_text(host_pattern + "\n", encoding="utf-8")
    config = {
        "sigwood": {"root": str(root), "default_window": ""},
        "allowlist": {
            "enabled": host_pattern is not None,
            "allowlist_dir": str(allowlist_dir),
            "domain_patterns": [],
            "connection_rules": [],
        },
    }
    return config, flat, zeek


def _run_json(
    capsys,
    config: dict,
    flat: Path | None,
    zeek: Path,
    *,
    source: str = "files",
) -> dict:
    assert runner.run(
        config,
        detect="syslog",
        syslog_dir=flat,
        zeek_dir=zeek,
        syslog_source=source,
        output_format="json",
        load_all=True,
        quiet=True,
    ) == 0
    return json.loads(capsys.readouterr().out)


def _run_text(capsys, config: dict, flat: Path, zeek: Path) -> str:
    assert runner.run(
        config,
        detect="syslog",
        syslog_dir=flat,
        zeek_dir=zeek,
        syslog_source="files",
        load_all=True,
        quiet=True,
    ) == 0
    return capsys.readouterr().out


def _stable_findings(payload: dict) -> list[dict]:
    findings = json.loads(json.dumps(payload["findings"]))
    for finding in findings:
        finding.pop("ts_generated")
    return findings


def _text_finding_section(rendered: str) -> str:
    marker = "\nsyslog - "
    return rendered[rendered.index(marker) + 1 :]


def test_cross_feed_singleton_recovery_converges_with_flat_only(
    tmp_path: Path, capsys,
) -> None:
    line = _syslog_line("router-a", "authentication placeholder alpha")
    both_cfg, both_flat, both_zeek = _write_feeds(
        tmp_path / "both", local_lines=[line], zeek_lines=[line]
    )
    flat_cfg, flat_flat, flat_zeek = _write_feeds(
        tmp_path / "flat-only", local_lines=[line], zeek_lines=[]
    )

    both_json = _run_json(capsys, both_cfg, both_flat, both_zeek)
    flat_json = _run_json(capsys, flat_cfg, flat_flat, flat_zeek)

    assert len(both_json["findings"]) == 1
    assert _stable_findings(both_json) == _stable_findings(flat_json)
    note = (
        "system logs: 1 host carried by both the local feed and Zeek syslog.log - "
        "kept the local rows (1 Zeek row set aside)"
    )
    assert note in both_json["run_summary"]["notes"]
    assert note not in flat_json["run_summary"]["notes"]
    assert both_json["run_summary"]["record_counts"] == {
        "*.log*": 1,
        "syslog*.log*": 1,
    }
    assert flat_json["run_summary"]["record_counts"] == {"*.log*": 1}

    both_text = _run_text(capsys, both_cfg, both_flat, both_zeek)
    flat_text = _run_text(capsys, flat_cfg, flat_flat, flat_zeek)
    assert note in " ".join(both_text.split())
    assert note not in " ".join(flat_text.split())
    assert _text_finding_section(both_text) == _text_finding_section(flat_text)


def test_cross_feed_note_renders_through_html(tmp_path: Path, capsys) -> None:
    line = _syslog_line("router-a", "authentication placeholder alpha")
    config, flat, zeek = _write_feeds(
        tmp_path, local_lines=[line], zeek_lines=[line]
    )
    assert runner.run(
        config,
        detect="syslog",
        syslog_dir=flat,
        zeek_dir=zeek,
        syslog_source="files",
        output_format="html",
        load_all=True,
        quiet=True,
    ) == 0
    rendered = capsys.readouterr().out
    assert (
        "system logs: 1 host carried by both the local feed and Zeek syslog.log - "
        "kept the local rows (1 Zeek row set aside)"
    ) in rendered


def test_cross_feed_note_plural_and_zero_overlap(tmp_path: Path, capsys) -> None:
    alpha = _syslog_line("router-a", "authentication placeholder alpha")
    beta = _syslog_line("router-b", "authentication placeholder beta", pid=102)
    plural_cfg, plural_flat, plural_zeek = _write_feeds(
        tmp_path / "plural",
        local_lines=[alpha, beta],
        zeek_lines=[alpha, beta, beta],
    )
    plural = _run_json(capsys, plural_cfg, plural_flat, plural_zeek)
    assert (
        "system logs: 2 hosts carried by both the local feed and Zeek syslog.log - "
        "kept the local rows (3 Zeek rows set aside)"
    ) in plural["run_summary"]["notes"]
    assert plural["run_summary"]["record_counts"] == {
        "*.log*": 2,
        "syslog*.log*": 3,
    }

    local = _syslog_line("router-a", "authentication placeholder alpha")
    zeek_only = _syslog_line("router-c", "authentication placeholder gamma")
    zero_cfg, zero_flat, zero_zeek = _write_feeds(
        tmp_path / "zero", local_lines=[local], zeek_lines=[zeek_only]
    )
    zero = _run_json(capsys, zero_cfg, zero_flat, zero_zeek)
    assert not any(
        "carried by both the local feed and Zeek syslog.log" in note
        for note in zero["run_summary"]["notes"]
    )


def test_zeek_only_findings_unchanged_and_local_lane_off(
    tmp_path: Path, capsys, monkeypatch,
) -> None:
    line = _syslog_line("router-z", "authentication placeholder zeta")
    config, flat, zeek = _write_feeds(
        tmp_path, local_lines=[], zeek_lines=[line]
    )
    normal = _run_json(capsys, config, None, zeek, source="off")

    monkeypatch.setattr(
        runner,
        "_arbitrate_cross_feed_syslog",
        lambda load_result: (load_result, None),
    )
    baseline = _run_json(capsys, config, None, zeek, source="off")

    assert _stable_findings(normal) == _stable_findings(baseline)
    assert normal["run_summary"]["record_counts"] == {"syslog*.log*": 1}
    assert not any(
        "carried by both" in note for note in normal["run_summary"]["notes"]
    )


def test_allowlist_host_total_uses_arbitrated_frames(tmp_path: Path, capsys) -> None:
    shared = _syslog_line("shared-a", "authentication placeholder alpha")
    zeek_only = _syslog_line("zeek-only", "authentication placeholder beta", pid=102)
    config, flat, zeek = _write_feeds(
        tmp_path,
        local_lines=[shared],
        zeek_lines=[shared, zeek_only],
        host_pattern="shared-*",
    )

    payload = _run_json(capsys, config, flat, zeek)
    suppression = payload["run_summary"]["suppression"]

    assert suppression["host_total"] == 2
    assert suppression["host_rows"] == 1
    assert suppression["hosts_matched"] == 1


def test_cross_feed_reboot_keeps_one_local_signal(tmp_path: Path, capsys) -> None:
    local = _syslog_line(
        "Router-A",
        "System is rebooting.",
        program="systemd-logind",
        pid=1,
    )
    zeek_copy = _syslog_line(
        "router-a",
        "System is rebooting.",
        program="systemd-logind",
        pid=1,
    )
    config, flat, zeek = _write_feeds(
        tmp_path, local_lines=[local], zeek_lines=[zeek_copy]
    )

    payload = _run_json(capsys, config, flat, zeek)
    reboots = [
        finding
        for finding in payload["findings"]
        if finding["evidence"].get("tier") == "reboot"
    ]

    assert len(reboots) == 1
    assert reboots[0]["evidence"]["signal_count"] == 1
    assert reboots[0]["evidence"]["host"] == "Router-A"
