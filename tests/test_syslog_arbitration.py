"""System-log intent, scope, provider, and dry-probe arbitration tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import sigwood.runner as runner

from sigwood.common.journal_probe import JournalProbeCode, JournalProbeResult
from sigwood.common.loader import (
    JournalCaptureOutcome,
    JournalExecutableMissingError,
    JournalProcessError,
    PreparedJournalCapture,
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
