"""Public CLI system-log mode, conflict, scope, and dry-run tests."""

from __future__ import annotations

from pathlib import Path

import pytest

import sigwood.cli as cli
import sigwood.runner as runner
from sigwood.common import config as cfg
from sigwood.common import loader
from sigwood.common.journal_probe import JournalProbeCode, JournalProbeResult


_SYSLOG_LINE = "Jun  6 12:00:00 host.example sshd[1]: accepted placeholder\n"
_ZEEK_CONN = (
    '{"_path":"conn","ts":1717675200.0,"uid":"C1",'
    '"id.orig_h":"192.0.2.10","id.orig_p":50000,'
    '"id.resp_h":"198.51.100.20","id.resp_p":443,"proto":"tcp"}\n'
)


def _config(tmp_path: Path, syslog_dir: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        "[sigwood]\n"
        'root = ""\n'
        'detect = "all"\n'
        f'syslog_dir = "{syslog_dir}"\n'
        'syslog_source = "auto"\n'
        'zeek_dir = ""\n',
        encoding="utf-8",
    )
    return path


def _exit_one(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(argv)
    assert caught.value.code == 1


def test_flag_allowlist_is_hunt_and_syslog_only() -> None:
    assert "syslog_source" in cli._VERBS["hunt"].allowed
    assert "syslog_source" in cli._VERBS["syslog"].allowed
    for verb in (
        "beacon", "dns", "scan", "duration", "aws", "digest", "graph",
        "export", "init", "allowlist",
    ):
        assert "syslog_source" not in cli._VERBS[verb].allowed


def test_invalid_mode_is_public_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    _exit_one(["hunt", "--syslog-source=AUTO"])
    err = capsys.readouterr().err
    assert "sigwood: syslog_source must be one of" in err
    assert "run 'sigwood --help' for usage" in err


def test_known_flag_on_wrong_verb_is_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _exit_one(["dns", "--syslog-source=files"])
    err = capsys.readouterr().err
    assert "not valid for dns" in err
    assert "run 'sigwood --help' for usage" in err


def test_forced_journal_with_flat_positional_conflicts_before_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log = tmp_path / "messages"
    log.write_text(_SYSLOG_LINE, encoding="utf-8")
    config = _config(tmp_path, tmp_path)
    monkeypatch.setattr(
        runner,
        "probe_journal",
        lambda **_kwargs: pytest.fail("conflict must win before probing"),
    )
    _exit_one([
        "syslog", str(log), "--syslog-source=journal",
        f"--config={config}", "--dry-run",
    ])
    err = capsys.readouterr().err
    assert "cannot be combined with a syslog PATH or --syslog-dir" in err
    assert "run 'sigwood --help' for usage" in err


def test_explicit_active_mode_with_final_selection_excluding_syslog_is_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _exit_one(["hunt", "--detect=dns", "--syslog-source=files", "--dry-run"])
    err = capsys.readouterr().err
    assert "requires the syslog detector in the final selection" in err
    assert "run 'sigwood --help' for usage" in err


def test_explicit_off_is_legal_with_syslog_excluded_and_never_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.setattr(
        runner,
        "probe_journal",
        lambda **_kwargs: pytest.fail("off must not probe"),
    )
    assert cli._main([
        "hunt", "--detect=dns", "--syslog-source=off", "--dry-run",
    ]) == 0


def test_flag_only_implicit_hunt_counts_as_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.setattr(
        runner,
        "probe_journal",
        lambda **_kwargs: pytest.fail("off must not probe"),
    )
    assert cli._main(["--syslog-source=off", "--dry-run"]) == 0


def test_explicit_files_widens_zeek_positional_scope_before_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "messages").write_text(_SYSLOG_LINE, encoding="utf-8")
    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_CONN, encoding="utf-8")
    config = _config(tmp_path, flat)
    monkeypatch.setattr(
        runner,
        "probe_journal",
        lambda **_kwargs: pytest.fail("files must not probe"),
    )
    assert cli._main([
        "hunt", str(conn), "--detect=syslog", "--syslog-source=files",
        f"--config={config}", "--dry-run",
    ]) == 0
    out = capsys.readouterr().out
    assert f"files {flat} (explicit)" in out


def test_config_auto_does_not_probe_for_zeek_scoped_positional(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_CONN, encoding="utf-8")
    config = _config(tmp_path, tmp_path / "flat")
    monkeypatch.setattr(
        runner,
        "probe_journal",
        lambda **_kwargs: pytest.fail("config-only auto must not widen scope"),
    )
    assert cli._main([
        "hunt", str(conn), "--detect=syslog", f"--config={config}", "--dry-run",
    ]) == 0


def test_auto_missing_dry_run_falls_back_without_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "messages").write_text(_SYSLOG_LINE, encoding="utf-8")
    config = _config(tmp_path, flat)
    monkeypatch.setattr(
        runner,
        "probe_journal",
        lambda **_kwargs: JournalProbeResult(JournalProbeCode.EXECUTABLE_MISSING),
    )
    assert cli._main([
        "syslog", "--syslog-source=auto", f"--config={config}", "--dry-run",
    ]) == 0
    captured = capsys.readouterr()
    assert "auto fallback; journal unavailable" in captured.out
    assert "system journal:" not in captured.err


def test_auto_spawn_failure_warning_survives_quiet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _config(tmp_path, tmp_path / "flat")
    monkeypatch.setattr(
        runner,
        "probe_journal",
        lambda **_kwargs: JournalProbeResult(JournalProbeCode.SPAWN_FAILED),
    )
    assert cli._main([
        "syslog", "--syslog-source=auto", f"--config={config}", "--dry-run",
        "--quiet",
    ]) == 0
    err = capsys.readouterr().err
    assert "system journal: journalctl could not be started" in err


@pytest.mark.parametrize(
    ("mode", "provider_copy", "fallback_copy"),
    [
        ("journal", "journal (selected; query empty)", "system fallback:"),
        ("auto", "auto fallback; journal query empty", None),
    ],
)
def test_empty_dry_probe_preserves_forced_journal_and_auto_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    provider_copy: str,
    fallback_copy: str | None,
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "messages").write_text(_SYSLOG_LINE, encoding="utf-8")
    config = _config(tmp_path, flat)
    monkeypatch.setattr(
        runner,
        "probe_journal",
        lambda **_kwargs: JournalProbeResult(JournalProbeCode.EMPTY),
    )
    assert cli._main([
        "syslog", f"--syslog-source={mode}", f"--config={config}", "--dry-run",
    ]) == 0
    out = capsys.readouterr().out
    assert provider_copy in out
    if fallback_copy is not None:
        assert fallback_copy in out
    else:
        assert "system fallback:" not in out


def test_forced_journal_probe_failure_is_operational_not_usage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _config(tmp_path, tmp_path / "flat")
    monkeypatch.setattr(
        runner,
        "probe_journal",
        lambda **_kwargs: JournalProbeResult(JournalProbeCode.EXECUTABLE_MISSING),
    )
    _exit_one([
        "syslog", "--syslog-source=journal", f"--config={config}", "--dry-run",
    ])
    err = capsys.readouterr().err
    assert "sigwood: journalctl not found" in err
    assert "run 'sigwood --help' for usage" not in err


@pytest.mark.parametrize(
    ("mode", "provider_line"),
    [
        ("off", "system logs: local lane off"),
        ("files", "system logs: no eligible flat files found"),
    ],
)
def test_non_journal_modes_never_prepare_and_explain_combined_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    provider_line: str,
) -> None:
    config = _config(tmp_path, tmp_path / "missing-flat")
    monkeypatch.setattr(
        loader,
        "prepare_journal_capture",
        lambda **_kwargs: pytest.fail(f"{mode} must not prepare the journal"),
    )
    assert cli._main([
        "syslog", f"--syslog-source={mode}", f"--config={config}", "--quiet",
    ]) == 1
    err = capsys.readouterr().err
    assert provider_line in err
    skipped = "no syslog source found (need a readable system journal"
    assert skipped in err
    assert err.index(provider_line) < err.index(skipped)


def test_auto_failure_warning_precedes_fallback_and_combined_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _config(tmp_path, tmp_path / "missing-flat")

    def fail_capture(**_kwargs):
        raise loader.JournalProcessError("journalctl failed - permission denied")

    monkeypatch.setattr(loader, "prepare_journal_capture", fail_capture)
    assert cli._main([
        "syslog", "--syslog-source=auto", f"--config={config}", "--quiet",
    ]) == 1
    err = capsys.readouterr().err
    warning = "system journal: journalctl failed - permission denied"
    fallback = "system logs: no eligible flat files found"
    skipped = "no syslog source found (need a readable system journal"
    assert warning in err
    assert fallback in err
    assert skipped in err
    assert err.index(warning) < err.index(fallback) < err.index(skipped)
