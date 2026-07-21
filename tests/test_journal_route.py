"""End-to-end system-journal intent, loader, detector, and render routes."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

import sigwood.cli as cli
import sigwood.common.loader as loader
from sigwood.common.loader import journal
from sigwood.detectors import syslog as syslog_detector


def _executable(tmp_path: Path, records: list[dict], stderr: str = "") -> str:
    path = tmp_path / "journalctl"
    body = (
        "import json, sys\n"
        f"records = {records!r}\n"
        "for record in records:\n"
        "    print(json.dumps(record))\n"
        f"sys.stderr.write({stderr!r})\n"
    )
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _record(message: str = "System is rebooting.") -> dict:
    return {
        "__REALTIME_TIMESTAMP": "1760000000000000",
        "MESSAGE": message,
        "_HOSTNAME": "host.example",
        "SYSLOG_IDENTIFIER": "systemd-logind",
        "_PID": "1",
    }


def _config(tmp_path: Path, flat: Path, *, mode: str | None) -> Path:
    path = tmp_path / f"config-{mode or 'legacy'}.toml"
    source_line = f'syslog_source = "{mode}"\n' if mode is not None else ""
    path.write_text(
        "[sigwood]\n"
        'root = ""\n'
        'detect = "syslog"\n'
        f'syslog_dir = "{flat}"\n'
        f"{source_line}"
        'zeek_dir = ""\n'
        'default_window = "7d"\n',
        encoding="utf-8",
    )
    return path


def _track_capture_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> list[Path]:
    created: list[Path] = []
    real_mkdtemp = journal.tempfile.mkdtemp

    def tracked_mkdtemp(*, prefix: str) -> str:
        path = Path(real_mkdtemp(prefix=prefix, dir=tmp_path))
        created.append(path)
        return str(path)

    monkeypatch.setattr(journal.tempfile, "mkdtemp", tracked_mkdtemp)
    real_run = syslog_detector.run

    def assert_clean_before_detector(context):
        assert created
        assert all(not path.exists() for path in created)
        assert journal._ACTIVE_CAPTURES == set()
        return real_run(context)

    monkeypatch.setattr(syslog_detector, "run", assert_clean_before_detector)
    return created


def test_forced_journal_real_route_reaches_text_and_json_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    executable = _executable(tmp_path, [_record()])
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: executable)
    created = _track_capture_cleanup(tmp_path, monkeypatch)
    config = _config(tmp_path, flat, mode="journal")

    text_path = tmp_path / "report.txt"
    assert cli._main([
        "syslog", f"--config={config}", "--syslog-source=journal", "--all",
        "--quiet", f"--out={text_path}",
    ]) == 0
    text = text_path.read_text(encoding="utf-8")
    assert "system logs: journal (explicit;" in text
    assert "host.example" in text

    json_path = tmp_path / "report.json"
    assert cli._main([
        "syslog", f"--config={config}", "--syslog-source=journal", "--all",
        "--quiet", "--format=json", f"--out={json_path}",
    ]) == 0
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    summary = payload["run_summary"]
    assert summary["record_counts"] == {"*.log*": 1}
    assert summary["data_size_bytes"] > 0
    assert summary["data_sources"] == ["syslog_journal"]
    assert sum(note.startswith("system logs:") for note in summary["notes"]) == 1
    assert payload["findings"][0]["evidence"]["tier"] == "reboot"
    assert len(created) == 2
    assert all(not path.exists() for path in created)
    assert journal._ACTIVE_CAPTURES == set()


def test_auto_ready_never_reads_flat_archive_for_comparison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "messages").write_text(
        "Jun  6 12:00:00 host.example sshd[2]: flat-only marker\n",
        encoding="utf-8",
    )
    executable = _executable(tmp_path, [_record("journal-only marker")])
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: executable)
    _track_capture_cleanup(tmp_path, monkeypatch)
    config = _config(tmp_path, flat, mode="auto")
    out = tmp_path / "auto.json"

    assert cli._main([
        "syslog", f"--config={config}", "--all", "--quiet", "--format=json",
        f"--out={out}",
    ]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    summary = payload["run_summary"]
    assert summary["record_counts"] == {"*.log*": 1}
    assert summary["data_sources"] == ["syslog_journal"]
    provider = next(n for n in summary["notes"] if n.startswith("system logs:"))
    assert "journal (auto;" in provider
    assert f"{flat} fallback not loaded" in provider
    assert "flat-only marker" not in out.read_text(encoding="utf-8")


def test_auto_missing_real_route_falls_back_to_flat_without_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "messages").write_text(
        "Jun  6 12:00:00 host.example sshd[2]: flat marker\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: None)
    config = _config(tmp_path, flat, mode="auto")
    out = tmp_path / "fallback.json"

    assert cli._main([
        "syslog", f"--config={config}", "--all", "--quiet", "--format=json",
        f"--out={out}",
    ]) == 0
    captured = capsys.readouterr()
    assert "system journal:" not in captured.err
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["run_summary"]["data_sources"] == ["syslog_raw"]
    provider = next(
        note for note in payload["run_summary"]["notes"]
        if note.startswith("system logs:")
    )
    assert "files" in provider
    assert "auto; journal unavailable" in provider


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        ([], "journal had no entries in the selected window"),
        (
            [{"__REALTIME_TIMESTAMP": "1760000000000000"}],
            "journal had no usable entries in the selected window",
        ),
    ],
)
def test_auto_unsuitable_journal_falls_back_to_flat_on_real_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    records: list[dict],
    expected: str,
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "messages").write_text(
        "Jun  6 12:00:00 host.example sshd[2]: flat marker\n",
        encoding="utf-8",
    )
    executable = _executable(tmp_path, records)
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: executable)
    config = _config(tmp_path, flat, mode="auto")
    out = tmp_path / "fallback-empty.json"

    assert cli._main([
        "syslog", f"--config={config}", "--all", "--quiet", "--format=json",
        f"--out={out}",
    ]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    summary = payload["run_summary"]
    assert summary["data_sources"] == ["syslog_raw"]
    provider = next(
        note for note in summary["notes"] if note.startswith("system logs:")
    )
    assert provider.startswith(f"system logs: files {flat} (auto;")
    assert expected in provider


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        ([], "journal had no entries in the selected window"),
        (
            [{"__REALTIME_TIMESTAMP": "1760000000000000"}],
            "journal had no usable entries in the selected window",
        ),
    ],
)
def test_forced_journal_keeps_empty_provider_and_discloses_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    records: list[dict],
    expected: str,
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    executable = _executable(tmp_path, records)
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: executable)
    config = _config(tmp_path, flat, mode="journal")
    out = tmp_path / "empty.json"

    assert cli._main([
        "syslog", f"--config={config}", "--syslog-source=journal", "--all",
        "--quiet", "--format=json", f"--out={out}",
    ]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    summary = payload["run_summary"]
    assert sum(summary["record_counts"].values()) == 0
    provider = next(
        note for note in summary["notes"] if note.startswith("system logs:")
    )
    assert provider.startswith("system logs: journal (explicit;")
    assert expected in provider
    assert "syslog_raw" not in summary["data_sources"]


def test_legacy_auto_migration_rider_appears_only_when_journal_wins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "messages").write_text(
        "Jun  6 12:00:00 host.example sshd[2]: flat marker\n",
        encoding="utf-8",
    )
    executable = _executable(tmp_path, [_record("journal marker")])
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: executable)
    config = _config(tmp_path, flat, mode=None)
    journal_out = tmp_path / "journal.json"

    assert cli._main([
        "syslog", f"--config={config}", "--all", "--quiet", "--format=json",
        f"--out={journal_out}",
    ]) == 0
    journal_payload = json.loads(journal_out.read_text(encoding="utf-8"))
    journal_note = next(
        note for note in journal_payload["run_summary"]["notes"]
        if note.startswith("system logs:")
    )
    assert "auto from legacy config" in journal_note
    assert 'set syslog_source="files" to keep file-only behavior' in journal_note

    monkeypatch.setattr(journal, "resolve_journalctl", lambda: None)
    files_out = tmp_path / "files.json"
    assert cli._main([
        "syslog", f"--config={config}", "--all", "--quiet", "--format=json",
        f"--out={files_out}",
    ]) == 0
    files_payload = json.loads(files_out.read_text(encoding="utf-8"))
    files_note = next(
        note for note in files_payload["run_summary"]["notes"]
        if note.startswith("system logs:")
    )
    assert "auto; journal unavailable" in files_note
    assert "legacy config" not in files_note


def test_auto_process_failure_warns_and_persists_fallback_reason_under_quiet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "messages").write_text(
        "Jun  6 12:00:00 host.example sshd[2]: flat marker\n",
        encoding="utf-8",
    )
    executable = tmp_path / "journalctl"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "sys.stderr.write('permission denied\\x1b[31m\\nforged\\n')\n"
        "raise SystemExit(7)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: str(executable))
    config = _config(tmp_path, flat, mode="auto")
    out = tmp_path / "fallback-failure.json"

    assert cli._main([
        "syslog", f"--config={config}", "--all", "--quiet", "--format=json",
        f"--out={out}",
    ]) == 0
    err = capsys.readouterr().err
    assert "system journal: journalctl failed (exit 7) - permission denied[31m" in err
    assert "\x1b" not in err
    payload = json.loads(out.read_text(encoding="utf-8"))
    provider = next(
        note for note in payload["run_summary"]["notes"]
        if note.startswith("system logs:")
    )
    assert "files" in provider
    assert "auto; journal unavailable - journalctl failed (exit 7)" in provider
    assert "\x1b" not in provider


def test_runner_injects_the_producer_window_by_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    executable = _executable(tmp_path, [_record("journal marker")])
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: executable)
    config = _config(tmp_path, flat, mode="journal")
    out = tmp_path / "window.json"
    real_resolve = loader.resolve_load_windows
    observed_identity: list[bool] = []

    def resolve_spy(*args, **kwargs):
        injected = kwargs["pre_resolved_windows"]["journal"]
        windows = real_resolve(*args, **kwargs)
        observed_identity.append(any(window is injected for window in windows))
        return windows

    monkeypatch.setattr(loader, "resolve_load_windows", resolve_spy)
    assert cli._main([
        "syslog", f"--config={config}", "--syslog-source=journal", "--quiet",
        "--format=json", f"--out={out}",
    ]) == 0
    assert observed_identity == [True]
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["run_summary"]["record_counts"] == {"*.log*": 1}


def test_journal_capture_keyboard_interrupt_reenters_cli_130_and_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    pid_file = tmp_path / "pid"
    executable = tmp_path / "journalctl"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import os, signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: str(executable))
    capture_dir = tmp_path / "capture"

    def fixed_mkdtemp(*, prefix: str) -> str:
        assert prefix == "sigwood-journal-"
        capture_dir.mkdir()
        return str(capture_dir)

    def interrupt_wait(proc, failure):
        del proc, failure
        deadline = time.monotonic() + 2
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_file.exists()
        raise KeyboardInterrupt

    monkeypatch.setattr(journal.tempfile, "mkdtemp", fixed_mkdtemp)
    monkeypatch.setattr(journal, "_wait_for_process", interrupt_wait)
    config = _config(tmp_path, tmp_path / "flat", mode="journal")

    with pytest.raises(SystemExit) as caught:
        cli.main([
            "syslog", f"--config={config}", "--syslog-source=journal", "--all",
            "--quiet",
        ])
    assert caught.value.code == 130
    captured = capsys.readouterr()
    assert captured.err == "Stopped.\n"
    assert "Traceback" not in captured.out + captured.err
    assert not capture_dir.exists()
    assert journal._ACTIVE_CAPTURES == set()
    pid = int(pid_file.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
