"""Bounded stdlib journalctl probe and process-contract tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigwood.common import journal_probe
from sigwood.common.journal_probe import (
    MAX_JOURNAL_RECORD_BYTES,
    MAX_JOURNAL_STDERR_BYTES,
    JournalProbeCode,
)


def _executable(tmp_path: Path, body: str) -> str:
    path = tmp_path / "journalctl"
    path.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def test_probe_argv_environment_and_spawn_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(
        tmp_path,
        """
import json, os, sys
print(json.dumps({
  "__REALTIME_TIMESTAMP": "1700000000000000",
  "MESSAGE": "ok",
  "argv": sys.argv[1:],
  "env": {k: os.environ.get(k) for k in (
    "LC_ALL", "LANG", "SYSTEMD_COLORS", "SYSTEMD_LOG_COLOR",
    "SYSTEMD_PAGER", "HOME", "PATH", "XDG_RUNTIME_DIR",
    "SYSTEMD_LOG_LEVEL", "SYSTEMD_LOG_TARGET")},
}))
""",
    )
    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: executable)
    monkeypatch.setenv("SYSTEMD_LOG_LEVEL", "debug")
    monkeypatch.setenv("SYSTEMD_LOG_TARGET", "console")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/tmp/runtime-placeholder")

    calls: list[tuple[list[str], dict[str, object]]] = []
    real_popen = subprocess.Popen

    def recording_popen(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return real_popen(argv, **kwargs)

    monkeypatch.setattr(journal_probe.subprocess, "Popen", recording_popen)
    since = datetime(2026, 1, 1, 0, 0, 0, 100_000, tzinfo=timezone.utc)
    until = datetime(2026, 1, 1, 0, 0, 1, 100_000, tzinfo=timezone.utc)
    result = journal_probe.probe_journal(since=since, until=until)

    assert result.code is JournalProbeCode.READY
    record = json.loads(result.stdout)
    assert record["argv"] == [
        "--system",
        "--no-pager",
        "--output=json",
        "--all",
        "--output-fields=__REALTIME_TIMESTAMP,MESSAGE,_HOSTNAME,"
        "SYSLOG_IDENTIFIER,_COMM,_PID,SYSLOG_PID",
        "--since=@1767225600",
        "--until=@1767225602",
        "--lines=1",
    ]
    assert record["env"] | {
        "SYSTEMD_LOG_LEVEL": None,
        "SYSTEMD_LOG_TARGET": None,
    } == record["env"]
    assert record["env"]["LC_ALL"] == "C"
    assert record["env"]["SYSTEMD_PAGER"] == "cat"
    assert record["env"]["XDG_RUNTIME_DIR"] == "/tmp/runtime-placeholder"
    _, kwargs = calls[0]
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE
    assert kwargs["close_fds"] is True
    assert kwargs["start_new_session"] is True
    assert kwargs["shell"] is False


def test_probe_missing_empty_nonzero_and_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: None)
    assert journal_probe.probe_journal().code is JournalProbeCode.EXECUTABLE_MISSING

    empty = _executable(tmp_path, "pass")
    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: empty)
    assert journal_probe.probe_journal().code is JournalProbeCode.EMPTY

    failed = _executable(tmp_path, "import sys; print('denied', file=sys.stderr); sys.exit(7)")
    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: failed)
    result = journal_probe.probe_journal()
    assert result.code is JournalProbeCode.EXIT_NONZERO
    assert result.returncode == 7
    assert result.stdout == b""
    assert result.stderr == b"denied\n"

    signalled = _executable(tmp_path, "import os, signal; os.kill(os.getpid(), signal.SIGTERM)")
    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: signalled)
    result = journal_probe.probe_journal()
    assert result.code is JournalProbeCode.SIGNALLED
    assert result.returncode == -15


def test_resolver_returns_absolute_path_and_spawn_failure_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(tmp_path, "pass")
    monkeypatch.setattr(journal_probe.shutil, "which", lambda name: executable)
    assert journal_probe.resolve_journalctl() == str(Path(executable).resolve())

    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: executable)

    def fail_spawn(*args, **kwargs):
        del args, kwargs
        raise OSError("synthetic spawn failure")

    monkeypatch.setattr(journal_probe.subprocess, "Popen", fail_spawn)
    assert journal_probe.probe_journal().code is JournalProbeCode.SPAWN_FAILED


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            f"import sys; sys.stdout.buffer.write(b'x' * {MAX_JOURNAL_RECORD_BYTES + 1} + b'\\n')",
            JournalProbeCode.RECORD_TOO_LARGE,
        ),
        (
            "import sys; sys.stdout.buffer.write(b'{\\xff}\\n')",
            JournalProbeCode.INVALID_UTF8,
        ),
    ],
)
def test_probe_rejects_hostile_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
    expected: JournalProbeCode,
) -> None:
    executable = _executable(tmp_path, body)
    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: executable)
    result = journal_probe.probe_journal()
    assert result.code is expected
    assert result.stdout == b""


def test_probe_accepts_exact_record_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = b'{"__REALTIME_TIMESTAMP":"1","MESSAGE":"'
    suffix = b'"}'
    padding = MAX_JOURNAL_RECORD_BYTES - len(prefix) - len(suffix)
    body = (
        "import sys; "
        f"sys.stdout.buffer.write({prefix!r} + b'x' * {padding} + {suffix!r} + b'\\n')"
    )
    executable = _executable(tmp_path, body)
    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: executable)
    result = journal_probe.probe_journal()
    assert result.code is JournalProbeCode.READY
    assert len(result.stdout.rstrip(b"\n")) == MAX_JOURNAL_RECORD_BYTES


def test_probe_stderr_flood_is_drained_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(
        tmp_path,
        """
import json, sys
sys.stderr.buffer.write(b'w' * 200000)
print(json.dumps({"__REALTIME_TIMESTAMP":"1","MESSAGE":"ok"}))
""",
    )
    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: executable)
    result = journal_probe.probe_journal()
    assert result.code is JournalProbeCode.READY
    assert len(result.stderr) == MAX_JOURNAL_STDERR_BYTES
    assert result.stderr_truncated is True


def test_probe_keyboard_interrupt_terminates_and_reaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "pid"
    executable = _executable(
        tmp_path,
        f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)",
    )
    monkeypatch.setattr(journal_probe, "resolve_journalctl", lambda: executable)

    def interrupt_wait(proc, failure):
        del proc, failure
        deadline = time.monotonic() + 2
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_file.exists()
        raise KeyboardInterrupt

    monkeypatch.setattr(journal_probe, "_wait_for_process", interrupt_wait)
    with pytest.raises(KeyboardInterrupt):
        journal_probe.probe_journal()
    pid = int(pid_file.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_probe_module_is_stdlib_only() -> None:
    source = Path(journal_probe.__file__).read_text(encoding="utf-8")
    forbidden = ("sigwood.", "pandas", "loader", "runner", "detectors", "outputs")
    assert not any(f"import {name}" in source for name in forbidden)
    assert not any(f"from {name}" in source for name in forbidden)
