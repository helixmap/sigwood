"""Bounded, read-only ``journalctl`` process contract and tail probe.

This module is a deliberately small stdlib-only leaf.  It owns executable
resolution, argv/environment construction, conservative native time bounds,
the receipt-timestamp scalar rule, bounded pipe draining, and process-group
cancellation.  It never prints and never creates project or capture files.
"""

from __future__ import annotations

import math
import os
import signal
import shutil
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import BinaryIO


MAX_JOURNAL_RECORD_BYTES = 1 << 20
MAX_JOURNAL_STDERR_BYTES = 64 << 10
MAX_JOURNAL_DIAGNOSTIC_CHARS = 512

_OUTPUT_FIELDS = (
    "__REALTIME_TIMESTAMP,MESSAGE,_HOSTNAME,SYSLOG_IDENTIFIER,"
    "_COMM,_PID,SYSLOG_PID"
)


class JournalProbeCode(str, Enum):
    """Tool-authored outcomes returned by :func:`probe_journal`."""

    READY = "ready"
    EMPTY = "empty"
    EXECUTABLE_MISSING = "executable_missing"
    SPAWN_FAILED = "spawn_failed"
    EXIT_NONZERO = "exit_nonzero"
    SIGNALLED = "signalled"
    INVALID_UTF8 = "invalid_utf8"
    RECORD_TOO_LARGE = "record_too_large"


@dataclass(frozen=True)
class JournalProbeResult:
    """Bounded result of a one-entry journal capability/tail probe."""

    code: JournalProbeCode
    stdout: bytes = b""
    stderr: bytes = b""
    returncode: int | None = None
    stderr_truncated: bool = False


def parse_receipt_timestamp(value: object) -> float | None:
    """Return journal receipt microseconds as epoch seconds when valid."""
    if not isinstance(value, str) or not value or not value.isascii():
        return None
    if any(ch < "0" or ch > "9" for ch in value):
        return None
    try:
        return int(value) / 1_000_000
    except (ValueError, OverflowError):
        return None


def resolve_journalctl() -> str | None:
    """Resolve ``journalctl`` once to an absolute executable path."""
    executable = shutil.which("journalctl")
    if executable is None:
        return None
    return str(Path(executable).resolve())


def _aware_epoch(value: datetime) -> float:
    """Convert an aware datetime to UTC epoch seconds."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("journal time bounds must be timezone-aware")
    return value.astimezone(timezone.utc).timestamp()


def build_journal_argv(
    executable: str,
    since: datetime | None,
    until: datetime | None,
    *,
    tail: bool,
) -> list[str]:
    """Build the fixed journalctl argv with conservative native bounds."""
    argv = [
        executable,
        "--system",
        "--no-pager",
        "--output=json",
        "--all",
        f"--output-fields={_OUTPUT_FIELDS}",
    ]
    if since is not None:
        argv.append(f"--since=@{math.floor(_aware_epoch(since))}")
    if until is not None:
        argv.append(f"--until=@{math.ceil(_aware_epoch(until))}")
    if tail:
        argv.append("--lines=1")
    return argv


def journal_environment() -> dict[str, str]:
    """Return the scrubbed environment used for every journalctl spawn."""
    env = dict(os.environ)
    env.pop("SYSTEMD_LOG_LEVEL", None)
    env.pop("SYSTEMD_LOG_TARGET", None)
    env.update(
        {
            "LC_ALL": "C",
            "LANG": "C",
            "SYSTEMD_COLORS": "0",
            "SYSTEMD_LOG_COLOR": "0",
            "SYSTEMD_PAGER": "cat",
        }
    )
    return env


class _StdoutDrain:
    """Bounded physical-record validator for the one-entry probe."""

    def __init__(self, failure: threading.Event) -> None:
        self.failure = failure
        self.code: JournalProbeCode | None = None
        self.read_error: OSError | None = None
        self.first_record: bytes | None = None
        self.records = 0

    def _record(self, payload: bytes, *, terminated: bool) -> None:
        self.records += 1
        if self.code is not None:
            return
        if len(payload) > MAX_JOURNAL_RECORD_BYTES:
            self.code = JournalProbeCode.RECORD_TOO_LARGE
            self.failure.set()
            return
        try:
            payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            self.code = JournalProbeCode.INVALID_UTF8
            self.failure.set()
            return
        if self.first_record is None:
            self.first_record = payload + (b"\n" if terminated else b"")

    def run(self, pipe: BinaryIO) -> None:
        record = bytearray()
        discarding = False
        try:
            while True:
                chunk = pipe.read(64 << 10)
                if not chunk:
                    break
                for byte in chunk:
                    if byte == 0x0A:
                        if discarding:
                            self.records += 1
                        else:
                            self._record(bytes(record), terminated=True)
                        record.clear()
                        discarding = False
                        continue
                    if discarding:
                        continue
                    if len(record) >= MAX_JOURNAL_RECORD_BYTES:
                        self.code = JournalProbeCode.RECORD_TOO_LARGE
                        self.failure.set()
                        record.clear()
                        discarding = True
                        continue
                    record.append(byte)
        except OSError as exc:
            self.read_error = exc
            self.failure.set()
            return
        if record or discarding:
            if discarding:
                self.records += 1
            else:
                self._record(bytes(record), terminated=False)


class _StderrDrain:
    """Retain a bounded stderr prefix while draining the entire pipe."""

    def __init__(self, failure: threading.Event | None = None) -> None:
        self.failure = failure
        self.data = bytearray()
        self.truncated = False
        self.read_error: OSError | None = None

    def run(self, pipe: BinaryIO) -> None:
        try:
            while True:
                chunk = pipe.read(64 << 10)
                if not chunk:
                    return
                remaining = MAX_JOURNAL_STDERR_BYTES - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.truncated = True
        except OSError as exc:
            self.read_error = exc
            if self.failure is not None:
                self.failure.set()


def terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    """Terminate, kill if necessary, and reap an isolated child group."""
    if proc.poll() is not None:
        proc.wait()
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=1.0)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait()


def _wait_for_process(
    proc: subprocess.Popen[bytes], failure: threading.Event
) -> bool:
    """Wait without a run timeout; return whether a worker caused shutdown."""
    parent_terminated = False
    while proc.poll() is None:
        if failure.is_set():
            parent_terminated = True
            terminate_process_group(proc)
            break
        try:
            proc.wait(timeout=0.05)
        except subprocess.TimeoutExpired:
            continue
    return parent_terminated


def _probe_with_executable(
    executable: str,
    since: datetime | None,
    until: datetime | None,
) -> JournalProbeResult:
    argv = build_journal_argv(executable, since, until, tail=True)
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            shell=False,
            env=journal_environment(),
        )
    except OSError:
        return JournalProbeResult(JournalProbeCode.SPAWN_FAILED)

    assert proc.stdout is not None and proc.stderr is not None
    failure = threading.Event()
    stdout_drain = _StdoutDrain(failure)
    stderr_drain = _StderrDrain(failure)
    stdout_thread = threading.Thread(
        target=stdout_drain.run, args=(proc.stdout,), name="journal-probe-stdout"
    )
    stderr_thread = threading.Thread(
        target=stderr_drain.run, args=(proc.stderr,), name="journal-probe-stderr"
    )
    stdout_thread.start()
    stderr_thread.start()
    interrupted = False
    parent_terminated = False
    try:
        parent_terminated = _wait_for_process(proc, failure)
    except KeyboardInterrupt:
        interrupted = True
        terminate_process_group(proc)
    finally:
        stdout_thread.join()
        stderr_thread.join()
        proc.stdout.close()
        proc.stderr.close()
        if proc.poll() is None:
            proc.wait()
    if interrupted:
        raise KeyboardInterrupt

    stderr = bytes(stderr_drain.data)
    rc = proc.returncode
    if parent_terminated and stdout_drain.code is not None:
        return JournalProbeResult(
            stdout_drain.code,
            stderr=stderr,
            returncode=rc,
            stderr_truncated=stderr_drain.truncated,
        )
    if parent_terminated and (
        stdout_drain.read_error is not None or stderr_drain.read_error is not None
    ):
        return JournalProbeResult(
            JournalProbeCode.SPAWN_FAILED,
            stderr=stderr,
            returncode=rc,
            stderr_truncated=stderr_drain.truncated,
        )
    if rc is not None and rc < 0:
        return JournalProbeResult(
            JournalProbeCode.SIGNALLED,
            stderr=stderr,
            returncode=rc,
            stderr_truncated=stderr_drain.truncated,
        )
    if rc:
        return JournalProbeResult(
            JournalProbeCode.EXIT_NONZERO,
            stderr=stderr,
            returncode=rc,
            stderr_truncated=stderr_drain.truncated,
        )
    if stdout_drain.read_error is not None or stderr_drain.read_error is not None:
        return JournalProbeResult(
            JournalProbeCode.SPAWN_FAILED,
            stderr=stderr,
            returncode=rc,
            stderr_truncated=stderr_drain.truncated,
        )
    if stdout_drain.code is not None:
        return JournalProbeResult(
            stdout_drain.code,
            stderr=stderr,
            returncode=rc,
            stderr_truncated=stderr_drain.truncated,
        )
    if stdout_drain.records == 0:
        return JournalProbeResult(
            JournalProbeCode.EMPTY,
            stderr=stderr,
            returncode=rc,
            stderr_truncated=stderr_drain.truncated,
        )
    return JournalProbeResult(
        JournalProbeCode.READY,
        stdout=stdout_drain.first_record or b"",
        stderr=stderr,
        returncode=rc,
        stderr_truncated=stderr_drain.truncated,
    )


def probe_journal(
    *, since: datetime | None = None, until: datetime | None = None
) -> JournalProbeResult:
    """Run a bounded one-entry system-journal probe without printing."""
    executable = resolve_journalctl()
    if executable is None:
        return JournalProbeResult(JournalProbeCode.EXECUTABLE_MISSING)
    return _probe_with_executable(executable, since, until)
