"""Loader-owned live system-journal producer and parser strategy."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import threading
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from sigwood.common.journal_probe import (
    MAX_JOURNAL_DIAGNOSTIC_CHARS,
    MAX_JOURNAL_RECORD_BYTES,
    JournalProbeCode,
    _StderrDrain,
    _probe_with_executable,
    _wait_for_process,
    build_journal_argv,
    journal_environment,
    resolve_journalctl,
    terminate_process_group,
)
from sigwood.common.loader.windowing import LoadWindow
from sigwood.common.sanitize import strip_control
from sigwood.parsers.journal import (
    JournalSkipReason,
    parse_receipt_from_record,
    parse_record,
)


class JournalError(ValueError):
    """Base for expected journal producer failures."""


class JournalUnavailableError(JournalError):
    """The fixed journalctl executable is missing or cannot be spawned."""


class JournalExecutableMissingError(JournalUnavailableError):
    """The fixed journalctl executable is absent from the executable path."""


class JournalProcessError(JournalError):
    """journalctl exited unsuccessfully or by an unexpected signal."""


class JournalProtocolError(JournalError):
    """journalctl emitted output outside the bounded JSON protocol."""


class JournalCaptureIOError(JournalError):
    """The private transient capture could not be created, written, or read."""


class JournalCaptureOutcome(str, Enum):
    """Usability outcome for a successfully prepared capture."""

    READY = "ready"
    CLEAN_EMPTY = "clean_empty"
    NO_USABLE = "no_usable"


@dataclass(frozen=True)
class PreparedJournalCapture:
    """Prepared loader input valid only inside its owning context manager."""

    capture_path: Path
    load_window: LoadWindow | None
    outcome: JournalCaptureOutcome
    has_usable_rows: bool
    warnings: tuple[str, ...]
    reason_codes: tuple[str, ...]


_ACTIVE_CAPTURES: set[Path] = set()
_ACTIVE_CAPTURES_LOCK = threading.Lock()

_SKIP_PHRASES = {
    JournalSkipReason.MALFORMED_JSON: "malformed JSON",
    JournalSkipReason.DUPLICATE_KEYS: "duplicate JSON keys",
    JournalSkipReason.NON_OBJECT: "non-object JSON",
    JournalSkipReason.MISSING_TIMESTAMP: "missing receipt timestamp",
    JournalSkipReason.INVALID_TIMESTAMP: "invalid receipt timestamp",
    JournalSkipReason.MISSING_MESSAGE: "missing MESSAGE",
    JournalSkipReason.INVALID_MESSAGE: "invalid MESSAGE",
}


def _resolved(path: Path) -> Path:
    return path.resolve()


def _register_capture(path: Path) -> None:
    with _ACTIVE_CAPTURES_LOCK:
        _ACTIVE_CAPTURES.add(_resolved(path))


def _unregister_capture(path: Path) -> None:
    with _ACTIVE_CAPTURES_LOCK:
        _ACTIVE_CAPTURES.discard(_resolved(path))


def _discover_journal_capture(
    path: Path,
    pattern: str,
    since: datetime | None,
    until: datetime | None,
) -> list[Path]:
    """Accept only an active capture created by this producer."""
    del pattern, since, until
    with _ACTIVE_CAPTURES_LOCK:
        trusted = _resolved(path) in _ACTIVE_CAPTURES
    if not trusted:
        raise ValueError("journal source requires an active loader capture")
    return [path]


def _journal_read_error(exc: BaseException) -> BaseException:
    """Translate generic file reads into the journal capture-I/O domain."""
    del exc
    return JournalCaptureIOError(
        "system journal capture could not be read - retry the run"
    )


def _journal_strategy_parse(
    line_iter: Any,
    *,
    path: Path,
    warnings: list[str] | None,
) -> Iterator[dict[str, object]]:
    """Adapt pure record parsing to the uniform stream loader contract."""
    del path
    skipped: Counter[JournalSkipReason] = Counter()
    for line in line_iter:
        parsed = parse_record(line)
        if isinstance(parsed, JournalSkipReason):
            skipped[parsed] += 1
            continue
        yield parsed
    if warnings is None:
        return
    for reason in JournalSkipReason:
        count = skipped.get(reason, 0)
        if not count:
            continue
        noun = "entry" if count == 1 else "entries"
        warnings.append(
            f"system journal: skipped {count} {noun} - {_SKIP_PHRASES[reason]}"
        )


def _diagnostic_lines(stderr: bytes) -> tuple[str, ...]:
    """Return a bounded, deduplicated, terminal-safe child diagnostic set."""
    decoded = stderr.decode("utf-8", errors="replace")
    seen: set[str] = set()
    lines: list[str] = []
    for raw in decoded.splitlines():
        clean = strip_control(raw).strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        lines.append(clean[:MAX_JOURNAL_DIAGNOSTIC_CHARS])
        if len(lines) == 8:
            break
    return tuple(lines)


def _failure_detail(stderr: bytes) -> str | None:
    lines = _diagnostic_lines(stderr)
    return lines[0] if lines else None


def _warnings_from_stderr(stderr: bytes) -> tuple[str, ...]:
    return tuple(f"journalctl: {line}" for line in _diagnostic_lines(stderr))


def _raise_probe_failure(code: JournalProbeCode, rc: int | None, stderr: bytes) -> None:
    detail = _failure_detail(stderr)
    if code is JournalProbeCode.EXECUTABLE_MISSING:
        raise JournalExecutableMissingError(
            "journalctl not found - install systemd journal tools or choose files"
        )
    if code is JournalProbeCode.SPAWN_FAILED:
        raise JournalUnavailableError("journalctl could not be started")
    if code is JournalProbeCode.SIGNALLED:
        signal_number = abs(rc or 0)
        raise JournalProcessError(
            f"journalctl terminated by signal {signal_number}"
        )
    if code is JournalProbeCode.EXIT_NONZERO:
        message = f"journalctl failed (exit {rc or 1})"
        if detail:
            message += f" - {detail}"
        raise JournalProcessError(message)
    if code is JournalProbeCode.INVALID_UTF8:
        raise JournalProtocolError("journalctl returned invalid UTF-8")
    if code is JournalProbeCode.RECORD_TOO_LARGE:
        raise JournalProtocolError("journalctl record exceeded 1 MiB")


class _CaptureStdoutDrain:
    """Validate and materialize bounded records while probing first usability."""

    def __init__(self, target: BinaryIO, failure: threading.Event) -> None:
        self.target = target
        self.failure = failure
        self.protocol_code: JournalProbeCode | None = None
        self.capture_error: BaseException | None = None
        self.records = 0
        self.has_usable = False
        self.skip_reasons: Counter[JournalSkipReason] = Counter()

    def _fail_protocol(self, code: JournalProbeCode) -> None:
        if self.protocol_code is None:
            self.protocol_code = code
            self.failure.set()

    def _write_record(self, payload: bytes, *, terminated: bool) -> None:
        self.records += 1
        if self.protocol_code is not None or self.capture_error is not None:
            return
        if len(payload) > MAX_JOURNAL_RECORD_BYTES:
            self._fail_protocol(JournalProbeCode.RECORD_TOO_LARGE)
            return
        try:
            decoded = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            self._fail_protocol(JournalProbeCode.INVALID_UTF8)
            return
        try:
            self.target.write(payload)
            if terminated:
                self.target.write(b"\n")
        except OSError as exc:
            self.capture_error = exc
            self.failure.set()
            return
        if self.has_usable:
            return
        parsed = parse_record(decoded)
        if isinstance(parsed, JournalSkipReason):
            self.skip_reasons[parsed] += 1
        else:
            self.has_usable = True

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
                            self._write_record(bytes(record), terminated=True)
                        record.clear()
                        discarding = False
                        continue
                    if discarding:
                        continue
                    if len(record) >= MAX_JOURNAL_RECORD_BYTES:
                        self._fail_protocol(JournalProbeCode.RECORD_TOO_LARGE)
                        record.clear()
                        discarding = True
                        continue
                    record.append(byte)
        except OSError as exc:
            self.capture_error = exc
            self.failure.set()
            return
        if record or discarding:
            if discarding:
                self.records += 1
            else:
                self._write_record(bytes(record), terminated=False)


@dataclass(frozen=True)
class _CaptureResult:
    records: int
    has_usable: bool
    skip_reasons: tuple[str, ...]
    stderr: bytes


def _capture_main(
    executable: str,
    since: datetime | None,
    until: datetime | None,
    target: BinaryIO,
) -> _CaptureResult:
    argv = build_journal_argv(executable, since, until, tail=False)
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
    except OSError as exc:
        raise JournalUnavailableError("journalctl could not be started") from exc

    assert proc.stdout is not None and proc.stderr is not None
    failure = threading.Event()
    stdout_drain = _CaptureStdoutDrain(target, failure)
    stderr_drain = _StderrDrain(failure)
    stdout_thread = threading.Thread(
        target=stdout_drain.run, args=(proc.stdout,), name="journal-capture-stdout"
    )
    stderr_thread = threading.Thread(
        target=stderr_drain.run, args=(proc.stderr,), name="journal-capture-stderr"
    )
    stdout_thread.start()
    stderr_thread.start()
    parent_terminated = False
    interrupted = False
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
    if parent_terminated:
        if (
            stdout_drain.capture_error is not None
            or stderr_drain.read_error is not None
        ):
            cause = stdout_drain.capture_error or stderr_drain.read_error
            raise JournalCaptureIOError(
                "system journal capture could not be written - "
                "check temporary storage space and retry"
            ) from cause
        if stdout_drain.protocol_code is JournalProbeCode.INVALID_UTF8:
            raise JournalProtocolError("journalctl returned invalid UTF-8")
        if stdout_drain.protocol_code is JournalProbeCode.RECORD_TOO_LARGE:
            raise JournalProtocolError("journalctl record exceeded 1 MiB")

    rc = proc.returncode
    if rc is not None and rc < 0:
        raise JournalProcessError(
            f"journalctl terminated by signal {abs(rc)}"
        )
    if rc:
        message = f"journalctl failed (exit {rc})"
        detail = _failure_detail(stderr)
        if detail:
            message += f" - {detail}"
        raise JournalProcessError(message)
    if stdout_drain.capture_error is not None or stderr_drain.read_error is not None:
        cause = stdout_drain.capture_error or stderr_drain.read_error
        raise JournalCaptureIOError(
            "system journal capture could not be written - "
            "check temporary storage space and retry"
        ) from cause
    if stdout_drain.protocol_code is JournalProbeCode.INVALID_UTF8:
        raise JournalProtocolError("journalctl returned invalid UTF-8")
    if stdout_drain.protocol_code is JournalProbeCode.RECORD_TOO_LARGE:
        raise JournalProtocolError("journalctl record exceeded 1 MiB")
    return _CaptureResult(
        records=stdout_drain.records,
        has_usable=stdout_drain.has_usable,
        skip_reasons=tuple(
            reason.value
            for reason in JournalSkipReason
            if stdout_drain.skip_reasons.get(reason, 0)
        ),
        stderr=stderr,
    )


def _create_capture() -> tuple[Path, Path, BinaryIO]:
    directory: Path | None = None
    path: Path | None = None
    fd: int | None = None
    try:
        directory = Path(tempfile.mkdtemp(prefix="sigwood-journal-"))
        os.chmod(directory, 0o700)
        if stat.S_IMODE(directory.stat().st_mode) != 0o700:
            raise OSError("private directory mode could not be set")
        path = directory / "system-journal.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(fd, 0o600)
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise OSError("private capture mode could not be set")
        stream = os.fdopen(fd, "wb")
        fd = None
        return directory, path, stream
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        if path is not None:
            try:
                path.unlink()
            except OSError:
                pass
        if directory is not None:
            try:
                directory.rmdir()
            except OSError:
                pass
        raise JournalCaptureIOError(
            "system journal capture could not be created - "
            "check temporary storage space and retry"
        ) from exc


@contextmanager
def prepare_journal_capture(
    *,
    since: datetime | None,
    until: datetime | None,
    default_span: timedelta | None,
) -> Iterator[PreparedJournalCapture]:
    """Prepare one private journal capture and remove it on every exit."""
    executable = resolve_journalctl()
    if executable is None:
        _raise_probe_failure(JournalProbeCode.EXECUTABLE_MISSING, None, b"")
        raise AssertionError("unreachable")

    load_window: LoadWindow | None = None
    probe_warnings: tuple[str, ...] = ()
    clean_empty = False
    main_since, main_until = since, until
    if since is None and until is None and default_span is not None:
        probe = _probe_with_executable(executable, None, None)
        if probe.code is JournalProbeCode.EMPTY:
            clean_empty = True
            probe_warnings = _warnings_from_stderr(probe.stderr)
        elif probe.code is JournalProbeCode.READY:
            anchor = parse_receipt_from_record(
                probe.stdout.decode("utf-8", errors="strict")
            )
            if anchor is None:
                raise JournalProtocolError(
                    "journal default window could not determine the newest entry - "
                    "use --all or an explicit --since"
                )
            try:
                anchor_dt = datetime.fromtimestamp(anchor, tz=timezone.utc)
                main_since = anchor_dt - default_span
            except (OverflowError, OSError, ValueError) as exc:
                raise JournalProtocolError(
                    "journal default window returned an unusable receipt timestamp - "
                    "use --all or an explicit --since"
                ) from exc
            main_until = anchor_dt
            load_window = LoadWindow(
                source="journal",
                select_window=(main_since, main_until),
                trim_span=None,
                keep_null=False,
            )
            probe_warnings = _warnings_from_stderr(probe.stderr)
        else:
            _raise_probe_failure(probe.code, probe.returncode, probe.stderr)

    directory: Path | None = None
    path: Path | None = None
    stream: BinaryIO | None = None
    registered = False
    try:
        directory, path, stream = _create_capture()
        if clean_empty:
            capture_result = _CaptureResult(0, False, (), b"")
        else:
            capture_result = _capture_main(
                executable, main_since, main_until, stream
            )
        try:
            stream.flush()
            stream.close()
            stream = None
        except OSError as exc:
            raise JournalCaptureIOError(
                "system journal capture could not be written - "
                "check temporary storage space and retry"
            ) from exc

        if clean_empty or capture_result.records == 0:
            outcome = JournalCaptureOutcome.CLEAN_EMPTY
            reason_codes = ("empty",)
        elif capture_result.has_usable:
            outcome = JournalCaptureOutcome.READY
            reason_codes = ()
        else:
            outcome = JournalCaptureOutcome.NO_USABLE
            reason_codes = capture_result.skip_reasons
        warnings = tuple(
            dict.fromkeys(
                (*probe_warnings, *_warnings_from_stderr(capture_result.stderr))
            )
        )
        _register_capture(path)
        registered = True
        yield PreparedJournalCapture(
            capture_path=path,
            load_window=load_window,
            outcome=outcome,
            has_usable_rows=capture_result.has_usable,
            warnings=warnings,
            reason_codes=reason_codes,
        )
    finally:
        active_error = sys.exc_info()[0] is not None
        cleanup_error: OSError | None = None
        if stream is not None:
            try:
                stream.close()
            except OSError as exc:
                cleanup_error = exc
        if path is not None:
            if registered:
                _unregister_capture(path)
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        if directory is not None:
            try:
                directory.rmdir()
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        if cleanup_error is not None and not active_error:
            raise JournalCaptureIOError(
                "system journal capture could not be removed - retry the run"
            ) from cleanup_error
