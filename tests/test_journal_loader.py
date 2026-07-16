"""Secure journal producer, registry, and generic-loader integration tests."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sigwood.common.loader as loader
from sigwood.common.journal_probe import MAX_JOURNAL_RECORD_BYTES
from sigwood.common.loader import journal


def _executable(tmp_path: Path, body: str) -> str:
    path = tmp_path / "journalctl"
    path.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _record(ts_us: int, message: object = "event", **fields: object) -> str:
    value: dict[str, object] = {
        "__REALTIME_TIMESTAMP": str(ts_us),
        "MESSAGE": message,
        "_HOSTNAME": "host.example",
        "SYSLOG_IDENTIFIER": "service",
        "_PID": "123",
    }
    value.update(fields)
    return json.dumps(value)


def _patch_executable(
    monkeypatch: pytest.MonkeyPatch, executable: str
) -> None:
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: executable)


def test_prepare_load_window_accounting_display_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchor_us = 1_700_000_000_000_000
    before = _record(anchor_us - 3_600_000_001, "before")
    inside = _record(anchor_us - 3_600_000_000, "inside")
    anchor = _record(anchor_us, "anchor")
    after = _record(anchor_us + 1, "after")
    executable = _executable(
        tmp_path,
        f"""
import sys
if "--lines=1" in sys.argv:
    print({anchor!r})
else:
    print({before!r}); print({inside!r}); print({anchor!r}); print({after!r})
""",
    )
    resolve_calls = 0

    def resolve_once():
        nonlocal resolve_calls
        resolve_calls += 1
        return executable

    monkeypatch.setattr(journal, "resolve_journalctl", resolve_once)

    descriptions: list[str] = []
    real_progress = loader.progress

    def progress_spy(iterable, **kwargs):
        descriptions.append(kwargs["desc"])
        return real_progress(iterable, **kwargs)

    monkeypatch.setattr(loader, "progress", progress_spy)
    capture_path: Path
    with loader.prepare_journal_capture(
        since=None, until=None, default_span=timedelta(hours=1)
    ) as prepared:
        capture_path = prepared.capture_path
        assert stat.S_IMODE(capture_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(capture_path.stat().st_mode) == 0o600
        assert prepared.outcome is loader.JournalCaptureOutcome.READY
        assert prepared.has_usable_rows is True
        assert prepared.load_window is not None
        windows = loader.resolve_load_windows(
            {"*.log*": "journal"},
            {"journal": [capture_path]},
            "1h",
            since=None,
            until=None,
            load_all=False,
            pre_resolved_windows={"journal": prepared.load_window},
        )
        assert windows[0] is prepared.load_window
        select_window = windows[0].select_window
        assert select_window is not None
        result = loader.load_required_logs(
            {"*.log*": "journal"},
            {"journal": [capture_path]},
            source_windows={"journal": select_window},
        )
        assert result.record_counts == {"*.log*": 2}
        assert result.logs["*.log*"]["raw"].tolist() == ["inside", "anchor"]
        assert result.data_window == select_window
        assert result.data_size_bytes == capture_path.stat().st_size
        assert result.rotation_skips == {}
        assert result.permission_skips == {}
        assert descriptions == ["loaded system journal"]
        assert resolve_calls == 1
    assert not capture_path.exists()
    assert not capture_path.parent.exists()


def test_clean_empty_probe_yields_registered_empty_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(tmp_path, "pass")
    _patch_executable(monkeypatch, executable)
    with loader.prepare_journal_capture(
        since=None, until=None, default_span=timedelta(days=1)
    ) as prepared:
        assert prepared.outcome is loader.JournalCaptureOutcome.CLEAN_EMPTY
        assert prepared.capture_path.stat().st_size == 0
        result = loader.load_required_logs(
            {"*.log*": "journal"}, {"journal": [prepared.capture_path]}
        )
        assert result.logs["*.log*"].empty
        assert result.record_counts == {}
        assert result.data_size_bytes == 0
        assert result.permission_skips == {}


def test_default_probe_entry_without_receipt_timestamp_is_protocol_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(
        tmp_path, "print('{\"MESSAGE\":\"missing receipt\"}')"
    )
    _patch_executable(monkeypatch, executable)
    with pytest.raises(loader.JournalProtocolError, match="could not determine"):
        with loader.prepare_journal_capture(
            since=None, until=None, default_span=timedelta(days=1)
        ):
            pass


def test_default_probe_out_of_range_receipt_is_protocol_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _record(int("1" + "0" * 100))
    executable = _executable(tmp_path, f"print({record!r})")
    _patch_executable(monkeypatch, executable)
    with pytest.raises(loader.JournalProtocolError, match="unusable receipt"):
        with loader.prepare_journal_capture(
            since=None, until=None, default_span=timedelta(days=1)
        ):
            pass


def test_entries_without_usable_rows_remain_typed_and_aggregate_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = json.dumps({"__REALTIME_TIMESTAMP": "1", "MESSAGE": None})
    executable = _executable(tmp_path, f"print({missing!r}); print({missing!r})")
    _patch_executable(monkeypatch, executable)
    with loader.prepare_journal_capture(
        since=None, until=None, default_span=None
    ) as prepared:
        assert prepared.outcome is loader.JournalCaptureOutcome.NO_USABLE
        assert prepared.reason_codes == ("missing_message",)
        result = loader.load_required_logs(
            {"*.log*": "journal"}, {"journal": [prepared.capture_path]}
        )
        assert result.logs["*.log*"].empty
        assert result.warnings == [
            "system journal: skipped 2 entries - missing MESSAGE"
        ]


def test_active_capture_registry_rejects_arbitrary_and_stale_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arbitrary = tmp_path / "system-journal.jsonl"
    arbitrary.write_text(_record(1), encoding="utf-8")
    with pytest.raises(ValueError, match="active loader capture"):
        loader._discover_journal_capture(arbitrary, "*.log*", None, None)

    executable = _executable(tmp_path, f"print({_record(1)!r})")
    _patch_executable(monkeypatch, executable)
    with loader.prepare_journal_capture(
        since=None, until=None, default_span=None
    ) as prepared:
        active = prepared.capture_path
        assert loader._discover_journal_capture(active, "*.log*", None, None) == [
            active
        ]
    with pytest.raises(ValueError, match="active loader capture"):
        loader._discover_journal_capture(active, "*.log*", None, None)


def test_read_back_open_failure_is_capture_io_not_permission_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(tmp_path, f"print({_record(1)!r})")
    _patch_executable(monkeypatch, executable)
    with loader.prepare_journal_capture(
        since=None, until=None, default_span=None
    ) as prepared:
        real_open = loader._open_log

        def denied(path):
            if path == prepared.capture_path:
                raise PermissionError("synthetic")
            return real_open(path)

        monkeypatch.setattr(loader, "_open_log", denied)
        with pytest.raises(loader.JournalCaptureIOError) as caught:
            loader.load_required_logs(
                {"*.log*": "journal"}, {"journal": [prepared.capture_path]}
            )
        assert str(prepared.capture_path) not in str(caught.value)
        assert "system-journal.jsonl" not in str(caught.value)


def test_nonzero_partial_stdout_and_protocol_failures_discard_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    partial = _record(1)
    executable = _executable(
        tmp_path, f"import sys; print({partial!r}); print('denied', file=sys.stderr); sys.exit(9)"
    )
    _patch_executable(monkeypatch, executable)
    with pytest.raises(loader.JournalProcessError, match=r"exit 9.*denied"):
        with loader.prepare_journal_capture(
            since=None, until=None, default_span=None
        ):
            pass

    executable = _executable(
        tmp_path, "import sys; sys.stdout.buffer.write(b'{\\xff}\\n')"
    )
    _patch_executable(monkeypatch, executable)
    with pytest.raises(loader.JournalProtocolError, match="invalid UTF-8"):
        with loader.prepare_journal_capture(
            since=None, until=None, default_span=None
        ):
            pass

    executable = _executable(
        tmp_path,
        "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
    )
    _patch_executable(monkeypatch, executable)
    with pytest.raises(loader.JournalProcessError, match="signal 15"):
        with loader.prepare_journal_capture(
            since=None, until=None, default_span=None
        ):
            pass


def test_main_capture_accepts_exact_record_ceiling_and_rejects_next_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = b'{"__REALTIME_TIMESTAMP":"1","MESSAGE":"'
    suffix = b'"}'
    padding = MAX_JOURNAL_RECORD_BYTES - len(prefix) - len(suffix)
    exact = _executable(
        tmp_path,
        "import sys; "
        f"sys.stdout.buffer.write({prefix!r} + b'x' * {padding} + "
        f"{suffix!r} + b'\\n')",
    )
    _patch_executable(monkeypatch, exact)
    with loader.prepare_journal_capture(
        since=None, until=None, default_span=None
    ) as prepared:
        assert prepared.outcome is loader.JournalCaptureOutcome.READY
        assert prepared.capture_path.stat().st_size == MAX_JOURNAL_RECORD_BYTES + 1

    too_large = _executable(
        tmp_path,
        "import sys; "
        f"sys.stdout.buffer.write({prefix!r} + b'x' * {padding + 1} + "
        f"{suffix!r} + b'\\n')",
    )
    _patch_executable(monkeypatch, too_large)
    with pytest.raises(loader.JournalProtocolError, match="exceeded 1 MiB"):
        with loader.prepare_journal_capture(
            since=None, until=None, default_span=None
        ):
            pass


def test_capture_creation_failure_is_typed_and_path_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(tmp_path, f"print({_record(1)!r})")
    _patch_executable(monkeypatch, executable)

    def fail_create(*, prefix):
        del prefix
        raise OSError(f"cannot create under {tmp_path}")

    monkeypatch.setattr(journal.tempfile, "mkdtemp", fail_create)
    with pytest.raises(loader.JournalCaptureIOError) as caught:
        with loader.prepare_journal_capture(
            since=None, until=None, default_span=None
        ):
            pass
    assert str(tmp_path) not in str(caught.value)


@pytest.mark.parametrize("failure_point", ["write", "flush", "close"])
def test_capture_sink_failures_are_typed_and_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    executable = _executable(tmp_path, f"print({_record(1)!r})")
    _patch_executable(monkeypatch, executable)
    real_create = journal._create_capture
    artifacts: list[tuple[Path, Path]] = []

    class FailingStream:
        def __init__(self, stream) -> None:
            self.stream = stream

        def write(self, data):
            if failure_point == "write":
                raise OSError("synthetic write failure")
            return self.stream.write(data)

        def flush(self):
            if failure_point == "flush":
                raise OSError("synthetic flush failure")
            return self.stream.flush()

        def close(self):
            self.stream.close()
            if failure_point == "close":
                raise OSError("synthetic close failure")

    def failing_create():
        directory, path, stream = real_create()
        artifacts.append((directory, path))
        return directory, path, FailingStream(stream)

    monkeypatch.setattr(journal, "_create_capture", failing_create)
    with pytest.raises(loader.JournalCaptureIOError):
        with loader.prepare_journal_capture(
            since=None, until=None, default_span=None
        ):
            pass
    directory, path = artifacts[0]
    assert not path.exists()
    assert not directory.exists()


def test_capture_preparse_stops_after_first_usable_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(
        tmp_path,
        f"print({_record(1)!r}); print({_record(2)!r}); print({_record(3)!r})",
    )
    _patch_executable(monkeypatch, executable)
    real_parse = journal.parse_record
    calls = 0

    def parse_spy(line):
        nonlocal calls
        calls += 1
        return real_parse(line)

    monkeypatch.setattr(journal, "parse_record", parse_spy)
    with loader.prepare_journal_capture(
        since=None, until=None, default_span=None
    ) as prepared:
        assert prepared.has_usable_rows is True
    assert calls == 1


def test_capture_cancellation_reaps_child_and_removes_private_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "pid"
    executable = _executable(
        tmp_path,
        "import os, signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)",
    )
    _patch_executable(monkeypatch, executable)
    capture_dir = tmp_path / "capture"

    def fixed_mkdtemp(*, prefix):
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
    with pytest.raises(KeyboardInterrupt):
        with loader.prepare_journal_capture(
            since=None, until=None, default_span=None
        ):
            pass
    assert not capture_dir.exists()
    pid = int(pid_file.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_stderr_is_sanitized_deduplicated_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _executable(
        tmp_path,
        f"""
import sys
print({_record(1)!r})
print("warn\\x1b[31m", file=sys.stderr)
print("warn\\x1b[31m", file=sys.stderr)
print("x" * 800, file=sys.stderr)
""",
    )
    _patch_executable(monkeypatch, executable)
    with loader.prepare_journal_capture(
        since=None, until=None, default_span=None
    ) as prepared:
        assert len(prepared.warnings) == 2
        assert prepared.warnings[0] == "journalctl: warn[31m"
        assert len(prepared.warnings[1]) == len("journalctl: ") + 512
        assert "\x1b" not in "".join(prepared.warnings)


def test_display_label_read_warning_seam_hides_leaf() -> None:
    warning = loader._zeek_file_read_warning(
        Path("system-journal.jsonl"),
        OSError(),
        display_label="system journal",
    )
    assert warning == "system journal could not be read - unreadable (OSError); skipping"
    assert "system-journal.jsonl" not in warning


def test_capture_stat_and_mid_read_failures_use_owned_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    line = _record(1)
    executable = _executable(tmp_path, f"print({line!r})")
    _patch_executable(monkeypatch, executable)
    with loader.prepare_journal_capture(
        since=None, until=None, default_span=None
    ) as prepared:
        real_stat = Path.stat

        def broken_stat(path, *args, **kwargs):
            if path == prepared.capture_path:
                raise OSError("synthetic stat failure")
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", broken_stat)
        with pytest.raises(loader.JournalCaptureIOError):
            loader.load_required_logs(
                {"*.log*": "journal"}, {"journal": [prepared.capture_path]}
            )
        monkeypatch.setattr(Path, "stat", real_stat)

        @contextmanager
        def broken_open(path):
            assert path == prepared.capture_path

            def rows():
                yield line + "\n"
                raise OSError("synthetic mid-read failure")

            yield rows()

        monkeypatch.setattr(loader, "_open_log", broken_open)
        with pytest.raises(loader.JournalCaptureIOError):
            loader.load_required_logs(
                {"*.log*": "journal"}, {"journal": [prepared.capture_path]}
            )


def test_arbitrary_journal_json_has_no_public_sniff_route(tmp_path: Path) -> None:
    candidate = tmp_path / "journal.jsonl"
    candidate.write_text(_record(1) + "\n", encoding="utf-8")
    assert loader.sniff_format(candidate) != "journal"
