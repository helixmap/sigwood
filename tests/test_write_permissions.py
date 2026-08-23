"""Permission policy and raw-write durability for sigwood-owned artifacts."""

from __future__ import annotations

import ast
import errno
import fcntl
import io
import json
import os
import shutil
import stat
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pytest

import sigwood.cli as cli
import sigwood.cli_allowlist as cli_allowlist
import sigwood.cli_init as cli_init
import sigwood.runner as runner
from sigwood.common.finding import RunSummary
from sigwood.common.output import register_builtin_handlers
from sigwood.common.paths import (
    private_mkdir,
    private_open,
    private_write_bytes,
    private_write_text,
)
from sigwood.exporters import cloudtrail, splunk
from sigwood.outputs import pdf as pdf_mod
from sigwood.outputs.pdf import PdfHandler


_POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix", reason="artifact permission policy is POSIX-only",
)

_CONN_LINE = (
    '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
    '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
    '"id.resp_p":443,"proto":"tcp","duration":1.0,"orig_bytes":128}\n'
)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _symlink_refusal(path: Path) -> str:
    return (
        f"{path} is a symbolic link - refusing to write through it; "
        "remove it or choose another target"
    )


def _run_cli_process(
    *args: str, timeout: float = 3.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from sigwood.cli import main; main(sys.argv[1:])",
            *args,
        ],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


@contextmanager
def _temporary_umask(mode: int) -> Iterator[None]:
    previous = os.umask(mode)
    try:
        yield
    finally:
        os.umask(previous)


def _summary() -> RunSummary:
    return RunSummary(
        data_window=(
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 2, tzinfo=timezone.utc),
        ),
        record_counts={},
        data_size_bytes=0,
        detectors_run=["beacon"],
        detectors_skipped={},
    )


def _drive_handler(handler: object, close_handler: object) -> None:
    handler.begin(_summary())
    handler.write([])
    handler.end()
    close_handler()


@_POSIX_ONLY
def test_private_mkdir_sets_every_created_component_to_0700(tmp_path: Path) -> None:
    target = tmp_path / "first" / "second"
    with _temporary_umask(0):
        private_mkdir(target)
    assert _mode(tmp_path / "first") == 0o700
    assert _mode(target) == 0o700


@_POSIX_ONLY
@pytest.mark.parametrize("writer", ["text", "bytes"])
def test_private_write_retightens_existing_file(
    tmp_path: Path, writer: str,
) -> None:
    target = tmp_path / "artifact"
    target.write_bytes(b"loose")
    target.chmod(0o644)

    with _temporary_umask(0):
        if writer == "text":
            private_write_text(target, "private\r\n", newline="")
            expected = b"private\r\n"
        else:
            private_write_bytes(target, b"private\x00")
            expected = b"private\x00"

    assert target.read_bytes() == expected
    assert _mode(target) == 0o600


@_POSIX_ONLY
@pytest.mark.parametrize("writer", ["text", "bytes"])
def test_whole_value_writer_replaces_inaccessible_regular_destination(
    tmp_path: Path, writer: str,
) -> None:
    target = tmp_path / "artifact"
    target.write_bytes(b"old")
    target.chmod(0o000)

    if writer == "text":
        private_write_text(target, "replacement")
        expected = b"replacement"
    else:
        private_write_bytes(target, b"replacement")
        expected = b"replacement"

    assert target.read_bytes() == expected
    assert _mode(target) == 0o600


@_POSIX_ONLY
def test_private_write_never_changes_preexisting_parent_mode(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o755)

    with _temporary_umask(0):
        private_mkdir(parent)
        private_write_text(parent / "artifact", "x")

    assert _mode(parent) == 0o755
    assert _mode(parent / "artifact") == 0o600


@_POSIX_ONLY
def test_public_policy_remains_ambient_umask_governed(tmp_path: Path) -> None:
    parent = tmp_path / "system" / "nested"
    target = parent / "config.toml"
    with _temporary_umask(0o022):
        private_mkdir(parent, private=False)
        private_write_text(target, "value\r\n", private=False, newline="")

    assert _mode(tmp_path / "system") == 0o755
    assert _mode(parent) == 0o755
    assert _mode(target) == 0o644
    assert target.read_bytes() == b"value\r\n"


@_POSIX_ONLY
def test_cli_refuses_final_component_symlink_without_touching_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli.cfg, "SEARCH_PATHS", [])
    source = tmp_path / "conn.log"
    source.write_text(_CONN_LINE, encoding="utf-8")
    victim = tmp_path / "victim.conf"
    original = b"keep this configuration\n"
    victim.write_bytes(original)
    victim.chmod(0o644)
    target = tmp_path / "report.txt"
    target.symlink_to(victim)

    try:
        cli.main(["beacon", str(source), "--all", "-q", f"--out={target}"])
    except SystemExit as exc:
        exit_code = exc.code
    else:
        exit_code = 0

    captured = capsys.readouterr()
    assert (victim.read_bytes(), _mode(victim), exit_code) == (
        original,
        0o644,
        1,
    )
    assert captured.out == ""
    assert captured.err == f"sigwood: {_symlink_refusal(target)}\n"
    assert captured.err.count("sigwood:") == 1
    assert "run 'sigwood --help' for usage" not in captured.err


@_POSIX_ONLY
@pytest.mark.parametrize("output_format", ["text", "json", "csv", "html"])
def test_cli_refuses_fifo_leaf_without_hanging_or_guessing_its_type(
    tmp_path: Path, output_format: str,
) -> None:
    source = tmp_path / "conn.log"
    source.write_text(_CONN_LINE, encoding="utf-8")
    config = tmp_path / "config.toml"
    config.write_text(f'[sigwood]\nroot = "{tmp_path}"\n', encoding="utf-8")
    target = tmp_path / "report-\x1b[31m\x07.fifo"
    os.mkfifo(target)

    result = _run_cli_process(
        "beacon",
        str(source),
        "--all",
        "-q",
        f"--format={output_format}",
        f"--config={config}",
        f"--out={target}",
    )

    assert result.returncode == 1
    assert result.stdout == ""
    if output_format == "html":
        reason = "is not a regular file"
    else:
        reason = "could not be opened safely"
    assert result.stderr == (
        f"sigwood: {tmp_path}/report-[31m.fifo {reason} - refusing to write "
        "to it; choose a regular file or directory\n"
    )
    assert "FIFO" not in result.stderr
    assert "\x1b" not in result.stderr
    assert "\x07" not in result.stderr
    assert "Traceback" not in result.stderr
    assert stat.S_ISFIFO(target.stat().st_mode)


@_POSIX_ONLY
@pytest.mark.parametrize("output_format", ["text", "json", "csv", "html"])
def test_cli_refuses_device_leaf_with_actionable_error(
    tmp_path: Path, output_format: str,
) -> None:
    device = Path(os.devnull)
    if not device.exists():
        pytest.skip("platform has no null device")

    source = tmp_path / "conn.log"
    source.write_text(_CONN_LINE, encoding="utf-8")
    config = tmp_path / "config.toml"
    config.write_text(f'[sigwood]\nroot = "{tmp_path}"\n', encoding="utf-8")

    result = _run_cli_process(
        "beacon",
        str(source),
        "--all",
        "-q",
        f"--format={output_format}",
        f"--config={config}",
        f"--out={device}",
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == (
        f"sigwood: {device} is not a regular file - refusing to write to it; "
        "choose a regular file or directory\n"
    )
    assert "Operation not permitted" not in result.stderr
    assert "Traceback" not in result.stderr


@_POSIX_ONLY
@pytest.mark.parametrize("writer", ["text", "bytes"])
def test_whole_value_writer_refuses_symlink_without_raw_exception(
    tmp_path: Path, writer: str,
) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"preserve")
    target = tmp_path / "artifact"
    target.symlink_to(victim)

    with pytest.raises(ValueError) as exc_info:
        if writer == "text":
            private_write_text(target, "replacement")
        else:
            private_write_bytes(target, b"replacement")

    assert str(exc_info.value) == _symlink_refusal(target)
    assert victim.read_bytes() == b"preserve"


@_POSIX_ONLY
@pytest.mark.parametrize("leaf", ["fifo", "device"])
def test_pdf_helper_refuses_nonregular_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, leaf: str,
) -> None:
    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", lambda _html: b"%PDF-private")
    target = tmp_path / "report.fifo" if leaf == "fifo" else Path(os.devnull)
    if leaf == "fifo":
        os.mkfifo(target)
    elif not target.exists():
        pytest.skip("platform has no null device")
    handler = PdfHandler(output_path=target, verbose_level=0)
    handler.begin(_summary())
    handler.write([])

    with pytest.raises(ValueError) as exc_info:
        handler.end()

    assert str(exc_info.value) == (
        f"{target} is not a regular file - refusing to write to it; "
        "choose a regular file or directory"
    )
    if leaf == "fifo":
        assert stat.S_ISFIFO(target.stat().st_mode)


@_POSIX_ONLY
@pytest.mark.parametrize("private", [True, False])
def test_write_fd_refuses_final_component_symlink(
    tmp_path: Path, private: bool,
) -> None:
    import sigwood.common.paths as paths_mod

    victim = tmp_path / "victim"
    original = b"preserve me"
    victim.write_bytes(original)
    victim.chmod(0o644)
    target = tmp_path / "artifact"
    target.symlink_to(victim)
    opened_fd: int | None = None

    try:
        with pytest.raises(ValueError) as exc_info:
            opened_fd = paths_mod._write_fd(target, private=private)
    finally:
        # Close an unexpected fd before pytest reports the missing exception.
        if opened_fd is not None:
            os.close(opened_fd)

    assert str(exc_info.value) == _symlink_refusal(target)
    assert victim.read_bytes() == original
    assert _mode(victim) == 0o644


@_POSIX_ONLY
def test_write_preserves_intermediate_symlink_loop_oserror(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    loop.symlink_to("loop", target_is_directory=True)
    target = loop / "artifact"

    with pytest.raises(OSError) as exc_info:
        private_write_text(target, "never written")

    assert exc_info.value.errno == errno.ELOOP
    assert _symlink_refusal(target) not in str(exc_info.value)


@_POSIX_ONLY
def test_write_fd_propagates_non_eloop_without_leaf_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sigwood.common.paths as paths_mod

    target = tmp_path / "artifact"
    open_error = PermissionError(errno.EACCES, "denied", str(target))

    def _fail_open(*_args: object, **_kwargs: object) -> int:
        raise open_error

    def _unexpected_lstat(*_args: object, **_kwargs: object) -> os.stat_result:
        raise AssertionError("non-ELOOP failure must not classify the leaf")

    monkeypatch.setattr(paths_mod.os, "open", _fail_open)
    monkeypatch.setattr(paths_mod.os, "lstat", _unexpected_lstat)

    with pytest.raises(PermissionError) as exc_info:
        paths_mod._write_fd(target, private=True)

    assert exc_info.value is open_error


@_POSIX_ONLY
def test_write_fd_propagates_original_eloop_when_leaf_classification_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sigwood.common.paths as paths_mod

    target = tmp_path / "loop" / "artifact"
    open_error = OSError(errno.ELOOP, "open loop", str(target))

    def _fail_open(*_args: object, **_kwargs: object) -> int:
        raise open_error

    def _fail_lstat(*_args: object, **_kwargs: object) -> os.stat_result:
        raise PermissionError(errno.EACCES, "classification denied", str(target))

    monkeypatch.setattr(paths_mod.os, "open", _fail_open)
    monkeypatch.setattr(paths_mod.os, "lstat", _fail_lstat)

    with pytest.raises(OSError) as exc_info:
        paths_mod._write_fd(target, private=True)

    assert exc_info.value is open_error


@_POSIX_ONLY
def test_write_through_symlinked_parent_directory_remains_supported(
    tmp_path: Path,
) -> None:
    relocated = tmp_path / "relocated-reports"
    relocated.mkdir()
    reports = tmp_path / "reports"
    reports.symlink_to(relocated, target_is_directory=True)

    # Final-component refusal intentionally does not close the residual risk in
    # parent components; ordinary relocated report directories remain supported.
    private_write_text(reports / "report.txt", "relocated\r\n", newline="")

    written = relocated / "report.txt"
    assert written.read_bytes() == b"relocated\r\n"
    assert _mode(written) == 0o600


@_POSIX_ONLY
@pytest.mark.parametrize("private", [True, False])
def test_private_open_keeps_regular_route_bytes_and_clears_nonblocking(
    tmp_path: Path, private: bool,
) -> None:
    target = tmp_path / "artifact"

    with _temporary_umask(0o022):
        with private_open(target, private=private, newline="") as stream:
            assert fcntl.fcntl(stream.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK == 0
            stream.write("first\r\nsecond\n")

    assert target.read_bytes() == b"first\r\nsecond\n"
    assert _mode(target) == (0o600 if private else 0o644)


@_POSIX_ONLY
def test_write_fd_preserves_write_only_open_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sigwood.common.paths as paths_mod

    real_open = paths_mod._open_through_walked_parent
    observed_flags: list[int] = []

    def _record_flags(
        path: str | os.PathLike[str], flags: int, mode: int,
    ) -> int:
        observed_flags.append(flags)
        return real_open(path, flags, mode)

    monkeypatch.setattr(paths_mod, "_open_through_walked_parent", _record_flags)
    with private_open(tmp_path / "artifact") as stream:
        stream.write("ok")

    assert len(observed_flags) == 1
    assert observed_flags[0] & os.O_ACCMODE == os.O_WRONLY


@_POSIX_ONLY
@pytest.mark.parametrize("failure", ["fstat", "fcntl", "fchmod", "fdopen"])
def test_private_open_closes_fd_when_setup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    import sigwood.common.paths as paths_mod

    closed: list[int] = []
    opened: list[int] = []
    real_close = paths_mod.os.close
    real_open = paths_mod.os.open

    def _fail_fchmod(_fd: int, _mode: int) -> None:
        raise OSError("fchmod failed")

    def _fail_fstat(_fd: int) -> os.stat_result:
        raise OSError("fstat failed")

    def _fail_fcntl(*_args: object) -> int:
        raise OSError("fcntl failed")

    def _fail_fdopen(*_args: object, **_kwargs: object) -> None:
        raise OSError("fdopen failed")

    def _record_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    if failure == "fstat":
        monkeypatch.setattr(paths_mod.os, "fstat", _fail_fstat)
    elif failure == "fcntl":
        monkeypatch.setattr(paths_mod.fcntl, "fcntl", _fail_fcntl)
    elif failure == "fchmod":
        monkeypatch.setattr(paths_mod.os, "fchmod", _fail_fchmod)
    else:
        monkeypatch.setattr(paths_mod.os, "fdopen", _fail_fdopen)
    def _record_open(*args: object, **kwargs: object) -> int:
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    monkeypatch.setattr(paths_mod.os, "close", _record_close)
    monkeypatch.setattr(paths_mod.os, "open", _record_open)

    with pytest.raises(OSError, match=f"{failure} failed"):
        private_open(tmp_path / "artifact")
    # The invariant is that nothing LEAKS, not that exactly one descriptor was
    # opened: walking the parent components opens a descriptor per level, and
    # each must be released on the failure path too. Counting opens against
    # closes states that directly instead of encoding one particular walk depth.
    assert len(opened) == len(closed) != 0


@_POSIX_ONLY
@pytest.mark.parametrize(
    ("output_format", "suffix"),
    [("text", "txt"), ("json", "json"), ("csv", "csv"), ("html", "html")],
)
def test_report_file_modes_and_stream_bytes_match(
    tmp_path: Path, output_format: str, suffix: str,
) -> None:
    register_builtin_handlers()
    stream = io.StringIO()
    stream_handler, stream_close, _ = runner._build_output_handler(
        output_format, output_dir=None, output_file=None,
        verbose_level=0, stream=stream,
    )
    _drive_handler(stream_handler, stream_close)

    target = tmp_path / output_format / f"report.{suffix}"
    with _temporary_umask(0):
        file_handler, file_close, written = runner._build_output_handler(
            output_format, output_dir=None, output_file=target, verbose_level=0,
        )
        _drive_handler(file_handler, file_close)

    assert written == target
    assert target.read_bytes() == stream.getvalue().encode("utf-8")
    assert _mode(target) == 0o600
    assert _mode(target.parent) == 0o700


@_POSIX_ONLY
def test_directory_verdict_creates_private_report_tree(tmp_path: Path) -> None:
    register_builtin_handlers()
    output_dir = tmp_path / "reports" / "daily"
    with _temporary_umask(0):
        handler, close_handler, written = runner._build_output_handler(
            "text", output_dir=output_dir, output_file=None,
            verbose_level=0, detectors_run=["beacon"],
        )
        _drive_handler(handler, close_handler)

    assert written is not None
    assert _mode(tmp_path / "reports") == 0o700
    assert _mode(output_dir) == 0o700
    assert _mode(written) == 0o600


@_POSIX_ONLY
def test_pdf_helper_seam_writes_private_file_without_optional_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", lambda _html: b"%PDF-private")
    target = tmp_path / "reports" / "pdf" / "report.pdf"
    handler = PdfHandler(output_path=target, verbose_level=0)
    handler.begin(_summary())
    handler.write([])

    with _temporary_umask(0):
        handler.end()

    assert target.read_bytes() == b"%PDF-private"
    assert _mode(target) == 0o600
    assert _mode(tmp_path / "reports") == 0o700
    assert _mode(target.parent) == 0o700


@_POSIX_ONLY
def test_graph_artifact_and_created_parent_are_private(tmp_path: Path) -> None:
    source = tmp_path / "captured.log"
    source.write_text(_CONN_LINE, encoding="utf-8")
    target = tmp_path / "graphs" / "daily" / "conn.html"
    config = {
        "sigwood": {"default_window": "all", "warn_above": 10_000_000},
        "graph": {},
    }

    with _temporary_umask(0):
        written = runner.run_graph(
            config,
            kind="conn",
            inputs=source,
            output_file=target,
            load_all=True,
            quiet=True,
            show_progress=False,
        )

    assert written == target
    html = target.read_text(encoding="utf-8")
    assert "const DATA = " in html
    assert _mode(target) == 0o600
    assert _mode(tmp_path / "graphs") == 0o700
    assert _mode(target.parent) == 0o700


@_POSIX_ONLY
def test_digest_out_stream_writes_private_exact_bytes(tmp_path: Path) -> None:
    target = tmp_path / "digests" / "daily" / "digest.txt"
    with _temporary_umask(0):
        get_stream, close_stream, dest = cli._build_digest_fanout_stream(
            {"out": str(target)},
        )
        get_stream().write("first\r\nsecond\n")
        close_stream()

    assert dest == target
    assert target.read_bytes() == b"first\r\nsecond\n"
    assert _mode(target) == 0o600
    assert _mode(tmp_path / "digests") == 0o700
    assert _mode(target.parent) == 0o700


@_POSIX_ONLY
def test_splunk_export_file_and_directory_are_private(tmp_path: Path) -> None:
    target = tmp_path / "exports" / "syslog" / "events.log"
    rows = [{
        "_time": "2026-01-01T00:00:00Z",
        "_raw": "<34>Jan  1 00:00:00 host1 app[1]: ready",
    }]
    with _temporary_umask(0):
        count, meta = splunk.write(rows, target, verbose=False)

    assert count == 1
    assert meta["paths"] == [target]
    assert target.read_text(encoding="utf-8") == "Jan  1 00:00:00 host1 app[1]: ready\n"
    assert _mode(target) == 0o600
    assert _mode(tmp_path / "exports") == 0o700
    assert _mode(target.parent) == 0o700


@_POSIX_ONLY
def test_cloudtrail_unsplit_file_is_private(tmp_path: Path) -> None:
    target = tmp_path / "exports" / "cloudtrail" / "events.json.log"
    event = {"eventTime": "2026-01-01T00:00:00Z", "eventName": "ListThings"}

    with _temporary_umask(0):
        count, meta = cloudtrail.write([event], target, verbose=False)

    assert count == 1
    assert meta["paths"] == [target]
    assert json.loads(target.read_text(encoding="utf-8")) == event
    assert _mode(target) == 0o600
    assert _mode(tmp_path / "exports") == 0o700
    assert _mode(target.parent) == 0o700


@_POSIX_ONLY
def test_cloudtrail_split_reopens_every_part_privately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cloudtrail, "_PART_SPLIT_BYTES", 1)
    target = tmp_path / "exports" / "cloudtrail" / "events.json.log"
    events = [
        {"eventTime": "2026-01-01T00:00:00Z", "eventName": "ListThings"},
        {"eventTime": "2026-01-01T00:00:01Z", "eventName": "GetThing"},
    ]
    with _temporary_umask(0):
        count, meta = cloudtrail.write(events, target, verbose=False)

    assert count == 2
    paths = meta["paths"]
    assert [path.name for path in paths] == [
        "events_part01.json.log", "events_part02.json.log",
    ]
    assert [json.loads(path.read_text(encoding="utf-8")) for path in paths] == events
    assert {_mode(path) for path in paths} == {0o600}
    assert _mode(tmp_path / "exports") == 0o700
    assert _mode(target.parent) == 0o700


def _config_for_root(path: Path, root: Path) -> None:
    path.write_text(
        f'[sigwood]\nroot = "{root}"\n',
        encoding="utf-8",
    )


@_POSIX_ONLY
def test_allowlist_copy_creates_private_destination(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    root = tmp_path / "home"
    _config_for_root(config_path, root)

    with _temporary_umask(0):
        cli_allowlist.run_allowlist(
            ["copy", "common"], config_path=str(config_path),
        )

    allowlist_dir = root / "allowlist.d"
    dest = allowlist_dir / "domains_common_local"
    assert dest.exists()
    assert _mode(root) == 0o700
    assert _mode(allowlist_dir) == 0o700
    assert _mode(dest) == 0o600


@_POSIX_ONLY
def test_allowlist_toggle_retightens_config_and_backup(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    _config_for_root(config_path, tmp_path / "home")
    original = config_path.read_bytes()
    config_path.chmod(0o644)

    with _temporary_umask(0):
        cli_allowlist.run_allowlist(
            ["enable", "homelab"], config_path=str(config_path),
        )

    backup = config_path.with_suffix(".toml.bak")
    assert backup.read_bytes() == original
    assert _mode(backup) == 0o600
    assert _mode(config_path) == 0o600
    assert b"homelab = true" in config_path.read_bytes()


def _stub_fresh_init(
    monkeypatch: pytest.MonkeyPatch, home: Path,
) -> None:
    actions = {key: cli_init._SKIP for key in cli_init._MANAGED_KEYS}
    monkeypatch.setattr(
        cli_init, "_collect_actions", lambda *_a, **_kw: (dict(actions), None),
    )
    monkeypatch.setattr(
        cli_init, "_location_flow", lambda: (home, str(home)),
    )
    monkeypatch.setattr(cli_init, "_resolve_all", lambda *_a, **_kw: {})
    monkeypatch.setattr(cli_init, "_render_summary", lambda *_a, **_kw: None)
    monkeypatch.setattr(cli_init, "_confirm_accept", lambda: "accept")
    monkeypatch.setattr(cli_init, "_print_confirm", lambda *_a, **_kw: None)
    monkeypatch.setattr(cli_init, "_print_intro", lambda *_a, **_kw: None)


@_POSIX_ONLY
def test_fresh_init_creates_private_home_config_and_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "private-home"
    _stub_fresh_init(monkeypatch, home)

    with _temporary_umask(0):
        cli_init._fresh_flow()

    allowlist_dir = home / "allowlist.d"
    assert _mode(home) == 0o700
    assert _mode(home / "config.toml") == 0o600
    assert _mode(allowlist_dir) == 0o700
    assert {
        path.name: _mode(path) for path in allowlist_dir.iterdir() if path.is_file()
    } == {"connections": 0o600, "domains_user": 0o600, "hosts": 0o600}


@_POSIX_ONLY
def test_init_backup_is_private_and_byte_faithful(tmp_path: Path) -> None:
    target = tmp_path / "home" / "config.toml"
    target.parent.mkdir()
    target.parent.chmod(0o755)
    target.write_text("old", encoding="utf-8")
    target.chmod(0o644)
    original = b"original\r\nbytes\x00"
    actions = {key: cli_init._SKIP for key in cli_init._MANAGED_KEYS}
    actions["root"] = cli_init._set(str(target.parent))

    with _temporary_umask(0):
        cli_init._write_config(
            target,
            cli_init._load_example_text(),
            actions,
            fresh=True,
            existing_raw=original,
        )

    backup = target.with_suffix(".toml.bak")
    assert backup.read_bytes() == original
    assert _mode(backup) == 0o600
    assert _mode(target) == 0o600
    assert _mode(target.parent) == 0o755


@_POSIX_ONLY
def test_system_init_branch_uses_ambient_umask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "system-home"
    monkeypatch.setattr(cli_init, "_SYSTEM_ROOT", str(home))
    _stub_fresh_init(monkeypatch, home)

    with _temporary_umask(0o022):
        cli_init._fresh_flow()

    allowlist_dir = home / "allowlist.d"
    assert _mode(home) == 0o755
    assert _mode(home / "config.toml") == 0o644
    assert _mode(allowlist_dir) == 0o755
    assert {_mode(path) for path in allowlist_dir.iterdir() if path.is_file()} == {0o644}


@_POSIX_ONLY
def test_loose_root_advisory_exact_shape(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "home"
    root.mkdir()
    root.chmod(0o755)

    cli._advise_loose_root({"sigwood": {"root": str(root)}})

    assert capsys.readouterr().err == (
        f"sigwood home {root} is group/world-accessible (drwxr-xr-x) - "
        f"chmod 700 {root} to close it\n"
    )


@_POSIX_ONLY
@pytest.mark.parametrize("state", ["secure", "missing"])
def test_secure_or_missing_root_is_silent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state: str,
) -> None:
    root = tmp_path / state
    if state == "secure":
        root.mkdir()
        root.chmod(0o700)

    cli._advise_loose_root({"sigwood": {"root": str(root)}})

    assert capsys.readouterr().err == ""


@_POSIX_ONLY
def test_quiet_hunt_still_emits_loose_root_advisory_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "home"
    root.mkdir()
    root.chmod(0o755)
    config = {"sigwood": {"root": str(root)}}
    monkeypatch.setattr(cli.cfg, "load", lambda _path: config)
    monkeypatch.setattr(cli, "_runner_kwargs", lambda *_a, **_kw: {})
    monkeypatch.setattr(runner, "run", lambda **_kw: 0)

    assert cli._main(["hunt", "-q"]) == 0

    err = capsys.readouterr().err
    assert err.count("sigwood home ") == 1
    assert "group/world-accessible" in err


@_POSIX_ONLY
def test_loose_root_advisory_strips_terminal_controls(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "home\x1b[31m\x07\x7f\x85"
    root.mkdir()
    root.chmod(0o755)

    cli._advise_loose_root({"sigwood": {"root": str(root)}})

    err = capsys.readouterr().err
    assert "home[31m" in err
    assert not [
        ch for ch in err
        if (ord(ch) < 0x20 and ch != "\n")
        or ord(ch) == 0x7F
        or 0x80 <= ord(ch) <= 0x9F
    ]


def test_main_sets_umask_for_hunt_but_not_init(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(cli.os, "umask", lambda mode: calls.append(mode))
    monkeypatch.setattr(cli, "_run_hunt", lambda *_a, **_kw: 0)
    monkeypatch.setattr(cli, "_run_init", lambda *_a, **_kw: None)

    assert cli._main(["hunt"]) == 0
    assert calls == [0o077]
    assert cli._main(["init"]) == 0
    assert calls == [0o077]


def _literal_mode(call: ast.Call) -> str | None:
    mode_node: ast.expr | None = None
    if isinstance(call.func, ast.Name) and call.func.id == "open":
        if len(call.args) > 1:
            mode_node = call.args[1]
    elif isinstance(call.func, ast.Attribute) and call.func.attr == "open":
        if call.args:
            mode_node = call.args[0]
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
        return mode_node.value
    return None


def _raw_write_violations(source: str, label: str) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "mkdir", "makedirs", "write_text", "write_bytes",
        }:
            violations.append(f"{label}:{node.lineno}:{node.func.attr}")
            continue
        mode = _literal_mode(node)
        if mode and (mode[0] in "wax" or "+" in mode):
            violations.append(f"{label}:{node.lineno}:open({mode})")
    return violations


@pytest.mark.parametrize(
    "source",
    [
        "open('x', 'w')",
        "Path('x').open('wb')",
        "Path('x').mkdir()",
        "os.mkdir('x')",
        "os.makedirs('x')",
        "Path('x').write_text('x')",
        "Path('x').write_bytes(b'x')",
        "open('x', mode='r+')",
    ],
)
def test_raw_write_tripwire_canaries_fail(source: str) -> None:
    assert _raw_write_violations(source, "canary")


@pytest.mark.parametrize(
    "source",
    ["open('x')", "open('x', 'r')", "Path('x').open('rb')", "gzip.open(p, 'rt')"],
)
def test_raw_write_tripwire_allows_read_modes(source: str) -> None:
    assert _raw_write_violations(source, "canary") == []


def test_sigwood_package_has_no_unowned_raw_write_primitives() -> None:
    package = Path("sigwood")
    exemptions = {"common/paths.py", "common/loader/journal.py"}
    violations: list[str] = []
    for path in sorted(package.rglob("*.py")):
        relative = path.relative_to(package).as_posix()
        if relative in exemptions:
            continue
        violations.extend(
            _raw_write_violations(path.read_text(encoding="utf-8"), relative)
        )
    assert violations == []


@_POSIX_ONLY
def test_hostile_parent_symlink_does_not_receive_the_write(tmp_path: Path) -> None:
    """A substituted parent directory must not capture an artifact.

    O_NOFOLLOW on the final name protects the file that is opened and says
    nothing about the directories walked to reach it, so before the parent walk
    a planted symlink among the parents silently redirected findings into a
    directory another account controls.
    """
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    os.chmod(attacker, 0o777)
    hijacked = tmp_path / "reports"
    hijacked.symlink_to(attacker)

    with pytest.raises(ValueError, match="refusing to write through it"):
        private_write_text(hijacked / "findings.txt", "secret")

    assert list(attacker.iterdir()) == []


@_POSIX_ONLY
def test_owner_relocated_parent_symlink_still_writes(tmp_path: Path) -> None:
    """A relocated directory is ordinary and stays supported.

    The refusal above must key on who could have chosen the link, not on the
    presence of a link: pointing a reports directory at another disk is a normal
    setup and documented as supported.
    """
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    relocated = tmp_path / "reports"
    relocated.symlink_to(elsewhere)

    private_write_text(relocated / "findings.txt", "ok")

    written = elsewhere / "findings.txt"
    assert written.read_text(encoding="utf-8") == "ok"
    assert _mode(written) == 0o600


@_POSIX_ONLY
def test_sticky_shared_parent_symlink_is_not_treated_as_hostile(tmp_path: Path) -> None:
    """A sticky shared directory is the safe-shared pattern, not an attack.

    In a sticky directory another account may create its own names but cannot
    remove or replace one it does not own. Refusing every world-writable target
    rejects `/tmp` itself, which on macOS is a symlink to a 1777 `/private/tmp`,
    and writing there is ordinary.
    """
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    link = tmp_path / "reports"
    link.symlink_to(shared)

    private_write_text(link / "findings.txt", "ok")

    assert (shared / "findings.txt").read_text(encoding="utf-8") == "ok"


@_POSIX_ONLY
def test_world_writable_parent_symlink_without_sticky_is_refused(tmp_path: Path) -> None:
    """Without the sticky bit, any account can replace names beneath it."""
    loose = tmp_path / "loose"
    loose.mkdir()
    os.chmod(loose, 0o777)
    link = tmp_path / "reports"
    link.symlink_to(loose)

    with pytest.raises(ValueError, match="sticky"):
        private_write_text(link / "findings.txt", "secret")

    assert list(loose.iterdir()) == []


@_POSIX_ONLY
def test_hard_linked_destination_keeps_its_contents(tmp_path: Path) -> None:
    """A hard link at the destination must lose a name, never its contents.

    Opening with O_TRUNC empties the file before anything is known about it, and
    a hard link is a second name for that same inode, so the other name's data
    went with it. Creating a fresh name and renaming over the target never opens
    what is already there.
    """
    victim = tmp_path / "evidence.txt"
    victim.write_text("irreplaceable", encoding="utf-8")
    target = tmp_path / "report.txt"
    os.link(victim, target)
    assert os.stat(victim).st_nlink == 2

    private_write_text(target, "findings")

    assert victim.read_text(encoding="utf-8") == "irreplaceable"
    assert target.read_text(encoding="utf-8") == "findings"
    assert os.stat(victim).st_nlink == 1
    assert _mode(target) == 0o600


@_POSIX_ONLY
def test_hard_linked_destination_survives_the_bytes_writer(tmp_path: Path) -> None:
    """The byte writer shares the replace path, so it shares the protection."""
    victim = tmp_path / "evidence.bin"
    victim.write_bytes(b"irreplaceable")
    target = tmp_path / "report.bin"
    os.link(victim, target)

    private_write_bytes(target, b"findings")

    assert victim.read_bytes() == b"irreplaceable"
    assert target.read_bytes() == b"findings"


@_POSIX_ONLY
def test_failed_whole_value_write_leaves_no_temporary(tmp_path: Path) -> None:
    """A write that dies mid-value must not leave a stray private file behind."""
    import sigwood.common.paths as paths_mod

    target = tmp_path / "report.txt"

    class _Boom(bytes):
        def __len__(self) -> int:  # pragma: no cover - exercised via the raise
            raise OSError("write failed")

    original = paths_mod.os.fdopen

    def _explode(*args: object, **kwargs: object):
        handle = original(*args, **kwargs)
        handle.close()
        raise OSError("write failed")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(paths_mod.os, "fdopen", _explode)
        with pytest.raises(OSError, match="write failed"):
            private_write_text(target, "findings")

    assert not target.exists()
    assert [p.name for p in tmp_path.iterdir()] == []


@_POSIX_ONLY
def test_write_survives_a_parent_replaced_mid_walk(tmp_path: Path) -> None:
    """A parent removed and recreated between the walk and the open must not fail.

    Walking the path holds a descriptor to the containing directory while the
    leaf is opened, so a concurrent writer that recreates that directory leaves
    the descriptor pointing at an unlinked inode and the create fails ENOENT.
    Resolving the whole path at open time never saw this, so the walk must retry
    rather than regress the concurrency the export provenance writers rely on.
    """
    import sigwood.common.paths as paths_mod

    parent = tmp_path / "reports"
    parent.mkdir()
    target = parent / "findings.txt"

    real_walk = paths_mod._open_parent_dirfd
    calls: list[int] = []

    def _swap_parent_once(path: object) -> tuple[int | None, str]:
        result = real_walk(path)
        calls.append(1)
        if len(calls) == 1:
            # Stand in for the concurrent writer: the directory the descriptor
            # refers to is unlinked and a fresh one takes its name.
            shutil.rmtree(parent)
            parent.mkdir()
        return result

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(paths_mod, "_open_parent_dirfd", _swap_parent_once)
        private_write_text(target, "findings")

    assert target.read_text(encoding="utf-8") == "findings"
    assert len(calls) == 2, "expected exactly one re-walk, not a retry loop"
