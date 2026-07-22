"""Permission policy and raw-write durability for sigwood-owned artifacts."""

from __future__ import annotations

import ast
import io
import json
import os
import stat
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
@pytest.mark.parametrize("failure", ["fchmod", "fdopen"])
def test_private_open_closes_fd_when_setup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    import sigwood.common.paths as paths_mod

    closed: list[int] = []
    real_close = paths_mod.os.close

    def _fail_fchmod(_fd: int, _mode: int) -> None:
        raise OSError("fchmod failed")

    def _fail_fdopen(*_args: object, **_kwargs: object) -> None:
        raise OSError("fdopen failed")

    def _record_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    if failure == "fchmod":
        monkeypatch.setattr(paths_mod.os, "fchmod", _fail_fchmod)
    else:
        monkeypatch.setattr(paths_mod.os, "fdopen", _fail_fdopen)
    monkeypatch.setattr(paths_mod.os, "close", _record_close)

    with pytest.raises(OSError, match=f"{failure} failed"):
        private_open(tmp_path / "artifact")
    assert len(closed) == 1


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
