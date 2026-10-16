"""The one retry command a shallow run offers: the operator's own, plus --recursive.

When an input the invocation supplied has subdirectories the run did not
search, the run offers the operator's own command with ``--recursive`` inserted
once: after an explicit verb, or after ``sigwood`` for an implicit hunt. The
CLI composes it from the original argv, withholds it when any token carries a
control character or the command passes the length limit, and the runner
places it once after the coverage notices, on stderr and in saved notes.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import sigwood.cli as cli
import sigwood.runner as runner
from sigwood.common.errors import UsageError
from sigwood.common.journal_probe import JournalProbeCode, JournalProbeResult

_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
_PREFIX = "discovery: to search those subdirectories as well, rerun with --recursive: "


def _stamp(days_ago: float, minute: int = 0) -> str:
    moment = datetime.now() - timedelta(days=days_ago) + timedelta(minutes=minute)
    return f"{_MONTHS[moment.month - 1]} {moment.day:2d} {moment:%H:%M:%S}"


def _syslog(days_ago: float = 1, host: str = "host-a", n: int = 2) -> str:
    return "".join(
        f"{_stamp(days_ago, i)} {host} sshd[{100 + i}]: Accepted publickey for "
        f"alice from 192.0.2.{i + 1} port 22 ssh2\n"
        for i in range(n)
    )


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _shallow(root: Path) -> Path:
    """A syslog directory with logs at the top and more one level down."""
    _write(root / "messages", _syslog(1))
    _write(root / "deeper" / "messages", _syslog(2, host="host-b"))
    return root


def _config(tmp_path: Path, **sigwood: str) -> Path:
    values = {
        "root": "", "zeek_dir": "", "syslog_dir": "", "pihole_dir": "",
        "cloudtrail_dir": "", "syslog_source": "files",
    }
    values.update(sigwood)
    lines = ["[sigwood]", *(f'{key} = "{value}"' for key, value in values.items())]
    path = tmp_path / f"config-{len(list(tmp_path.glob('config-*.toml')))}.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    return tmp_path


def _retries(text: str) -> list[str]:
    return [line[len(_PREFIX):] for line in text.splitlines() if line.startswith(_PREFIX)]


def _dry_err(argv: list[str], capsys) -> str:
    assert cli._main(argv) == 0
    return capsys.readouterr().err


# ── composition: exact tokens, controls withheld, the length limit ──────────


@pytest.mark.parametrize("argv", [
    ("sigwood", "--recursive", "/srv/logs with spaces/", "-q"),
    ("sigwood", "syslog", "--recursive", "it's \"quoted\"", "--days=0-30"),
    ("sigwood", "hunt", "--recursive", "$(id)", "a;b", "c&&d", "<script>x</script>"),
    ("sigwood", "--recursive", "./-leading-dash", "--zeek-dir=a b", "--out=-"),
    ("sigwood", "dns", "--recursive", "<img src=x onerror=alert(1)>", "`touch x`"),
])
def test_the_command_parses_back_to_the_exact_tokens(argv):
    command = cli._recursive_retry_command(argv)
    assert command is not None
    assert shlex.split(command) == list(argv)


@pytest.mark.parametrize("token", [
    "esc\x1b[2Jpath", "new\nline", "csi\x9bm", "nul\x00", "del\x7f", "surrogate\udc80",
])
@pytest.mark.parametrize("position", [1, 3])
def test_a_control_in_any_token_withholds_the_command(token, position):
    argv = ["sigwood", "syslog", "--recursive", "/srv/logs", "--config=/etc/x.toml"]
    argv[position] = token
    assert cli._recursive_retry_command(argv) is None


def test_the_length_limit_is_inclusive_and_never_truncates():
    limit = cli._RECURSIVE_RETRY_LIMIT
    base = ["sigwood", "syslog", "--recursive"]
    head = len(shlex.join(base)) + 1  # the separating space
    exact = [*base, "a" * (limit - head)]
    assert len(shlex.join(exact)) == limit
    assert cli._recursive_retry_command(exact) == shlex.join(exact)
    over = [*base, "a" * (limit - head + 1)]
    assert cli._recursive_retry_command(over) is None


def test_the_runner_never_receives_a_command_without_provenance_or_when_recursive():
    parsed = {"dry_run": True}
    config = {"sigwood": {}}
    assert "recursive_retry" not in cli._runner_kwargs(parsed, config)
    kwargs = cli._runner_kwargs(parsed, config, retry_argv=("sigwood", "--recursive", "x"))
    assert kwargs["recursive_retry"] == "sigwood --recursive x"
    already = cli._runner_kwargs(
        {"dry_run": True, "recursive": True}, config,
        retry_argv=("sigwood", "--recursive", "x"),
    )
    assert "recursive_retry" not in already


# ── placement on the real CLI ───────────────────────────────────────────────


@pytest.mark.parametrize(("lead", "inserted"), [
    ([], ["sigwood", "--recursive"]),
    (["hunt"], ["sigwood", "hunt", "--recursive"]),
    (["syslog"], ["sigwood", "syslog", "--recursive"]),
])
def test_the_flag_goes_after_the_verb_or_after_sigwood(isolated, capsys, lead, inserted):
    root = _shallow(isolated / "logs")
    config = _config(isolated)
    tail = [str(root), f"--config={config}", "--dry-run"]
    err = _dry_err([*lead, *tail], capsys)
    (command,) = _retries(err)
    assert shlex.split(command) == [*inserted, *tail]


def test_several_inputs_and_flags_yield_one_command_with_every_token(isolated, capsys):
    first = _shallow(isolated / "one dir")
    second = _shallow(isolated / "two;dir")
    config = _config(isolated)
    argv = [
        "syslog", str(first), str(second), f"--syslog-dir={_shallow(isolated / 'over')}",
        "--days=0-30", "-v", f"--config={config}", "--dry-run",
    ]
    err = _dry_err(argv, capsys)
    assert err.count("subdirectory this run did not search") == 3
    (command,) = _retries(err)
    assert shlex.split(command) == ["sigwood", "syslog", "--recursive", *argv[1:]]


def test_markup_and_shell_characters_in_a_path_are_quoted_data(isolated, capsys):
    root = _shallow(isolated / "<img src=x>$(id)'q\"")
    config = _config(isolated)
    err = _dry_err(["syslog", str(root), f"--config={config}", "--dry-run"], capsys)
    (command,) = _retries(err)
    assert shlex.split(command)[3] == str(root)


def test_a_control_in_another_token_withholds_the_command_but_keeps_the_notice(isolated, capsys):
    root = _shallow(isolated / "logs")
    odd = _write(isolated / "odd\x1bname.log", _syslog(1))
    config = _config(isolated)
    err = _dry_err(["syslog", str(root), str(odd), f"--config={config}", "--dry-run"], capsys)
    assert "subdirectory this run did not search" in err
    assert _retries(err) == []
    assert "\x1b" not in err


def test_a_command_past_the_limit_is_withheld_while_the_notice_stays(isolated, capsys):
    root = _shallow(isolated / "logs")
    config = _config(isolated)
    extras = [
        _write(isolated / "extra" / (f"{i:03d}-" + "x" * 180 + ".log"), _syslog(1))
        for i in range(30)
    ]
    argv = ["syslog", str(root), *map(str, extras), f"--config={config}", "--dry-run"]
    assert len(shlex.join(["sigwood", "syslog", "--recursive", *argv[1:]])) > (
        cli._RECURSIVE_RETRY_LIMIT
    )
    err = _dry_err(argv, capsys)
    assert "subdirectory this run did not search" in err
    assert _retries(err) == []


def test_configured_roots_and_recursive_runs_offer_no_command(isolated, capsys):
    configured = isolated / "configured"
    _write(configured / "notes.txt", "not syslog\n")
    _write(configured / "deeper" / "messages", _syslog(2))
    config = _config(isolated, syslog_dir=str(configured))
    err = _dry_err(["syslog", f"--config={config}", "--dry-run"], capsys)
    assert "subdirectory this run did not search" in err  # zero candidates
    assert _retries(err) == []
    root = _shallow(isolated / "logs")
    err = _dry_err(
        ["syslog", "--recursive", str(root), f"--config={_config(isolated)}", "--dry-run"],
        capsys,
    )
    assert _retries(err) == []


def test_one_command_reaches_every_saved_surface_and_csv_stays_findings_only(isolated, capsys):
    first = _shallow(isolated / "one")
    second = _shallow(isolated / "two")
    config = _config(isolated)
    outputs = {}
    for fmt in ("json", "text", "html", "csv"):
        out = isolated / f"report.{fmt}"
        assert cli._main([
            "syslog", str(first), str(second), f"--config={config}", "-q",
            f"--format={fmt}", f"--out={out}",
        ]) == 0
        outputs[fmt] = out.read_text(encoding="utf-8")
        assert len(_retries(capsys.readouterr().err)) == 1
    notes = json.loads(outputs["json"])["run_summary"]["notes"]
    assert sum(note.startswith(_PREFIX) for note in notes) == 1
    assert outputs["text"].count("rerun with --recursive") == 1
    assert outputs["html"].count("rerun with --recursive") == 1
    assert "rerun with --recursive" not in outputs["csv"]


# ── the emitted command, executed ───────────────────────────────────────────


def test_the_emitted_command_runs_from_its_original_directory(isolated, capsys, monkeypatch):
    _shallow(isolated / "logs")
    config = _config(isolated)
    monkeypatch.chdir(isolated)
    err = _dry_err(["syslog", "logs", f"--config={config}", "--dry-run"], capsys)
    (command,) = _retries(err)
    assert shlex.split(command)[3] == "logs"  # relative, exactly as typed
    sigwood_bin = Path(sys.executable).with_name("sigwood")
    env = {**os.environ, "PATH": f"{sigwood_bin.parent}{os.pathsep}{os.environ['PATH']}"}
    done = subprocess.run(
        ["bash", "-c", command], cwd=isolated, env=env,
        capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    assert "subdirectory this run did not search" not in done.stderr
    assert "2 discovered" in done.stdout  # both files, the deeper one included


def test_an_emitted_command_keeps_a_journal_conflict_instead_of_changing_flags(
    isolated, capsys, monkeypatch,
):
    monkeypatch.setattr(
        runner, "probe_journal", lambda **kw: JournalProbeResult(JournalProbeCode.READY),
    )
    zeek = isolated / "zeek"
    _write(zeek / "conn.log", json.dumps({
        "_path": "conn", "ts": 1760000000.0, "uid": "C1", "id.orig_h": "192.0.2.10",
        "id.orig_p": 40000, "id.resp_h": "198.51.100.20", "id.resp_p": 443,
        "proto": "tcp", "conn_state": "SF", "duration": 1.5,
        "orig_bytes": 100, "resp_bytes": 900, "local_orig": True,
    }) + "\n")
    _write(zeek / "host-b" / "messages", _syslog(1))
    config = _config(isolated)
    err = _dry_err(
        ["hunt", str(zeek), "--syslog-source=journal", f"--config={config}", "--dry-run"],
        capsys,
    )
    (command,) = _retries(err)
    tokens = shlex.split(command)
    assert "--syslog-source=journal" in tokens
    with pytest.raises(UsageError) as conflict:
        cli._main(tokens[1:])
    assert "cannot be combined with syslog files found by --recursive" in str(conflict.value)
