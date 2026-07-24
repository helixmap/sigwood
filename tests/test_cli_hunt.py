"""Dispatch + intent invariant for the ``hunt`` verb (the bare-flag cliff).

The hunt runs iff intent is present - a positional (implicit) OR the ``hunt``
verb (explicit). A lone flag is set dressing, never sufficient intent. Every
case drives the public boundary ``cli.main`` so the ``sigwood:`` prefix, exit
code, and usage pointer (part of the contract) are exercised.
"""

from __future__ import annotations

import json
import shlex
from datetime import datetime
from pathlib import Path

import pytest

from sigwood import cli
from sigwood.common import config as cfg


_NOTHING = "nothing to hunt - run 'sigwood hunt' or pass a log file"
_POINTER = "run 'sigwood --help' for usage"


def _no_run(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    """Record whether the runner was reached - a no-intent route must not run."""
    state = {"called": False}

    def _run(**_kw: object) -> None:
        state["called"] = True

    monkeypatch.setattr("sigwood.runner.run", _run)
    return state


def _capture_run(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Stub the runner and isolate config (SEARCH_PATHS=[] → cfg.load returns
    the defaults, never the developer's real ~/.sigwood/config.toml)."""
    state: dict[str, object] = {"called": False, "kw": None}

    def _run(**kw: object) -> None:
        state["called"] = True
        state["kw"] = kw

    monkeypatch.setattr("sigwood.runner.run", _run)
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    return state


# ── flags-only → no intent → error ──────────────────────────────────────────


@pytest.mark.parametrize("args", [
    ["-q"],
    ["--since=7d"],
    ["--detect=beacon"],
    ["--zeek-dir=PATH"],
    ["--syslog-dir=PATH"],
    ["--zeek-dir=PATH", "--format=text"],
])
def test_flags_only_is_not_intent(
    args: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Only flags (incl. source-dir / format flags) → the hunt errors, exit 1,
    with the usage pointer, and never reaches the runner."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    state = _no_run(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(args)

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert _NOTHING in err
    assert _POINTER in err
    assert state["called"] is False


def test_format_bogus_flags_only_reports_no_intent_not_format(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ordering: the no-target guard precedes output-format validation, so a
    flags-only ``--format=bogus`` reports the intent failure, NOT 'unknown
    output format'."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    state = _no_run(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--format=bogus"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert _NOTHING in err
    assert "unknown output format" not in err
    assert state["called"] is False


# ── the guard short-circuits before any run-side side effect ─────────────────


def test_no_target_guard_precedes_config_load(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An exploding cfg.load is never reached on a flags-only route - the guard
    fires immediately after the parse, before config load."""
    def _boom(*_a: object, **_k: object) -> object:
        raise AssertionError("cfg.load must not be reached on a no-intent route")

    monkeypatch.setattr(cfg, "load", _boom)

    with pytest.raises(SystemExit) as exc:
        cli.main(["-q"])

    assert exc.value.code == 1
    assert _NOTHING in capsys.readouterr().err


def test_bad_config_flag_alone_is_no_intent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--config=<bad>`` with no verb/path errors as no-intent - the bad config
    is never read (the guard precedes config load, so no config error surfaces)."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["--config=/nonexistent/bad.toml"])

    assert exc.value.code == 1
    assert _NOTHING in capsys.readouterr().err


# ── intent-present output-format validation still fires (guard is implicit-only)


def test_explicit_hunt_format_bogus_reports_unknown_format_no_pointer(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``hunt --format=bogus`` is intent-present (explicit verb) → the guard does
    NOT fire; output-format validation runs and reports the operational error
    with the registry list and NO usage pointer (a ValueError, not UsageError)."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])

    with pytest.raises(SystemExit) as exc:
        cli.main(["hunt", "--format=bogus"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "unknown output format 'bogus'" in err
    assert "available:" in err
    assert _POINTER not in err
    assert _NOTHING not in err


# ── parser errors win; unknown leading tokens never enter the hunt route ──────


def test_parser_error_wins_over_no_target(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--bogus`` raises inside the parser before the no-target check runs."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    state = _no_run(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(["--bogus"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "unknown flag --bogus" in err
    assert _NOTHING not in err
    assert state["called"] is False


@pytest.mark.parametrize("args", [["foo"], ["foo", "bar.log"]])
def test_unknown_leading_token_never_enters_hunt(
    args: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unknown leading token is ``unknown command 'foo'``, even when a later
    token looks path-like - it never enters the hunt route."""
    monkeypatch.chdir(tmp_path)  # ensure no file named 'foo' shadows the token
    state = _no_run(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(args)

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "unknown command 'foo'" in err
    assert state["called"] is False


# ── intent present (positional or explicit verb) → runs ──────────────────────


def test_positional_runs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = _capture_run(monkeypatch)
    conn = tmp_path / "conn.log"
    conn.write_text("", encoding="utf-8")

    cli.main([str(conn)])

    assert state["called"] is True


def test_multi_positional_runs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = _capture_run(monkeypatch)
    a = tmp_path / "conn.log"
    a.write_text("", encoding="utf-8")
    b = tmp_path / "other.log"
    b.write_text("", encoding="utf-8")

    cli.main([str(a), str(b)])

    assert state["called"] is True


def test_flag_then_positional_runs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = _capture_run(monkeypatch)
    conn = tmp_path / "conn.log"
    conn.write_text("", encoding="utf-8")

    cli.main(["-q", str(conn)])

    assert state["called"] is True


def test_explicit_hunt_no_positional_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    """The explicit verb runs against the config nest even with no PATH."""
    state = _capture_run(monkeypatch)

    cli.main(["hunt"])

    assert state["called"] is True


def test_explicit_hunt_positional_runs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = _capture_run(monkeypatch)
    conn = tmp_path / "conn.log"
    conn.write_text("", encoding="utf-8")

    cli.main(["hunt", str(conn)])

    assert state["called"] is True


def test_explicit_hunt_detect_no_positional_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit verb + flags, no PATH → runs. Proves ``require_target`` rides
    only the implicit routes."""
    state = _capture_run(monkeypatch)

    cli.main(["hunt", "--detect=beacon"])

    assert state["called"] is True


# ── help surfaces ────────────────────────────────────────────────────────────


def test_hunt_help_renders_hunt_verb_help(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["hunt", "--help"])
    out = capsys.readouterr().out
    assert "Usage: sigwood hunt [options] [PATH ...]" in out


def test_bare_sigwood_prints_global_usage(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    cli.main([])
    out = capsys.readouterr().out
    assert "sigwood - network threat hunting" in out
    assert "sigwood hunt [options] [PATH ...]" in out


# ── --utc end-to-end: the banner label follows the flag ──────────────────────


def test_utc_flag_renders_utc_label_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    pin_tz,
    restore_display_utc,
) -> None:
    """A real --utc hunt through cli.main renders the UTC label in the banner
    window cells; the same run without the flag stays local-labeled."""
    import json

    pin_tz("Etc/GMT+6")
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    conn = tmp_path / "conn.log"
    rows = [
        {"ts": 1750000000.0, "id.orig_h": "192.0.2.10",
         "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",
         "conn_state": "SF", "orig_bytes": 100, "local_orig": True},
        {"ts": 1750000060.0, "id.orig_h": "192.0.2.10",
         "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp",
         "conn_state": "SF", "orig_bytes": 100, "local_orig": True},
    ]
    conn.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    def banner_window_line(out: str) -> str:
        lines = [l for l in out.splitlines() if l.startswith("data found:")]
        assert len(lines) == 1
        return lines[0]

    cli.main(["--detect=beacon", str(conn)])
    line = banner_window_line(capsys.readouterr().out)
    assert line.rstrip().endswith("local  (1m)")
    assert " UTC" not in line

    cli.main(["--detect=beacon", "--utc", str(conn)])
    line = banner_window_line(capsys.readouterr().out)
    assert " UTC" in line
    assert " local" not in line


# ── zero-yield garbage end-to-end: per-file warning + honest data-found ───────


_ZY_GARBAGE = "totally ordinary prose line one\nanother line of plain words here\n"
_ZY_WARNING = "conn.log: no Zeek records found - is this a Zeek log?"


def _garbage_conn(tmp_path: Path) -> Path:
    conn = tmp_path / "conn.log"
    conn.write_text(_ZY_GARBAGE, encoding="utf-8")
    return conn


def _data_found_line(out: str) -> str:
    lines = [l for l in out.splitlines() if l.startswith("data found:")]
    assert len(lines) == 1
    return lines[0]


def test_garbage_conn_log_warns_and_banner_none(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A garbage file named conn.log: exit 0, stderr carries the per-file
    no-records warning, and the banner answers `data found: none`."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    # A clean run returns None; every error arm raises SystemExit - exit 0.
    assert cli.main(["--detect=beacon", str(_garbage_conn(tmp_path))]) is None
    captured = capsys.readouterr()
    assert _ZY_WARNING in captured.err
    assert _data_found_line(captured.out) == "data found:    none"


def test_garbage_conn_log_since_never_paints_requested_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--since on garbage: the rendered `data found:` line answers `none` -
    the requested window is never presented as found data."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    # A clean run returns None; every error arm raises SystemExit - exit 0.
    assert cli.main(
        ["--detect=beacon", "--since=7d", str(_garbage_conn(tmp_path))]
    ) is None
    captured = capsys.readouterr()
    assert _ZY_WARNING in captured.err
    assert _data_found_line(captured.out) == "data found:    none"


def test_garbage_conn_log_json_null_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--format=json on garbage: run_summary.data_window is null and the
    document parses."""
    import json

    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    assert cli.main(
        ["--detect=beacon", "--format=json", str(_garbage_conn(tmp_path))]
    ) is None
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_summary"]["data_window"] is None


@pytest.mark.parametrize("route", ["hunt", "detector", "implicit"])
def test_real_cli_json_records_exact_full_invocation(
    route: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """All three analysis entries preserve the full original argv spelling.

    This drives the real runner and JSON file sink; only config discovery is
    isolated from the developer environment.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    source_dir = tmp_path / "source with space and ' quote"
    source_dir.mkdir()
    source = _garbage_conn(source_dir)
    target = tmp_path / f"{route}.json"
    common = ["--format=json", f"--out={target}", str(source)]
    if route == "hunt":
        argv = ["hunt", "--detect=beacon", *common]
    elif route == "detector":
        argv = ["beacon", *common]
    else:
        argv = [str(source), "--detect=beacon", *common[:-1]]

    assert cli.main(argv) is None
    capsys.readouterr()
    summary = json.loads(target.read_text(encoding="utf-8"))["run_summary"]
    invocation = summary["invocation"]

    assert invocation == shlex.join(["sigwood", *argv])
    assert shlex.split(invocation) == ["sigwood", *argv]
    assert datetime.fromisoformat(summary["generated_at"]).utcoffset() is not None


def test_garbage_conn_log_html_window_none(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--format=html on garbage: the header window row reads `none`."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    assert cli.main(
        ["--detect=beacon", "--format=html", str(_garbage_conn(tmp_path))]
    ) is None
    out = capsys.readouterr().out
    assert (
        '<span class="meta-label">window</span>'
        '<span class="meta-value">none</span>'
    ) in out
