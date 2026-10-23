"""Public disclosure strings across CLI planning and report boundaries."""
from __future__ import annotations

from dataclasses import replace
import json

from sigwood import cli, runner
from sigwood.detectors import syslog
from tests.test_discovery_inventory import (
    _deny_iterdir, _isolated_config, _module, _syslog_lines, _write,
)
from tests.test_runner_facade import _inputs


def _invoke(argv, tmp_path, monkeypatch, capsys, request):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    request.node.user_properties.append(("cli_argv", json.dumps(argv)))
    try:
        cli.main(argv)
    except SystemExit as exc:
        code = exc.code
    else:
        code = 0
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    return code, captured


def _partial(tmp_path, monkeypatch):
    root = tmp_path / "logs"
    _write(root / "messages", _syslog_lines(20, host="top"))
    _write(root / "child" / "messages", _syslog_lines(20, host="child"))
    denied = tmp_path / "denied"
    denied.mkdir()
    _deny_iterdir(monkeypatch, denied)
    config = _isolated_config(tmp_path, default_window="all")
    coverage = (
        f"syslog: {root} has 1 subdirectory this run did not search (child) - "
        "pass a subdirectory or its files directly to include them"
    )
    denial = (
        "syslog: directory could not be listed (permission denied) - its "
        f"contents are absent from this run ({denied})"
    )
    return root, denied, config, coverage, denial


def _summary(path):
    summary = json.loads(path.read_text())["run_summary"]
    assert all(isinstance(note, str) for note in summary["notes"])
    assert "kind" not in summary and "provenance" not in summary
    return summary


def test_dry_note_sinks_keep_exact_strings(tmp_path, monkeypatch, capsys, request):
    root, denied, config, coverage, denial = _partial(tmp_path, monkeypatch)
    code, captured = _invoke([
        "syslog", str(root), f"--syslog-dir={denied}", f"--config={config}",
        "--dry-run", "-q", "-y",
    ], tmp_path, monkeypatch, capsys, request)
    assert code == 0
    assert captured.err.splitlines().count(coverage) == 1
    assert captured.err.splitlines().count(denial) == 1
    assert captured.err.index(coverage) < captured.err.index(denial)
    assert '"findings"' not in captured.out


def test_live_note_carrier_keeps_exact_strings(tmp_path, monkeypatch, capsys, request):
    root, denied, config, coverage, denial = _partial(tmp_path, monkeypatch)
    output = tmp_path / "report.json"
    code, captured = _invoke([
        "syslog", str(root), f"--syslog-dir={denied}", f"--config={config}",
        "--all", "--format=json", f"--out={output}", "-q", "-y",
    ], tmp_path, monkeypatch, capsys, request)
    assert code == 0
    assert captured.err.splitlines().count(coverage) == 1
    notes = _summary(output)["notes"]
    assert notes.count(coverage) == notes.count(denial) == 1
    assert notes.index(coverage) < notes.index(denial)


def test_all_skipped_note_sink_keeps_exact_string(tmp_path, monkeypatch, capsys, request):
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    denied = tmp_path / "denied"
    denied.mkdir()
    _deny_iterdir(monkeypatch, denied)
    mod = _module("pair", required=[
        {"source": "zeek_dir", "pattern": "conn*.log*"},
        {"source": "syslog_dir", "pattern": "*.log*"},
    ])
    monkeypatch.setattr(runner, "select_detectors", lambda *a, **k: runner.DetectorSelection(
        {"pair": mod}, ["pair"], {},
    ))
    config = _isolated_config(tmp_path, detect="pair", default_window="all")
    code, captured = _invoke([
        "hunt", f"--zeek-dir={zeek}", f"--syslog-dir={denied}",
        f"--config={config}", "-q", "-y",
    ], tmp_path, monkeypatch, capsys, request)
    assert code == 1
    denial = (
        "syslog: directory could not be listed (permission denied) - its "
        f"contents are absent from this run ({denied})"
    )
    assert captured.err.splitlines().count(denial) == 1
    assert captured.err.index(denial) < captured.err.index("no detectors could run")


def test_unselected_note_sink_keeps_exact_string(tmp_path, monkeypatch, capsys, request):
    root = tmp_path / "logs"
    _write(root / "messages", _syslog_lines(20))
    _write(root / "messages.1", _syslog_lines(2))
    (root / "messages.2.gz").write_bytes(b"not a gzip stream\n")
    config = _isolated_config(tmp_path)
    output = tmp_path / "report.json"
    code, captured = _invoke([
        "syslog", "--recursive", str(root), "--since=2026-09-19",
        "--until=2026-09-22", f"--config={config}", "--format=json",
        f"--out={output}", "-q", "-y",
    ], tmp_path, monkeypatch, capsys, request)
    assert code == 0
    expected = (
        f"discovery: 1 file under {root} could not be read (BadGzipFile) - kept "
        "as a possible syslog file, but this run's time window did not select "
        "it (messages.2.gz)"
    )
    assert captured.err.splitlines().count(expected) == 1
    assert _summary(output)["notes"].count(expected) == 1


def test_recovered_preparation_note_ingress_keeps_exact_string(
    tmp_path, monkeypatch, capsys, request,
):
    config, *_ = _inputs(tmp_path)
    calls = []

    def injected_failure(host):
        calls.append(True)
        raise RuntimeError("oracle induced preparation failure")

    monkeypatch.setattr(syslog, "PREPARED_POPULATION", replace(
        syslog.PREPARED_POPULATION, prepare=injected_failure,
    ))
    request.node.user_properties.append(("injected_failure", "preparation RuntimeError"))
    output = tmp_path / "report.json"
    code, _ = _invoke([
        "hunt", "--detect=syslog", f"--config={config}", "--all",
        "--format=json", f"--out={output}", "-q", "-y",
    ], tmp_path, monkeypatch, capsys, request)
    assert code == 0 and calls == [True]
    summary = _summary(output)
    assert summary["detectors_failed"] == {}
    expected = (
        "syslog: prepared load failed - oracle induced preparation failure; "
        "analysis ran on the full frame"
    )
    assert summary["notes"].count(expected) == 1


def test_arbitration_note_ingress_keeps_exact_string(tmp_path, monkeypatch, capsys, request):
    config, *_ = _inputs(tmp_path)
    seen = []
    original = syslog.run

    def observe(context, **kwargs):
        seen.append((len(context.logs["*.log*"]), len(context.logs["syslog*.log*"])))
        return original(context, **kwargs)

    monkeypatch.setattr(syslog, "run", observe)
    output = tmp_path / "report.json"
    code, _ = _invoke([
        "hunt", "--detect=syslog", f"--config={config}", "--all",
        "--format=json", f"--out={output}", "-q", "-y",
    ], tmp_path, monkeypatch, capsys, request)
    assert code == 0 and seen == [(2, 0)]
    notes = _summary(output)["notes"]
    expected = (
        "system logs: 1 host carried by both the local feed and Zeek syslog.log - "
        "kept the local rows (1 Zeek row set aside)"
    )
    assert notes.count(expected) == 1
    provider = next(note for note in notes if note.startswith("system logs: files "))
    assert notes.index(provider) + 1 == notes.index(expected)
