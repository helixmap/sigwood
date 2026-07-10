"""End-to-end tests for the output-path cascade across analyze and export.

Five-tier export cascade (most-specific wins):
  1. --out (CLI)
  2. query["export_dir"]            (per-query - finest grain)
  3. backend["export_dir"]          ([export.cloudtrail].export_dir, [export.splunk].export_dir)
  4. sigwood["export_dir"]          (global default - ships ~/.sigwood/exports;
                                     auto-segments per source into <base>/<source>/)
  5. "."                            (CWD floor)

Analyze medium: stdout default; --out OR [sigwood].report_dir opts into file.
"""

from __future__ import annotations

import io
import sys
from datetime import datetime
from pathlib import Path

import pytest

from sigwood import cli
from sigwood.common import config as cfg
from sigwood.common.paths import effective_root
from sigwood.exporters import _resolve_output_path


class _FakeStdout:
    """Minimal stdout stand-in: a controllable ``isatty()`` and a binary
    ``.buffer`` - lets sigwood's pdf-destination contract decide the branch,
    not pytest's capture shape."""

    def __init__(self, *, tty: bool) -> None:
        self._tty = tty
        self.buffer = io.BytesIO()

    def isatty(self) -> bool:
        return self._tty


def _boom_import():
    raise ImportError("No module named 'weasyprint'")


# ── Export cascade - splunk-shaped (with queries) ─────────────────────────────


def test_export_tier1_cli_wins_over_all(tmp_path: Path) -> None:
    """--out beats per-query, backend, and global."""
    cli_dir = tmp_path / "cli_dir"
    query = {"export_dir": str(tmp_path / "query_dir"), "output_basename": "syslog"}
    backend = {"export_dir": str(tmp_path / "backend_dir")}
    sigwood = {"export_dir": str(tmp_path / "global_dir")}
    result = _resolve_output_path(
        query, f"{cli_dir}/", datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", backend_config=backend, sigwood_config=sigwood,
    )
    assert result.parent == cli_dir
    assert result.name == "syslog_20260601_7d.log"


def test_export_tier2_per_query_wins_over_backend_and_global(tmp_path: Path) -> None:
    """No CLI; per-query export_dir beats backend export_dir and global export_dir."""
    query = {"export_dir": str(tmp_path / "query_dir"), "output_basename": "syslog"}
    backend = {"export_dir": str(tmp_path / "backend_dir")}
    sigwood = {"export_dir": str(tmp_path / "global_dir")}
    (tmp_path / "query_dir").mkdir()  # ensure existing dir verdict
    result = _resolve_output_path(
        query, None, datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", backend_config=backend, sigwood_config=sigwood,
    )
    assert result.parent == tmp_path / "query_dir"


def test_export_tier3_backend_wins_over_global(tmp_path: Path) -> None:
    """No CLI/per-query; backend export_dir beats global export_dir."""
    query = {"output_basename": "syslog"}   # no output_dir
    backend = {"export_dir": str(tmp_path / "backend_dir")}
    sigwood = {"export_dir": str(tmp_path / "global_dir")}
    (tmp_path / "backend_dir").mkdir()
    result = _resolve_output_path(
        query, None, datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", backend_config=backend, sigwood_config=sigwood,
    )
    assert result.parent == tmp_path / "backend_dir"


def test_export_tier4_global_wins_when_only_sigwood_set(tmp_path: Path) -> None:
    """No CLI/per-query/backend; global export_dir wins AND auto-segments by
    source: the global base is <base>/<basename>/, basename "syslog"."""
    query = {"output_basename": "syslog"}
    backend = {}
    sigwood = {"export_dir": str(tmp_path / "global_dir")}
    (tmp_path / "global_dir").mkdir()
    result = _resolve_output_path(
        query, None, datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", backend_config=backend, sigwood_config=sigwood,
    )
    assert result.parent == tmp_path / "global_dir" / "syslog"


def test_export_tier5_cwd_floor_when_nothing_set(monkeypatch, tmp_path: Path) -> None:
    """All empty -> CWD floor ('.')."""
    monkeypatch.chdir(tmp_path)
    query = {"output_basename": "syslog"}
    result = _resolve_output_path(
        query, None, datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", backend_config={}, sigwood_config={},
    )
    # CWD floor: "." -> resolves to current directory, which is tmp_path
    assert result.parent == Path(".")


# ── Export cascade - cloudtrail-shaped (no per-query stanza) ─────────────────


def test_cloudtrail_cascade_backend_wins_over_global(tmp_path: Path) -> None:
    """CloudTrail's implicit-default query has no output_dir; backend wins."""
    query = {"output_basename": "cloudtrail"}   # synthetic implicit default
    backend = {"export_dir": str(tmp_path / "ct_dir")}
    sigwood = {"export_dir": str(tmp_path / "global_dir")}
    (tmp_path / "ct_dir").mkdir()
    result = _resolve_output_path(
        query, None, datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", extension=".json.log",
        backend_config=backend, sigwood_config=sigwood,
    )
    assert result.parent == tmp_path / "ct_dir"
    assert result.name == "cloudtrail_20260601_7d.json.log"


def test_cloudtrail_cascade_falls_to_global_when_no_backend_dir(tmp_path: Path) -> None:
    """Global tier wins for cloudtrail's implicit default → auto-segments to
    <base>/cloudtrail/."""
    query = {"output_basename": "cloudtrail"}
    backend = {}   # no export_dir on backend stanza
    sigwood = {"export_dir": str(tmp_path / "global_dir")}
    (tmp_path / "global_dir").mkdir()
    result = _resolve_output_path(
        query, None, datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", extension=".json.log",
        backend_config=backend, sigwood_config=sigwood,
    )
    assert result.parent == tmp_path / "global_dir" / "cloudtrail"


def test_cloudtrail_cascade_falls_to_cwd_when_nothing_set(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    query = {"output_basename": "cloudtrail"}
    result = _resolve_output_path(
        query, None, datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", extension=".json.log",
        backend_config={}, sigwood_config={},
    )
    assert result.parent == Path(".")


def test_stale_per_query_output_dir_does_not_participate(tmp_path: Path) -> None:
    """A/D negative (scoped to EXPORT config): the per-query tier now reads only
    ``export_dir``. A stale ``output_dir`` key in a query stanza is inert - the
    cascade falls through to the backend tier, NOT the stale value;
    ``output_dir`` is not a valid export-config key.

    Scoped strictly to the exporter cascade - the unrelated analyze-report
    ``output_dir`` kwarg (runner/cli) is a different function parameter and is
    untouched by this change."""
    query = {"output_dir": str(tmp_path / "stale_dir"), "output_basename": "syslog"}
    backend = {"export_dir": str(tmp_path / "backend_dir")}
    sigwood = {"export_dir": str(tmp_path / "global_dir")}
    (tmp_path / "backend_dir").mkdir()
    result = _resolve_output_path(
        query, None, datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", backend_config=backend, sigwood_config=sigwood,
    )
    # Backend tier wins (literal, no segment); stale output_dir is ignored.
    assert result.parent == tmp_path / "backend_dir"
    assert "stale_dir" not in str(result)


def test_explicit_per_query_export_dir_does_not_segment(tmp_path: Path) -> None:
    """Per-query ``export_dir`` is a LITERAL final dir - it wins over the global
    base and does NOT auto-segment by source (only tier 4 segments)."""
    query = {"export_dir": str(tmp_path / "query_dir"), "output_basename": "syslog"}
    sigwood = {"export_dir": str(tmp_path / "global_dir")}
    (tmp_path / "query_dir").mkdir()
    result = _resolve_output_path(
        query, None, datetime(2026, 6, 1), datetime(2026, 6, 8),
        "default", backend_config={}, sigwood_config=sigwood,
    )
    assert result.parent == tmp_path / "query_dir"   # NOT .../query_dir/syslog


def test_export_default_config_lands_at_shipped_export_dir(monkeypatch, tmp_path: Path) -> None:
    """Zero-config sanity: cfg.load() with no user file yields the shipped
    [sigwood].export_dir = ~/.sigwood/exports, which is reached at tier 4.

    No shipped Splunk query - the user must define one. The cascade still works
    against an empty query stanza (which is what CloudTrail's implicit default
    looks like at the orchestrator's call site)."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [tmp_path / "missing.toml"])
    config = cfg.load(config_file=None)
    sigwood_cfg = config["sigwood"]
    backend_cfg = config["export"]["splunk"]   # has no export_dir at backend level
    query_cfg = {"output_basename": "cloudtrail"}   # synthetic - no query.* shipped
    # Trailing slash on the shipped default communicates directory intent to be_like_water.
    # Post live-root flip: export_dir is now the relative "exports/" that joins to
    # root=~/.sigwood via resolve_path. Caller threads root in explicitly.
    assert sigwood_cfg["export_dir"] == "exports/"
    result = _resolve_output_path(
        query_cfg, None, datetime(2026, 5, 30), datetime(2026, 5, 31),
        "default", backend_config=backend_cfg, sigwood_config=sigwood_cfg,
        root=effective_root(config),
    )
    # Global tier (4) auto-segments per source: basename "cloudtrail".
    assert result.parent == Path("~/.sigwood/exports/cloudtrail").expanduser()


# ── Analyze medium decision ───────────────────────────────────────────────────


def test_analyze_bare_default_config_yields_stdout_mode(
    monkeypatch, tmp_path: Path,
) -> None:
    """REGRESSION GUARD: bare `sigwood <path>` on default config (no report_dir,
    no --out) yields output_dir=None and output_file=None - runner floors to stdout.
    Today's behavior must be preserved exactly."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [tmp_path / "missing.toml"])
    config = cfg.load(config_file=None)
    # No report_dir set in defaults.
    assert "report_dir" not in config["sigwood"] or not config["sigwood"].get("report_dir")
    kwargs = cli._runner_kwargs({}, config)
    assert kwargs["output_dir"] is None
    assert kwargs["output_file"] is None


def test_analyze_out_dir_with_trailing_slash_resolves_to_dir(tmp_path: Path) -> None:
    target = tmp_path / "myreports"
    kwargs = cli._runner_kwargs({"out": f"{target}/"}, config={"sigwood": {}})
    assert kwargs["output_dir"] == target
    assert kwargs["output_file"] is None


def test_analyze_out_file_with_no_trailing_slash_and_not_exists_resolves_to_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "report.html"
    kwargs = cli._runner_kwargs({"out": str(target)}, config={"sigwood": {}})
    assert kwargs["output_file"] == target
    assert kwargs["output_dir"] is None


def test_analyze_report_dir_set_no_cli_yields_path(tmp_path: Path) -> None:
    """[sigwood].report_dir set, no --out: file mode at report_dir target."""
    target = tmp_path / "reports"
    target.mkdir()    # existing dir -> Step 2 DIRECTORY verdict
    kwargs = cli._runner_kwargs(
        {}, config={"sigwood": {"report_dir": str(target)}},
    )
    assert kwargs["output_dir"] == target
    assert kwargs["output_file"] is None


def test_analyze_cli_out_overrides_report_dir(tmp_path: Path) -> None:
    """--out wins over [sigwood].report_dir."""
    cli_target = tmp_path / "cli_dir"
    config_target = tmp_path / "config_dir"
    config_target.mkdir()
    kwargs = cli._runner_kwargs(
        {"out": f"{cli_target}/"},
        config={"sigwood": {"report_dir": str(config_target)}},
    )
    assert kwargs["output_dir"] == cli_target
    assert kwargs["output_file"] is None


# ── Analyze destination: -o=- and pdf tty/preflight ordering ─────────────────


def test_analyze_dash_out_forces_stdout_over_report_dir(tmp_path: Path) -> None:
    """`-o=-` forces stdout even when [sigwood].report_dir is set."""
    rd = tmp_path / "reports"
    rd.mkdir()
    kwargs = cli._runner_kwargs({"out": "-"}, config={"sigwood": {"report_dir": str(rd)}})
    assert kwargs["output_file"] is None
    assert kwargs["output_dir"] is None


def test_analyze_pdf_tty_no_target_wins_over_missing_stack(monkeypatch) -> None:
    """pdf + no target + TTY + MISSING stack → PDF_TTY_ERROR, NOT the stack error.
    Terminal-safety wins; a missing WeasyPrint/Pango never masks it. _runner_kwargs
    raises before runner.run → before any log is read."""
    import sigwood.outputs.pdf as pdf_mod
    from sigwood.outputs.pdf import PDF_TTY_ERROR, _PDF_PIP_ERROR

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", _boom_import)
    monkeypatch.setattr(sys, "stdout", _FakeStdout(tty=True))
    with pytest.raises(ValueError) as exc:
        cli._runner_kwargs({"format": "pdf"}, config={"sigwood": {}})
    assert str(exc.value) == PDF_TTY_ERROR
    assert str(exc.value) != _PDF_PIP_ERROR  # the stack preflight never masks the tty error


def test_analyze_pdf_dash_out_tty_hits_tty_error(monkeypatch) -> None:
    """pdf + `-o=-` + TTY → the same pdf-tty error (forced stdout to a terminal)."""
    import sigwood.outputs.pdf as pdf_mod
    from sigwood.outputs.pdf import PDF_TTY_ERROR

    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", lambda html_str: b"%PDF")
    monkeypatch.setattr(sys, "stdout", _FakeStdout(tty=True))
    with pytest.raises(ValueError) as exc:
        cli._runner_kwargs({"format": "pdf", "out": "-"}, config={"sigwood": {}})
    assert str(exc.value) == PDF_TTY_ERROR


def test_analyze_pdf_pipe_no_target_reaches_preflight(monkeypatch) -> None:
    """pdf + no target + PIPE (not tty) → tty check skipped, preflight reaches the
    stack → the pip-extra message when the python package is missing (fail-fast for
    a pipe target)."""
    import sigwood.outputs.pdf as pdf_mod
    from sigwood.outputs.pdf import _PDF_PIP_ERROR

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", _boom_import)
    monkeypatch.setattr(sys, "stdout", _FakeStdout(tty=False))
    with pytest.raises(ValueError) as exc:
        cli._runner_kwargs({"format": "pdf"}, config={"sigwood": {}})
    assert str(exc.value) == _PDF_PIP_ERROR


def test_analyze_pdf_dry_run_skips_preflight_and_tty(monkeypatch) -> None:
    """--dry-run renders NO pdf (run() short-circuits), so the pdf TTY/preflight
    block must SKIP: `-f pdf --dry-run` on a tty with a MISSING stack does not
    raise - it returns kwargs so the plan can print."""
    import sigwood.outputs.pdf as pdf_mod

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", _boom_import)
    monkeypatch.setattr(sys, "stdout", _FakeStdout(tty=True))
    kwargs = cli._runner_kwargs(
        {"format": "pdf", "dry_run": True}, config={"sigwood": {}},
    )
    assert kwargs["output_format"] == "pdf"
    assert kwargs["dry_run"] is True


def test_analyze_pdf_config_derived_preflights_on_file_target(tmp_path, monkeypatch) -> None:
    """config-derived output_format=pdf (no -f) to a FILE target → tty check
    skipped, preflight reaches the stack → the pip-extra message before runner.run.
    Proves preflight covers the config-derived path, not just parsed --format."""
    import sigwood.outputs.pdf as pdf_mod
    from sigwood.outputs.pdf import _PDF_PIP_ERROR

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", _boom_import)
    with pytest.raises(ValueError) as exc:
        cli._runner_kwargs(
            {"out": str(tmp_path / "r.pdf")},
            config={"sigwood": {"output_format": "pdf"}},
        )
    assert str(exc.value) == _PDF_PIP_ERROR


# ── Multi-query guard via resolver verdict ───────────────────────────────────


def _splunk_config_with_queries(tmp_path: Path, queries: dict) -> dict:
    return {
        "sigwood": {"export_dir": str(tmp_path / "global_dir")},
        "export": {"splunk": {"host": "192.0.2.20", "port": 8089, "query": queries}},
    }


def test_multi_query_guard_fires_on_file_verdict(monkeypatch, tmp_path: Path) -> None:
    """--out=hunt.log (not exists) + 2 queries -> error keying on FILE verdict."""
    from sigwood.exporters import run_export

    config = _splunk_config_with_queries(tmp_path, {
        "a": {"spl": "search a"},
        "b": {"spl": "search b"},
    })
    target = tmp_path / "hunt.log"      # not exists -> step 3 -> FILE
    with pytest.raises(ValueError, match="explicit file path"):
        run_export(
            config=config, backend="splunk", query_names=["a", "b"],
            since=datetime(2026, 6, 1), until=datetime(2026, 6, 8),
            out=str(target), verbose=False,
        )


def test_multi_query_guard_silent_for_directory_verdict(monkeypatch, tmp_path: Path) -> None:
    """--out=hunt/ (trailing slash) + 2 queries -> no error (DIRECTORY verdict).

    We monkeypatch backend.fetch to skip the actual Splunk call.
    """
    from sigwood.exporters import run_export, splunk as splunk_module

    config = _splunk_config_with_queries(tmp_path, {
        "a": {"spl": "search a"},
        "b": {"spl": "search b"},
    })
    monkeypatch.setattr(
        splunk_module, "fetch",
        lambda *a, **kw: ([], {"units": 0, "unit_label": "chunks"}),
    )
    monkeypatch.setattr(splunk_module, "write", lambda rows, outpath, verbose: (0, {"bytes": 0, "paths": [outpath]}))

    out_dir = tmp_path / "hunt"
    # Should not raise. Multi-query in a DIRECTORY target is fine - each
    # auto-names.
    run_export(
        config=config, backend="splunk", query_names=["a", "b"],
        since=datetime(2026, 6, 1), until=datetime(2026, 6, 8),
        out=f"{out_dir}/", verbose=False,
    )


def test_multi_query_guard_silent_for_single_query_with_file_target(
    monkeypatch, tmp_path: Path,
) -> None:
    """--out=hunt.log (FILE verdict) + 1 query -> no error (gate doesn't fire)."""
    from sigwood.exporters import run_export, splunk as splunk_module

    config = _splunk_config_with_queries(tmp_path, {"a": {"spl": "search a"}})
    monkeypatch.setattr(
        splunk_module, "fetch",
        lambda *a, **kw: ([], {"units": 0, "unit_label": "chunks"}),
    )
    captured: dict = {}

    def _capture_write(rows, outpath, verbose):
        captured["outpath"] = outpath
        return 0, {"bytes": 0, "paths": [outpath]}

    monkeypatch.setattr(splunk_module, "write", _capture_write)

    target = tmp_path / "single.log"
    run_export(
        config=config, backend="splunk", query_names=["a"],
        since=datetime(2026, 6, 1), until=datetime(2026, 6, 8),
        out=str(target), verbose=False,
    )
    assert captured["outpath"] == target


# ── File-target + CloudTrail split ───────────────────────────────────────────


def test_cloudtrail_explicit_filename_no_split(tmp_path: Path) -> None:
    """Bare name when output fits under the split threshold."""
    from sigwood.exporters import cloudtrail as ct

    events = [{"eventTime": "2026-06-01T01:00:00Z", "eventName": "x"}]
    outpath = tmp_path / "hunt.json.log"
    n, _ = ct.write(events, outpath, verbose=False)
    assert n == 1
    assert outpath.exists()
    # No _part* files
    siblings = sorted(p.name for p in tmp_path.iterdir())
    assert siblings == ["hunt.json.log"]


def test_cloudtrail_explicit_filename_splits_into_part_files(
    tmp_path: Path, monkeypatch,
) -> None:
    """File target + forced split appends _partNN to the stem before all suffixes."""
    from sigwood.exporters import cloudtrail as ct

    monkeypatch.setattr(ct, "_PART_SPLIT_BYTES", 100)
    events = [
        {"eventTime": f"2026-06-01T01:00:{i:02d}Z", "eventName": "x", "i": i}
        for i in range(20)
    ]
    outpath = tmp_path / "hunt.json.log"
    ct.write(events, outpath, verbose=False)
    # Bare name should NOT remain - first split renames it to _part01.
    assert not outpath.exists()
    parts = sorted(p.name for p in tmp_path.glob("hunt_part*.json.log"))
    assert len(parts) >= 2
    assert parts[0] == "hunt_part01.json.log"


# ── orchestrator write-side liveness ─────────────────────────────────────────


from tests.test_display import _FakeStream  # noqa: E402  reuse non-tty mock


def test_orchestrator_seals_write_record_to_stderr(
    monkeypatch, tmp_path: Path, capsys,
) -> None:
    """run_export wraps backend_module.write in a liveness block; the sealed
    record lands on stderr and the existing export stdout surface is unchanged.
    """
    from sigwood.exporters import run_export, splunk as splunk_module

    config = _splunk_config_with_queries(tmp_path, {"a": {"spl": "search a"}})
    monkeypatch.setattr(
        splunk_module, "fetch",
        lambda *a, **kw: ([], {"units": 0, "unit_label": "chunks"}),
    )
    # Backend write returns a known count - no real I/O.
    monkeypatch.setattr(splunk_module, "write", lambda rows, outpath, verbose: (1234, {"bytes": 0, "paths": [outpath]}))

    fake = _FakeStream(tty=False)
    monkeypatch.setattr(sys, "stderr", fake)

    target = tmp_path / "single.log"
    run_export(
        config=config, backend="splunk", query_names=["a"],
        since=datetime(2026, 6, 1), until=datetime(2026, 6, 8),
        out=str(target), verbose=False,
    )

    # Narration rebuild: the write record lands as ONE stdout result line, NOT a
    # stderr liveness seal - no "a: wrote 1,234 lines" stderr seal.
    assert "a: wrote 1,234 lines" not in fake.output

    # stdout grammar: plain header, lowercase window line, ONE per-query result
    # line. No "running …" line, no "done · …" tally for a single query, no boxed
    # Backend/Query/Written rows.
    captured = capsys.readouterr()
    assert "sigwood export · splunk" in captured.out
    assert "window:" in captured.out
    assert "a · 1,234 lines" in captured.out
    assert "running a …" not in captured.out
    assert "done · 1 query" not in captured.out
    # No boxed-summary surface.
    assert "Backend :" not in captured.out
    assert "Query   :" not in captured.out
    assert "Written :" not in captured.out
    assert "sigwood export: running query: a" not in fake.output
    assert "Written : 1,234 lines" not in fake.output


def test_export_no_ansi_in_output(monkeypatch, tmp_path: Path, capsys) -> None:
    """Exporter narration carries NO ANSI escape codes - plain text only."""
    from sigwood.exporters import run_export, splunk as splunk_module

    config = _splunk_config_with_queries(tmp_path, {"a": {"spl": "search a"}})
    monkeypatch.setattr(
        splunk_module, "fetch",
        lambda *a, **kw: ([], {"units": 0, "unit_label": "chunks"}),
    )
    monkeypatch.setattr(
        splunk_module, "write",
        lambda rows, outpath, verbose: (100, {"bytes": 0, "paths": [outpath]}),
    )

    target = tmp_path / "single.log"
    run_export(
        config=config, backend="splunk", query_names=["a"],
        since=datetime(2026, 6, 1), until=datetime(2026, 6, 8),
        out=str(target), verbose=False,
    )
    out = capsys.readouterr().out
    assert "\x1b[" not in out


def test_export_multi_query_totals_line(monkeypatch, tmp_path: Path, capsys) -> None:
    """With multiple queries, the final ``done · N queries · …`` line
    aggregates lines + bytes across them."""
    from sigwood.exporters import run_export, splunk as splunk_module

    config = _splunk_config_with_queries(
        tmp_path, {"a": {"spl": "search a"}, "b": {"spl": "search b"}}
    )
    monkeypatch.setattr(
        splunk_module, "fetch",
        lambda *a, **kw: ([], {"units": 0, "unit_label": "chunks"}),
    )

    def _write(rows, outpath, verbose):
        return 100, {"bytes": 4096, "paths": [outpath]}

    monkeypatch.setattr(splunk_module, "write", _write)

    run_export(
        config=config, backend="splunk", query_names=["a", "b"],
        since=datetime(2026, 6, 1), until=datetime(2026, 6, 8),
        out=None, verbose=False,
    )
    out = capsys.readouterr().out
    # Aggregated totals: 2 queries · 200 lines · 8 KB-ish.
    assert "done · 2 queries · 200 lines" in out


def test_export_cloudtrail_split_renders_plus_K_more(
    monkeypatch, tmp_path: Path, capsys,
) -> None:
    """CloudTrail split: when write_meta carries multiple paths the
    result line reads ``→ <first_part> (+K more)`` with K = len(paths) - 1."""
    from sigwood.exporters import run_export
    from sigwood.exporters import cloudtrail as ct_module
    from sigwood.exporters import splunk as splunk_module

    config = _splunk_config_with_queries(tmp_path, {"only": {"spl": "search x"}})
    monkeypatch.setattr(
        splunk_module, "fetch",
        lambda *a, **kw: ([], {"units": 0, "unit_label": "chunks"}),
    )

    def _split_write(rows, outpath, verbose):
        # Simulate a 3-part split: bytes summed across parts; paths is the
        # ordered list the orchestrator reads.
        parts = [
            outpath.with_name(outpath.stem + "_part01.log"),
            outpath.with_name(outpath.stem + "_part02.log"),
            outpath.with_name(outpath.stem + "_part03.log"),
        ]
        return 7_000_000, {"bytes": 6_000_000_000, "paths": parts}

    monkeypatch.setattr(splunk_module, "write", _split_write)

    run_export(
        config=config, backend="splunk", query_names=["only"],
        since=datetime(2026, 6, 1), until=datetime(2026, 6, 8),
        out=None, verbose=False,
    )
    out = capsys.readouterr().out
    assert "(+2 more)" in out
    # Bytes are summed (~5.6 GB).
    assert "GB" in out


def test_export_streams_per_query_fetch_then_write(
    monkeypatch, tmp_path: Path,
) -> None:
    """Each query streams ``fetch → write`` in turn; the first
    query's ``write`` MUST complete before the second query's ``fetch``
    begins. This preserves partial-success durability and bounds peak
    memory to one query's result set."""
    from sigwood.exporters import run_export, splunk as splunk_module

    config = _splunk_config_with_queries(
        tmp_path, {"a": {"spl": "search a"}, "b": {"spl": "search b"}}
    )

    call_log: list[str] = []

    def _fetch(query_config, *a, **kw):
        # Tag every fetch with the SPL string so we can assert ordering.
        call_log.append(f"fetch:{query_config['spl']}")
        return ([], {"units": 0, "unit_label": "chunks"})

    # `current_query` tracks which query's fetch most recently fired so
    # `_write` can label itself with the right name even when both queries
    # land in the same output directory (the shared `global_dir` shape from
    # this test's fixture).
    current_query: dict[str, str] = {}

    def _fetch_tracking(query_config, *a, **kw):
        for tag in ("a", "b"):
            if query_config.get("spl", "").endswith(tag):
                current_query["name"] = tag
        return _fetch(query_config, *a, **kw)

    def _write(rows, outpath, verbose):
        call_log.append(f"write:{current_query.get('name', '?')}")
        return 0, {"bytes": 0, "paths": [outpath]}

    monkeypatch.setattr(splunk_module, "fetch", _fetch_tracking)
    monkeypatch.setattr(splunk_module, "write", _write)

    run_export(
        config=config, backend="splunk", query_names=["a", "b"],
        since=datetime(2026, 6, 1), until=datetime(2026, 6, 8),
        out=None, verbose=False,
    )

    # Streaming order: fetch a, write a, fetch b, write b. The first
    # `write` MUST happen before the second `fetch` so an export remains
    # streaming and partial-success-durable.
    assert call_log == [
        "fetch:search a",
        "write:a",
        "fetch:search b",
        "write:b",
    ], call_log
