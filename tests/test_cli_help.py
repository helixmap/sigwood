"""Per-command help, side-effect-light help short-circuit, and a few other
parser-surface invariants that don't fit the verb-specific suites.

Key promises locked here:
  - ``sigwood <verb> --help`` / ``-h`` renders that verb's own generated help.
  - Help fires BEFORE config load, output-registry lookup, sniff dispatch, or
    init wizard entry.
  - ``--help=anything`` and ``-h=anything`` are NOT help - they raise the
    strict-parser "takes no value" error.
  - ``sigwood conn.log`` (a real file in CWD) resolves as a path, not as an
    unknown command.
  - ``--format=FORMAT`` validates via the registered output handler list.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sigwood import cli
from sigwood.common import config as cfg


# ── per-command help renders from the spec ───────────────────────────────────


@pytest.mark.parametrize("verb", [
    "hunt", "beacon", "dns", "syslog", "scan", "duration", "aws",
    "digest", "graph", "export", "init",
])
def test_render_verb_help_lists_verb_allowed_flags(verb: str) -> None:
    """Every flag in a verb's allowed set appears in its rendered help, and
    no flag from outside the allowed set leaks in."""
    rendered = cli._render_verb_help(verb)
    vs = cli._VERBS[verb]
    for spec in cli._FLAG_LIST:
        if spec.key in vs.allowed:
            assert spec.long in rendered, (
                f"{spec.long} should be in {verb!r} help"
            )
            if spec.short:
                assert f"-{spec.short}" in rendered
        else:
            assert spec.long not in rendered, (
                f"{spec.long} should NOT be in {verb!r} help"
            )


def test_render_verb_help_blob_path_never_appears() -> None:
    """``blob_path`` is an INTERNAL routing key - must not appear in any
    rendered help. Padding the spec/allowed-set with it would silently mint
    an unadvertised ``--blob-path`` ([[feedback-cli-surface-discipline]])."""
    for verb in cli._VERBS:
        rendered = cli._render_verb_help(verb)
        assert "blob_path" not in rendered
        assert "--blob-path" not in rendered
        assert "-blob-path" not in rendered


def test_graph_kind_help_literals_track_supported_kinds() -> None:
    from sigwood.common.sources import graph_supported_kinds

    expected = (
        "[" + "|".join(graph_supported_kinds()) + "] [PATH ...]"
    )

    assert cli._VERBS["graph"].positional_shape == expected
    assert (
        f"sigwood graph [options] {expected} "
        "replay-oriented conn/DNS/Pi-hole HTML artifact"
    ) in cli._global_usage_text()


def test_init_help_only_lists_help(capsys: pytest.CaptureFixture[str]) -> None:
    """init's allowed set is ``{help}`` - its rendered help mentions
    ``--help`` and nothing else from the spec."""
    rendered = cli._render_verb_help("init")
    assert "--help" in rendered
    for spec in cli._FLAG_LIST:
        if spec.key != "help":
            assert spec.long not in rendered


# ── side-effect-light help: no config load, no sniff, no wizard ──────────────


def test_verb_help_does_not_load_config(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``<verb> --help`` short-circuits BEFORE cfg.load is called."""
    def _exploding_load(_path=None):  # pragma: no cover - would only run on failure
        raise RuntimeError("config must not load during help")

    monkeypatch.setattr(cfg, "load", _exploding_load)
    for argv in (
        ["beacon", "--help"], ["beacon", "-h"],
        ["digest", "--help"], ["digest", "-h"],
        ["graph", "--help"], ["graph", "-h"],
        ["export", "--help"], ["init", "--help"],
        ["--help"], ["-h"],
    ):
        rc = cli._main(argv)
        assert rc == 0
        capsys.readouterr()


def test_init_help_does_not_start_wizard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``init -h`` must NOT enter the wizard (no run_init call, no input())."""
    called = {"wizard": False}

    def _spy_run_init():  # pragma: no cover - would only run on failure
        called["wizard"] = True

    monkeypatch.setattr("sigwood.cli_init.run_init", _spy_run_init)

    rc = cli._main(["init", "-h"])

    assert rc == 0
    assert called["wizard"] is False
    out = capsys.readouterr().out
    assert "Usage: sigwood init" in out


def test_digest_help_does_not_sniff(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """``digest --help`` must NOT call sniff_format_detailed even when a
    positional is also passed."""
    called = {"sniffed": False}

    def _spy_sniff(_path):  # pragma: no cover - would only run on failure
        called["sniffed"] = True
        raise RuntimeError("sniff must not run during help")

    monkeypatch.setattr(
        "sigwood.common.loader.sniff_format_detailed", _spy_sniff,
    )
    pretend = tmp_path / "anything.log"
    pretend.write_text("placeholder\n", encoding="utf-8")

    rc = cli._main(["digest", str(pretend), "--help"])

    assert rc == 0
    assert called["sniffed"] is False


def test_help_with_format_bogus_short_circuits_before_registry(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--help --format=bogus`` shows usage; the output registry is NEVER
    consulted - the help short-circuit wins."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])

    def _exploding_get_handler(_name):  # pragma: no cover
        raise RuntimeError("registry must not run during help")

    monkeypatch.setattr("sigwood.cli.get_handler", _exploding_get_handler)

    rc = cli._main(["beacon", "--help", "--format=bogus"])

    assert rc == 0


# ── --help=anything / -h=anything are NOT help ───────────────────────────────


def test_help_with_value_raises_takes_no_value(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--help=foo`` is a value-on-bool error from the strict parser, not
    a help short-circuit."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit):
        cli.main(["--help=foo"])
    err = capsys.readouterr().err
    assert "--help (-h) takes no value" in err


def test_short_help_with_value_raises_takes_no_value(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit):
        cli.main(["-h=foo"])
    err = capsys.readouterr().err
    assert "--help (-h) takes no value" in err


# ── sigwood conn.log (bare filename in CWD) ────────────────────────────────


def test_bare_filename_in_cwd_routes_as_analyze_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A token that exists on disk routes to the analyze path (not 'unknown
    command') even when it lacks the path-shape prefixes."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.chdir(tmp_path)

    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.runner.run", fake_run)

    (tmp_path / "conn.log").write_text("", encoding="utf-8")

    cli._main(["conn.log"])

    # CLI now passes raw strings; the resolver owns Path conversion.
    assert captured.get("zeek_dir") == "conn.log"


def test_mistyped_filename_reports_not_found_not_unknown_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A NONEXISTENT token carrying a file extension is a filename attempt, not a
    verb typo: it routes to the hunt so the positional-existence owner reports
    ``<path>: not found``. A verb-shaped typo (no extension) still reports
    ``unknown command``."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.chdir(tmp_path)  # nope.log does NOT exist here

    # filename-shaped → routes to hunt → the not-found owner raises (cli.main renders it)
    with pytest.raises(ValueError, match=r"nope\.log: not found"):
        cli._main(["nope.log"])

    # verb-shaped typo (no extension) → stays 'unknown command' (a sys.exit path)
    with pytest.raises(SystemExit):
        cli._main(["huntt"])
    assert "unknown command 'huntt'" in capsys.readouterr().err


# ── --format=FORMAT validation via the registry ──────────────────────────────


def test_unknown_output_format_raises_with_available_list(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """``--format=bogus`` raises a CLI-formatted error with the registry's
    live available-format list, not a hardcoded one.

    Intent-bearing invocation (a positional) - under the hunt verb, source-dir
    flags alone are not sufficient intent, so this proves the registry
    error contract survives format validation on a real run, not the no-target
    guard. ``get_handler`` precedes config load / path existence, so the
    registry error wins regardless of the empty fixture file."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    conn = zeek_dir / "conn.log"
    conn.write_text("", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        cli.main([str(conn), "--format=bogus"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "unknown output format 'bogus'" in err
    assert "available:" in err
    # Built-in handlers must surface
    for fmt in ("text", "json", "csv", "html", "pdf"):
        assert fmt in err


def test_digest_unknown_output_format_uses_same_registry_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Digest validates --format via the same registry - uniform error voice.
    Registry check happens BEFORE digest's text-only rail, so ``--format=bogus``
    reports 'Unknown output format', not 'currently supports only text'."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    log = tmp_path / "x.log"
    log.write_text("", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        cli.main(["digest", str(log), "--format=bogus"])

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "unknown output format 'bogus'" in err


# ── export positionals come from the parser ──────────────────────────────────


def test_export_positionals_come_from_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``sigwood export splunk q1 q2`` consumes positionals from the
    parser's ``paths`` list, not by re-scraping raw args."""
    captured: dict = {}

    def fake_run_export(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.exporters.run_export", fake_run_export)
    monkeypatch.setattr(cfg, "load", lambda _=None: {
        "export": {"splunk": {"host": "192.0.2.20", "port": 8089,
                              "query": {"q1": {"spl": "x"}, "q2": {"spl": "y"}}}},
    })

    cli.main(["export", "splunk", "q1", "q2"])

    assert captured["backend"] == "splunk"
    assert captured["query_names"] == ["q1", "q2"]


# ── digest combination guard (preserved) ─────────────────────────────────────


def test_digest_path_plus_zeek_dir_still_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``digest PATH --zeek-dir=…`` is rejected (positional self-routes via
    sniff). Bare digest with --zeek-dir is allowed - that's the bare-conn
    config-driven path."""
    monkeypatch.setattr(cfg, "load", lambda _=None: {"sigwood": {}})
    log = tmp_path / "x.log"
    log.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="--zeek-dir is not valid alongside"):
        cli._main(["digest", str(log), "--zeek-dir=/x"])


# ── bare short-form value flag mentions both spellings ───────────────────────


def test_bare_short_value_flag_short_lead_message(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bare short value flag (``-o``) raises the actionable error mentioning
    both ``-o=…`` and ``--out=…``."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit) as exc:
        cli.main(["-o"])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "sigwood: --out (-o) needs a value: -o=… or --out=…" in err


# ── --detect/-d on single-detector verbs raises wrong-verb ───────────────────


def test_detect_on_single_detector_verb_raises_wrong_verb(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit) as exc:
        cli.main(["beacon", "--detect=all"])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "--detect (-d) is not valid for beacon" in err


def test_short_detect_on_single_detector_verb_raises_wrong_verb(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    with pytest.raises(SystemExit) as exc:
        cli.main(["beacon", "-d=all"])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "-d (--detect) is not valid for beacon" in err


def test_export_naive_since_follows_config_knob(
    monkeypatch: pytest.MonkeyPatch, pin_tz, restore_display_utc,
) -> None:
    """Config loads BEFORE the timeframe on the export path: a naive --since
    reads per [sigwood].use_utc (UTC midnight vs local midnight - manual
    -6h arithmetic under the pinned zone), and the SAME resolved bool is
    threaded to run_export."""
    from datetime import datetime, timezone

    pin_tz("Etc/GMT+6")
    captured: dict = {}

    def fake_run_export(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("sigwood.exporters.run_export", fake_run_export)
    base = {"export": {"splunk": {"host": "192.0.2.20", "port": 8089,
                                  "query": {"q1": {"spl": "x"}}}}}

    monkeypatch.setattr(cfg, "load", lambda _=None: {
        **base, "sigwood": {"use_utc": True},
    })
    cli.main(["export", "splunk", "q1", "--since=2026-05-01"])
    assert captured["since"] == datetime(2026, 5, 1, 0, 0, tzinfo=timezone.utc)
    assert captured["use_utc"] is True

    monkeypatch.setattr(cfg, "load", lambda _=None: {
        **base, "sigwood": {"use_utc": False},
    })
    cli.main(["export", "splunk", "q1", "--since=2026-05-01"])
    assert captured["since"] == datetime(2026, 5, 1, 6, 0, tzinfo=timezone.utc)
    assert captured["use_utc"] is False
