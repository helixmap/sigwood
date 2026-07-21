"""CLI-vs-config provenance for the SIGWOOD_ROOT path rail.

CLI-supplied paths get root="" (just ~-expansion, shell semantics). Config
paths flow through ``resolve_path(value, root)`` so SIGWOOD_ROOT applies. The
provenance split must hold at every resolve site: ``_runner_kwargs``,
``_digest_runner_kwargs``, ``_build_digest_fanout_stream``, and the exporter
output cascade.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from sigwood import cli
from sigwood.common import config as cfg
from sigwood.exporters import _resolve_output_path


# ── analyze: source-dir SIGWOOD_ROOT rail ────────────────────────────────────
#
# `_runner_kwargs` does NOT resolve source dirs - it passes raw strings (or
# None) to `runner.run`, which calls `common.sources.resolve_sources`. The
# provenance rail is covered across these tests:
#
#   relative-config + SIGWOOD_ROOT  → tests/test_sources.py:
#                                      test_resolve_sources_config_relative_uses_sigwood_root
#                                      AND test_runner_run_applies_root_to_config_source_dirs (this file, below)
#   absolute-config ignores root    → covered by resolve_path's own absolute branch
#                                      (exercised indirectly by every resolver test)
#   CLI override never gets root    → tests/test_sources.py:
#                                      test_resolve_sources_relative_override_ignores_sigwood_root
#   env SIGWOOD_ROOT wins over config    → tests/test_sources.py:
#                                      test_resolve_sources_env_sigwood_root_wins_over_config


# ── analyze: --out / report_dir ──────────────────────────────────────────────


def test_runner_kwargs_relative_report_dir_resolves_against_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    root = tmp_path / "sigwood-root"
    (root / "reports").mkdir(parents=True)
    config = {"sigwood": {"root": str(root), "report_dir": "reports"}}
    kwargs = cli._runner_kwargs({}, config)
    assert kwargs["output_dir"] == root / "reports"


def test_runner_kwargs_cli_out_relative_ignores_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """--out=relative-dir/ resolves against CWD, NOT SIGWOOD_ROOT."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    config = {"sigwood": {"root": str(tmp_path / "should-not-apply")}}
    kwargs = cli._runner_kwargs({"out": "rel-cli/"}, config)
    assert kwargs["output_dir"] == Path("rel-cli")


# ── digest: _build_digest_fanout_stream is --out-only, never report_dir ──────


def test_digest_fanout_ignores_report_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Digest is fully OFF report_dir: with report_dir set and NO --out, the
    fan-out stream is stdout and opens no file (the resolver never reads config)."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    root = tmp_path / "sigwood-root"
    (root / "reports").mkdir(parents=True)
    # config is not an input to the resolver - pass parsed only.
    get_stream, close_stream, dest = cli._build_digest_fanout_stream({})
    try:
        assert dest is None
        assert get_stream() is sys.stdout
    finally:
        close_stream()
    assert list((root / "reports").iterdir()) == []


def test_digest_fanout_cli_out_relative_ignores_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """CLI --out is ~-expanded but CWD-relative (never SIGWOOD_ROOT). An explicit FILE
    verdict is the exact path."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    parsed: dict[str, Any] = {"out": str(tmp_path / "rel.txt")}
    get_stream, close_stream, dest = cli._build_digest_fanout_stream(parsed)
    try:
        assert dest == tmp_path / "rel.txt"
        fh = get_stream()
        fh.write("digest\n")
    finally:
        close_stream()
    assert (tmp_path / "rel.txt").read_bytes() == b"digest\n"


# ── exporter cascade: root applies to config tiers, "" to CLI ────────────────


def test_export_cascade_root_applies_to_sigwood_export_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Config-supplied [sigwood].export_dir is relative + root set → joined,
    then auto-segmented per source (global tier). The ``syslog`` subdir is NOT
    pre-created - the trailing-slash directory verdict resolves it regardless."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    root = tmp_path / "sigwood-root"
    (root / "exports").mkdir(parents=True)
    result = _resolve_output_path(
        {"output_basename": "syslog"}, None,
        datetime(2026, 6, 1), datetime(2026, 6, 2), "default",
        backend_config={}, sigwood_config={"export_dir": "exports"},
        root=str(root),
    )
    assert result.parent == root / "exports" / "syslog"


def test_export_cascade_cli_out_ignores_root(tmp_path: Path) -> None:
    """CLI --out resolves against CWD even when root is set."""
    cli_dir = tmp_path / "cli_out"
    result = _resolve_output_path(
        {"output_basename": "syslog"}, f"{cli_dir}/",
        datetime(2026, 6, 1), datetime(2026, 6, 2), "default",
        backend_config={"export_dir": "should-not-apply"},
        sigwood_config={"export_dir": "ignored-too"},
        root="/sigwood-root",
    )
    assert result.parent == cli_dir


# ── empty config slots cascade to CWD floor ──────────────────────────────────


# ── runner.run / run_digest - programmatic-caller config-fallback rail ──────


def test_runner_run_applies_root_to_config_source_dirs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    """Programmatic ``runner.run(config=...)`` callers must see
    SIGWOOD_ROOT applied to relative config-supplied source dirs, just like the
    CLI seam does. dry_run prints the resolved paths."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    from sigwood import runner
    runner.run(
        config={"sigwood": {
            "root": "/tmp/sigwood-root",
            "zeek_dir": "zeek",
            "syslog_dir": "syslog",
            "pihole_dir": "pihole",
            "cloudtrail_dir": "cloudtrail",
        }},
        dry_run=True,
    )
    out = capsys.readouterr().out
    assert "/tmp/sigwood-root/zeek" in out
    assert "/tmp/sigwood-root/syslog" in out
    assert "/tmp/sigwood-root/pihole" in out
    assert "/tmp/sigwood-root/cloudtrail" in out


def test_runner_run_digest_applies_root_to_config_source_dirs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    """run_digest's per-schema config fallback honors SIGWOOD_ROOT. The syslog
    branch is the one with a TWO-key fallback (syslog_dir first, then zeek);
    cloudtrail and conn each have a single-key fallback. All flow through
    resolve_path."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    from sigwood import runner

    runner.run_digest(
        config={"sigwood": {"root": "/tmp/sigwood-root", "syslog_dir": "syslog"}},
        schema="syslog",
        dry_run=True,
    )
    out = capsys.readouterr().out
    assert "/tmp/sigwood-root/syslog" in out


def test_runner_run_digest_cloudtrail_fallback_applies_root(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    from sigwood import runner

    runner.run_digest(
        config={"sigwood": {"root": "/tmp/sigwood-root", "cloudtrail_dir": "ct"}},
        schema="cloudtrail",
        dry_run=True,
    )
    out = capsys.readouterr().out
    assert "/tmp/sigwood-root/ct" in out


def test_export_cascade_empty_config_values_still_floor_to_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """resolve_path('', root) → None, but the floor is a literal '.'."""
    monkeypatch.chdir(tmp_path)
    result = _resolve_output_path(
        {"output_basename": "syslog"}, None,
        datetime(2026, 6, 1), datetime(2026, 6, 2), "default",
        backend_config={"export_dir": ""},
        sigwood_config={"export_dir": ""},
        root="/sigwood-root",
    )
    assert result.parent == Path(".")
