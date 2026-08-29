"""Real-CLI regressions for dnsblock with an absent implicit window."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigwood import cli
from sigwood.common import config as config_module
from sigwood.detectors import dnsblock


UTC = timezone.utc
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_demo_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    config_path: Path,
) -> tuple[object, tuple[datetime, datetime], str]:
    """Observe the real fold and prepared carrier without supplying either."""
    monkeypatch.chdir(PROJECT_ROOT)
    monkeypatch.setattr(config_module, "SEARCH_PATHS", [])
    monkeypatch.setenv("FAST_HDBSCAN_NUMBA_CACHE", "false")

    observed: dict[str, object] = {}
    real_sink_factory = dnsblock.make_anchor_block_sink
    real_run = dnsblock.run

    def observe_sink(*args, **kwargs):
        sink = real_sink_factory(*args, **kwargs)

        def observe_commit(run, delta):
            result = sink.commit_file(run, delta)
            anchor = result.anchor
            if anchor.minimum_ts is not None and anchor.maximum_ts is not None:
                observed["range"] = (
                    datetime.fromtimestamp(anchor.minimum_ts, tz=UTC),
                    datetime.fromtimestamp(anchor.maximum_ts, tz=UTC),
                )
            return result

        return replace(sink, commit_file=observe_commit)

    def observe_run(context, *, _prepared=None):
        observed["prepared"] = _prepared
        return real_run(context, _prepared=_prepared)

    monkeypatch.setattr(dnsblock, "make_anchor_block_sink", observe_sink)
    monkeypatch.setattr(dnsblock, "run", observe_run)

    cli.main([
        "hunt",
        f"--config={config_path}",
        "--detect=dnsblock",
        "--no-allowlist",
        "-q",
    ])
    captured = capsys.readouterr()

    return observed["prepared"], observed["range"], captured.out + captured.err


def test_disabled_default_uses_the_observed_archive_range_through_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    prepared, observed_range, terminal = _run_demo_cli(
        monkeypatch, capsys, PROJECT_ROOT / "demo" / "sigwood.toml"
    )

    assert "Traceback" not in terminal
    assert prepared.preflight.report_interval == observed_range


def test_configured_default_keeps_its_existing_report_interval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "sigwood.toml"
    source = (PROJECT_ROOT / "demo" / "sigwood.toml").read_text(encoding="utf-8")
    config.write_text(
        source.replace('default_window = "all"', 'default_window = "7d"'),
        encoding="utf-8",
    )

    prepared, observed_range, terminal = _run_demo_cli(
        monkeypatch, capsys, config
    )

    assert "Traceback" not in terminal
    observed_end = observed_range[1]
    assert prepared.preflight.report_interval == (
        observed_end - timedelta(days=7),
        observed_end,
    )
