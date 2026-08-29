"""Real-CLI regressions for dnsblock with an absent implicit window."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigwood import cli
from sigwood.common import config as config_module
from sigwood.detectors import dnsblock
from sigwood.parsers.syslog import parse_timestamp


UTC = timezone.utc


def _fixture_config(
    tmp_path: Path,
    *,
    default_window: str,
) -> tuple[Path, tuple[datetime, datetime]]:
    """Build a complete, clock-relative Pi-hole input under ``tmp_path``."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    anchor = datetime.now(UTC).replace(microsecond=0)
    instants = (anchor - timedelta(hours=2), anchor - timedelta(hours=1))
    lines = [
        (
            f"{instant:%b} {instant.day:2d} {instant:%H:%M:%S} "
            f"dnsmasq[1]: query[A] fixture-{index}.test from 192.0.2.10"
        )
        for index, instant in enumerate(instants, start=1)
    ]
    (pihole_dir / "pihole.log").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    parsed = [parse_timestamp(line) for line in lines]
    assert all(value is not None for value in parsed)
    extrema = sorted(value for value in parsed if value is not None)

    config = tmp_path / "sigwood.toml"
    config.write_text(
        (
            "[sigwood]\n"
            f'pihole_dir = "{pihole_dir}"\n'
            f'default_window = "{default_window}"\n'
        ),
        encoding="utf-8",
    )
    return config, (extrema[0], extrema[-1])


def _run_fixture_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    config_path: Path,
) -> tuple[object, tuple[datetime, datetime], str]:
    """Observe the real fold and prepared carrier without supplying either."""
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
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, expected_range = _fixture_config(tmp_path, default_window="all")
    prepared, observed_range, terminal = _run_fixture_cli(
        monkeypatch, capsys, config
    )

    assert "Traceback" not in terminal
    assert observed_range == expected_range
    assert prepared.preflight.report_interval == observed_range


def test_configured_default_keeps_its_existing_report_interval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, expected_range = _fixture_config(tmp_path, default_window="7d")
    prepared, observed_range, terminal = _run_fixture_cli(
        monkeypatch, capsys, config
    )

    assert "Traceback" not in terminal
    assert observed_range == expected_range
    observed_end = observed_range[1]
    assert prepared.preflight.report_interval == (
        observed_end - timedelta(days=7),
        observed_end,
    )
