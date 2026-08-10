from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sigwood import runner
from sigwood.common.loader import (
    AvailabilityReason,
    AvailabilityState,
    ExportAvailability,
)
import sigwood.common.loader.pipeline as pipeline
from sigwood.detectors import dnsblock


UTC = timezone.utc


def _selection() -> runner.DetectorSelection:
    return runner.DetectorSelection(
        {"dnsblock": dnsblock},
        ["dnsblock"],
        {},
        vocab={"dnsblock": {}},
    )


def _write_log(path) -> None:
    path.write_text(
        "Jan 20 00:00:00 resolver.example.test dnsmasq[1]: "
        "query[A] x.example from 192.0.2.7\n"
        "Jan 20 00:00:01 resolver.example.test dnsmasq[1]: "
        "gravity blocked x.example is 0.0.0.0\n",
        encoding="utf-8",
    )


def test_injected_planned_detector_traverses_runner_and_receives_preflight(
    tmp_path, monkeypatch,
):
    log = tmp_path / "pihole.log"
    _write_log(log)
    captured = {}
    real_run = dnsblock.run

    def observe(context, *, _prepared=None):
        captured["prepared"] = _prepared
        return real_run(context, _prepared=_prepared)

    monkeypatch.setattr(dnsblock, "run", observe)
    rc = runner.run(
        config={"sigwood": {"root": "", "warn_above": 0}},
        detect="dnsblock",
        pihole_dir=log,
        since=datetime(2026, 1, 19, tzinfo=UTC),
        until=datetime(2026, 1, 21, tzinfo=UTC),
        quiet=True,
        _detector_selection=_selection(),
    )
    assert rc == 0
    assert isinstance(captured["prepared"], dnsblock.DnsblockPrepared)
    assert captured["prepared"].preflight.snapshot_identity
    assert {label for label, _seconds in captured["prepared"].preflight.pass_wall_seconds} == {
        "anchor_block",
        "population",
    }


def test_dnsblock_only_passes_never_retain_a_second_frame(
    tmp_path, monkeypatch,
):
    log = tmp_path / "pihole.log"
    _write_log(log)
    preserve = []
    real_fold = pipeline.run_folded_source

    def observe(*args, **kwargs):
        preserve.append(args[4].preserve_frame)
        return real_fold(*args, **kwargs)

    monkeypatch.setattr(pipeline, "run_folded_source", observe)
    assert runner.run(
        config={"sigwood": {"root": "", "warn_above": 0}},
        detect="dnsblock",
        pihole_dir=log,
        since=datetime(2026, 1, 19, tzinfo=UTC),
        until=datetime(2026, 1, 21, tzinfo=UTC),
        quiet=True,
        _detector_selection=_selection(),
    ) == 0
    assert preserve == [False, False]


def test_no_allowlist_uses_zero_copy_keep_mask(tmp_path, monkeypatch):
    log = tmp_path / "pihole.log"
    _write_log(log)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("--no-allowlist must not copy/filter each folded chunk")

    monkeypatch.setattr(runner, "_positional_allowlist_mask", forbidden)
    assert runner.run(
        config={"sigwood": {"root": "", "warn_above": 0}},
        detect="dnsblock",
        pihole_dir=log,
        since=datetime(2026, 1, 19, tzinfo=UTC),
        until=datetime(2026, 1, 21, tzinfo=UTC),
        no_allowlist=True,
        quiet=True,
        _detector_selection=_selection(),
    ) == 0


def test_mixed_pihole_sibling_receives_one_ordinary_final_frame(tmp_path):
    log = tmp_path / "pihole.log"
    _write_log(log)
    seen = {}

    def sibling_run(context):
        seen["rows"] = len(context.logs["pihole*.log*"])
        seen["events"] = context.logs["pihole*.log*"]["event_type"].tolist()
        return []

    sibling = SimpleNamespace(
        DETECTOR_NAME="sibling",
        STATUS="available",
        REQUIRED_LOGS=[{"source": "pihole_dir", "pattern": "pihole*.log*"}],
        OPTIONAL_LOGS=[],
        DEFAULT_CONFIG={},
        run=sibling_run,
    )
    selection = runner.DetectorSelection(
        {"dnsblock": dnsblock, "sibling": sibling},
        ["dnsblock", "sibling"],
        {},
        vocab={"dnsblock": {}, "sibling": {}},
    )
    assert runner.run(
        config={"sigwood": {"root": "", "warn_above": 0}},
        detect="dnsblock,sibling",
        pihole_dir=log,
        since=datetime(2026, 1, 19, tzinfo=UTC),
        until=datetime(2026, 1, 21, tzinfo=UTC),
        quiet=True,
        _detector_selection=selection,
    ) == 0
    assert seen == {"rows": 2, "events": ["query", "gravity_blocked"]}


def test_final_population_validation_is_the_only_coverage_source(
    tmp_path, monkeypatch,
):
    log = tmp_path / "pihole.log"
    _write_log(log)
    start = datetime(2026, 1, 10, tzinfo=UTC)
    end = datetime(2026, 1, 21, tzinfo=UTC)
    calls = 0

    def changing_validation(files):
        nonlocal calls
        calls += 1
        path = list(files)[0]
        # The first combined pass disagrees; final population validation wins.
        if calls == 1:
            return (
                ExportAvailability(
                    path,
                    AvailabilityState.UNKNOWN,
                    AvailabilityReason.MANIFEST_UNREADABLE,
                ),
            )
        return (
            ExportAvailability(
                path,
                AvailabilityState.TRUSTED,
                AvailabilityReason.TRUSTED,
                (start - timedelta(days=30), end),
            ),
        )

    monkeypatch.setattr(pipeline, "validate_selected_files", changing_validation)
    captured = {}
    real_run = dnsblock.run

    def observe(context, *, _prepared=None):
        captured["prepared"] = _prepared
        return real_run(context, _prepared=_prepared)

    monkeypatch.setattr(dnsblock, "run", observe)
    assert runner.run(
        config={"sigwood": {"root": "", "warn_above": 0}},
        detect="dnsblock",
        pihole_dir=log,
        quiet=True,
        _detector_selection=_selection(),
    ) == 0
    assert calls == 2
    assert captured["prepared"].preflight.coverage_lane.value == "strong"


def test_first_pass_timing_survives_population_failure(tmp_path, monkeypatch):
    log = tmp_path / "pihole.log"
    _write_log(log)
    artifact = tmp_path / "progress.json"
    import sigwood.common.loader as loader_package

    real_load = loader_package.load_required_logs
    calls = 0

    def fail_population(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("synthetic population timeout")
        return real_load(*args, **kwargs)

    monkeypatch.setattr(loader_package, "load_required_logs", fail_population)
    with pytest.raises(RuntimeError, match="synthetic population timeout"):
        runner.run(
            config={"sigwood": {"root": "", "warn_above": 0}},
            detect="dnsblock",
            pihole_dir=log,
            since=datetime(2026, 1, 19, tzinfo=UTC),
            until=datetime(2026, 1, 21, tzinfo=UTC),
            quiet=True,
            _detector_selection=_selection(),
            _dnsblock_preflight_path=artifact,
        )
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["preflight"]["state"] == "IN_PROGRESS"
    assert payload["preflight"]["cause"] == "population pass in progress"
    assert payload["preflight"]["pass_wall_seconds"][0][0] == "anchor_block"


def test_public_discovery_does_not_expose_planned_dnsblock():
    assert "dnsblock" not in runner.discover_detectors()
