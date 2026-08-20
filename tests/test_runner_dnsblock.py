from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sigwood import runner
from sigwood.common.finding import MethodTag
from sigwood.common.loader import (
    AvailabilityReason,
    AvailabilityState,
    ExportAvailability,
    PROVENANCE_MANIFEST_NAME,
    PROVENANCE_SCHEMA_VERSION,
    ProvenanceEntry,
    ProvenanceManifest,
    DualWindow,
    PositionalMask,
    canonical_manifest_bytes,
    hash_file,
)
from sigwood.common.paths import private_write_bytes
import sigwood.common.loader.pipeline as pipeline
from sigwood.detectors import dnsblock


UTC = timezone.utc


def test_cadence_batch_packing_is_deterministic_and_preserves_oversize_singletons():
    pairs = (("a", "one"), ("b", "two"), ("c", "three"), ("d", "four"))
    assert runner._pack_dnsblock_cadence_batches(
        pairs,
        {pairs[0]: 4, pairs[1]: 6, pairs[2]: 11, pairs[3]: 3},
        limit=10,
    ) == ((pairs[0], pairs[1]), (pairs[2],), (pairs[3],))


def test_cadence_batch_packing_rejects_missing_or_negative_bounds():
    pair = ("a", "one")
    with pytest.raises(ValueError, match="do not conserve"):
        runner._pack_dnsblock_cadence_batches((pair,), {}, limit=10)
    with pytest.raises(ValueError, match="non-negative"):
        runner._pack_dnsblock_cadence_batches((pair,), {pair: -1}, limit=10)


def test_private_calibration_batch_shares_physical_passes_and_isolates_windows_lanes(
    tmp_path, monkeypatch,
):
    log = tmp_path / "pihole.log"
    _write_log(log)
    windows = (
        DualWindow(
            (
                datetime(2026, 1, 19, tzinfo=UTC),
                datetime(2026, 1, 21, tzinfo=UTC),
            )
        ),
        DualWindow(
            (
                datetime(2026, 1, 21, tzinfo=UTC),
                datetime(2026, 1, 22, tzinfo=UTC),
            )
        ),
    )

    def default_mask(frame):
        return PositionalMask(
            tuple(value != "query" for value in frame["event_type"])
        )

    def unsuppressed(frame):
        return PositionalMask((True,) * len(frame))

    from sigwood.common import loader

    calls = 0
    real_load = loader.load_required_logs

    def observed_load(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_load(*args, **kwargs)

    monkeypatch.setattr(loader, "load_required_logs", observed_load)
    batch = runner._prepare_dnsblock_calibration_batch(
        source_paths=(log,),
        windows=windows,
        lane_masks={"default": default_mask, "unsuppressed": unsuppressed},
        dnsblock_mod=dnsblock,
    )
    assert calls == 2  # one shared anchor/block pass + one shared population pass
    assert set(batch.prepared) == {
        (0, "default"),
        (0, "unsuppressed"),
        (1, "default"),
        (1, "unsuppressed"),
    }
    assert batch.prepared[(0, "default")].preflight.a2_rows == 0
    assert batch.prepared[(0, "unsuppressed")].preflight.a2_rows == 1
    assert batch.prepared[(1, "default")].preflight.a2_rows == 0
    assert batch.prepared[(1, "unsuppressed")].preflight.a2_rows == 0
    assert all(
        item.preflight.snapshot_identity == batch.snapshot_identity_sha256
        for item in batch.prepared.values()
    )
    assert 0 <= batch.max_window_routes <= dnsblock.LIMITS.per_window_routes
    assert 0 <= batch.max_inflight_cadence_gaps <= dnsblock.LIMITS.cadence_gaps


def test_private_calibration_batch_rejects_the_wrong_detector_identity(tmp_path):
    with pytest.raises(
        ValueError, match="calibration requires the dnsblock detector"
    ):
        runner._prepare_dnsblock_calibration_batch(
            source_paths=(tmp_path / "pihole.log",),
            windows=(
                DualWindow(
                    (
                        datetime(2026, 1, 19, tzinfo=UTC),
                        datetime(2026, 1, 21, tzinfo=UTC),
                    )
                ),
            ),
            lane_masks={"default": object(), "unsuppressed": object()},
            dnsblock_mod=SimpleNamespace(DETECTOR_NAME="dns"),
        )


def test_cross_carrier_cadence_packing_enforces_one_total_bound():
    work = (
        ((0, "default"), ("a", "one"), 4),
        ((0, "unsuppressed"), ("a", "one"), 6),
        ((1, "default"), ("b", "two"), 11),
        ((1, "unsuppressed"), ("b", "two"), 3),
    )
    assert runner._pack_dnsblock_calibration_work(work, limit=10) == (
        (work[0], work[1]),
        (work[2],),
        (work[3],),
    )


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


def _write_arrival_log(path, name="a.example.com") -> None:
    lines = []
    for day in range(1, 28):
        lines.append(
            f"Jan {day:2d} 12:00:00 resolver.example.test dnsmasq[1]: "
            "query[A] background.example.net from 192.0.2.7"
        )
    # Five distinct report periods exercise the shipped ratified arrival gate.
    for month, day in (
        ("Jan", 28),
        ("Jan", 29),
        ("Jan", 30),
        ("Jan", 31),
        ("Feb", 1),
    ):
        lines.extend(
            [
                f"{month} {day:2d} 12:00:00 resolver.example.test dnsmasq[1]: "
                f"query[A] {name} from 192.0.2.7",
                f"{month} {day:2d} 12:00:01 resolver.example.test dnsmasq[1]: "
                f"gravity blocked {name} is 0.0.0.0",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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


@pytest.mark.parametrize(
    ("suppress_blocks", "expected"),
    [
        (
            False,
            "dnsblock: blocked-name activity found, but nothing met the reporting thresholds",
        ),
        (
            True,
            "dnsblock: all block-outcome rows were removed by the allowlist",
        ),
    ],
)
def test_real_population_path_selects_honest_zero_cause(
    tmp_path, monkeypatch, suppress_blocks, expected,
):
    from sigwood.common import allowlist as allowlist_mod

    source = tmp_path / "logs"
    source.mkdir()
    _write_log(source / "pihole.log")
    config = {
        "sigwood": {"root": str(tmp_path), "warn_above": 0},
    }
    no_allowlist = True
    if suppress_blocks:
        monkeypatch.setattr(allowlist_mod, "_SHIPPED_LISTS", ())
        (source / "pihole.log").write_text(
            "Jan 20 00:00:00 resolver.example.test dnsmasq[1]: "
            "query[A] retained.example from 192.0.2.7\n"
            "Jan 20 00:00:01 resolver.example.test dnsmasq[1]: "
            "gravity blocked x.example is 0.0.0.0\n",
            encoding="utf-8",
        )
        allowlist_dir = tmp_path / "allowlist.d"
        allowlist_dir.mkdir()
        (allowlist_dir / "domains_u4").write_text("x.example\n", encoding="utf-8")
        config["allowlist"] = {
            "allowlist_dir": str(allowlist_dir),
            "domain_patterns": [],
            "connection_rules": [],
        }
        no_allowlist = False
    artifact = tmp_path / "aggregate.json"
    assert runner.run(
        config=config,
        detect="dnsblock",
        pihole_dir=source,
        since=datetime(2026, 1, 19, tzinfo=UTC),
        until=datetime(2026, 1, 21, tzinfo=UTC),
        no_allowlist=no_allowlist,
        quiet=True,
        _detector_selection=_selection(),
        _dnsblock_preflight_path=artifact,
    ) == 0
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["summary_notes"][-1] == expected
    assert payload["summary_notes"][-1] != "dnsblock: no Pi-hole query rows in the window"


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


def test_public_discovery_exposes_opt_in_dnsblock():
    assert "dnsblock" in runner.discover_detectors()
    assert "dnsblock" in runner.select_detectors("all").selected
    assert "dnsblock" not in runner.select_detectors(None).selected
    assert dnsblock.DETECTOR_METHOD == MethodTag("pattern", named=False)


def test_arrival_traverses_real_discovery_loader_runner_and_cadence(tmp_path):
    source = tmp_path / "logs"
    source.mkdir()
    _write_arrival_log(source / "pihole.log")
    output = tmp_path / "arrival.json"
    captured = {}
    real_run = dnsblock.run

    def observe(context, *, _prepared=None):
        captured["prepared"] = _prepared
        return real_run(context, _prepared=_prepared)

    original = dnsblock.run
    dnsblock.run = observe
    try:
        rc = runner.run(
            config={
                "sigwood": {
                    "root": "",
                    "warn_above": 0,
                    "default_window": "7d",
                }
            },
            detect="dnsblock",
            pihole_dir=source,
            output_format="json",
            output_file=output,
            no_allowlist=True,
            quiet=True,
            use_utc=True,
        )
    finally:
        dnsblock.run = original
    assert rc == 0
    prepared = captured["prepared"]
    assert prepared.cadence_complete is True
    assert {label for label, _seconds in prepared.preflight.pass_wall_seconds} == {
        "anchor_block",
        "population",
        "cadence",
    }
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["run_summary"]["detector_methods"] == {
        "dnsblock": {"label": "pattern", "named": False}
    }
    arrivals = [
        finding
        for finding in payload["findings"]
        if finding["evidence"].get("kind") == "arrival"
    ]
    assert len(arrivals) == 1
    assert arrivals[0]["title"] == "192.0.2.7 → example.com"


def test_u4_strong_burst_and_recurring_use_real_manifest_loader_runner_route(
    tmp_path, monkeypatch,
):
    source = tmp_path / "receipted"
    source.mkdir()
    log = source / "pihole.log"
    lines = []
    for day in range(1, 27):
        lines.append(
            f"Jan {day:2d} 12:00:00 resolver.example.test dnsmasq[1]: "
            "query[A] background.example.net from 192.0.2.7"
        )
    # Earlier activity makes the steady pair recurring rather than arrival.
    lines.append(
        "Jan 10 12:00:00 resolver.example.test dnsmasq[1]: "
        "query[A] recurring.example.org from 192.0.2.9"
    )
    # Four active periods with a 400-event peak exercise the shipped ratified
    # burst vector (400, 12, 4); this is a product-route default test.
    for day, burst_count in ((28, 5), (29, 400), (30, 5), (31, 5)):
        for second in range(burst_count):
            lines.append(
                f"Jan {day:2d} 12:{second // 60:02d}:{second % 60:02d} "
                "resolver.example.test dnsmasq[1]: query[A] "
                "burst.example.com from 192.0.2.7"
            )
        lines.append(
            f"Jan {day:2d} 12:02:00 resolver.example.test dnsmasq[1]: "
            "gravity blocked burst.example.com is 0.0.0.0"
        )
        lines.append(
            f"Jan {day:2d} 13:00:00 resolver.example.test dnsmasq[1]: "
            "query[A] recurring.example.org from 192.0.2.9"
        )
        lines.append(
            f"Jan {day:2d} 13:00:01 resolver.example.test dnsmasq[1]: "
            "gravity blocked recurring.example.org is 0.0.0.0"
        )
    lines.append(
        "Feb  1 12:00:00 resolver.example.test dnsmasq[1]: "
        "query[A] background.example.net from 192.0.2.7"
    )
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    entry = ProvenanceEntry(
        PROVENANCE_SCHEMA_VERSION,
        hash_file(log),
        log.stat().st_size,
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 2, 2, tzinfo=UTC),
        "Etc/UTC",
        None,
        "sigwood",
        "synthetic",
        "success",
    )
    private_write_bytes(
        source / PROVENANCE_MANIFEST_NAME,
        canonical_manifest_bytes(
            ProvenanceManifest(
                PROVENANCE_SCHEMA_VERSION,
                1,
                datetime(2026, 2, 2, tzinfo=UTC),
                {log.name: entry},
            )
        ),
    )
    output = tmp_path / "u4.json"
    artifact = tmp_path / "u4-aggregate.json"
    captured = {}
    real_run = dnsblock.run

    def observe(context, *, _prepared=None):
        captured["prepared"] = _prepared
        return real_run(context, _prepared=_prepared)

    monkeypatch.setattr(dnsblock, "run", observe)
    assert runner.run(
        config={
            "sigwood": {"root": "", "warn_above": 0, "default_window": "5d"}
        },
        detect="dnsblock",
        pihole_dir=source,
        output_format="json",
        output_file=output,
        no_allowlist=True,
        quiet=True,
        use_utc=True,
        _detector_selection=_selection(),
        _dnsblock_preflight_path=artifact,
    ) == 0
    prepared = captured["prepared"]
    assert prepared.preflight.coverage_lane.value == "strong"
    assert len(prepared.analysis.burst_grids) == 75
    assert len(prepared.analysis.bursts) == 1
    assert prepared.analysis.recurring.pair_count == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert [item["evidence"]["kind"] for item in report["findings"]] == [
        "burst",
        "recurring_activity",
    ]
    aggregate = json.loads(artifact.read_text(encoding="utf-8"))
    assert aggregate["channels"]["burst"]["status"] == "READY"
    assert len(aggregate["burst_grids"]) == 75
    serialized = artifact.read_text(encoding="utf-8")
    assert "192.0.2." not in serialized
    assert "burst.example" not in serialized


@pytest.mark.parametrize(
    ("pattern", "name", "force_off", "expected_arrivals", "unknown_suffix"),
    [
        (r"re:\.example\.com$", "example.com", False, 0, False),
        ("a.example.com", "b.example.com", False, 1, False),
        ("*.example.com", "b.example.com", False, 0, False),
        (
            "invalid-sigwood-suffix",
            "host.invalid-sigwood-suffix",
            False,
            1,
            True,
        ),
        (
            "unrelated.invalid-sigwood-suffix",
            '=tag<script>&".invalid-sigwood-suffix',
            False,
            1,
            True,
        ),
        ("*.example.com", "b.example.com", True, 1, False),
    ],
)
def test_matcher_parity_through_real_runner_route(
    tmp_path,
    monkeypatch,
    pattern,
    name,
    force_off,
    expected_arrivals,
    unknown_suffix,
):
    from sigwood.common import allowlist as allowlist_mod

    monkeypatch.setattr(allowlist_mod, "_SHIPPED_LISTS", ())
    source = tmp_path / "logs"
    source.mkdir()
    _write_arrival_log(source / "pihole.log", name)
    allowlist_dir = tmp_path / "allowlist.d"
    allowlist_dir.mkdir()
    (allowlist_dir / "domains_u3").write_text(pattern + "\n", encoding="utf-8")
    output = tmp_path / "report.json"
    captured = {}
    real_run = dnsblock.run

    def observe(context, *, _prepared=None):
        captured["prepared"] = _prepared
        return real_run(context, _prepared=_prepared)

    monkeypatch.setattr(dnsblock, "run", observe)
    assert runner.run(
        config={
            "sigwood": {
                "root": str(tmp_path),
                "warn_above": 0,
                "default_window": "7d",
            },
            "allowlist": {
                "allowlist_dir": str(allowlist_dir),
                "domain_patterns": [],
                "connection_rules": [],
            },
        },
        detect="dnsblock",
        pihole_dir=source,
        output_format="json",
        output_file=output,
        no_allowlist=force_off,
        quiet=True,
        use_utc=True,
        _detector_selection=_selection(),
    ) == 0
    prepared = captured["prepared"]
    assert len(prepared.analysis.arrivals) == expected_arrivals
    if expected_arrivals:
        assert prepared.analysis.arrivals[0].unknown_suffix is unknown_suffix


def test_control_bearing_name_is_dropped_on_real_loader_runner_route(tmp_path):
    source = tmp_path / "logs"
    source.mkdir()
    hostile = "bad\x00name.invalid-sigwood-suffix"
    _write_arrival_log(source / "pihole.log", hostile)
    output = tmp_path / "report.json"
    captured = {}
    real_run = dnsblock.run

    def observe(context, *, _prepared=None):
        captured["prepared"] = _prepared
        return real_run(context, _prepared=_prepared)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(dnsblock, "run", observe)
        assert runner.run(
            config={"sigwood": {"root": "", "warn_above": 0, "default_window": "7d"}},
            detect="dnsblock",
            pihole_dir=source,
            output_format="json",
            output_file=output,
            no_allowlist=True,
            quiet=True,
            use_utc=True,
            _detector_selection=_selection(),
        ) == 0

    drops = dict(captured["prepared"].preflight.drop_counts)
    assert drops["control_in_name"] >= 1
    rendered = output.read_text(encoding="utf-8")
    assert "bad\\u0000name" not in rendered


@pytest.mark.parametrize("output_format", ["text", "csv", "html", "json"])
def test_admissible_hostile_unknown_suffix_traverses_real_reading_routes(
    tmp_path,
    output_format,
):
    source = tmp_path / "logs"
    source.mkdir()
    hostile = '=tag<script>&".invalid-sigwood-suffix'
    _write_arrival_log(source / "pihole.log", hostile)
    output = tmp_path / f"report.{output_format}"
    assert runner.run(
        config={"sigwood": {"root": "", "warn_above": 0, "default_window": "7d"}},
        detect="dnsblock",
        pihole_dir=source,
        output_format=output_format,
        output_file=output,
        no_allowlist=True,
        quiet=True,
        use_utc=True,
        _detector_selection=_selection(),
    ) == 0
    rendered = output.read_text(encoding="utf-8")
    if output_format == "html":
        assert "&lt;script&gt;" in rendered
        assert "href" not in rendered
    elif output_format == "json":
        titles = [item["title"] for item in json.loads(rendered)["findings"]]
        assert any(hostile in title for title in titles)
    elif output_format == "csv":
        rows = list(csv.DictReader(io.StringIO(rendered)))
        assert any(hostile in row["finding"] for row in rows)
        assert not any(
            value.startswith(("=", "+", "-", "@", "\t", "\r"))
            for row in rows
            for value in row.values()
        )
    else:
        assert hostile in rendered
