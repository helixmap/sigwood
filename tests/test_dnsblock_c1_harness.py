from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest

from tests.dnsblock_repeat_fixture import (
    BACKGROUND_NAME,
    FAMILY_KEY,
    Q_A_NAMES,
    Q_B_NAMES,
    QUALIFIED_NAMES,
    anchor_for,
    write_repeat_fixture,
)
from sigwood.detectors import dnsblock
from sigwood.parsers.syslog import parse_timestamp
from tools import dnsblock_c1_harness as harness


ROOT = Path(__file__).resolve().parents[1]


def _in_git_work_tree() -> bool:
    """Whether the harness can resolve its own source commit from ROOT.

    The harness records `source_head` as measurement provenance and fails closed
    when it cannot, so an artifact never claims a measurement without naming the
    commit that produced it. A tracked-file export (the release runbook builds
    one with `git archive`) carries no repository, and `tools/` is not part of
    the distribution, so the harness is out of scope there rather than broken.
    """
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        ).returncode == 0
    except OSError:
        return False


requires_git_work_tree = pytest.mark.skipif(
    not _in_git_work_tree(),
    reason="harness source_head provenance needs a git work tree",
)


def _utc_interval(window):
    return [value.replace("Z", "+00:00") for value in window]


def _repeat_preflight_counts(result):
    preflight = result["aggregate"]["preflight"]
    events = dict(preflight["raw_event_counts"])
    return preflight["a1_rows"], preflight["a2_rows"], events


def _route_counts(rows):
    return dict(rows)


def _assert_r12_route_preconditions(result):
    aggregate = result["aggregate"]
    preflight = aggregate["preflight"]
    observed = {
        "name_routes": _route_counts(preflight["name_routes"]),
        "historical_grid": preflight["grids"][4],
        "history_21_grid": preflight["grids"][5],
        "ratified_grid": preflight["grids"][11],
        "final_shape_routes": _route_counts(aggregate["final_shape_routes"]),
    }
    assert preflight["coverage_lane"] == "weak", observed
    assert observed["name_routes"] == {
        "prior_address_query": 1,
        "qualifying": 5,
    }, observed
    assert observed["historical_grid"]["days_required"] == 3, observed
    assert observed["historical_grid"]["history_required"] == 14, observed
    assert observed["historical_grid"]["qualifying_pairs"] == 1, observed
    assert _route_counts(observed["historical_grid"]["route_counts"]) == {
        "qualifying": 1
    }, observed
    # The serialized preflight does not expose the routing result's private
    # max_history_periods field.  A qualifying days=3/history=21 cell proves
    # the required >=21 history floor through the public grid instead.
    assert observed["history_21_grid"]["days_required"] == 3, observed
    assert observed["history_21_grid"]["history_required"] == 21, observed
    assert observed["history_21_grid"]["qualifying_pairs"] == 1, observed
    assert observed["ratified_grid"]["days_required"] == 5, observed
    assert observed["ratified_grid"]["history_required"] == 21, observed
    assert observed["ratified_grid"]["qualifying_pairs"] == 0, observed
    assert _route_counts(observed["ratified_grid"]["route_counts"]) == {
        "insufficient_active_periods": 1
    }, observed
    assert observed["final_shape_routes"] == {
        "neither": 0,
        "arrival_only": 1,
        "burst_only": 0,
        "overlap_burst_wins": 0,
    }, observed
    return observed


@requires_git_work_tree
def test_dnsblock_repeat_generated_fixture_uses_real_series_harness(tmp_path):
    previous_tz = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    if hasattr(time, "tzset"):
        time.tzset()
    try:
        now = datetime.now()
        fixture = write_repeat_fixture(tmp_path, anchor_for(now))
        first_year = parse_timestamp(fixture.first_stamp).year
        last_year = parse_timestamp(fixture.last_stamp).year
        assert first_year == last_year, (first_year, last_year)
        assert fixture.log.parent == tmp_path
        assert len(Q_A_NAMES) == len(Q_B_NAMES) == 5
        assert QUALIFIED_NAMES == Q_A_NAMES + Q_B_NAMES
        for name in (BACKGROUND_NAME, *QUALIFIED_NAMES):
            assert dnsblock._family(name) == (FAMILY_KEY, False)

        observed_repeat = {}
        observed_final_routes = {}
        for shape, batch_size in (("stepped", 4), ("single", 2), ("disjoint", 2)):
            artifact = tmp_path / f"{shape}-artifact.json"
            run = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "dnsblock_c1_harness.py"),
                    "--pihole-dir",
                    str(fixture.log),
                    "--artifact",
                    str(artifact),
                    "--series-request",
                    str(fixture.requests[shape]),
                    "--series-batch-size",
                    str(batch_size),
                    # The sealed C1 W-SHIFT campaign measured vector (3,14),
                    # while the shipped default is now (5,21). State the
                    # historical instrument explicitly here; see artifact
                    # 208de1daa4ebdfe4c4fd96b5ed79085706c292bca94088a2a91044b1587c99a4
                    # in the unit diagnosis.
                    "--arrival-days",
                    "3",
                    "--arrival-history",
                    "14",
                    "--output-format",
                    "json",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            assert run.returncode == 0, run.stderr
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            assert payload["series"]["allowlist_lanes"] == [
                "default",
                "unsuppressed",
            ]
            expected_windows = fixture.windows[shape]
            assert len(payload["results"]) == len(expected_windows) * 2
            by_window = {}
            for result in payload["results"]:
                ordinal = result["window_ordinal"]
                expected = expected_windows[ordinal]
                assert result["report_interval"] == _utc_interval(
                    (expected["start"], expected["end"])
                )
                assert result["context_interval"] == _utc_interval(
                    (expected["context_start"], expected["context_end"])
                )
                a1_rows, a2_rows, events = _repeat_preflight_counts(result)
                assert events["query"] - a1_rows == events["gravity_blocked"] - a2_rows
                routes = _assert_r12_route_preconditions(result)
                assert result["aggregate"]["channels"] == {
                    "burst": {
                        "status": "ABSTAINED",
                        "cause": "weak_coverage",
                        # Arrival stays on historical (3,14); burst follows the
                        # newly shipped active-period requirement.
                        "periods_required": 4,
                        "eligible_periods": 7,
                    },
                    "recurring": {
                        "status": "ABSTAINED",
                        "cause": "weak_coverage",
                    },
                }
                by_window.setdefault(ordinal, []).append(
                    (
                        result["allowlist_lane"],
                        a1_rows,
                        a2_rows,
                        events,
                        routes,
                    )
                )
            for ordinal, lane_facts in by_window.items():
                assert {lane for lane, *_facts in lane_facts} == {
                    "default",
                    "unsuppressed",
                }
                assert len(
                    {
                        (
                            a1,
                            a2,
                            tuple(sorted(events.items())),
                            json.dumps(routes, sort_keys=True),
                        )
                        for _, a1, a2, events, routes in lane_facts
                    }
                ) == 1
            observed_repeat[shape] = payload["repeat_burden"]
            observed_final_routes[shape] = [
                lane_facts[0][4]["final_shape_routes"]
                for lane_facts in by_window.values()
            ]

        # The r12 calendar reproduces the C1 campaign's explicit (3,14)
        # final-shape vector. The shipped (5,21) grid is retained above as a
        # public observable, not substituted into the historical measurement.
        assert {
            shape: result["maximum_observed"]
            for shape, result in observed_repeat.items()
        } == {"stepped": 4, "single": 1, "disjoint": 2}
        assert all(
            routes == {"neither": 0, "arrival_only": 1, "burst_only": 0,
                       "overlap_burst_wins": 0}
            for by_shape in observed_final_routes.values()
            for routes in by_shape
        )
        assert {
            shape: (
                result["violating_identities"],
                result["violation"],
            )
            for shape, result in observed_repeat.items()
        } == {
            "stepped": (1, "arrival_or_mixed"),
            "single": (0, None),
            "disjoint": (0, None),
        }

        batch_two_artifact = tmp_path / "stepped-batch-two-artifact.json"
        batch_two = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "dnsblock_c1_harness.py"),
                "--pihole-dir",
                str(fixture.log),
                "--artifact",
                str(batch_two_artifact),
                "--series-request",
                str(fixture.requests["stepped"]),
                "--series-batch-size",
                "2",
                "--arrival-days",
                "3",
                "--arrival-history",
                "14",
                "--output-format",
                "json",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert batch_two.returncode == 0, batch_two.stderr
        batch_two_payload = json.loads(
            batch_two_artifact.read_text(encoding="utf-8")
        )
        assert json.dumps(
            batch_two_payload["repeat_burden"], sort_keys=True
        ) == json.dumps(observed_repeat["stepped"], sort_keys=True)
    finally:
        if previous_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous_tz
        if hasattr(time, "tzset"):
            time.tzset()


def test_legacy_harness_route_rejects_the_historical_private_vector(
    tmp_path, capsys
):
    """After ratification, (3,14) is an override reserved for private requests."""
    source = tmp_path / "pihole.log"
    source.write_text("", encoding="utf-8")
    artifact = tmp_path / "artifact.json"

    with pytest.raises(SystemExit) as exc_info:
        harness.main(
            [
                "--pihole-dir",
                str(source),
                "--artifact",
                str(artifact),
                "--arrival-days",
                "3",
                "--arrival-history",
                "14",
            ]
        )

    assert exc_info.value.code == 2
    assert "private calibration vectors require a batch or series request" in (
        capsys.readouterr().err
    )
    assert not artifact.exists()


def test_series_partition_is_contiguous_at_most_with_remainder_last():
    windows = tuple(range(15))
    assert [len(batch) for batch in harness._partition_series(windows, batch_size=8)] == [8, 7]
    assert [len(batch) for batch in harness._partition_series(windows, batch_size=4)] == [
        4,
        4,
        4,
        3,
    ]
    witness = tuple(range(3))
    assert [len(batch) for batch in harness._partition_series(witness, batch_size=2)] == [2, 1]
    assert [len(batch) for batch in harness._partition_series(witness, batch_size=4)] == [3]
    assert [len(batch) for batch in harness._partition_series(witness, batch_size=8)] == [3]


@pytest.mark.parametrize(
    ("window_count", "expected"),
    ((1, 9000), (2, 18000), (3, 27000)),
)
def test_watchdog_scales_from_actual_batch_window_count(window_count, expected):
    assert harness._batch_watchdog_seconds(window_count) == expected


def test_series_watchdog_sums_ordered_batch_bounds_plus_assembly():
    assert harness._series_watchdog_seconds((1,)) == 9600
    assert harness._series_watchdog_seconds((2, 1)) == 27600
    assert harness._series_watchdog_seconds((3,)) == 27600


@pytest.mark.parametrize("window_count", (0, -1, True, 1.5))
def test_watchdog_rejects_malformed_window_cardinality(window_count):
    with pytest.raises(ValueError, match="positive window count"):
        harness._batch_watchdog_seconds(window_count)


@pytest.mark.parametrize("batch_window_counts", ((), [1], 1, "1"))
def test_series_watchdog_rejects_malformed_batch_cardinalities(
    batch_window_counts,
):
    with pytest.raises(ValueError, match="non-empty batch window counts"):
        harness._series_watchdog_seconds(batch_window_counts)


def test_series_request_rejects_duplicate_report_intervals(tmp_path):
    request = tmp_path / "duplicate-series.json"
    window = {
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-01-08T00:00:00Z",
    }
    request.write_text(json.dumps({"windows": [window, window]}), encoding="utf-8")
    with pytest.raises(ValueError, match="windows must be unique"):
        harness._series_windows(request)


@requires_git_work_tree
def test_harness_uses_real_runner_and_writes_aggregate_preflight(tmp_path):
    log = tmp_path / "pihole.log"
    log.write_text(
        "Jan 20 00:00:00 resolver.example.test dnsmasq[1]: "
        "query[A] x.example from 192.0.2.7\n"
        "Jan 20 00:00:01 resolver.example.test dnsmasq[1]: "
        "gravity blocked x.example is 0.0.0.0\n",
        encoding="utf-8",
    )
    artifact = tmp_path / "aggregate.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "dnsblock_c1_harness.py"),
            "--pihole-dir",
            str(log),
            "--artifact",
            str(artifact),
            "--since",
            "2026-01-19T00:00:00Z",
            "--until",
            "2026-01-21T00:00:00Z",
            "--no-allowlist",
            "--output-format",
            "json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["detector"] == "dnsblock"
    assert payload["status"] == "planned"
    assert payload["preflight"]["state"] == "READY"
    assert len(payload["preflight"]["grids"]) == 12
    assert payload["channels"]["burst"] == {
        "cause": "weak_coverage",
        "eligible_periods": 1,
        # The ordinary route consumes the shipped burst vector.
        "periods_required": 4,
        "status": "ABSTAINED",
    }
    assert payload["channels"]["recurring"]["status"] == "ABSTAINED"
    assert payload["burst_grids"] == []
    assert payload["summary_notes"][0] == (
        "these logs cannot prove how complete each day is, so counts use the days "
        "that carry data; burst and recurring activity were not evaluated"
    )
    assert {label for label, _seconds in payload["preflight"]["pass_wall_seconds"]} == {
        "anchor_block",
        "population",
    }
    assert payload["harness"]["rss_bar"]["limit_bytes"] == 1536 * 1024 * 1024
    assert payload["harness"]["wall_limit_seconds"] == 15 * 60
    assert payload["harness"]["per_window_watchdog_seconds"] == 9000
    assert payload["harness"]["batch_deadline_seconds"] == 9000
    digest = payload["harness"]["semantic_digest"]
    assert digest["schema"] == "sigwood.dnsblock.semantic-digest"
    assert digest["version"] == 1
    assert digest["format"] == "json"
    assert len(digest["sha256"]) == 64
    assert digest["finding_count"] == 0
    second_artifact = tmp_path / "aggregate-second.json"
    second_command = [
        sys.executable,
        str(ROOT / "tools" / "dnsblock_c1_harness.py"),
        "--pihole-dir",
        str(log),
        "--artifact",
        str(second_artifact),
        "--since",
        "2026-01-19T00:00:00Z",
        "--until",
        "2026-01-21T00:00:00Z",
        "--no-allowlist",
        "--output-format",
        "json",
    ]
    second = subprocess.run(
        second_command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert second.returncode == 0, second.stderr
    second_payload = json.loads(second_artifact.read_text(encoding="utf-8"))
    assert second_payload["harness"]["semantic_digest"]["sha256"] == digest["sha256"]
    serialized = artifact.read_text(encoding="utf-8")
    assert "192.0.2.7" not in serialized
    assert "x.example" not in serialized


@requires_git_work_tree
def test_harness_batch_request_uses_real_shared_runner_and_json_serializer(tmp_path):
    log = tmp_path / "pihole.log"
    log.write_text(
        "Jan 20 00:00:00 resolver.example.test dnsmasq[1]: "
        "query[A] x.example from 192.0.2.7\n"
        "Jan 20 00:00:01 resolver.example.test dnsmasq[1]: "
        "gravity blocked x.example is 0.0.0.0\n",
        encoding="utf-8",
    )
    request = tmp_path / "batch.json"
    request.write_text(
        json.dumps(
            {
                "windows": [
                    {
                        "start": "2026-01-19T00:00:00Z",
                        "end": "2026-01-21T00:00:00Z",
                    },
                    {
                        "start": "2026-01-21T00:00:00Z",
                        "end": "2026-01-22T00:00:00Z",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    artifact = tmp_path / "batch-artifact.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "dnsblock_c1_harness.py"),
            "--pihole-dir",
            str(log),
            "--artifact",
            str(artifact),
            "--batch-request",
            str(request),
            "--output-format",
            "json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["batch"]["window_count"] == 2
    assert payload["batch"]["watchdog_enforced"] is True
    assert payload["batch"]["per_window_watchdog_seconds"] == 9000
    assert payload["batch"]["batch_deadline_seconds"] == 18000
    assert len(payload["batch"]["content_identity_sha256"]) == 64
    assert payload["batch"]["allowlist_lanes"] == ["default", "unsuppressed"]
    assert payload["batch"]["peak_temp_bytes"] > 0
    assert payload["batch"]["max_window_routes"] >= 0
    assert payload["batch"]["max_inflight_cadence_gaps"] >= 0
    assert payload["batch"]["inflight_window_lane_bytes_estimate"] > 0
    assert len(payload["results"]) == 4
    assert {
        (item["window_ordinal"], item["allowlist_lane"])
        for item in payload["results"]
    } == {
        (0, "default"),
        (0, "unsuppressed"),
        (1, "default"),
        (1, "unsuppressed"),
    }
    assert all(
        item["semantic_digest"]["schema"]
        == "sigwood.dnsblock.semantic-digest"
        for item in payload["results"]
    )
    for lane, extra in (("default", []), ("unsuppressed", ["--no-allowlist"])):
        ordinary_artifact = tmp_path / f"ordinary-{lane}.json"
        ordinary = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "dnsblock_c1_harness.py"),
                "--pihole-dir",
                str(log),
                "--artifact",
                str(ordinary_artifact),
                "--since",
                "2026-01-19T00:00:00Z",
                "--until",
                "2026-01-21T00:00:00Z",
                "--output-format",
                "json",
                *extra,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert ordinary.returncode == 0, ordinary.stderr
        ordinary_payload = json.loads(ordinary_artifact.read_text(encoding="utf-8"))
        candidate = next(
            item
            for item in payload["results"]
            if item["window_ordinal"] == 0 and item["allowlist_lane"] == lane
        )
        assert candidate["semantic_summary"] == ordinary_payload["harness"][
            "semantic_summary"
        ]
        assert candidate["semantic_digest"] == ordinary_payload["harness"][
            "semantic_digest"
        ]
    assert any(
        # The batch request uses the shipped arrival vector, now five periods.
        "first-activity reporting needs 5 days with data" in note
        for item in payload["results"]
        for note in item["aggregate"]["summary_notes"]
    )
    serialized = artifact.read_text(encoding="utf-8")
    assert "192.0.2.7" not in serialized
    assert "x.example" not in serialized


def test_prepare_render_batch_captures_exact_loader_snapshot(
    tmp_path, monkeypatch
):
    source = tmp_path / "pihole"
    source.mkdir()
    for rotation, day in (("pihole.log.1", 19), ("pihole.log", 20)):
        lines = []
        for index in range(12):
            address = f"192.0.2.{index + 1}"
            name = f"synthetic-{day}-{index}.example.test"
            lines.extend(
                (
                    f"Jan {day} 00:{index:02d}:00 resolver.example.test "
                    f"dnsmasq[1]: query[A] {name} from {address}\n",
                    f"Jan {day} 00:{index:02d}:01 resolver.example.test "
                    f"dnsmasq[1]: gravity blocked {name} is 0.0.0.0\n",
                )
            )
        (source / rotation).write_text("".join(lines), encoding="utf-8")

    captured = []
    original = harness._snapshot_content_members

    def observe(snapshot):
        captured.append(snapshot)
        return original(snapshot)

    monkeypatch.setattr(harness, "_snapshot_content_members", observe)
    window = harness.DualWindow(
        (
            harness._instant("2026-01-19T00:00:00Z"),
            harness._instant("2026-01-21T00:00:00Z"),
        )
    )
    batch, results, _elapsed, _peak_temp, content_members = (
        harness._prepare_render_batch(
            selected_source=source,
            windows=(window,),
            effective_config={
                "sigwood": {"root": "", "warn_above": 0, "default_window": "7d"}
            },
            calibration_vector=harness.dnsblock.DnsblockCalibrationVector(),
            ordinal_offset=0,
        )
    )

    assert len(captured) == 1
    assert len(content_members) == 2
    assert {Path(member["resolved"]).name for member in content_members} == {
        "pihole.log",
        "pihole.log.1",
    }
    assert harness._validated_content_members(
        content_members, batch.content_identity_sha256
    ) == content_members
    assert batch.content_identity_sha256 == captured[0].content_identity_sha256
    assert len(results) == 2


@requires_git_work_tree
def test_harness_series_request_partitions_tail_and_emits_only_aggregate_unions(tmp_path):
    log = tmp_path / "pihole.log"
    log.write_text(
        "Jan 20 00:00:00 resolver.example.test dnsmasq[1]: "
        "query[A] x.example from 192.0.2.7\n"
        "Jan 20 00:00:01 resolver.example.test dnsmasq[1]: "
        "gravity blocked x.example is 0.0.0.0\n",
        encoding="utf-8",
    )
    request = tmp_path / "series.json"
    request.write_text(
        json.dumps(
            {
                "windows": [
                    {
                        "start": f"2026-01-{day:02d}T00:00:00Z",
                        "end": f"2026-01-{day + 1:02d}T00:00:00Z",
                    }
                    for day in (19, 20, 21)
                ]
            }
        ),
        encoding="utf-8",
    )
    artifact = tmp_path / "series-artifact.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "dnsblock_c1_harness.py"),
            "--pihole-dir",
            str(log),
            "--artifact",
            str(artifact),
            "--series-request",
            str(request),
            "--series-batch-size",
            "2",
            "--co-load",
            "2",
            "--output-format",
            "json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 3
    assert payload["series"]["batch_window_counts"] == [2, 1]
    assert payload["series"]["watchdog_enforced"] is True
    assert payload["series"]["co_load"] == 2
    assert payload["series"]["assembly_overhead_seconds"] == 600
    assert payload["series"]["per_window_watchdog_seconds"] == 9000
    assert payload["series"]["batch_deadline_seconds_by_batch"] == [18000, 9000]
    assert payload["series"]["series_deadline_seconds"] == 27600
    assert payload["series"]["batch_partition"] == {
        "ordering": "contiguous",
        "limit": "at_most_batch_size",
        "tail": "remainder_last",
    }
    assert len(set(payload["series"]["batch_content_identities"])) == 1
    assert payload["series"]["window_count"] == 3
    assert payload["series"]["peak_temp_bytes"] > 0
    assert payload["series"]["max_window_routes"] >= 0
    assert payload["series"]["max_inflight_cadence_gaps"] >= 0
    assert payload["series"]["inflight_window_lane_bytes_estimate"] > 0
    assert len(payload["results"]) == 6
    assert {
        (item["window_ordinal"], item["allowlist_lane"])
        for item in payload["results"]
    } == {
        (ordinal, lane)
        for ordinal in range(3)
        for lane in ("default", "unsuppressed")
    }
    assert len(payload["arrival_survivor_grid"]) == 12
    assert len(payload["burst_survivor_grid"]) == 75
    assert set(payload["repeat_burden"]) == {
        "rolling_periods",
        "maximum_allowed",
        "maximum_observed",
        "violating_identities",
        "violation",
    }
    serialized = artifact.read_text(encoding="utf-8")
    assert "192.0.2.7" not in serialized
    assert "x.example" not in serialized


def test_supervised_batch_timeout_reaps_group_and_leaves_no_partial(tmp_path):
    log = tmp_path / "pihole.log"
    log.write_text(
        "Jan 20 00:00:00 resolver.example.test dnsmasq[1]: "
        "query[A] x.example from 192.0.2.7\n",
        encoding="utf-8",
    )
    window = harness.DualWindow(
        (
            harness._instant("2026-01-19T00:00:00Z"),
            harness._instant("2026-01-21T00:00:00Z"),
        )
    )
    with pytest.raises(harness.BatchWatchdogError, match="batch_watchdog_timeout"):
        harness._supervised_batch(
            selected_source=log,
            windows=(window,),
            calibration_vector=harness.dnsblock.DnsblockCalibrationVector(),
            ordinal_offset=0,
            batch_ordinal=3,
            transaction_parent=tmp_path,
            deadline_seconds=0.001,
        )
    assert not list(tmp_path.glob(".dnsblock-c1-worker-*"))


def test_series_timeout_receipt_states_actual_timed_batch_bound(
    tmp_path, monkeypatch
):
    log = tmp_path / "pihole.log"
    log.write_text("", encoding="utf-8")
    request = tmp_path / "series.json"
    request.write_text(
        json.dumps(
            {
                "windows": [
                    {
                        "start": f"2026-01-{day:02d}T00:00:00Z",
                        "end": f"2026-01-{day + 1:02d}T00:00:00Z",
                    }
                    for day in (19, 20, 21)
                ]
            }
        ),
        encoding="utf-8",
    )
    artifact = tmp_path / "series-artifact.json"

    def timeout(**kwargs):
        raise harness.BatchWatchdogError(
            "batch_watchdog_timeout", kwargs["batch_ordinal"]
        )

    monkeypatch.setattr(harness, "_supervised_batch", timeout)
    assert (
        harness._run_series(
            selected_source=log,
            artifact=artifact,
            request=request,
            effective_config={},
            corpus_facts=None,
            calibration_vector=harness.dnsblock.DnsblockCalibrationVector(),
            batch_size=2,
            co_load=1,
        )
        == 124
    )
    receipt = json.loads(
        artifact.with_suffix(".json.timeout.json").read_text(encoding="utf-8")
    )
    assert receipt["per_window_watchdog_seconds"] == 9000
    assert receipt["batch_window_count"] == 2
    assert receipt["batch_deadline_seconds"] == 18000
    assert receipt["configured_batch_deadline_seconds"] == 18000
    assert receipt["batch_deadline_seconds_by_batch"] == [18000, 9000]
    assert receipt["series_deadline_seconds"] == 27600


def _content_member(path: Path, *, digest: str) -> dict:
    return {
        "resolved": str(path.resolve()),
        "source": "pihole_dir",
        "device": 1,
        "inode": 1,
        "compressed": False,
        "stat_bytes": 1,
        "mtime_ns": 1,
        "readable_bytes": 1,
        "sha256": digest,
    }


def _series_request(tmp_path: Path) -> Path:
    request = tmp_path / "series-content.json"
    request.write_text(
        json.dumps(
            {
                "windows": [
                    {
                        "start": f"2026-01-{day:02d}T00:00:00Z",
                        "end": f"2026-01-{day + 1:02d}T00:00:00Z",
                    }
                    for day in (19, 20, 21)
                ]
            }
        ),
        encoding="utf-8",
    )
    return request


def _series_partial(kwargs: dict, members: list[dict]) -> dict:
    windows = kwargs["windows"]
    offset = kwargs["ordinal_offset"]
    return {
        "snapshot_identity_sha256": "f" * 64,
        "content_identity_sha256": harness._content_identity_sha256(members),
        "content_members": members,
        "results": [
            {
                "window_ordinal": offset + index,
                "allowlist_lane": lane,
                "aggregate": {"preflight": {"state": "READY"}},
            }
            for index in range(len(windows))
            for lane in ("default", "unsuppressed")
        ],
        "worker_elapsed_seconds": 0.1,
        "peak_temp_bytes": 1,
        "peak_process_rss_bytes": 1,
        "data_size_bytes": 1,
        "max_window_routes": 0,
        "max_inflight_cadence_gaps": 0,
        "pass_wall_seconds": [],
        "survivor_batches": [],
        "repeat_batches": [],
    }


def _run_mocked_content_series(
    tmp_path: Path, monkeypatch, batch_members: list[list[dict]]
) -> tuple[int, Path]:
    artifact = tmp_path / "series-content-artifact.json"
    request = _series_request(tmp_path)

    def supervised(**kwargs):
        return _series_partial(kwargs, batch_members[kwargs["batch_ordinal"]])

    monkeypatch.setattr(harness, "_supervised_batch", supervised)
    result = harness._run_series(
        selected_source=tmp_path,
        artifact=artifact,
        request=request,
        effective_config={},
        corpus_facts=None,
        calibration_vector=harness.dnsblock.DnsblockCalibrationVector(),
        batch_size=2,
        co_load=1,
    )
    return result, artifact


@requires_git_work_tree
def test_series_content_identity_allows_different_batch_file_sets(
    tmp_path, monkeypatch
):
    first = _content_member(tmp_path / "pihole.log", digest="a" * 64)
    shared = _content_member(tmp_path / "pihole.log.1", digest="b" * 64)
    last = _content_member(tmp_path / "pihole.log.2", digest="c" * 64)
    result, artifact = _run_mocked_content_series(
        tmp_path, monkeypatch, [[first, shared], [shared, last]]
    )
    assert result == 0
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    expected_union = sorted([first, shared, last], key=lambda item: item["resolved"])
    assert payload["series"]["content_identity_sha256"] == (
        harness._content_identity_sha256(expected_union)
    )
    assert len(set(payload["series"]["batch_content_identities"])) == 2


def test_series_content_identity_rejects_changed_shared_file(tmp_path, monkeypatch):
    first = _content_member(tmp_path / "pihole.log", digest="a" * 64)
    shared = _content_member(tmp_path / "pihole.log.1", digest="b" * 64)
    changed = {**shared, "sha256": "c" * 64}
    result, artifact = _run_mocked_content_series(
        tmp_path, monkeypatch, [[first, shared], [changed]]
    )
    assert result == 2
    sidecar = json.loads(
        artifact.with_suffix(".json.timeout.json").read_text(encoding="utf-8")
    )
    assert sidecar["failure"] == "content_identity_mismatch"
    assert sidecar["disagreeing_shared_file_count"] == 1
    assert len(sidecar["batch_content_identities"]) == 2
    assert "resolved" not in json.dumps(sidecar)


@requires_git_work_tree
def test_series_single_file_content_identity_is_byte_compatible(
    tmp_path, monkeypatch
):
    member = _content_member(tmp_path / "pihole.log", digest="a" * 64)
    original_identity = harness._content_identity_sha256([member])
    result, artifact = _run_mocked_content_series(
        tmp_path, monkeypatch, [[member], [member]]
    )
    assert result == 0
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["series"]["content_identity_sha256"] == original_identity
    assert payload["series"]["batch_content_identities"] == [
        original_identity,
        original_identity,
    ]


def test_worker_content_members_reject_malformed_or_inconsistent_payload(tmp_path):
    member = _content_member(tmp_path / "pihole.log", digest="a" * 64)
    identity = harness._content_identity_sha256([member])
    assert harness._validated_content_members([member], identity) == [member]
    with pytest.raises(ValueError, match="malformed"):
        harness._validated_content_members([{**member, "unexpected": 1}], identity)
    with pytest.raises(ValueError, match="inconsistent"):
        harness._validated_content_members([member], "f" * 64)


def test_term_ignoring_worker_group_is_killed_and_reaped(monkeypatch):
    monkeypatch.setattr(harness, "_WATCHDOG_TERM_GRACE_SECONDS", 0.01)
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
        ],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    harness._terminate_worker_group(process)
    assert process.poll() is not None
    with pytest.raises(ProcessLookupError):
        os.kill(process.pid, 0)


def test_supervisor_refuses_substituted_symlink_partial(tmp_path, monkeypatch):
    log = tmp_path / "pihole.log"
    log.write_text("", encoding="utf-8")
    target = tmp_path / "substitute.json"
    target.write_text("{}", encoding="utf-8")

    class FakeProcess:
        pid = 999_999

        def __init__(self, argv, **_kwargs):
            partial = Path(argv[argv.index("--internal-worker-partial") + 1])
            partial.symlink_to(target)

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr(harness.subprocess, "Popen", FakeProcess)
    window = harness.DualWindow(
        (
            harness._instant("2026-01-19T00:00:00Z"),
            harness._instant("2026-01-21T00:00:00Z"),
        )
    )
    with pytest.raises(harness.BatchWatchdogError, match="partial_validation_failure"):
        harness._supervised_batch(
            selected_source=log,
            windows=(window,),
            calibration_vector=harness.dnsblock.DnsblockCalibrationVector(),
            ordinal_offset=0,
            batch_ordinal=0,
            transaction_parent=tmp_path,
        )
    assert target.read_text(encoding="utf-8") == "{}"


def test_wall_rate_separates_corpus_size_from_pass_count() -> None:
    """The wall cost is reported in a unit that survives a changing corpus.

    An absolute wall conflates corpus size, pass count and per-pass speed. The
    two real runs below sat on opposite sides of a 900s bar, yet per pass per
    GiB they differ by only ~10%: most of the gap was a third pass, not a
    slowdown. Figures are the recorded facts of those runs.
    """
    from tools.dnsblock_c1_harness import _wall_rate_facts

    green = _wall_rate_facts(
        533.5491471248679,
        {"member_bytes": 3232976285},
        [["anchor_block", 257.97], ["population", 275.51]],
    )
    breach = _wall_rate_facts(
        1316.7,
        {"member_bytes": int(4.5 * 1024 ** 3)},
        [["anchor", 431.0], ["cadence", 428.0], ["population", 457.0]],
    )

    assert green["wall_rate_pass_count"] == 2
    assert breach["wall_rate_pass_count"] == 3
    assert round(green["wall_rate_seconds_per_gib_per_pass"], 1) == 88.6
    assert round(breach["wall_rate_seconds_per_gib_per_pass"], 1) == 97.5
    # The absolute walls differ by 2.5x; per pass per GiB they differ by ~10%.
    ratio = (
        breach["wall_rate_seconds_per_gib_per_pass"]
        / green["wall_rate_seconds_per_gib_per_pass"]
    )
    assert 1.05 < ratio < 1.15


def test_wall_rate_reports_an_absent_denominator_rather_than_passing() -> None:
    """A missing corpus manifest or pass ledger cannot read as a green run."""
    from tools.dnsblock_c1_harness import _wall_rate_facts

    for corpus, passes in (
        (None, [["anchor", 1.0]]),
        ({"member_bytes": 0}, [["anchor", 1.0]]),
        ({"member_bytes": 1024 ** 3}, None),
    ):
        facts = _wall_rate_facts(100.0, corpus, passes)
        assert facts["wall_rate_seconds_per_gib_per_pass"] is None
        assert facts["wall_rate_measured"] is False


def test_wall_rate_bar_is_not_invented_from_two_observations() -> None:
    """No threshold ships until one is measured.

    Two runs cannot calibrate a bar, and a value chosen to make the current run
    green would be a preference wearing a measurement's clothes.
    """
    from tools.dnsblock_c1_harness import _wall_rate_facts

    facts = _wall_rate_facts(100.0, {"member_bytes": 1024 ** 3}, [["anchor", 100.0]])

    assert facts["wall_rate_bar"] == "not_ratified"
    assert facts["wall_rate_measured"] is True
