from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools import dnsblock_c1_harness as harness


ROOT = Path(__file__).resolve().parents[1]


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
    assert harness._series_watchdog_seconds(1) == 2400
    assert harness._series_watchdog_seconds(2) == 4200
    with pytest.raises(ValueError, match="positive batch count"):
        harness._series_watchdog_seconds(0)


def test_series_request_rejects_duplicate_report_intervals(tmp_path):
    request = tmp_path / "duplicate-series.json"
    window = {
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-01-08T00:00:00Z",
    }
    request.write_text(json.dumps({"windows": [window, window]}), encoding="utf-8")
    with pytest.raises(ValueError, match="windows must be unique"):
        harness._series_windows(request)


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
        "periods_required": 3,
        "status": "ABSTAINED",
    }
    assert payload["channels"]["recurring"]["status"] == "ABSTAINED"
    assert payload["burst_grids"] == []
    assert payload["summary_notes"][0] == (
        "period coverage is not verifiable from these logs; period counts use "
        "data-bearing periods, and burst and recurring activity were not evaluated"
    )
    assert {label for label, _seconds in payload["preflight"]["pass_wall_seconds"]} == {
        "anchor_block",
        "population",
    }
    assert payload["harness"]["rss_bar"]["limit_bytes"] == 1536 * 1024 * 1024
    assert payload["harness"]["wall_limit_seconds"] == 15 * 60
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
    assert payload["batch"]["batch_deadline_seconds"] == 1800
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
        "first-activity analysis needs 3 eligible periods" in note
        for item in payload["results"]
        for note in item["aggregate"]["summary_notes"]
    )
    serialized = artifact.read_text(encoding="utf-8")
    assert "192.0.2.7" not in serialized
    assert "x.example" not in serialized


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
    assert payload["series"]["series_deadline_seconds"] == 4200
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
