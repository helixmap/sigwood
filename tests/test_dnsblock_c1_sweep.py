from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from tools import dnsblock_c1_sweep as sweep


UTC = timezone.utc


def _matrix_payload():
    rows = []
    for obligation, nodeids in sweep.MATRIX_OBLIGATIONS.items():
        paths = sorted({nodeid.split("::", 1)[0] for nodeid in nodeids})
        rows.append(
            {
                "obligation": obligation,
                "command": [sys.executable, "-m", "pytest", "-q", *nodeids],
                "nodeids": list(nodeids),
                "source_sha256": {path: "a" * 64 for path in paths},
                "exit_code": 0,
                "duration_seconds": 0.25,
                "output_sha256": "b" * 64,
            }
        )
    return {
        "schema": f"{sweep.SCHEMA}.matrix",
        "schema_version": sweep.SCHEMA_VERSION,
        "authority": {
            "spec_version": sweep.SPEC_VERSION,
            "spec_sha256": sweep.SPEC_SHA256,
        },
        "obligation_count": len(sweep.MATRIX_OBLIGATIONS),
        "all_green": True,
        "rows": rows,
    }


def test_window_enumeration_is_instant_grain_and_complete():
    earliest = datetime(2026, 5, 10, 5, tzinfo=UTC)
    anchor = datetime(2026, 8, 9, 5, tzinfo=UTC)
    windows = sweep.enumerate_windows(earliest, anchor)
    trail = windows[sweep.WindowMode.TRAIL]
    shifts = windows[sweep.WindowMode.SHIFT]
    disjoint = windows[sweep.WindowMode.DISJ]
    whole = windows[sweep.WindowMode.ALL]
    assert trail[0].end == anchor
    assert trail[0].start == anchor - timedelta(days=7)
    assert len(shifts) == 85
    assert all(
        shifts[index].end - shifts[index + 1].end == timedelta(days=1)
        for index in range(len(shifts) - 1)
    )
    assert shifts[-1].start == earliest
    assert len(disjoint) == 13
    assert not any(window.partial_tail for window in disjoint)
    assert whole[0].start == earliest and whole[0].end == anchor


def test_disjoint_short_tail_is_provenance_not_a_shift_window():
    earliest = datetime(2026, 1, 1, tzinfo=UTC)
    anchor = earliest + timedelta(days=8, hours=12)
    windows = sweep.enumerate_windows(earliest, anchor)
    disjoint = windows[sweep.WindowMode.DISJ]
    assert [(item.end - item.start, item.partial_tail) for item in disjoint] == [
        (timedelta(days=7), False),
        (timedelta(days=1, hours=12), True),
    ]
    assert len(windows[sweep.WindowMode.SHIFT]) == 2


def test_harness_request_projection_is_context_true_and_excludes_provenance():
    earliest = datetime(2026, 1, 1, tzinfo=UTC)
    latest = sweep.CalibrationWindow(
        sweep.WindowMode.SHIFT,
        9,
        earliest + timedelta(days=14),
        earliest + timedelta(days=21),
        partial_tail=True,
    )
    first = sweep.CalibrationWindow(
        sweep.WindowMode.SHIFT,
        10,
        earliest,
        earliest + timedelta(days=7),
    )
    request = sweep.harness_series_request(
        (latest, first), corpus_earliest=earliest
    )
    assert request == {
        "windows": [
            {
                "start": "2026-01-15T00:00:00+00:00",
                "end": "2026-01-22T00:00:00+00:00",
                "context_start": "2026-01-01T00:00:00+00:00",
                "context_end": "2026-01-14T23:59:59.999999+00:00",
            },
            {
                "start": "2026-01-01T00:00:00+00:00",
                "end": "2026-01-08T00:00:00+00:00",
            },
        ]
    }
    assert not ({"mode", "ordinal", "partial_tail"} & request["windows"][0].keys())


def test_weak_corpus_snapshot_is_atomic_content_addressed_and_reusable(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    first = source / "one.log"
    second = source / "two.log"
    first.write_bytes(b"one\n")
    second.write_bytes(b"two\n")
    manifest = source / "manifest.tsv"
    manifest.write_text(
        f"one.log\t4\t{sweep._sha256_file(first)}\n"
        f"two.log\t4\t{sweep._sha256_file(second)}\n",
        encoding="utf-8",
    )
    destination = tmp_path / "pinned"
    result = sweep.pin_weak_corpus(
        source=source, manifest=manifest, destination_parent=destination
    )
    assert result["reused"] is False
    assert result["weak_snapshot_bytes"] == 8
    assert result["path"].is_dir()
    assert {path.name for path in result["path"].iterdir()} == {
        "manifest.tsv",
        "one.log",
        "two.log",
    }
    assert (result["path"].stat().st_mode & 0o777) == 0o700
    assert all((path.stat().st_mode & 0o777) == 0o600 for path in result["path"].iterdir())
    (source / "later.log").write_bytes(b"later\n")
    reused = sweep.pin_weak_corpus(
        source=source, manifest=manifest, destination_parent=destination
    )
    assert reused["reused"] is True
    assert reused["path"] == result["path"]


def test_weak_corpus_snapshot_rejects_symlink_and_manifest_mismatch(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    real = source / "real.log"
    real.write_bytes(b"safe\n")
    linked = source / "linked.log"
    linked.symlink_to(real)
    manifest = source / "manifest.tsv"
    manifest.write_text(
        f"linked.log\t5\t{sweep._sha256_file(real)}\n", encoding="utf-8"
    )
    with pytest.raises(OSError):
        sweep.pin_weak_corpus(
            source=source,
            manifest=manifest,
            destination_parent=tmp_path / "pinned",
        )
    assert not list((tmp_path / "pinned").glob("weak-*"))


def test_measurement_schedule_keeps_decisions_solo_and_retries_only_coload_watchdog():
    lock = threading.Lock()
    active = 0
    maximum = 0
    calls = []

    def runner(job, *, co_load):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
            calls.append((job["name"], co_load))
        time.sleep(0.01)
        with lock:
            active -= 1
        if job["name"] == "watchdog" and co_load == 2:
            return {"co_load": 2, "failure": "batch_watchdog_timeout"}
        return {"co_load": co_load, "failure": None}

    rows = sweep.run_measurement_schedule(
        (
            {"name": "oracle", "decision_input": True},
            {"name": "background", "decision_input": False},
            {"name": "watchdog", "decision_input": False},
            {"name": "promotion", "decision_input": True},
        ),
        runner,
    )
    assert maximum == 2
    assert calls[0] == ("oracle", 1)
    assert calls[-1] == ("promotion", 1)
    assert ("watchdog", 1) in calls
    assert rows[2]["receipt"]["failure"] == "batch_watchdog_timeout"
    assert rows[2]["solo_retry"]["failure"] is None
    assert rows[2]["decision_receipt"] == rows[2]["solo_retry"]


def test_prepatch_watchdog_annotation_binds_original_bytes_without_rewrite(tmp_path):
    artifact = tmp_path / "artifact.json"
    receipt = tmp_path / "receipt.json"
    destination = tmp_path / "annotation.json"
    artifact.write_bytes(b"artifact\n")
    receipt.write_bytes(b"receipt\n")
    before = (artifact.read_bytes(), receipt.read_bytes())
    payload = sweep.write_prepatch_watchdog_annotation(
        artifact=artifact, driver_receipt=receipt, destination=destination
    )
    assert payload["watchdog_enforced"] is False
    assert payload["series_watchdog"] == "NOT_ENFORCED"
    assert payload["harness_sha256"] == sweep.PREPATCH_HARNESS_SHA256
    assert (artifact.read_bytes(), receipt.read_bytes()) == before
    assert sweep.verify_receipt(destination) == payload


def test_watchdog_only_rerun_set_is_dependency_driven():
    assert sweep.watchdog_only_rerun_set(
        {
            "wall": ("elapsed_wall", "semantic_digest"),
            "control": ("watchdog_enforced",),
            "caps": ("immutable_caps", "route_count"),
        }
    ) == ("control",)


def test_complete_projection_counts_both_corpora_and_allowlist_lanes():
    projection = sweep.complete_campaign_projection(
        strong_window_seconds={"default": 100, "unsuppressed": 110},
        weak_window_seconds={"default": 20, "unsuppressed": 30},
        strong_shift_count=85,
        weak_shift_count=4,
        overhead_seconds=500,
    )
    assert dict(projection.series_seconds) == {
        "strong:default": 8500,
        "strong:unsuppressed": 9350,
        "weak:default": 80,
        "weak:unsuppressed": 120,
    }
    assert projection.total_seconds == 18_550
    assert projection.promotes is True
    exact_ceiling = sweep.complete_campaign_projection(
        strong_window_seconds={"default": 100, "unsuppressed": 110},
        weak_window_seconds={"default": 20, "unsuppressed": 30},
        strong_shift_count=85,
        weak_shift_count=4,
        overhead_seconds=500,
        ceiling_seconds=18_550,
    )
    assert exact_ceiling.total_seconds == exact_ceiling.ceiling_seconds
    assert exact_ceiling.promotes is False
    with pytest.raises(ValueError, match="both allowlist lanes"):
        sweep.complete_campaign_projection(
            strong_window_seconds={"default": 1},
            weak_window_seconds={"default": 1, "unsuppressed": 1},
            strong_shift_count=1,
            weak_shift_count=1,
            overhead_seconds=0,
        )


def _wall_candidate(batch_size, seconds, *, promotable=True):
    return {
        "batch_size": batch_size,
        "strong_window_seconds": {"default": seconds, "unsuppressed": seconds},
        "weak_window_seconds": {"default": seconds, "unsuppressed": seconds},
        "witness_comparisons": [{"promotable": promotable}],
        "snapshot_verified": True,
        "max_process_rss_bytes": sweep.FOLD_RSS_MAX_BYTES,
        "max_temp_bytes": sweep.TEMP_MAX_BYTES,
        "max_window_routes": sweep.WINDOW_ROUTE_MAX,
        "max_inflight_cadence_gaps": sweep.CADENCE_GAP_MAX,
        "memory_estimate_monotonic": True,
    }


def test_phase_w_selects_fastest_complete_green_candidate():
    result = sweep.select_wall_candidate(
        (
            _wall_candidate(2, 100),
            _wall_candidate(4, 80),
            _wall_candidate(8, 20, promotable=False),
        ),
        strong_shift_count=85,
        weak_shift_count=4,
        overhead_seconds=500,
    )
    assert result["outcome"] == "PROMOTE"
    assert result["selected_batch_size"] == 4
    assert result["candidates"][2]["rejected_reasons"] == ["semantic_parity"]


def test_phase_w_tie_chooses_smaller_batch_and_caps_are_inclusive():
    result = sweep.select_wall_candidate(
        (
            _wall_candidate(2, 20),
            _wall_candidate(4, 20),
            _wall_candidate(8, 30),
        ),
        strong_shift_count=85,
        weak_shift_count=4,
        overhead_seconds=500,
    )
    assert result["selected_batch_size"] == 2
    assert result["candidates"][0]["resource_measurements"] == {
        "max_process_rss_bytes": sweep.FOLD_RSS_MAX_BYTES,
        "max_temp_bytes": sweep.TEMP_MAX_BYTES,
        "max_window_routes": sweep.WINDOW_ROUTE_MAX,
        "max_inflight_cadence_gaps": sweep.CADENCE_GAP_MAX,
    }
    assert result["candidates"][0]["promotable"] is True


@pytest.mark.parametrize(
    ("field", "limit", "reason"),
    (
        ("max_process_rss_bytes", sweep.FOLD_RSS_MAX_BYTES, "process_rss"),
        ("max_temp_bytes", sweep.TEMP_MAX_BYTES, "temp_bytes"),
        ("max_window_routes", sweep.WINDOW_ROUTE_MAX, "window_routes"),
        (
            "max_inflight_cadence_gaps",
            sweep.CADENCE_GAP_MAX,
            "cadence_gaps",
        ),
    ),
)
def test_phase_w_rejects_each_resource_one_over_its_limit(field, limit, reason):
    candidates = [_wall_candidate(size, 20) for size in (2, 4, 8)]
    candidates[0][field] = limit + 1
    result = sweep.select_wall_candidate(
        candidates,
        strong_shift_count=85,
        weak_shift_count=4,
        overhead_seconds=500,
    )
    assert result["selected_batch_size"] == 4
    assert result["candidates"][0]["rejected_reasons"] == [reason]


def test_phase_w_rejects_snapshot_and_memory_estimate_gates():
    candidates = [_wall_candidate(size, 20) for size in (2, 4, 8)]
    candidates[0]["snapshot_verified"] = False
    candidates[1]["memory_estimate_monotonic"] = False
    candidates[2]["witness_comparisons"] = [{"promotable": False}]
    result = sweep.select_wall_candidate(
        candidates,
        strong_shift_count=85,
        weak_shift_count=4,
        overhead_seconds=500,
    )
    assert result["outcome"] == sweep.TerminalOutcome.RETURN_WALL.value
    assert result["selected_batch_size"] is None
    assert [row["rejected_reasons"] for row in result["candidates"]] == [
        ["snapshot_identity"],
        ["memory_estimate"],
        ["semantic_parity"],
    ]


def test_phase_w_returns_wall_when_every_frozen_candidate_fails():
    candidates = [
        _wall_candidate(2, 100, promotable=False),
        _wall_candidate(4, 100, promotable=False),
        _wall_candidate(8, 100, promotable=False),
    ]
    result = sweep.select_wall_candidate(
        candidates,
        strong_shift_count=85,
        weak_shift_count=4,
        overhead_seconds=0,
    )
    assert result["outcome"] == sweep.TerminalOutcome.RETURN_WALL.value
    assert result["selected_batch_size"] is None
    with pytest.raises(ValueError, match="exactly 2, 4, 8"):
        sweep.select_wall_candidate(
            candidates[:-1],
            strong_shift_count=85,
            weak_shift_count=4,
            overhead_seconds=0,
        )


def test_phase_w_candidate_assembly_uses_measured_series_and_all_witnesses(monkeypatch):
    def artifact(batch_size, coverage):
        start = "2026-01-01T00:00:00+00:00" if coverage == "strong" else "2026-02-01T00:00:00+00:00"
        end = "2026-01-08T00:00:00+00:00" if coverage == "strong" else "2026-02-08T00:00:00+00:00"
        return {
            "schema_version": 3,
            "series": {
                "batch_size": batch_size,
                "window_count": 1,
                "batch_count": 1,
                "batch_snapshot_identities": ["a" * 64],
                "batch_content_identities": ["b" * 64],
                "content_identity_sha256": "b" * 64,
                "elapsed_seconds": 20 if coverage == "strong" else 10,
                "peak_process_rss_bytes": batch_size * 100,
                "peak_temp_bytes": batch_size * 10,
                "max_window_routes": 7,
                "max_inflight_cadence_gaps": 8,
                "inflight_window_lane_bytes_estimate": batch_size * 1_000,
            },
            "results": [
                {
                    "allowlist_lane": lane,
                    "report_interval": [start, end],
                }
                for lane in sweep.ALLOWED_LANES
            ],
        }

    artifacts = {
        size: {coverage: artifact(size, coverage) for coverage in ("strong", "weak")}
        for size in (2, 4, 8)
    }
    references = {
        (coverage, result["allowlist_lane"], tuple(result["report_interval"])): {}
        for coverage in ("strong", "weak")
        for result in artifacts[2][coverage]["results"]
    }
    monkeypatch.setattr(
        sweep,
        "compare_witness",
        lambda reference, candidate: {"promotable": True},
    )
    rows = sweep.assemble_phase_w_candidates(artifacts, references)
    assert [row["batch_size"] for row in rows] == [2, 4, 8]
    assert rows[0]["strong_window_seconds"] == {
        "default": 10.0,
        "unsuppressed": 10.0,
    }
    assert rows[0]["weak_window_seconds"] == {
        "default": 5.0,
        "unsuppressed": 5.0,
    }
    assert len(rows[0]["witness_comparisons"]) == 4
    assert rows[-1]["max_process_rss_bytes"] == 800
    assert all(row["memory_estimate_monotonic"] for row in rows)

    artifacts[8]["strong"]["series"]["inflight_window_lane_bytes_estimate"] = 1
    artifacts[8]["weak"]["series"]["inflight_window_lane_bytes_estimate"] = 1
    nonmonotonic = sweep.assemble_phase_w_candidates(artifacts, references)
    assert not any(row["memory_estimate_monotonic"] for row in nonmonotonic)
    artifacts[8]["strong"]["series"]["inflight_window_lane_bytes_estimate"] = 8_000
    artifacts[8]["weak"]["series"]["inflight_window_lane_bytes_estimate"] = 8_000

    artifacts[4]["strong"]["series"]["batch_count"] = 2
    artifacts[4]["strong"]["series"]["batch_snapshot_identities"] = [
        "a" * 64,
        "b" * 64,
    ]
    snapshot_mismatch = sweep.assemble_phase_w_candidates(artifacts, references)
    assert snapshot_mismatch[1]["snapshot_verified"] is False
    with pytest.raises(ValueError, match="reference is missing"):
        sweep.assemble_phase_w_candidates(artifacts, {})


def test_phase_w_two_layer_identity_allows_scan_bound_partition_differences(monkeypatch):
    def artifact(batch_size, coverage):
        start = "2026-01-01T00:00:00+00:00"
        results = []
        for ordinal in range(3):
            end = f"2026-01-{ordinal + 8:02d}T00:00:00+00:00"
            for lane in sweep.ALLOWED_LANES:
                results.append(
                    {
                        "allowlist_lane": lane,
                        "report_interval": [start, end],
                    }
                )
        return {
            "schema_version": 3,
            "series": {
                "batch_size": batch_size,
                "window_count": 3,
                "batch_count": 2,
                "batch_snapshot_identities": ["a" * 64, "c" * 64],
                "batch_content_identities": ["b" * 64, "b" * 64],
                "content_identity_sha256": "b" * 64,
                "elapsed_seconds": 12,
                "peak_process_rss_bytes": 1,
                "peak_temp_bytes": 1,
                "max_window_routes": 1,
                "max_inflight_cadence_gaps": 1,
                "inflight_window_lane_bytes_estimate": 1,
            },
            "results": results,
        }

    artifacts = {
        size: {coverage: artifact(size, coverage) for coverage in ("strong", "weak")}
        for size in (2, 4, 8)
    }
    references = {
        (coverage, result["allowlist_lane"], tuple(result["report_interval"])): {}
        for coverage in ("strong", "weak")
        for result in artifacts[2][coverage]["results"]
    }
    monkeypatch.setattr(
        sweep, "compare_witness", lambda reference, candidate: {"promotable": True}
    )
    rows = sweep.assemble_phase_w_candidates(artifacts, references)
    assert all(row["snapshot_verified"] for row in rows)
    artifacts[2]["strong"]["series"]["batch_content_identities"][1] = "d" * 64
    rows = sweep.assemble_phase_w_candidates(artifacts, references)
    assert rows[0]["snapshot_verified"] is False


def test_nearest_rank_and_budgets_use_shift_only_p95_and_frozen_thresholds():
    assert sweep.nearest_rank(range(1, 21), 0.95) == 19
    assert sweep.shape_budget([15], [4, 8, 1])["passes"] is True
    assert sweep.shape_budget([4], [4, 9, 1])["passes"] is False
    assert sweep.global_budget([20], [6, 12, 1])["passes"] is True
    assert sweep.global_budget([6], [6, 13, 1])["passes"] is False
    assert sweep.shape_budget([9], [1, 2, 3])["p95"] == 3
    with pytest.raises(ValueError, match="complete W-TRAIL and W-SHIFT"):
        sweep.shape_budget([1], [])
    with pytest.raises(ValueError, match="non-negative integers"):
        sweep.global_budget([1], [True])


def test_axis_validity_uses_survivor_digest_movement_in_each_direction():
    axes = ((2, 3, 4), (7, 14, 21))
    selected = (3, 14)
    digests = {
        (3, 14): "selected",
        (2, 14): "left",
        (4, 14): "right",
        (3, 7): "down",
        (3, 21): "up",
    }
    assert sweep.axis_identity_valid(selected, axes, digests) is True
    digests[(4, 14)] = "selected"
    assert sweep.axis_identity_valid(selected, axes, digests) is False


def test_survivor_accumulator_unions_windows_and_emits_aggregate_only_facts():
    accumulator = sweep.GridSurvivorAccumulator(3)
    accumulator.ingest((("a\0x", 0b011), ("b\0x", 0b100)))
    accumulator.ingest((("a\0x", 0b100), ("c\0x", 0b010)))
    rows = accumulator.aggregate()
    assert [row["qualifying_pairs"] for row in rows] == [1, 2, 2]
    assert all(set(row) == {"cell_index", "qualifying_pairs", "identity_digest"} for row in rows)
    assert rows[2]["identity_digest"] == sweep._sha256_bytes(
        json.dumps(("a\0x", "b\0x"), separators=(",", ":")).encode("utf-8")
    )
    accumulator.clear()
    assert [row["qualifying_pairs"] for row in accumulator.aggregate()] == [0, 0, 0]


@pytest.mark.parametrize(
    "memberships",
    [
        (("missing-separator", 1),),
        (("a\0x", 0),),
        (("a\0x", 8),),
        (("a\0x", 1), ("a\0x", 2)),
    ],
)
def test_survivor_accumulator_rejects_malformed_private_memberships(memberships):
    with pytest.raises(ValueError, match="membership"):
        sweep.GridSurvivorAccumulator(3).ingest(memberships)


def test_vector_selection_requires_complete_grid_and_uses_frozen_tie_order():
    axes = ((2, 3), (7, 14))
    cells = {
        (2, 7): {
            "passes": True,
            "p95": 3,
            "max": 4,
            "identity_digest": "a" * 64,
        },
        (2, 14): {
            "passes": True,
            "p95": 3,
            "max": 4,
            "identity_digest": "b" * 64,
        },
        (3, 7): {
            "passes": True,
            "p95": 2,
            "max": 5,
            "identity_digest": "c" * 64,
        },
        (3, 14): {
            "passes": True,
            "p95": 3,
            "max": 4,
            "identity_digest": "d" * 64,
        },
    }
    assert sweep.select_vector(cells, axes) == (3, 7)
    cells[(3, 7)]["p95"] = 3
    cells[(3, 7)]["max"] = 4
    assert sweep.select_vector(cells, axes) == (2, 7)
    with pytest.raises(ValueError, match="complete frozen grid"):
        sweep.select_vector({key: value for key, value in cells.items() if key != (3, 14)}, axes)


def _shape_records():
    axes = ((2, 3), (7, 14))
    vectors = ((2, 7), (2, 14), (3, 7), (3, 14))
    records = []
    for lane in sweep.ALLOWED_LANES:
        for mode, ordinals in ((sweep.WindowMode.TRAIL.value, range(1)), (sweep.WindowMode.SHIFT.value, range(2))):
            for ordinal in ordinals:
                cells = []
                for index, (days, history) in enumerate(vectors):
                    cells.append(
                        {
                            "days": days,
                            "history": history,
                            "qualifying_pairs": index + ordinal,
                            "identity_digest": f"{index + ordinal + (10 if lane == 'unsuppressed' else 0):064x}",
                        }
                    )
                records.append(
                    {
                        "mode": mode,
                        "coverage_lane": "strong",
                        "allowlist_lane": lane,
                        "ordinal": ordinal,
                        "cells": cells,
                    }
                )
    records.sort(
        key=lambda row: (
            sweep.ALLOWED_LANES.index(row["allowlist_lane"]),
            0 if row["mode"] == sweep.WindowMode.TRAIL.value else 1,
            row["ordinal"],
        )
    )
    return axes, records


def test_shape_reducer_requires_complete_ordered_arms_and_frozen_cells():
    axes, records = _shape_records()
    reduced = sweep.reduce_shape_grid(
        records,
        axes=axes,
        vector_fields=("days", "history"),
        coverage_lanes=("strong",),
        expected_shift_counts={"strong": 2},
    )
    assert tuple(reduced) == ((2, 7), (2, 14), (3, 7), (3, 14))
    assert all(sweep._is_sha256(cell["identity_digest"]) for cell in reduced.values())
    assert sweep.select_vector(reduced, axes) == (2, 7)
    with pytest.raises(ValueError, match="incomplete or out of frozen order"):
        sweep.reduce_shape_grid(
            records[:-1],
            axes=axes,
            vector_fields=("days", "history"),
            coverage_lanes=("strong",),
            expected_shift_counts={"strong": 2},
        )


def test_shape_reducer_rejects_duplicate_or_incomplete_grid_cells():
    axes, records = _shape_records()
    duplicate = [dict(row) for row in records]
    duplicate[0] = {**duplicate[0], "cells": [*duplicate[0]["cells"], duplicate[0]["cells"][0]]}
    with pytest.raises(ValueError, match="duplicate vector"):
        sweep.reduce_shape_grid(
            duplicate,
            axes=axes,
            vector_fields=("days", "history"),
            coverage_lanes=("strong",),
            expected_shift_counts={"strong": 2},
        )


def test_global_burden_reducer_uses_closed_arms_and_shift_only_p95():
    records = []
    for lane in sweep.ALLOWED_LANES:
        records.append(
            {
                "mode": sweep.WindowMode.TRAIL.value,
                "coverage_lane": "strong",
                "allowlist_lane": lane,
                "ordinal": 0,
                "entity_findings": 20,
            }
        )
        for ordinal, count in enumerate((1, 2)):
            records.append(
                {
                    "mode": sweep.WindowMode.SHIFT.value,
                    "coverage_lane": "strong",
                    "allowlist_lane": lane,
                    "ordinal": ordinal,
                    "entity_findings": count,
                }
            )
    result = sweep.reduce_global_burden(
        records,
        coverage_lanes=("strong",),
        expected_shift_counts={"strong": 2},
    )
    assert result == {"p50": 2.0, "p95": 2.0, "max": 20, "passes": True}
    with pytest.raises(ValueError, match="incomplete or out of frozen order"):
        sweep.reduce_global_burden(
            records[:-1],
            coverage_lanes=("strong",),
            expected_shift_counts={"strong": 2},
        )


def test_repeat_reducer_deduplicates_arms_and_attributes_burst_only_violation():
    result = sweep.reduce_repeat_burden(
        (
            ("a\0x", 0, "burst"),
            ("a\0x", 0, "burst"),
            ("a\0x", 6, "burst"),
            ("a\0x", 13, "burst"),
            ("b\0x", 0, "arrival"),
            ("b\0x", 14, "arrival"),
        )
    )
    assert result == {
        "rolling_periods": 14,
        "maximum_allowed": 2,
        "maximum_observed": 3,
        "violating_identities": 1,
        "violation": "burst_only",
    }


def test_repeat_reducer_marks_arrival_or_mixed_and_rejects_bad_private_rows():
    result = sweep.reduce_repeat_burden(
        (
            ("a\0x", 1, "burst"),
            ("a\0x", 2, "arrival"),
            ("a\0x", 3, "burst"),
        )
    )
    assert result["violation"] == "arrival_or_mixed"
    with pytest.raises(ValueError, match="shape is invalid"):
        sweep.reduce_repeat_burden((("a\0x", 1, "context"),))


def _triage_case(ordinal, left="investigate", right="investigate", elapsed=60.0):
    return {
        "ordinal": ordinal,
        "reviewers": [
            {
                "disposition": left,
                "reason": "private detailed reason one",
                "lookups": 1,
                "elapsed_seconds": elapsed,
            },
            {
                "disposition": right,
                "reason": "private detailed reason two",
                "lookups": 2,
                "elapsed_seconds": 90.0,
            },
        ],
    }


def test_triage_summary_requires_reasons_but_releases_only_bounded_categories():
    cases = [_triage_case(index) for index in range(5)]
    cases[0] = _triage_case(0, "investigate", "mute_expected")
    summary = sweep.summarize_triage(cases)
    assert summary["state"] == "PASS"
    assert summary["disagreement_cases"] == 1
    assert summary["reason_category_counts"] == {
        "recorded": 10,
        "unresolved": 0,
        "over_budget": 0,
    }
    assert "private detailed reason" not in json.dumps(summary)


def test_triage_summary_applies_integer_cap_and_unmeasured_rules():
    cases = [_triage_case(index) for index in range(10)]
    cases[0] = _triage_case(0, "unresolved", "investigate")
    cases[1] = _triage_case(1, elapsed=301.0)
    assert sweep.summarize_triage(cases)["state"] == "PASS"
    cases[2] = _triage_case(2, "unresolved", "unresolved")
    assert sweep.summarize_triage(cases)["state"] == "FAIL"
    assert sweep.summarize_triage(cases[:4])["unmeasured_reason"] == "sample_below_five"
    assert sweep.summarize_triage(cases, reviewers_available=False)[
        "unmeasured_reason"
    ] == "reviewer_unavailable"
    bad = [_triage_case(index) for index in range(5)]
    bad[0]["reviewers"][0]["reason"] = ""
    with pytest.raises(ValueError, match="detailed private reason"):
        sweep.summarize_triage(bad)


def test_campaign_decision_applies_arrival_only_and_orthogonal_triage():
    axes = ((2, 3), (7, 14))
    arrival = {
        (2, 7): {"passes": True, "p95": 1, "max": 1, "identity_digest": "a" * 64},
        (2, 14): {"passes": True, "p95": 2, "max": 2, "identity_digest": "b" * 64},
        (3, 7): {"passes": True, "p95": 2, "max": 2, "identity_digest": "c" * 64},
        (3, 14): {"passes": True, "p95": 3, "max": 3, "identity_digest": "d" * 64},
    }
    burst = {
        vector: {**facts, "identity_digest": "e" * 64}
        for vector, facts in arrival.items()
    }
    result = sweep.decide_campaign(
        wall_promoted=True,
        arrival_cells=arrival,
        arrival_axes=axes,
        burst_cells=burst,
        burst_axes=axes,
        final_global_budget={"passes": True},
        repeat_burden={"violation": None},
        triage_summary={"state": "UNMEASURED"},
    )
    assert result["terminal_outcome"] == "SEALED_RATIFIED_ARRIVAL_ONLY"
    assert result["arrival_vector"] == [2, 7]
    assert result["burst_vector"] is None
    assert result["burst_enabled"] is False
    assert result["triage"]["state"] == "UNMEASURED"


def test_campaign_decision_stops_at_failed_wall_without_sweep_evidence():
    result = sweep.decide_campaign(
        wall_promoted=False,
        arrival_cells={},
        arrival_axes=(),
        burst_cells={},
        burst_axes=(),
        final_global_budget={},
        repeat_burden={},
        triage_summary={},
    )
    assert result == {
        "terminal_outcome": "RETURN_WALL",
        "arrival_vector": None,
        "burst_vector": None,
        "burst_enabled": False,
        "global_budget": None,
        "repeat_burden": None,
        "triage": None,
    }


def test_campaign_decision_rejects_global_or_arrival_repeat_burden():
    axes = ((2, 3), (7, 14))
    cells = {
        (2, 7): {"passes": True, "p95": 1, "max": 1, "identity_digest": "a" * 64},
        (2, 14): {"passes": True, "p95": 2, "max": 2, "identity_digest": "b" * 64},
        (3, 7): {"passes": True, "p95": 2, "max": 2, "identity_digest": "c" * 64},
        (3, 14): {"passes": True, "p95": 3, "max": 3, "identity_digest": "d" * 64},
    }
    result = sweep.decide_campaign(
        wall_promoted=True,
        arrival_cells=cells,
        arrival_axes=axes,
        burst_cells=cells,
        burst_axes=axes,
        final_global_budget={"passes": False},
        repeat_burden={"violation": "arrival_or_mixed"},
        triage_summary={"state": "PASS"},
    )
    assert result["terminal_outcome"] == "RETURN_INVALID_OR_BURDEN"


def test_terminal_lattice_preserves_arrival_on_burst_only_failure():
    common = dict(
        wall_promoted=True,
        arrival_valid=True,
        arrival_budget_passed=True,
        global_budget_passed=True,
    )
    assert sweep.classify_terminal(
        **common,
        burst_valid=False,
        burst_budget_passed=True,
        repeat_violation=None,
    ) is sweep.TerminalOutcome.SEALED_RATIFIED_ARRIVAL_ONLY
    assert sweep.classify_terminal(
        **common,
        burst_valid=True,
        burst_budget_passed=True,
        repeat_violation="burst_only",
    ) is sweep.TerminalOutcome.SEALED_RATIFIED_ARRIVAL_ONLY
    assert sweep.classify_terminal(
        **{**common, "arrival_valid": False},
        burst_valid=True,
        burst_budget_passed=True,
        repeat_violation=None,
    ) is sweep.TerminalOutcome.RETURN_INVALID_OR_BURDEN


def test_control_matrix_is_closed_and_validates_exact_command_receipts():
    payload = _matrix_payload()
    sweep.validate_control_matrix(payload)
    assert payload["obligation_count"] == 16
    assert all(row["command"][4:] == row["nodeids"] for row in payload["rows"])


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda payload: payload["rows"].pop(), "incomplete or out of order"),
        (
            lambda payload: payload["rows"][0]["nodeids"].append("tests/extra.py"),
            "node mapping mismatch",
        ),
        (
            lambda payload: payload["rows"][0].__setitem__("output_sha256", "short"),
            "output digest is invalid",
        ),
        (
            lambda payload: payload.__setitem__("all_green", False),
            "aggregate result is inconsistent",
        ),
    ],
)
def test_control_matrix_validation_fails_closed(mutation, message):
    payload = _matrix_payload()
    mutation(payload)
    with pytest.raises(ValueError, match=message):
        sweep.validate_control_matrix(payload)


def test_receipt_digest_rejects_tampering(tmp_path):
    path = tmp_path / "receipt.json"
    digest = sweep.atomic_receipt(path, {"aggregate_count": 3})
    assert sweep.verify_receipt(path) == {"aggregate_count": 3}
    assert len(digest) == 64
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["payload"]["aggregate_count"] = 4
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        sweep.verify_receipt(path)


def test_resumable_receipt_requires_exact_key_and_preserves_stale_evidence(tmp_path):
    path = tmp_path / "latest.json"
    first_key = "a" * 64
    assert sweep.write_resumable_receipt(
        path, key=first_key, payload={"aggregate_count": 3}
    ) == {"resumed": False, "superseded": None}
    assert sweep.write_resumable_receipt(
        path, key=first_key, payload={"aggregate_count": 3}
    ) == {"resumed": True, "superseded": None}
    with pytest.raises(ValueError, match="payload changed"):
        sweep.write_resumable_receipt(
            path, key=first_key, payload={"aggregate_count": 4}
        )
    second = sweep.write_resumable_receipt(
        path, key="b" * 64, payload={"aggregate_count": 4}
    )
    assert second["resumed"] is False
    assert second["superseded"] is not None
    superseded = tmp_path / "superseded"
    assert len(list(superseded.glob("latest-*.json"))) == 1
    assert sweep.verify_receipt(path)["receipt_key"] == "b" * 64


def test_series_receipt_fanout_is_complete_exact_key_and_resumable(tmp_path):
    results = []
    for lane in sweep.ALLOWED_LANES:
        aggregate = _parity_aggregate([])
        aggregate["preflight"].update(
            {
                "report_interval": [
                    "2026-08-02T05:00:00+00:00",
                    "2026-08-09T05:00:00+00:00",
                ],
                "snapshot_identity": "a" * 64,
                "coverage_lane": "strong",
                "context_interval": [
                    "2026-05-01T00:00:00+00:00",
                    "2026-08-02T04:59:59.999999+00:00",
                ],
            }
        )
        results.append(
            {
                "window_ordinal": 0,
                "allowlist_lane": lane,
                "report_interval": aggregate["preflight"]["report_interval"],
                "context_interval": aggregate["preflight"]["context_interval"],
                "aggregate": aggregate,
                "semantic_digest": {"sha256": "b" * 64},
            }
        )
    artifact = {
        "schema_version": 3,
        "detector": "dnsblock",
        "series": {
            "window_count": 1,
            "batch_count": 1,
            "batch_window_counts": [1],
            "batch_content_identities": ["1" * 64],
            "content_identity_sha256": "1" * 64,
            "watchdog_enforced": True,
            "per_window_watchdog_seconds": 9000,
            "batch_deadline_seconds_by_batch": [9000],
            "assembly_overhead_seconds": 600,
            "series_deadline_seconds": 9600,
            "co_load": 1,
            "corpus": {"manifest_sha256": "c" * 64},
        },
        "results": results,
    }
    kwargs = {
        "receipt_dir": tmp_path,
        "mode": sweep.WindowMode.TRAIL,
        "overlay_diff_sha256": "d" * 64,
        "harness_sha256": "e" * 64,
        "imports_sha256": {"runner": "f" * 64},
    }
    first = sweep.write_series_receipts(artifact, **kwargs)
    assert len(first) == 2
    assert all(row["resumed"] is False for row in first)
    second = sweep.write_series_receipts(artifact, **kwargs)
    assert all(row["resumed"] is True for row in second)
    receipt_payload = sweep.verify_receipt(tmp_path / first[0]["receipt"])
    assert receipt_payload["per_window_watchdog_seconds"] == 9000
    assert receipt_payload["batch_window_counts"] == [1]
    assert receipt_payload["batch_deadline_seconds_by_batch"] == [9000]
    assert "batch_deadline_seconds" not in receipt_payload

    provisional = json.loads(json.dumps(artifact))
    provisional["series"]["per_window_watchdog_seconds"] = 3600
    provisional["series"]["batch_deadline_seconds_by_batch"] = [3600]
    provisional["series"]["series_deadline_seconds"] = 4200
    provisional_kwargs = {
        **kwargs,
        "receipt_dir": tmp_path / "provisional-watchdog",
        "harness_sha256": sweep.PROVISIONAL_WATCHDOG_HARNESS_SHA256,
    }
    provisional_rows = sweep.write_series_receipts(
        provisional,
        **provisional_kwargs,
    )
    assert len(provisional_rows) == 2
    provisional_payload = sweep.verify_receipt(
        provisional_kwargs["receipt_dir"] / provisional_rows[0]["receipt"]
    )
    assert provisional_payload["per_window_watchdog_seconds"] == 3600
    assert provisional_payload["batch_deadline_seconds_by_batch"] == [3600]

    flat = json.loads(json.dumps(artifact))
    flat["series"].pop("per_window_watchdog_seconds")
    flat["series"].pop("batch_deadline_seconds_by_batch")
    flat["series"]["batch_deadline_seconds"] = 1800
    flat["series"]["series_deadline_seconds"] = 2400
    flat_kwargs = {
        **kwargs,
        "receipt_dir": tmp_path / "flat-watchdog",
        "harness_sha256": sweep.FLAT_WATCHDOG_HARNESS_SHA256,
    }
    flat_rows = sweep.write_series_receipts(flat, **flat_kwargs)
    assert len(flat_rows) == 2
    flat_payload = sweep.verify_receipt(
        flat_kwargs["receipt_dir"] / flat_rows[0]["receipt"]
    )
    assert "per_window_watchdog_seconds" not in flat_payload
    assert "batch_deadline_seconds_by_batch" not in flat_payload

    malformed = json.loads(json.dumps(artifact))
    malformed["series"]["batch_window_counts"] = [0]
    with pytest.raises(ValueError, match="watchdog facts are inconsistent"):
        sweep.write_series_receipts(
            malformed,
            **{**kwargs, "receipt_dir": tmp_path / "malformed"},
        )

    legacy = json.loads(json.dumps(artifact))
    for field in (
        "watchdog_enforced",
        "per_window_watchdog_seconds",
        "batch_deadline_seconds",
        "batch_deadline_seconds_by_batch",
        "assembly_overhead_seconds",
        "series_deadline_seconds",
        "co_load",
    ):
        legacy["series"].pop(field, None)
    legacy_kwargs = {
        **kwargs,
        "receipt_dir": tmp_path / "legacy",
        "harness_sha256": sweep.PREPATCH_HARNESS_SHA256,
    }
    legacy_rows = sweep.write_series_receipts(legacy, **legacy_kwargs)
    legacy_payload = sweep.verify_receipt(
        legacy_kwargs["receipt_dir"] / legacy_rows[0]["receipt"]
    )
    assert legacy_payload["watchdog_enforced"] is False
    assert legacy_payload["co_load"] == 1
    assert "per_window_watchdog_seconds" not in legacy_payload
    assert "batch_deadline_seconds_by_batch" not in legacy_payload
    with pytest.raises(ValueError, match="state watchdog enforcement"):
        sweep.write_series_receipts(
            legacy,
            **{**legacy_kwargs, "harness_sha256": "9" * 64},
        )
    artifact["results"][0]["aggregate"]["status"] = "changed"
    with pytest.raises(ValueError, match="payload changed"):
        sweep.write_series_receipts(artifact, **kwargs)


def test_union_content_harness_allows_window_dependent_batch_sets_only_by_exact_hash():
    series = {
        "batch_count": 2,
        "batch_content_identities": ["a" * 64, "b" * 64],
        "content_identity_sha256": "c" * 64,
    }
    sweep._validate_series_content_identity(
        series, sweep.UNION_CONTENT_HARNESS_SHA256
    )
    with pytest.raises(ValueError, match="content identity is inconsistent"):
        sweep._validate_series_content_identity(series, "d" * 64)


def test_series_content_identity_validation_fails_closed_on_malformed_facts():
    series = {
        "batch_count": 2,
        "batch_content_identities": ["a" * 64],
        "content_identity_sha256": "b" * 64,
    }
    with pytest.raises(ValueError, match="content identity is malformed"):
        sweep._validate_series_content_identity(
            series, sweep.UNION_CONTENT_HARNESS_SHA256
        )


def _parity_aggregate(pass_wall):
    return {
        "schema_version": 1,
        "detector": "dnsblock",
        "status": "planned",
        "preflight": {
            "state": "READY",
            "coverage_lane": "strong",
            "pass_wall_seconds": pass_wall,
            "snapshot_identity": "a" * 64,
            "data_size_bytes": 1,
            "observed_data_window": None,
            "resident_bytes": 1,
            "rows_kept": 1,
            "rows_suppressed": 0,
            "raw_event_counts": [],
            "drop_counts": [],
        },
        "channels": {"burst": {"status": "READY"}},
        "burst_grids": [],
        "final_shape_routes": [],
        "recurring": None,
        "summary_notes": [],
        "burden": {},
        "withheld_arrival_burst_pairs": 0,
    }


def test_witness_comparison_requires_digest_and_full_aggregate_parity():
    digest = {
        "schema": "sigwood.dnsblock.semantic-digest",
        "version": 1,
        "sha256": "c" * 64,
        "finding_count": 0,
        "format": "json",
    }
    reference = {
        **_parity_aggregate([["population", 10.0]]),
        "harness": {"semantic_digest": digest},
    }
    candidate = {
        "aggregate": _parity_aggregate([["population_shared", 2.0]]),
        "semantic_digest": dict(digest),
    }
    first = sweep.compare_witness(reference, candidate)
    assert first["promotable"] is True
    assert first["provenance_differences"] == [
        {
            "path": "preflight.pass_wall_seconds",
            "reason": "pass_telemetry",
            "reference_sha256": first["provenance_differences"][0]["reference_sha256"],
            "candidate_sha256": first["provenance_differences"][0]["candidate_sha256"],
        }
    ]
    candidate["aggregate"]["preflight"]["coverage_lane"] = "weak"
    comparison = sweep.compare_witness(reference, candidate)
    assert comparison["semantic_digest_equal"] is True
    assert comparison["aggregate_equal"] is False
    assert comparison["promotable"] is False
    candidate["aggregate"]["unknown_semantic"] = 1
    with pytest.raises(ValueError, match="unknown or missing"):
        sweep.compare_witness(reference, candidate)


def test_bundle_verifier_enforces_authority_and_aggregate_only_schema(tmp_path):
    path = tmp_path / "bundle.json"
    components = {}
    for label in ("spec", "harness", "driver", "runner", "detector"):
        component = tmp_path / f"{label}.txt"
        component.write_text(label, encoding="utf-8")
        components[label] = component
    receipt = sweep.seal_bundle(
        path,
        result={
            "snapshot_identity_sha256": "a" * 64,
            "windows": [
                {"finding_count": 1, "survivor_set_sha256": "b" * 64}
            ],
        },
        component_paths=components,
        project_root=tmp_path,
        overlay_diff_sha256="c" * 64,
        import_sha256={"runner": "d" * 64, "detector": "e" * 64},
    )
    assert len(receipt["bundle_sha256"]) == 64
    verified = sweep.verify_bundle(path, project_root=tmp_path)
    assert verified["verified"] is True
    components["runner"].write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="component hash mismatch"):
        sweep.verify_bundle(path, project_root=tmp_path)


def test_bundle_seal_rejects_identity_bearing_result(tmp_path):
    components = {}
    for label in ("spec", "harness", "driver"):
        component = tmp_path / label
        component.write_text(label, encoding="utf-8")
        components[label] = component
    with pytest.raises(ValueError, match="identity-bearing"):
        sweep.seal_bundle(
            tmp_path / "bundle.json",
            result={"address": "192.0.2.1"},
            component_paths=components,
            project_root=tmp_path,
            overlay_diff_sha256="none",
            import_sha256={},
        )
