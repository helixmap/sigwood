"""Contracts for the private, provisional bench-mouth scheduler."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from tools import bench_mouth
from tools.bench_mouth import (
    AmbientProcess,
    AmbientSample,
    BenchJob,
    BenchPolicyError,
    admit_against_idle_floor,
    collect_ambient_idle_floor,
    run_bench_jobs,
)


def test_decision_jobs_are_structurally_solo_while_semantic_work_refills() -> None:
    lock = threading.Lock()
    active: set[str] = set()
    started: list[tuple[str, tuple[str, ...]]] = []

    def job(name: str, delay: float):
        def run() -> str:
            with lock:
                started.append((name, tuple(sorted(active))))
                active.add(name)
            time.sleep(delay)
            with lock:
                active.remove(name)
            return name

        return run

    receipt = run_bench_jobs(
        (
            BenchJob("semantic-a", "semantic", job("semantic-a", 0.04)),
            BenchJob("semantic-b", "semantic", job("semantic-b", 0.01)),
            BenchJob("decision", "decision", job("decision", 0.001)),
            BenchJob("semantic-c", "semantic", job("semantic-c", 0.001)),
        )
    )

    decision_start = next(active_at_start for name, active_at_start in started if name == "decision")
    assert decision_start == ()
    assert receipt.declared_width == 2
    assert receipt.peak_observed_occupancy == 2
    assert receipt.watchdog_margin == "not_measured"


def test_semantic_jobs_refill_slots_and_report_actual_occupancy() -> None:
    first_started = threading.Event()
    release_first = threading.Event()
    third_started = threading.Event()

    def first() -> str:
        first_started.set()
        assert release_first.wait(1)
        return "first"

    def second() -> str:
        assert first_started.wait(1)
        return "second"

    def third() -> str:
        third_started.set()
        release_first.set()
        return "third"

    receipt = run_bench_jobs(
        (
            BenchJob("first", "semantic", first),
            BenchJob("second", "semantic", second),
            BenchJob("third", "semantic", third),
        )
    )

    assert third_started.is_set()
    assert receipt.peak_observed_occupancy == 2
    by_name = {launch.name: launch for launch in receipt.launches}
    assert by_name["first"].observed_occupancy == 1
    assert by_name["second"].observed_occupancy == 2
    assert by_name["third"].observed_occupancy == 2


def test_declared_width_is_not_misreported_as_actual_single_job_occupancy() -> None:
    receipt = run_bench_jobs((BenchJob("only", "semantic", lambda: "ok"),))

    assert receipt.declared_width == 2
    assert receipt.launches[0].observed_occupancy == 1
    assert receipt.launches[0].declared_width == 2


def test_unratified_width_refuses_watchdog_bearing_work() -> None:
    with pytest.raises(BenchPolicyError, match="watchdog-bearing"):
        run_bench_jobs((BenchJob("watchdog", "semantic", lambda: None, watchdog_bearing=True),))


def test_polygon_ratified_width_admits_watchdog_work_without_widening_the_default() -> None:
    """A ratified width is per-HOST and must not leak into the general default.

    Guards the failure mode where one machine's measured width silently becomes every
    machine's: a caller on an unmeasured host would inherit a number that oversubscribes it
    while the receipt still read as ratified.
    """
    receipt = run_bench_jobs(
        (BenchJob("watchdog", "semantic", lambda: "ok", watchdog_bearing=True),),
        declared_width=bench_mouth.POLYGON_RATIFIED_WIDTH,
        ratified=True,
        ratification_provenance=bench_mouth.POLYGON_RATIFICATION_PROVENANCE,
    )

    assert receipt.declared_width == 16
    assert receipt.ratified is True
    assert receipt.watchdog_margin != bench_mouth.WATCHDOG_MARGIN_NOT_MEASURED
    assert "polygon" in receipt.ratification_provenance

    # The general artifact stays provisional and still refuses watchdog work.
    assert bench_mouth.DEFAULT_DECLARED_WIDTH == 2
    with pytest.raises(BenchPolicyError, match="watchdog-bearing"):
        run_bench_jobs((BenchJob("w2", "semantic", lambda: None, watchdog_bearing=True),))


def test_c1_coload_surface_remains_frozen_at_one_or_two() -> None:
    harness = Path(__file__).parents[1] / "tools" / "dnsblock_c1_harness.py"

    assert "choices=(1, 2)" in harness.read_text(encoding="utf-8")


def test_idle_floor_is_bounded_aggregate_only_and_detects_transient_work() -> None:
    samples = iter(
        (
            AmbientSample(3.0, (AmbientProcess("WindowServer", 6.0), AmbientProcess("idle", 1.0))),
            AmbientSample(2.5, (AmbientProcess("WindowServer", 5.0), AmbientProcess("idle", 2.0))),
            AmbientSample(2.8, (AmbientProcess("WindowServer", 6.0), AmbientProcess("idle", 1.0))),
        )
    )
    floor = collect_ambient_idle_floor(
        lambda: next(samples), sample_count=3, interval_seconds=0.1, sleep=lambda _: None
    )

    assert floor.sample_count == 3
    assert floor.load1_floor == 2.5
    assert not hasattr(floor, "samples")
    admitted = admit_against_idle_floor(
        floor,
        AmbientSample(2.9, (AmbientProcess("WindowServer", 90.0), AmbientProcess("mediaanalysisd", 34.0))),
    )
    assert admitted.admitted is False
    assert admitted.reason == "transient-process-above-idle-baseline"
    assert admitted.transient_processes == ("mediaanalysisd",)
    assert "WindowServer" in admitted.permanent_exclusions
