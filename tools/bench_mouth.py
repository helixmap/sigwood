#!/usr/bin/env python3
"""Private, deliberately provisional scheduler for bounded bench work.

This tool separates a declared bench width from the occupancy actually observed
at each launch.  It is not a C1 scheduler and must not be used to widen the
frozen C1 co-load surface.  Until a width is ratified, watchdog-bearing work is
refused and every receipt says that a watchdog margin is not measured.

A ratified width exists for polygon only (``POLYGON_RATIFIED_WIDTH``).  Ratification is
per-host because the measurement is per-host; the general declared default stays
provisional so that a caller on an unmeasured machine cannot inherit another machine's
number without asking for it.

The ambient sampler is intentionally low-frequency and bounded.  It retains
only aggregate load and process-CPU maxima in its returned floor; it never
retains command lines, process identifiers, or a raw sample series.
"""

from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from statistics import median
import os
from pathlib import Path
import subprocess
import threading
import time
from typing import Callable, Iterable, Literal


JobClass = Literal["decision", "semantic"]
WATCHDOG_MARGIN_NOT_MEASURED = "not_measured"
# The GENERAL artifact stays provisional at 2. A ratified width is a property of the HOST it
# was measured on, so this default must not inherit one: the same number that is measured and
# safe on a 16-physical-core machine oversubscribes a 12-performance-core one, and a caller
# that never opted in would get an unmeasured width silently.
DEFAULT_DECLARED_WIDTH = 2

# Ratified for POLYGON ONLY, by a preregistered ladder sweep whose gates were fixed before any
# trial ran: semantic invariance held across 201 invocations (one digest), within-trial CV was
# 0.029 against a 0.20 bar, and degradation was located between 16 and 24 rather than left
# above an unprobed edge. Callers on any other host pass their own measured width or stay at
# the provisional default; there is no ratified width for euclid.
POLYGON_RATIFIED_WIDTH = 16
POLYGON_RATIFICATION_PROVENANCE = (
    "polygon-width-sweep-2026-08-15; ladder {1,2,4,8,12,16}+24, 3 trials each, 201 invocations"
)
DEFAULT_PERMANENT_SERVICES = frozenset({"WindowServer", "bztransmit"})


class BenchPolicyError(ValueError):
    """The requested private bench cannot make an honest provisional claim."""


@dataclass(frozen=True)
class BenchJob:
    """One in-memory bench job.

    ``decision`` jobs are wall-bearing: the scheduler runs them with no other
    job active.  ``semantic`` jobs are the only jobs eligible for N-slot work.
    """

    name: str
    job_class: JobClass
    run: Callable[[], object]
    watchdog_bearing: bool = False

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise BenchPolicyError("bench job name must be non-empty")
        if self.job_class not in {"decision", "semantic"}:
            raise BenchPolicyError("bench job class must be decision or semantic")


@dataclass(frozen=True)
class LaunchReceipt:
    """Aggregate per-launch evidence; planned width is never occupancy."""

    name: str
    job_class: JobClass
    declared_width: int
    observed_occupancy: int
    watchdog_margin: str
    result: object


@dataclass(frozen=True)
class BenchRunReceipt:
    declared_width: int
    ratified: bool
    ratification_provenance: str
    watchdog_margin: str
    launches: tuple[LaunchReceipt, ...]

    @property
    def peak_observed_occupancy(self) -> int:
        return max((launch.observed_occupancy for launch in self.launches), default=0)


def run_bench_jobs(
    jobs: Iterable[BenchJob],
    *,
    declared_width: int = DEFAULT_DECLARED_WIDTH,
    ratified: bool = False,
    ratification_provenance: str = "C1-width-2-provisional-only",
) -> BenchRunReceipt:
    """Run jobs with structural decision isolation and semantic refill.

    The scheduler preserves submission order.  It drains semantic work before
    a decision job, runs that decision solo, then refills semantic slots as
    each future completes.  That makes a decision boundary an execution
    property rather than a convention supplied by a caller.
    """

    if type(declared_width) is not int or declared_width < 1:
        raise BenchPolicyError("declared width must be a positive integer")
    if not ratification_provenance.strip():
        raise BenchPolicyError("ratification provenance must be non-empty")

    queued = deque(jobs)
    if not ratified and any(job.watchdog_bearing for job in queued):
        raise BenchPolicyError(
            "watchdog-bearing work is refused until the declared width is ratified"
        )
    watchdog_margin = "ratified" if ratified else WATCHDOG_MARGIN_NOT_MEASURED
    launches: list[LaunchReceipt] = []

    with ThreadPoolExecutor(max_workers=declared_width) as executor:
        active: dict[Future[object], BenchJob] = {}
        running_lock = threading.Lock()
        running_count = [0]
        while queued or active:
            # A decision boundary drains semantic work and never refills until
            # the decision has run alone.
            if queued and queued[0].job_class == "decision":
                if active:
                    _collect_completed(active, launches, declared_width, watchdog_margin)
                    continue
                job = queued.popleft()
                launches.append(
                    LaunchReceipt(
                        name=job.name,
                        job_class=job.job_class,
                        declared_width=declared_width,
                        observed_occupancy=1,
                        watchdog_margin=watchdog_margin,
                        result=job.run(),
                    )
                )
                continue

            # Fill every free semantic slot.  The next wait is
            # FIRST_COMPLETED, so a finished job immediately makes a slot for
            # the next eligible semantic job instead of creating static waves.
            while (
                queued
                and queued[0].job_class == "semantic"
                and len(active) < declared_width
            ):
                job = queued.popleft()
                future = executor.submit(_run_semantic, job, running_lock, running_count)
                active[future] = job

            if active:
                _collect_completed(active, launches, declared_width, watchdog_margin)
            elif queued:
                raise BenchPolicyError("unknown queued bench job class")

    return BenchRunReceipt(
        declared_width=declared_width,
        ratified=ratified,
        ratification_provenance=ratification_provenance,
        watchdog_margin=watchdog_margin,
        launches=tuple(launches),
    )


def _collect_completed(
    active: dict[Future[object], BenchJob],
    launches: list[LaunchReceipt],
    declared_width: int,
    watchdog_margin: str,
) -> None:
    done, _ = wait(active, return_when=FIRST_COMPLETED)
    for future in done:
        job = active.pop(future)
        result, occupancy = future.result()
        launches.append(
            LaunchReceipt(
                name=job.name,
                job_class=job.job_class,
                declared_width=declared_width,
                observed_occupancy=occupancy,
                watchdog_margin=watchdog_margin,
                result=result,
            )
        )


def _run_semantic(
    job: BenchJob,
    running_lock: threading.Lock,
    running_count: list[int],
) -> tuple[object, int]:
    """Return the real occupancy at job entry, not a queue-capacity guess."""

    with running_lock:
        running_count[0] += 1
        occupancy = running_count[0]
    try:
        return job.run(), occupancy
    finally:
        with running_lock:
            running_count[0] -= 1


@dataclass(frozen=True)
class AmbientProcess:
    name: str
    cpu_percent: float

    def __post_init__(self) -> None:
        if not self.name or self.cpu_percent < 0:
            raise BenchPolicyError("ambient process requires a name and non-negative CPU")


@dataclass(frozen=True)
class AmbientSample:
    load1: float
    processes: tuple[AmbientProcess, ...]

    def __post_init__(self) -> None:
        if self.load1 < 0:
            raise BenchPolicyError("ambient load must be non-negative")


@dataclass(frozen=True)
class AmbientIdleFloor:
    """Aggregate-only bounded sampler result suitable for a later admission."""

    sample_count: int
    load1_floor: float
    load1_median: float
    process_cpu_peak: tuple[tuple[str, float], ...]


@dataclass(frozen=True)
class AmbientAdmission:
    admitted: bool
    reason: str | None
    load1_limit: float
    transient_processes: tuple[str, ...]
    permanent_exclusions: tuple[str, ...]


def collect_ambient_idle_floor(
    sample: Callable[[], AmbientSample] | None = None,
    *,
    sample_count: int = 6,
    interval_seconds: float = 60.0,
    sleep: Callable[[float], None] = time.sleep,
) -> AmbientIdleFloor:
    """Collect a bounded low-frequency ambient baseline without bench work."""

    if type(sample_count) is not int or sample_count < 2:
        raise BenchPolicyError("ambient sampler requires at least two samples")
    if interval_seconds <= 0:
        raise BenchPolicyError("ambient sampling interval must be positive")
    reader = read_ambient_sample if sample is None else sample
    samples: list[AmbientSample] = []
    for index in range(sample_count):
        samples.append(reader())
        if index + 1 < sample_count:
            sleep(interval_seconds)

    peaks: dict[str, float] = {}
    for item in samples:
        for process in item.processes:
            peaks[process.name] = max(peaks.get(process.name, 0.0), process.cpu_percent)
    loads = [item.load1 for item in samples]
    return AmbientIdleFloor(
        sample_count=sample_count,
        load1_floor=min(loads),
        load1_median=float(median(loads)),
        process_cpu_peak=tuple(sorted(peaks.items())),
    )


def read_ambient_sample() -> AmbientSample:
    """Read one small host snapshot, retaining no PID, argv, or raw output."""

    completed = subprocess.run(
        ["ps", "-Ao", "comm=,pcpu="],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    processes: list[AmbientProcess] = []
    for line in completed.stdout.splitlines():
        fields = line.rsplit(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            cpu = float(fields[1])
        except ValueError:
            continue
        if cpu < 0:
            continue
        name = Path(fields[0]).name
        if name:
            processes.append(AmbientProcess(name=name, cpu_percent=cpu))
    return AmbientSample(load1=float(os.getloadavg()[0]), processes=tuple(processes))


def admit_against_idle_floor(
    floor: AmbientIdleFloor,
    current: AmbientSample,
    *,
    load1_delta: float = 0.5,
    cpu_percent_delta: float = 10.0,
    permanent_exclusions: Iterable[str] = DEFAULT_PERMANENT_SERVICES,
) -> AmbientAdmission:
    """Evaluate a later sweep admission relative to a measured idle baseline."""

    if load1_delta < 0 or cpu_percent_delta < 0:
        raise BenchPolicyError("ambient admission deltas must be non-negative")
    exclusions = tuple(sorted({name for name in permanent_exclusions if name}))
    exclusion_set = frozenset(exclusions)
    limit = floor.load1_floor + load1_delta
    if current.load1 > limit:
        return AmbientAdmission(False, "load-above-idle-baseline", limit, (), exclusions)
    baseline_cpu = dict(floor.process_cpu_peak)
    transient = tuple(
        sorted(
            process.name
            for process in current.processes
            if process.name not in exclusion_set
            and process.cpu_percent > baseline_cpu.get(process.name, 0.0) + cpu_percent_delta
        )
    )
    if transient:
        return AmbientAdmission(False, "transient-process-above-idle-baseline", limit, transient, exclusions)
    return AmbientAdmission(True, None, limit, (), exclusions)
