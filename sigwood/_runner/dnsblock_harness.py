"""Private dnsblock calibration batching and evidence artifacts."""
from __future__ import annotations

from typing import Any
from sigwood.common.loader import DualWindow
from typing import Mapping
from pathlib import Path
from sigwood.common.loader import PreparedState
from typing import Sequence
from dataclasses import asdict
from dataclasses import dataclass
from datetime import date
from datetime import datetime
import json
import os
from sigwood.common.paths import private_mkdir
from sigwood.common.paths import private_write_text
import time


@dataclass(frozen=True)
class DnsblockCalibrationBatch:
    """Private aggregate carrier returned by the calibration preparation path."""

    prepared: Mapping[tuple[int, str], Any]
    snapshot_identity_sha256: str
    content_identity_sha256: str
    pass_wall_seconds: tuple[tuple[str, float], ...]
    data_size_bytes: int
    max_window_routes: int
    max_inflight_cadence_gaps: int


def _prepare_dnsblock_calibration_batch(
    *,
    source_paths: Sequence[Path],
    windows: tuple[DualWindow, ...],
    lane_masks: Mapping[str, Any],
    dnsblock_mod: Any,
    calibration_vector: Any | None = None,
) -> DnsblockCalibrationBatch:
    """Prepare 2/4/8 exact windows and both allowlist lanes on real fold sinks.

    The broad ``DualWindow`` controls only physical I/O.  Every population and
    cadence sink reclassifies rows against its own exact interval.  Results are
    kept independent by unique fold channels and returned as ordinary
    ``DnsblockPrepared`` values for detector routing and real serializer use.
    """
    from sigwood.common import loader

    # STATUS=="planned" used to stand in for "this is the dnsblock harness".
    # Activation retires that proxy; identity is the property this machinery
    # actually requires, and unlike a planned/available union it can fail.
    if getattr(dnsblock_mod, "DETECTOR_NAME", None) != "dnsblock":
        raise ValueError("dnsblock calibration requires the dnsblock detector")
    if not 1 <= len(windows) <= 8:
        raise ValueError("dnsblock calibration window batch must contain 1 through 8 windows")
    if set(lane_masks) != {"default", "unsuppressed"}:
        raise ValueError("dnsblock calibration requires default and unsuppressed lanes")
    if not source_paths:
        raise ValueError("dnsblock calibration requires at least one source path")
    for window in windows:
        if not isinstance(window, DualWindow):
            raise ValueError("dnsblock calibration windows must use DualWindow")

    pattern = runner._PIHOLE_PATTERN
    one_pattern = {pattern: "pihole_dir"}
    source_dirs = {"pihole_dir": [Path(path) for path in source_paths]}
    starts = [
        window.context_interval[0]
        if window.context_interval is not None
        else window.report_interval[0]
        for window in windows
    ]
    broad = DualWindow((min(starts), max(window.report_interval[1] for window in windows)))
    pass_walls: dict[str, float] = {}

    anchor_sinks = tuple(
        dnsblock_mod.make_anchor_block_sink(
            lane_masks[lane],
            channel=f"dnsblock.anchor_blocks.{lane}",
        )
        for lane in ("default", "unsuppressed")
    )
    started = time.monotonic()
    anchor_result = loader.load_required_logs(
        one_pattern,
        source_dirs,
        broad.report_interval[0],
        broad.report_interval[1],
        show_progress=False,
        sink_plans={pattern: loader.SinkPlan(anchor_sinks, preserve_frame=False)},
        dual_windows={pattern: broad},
    )
    pass_walls["anchor_block_shared"] = time.monotonic() - started
    snapshot = anchor_result.snapshots.get(pattern)
    if snapshot is None:
        raise ValueError("dnsblock calibration could not establish a source snapshot")

    prepared: dict[tuple[int, str], Any] = {}
    inventories: dict[tuple[int, str], Any] = {}
    block_statuses: dict[tuple[int, str], Any] = {}
    population_sinks = []
    for index, window in enumerate(windows):
        for lane in ("default", "unsuppressed"):
            key = (index, lane)
            channel = f"dnsblock.anchor_blocks.{lane}"
            status = anchor_result.prepared_status.get(
                channel,
                loader.PreparedStatus(
                    loader.PreparedState.FAILED,
                    "anchor/block pass unavailable",
                ),
            )
            facts = anchor_result.fold_results.get(pattern, {}).get(channel)
            inventory = None
            if status.state is loader.PreparedState.READY and facts is not None:
                try:
                    inventory = dnsblock_mod.finalize_block_inventory(
                        facts.blocks,
                        window.report_interval,
                    )
                except loader.FoldAbstention as exc:
                    status = loader.PreparedStatus(loader.PreparedState.ABSTAINED, str(exc))
            inventories[key] = inventory or dnsblock_mod.BlockInventory()
            block_statuses[key] = status
            population_sinks.append(
                dnsblock_mod.make_population_sink(
                    inventories[key],
                    window,
                    lane_masks[lane],
                    channel=f"dnsblock.population.{index}.{lane}",
                    sink_local_window=True,
                    capture_summary_window=lane == "unsuppressed",
                )
            )

    started = time.monotonic()
    population_result = loader.load_required_logs(
        one_pattern,
        source_dirs,
        broad.report_interval[0],
        broad.report_interval[1],
        show_progress=False,
        sink_plans={
            pattern: loader.SinkPlan(tuple(population_sinks), preserve_frame=False)
        },
        dual_windows={pattern: broad},
        prepared_snapshots={pattern: snapshot},
    )
    pass_walls["population_shared"] = time.monotonic() - started
    population_states = {
        (index, lane): population_result.fold_results.get(pattern, {}).get(
            f"dnsblock.population.{index}.{lane}"
        )
        for index, _window in enumerate(windows)
        for lane in ("default", "unsuppressed")
    }
    for index, window in enumerate(windows):
        for lane in ("default", "unsuppressed"):
            key = (index, lane)
            channel = f"dnsblock.population.{index}.{lane}"
            coverage = runner._select_coverage_lane(
                population_result.availability.get(pattern, ()),
                window.report_interval,
            )
            population_status = population_result.prepared_status.get(
                channel,
                loader.PreparedStatus(
                    loader.PreparedState.FAILED,
                    "population pass unavailable",
                ),
            )
            prepared[key] = dnsblock_mod.build_prepared(
                snapshot_identity=snapshot.identity_sha256,
                window=window,
                coverage=coverage,
                block_status=block_statuses[key],
                population_status=population_status,
                blocks=inventories[key],
                population=population_states[key],
                pass_wall_seconds=tuple(sorted(pass_walls.items())),
                calibration_vector=calibration_vector,
                summary_population=population_states[(index, "unsuppressed")],
                data_size_bytes=population_result.data_size_bytes,
            )

    work: list[tuple[tuple[int, str], tuple[str, str], int]] = []
    for key in sorted(prepared):
        item = prepared[key]
        if (
            item.preflight.state is loader.PreparedState.READY
            and item.analysis is not None
        ):
            bounds = {
                (address, family): count
                for address, family, count in item.analysis.cadence_query_event_upper_bounds
            }
            work.extend((key, pair, bounds[pair]) for pair in item.analysis.cadence_worklist)

    cadence_results: dict[tuple[int, str], dict[tuple[str, str], Any]] = {
        key: {} for key in prepared
    }
    cadence_statuses = {
        key: loader.PreparedStatus(loader.PreparedState.READY) for key in prepared
    }
    cadence_started = time.monotonic()
    cadence_batches = _pack_dnsblock_calibration_work(
        tuple(work), limit=dnsblock_mod.LIMITS.cadence_gaps
    )
    max_inflight_cadence_gaps = max(
        (
            min(
                sum(item[2] for item in cadence_batch),
                dnsblock_mod.LIMITS.cadence_gaps,
            )
            for cadence_batch in cadence_batches
        ),
        default=0,
    )
    for batch in cadence_batches:
        sinks = []
        sink_meta: dict[str, tuple[tuple[int, str], tuple[tuple[str, str], ...], bool]] = {}
        grouped: dict[tuple[int, str], list[tuple[tuple[str, str], int]]] = {}
        for key, pair, bound in batch:
            grouped.setdefault(key, []).append((pair, bound))
        for key, values in grouped.items():
            index, lane = key
            pairs = tuple(pair for pair, _bound in values)
            over_bound = len(values) == 1 and values[0][1] > dnsblock_mod.LIMITS.cadence_gaps
            channel = f"dnsblock.cadence.{index}.{lane}"
            sink = (
                dnsblock_mod.make_cadence_sink(
                    pairs[0],
                    inventories[key],
                    lane_masks[lane],
                    window=windows[index],
                    channel=channel,
                )
                if over_bound
                else dnsblock_mod.make_cadence_batch_sink(
                    pairs,
                    inventories[key],
                    lane_masks[lane],
                    window=windows[index],
                    channel=channel,
                )
            )
            sinks.append(sink)
            sink_meta[channel] = (key, pairs, over_bound)
        cadence_load = loader.load_required_logs(
            one_pattern,
            source_dirs,
            broad.report_interval[0],
            broad.report_interval[1],
            show_progress=False,
            sink_plans={pattern: loader.SinkPlan(tuple(sinks), preserve_frame=False)},
            dual_windows={pattern: broad},
            prepared_snapshots={pattern: snapshot},
        )
        for channel, (key, pairs, over_bound) in sink_meta.items():
            status = cadence_load.prepared_status.get(
                channel,
                loader.PreparedStatus(
                    loader.PreparedState.FAILED,
                    "cadence pass unavailable",
                ),
            )
            if status.state is not loader.PreparedState.READY:
                cadence_statuses[key] = status
                continue
            result = cadence_load.fold_results.get(pattern, {}).get(channel)
            if result is None:
                cadence_statuses[key] = loader.PreparedStatus(
                    loader.PreparedState.FAILED,
                    "cadence pass produced no reducer state",
                )
                continue
            if over_bound:
                cadence_results[key][pairs[0]] = result
            else:
                cadence_results[key].update(
                    {
                        pair: result.states.get(pair, dnsblock_mod.CadenceState())
                        for pair in pairs
                    }
                )
    pass_walls["cadence_shared"] = time.monotonic() - cadence_started
    for key, item in tuple(prepared.items()):
        prepared[key] = dnsblock_mod.finalize_cadence(
            item,
            status=cadence_statuses[key],
            results=cadence_results[key],
            pass_wall_seconds=tuple(sorted(pass_walls.items())),
        )
    max_window_routes = max(
        (
            sum(count for _route, count in item.analysis.pair_routes)
            for item in prepared.values()
            if item.analysis is not None
        ),
        default=0,
    )
    return DnsblockCalibrationBatch(
        prepared=prepared,
        snapshot_identity_sha256=snapshot.identity_sha256,
        content_identity_sha256=snapshot.content_identity_sha256,
        pass_wall_seconds=tuple(sorted(pass_walls.items())),
        data_size_bytes=population_result.data_size_bytes,
        max_window_routes=max_window_routes,
        max_inflight_cadence_gaps=max_inflight_cadence_gaps,
    )


def _pack_dnsblock_calibration_work(
    work: tuple[tuple[tuple[int, str], tuple[str, str], int], ...],
    *,
    limit: int,
) -> tuple[tuple[tuple[tuple[int, str], tuple[str, str], int], ...], ...]:
    """Pack cross-window/lane cadence work under one total conservative bound."""
    if limit <= 0:
        raise ValueError("dnsblock calibration cadence limit must be positive")
    batches = []
    current = []
    total = 0
    for item in work:
        bound = int(item[2])
        if bound < 0:
            raise ValueError("dnsblock calibration cadence bound must be non-negative")
        if bound > limit:
            if current:
                batches.append(tuple(current))
                current = []
                total = 0
            batches.append((item,))
            continue
        if current and total + bound > limit:
            batches.append(tuple(current))
            current = []
            total = 0
        current.append(item)
        total += bound
    if current:
        batches.append(tuple(current))
    if tuple(item for batch in batches for item in batch) != work:
        raise ValueError("dnsblock calibration cadence packing lost work")
    return tuple(batches)


def _write_dnsblock_evidence_payload(path: Path, payload: Mapping[str, Any]) -> None:
    """Atomically persist an aggregate-only internal dnsblock evidence payload."""
    target = Path(path)
    if target.name in {"", ".", ".."}:
        raise ValueError("dnsblock preflight artifact needs a file path")
    private_mkdir(target.parent)
    temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")

    def encode(value: Any) -> Any:
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        if hasattr(value, "value"):
            return value.value
        raise TypeError(f"unsupported dnsblock evidence value: {type(value).__name__}")

    try:
        private_write_text(
            temporary,
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=encode)
            + "\n",
        )
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_dnsblock_preflight_progress(
    path: Path,
    *,
    snapshot_identity: str,
    report_interval: tuple[datetime, datetime],
    block_status: Any,
    pass_wall_seconds: tuple[tuple[str, float], ...],
) -> None:
    """Leave useful aggregate timing evidence even if population is timed out."""
    state = (
        "IN_PROGRESS"
        if block_status.state is PreparedState.READY
        else block_status.state.value
    )
    _write_dnsblock_evidence_payload(
        path,
        {
            "schema_version": 1,
            "detector": "dnsblock",
            "status": "planned",
            "preflight": {
                "state": state,
                "cause": (
                    "population pass in progress"
                    if state == "IN_PROGRESS"
                    else block_status.cause
                ),
                "snapshot_identity": snapshot_identity,
                "report_interval": report_interval,
                "pass_wall_seconds": pass_wall_seconds,
            },
        },
    )


def _write_dnsblock_preflight_artifact(path: Path, prepared: Any) -> None:
    """Atomically persist the completed aggregate-only dnsblock evidence carrier."""
    analysis = prepared.analysis
    aggregate: dict[str, Any] = {
        "channels": {},
        "burst_grids": [],
        "final_shape_routes": [],
        "burden": {"entity_findings": 0, "context_findings": 0},
        "recurring": None,
        "summary_notes": runner.flatten_notes(runner._format_dnsblock_summary_notes(prepared)),
    }
    if analysis is not None:
        aggregate.update(
            {
                "channels": {
                    "burst": asdict(analysis.burst_channel),
                    "recurring": {
                        "status": analysis.recurring.status,
                        "cause": analysis.recurring.cause,
                    },
                },
                "burst_grids": [asdict(cell) for cell in analysis.burst_grids],
                "final_shape_routes": list(analysis.final_shape_routes),
                "burden": {
                    "entity_findings": analysis.notes.entity_findings,
                    "context_findings": analysis.notes.context_findings,
                },
                "withheld_arrival_burst_pairs": (
                    analysis.withheld_arrival_burst_pairs
                ),
                "recurring": asdict(analysis.recurring),
            }
        )
    _write_dnsblock_evidence_payload(
        path,
        {
            "schema_version": 1,
            "detector": "dnsblock",
            "status": "planned",
            "preflight": asdict(prepared.preflight),
            **aggregate,
        },
    )


import sigwood.runner as runner
