#!/usr/bin/env python3
"""Aggregate-only C1 calibration campaign driver for planned dnsblock.

This module owns window enumeration, complete-campaign projection, resumable
receipt identity, selection arithmetic, terminal classification, and bundle
verification.  It never parses a log or derives detector semantics; every
measurement receipt must come from ``dnsblock_c1_harness.py`` over the real
runner path.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import itertools
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from sigwood.common.paths import private_mkdir, private_write_bytes, private_write_text


SCHEMA = "sigwood.dnsblock.c1-sweep"
SCHEMA_VERSION = 1
SPEC_VERSION = "7.1"
SPEC_SHA256 = "14b75eab74801f03cdd6bbfce73c162e8671eee41fc7eb2b37cf216590ac564a"
BASELINE_COMMIT = "cf9dd615016e398934de269075dd9cccde5e39ef"
WINDOW_DAYS = 7
CAMPAIGN_CEILING_SECONDS = 36 * 60 * 60
BUNDLE_MAX_BYTES = 100_000_000
BUNDLE_MAX_ROWS = 1_000_000
FOLD_RSS_MAX_BYTES = 1536 * 1024 * 1024
TEMP_MAX_BYTES = 1024 * 1024 * 1024
WINDOW_ROUTE_MAX = 1_000_000
CADENCE_GAP_MAX = 10_000
ALLOWED_LANES = ("default", "unsuppressed")
ALLOWED_COVERAGE = ("strong", "weak")
WINDOW_BATCH_SIZES = (2, 4, 8)
ASSEMBLY_OVERHEAD_SECONDS = 600
# MEASURED: the heaviest context-true single window was approximately 7600s;
# 9000s retains roughly 1.2x margin while tight bounds reduce expected work.
PER_WINDOW_WATCHDOG_SECONDS = 9000
PREPATCH_HARNESS_SHA256 = "5b3570e46388e786e00123fee39a9e07a2147783a2789283fa690a8ff6053b20"
FLAT_WATCHDOG_HARNESS_SHA256 = "aadb0d04317677db43da388c4575987ff9455b9e157968a2b3280d89407d5934"
PROVISIONAL_WATCHDOG_HARNESS_SHA256 = "bdc3886c40b28bda7485e12032f028f1c9d8f6f480577a4921d434bc37010903"
UNION_CONTENT_HARNESS_SHA256 = "9b918d6179dcb972a83a77884edf8296e7c0de3e8786aad7bfff53757a152877"

MATRIX_OBLIGATIONS: Mapping[str, tuple[str, ...]] = {
    "future_leak": (
        "tests/test_dnsblock_detector.py::test_future_row_outside_dual_window_cannot_change_grid_digests",
    ),
    "availability_vs_data_bearing": (
        "tests/test_export_provenance.py::test_runner_merges_overlaps_and_keeps_unbounded_conservative",
        "tests/test_export_provenance.py::test_validation_downgrades_missing_mismatch_incomplete_and_symlink",
        "tests/test_export_provenance.py::test_real_export_load_and_runner_lane_then_mutation_downgrade",
        "tests/test_dnsblock_detector.py::test_readiness_negatives_keep_positive_observations_outside_lane_one",
    ),
    "instant_boundary_partial_left": (
        "tests/test_loader_fold.py::test_dual_window_requires_strictly_earlier_context",
        "tests/test_dnsblock_detector.py::test_period_boundaries_match_scalar_and_vectorized_paths",
        "tests/test_dnsblock_u3.py::test_sink_local_window_classification_overrides_broad_physical_masks",
        "tests/test_dnsblock_c1_sweep.py::test_disjoint_short_tail_is_provenance_not_a_shift_window",
    ),
    "complete_conservation": (
        "tests/test_dnsblock_u3.py::test_actual_pair_routes_conserve_the_complete_frozen_vocabulary",
        "tests/test_dnsblock_u4.py::test_burst_grid_routes_all_pairs_once_and_uses_earliest_wall_clock_argmax",
        "tests/test_dnsblock_u4.py::test_recurring_state_and_row_survive_overlap_resolution_and_stay_context_last",
        "tests/test_dnsblock_u3.py::test_u3_fold_conserves_members_and_report_only_share_facts",
        "tests/test_dnsblock_u5.py::test_recurring_visibility_matrix_is_output_owned_and_counts_are_pre_cap",
        "tests/test_dnsblock_u5.py::test_context_rows_are_last_full_width_and_outside_the_cap_budget",
        "tests/test_dnsblock_u5.py::test_unknown_kind_is_preserved_in_a_trailing_full_width_section",
        "tests/test_dnsblock_u3.py::test_cap_note_table_is_lockstep_with_every_detector_cap_cause",
    ),
    "mixed_reason_permutation": (
        "tests/test_dnsblock_u4.py::test_burst_grid_and_candidates_are_deterministic_under_state_permutation",
        "tests/test_dnsblock_u5.py::test_semantic_digest_ignores_volatile_fields_and_moves_on_meaning",
    ),
    "a1_subset_and_route_flip": (
        "tests/test_dnsblock_detector.py::test_population_preflight_has_all_twelve_grid_cells_and_a1_subset",
        "tests/test_dnsblock_detector.py::test_finalized_block_inventory_matches_dedicated_pass_on_straddling_start_date",
    ),
    "candidate_prefix_readiness": (
        "tests/test_dnsblock_detector.py::test_readiness_negatives_keep_positive_observations_outside_lane_one",
    ),
    "real_cap_trip_discard": (
        "tests/test_loader_fold.py::test_common_record_limit_exact_and_one_over_are_constant_derived",
        "tests/test_loader_fold.py::test_chunk_caps_exact_and_one_over_without_giant_allocation",
        "tests/test_dnsblock_detector.py::test_population_cap_table_abstains_without_partial_state",
        "tests/test_dnsblock_detector.py::test_postfold_cap_table_abstains_without_partial_prepared_state",
        "tests/test_dnsblock_u3.py::test_cadence_batch_enforces_total_in_flight_gap_cap",
    ),
    "hostile_name_real_renderers": (
        "tests/test_runner_dnsblock.py::test_control_bearing_name_is_dropped_on_real_loader_runner_route",
        "tests/test_runner_dnsblock.py::test_admissible_hostile_unknown_suffix_traverses_real_reading_routes",
        "tests/test_dnsblock_u5.py::test_all_five_handlers_receive_dnsblock_and_keep_machine_surfaces_uncapped",
        "tests/test_raw_output_sink_sanitize.py",
    ),
    "bounded_and_configured_windows": (
        "tests/test_loader_fold.py::test_bounded_explicit_and_all_never_gain_implicit_context",
        "tests/test_loader_fold.py::test_unbounded_fold_context_ends_one_microsecond_before_report",
    ),
    "steady_partial_negative": (
        "tests/test_dnsblock_u4.py::test_steady_partial_capture_does_not_clear_burst_and_missing_strong_period_speaks",
    ),
    "snapshot_mutation_refusal": (
        "tests/test_loader_fold.py::test_prepared_snapshot_reuse_performs_no_rediscovery_or_recapture",
        "tests/test_loader_fold.py::test_snapshot_mutation_fails_fold_and_discards_all_partial_state",
        "tests/test_loader_fold.py::test_snapshot_refuses_equal_size_equal_mtime_rewrite",
        "tests/test_loader_fold.py::test_cancellation_propagates_without_commit",
    ),
    "allowlist_lane_isolation": (
        "tests/test_runner_dnsblock.py::test_no_allowlist_uses_zero_copy_keep_mask",
        "tests/test_runner_dnsblock.py::test_private_calibration_batch_shares_physical_passes_and_isolates_windows_lanes",
        "tests/test_runner_dnsblock.py::test_matcher_parity_through_real_runner_route",
    ),
    "mixed_frame_fold_stability": (
        "tests/test_loader_fold.py::test_fold_failure_and_cap_abstention_preserve_frame_sibling",
        "tests/test_loader_fold.py::test_folded_and_ordinary_oversize_parity",
        "tests/test_runner_dnsblock.py::test_mixed_pihole_sibling_receives_one_ordinary_final_frame",
    ),
    "coverage_lane_selection": (
        "tests/test_runner_dnsblock.py::test_final_population_validation_is_the_only_coverage_source",
        "tests/test_dnsblock_u4.py::test_weak_lane_refuses_burst_and_recurring_without_grid_evaluation",
    ),
    "c1_window_batch_resume_selection_seal": (
        "tests/test_dnsblock_c1_sweep.py",
        "tests/test_dnsblock_c1_harness.py::test_harness_batch_request_uses_real_shared_runner_and_json_serializer",
        "tests/test_dnsblock_c1_harness.py::test_harness_series_request_partitions_tail_and_emits_only_aggregate_unions",
        "tests/test_dnsblock_u3.py::test_cadence_batch_matches_independent_pair_reducers",
        "tests/test_runner_dnsblock.py::test_cross_carrier_cadence_packing_enforces_one_total_bound",
        "tests/test_dnsblock_u4.py::test_private_burst_vector_and_arrival_only_arm_keep_complete_grid",
    ),
}

_IDENTITY_KEYS = frozenset(
    {
        "address",
        "addresses",
        "family",
        "family_key",
        "families",
        "name",
        "names",
        "src",
        "query",
        "identity",
        "identities",
        "survivors",
    }
)


class WindowMode(str, Enum):
    TRAIL = "W-TRAIL"
    SHIFT = "W-SHIFT"
    DISJ = "W-DISJ"
    ALL = "W-ALL"


class TerminalOutcome(str, Enum):
    RETURN_WALL = "RETURN_WALL"
    RETURN_INVALID_OR_BURDEN = "RETURN_INVALID_OR_BURDEN"
    SEALED_RATIFIED = "SEALED_RATIFIED"
    SEALED_RATIFIED_ARRIVAL_ONLY = "SEALED_RATIFIED_ARRIVAL_ONLY"


@dataclass(frozen=True)
class CalibrationWindow:
    mode: WindowMode
    ordinal: int
    start: datetime
    end: datetime
    partial_tail: bool = False

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("C1 windows must be timezone-aware")
        if self.start > self.end:
            raise ValueError("C1 window start must not follow its end")

    def json(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "ordinal": self.ordinal,
            "start": self.start.astimezone(timezone.utc).isoformat(),
            "end": self.end.astimezone(timezone.utc).isoformat(),
            "partial_tail": self.partial_tail,
        }

    def harness_request(self, *, corpus_earliest: datetime) -> dict[str, str]:
        """Project provenance-bearing calibration metadata into DualWindow JSON."""
        if corpus_earliest.tzinfo is None or corpus_earliest.utcoffset() is None:
            raise ValueError("C1 corpus start must be timezone-aware")
        earliest = corpus_earliest.astimezone(timezone.utc)
        start = self.start.astimezone(timezone.utc)
        result = {
            "start": start.isoformat(),
            "end": self.end.astimezone(timezone.utc).isoformat(),
        }
        if start > earliest:
            result.update(
                {
                    "context_start": earliest.isoformat(),
                    "context_end": (start - timedelta(microseconds=1)).isoformat(),
                }
            )
        return result


def harness_series_request(
    windows: Sequence[CalibrationWindow], *, corpus_earliest: datetime
) -> dict[str, list[dict[str, str]]]:
    """Return the exact context-true private harness request projection."""
    if not windows:
        raise ValueError("C1 harness request requires at least one window")
    return {
        "windows": [
            window.harness_request(corpus_earliest=corpus_earliest)
            for window in windows
        ]
    }


@dataclass(frozen=True)
class CampaignProjection:
    series_seconds: tuple[tuple[str, float], ...]
    overhead_seconds: float
    total_seconds: float
    ceiling_seconds: int

    @property
    def promotes(self) -> bool:
        return self.total_seconds < self.ceiling_seconds


class GridSurvivorAccumulator:
    """In-memory survivor union that releases only counts and set digests."""

    def __init__(self, cell_count: int) -> None:
        if isinstance(cell_count, bool) or not isinstance(cell_count, int) or cell_count <= 0:
            raise ValueError("C1 survivor grid size must be a positive integer")
        self._cell_count = cell_count
        self._cells: list[set[str]] = [set() for _index in range(cell_count)]

    def ingest(self, memberships: Sequence[tuple[str, int]]) -> None:
        seen: set[str] = set()
        for identity, mask in memberships:
            if (
                not isinstance(identity, str)
                or "\0" not in identity
                or identity in seen
            ):
                raise ValueError("C1 survivor membership identity is malformed or repeated")
            if (
                isinstance(mask, bool)
                or not isinstance(mask, int)
                or mask <= 0
                or mask >= (1 << self._cell_count)
            ):
                raise ValueError("C1 survivor membership mask is outside the grid")
            seen.add(identity)
            remaining = mask
            while remaining:
                least_bit = remaining & -remaining
                index = least_bit.bit_length() - 1
                self._cells[index].add(identity)
                remaining ^= least_bit

    def aggregate(self) -> tuple[dict[str, int | str], ...]:
        rows = []
        for index, identities in enumerate(self._cells):
            encoded = json.dumps(
                tuple(sorted(identities)), separators=(",", ":")
            ).encode("utf-8")
            rows.append(
                {
                    "cell_index": index,
                    "qualifying_pairs": len(identities),
                    "identity_digest": _sha256_bytes(encoded),
                }
            )
        return tuple(rows)

    def clear(self) -> None:
        self._cells = [set() for _index in range(self._cell_count)]


def _instant(text: str) -> datetime:
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    value = datetime.fromisoformat(normalized)
    if value.tzinfo is None or value.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include a UTC offset")
    return value.astimezone(timezone.utc)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _read_regular_nofollow(
    path: Path, *, max_bytes: int = 8 * 1024 * 1024
) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    )
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("C1 weak snapshot source is not a regular file")
        if info.st_size > max_bytes:
            raise ValueError("C1 weak manifest exceeds its byte bound")
        raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("C1 weak manifest exceeds its byte bound")
        return raw, info


def _hash_regular_nofollow(path: Path) -> tuple[int, str, os.stat_result]:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    )
    digest = hashlib.sha256()
    size = 0
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("C1 weak snapshot source is not a regular file")
        while block := stream.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    return size, digest.hexdigest(), info


def _parse_weak_manifest(raw: bytes) -> tuple[tuple[str, int, str], ...]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("C1 weak manifest is not UTF-8") from exc
    rows = []
    seen = set()
    for line in lines:
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError("C1 weak manifest row is malformed")
        name, size_text, digest = fields
        if (
            Path(name).name != name
            or name in {".", ".."}
            or name in seen
            or not size_text.isascii()
            or not size_text.isdigit()
            or (size_text.startswith("0") and size_text != "0")
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("C1 weak manifest member is unsafe or noncanonical")
        seen.add(name)
        rows.append((name, int(size_text), digest))
    if not rows:
        raise ValueError("C1 weak manifest is empty")
    return tuple(rows)


def pin_weak_corpus(
    *, source: Path, manifest: Path, destination_parent: Path
) -> dict[str, Any]:
    """Publish one immutable, content-addressed weak campaign snapshot."""
    source = Path(source)
    manifest = Path(manifest)
    destination_parent = Path(destination_parent)
    raw_manifest, manifest_stat = _read_regular_nofollow(manifest)
    rows = _parse_weak_manifest(raw_manifest)
    if manifest.name in {name for name, _size, _digest in rows}:
        raise ValueError("C1 weak manifest collides with a selected member")
    manifest_sha256 = _sha256_bytes(raw_manifest)
    total_bytes = sum(size for _name, size, _digest in rows)
    private_mkdir(destination_parent)
    if shutil.disk_usage(destination_parent).free < 2 * (total_bytes + len(raw_manifest)):
        raise ValueError("C1 weak snapshot destination lacks staging capacity")
    final = destination_parent / f"weak-{manifest_sha256}"

    def validate_published(path: Path) -> None:
        published_manifest, _info = _read_regular_nofollow(path / manifest.name)
        if published_manifest != raw_manifest:
            raise ValueError("C1 published weak snapshot manifest drifted")
        if {item.name for item in path.iterdir()} != {
            manifest.name,
            *(name for name, _size, _digest in rows),
        }:
            raise ValueError("C1 published weak snapshot member set drifted")
        for name, size, digest in rows:
            actual_size, actual_digest, _info = _hash_regular_nofollow(path / name)
            if actual_size != size or actual_digest != digest:
                raise ValueError("C1 published weak snapshot member drifted")

    if final.exists():
        validate_published(final)
        return {
            "path": final,
            "manifest_sha256": manifest_sha256,
            "member_count": len(rows),
            "weak_snapshot_bytes": total_bytes,
            "reused": True,
        }

    stage = Path(tempfile.mkdtemp(prefix=".weak-stage-", dir=destination_parent))
    os.chmod(stage, 0o700)
    marker = stage / ".c1-owned-stage"
    private_write_text(marker, manifest_sha256 + "\n")
    try:
        for name, expected_size, expected_digest in rows:
            source_path = source / name
            descriptor = os.open(
                source_path,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            )
            destination_path = stage / name
            output = os.open(
                destination_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            digest = hashlib.sha256()
            copied = 0
            try:
                with os.fdopen(descriptor, "rb") as source_stream, os.fdopen(
                    output, "wb"
                ) as destination_stream:
                    source_info = os.fstat(source_stream.fileno())
                    if not stat.S_ISREG(source_info.st_mode):
                        raise ValueError("C1 weak snapshot member is not regular")
                    while block := source_stream.read(1024 * 1024):
                        destination_stream.write(block)
                        digest.update(block)
                        copied += len(block)
                    destination_stream.flush()
                    os.fsync(destination_stream.fileno())
            except BaseException:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                try:
                    os.close(output)
                except OSError:
                    pass
                raise
            if copied != expected_size or digest.hexdigest() != expected_digest:
                raise ValueError("C1 weak snapshot member does not match manifest")
            reopened_size, reopened_digest, reopened_info = _hash_regular_nofollow(
                source_path
            )
            if (
                reopened_size != expected_size
                or reopened_digest != expected_digest
                or reopened_info.st_dev != source_info.st_dev
                or reopened_info.st_ino != source_info.st_ino
                or reopened_info.st_size != source_info.st_size
                or reopened_info.st_mtime_ns != source_info.st_mtime_ns
            ):
                raise ValueError("C1 weak snapshot member changed during copy")
        current_manifest, current_stat = _read_regular_nofollow(manifest)
        if (
            current_manifest != raw_manifest
            or current_stat.st_dev != manifest_stat.st_dev
            or current_stat.st_ino != manifest_stat.st_ino
            or current_stat.st_size != manifest_stat.st_size
            or current_stat.st_mtime_ns != manifest_stat.st_mtime_ns
        ):
            raise ValueError("C1 weak manifest changed during snapshot publication")
        private_write_bytes(stage / manifest.name, raw_manifest)
        manifest_fd = os.open(
            stage / manifest.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            os.fsync(manifest_fd)
        finally:
            os.close(manifest_fd)
        directory_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        marker.unlink()
        os.replace(stage, final)
        parent_fd = os.open(destination_parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        validate_published(final)
    except BaseException:
        if stage.exists() and marker.exists():
            for child in stage.iterdir():
                if child.is_file() and not child.is_symlink():
                    child.unlink()
            stage.rmdir()
        raise
    return {
        "path": final,
        "manifest_sha256": manifest_sha256,
        "member_count": len(rows),
        "weak_snapshot_bytes": total_bytes,
        "reused": False,
    }


def run_measurement_schedule(
    jobs: Sequence[Mapping[str, Any]],
    runner: Any,
) -> tuple[dict[str, Any], ...]:
    """Run decision inputs solo and bounded non-decision work at width two."""
    results: list[dict[str, Any] | None] = [None] * len(jobs)

    def run_one(index: int, job: Mapping[str, Any], co_load: int) -> dict[str, Any]:
        receipt = runner(job, co_load=co_load)
        if not isinstance(receipt, dict):
            raise ValueError("C1 measurement runner must return one receipt object")
        observed = receipt.get("co_load", co_load)
        if observed != co_load:
            raise ValueError("C1 measurement receipt co-load is not observed occupancy")
        row = {"job_index": index, "co_load": co_load, "receipt": receipt}
        if co_load == 2 and receipt.get("failure") in {
            "batch_watchdog_timeout",
            "series_watchdog_timeout",
        }:
            retry = runner(job, co_load=1)
            if not isinstance(retry, dict) or retry.get("co_load", 1) != 1:
                raise ValueError("C1 solo watchdog retry receipt is malformed")
            row["solo_retry"] = retry
            row["decision_receipt"] = retry
        else:
            row["solo_retry"] = None
            row["decision_receipt"] = receipt
        return row

    pending: list[tuple[int, Mapping[str, Any]]] = []

    def flush_pending() -> None:
        nonlocal pending
        while pending:
            group, pending = pending[:2], pending[2:]
            width = len(group)
            if width == 1:
                index, job = group[0]
                results[index] = run_one(index, job, 1)
                continue
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = {
                    executor.submit(run_one, index, job, 2): index
                    for index, job in group
                }
                for future, index in futures.items():
                    results[index] = future.result()

    for index, job in enumerate(jobs):
        if not isinstance(job, Mapping):
            raise ValueError("C1 measurement job must be an object")
        if job.get("decision_input") is True:
            flush_pending()
            results[index] = run_one(index, job, 1)
        elif job.get("decision_input") is False:
            pending.append((index, job))
        else:
            raise ValueError("C1 measurement job must classify decision input")
    flush_pending()
    if any(row is None for row in results):
        raise ValueError("C1 measurement schedule lost a job")
    return tuple(row for row in results if row is not None)


def write_prepatch_watchdog_annotation(
    *, artifact: Path, driver_receipt: Path, destination: Path
) -> dict[str, Any]:
    """Bind immutable pre-patch evidence to its truthful NOT_ENFORCED label."""
    artifact_sha256 = _sha256_file(Path(artifact))
    receipt_sha256 = _sha256_file(Path(driver_receipt))
    payload = {
        "schema": f"{SCHEMA}.watchdog-annotation",
        "schema_version": 1,
        "artifact_sha256": artifact_sha256,
        "driver_receipt_sha256": receipt_sha256,
        "harness_sha256": PREPATCH_HARNESS_SHA256,
        "watchdog_enforced": False,
        "series_watchdog": "NOT_ENFORCED",
    }
    atomic_receipt(Path(destination), payload)
    return payload


def watchdog_only_rerun_set(
    measurements: Mapping[str, Sequence[str]],
) -> tuple[str, ...]:
    """Return only measurements whose grading dependencies consume watchdogs."""
    allowed = {
        "watchdog_enforced",
        "semantic_digest",
        "aggregate_parity",
        "elapsed_wall",
        "survivor_digest",
        "route_count",
        "census",
        "rss",
        "temp",
        "immutable_caps",
    }
    reruns = []
    for label, dependencies in measurements.items():
        if not isinstance(label, str) or not label or not isinstance(dependencies, Sequence):
            raise ValueError("C1 measurement dependency declaration is malformed")
        dependency_set = set(dependencies)
        if not dependency_set <= allowed:
            raise ValueError("C1 measurement dependency is not recognized")
        if "watchdog_enforced" in dependency_set:
            reruns.append(label)
    return tuple(reruns)


def enumerate_windows(
    earliest: datetime,
    anchor: datetime,
    *,
    days: int = WINDOW_DAYS,
) -> dict[WindowMode, tuple[CalibrationWindow, ...]]:
    """Enumerate the v7.1 instant-grain W-TRAIL/SHIFT/DISJ/ALL list."""
    if earliest.tzinfo is None or anchor.tzinfo is None:
        raise ValueError("C1 corpus bounds must be timezone-aware")
    earliest = earliest.astimezone(timezone.utc)
    anchor = anchor.astimezone(timezone.utc)
    if earliest > anchor:
        raise ValueError("C1 corpus start must not follow its anchor")
    if days <= 0:
        raise ValueError("C1 window length must be positive")
    span = timedelta(days=days)
    step = timedelta(days=1)

    trail = CalibrationWindow(WindowMode.TRAIL, 0, anchor - span, anchor)
    shifts: list[CalibrationWindow] = []
    ordinal = 0
    end = anchor
    while end - span >= earliest:
        shifts.append(
            CalibrationWindow(WindowMode.SHIFT, ordinal, end - span, end)
        )
        ordinal += 1
        end -= step

    disjoint: list[CalibrationWindow] = []
    start = earliest
    ordinal = 0
    while start < anchor:
        end = min(start + span, anchor)
        disjoint.append(
            CalibrationWindow(
                WindowMode.DISJ,
                ordinal,
                start,
                end,
                partial_tail=(end - start) < span,
            )
        )
        ordinal += 1
        start = end

    whole = CalibrationWindow(WindowMode.ALL, 0, earliest, anchor)
    return {
        WindowMode.TRAIL: (trail,),
        WindowMode.SHIFT: tuple(shifts),
        WindowMode.DISJ: tuple(disjoint),
        WindowMode.ALL: (whole,),
    }


def complete_campaign_projection(
    *,
    strong_window_seconds: Mapping[str, float],
    weak_window_seconds: Mapping[str, float],
    strong_shift_count: int,
    weak_shift_count: int,
    overhead_seconds: float,
    ceiling_seconds: int = CAMPAIGN_CEILING_SECONDS,
) -> CampaignProjection:
    """Project all four selection-bearing series plus bounded overhead."""
    if strong_shift_count < 0 or weak_shift_count < 0:
        raise ValueError("C1 W-SHIFT counts must be non-negative")
    if overhead_seconds < 0 or ceiling_seconds <= 0:
        raise ValueError("C1 projection bounds must be positive")
    series: list[tuple[str, float]] = []
    for coverage, walls, count in (
        ("strong", strong_window_seconds, strong_shift_count),
        ("weak", weak_window_seconds, weak_shift_count),
    ):
        if set(walls) != set(ALLOWED_LANES):
            raise ValueError(f"C1 {coverage} projection requires both allowlist lanes")
        for lane in ALLOWED_LANES:
            wall = float(walls[lane])
            if not math.isfinite(wall) or wall < 0:
                raise ValueError("C1 projected wall must be finite and non-negative")
            series.append((f"{coverage}:{lane}", wall * count))
    total = sum(value for _key, value in series) + float(overhead_seconds)
    return CampaignProjection(
        tuple(series),
        float(overhead_seconds),
        total,
        int(ceiling_seconds),
    )


def select_wall_candidate(
    candidates: Sequence[Mapping[str, Any]],
    *,
    strong_shift_count: int,
    weak_shift_count: int,
    overhead_seconds: float,
) -> dict[str, Any]:
    """Grade the frozen 2/4/8 Phase-W candidates and select the fastest green one."""
    if [candidate.get("batch_size") for candidate in candidates] != [2, 4, 8]:
        raise ValueError("C1 Phase-W candidates must be exactly 2, 4, 8 in order")
    rows = []
    eligible = []
    for candidate in candidates:
        if set(candidate) != {
            "batch_size",
            "strong_window_seconds",
            "weak_window_seconds",
            "witness_comparisons",
            "snapshot_verified",
            "max_process_rss_bytes",
            "max_temp_bytes",
            "max_window_routes",
            "max_inflight_cadence_gaps",
            "memory_estimate_monotonic",
        }:
            raise ValueError("C1 Phase-W candidate fields are incomplete")
        comparisons = candidate["witness_comparisons"]
        if not isinstance(comparisons, list) or not comparisons:
            raise ValueError("C1 Phase-W candidate witness set is empty")
        if any(
            not isinstance(comparison, dict)
            or not isinstance(comparison.get("promotable"), bool)
            for comparison in comparisons
        ):
            raise ValueError("C1 Phase-W witness comparison is malformed")
        resources = {}
        for field in (
            "max_process_rss_bytes",
            "max_temp_bytes",
            "max_window_routes",
            "max_inflight_cadence_gaps",
        ):
            value = candidate[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("C1 Phase-W resource measurement is invalid")
            resources[field] = value
        if not isinstance(candidate["snapshot_verified"], bool) or not isinstance(
            candidate["memory_estimate_monotonic"], bool
        ):
            raise ValueError("C1 Phase-W candidate gate must be boolean")
        projection = complete_campaign_projection(
            strong_window_seconds=candidate["strong_window_seconds"],
            weak_window_seconds=candidate["weak_window_seconds"],
            strong_shift_count=strong_shift_count,
            weak_shift_count=weak_shift_count,
            overhead_seconds=overhead_seconds,
        )
        rejected = []
        if not all(comparison["promotable"] for comparison in comparisons):
            rejected.append("semantic_parity")
        if not candidate["snapshot_verified"]:
            rejected.append("snapshot_identity")
        if resources["max_process_rss_bytes"] > FOLD_RSS_MAX_BYTES:
            rejected.append("process_rss")
        if resources["max_temp_bytes"] > TEMP_MAX_BYTES:
            rejected.append("temp_bytes")
        if resources["max_window_routes"] > WINDOW_ROUTE_MAX:
            rejected.append("window_routes")
        if resources["max_inflight_cadence_gaps"] > CADENCE_GAP_MAX:
            rejected.append("cadence_gaps")
        if not candidate["memory_estimate_monotonic"]:
            rejected.append("memory_estimate")
        if not projection.promotes:
            rejected.append("campaign_wall")
        row = {
            "batch_size": candidate["batch_size"],
            "projection": asdict(projection),
            "resource_measurements": resources,
            "witness_count": len(comparisons),
            "rejected_reasons": rejected,
            "promotable": not rejected,
        }
        rows.append(row)
        if not rejected:
            eligible.append((projection.total_seconds, candidate["batch_size"]))
    selected = min(eligible)[1] if eligible else None
    return {
        "outcome": "PROMOTE" if selected is not None else TerminalOutcome.RETURN_WALL.value,
        "selected_batch_size": selected,
        "candidates": rows,
    }


def nearest_rank(values: Iterable[int | float], percentile: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("nearest-rank requires at least one value")
    if not 0 < percentile <= 1:
        raise ValueError("nearest-rank percentile must be in (0, 1]")
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def _budget_summary(
    trail_values: Sequence[int],
    shift_values: Sequence[int],
    *,
    limits: tuple[int, int, int],
) -> dict[str, float | int | bool]:
    if not trail_values or not shift_values:
        raise ValueError("C1 budget requires complete W-TRAIL and W-SHIFT series")
    combined = [*trail_values, *shift_values]
    for value in combined:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("C1 burden values must be non-negative integers")
    result = {
        "p50": nearest_rank(combined, 0.50),
        "p95": nearest_rank(shift_values, 0.95),
        "max": max(combined),
    }
    p50_limit, p95_limit, max_limit = limits
    result["passes"] = result["p50"] <= p50_limit and result[
        "p95"
    ] <= p95_limit and result["max"] <= max_limit
    return result


def shape_budget(
    trail_values: Sequence[int], shift_values: Sequence[int]
) -> dict[str, float | int | bool]:
    """Grade shape burden with p95 frozen to W-SHIFT only."""
    return _budget_summary(
        trail_values,
        shift_values,
        limits=(4, 8, 15),
    )


def global_budget(
    trail_values: Sequence[int], shift_values: Sequence[int]
) -> dict[str, float | int | bool]:
    """Grade final entity burden with p95 frozen to W-SHIFT only."""
    return _budget_summary(
        trail_values,
        shift_values,
        limits=(6, 12, 20),
    )


def axis_identity_valid(
    selected: tuple[int, ...],
    axes: Sequence[Sequence[int]],
    identity_digests: Mapping[tuple[int, ...], str],
) -> bool:
    """Require survivor-set movement at every available adjacent axis step."""
    if len(selected) != len(axes):
        raise ValueError("C1 selected vector does not match its axes")
    selected_digest = identity_digests.get(selected)
    if selected_digest is None:
        raise ValueError("C1 selected cell is absent from the complete grid")
    for axis_index, values in enumerate(axes):
        ordered = tuple(values)
        try:
            position = ordered.index(selected[axis_index])
        except ValueError as exc:
            raise ValueError("C1 selected value is outside its frozen grid") from exc
        neighbor_positions = []
        if position > 0:
            neighbor_positions.append(position - 1)
        if position + 1 < len(ordered):
            neighbor_positions.append(position + 1)
        if not neighbor_positions:
            raise ValueError("C1 tuned axis must contain an adjacent grid step")
        for neighbor_position in neighbor_positions:
            neighbor = list(selected)
            neighbor[axis_index] = ordered[neighbor_position]
            digest = identity_digests.get(tuple(neighbor))
            if digest is None:
                raise ValueError("C1 adjacent cell is absent from the complete grid")
            if digest == selected_digest:
                return False
    return True


def select_vector(
    cells: Mapping[tuple[int, ...], Mapping[str, Any]],
    axes: Sequence[Sequence[int]],
) -> tuple[int, ...]:
    """Select one valid cell by the frozen budget/lexicographic rule."""
    expected = math.prod(len(tuple(axis)) for axis in axes)
    if len(cells) != expected:
        raise ValueError("C1 selection requires the complete frozen grid")
    digests: dict[tuple[int, ...], str] = {}
    for vector, facts in cells.items():
        if len(vector) != len(axes):
            raise ValueError("C1 cell vector does not match its axes")
        digest = facts.get("identity_digest")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("C1 cell identity digest must be SHA-256")
        digests[vector] = digest
    candidates = []
    for vector, facts in cells.items():
        if not bool(facts.get("passes")):
            continue
        if not axis_identity_valid(vector, axes, digests):
            continue
        p95 = float(facts.get("p95"))
        maximum = int(facts.get("max"))
        if not math.isfinite(p95) or p95 < 0 or maximum < 0:
            raise ValueError("C1 selection metrics must be finite and non-negative")
        candidates.append(((p95, maximum, *vector), vector))
    if not candidates:
        raise ValueError("C1 grid has no valid budget-passing vector")
    return min(candidates)[1]


def _selection_keys(
    coverage_lanes: Sequence[str], expected_shift_counts: Mapping[str, int]
) -> tuple[tuple[str, str, str, int], ...]:
    coverage_lanes = tuple(coverage_lanes)
    if not coverage_lanes or len(set(coverage_lanes)) != len(coverage_lanes):
        raise ValueError("C1 shape coverage lanes must be unique and non-empty")
    if set(expected_shift_counts) != set(coverage_lanes):
        raise ValueError("C1 shift counts must cover every shape coverage lane")
    expected_keys = []
    for coverage in coverage_lanes:
        count = expected_shift_counts[coverage]
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ValueError("C1 shape shift counts must be positive integers")
        for allowlist in ALLOWED_LANES:
            expected_keys.append((WindowMode.TRAIL.value, coverage, allowlist, 0))
            expected_keys.extend(
                (WindowMode.SHIFT.value, coverage, allowlist, ordinal)
                for ordinal in range(count)
            )
    return tuple(expected_keys)


def _selection_matrix(
    records: Sequence[Mapping[str, Any]],
    *,
    coverage_lanes: Sequence[str],
    expected_shift_counts: Mapping[str, int],
    payload_field: str,
) -> tuple[
    tuple[tuple[str, str, str, int], ...],
    dict[tuple[str, str, str, int], Mapping[str, Any]],
]:
    """Validate a complete ordered selection matrix without erasing abstention state."""
    expected_keys = _selection_keys(coverage_lanes, expected_shift_counts)
    indexed: dict[tuple[str, str, str, int], Mapping[str, Any]] = {}
    expected_fields = {
        "mode",
        "coverage_lane",
        "allowlist_lane",
        "ordinal",
        "state",
        "cause",
        payload_field,
    }
    for record in records:
        if set(record) != expected_fields:
            raise ValueError("C1 selection record fields are incomplete")
        ordinal = record["ordinal"]
        state = record["state"]
        cause = record["cause"]
        if isinstance(ordinal, bool) or not isinstance(ordinal, int):
            raise ValueError("C1 selection record ordinal is invalid")
        if state not in {"READY", "ABSTAINED"} or not isinstance(cause, str):
            raise ValueError("C1 selection record state is invalid")
        if (state == "READY" and cause) or (state == "ABSTAINED" and not cause):
            raise ValueError("C1 selection record state and cause are inconsistent")
        key = (
            str(record["mode"]),
            str(record["coverage_lane"]),
            str(record["allowlist_lane"]),
            ordinal,
        )
        if key in indexed:
            raise ValueError("C1 selection matrix contains a duplicate record")
        indexed[key] = record
    if tuple(indexed) != expected_keys:
        raise ValueError("C1 selection matrix is incomplete or out of frozen order")
    return expected_keys, indexed


def _selection_exclusion_disclosure(
    expected_keys: Sequence[tuple[str, str, str, int]],
    indexed: Mapping[tuple[str, str, str, int], Mapping[str, Any]],
) -> dict[str, Any]:
    """Expose typed abstentions and denominator changes without treating them as zeroes."""
    modes = (WindowMode.TRAIL.value, WindowMode.SHIFT.value)
    expected = {mode: sum(key[0] == mode for key in expected_keys) for mode in modes}
    measured = {
        mode: sum(
            key[0] == mode and indexed[key]["state"] == "READY"
            for key in expected_keys
        )
        for mode in modes
    }
    by_lane = {}
    for lane in ALLOWED_LANES:
        by_lane[lane] = {
            mode: {
                "expected": sum(key[0] == mode and key[2] == lane for key in expected_keys),
                "measured": sum(
                    key[0] == mode
                    and key[2] == lane
                    and indexed[key]["state"] == "READY"
                    for key in expected_keys
                ),
            }
            for mode in modes
        }
    causes: dict[str, int] = {}
    for key in expected_keys:
        record = indexed[key]
        if record["state"] == "ABSTAINED":
            causes[record["cause"]] = causes.get(record["cause"], 0) + 1
    return {
        "excluded_count": sum(causes.values()),
        "excluded_by_cause": dict(sorted(causes.items())),
        "sample_counts": {
            mode: {"expected": expected[mode], "measured": measured[mode]}
            for mode in modes
        },
        "sample_counts_by_allowlist_lane": by_lane,
        "bias_caveat": {
            "kind": "inference",
            "text": (
                "Excluded abstentions are unmeasured, not zeroes; their removal can bias "
                "the surviving distribution optimistically. Adjacent measured rows are "
                "context, not measurements of excluded rows."
            ),
        },
    }


def _adjacent_burden_context(
    expected_keys: Sequence[tuple[str, str, str, int]],
    indexed: Mapping[tuple[str, str, str, int], Mapping[str, Any]],
    counts: Mapping[tuple[str, str, str, int], int],
) -> dict[str, Any]:
    """Report nearby measured burden without projecting it onto abstained windows."""
    by_coverage = []
    for coverage in dict.fromkeys(key[1] for key in expected_keys):
        measured_shifts = [
            counts[key]
            for key in expected_keys
            if key[1] == coverage
            and key[0] == WindowMode.SHIFT.value
            and indexed[key]["state"] == "READY"
        ]
        adjacent = []
        for key in expected_keys:
            if (
                key[1] != coverage
                or key[0] != WindowMode.SHIFT.value
                or indexed[key]["state"] != "ABSTAINED"
            ):
                continue
            for ordinal in (key[3] - 1, key[3] + 1):
                neighbor = (key[0], key[1], key[2], ordinal)
                if neighbor in indexed and indexed[neighbor]["state"] == "READY":
                    adjacent.append(counts[neighbor])
        if adjacent:
            median = nearest_rank(measured_shifts, 0.50)
            by_coverage.append(
                {
                    "coverage_lane": coverage,
                    "measured_shift_median": median,
                    "adjacent_ready_count": len(adjacent),
                    "adjacent_ready_above_median_count": sum(
                        value > median for value in adjacent
                    ),
                }
            )
    return {
        "kind": "inference",
        "text": (
            "Above-median burden in adjacent READY windows is context suggesting "
            "possible optimism after exclusion, not a measurement of abstained windows."
        ),
        "by_coverage_lane": by_coverage,
    }


def reduce_shape_grid(
    records: Sequence[Mapping[str, Any]],
    *,
    axes: Sequence[Sequence[int]],
    vector_fields: Sequence[str],
    coverage_lanes: Sequence[str],
    expected_shift_counts: Mapping[str, int],
) -> dict[tuple[int, ...], dict[str, Any]]:
    """Reduce one complete shape matrix into selection-ready cell facts."""
    axes = tuple(tuple(axis) for axis in axes)
    vector_fields = tuple(vector_fields)
    if len(axes) != len(vector_fields) or not axes or any(not axis for axis in axes):
        raise ValueError("C1 shape grid axes and vector fields must align")
    expected_keys, indexed = _selection_matrix(
        records,
        coverage_lanes=coverage_lanes,
        expected_shift_counts=expected_shift_counts,
        payload_field="cells",
    )
    disclosure = _selection_exclusion_disclosure(expected_keys, indexed)

    vectors = tuple(itertools.product(*axes))
    trail_values = {vector: [] for vector in vectors}
    shift_values = {vector: [] for vector in vectors}
    identity_vectors = {vector: [] for vector in vectors}
    for key in expected_keys:
        record = indexed[key]
        cells = record["cells"]
        if not isinstance(cells, list):
            raise ValueError("C1 shape grid cells are missing")
        if record["state"] == "ABSTAINED":
            if cells:
                raise ValueError("C1 abstained shape record carries a grid")
            continue
        cell_index: dict[tuple[int, ...], Mapping[str, Any]] = {}
        for cell in cells:
            if not isinstance(cell, dict) or not set(vector_fields) <= set(cell):
                raise ValueError("C1 shape grid cell is malformed")
            try:
                vector = tuple(int(cell[field]) for field in vector_fields)
            except (TypeError, ValueError) as exc:
                raise ValueError("C1 shape grid vector is invalid") from exc
            if vector in cell_index:
                raise ValueError("C1 shape grid contains a duplicate vector")
            count = cell.get("qualifying_pairs")
            digest = cell.get("identity_digest")
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
                or not _is_sha256(digest)
            ):
                raise ValueError("C1 shape cell aggregate is invalid")
            cell_index[vector] = cell
        if tuple(cell_index) != vectors:
            raise ValueError("C1 shape record does not contain the frozen grid")
        destination = trail_values if key[0] == WindowMode.TRAIL.value else shift_values
        for vector in vectors:
            cell = cell_index[vector]
            destination[vector].append(cell["qualifying_pairs"])
            identity_vectors[vector].append((*key, cell["identity_digest"]))

    reduced = {}
    for vector in vectors:
        budget = shape_budget(trail_values[vector], shift_values[vector])
        reduced[vector] = {
            **budget,
            "identity_digest": _sha256_bytes(
                canonical_json_bytes(identity_vectors[vector])
            ),
            "exclusion_disclosure": disclosure,
        }
    return reduced


def reduce_global_burden(
    records: Sequence[Mapping[str, Any]],
    *,
    coverage_lanes: Sequence[str],
    expected_shift_counts: Mapping[str, int],
) -> dict[str, Any]:
    """Grade the selected combined deck over a closed campaign keyspace."""
    expected_keys, indexed = _selection_matrix(
        records,
        coverage_lanes=coverage_lanes,
        expected_shift_counts=expected_shift_counts,
        payload_field="entity_findings",
    )
    counts: dict[tuple[str, str, str, int], int] = {}
    for key, record in indexed.items():
        count = record["entity_findings"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("C1 global burden count is invalid")
        if record["state"] == "ABSTAINED" and count != 0:
            raise ValueError("C1 abstained global burden record carries a measurement")
        counts[key] = count
    trail = [
        counts[key]
        for key in expected_keys
        if key[0] == WindowMode.TRAIL.value and indexed[key]["state"] == "READY"
    ]
    shifts = [
        counts[key]
        for key in expected_keys
        if key[0] == WindowMode.SHIFT.value and indexed[key]["state"] == "READY"
    ]
    disclosure = _selection_exclusion_disclosure(expected_keys, indexed)
    disclosure["adjacent_burden_context"] = _adjacent_burden_context(
        expected_keys, indexed, counts
    )
    return {
        **global_budget(trail, shifts),
        "exclusion_disclosure": disclosure,
    }


def reduce_repeat_burden(
    appearances: Iterable[tuple[str, int, str]],
    *,
    rolling_periods: int = 14,
    maximum_allowed: int = 2,
) -> dict[str, int | str | None]:
    """Evaluate private repeat identities and release aggregate attribution only."""
    if rolling_periods <= 0 or maximum_allowed < 0:
        raise ValueError("C1 repeat bounds are invalid")
    by_identity: dict[str, dict[int, set[str]]] = {}
    for identity, period, shape in appearances:
        if not isinstance(identity, str) or "\0" not in identity:
            raise ValueError("C1 repeat identity is malformed")
        if isinstance(period, bool) or not isinstance(period, int):
            raise ValueError("C1 repeat period is invalid")
        if shape not in {"arrival", "burst"}:
            raise ValueError("C1 repeat shape is invalid")
        by_identity.setdefault(identity, {}).setdefault(period, set()).add(shape)

    global_max = 0
    violating = 0
    burst_only = True
    for periods in by_identity.values():
        ordered = sorted(periods)
        left = 0
        identity_max = 0
        violating_shapes: set[str] = set()
        for right, current in enumerate(ordered):
            while current - ordered[left] >= rolling_periods:
                left += 1
            count = right - left + 1
            identity_max = max(identity_max, count)
            if count > maximum_allowed:
                for violation_period in ordered[left : right + 1]:
                    violating_shapes.update(periods[violation_period])
        global_max = max(global_max, identity_max)
        if identity_max > maximum_allowed:
            violating += 1
            if violating_shapes != {"burst"}:
                burst_only = False
    violation = None
    if violating:
        violation = "burst_only" if burst_only else "arrival_or_mixed"
    return {
        "rolling_periods": rolling_periods,
        "maximum_allowed": maximum_allowed,
        "maximum_observed": global_max,
        "violating_identities": violating,
        "violation": violation,
    }


def summarize_triage(
    cases: Sequence[Mapping[str, Any]],
    *,
    reviewers_available: bool = True,
) -> dict[str, Any]:
    """Validate private reviewer records and release bounded aggregate facts."""
    if len(cases) > 12:
        raise ValueError("C1 triage sample exceeds twelve cases")
    seen_ordinals: set[int] = set()
    dispositions = {"investigate": 0, "mute_expected": 0, "unresolved": 0}
    reason_categories = {"recorded": 0, "unresolved": 0, "over_budget": 0}
    unresolved_cases = 0
    disagreement_cases = 0
    lookup_count = 0
    elapsed_seconds = 0.0
    for case in cases:
        if set(case) != {"ordinal", "reviewers"}:
            raise ValueError("C1 triage case fields are incomplete")
        ordinal = case["ordinal"]
        reviewers = case["reviewers"]
        if (
            isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal < 0
            or ordinal in seen_ordinals
        ):
            raise ValueError("C1 triage ordinal is invalid or repeated")
        if not isinstance(reviewers, list) or len(reviewers) != 2:
            raise ValueError("C1 triage case requires exactly two reviewers")
        seen_ordinals.add(ordinal)
        case_concrete = []
        case_unresolved = False
        for review in reviewers:
            if not isinstance(review, dict) or set(review) != {
                "disposition",
                "reason",
                "lookups",
                "elapsed_seconds",
            }:
                raise ValueError("C1 triage review fields are incomplete")
            disposition = review["disposition"]
            reason = review["reason"]
            lookups = review["lookups"]
            elapsed = review["elapsed_seconds"]
            if disposition not in dispositions:
                raise ValueError("C1 triage disposition is invalid")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("C1 triage review requires a detailed private reason")
            if isinstance(lookups, bool) or not isinstance(lookups, int) or lookups < 0:
                raise ValueError("C1 triage lookup count is invalid")
            if (
                isinstance(elapsed, bool)
                or not isinstance(elapsed, (int, float))
                or not math.isfinite(elapsed)
                or elapsed < 0
            ):
                raise ValueError("C1 triage elapsed time is invalid")
            dispositions[disposition] += 1
            lookup_count += lookups
            elapsed_seconds += float(elapsed)
            if elapsed > 300:
                reason_categories["over_budget"] += 1
                case_unresolved = True
            elif disposition == "unresolved":
                reason_categories["unresolved"] += 1
                case_unresolved = True
            else:
                reason_categories["recorded"] += 1
                case_concrete.append(disposition)
        if case_unresolved:
            unresolved_cases += 1
        elif len(set(case_concrete)) == 2:
            disagreement_cases += 1

    sample_size = len(cases)
    if not reviewers_available:
        state = "UNMEASURED"
        unmeasured_reason = "reviewer_unavailable"
    elif sample_size < 5:
        state = "UNMEASURED"
        unmeasured_reason = "sample_below_five"
    else:
        state = "PASS" if 5 * unresolved_cases <= sample_size else "FAIL"
        unmeasured_reason = None
    return {
        "state": state,
        "unmeasured_reason": unmeasured_reason,
        "sample_size": sample_size,
        "unresolved_cases": unresolved_cases,
        "disagreement_cases": disagreement_cases,
        "disposition_counts": dispositions,
        "reason_category_counts": reason_categories,
        "lookup_count": lookup_count,
        "elapsed_seconds": elapsed_seconds,
    }


def decide_campaign(
    *,
    wall_promoted: bool,
    arrival_cells: Mapping[tuple[int, ...], Mapping[str, Any]],
    arrival_axes: Sequence[Sequence[int]],
    burst_cells: Mapping[tuple[int, ...], Mapping[str, Any]],
    burst_axes: Sequence[Sequence[int]],
    final_global_budget: Mapping[str, Any],
    repeat_burden: Mapping[str, Any],
    triage_summary: Mapping[str, Any],
) -> dict[str, Any]:
    """Resolve C1 selection and the amended terminal lattice in one place."""
    if not isinstance(wall_promoted, bool):
        raise ValueError("C1 wall promotion state must be boolean")
    if not wall_promoted:
        return {
            "terminal_outcome": TerminalOutcome.RETURN_WALL.value,
            "arrival_vector": None,
            "burst_vector": None,
            "burst_enabled": False,
            "global_budget": None,
            "repeat_burden": None,
            "triage": None,
        }
    if not isinstance(final_global_budget.get("passes"), bool):
        raise ValueError("C1 final global budget is incomplete")
    repeat_violation = repeat_burden.get("violation")
    if repeat_violation not in {None, "burst_only", "arrival_or_mixed"}:
        raise ValueError("C1 repeat burden attribution is invalid")
    if triage_summary.get("state") not in {"PASS", "FAIL", "UNMEASURED"}:
        raise ValueError("C1 triage state is invalid")

    def selected_or_none(cells, axes):
        try:
            return select_vector(cells, axes)
        except ValueError as exc:
            if str(exc) != "C1 grid has no valid budget-passing vector":
                raise
            return None

    arrival_vector = selected_or_none(arrival_cells, arrival_axes)
    burst_vector = selected_or_none(burst_cells, burst_axes)
    outcome = classify_terminal(
        wall_promoted=wall_promoted,
        arrival_valid=arrival_vector is not None,
        arrival_budget_passed=arrival_vector is not None,
        burst_valid=burst_vector is not None,
        burst_budget_passed=burst_vector is not None,
        global_budget_passed=bool(final_global_budget["passes"]),
        repeat_violation=repeat_violation,
    )
    return {
        "terminal_outcome": outcome.value,
        "arrival_vector": list(arrival_vector) if arrival_vector is not None else None,
        "burst_vector": list(burst_vector) if burst_vector is not None else None,
        "burst_enabled": outcome is TerminalOutcome.SEALED_RATIFIED,
        "global_budget": dict(final_global_budget),
        "repeat_burden": dict(repeat_burden),
        "triage": dict(triage_summary),
    }


def _test_source_hashes(project_root: Path, nodeids: Sequence[str]) -> dict[str, str]:
    paths = sorted({nodeid.split("::", 1)[0] for nodeid in nodeids})
    result = {}
    for relative in paths:
        path = (project_root / relative).resolve()
        try:
            path.relative_to(project_root.resolve())
        except ValueError as exc:
            raise ValueError("C1 matrix test path escapes project root") from exc
        if not path.is_file():
            raise ValueError(f"C1 matrix test source is missing: {relative}")
        result[relative] = _sha256_file(path)
    return result


def run_control_matrix(project_root: Path, output: Path) -> dict[str, Any]:
    """Run every frozen §12 obligation as one aggregate receipt bundle."""
    root = project_root.resolve()
    rows = []
    all_green = True
    for obligation, nodeids in MATRIX_OBLIGATIONS.items():
        command = [sys.executable, "-m", "pytest", "-q", *nodeids]
        source_sha256 = _test_source_hashes(root, nodeids)
        started = time.monotonic()
        completed = subprocess.run(
            command,
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        duration = time.monotonic() - started
        if _test_source_hashes(root, nodeids) != source_sha256:
            raise ValueError("C1 matrix test source changed during execution")
        output_digest = _sha256_bytes(
            (completed.stdout + "\0" + completed.stderr).encode("utf-8")
        )
        all_green = all_green and completed.returncode == 0
        rows.append(
            {
                "obligation": obligation,
                "command": command,
                "nodeids": list(nodeids),
                "source_sha256": source_sha256,
                "exit_code": completed.returncode,
                "duration_seconds": duration,
                "output_sha256": output_digest,
            }
        )
    payload = {
        "schema": f"{SCHEMA}.matrix",
        "schema_version": SCHEMA_VERSION,
        "authority": {"spec_version": SPEC_VERSION, "spec_sha256": SPEC_SHA256},
        "obligation_count": len(MATRIX_OBLIGATIONS),
        "all_green": all_green,
        "rows": rows,
    }
    atomic_receipt(output, payload)
    validate_control_matrix(payload, project_root=root)
    return payload


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def validate_control_matrix(
    payload: Mapping[str, Any], *, project_root: Path | None = None
) -> None:
    if payload.get("schema") != f"{SCHEMA}.matrix" or payload.get("schema_version") != 1:
        raise ValueError("C1 matrix schema mismatch")
    authority = payload.get("authority")
    if authority != {"spec_version": SPEC_VERSION, "spec_sha256": SPEC_SHA256}:
        raise ValueError("C1 matrix authority mismatch")
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise ValueError("C1 matrix rows are missing")
    names = [row.get("obligation") for row in rows if isinstance(row, dict)]
    if names != list(MATRIX_OBLIGATIONS):
        raise ValueError("C1 matrix obligations are incomplete or out of order")
    if payload.get("obligation_count") != len(MATRIX_OBLIGATIONS):
        raise ValueError("C1 matrix obligation count mismatch")
    root = project_root.resolve() if project_root is not None else None
    for row, (obligation, nodeids) in zip(rows, MATRIX_OBLIGATIONS.items(), strict=True):
        if not isinstance(row, dict) or set(row) != {
            "obligation",
            "command",
            "nodeids",
            "source_sha256",
            "exit_code",
            "duration_seconds",
            "output_sha256",
        }:
            raise ValueError("C1 matrix row shape mismatch")
        if row["obligation"] != obligation or row["nodeids"] != list(nodeids):
            raise ValueError("C1 matrix node mapping mismatch")
        command = row["command"]
        if (
            not isinstance(command, list)
            or len(command) != 4 + len(nodeids)
            or not isinstance(command[0], str)
            or not command[0]
            or command[1:] != ["-m", "pytest", "-q", *nodeids]
        ):
            raise ValueError("C1 matrix command mismatch")
        sources = row["source_sha256"]
        expected_paths = sorted({nodeid.split("::", 1)[0] for nodeid in nodeids})
        if (
            not isinstance(sources, dict)
            or list(sources) != expected_paths
            or not all(_is_sha256(value) for value in sources.values())
        ):
            raise ValueError("C1 matrix source hash map mismatch")
        if root is not None and sources != _test_source_hashes(root, nodeids):
            raise ValueError("C1 matrix source hash verification failed")
        exit_code = row["exit_code"]
        duration = row["duration_seconds"]
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise ValueError("C1 matrix exit code is invalid")
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or duration < 0
        ):
            raise ValueError("C1 matrix duration is invalid")
        if not _is_sha256(row["output_sha256"]):
            raise ValueError("C1 matrix output digest is invalid")
    computed_green = all(row.get("exit_code") == 0 for row in rows)
    if not isinstance(payload.get("all_green"), bool) or payload["all_green"] != computed_green:
        raise ValueError("C1 matrix aggregate result is inconsistent")


def classify_terminal(
    *,
    wall_promoted: bool,
    arrival_valid: bool,
    arrival_budget_passed: bool,
    burst_valid: bool,
    burst_budget_passed: bool,
    global_budget_passed: bool,
    repeat_violation: str | None,
) -> TerminalOutcome:
    """Apply James amendment A1's split arrival/burst terminal lattice."""
    if not wall_promoted:
        return TerminalOutcome.RETURN_WALL
    if (
        not arrival_valid
        or not arrival_budget_passed
        or not global_budget_passed
        or repeat_violation == "arrival_or_mixed"
    ):
        return TerminalOutcome.RETURN_INVALID_OR_BURDEN
    if not burst_valid or not burst_budget_passed or repeat_violation == "burst_only":
        return TerminalOutcome.SEALED_RATIFIED_ARRIVAL_ONLY
    if repeat_violation not in (None, ""):
        raise ValueError("C1 repeat violation attribution is not recognized")
    return TerminalOutcome.SEALED_RATIFIED


def receipt_key(fields: Mapping[str, Any]) -> str:
    required = {
        "spec_sha256",
        "source_baseline",
        "overlay_diff_sha256",
        "harness_sha256",
        "imports_sha256",
        "corpus_manifest_sha256",
        "snapshot_identity_sha256",
        "window_start",
        "window_end",
        "coverage_lane",
        "allowlist_lane",
        "output_format",
        "driver_schema",
    }
    if set(fields) != required:
        raise ValueError("C1 receipt key fields must match the frozen schema exactly")
    return _sha256_bytes(canonical_json_bytes(dict(fields)))


def atomic_receipt(path: Path, payload: Mapping[str, Any]) -> str:
    """Write one private receipt with a detached canonical payload digest."""
    body = dict(payload)
    body_digest = _sha256_bytes(canonical_json_bytes(body))
    envelope = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "payload_sha256": body_digest,
        "payload": body,
    }
    private_mkdir(path.parent)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        private_write_text(
            temporary,
            canonical_json_bytes(envelope).decode("utf-8") + "\n",
        )
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return body_digest


def write_resumable_receipt(
    path: Path,
    *,
    key: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Resume an exact receipt or preserve a stale one before replacement."""
    if len(key) != 64:
        raise ValueError("C1 receipt key must be a SHA-256 digest")
    body = {"receipt_key": key, **dict(payload)}
    if path.exists():
        try:
            existing = verify_receipt(path)
        except (OSError, ValueError, json.JSONDecodeError):
            existing = None
        if existing is not None and existing.get("receipt_key") == key:
            if existing != body:
                raise ValueError("C1 exact-key receipt payload changed")
            return {"resumed": True, "superseded": None}
        superseded_dir = path.parent / "superseded"
        private_mkdir(superseded_dir)
        old_digest = _sha256_file(path)
        superseded = superseded_dir / f"{path.stem}-{old_digest[:16]}{path.suffix}"
        if superseded.exists() and _sha256_file(superseded) != old_digest:
            raise ValueError("C1 superseded receipt name collision")
        if not superseded.exists():
            shutil.move(path, superseded)
        else:
            path.unlink()
    else:
        superseded = None
    atomic_receipt(path, body)
    return {
        "resumed": False,
        "superseded": str(superseded) if superseded is not None else None,
    }


def verify_receipt(path: Path) -> dict[str, Any]:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    if envelope.get("schema") != SCHEMA or envelope.get("schema_version") != 1:
        raise ValueError("C1 receipt schema is not recognized")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("C1 receipt payload must be an object")
    if envelope.get("payload_sha256") != _sha256_bytes(canonical_json_bytes(payload)):
        raise ValueError("C1 receipt digest mismatch")
    return payload


def _validate_series_content_identity(
    series: Mapping[str, Any], harness_sha256: str
) -> None:
    batch_count = series.get("batch_count")
    batch_identities = series.get("batch_content_identities")
    content_identity = series.get("content_identity_sha256")
    if (
        isinstance(batch_count, bool)
        or not isinstance(batch_count, int)
        or batch_count <= 0
        or not isinstance(batch_identities, list)
        or len(batch_identities) != batch_count
        or not all(_is_sha256(value) for value in batch_identities)
        or not _is_sha256(content_identity)
    ):
        raise ValueError("C1 series content identity is malformed")
    if harness_sha256 != UNION_CONTENT_HARNESS_SHA256 and (
        len(set(batch_identities)) != 1 or batch_identities[0] != content_identity
    ):
        raise ValueError("C1 series content identity is inconsistent")


def write_series_receipts(
    artifact: Mapping[str, Any],
    *,
    receipt_dir: Path,
    mode: WindowMode,
    overlay_diff_sha256: str,
    harness_sha256: str,
    imports_sha256: Mapping[str, str],
) -> tuple[dict[str, Any], ...]:
    """Fan one complete harness series into exact-key per-window/lane receipts."""
    if artifact.get("schema_version") != 3 or artifact.get("detector") != "dnsblock":
        raise ValueError("C1 series artifact schema mismatch")
    series = artifact.get("series")
    results = artifact.get("results")
    if not isinstance(series, dict) or not isinstance(results, list):
        raise ValueError("C1 series artifact is incomplete")
    window_count = series.get("window_count")
    corpus = series.get("corpus")
    if (
        isinstance(window_count, bool)
        or not isinstance(window_count, int)
        or window_count <= 0
        or not isinstance(corpus, dict)
        or not _is_sha256(corpus.get("manifest_sha256"))
    ):
        raise ValueError("C1 series corpus identity is incomplete")
    if not _is_sha256(harness_sha256) or not imports_sha256 or not all(
        isinstance(label, str) and label and _is_sha256(digest)
        for label, digest in imports_sha256.items()
    ):
        raise ValueError("C1 series code identity is invalid")
    if overlay_diff_sha256 != "none" and not _is_sha256(overlay_diff_sha256):
        raise ValueError("C1 series overlay identity is invalid")
    _validate_series_content_identity(series, harness_sha256)
    watchdog_enforced = series.get("watchdog_enforced")
    co_load = series.get("co_load")
    if harness_sha256 == PREPATCH_HARNESS_SHA256:
        if watchdog_enforced is None:
            watchdog_enforced = False
        if co_load is None:
            co_load = 1
    if not isinstance(watchdog_enforced, bool):
        raise ValueError("C1 patched series must state watchdog enforcement")
    if isinstance(co_load, bool) or co_load not in (1, 2):
        raise ValueError("C1 patched series must state observed co-load")
    if watchdog_enforced:
        assembly_overhead = series.get("assembly_overhead_seconds")
        series_deadline = series.get("series_deadline_seconds")
        batch_count = series.get("batch_count")
        if (
            assembly_overhead != ASSEMBLY_OVERHEAD_SECONDS
            or isinstance(batch_count, bool)
            or not isinstance(batch_count, int)
            or batch_count <= 0
        ):
            raise ValueError("C1 series watchdog facts are inconsistent")
        if harness_sha256 == FLAT_WATCHDOG_HARNESS_SHA256:
            if (
                series.get("batch_deadline_seconds") != 1800
                or series_deadline
                != 1800 * batch_count + ASSEMBLY_OVERHEAD_SECONDS
            ):
                raise ValueError("C1 series watchdog facts are inconsistent")
        else:
            batch_window_counts = series.get("batch_window_counts")
            batch_deadlines = series.get("batch_deadline_seconds_by_batch")
            per_window = series.get("per_window_watchdog_seconds")
            expected_per_window = (
                3600
                if harness_sha256 == PROVISIONAL_WATCHDOG_HARNESS_SHA256
                else PER_WINDOW_WATCHDOG_SECONDS
            )
            if (
                per_window != expected_per_window
                or not isinstance(batch_window_counts, list)
                or len(batch_window_counts) != batch_count
                or any(
                    isinstance(count, bool)
                    or not isinstance(count, int)
                    or count <= 0
                    for count in batch_window_counts
                )
                or sum(batch_window_counts) != window_count
                or batch_deadlines
                != [per_window * count for count in batch_window_counts]
                or series_deadline
                != sum(batch_deadlines) + ASSEMBLY_OVERHEAD_SECONDS
            ):
                raise ValueError("C1 series watchdog facts are inconsistent")
    expected_keys = [
        (ordinal, lane)
        for ordinal in range(window_count)
        for lane in ALLOWED_LANES
    ]
    indexed = {}
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("C1 series result is malformed")
        key = (result.get("window_ordinal"), result.get("allowlist_lane"))
        if key not in expected_keys:
            raise ValueError("C1 series contains an unexpected result key")
        if key in indexed:
            raise ValueError("C1 series contains a duplicate result")
        indexed[key] = result
    if set(indexed) != set(expected_keys):
        raise ValueError("C1 series result keyspace is incomplete")

    for ordinal in range(window_count):
        contexts = {
            canonical_json_bytes(indexed[(ordinal, lane)].get("context_interval"))
            for lane in ALLOWED_LANES
        }
        if len(contexts) != 1:
            raise ValueError("C1 series allowlist lanes disagree on context interval")

    rows = []
    for ordinal, lane in expected_keys:
        result = indexed[(ordinal, lane)]
        aggregate = result.get("aggregate")
        digest = result.get("semantic_digest")
        if not isinstance(aggregate, dict) or not isinstance(digest, dict):
            raise ValueError("C1 series result aggregate is incomplete")
        preflight = aggregate.get("preflight")
        interval = result.get("report_interval")
        context_interval = result.get("context_interval")
        if (
            not isinstance(preflight, dict)
            or not isinstance(interval, list)
            or len(interval) != 2
            or interval != preflight.get("report_interval")
            or context_interval != preflight.get("context_interval")
            or (
                context_interval is not None
                and (
                    not isinstance(context_interval, list)
                    or len(context_interval) != 2
                    or not all(isinstance(value, str) for value in context_interval)
                )
            )
            or not _is_sha256(preflight.get("snapshot_identity"))
            or preflight.get("coverage_lane") not in ALLOWED_COVERAGE
            or not _is_sha256(digest.get("sha256"))
        ):
            raise ValueError("C1 series result identity is invalid")
        key_fields = {
            "spec_sha256": SPEC_SHA256,
            "source_baseline": BASELINE_COMMIT,
            "overlay_diff_sha256": overlay_diff_sha256,
            "harness_sha256": harness_sha256,
            "imports_sha256": dict(imports_sha256),
            "corpus_manifest_sha256": corpus["manifest_sha256"],
            "snapshot_identity_sha256": preflight["snapshot_identity"],
            "window_start": interval[0],
            "window_end": interval[1],
            "coverage_lane": preflight["coverage_lane"],
            "allowlist_lane": lane,
            "output_format": "json",
            "driver_schema": SCHEMA_VERSION,
        }
        key = receipt_key(key_fields)
        body = {
            "window_mode": mode.value,
            "window_ordinal": ordinal,
            "allowlist_lane": lane,
            "context_interval": context_interval,
            "watchdog_enforced": watchdog_enforced,
            "batch_deadline_seconds": series.get("batch_deadline_seconds"),
            "assembly_overhead_seconds": series.get("assembly_overhead_seconds"),
            "series_deadline_seconds": series.get("series_deadline_seconds"),
            "co_load": co_load,
            "key_fields": key_fields,
            "aggregate": aggregate,
            "semantic_digest": digest,
        }
        if series.get("per_window_watchdog_seconds") is not None:
            body.pop("batch_deadline_seconds")
            body.update(
                {
                    "per_window_watchdog_seconds": series[
                        "per_window_watchdog_seconds"
                    ],
                    "batch_window_counts": series.get("batch_window_counts"),
                    "batch_deadline_seconds_by_batch": series.get(
                        "batch_deadline_seconds_by_batch"
                    ),
                }
            )
        path = receipt_dir / f"{mode.value.lower()}-{ordinal:04d}-{lane}.json"
        outcome = write_resumable_receipt(path, key=key, payload=body)
        rows.append(
            {
                "window_ordinal": ordinal,
                "allowlist_lane": lane,
                "receipt": path.name,
                "receipt_key": key,
                **outcome,
            }
        )
    return tuple(rows)


_PARITY_AGGREGATE_KEYS = frozenset(
    {
        "schema_version",
        "detector",
        "status",
        "preflight",
        "channels",
        "burst_grids",
        "final_shape_routes",
        "recurring",
        "summary_notes",
        "burden",
        "withheld_arrival_burst_pairs",
    }
)
_PARITY_PROVENANCE_FIELDS = {
    "pass_wall_seconds": "pass_telemetry",
    "snapshot_identity": "scan_bound_identity",
    "data_size_bytes": "whole_load_bytes",
    "observed_data_window": "whole_load_observed_span",
    "resident_bytes": "reducer_residency",
    "rows_kept": "whole_load_row_accounting",
    "rows_suppressed": "whole_load_row_accounting",
    "raw_event_counts": "whole_load_event_accounting",
    "drop_counts": "outside_window_drop_accounting",
}


def _parity_parts(
    artifact: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split the closed detector-semantic projection from justified provenance."""
    wrapped = "aggregate" in artifact
    value: Any = artifact.get("aggregate", artifact)
    if not isinstance(value, dict):
        raise ValueError("C1 parity artifact aggregate must be an object")
    allowed_keys = _PARITY_AGGREGATE_KEYS if wrapped else (_PARITY_AGGREGATE_KEYS | {"harness"})
    if set(value) != allowed_keys:
        raise ValueError("C1 parity artifact has unknown or missing aggregate fields")
    normalized = json.loads(
        canonical_json_bytes(
            {key: value[key] for key in _PARITY_AGGREGATE_KEYS}
        ).decode("utf-8")
    )
    preflight = normalized.get("preflight")
    if not isinstance(preflight, dict):
        raise ValueError("C1 parity preflight must be an object")
    provenance = {}
    for field, reason in _PARITY_PROVENANCE_FIELDS.items():
        if field not in preflight:
            raise ValueError(f"C1 parity preflight is missing {field}")
        provenance[field] = {"reason": reason, "value": preflight.pop(field)}
    for field in ("rows_kept", "rows_suppressed", "data_size_bytes", "resident_bytes"):
        number = provenance[field]["value"]
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise ValueError("C1 parity row/byte provenance is malformed")
    return normalized, provenance


def aggregate_parity_payload(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Return the closed detector-semantic aggregate projection."""
    semantic, _provenance = _parity_parts(artifact)
    return semantic


def compare_witness(
    reference: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail closed unless semantic digest and full aggregate both match."""
    reference_harness = reference.get("harness")
    if not isinstance(reference_harness, dict):
        raise ValueError("C1 reference harness receipt is missing")
    reference_digest = reference_harness.get("semantic_digest")
    candidate_digest = candidate.get("semantic_digest")
    if not isinstance(reference_digest, dict) or not isinstance(candidate_digest, dict):
        raise ValueError("C1 witness semantic digest is missing")
    reference_aggregate, reference_provenance = _parity_parts(reference)
    candidate_aggregate, candidate_provenance = _parity_parts(candidate)
    reference_aggregate_sha256 = _sha256_bytes(canonical_json_bytes(reference_aggregate))
    candidate_aggregate_sha256 = _sha256_bytes(canonical_json_bytes(candidate_aggregate))
    semantic_equal = reference_digest == candidate_digest
    aggregate_equal = reference_aggregate_sha256 == candidate_aggregate_sha256
    provenance_differences = []
    for field, reason in _PARITY_PROVENANCE_FIELDS.items():
        reference_value = reference_provenance[field]["value"]
        candidate_value = candidate_provenance[field]["value"]
        if reference_value != candidate_value:
            provenance_differences.append(
                {
                    "path": f"preflight.{field}",
                    "reason": reason,
                    "reference_sha256": _sha256_bytes(
                        canonical_json_bytes(reference_value)
                    ),
                    "candidate_sha256": _sha256_bytes(
                        canonical_json_bytes(candidate_value)
                    ),
                }
            )
    return {
        "semantic_digest_equal": semantic_equal,
        "aggregate_equal": aggregate_equal,
        "reference_semantic_sha256": reference_digest.get("sha256"),
        "candidate_semantic_sha256": candidate_digest.get("sha256"),
        "reference_aggregate_sha256": reference_aggregate_sha256,
        "candidate_aggregate_sha256": candidate_aggregate_sha256,
        "provenance_differences": provenance_differences,
        "promotable": semantic_equal and aggregate_equal,
    }


def assemble_phase_w_candidates(
    artifacts: Mapping[int, Mapping[str, Mapping[str, Any]]],
    references: Mapping[tuple[str, str, tuple[str, str]], Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Derive the frozen candidate rows from measured series artifacts."""
    if list(artifacts) != [2, 4, 8]:
        raise ValueError("C1 Phase-W artifacts must be exactly 2, 4, 8 in order")
    estimates = []
    rows = []
    for batch_size, coverage_artifacts in artifacts.items():
        if set(coverage_artifacts) != {"strong", "weak"}:
            raise ValueError("C1 Phase-W candidate requires strong and weak artifacts")
        comparisons = []
        seconds = {}
        snapshot_verified = True
        resource_maxima = {
            "max_process_rss_bytes": 0,
            "max_temp_bytes": 0,
            "max_window_routes": 0,
            "max_inflight_cadence_gaps": 0,
        }
        estimate = 0
        for coverage in ("strong", "weak"):
            artifact = coverage_artifacts[coverage]
            series = artifact.get("series")
            results = artifact.get("results")
            if (
                artifact.get("schema_version") != 3
                or not isinstance(series, dict)
                or not isinstance(results, list)
                or series.get("batch_size") != batch_size
            ):
                raise ValueError("C1 Phase-W series artifact identity is invalid")
            window_count = series.get("window_count")
            elapsed = series.get("elapsed_seconds")
            if (
                isinstance(window_count, bool)
                or not isinstance(window_count, int)
                or window_count <= 0
                or isinstance(elapsed, bool)
                or not isinstance(elapsed, (int, float))
                or not math.isfinite(float(elapsed))
                or elapsed < 0
                or len(results) != 2 * window_count
            ):
                raise ValueError("C1 Phase-W series measurement is incomplete")
            amortized_lane_seconds = float(elapsed) / (2 * window_count)
            seconds[coverage] = {
                lane: amortized_lane_seconds for lane in ALLOWED_LANES
            }
            identities = series.get("batch_snapshot_identities")
            content_identities = series.get("batch_content_identities")
            content_identity = series.get("content_identity_sha256")
            snapshot_verified = snapshot_verified and (
                isinstance(identities, list)
                and len(identities) == series.get("batch_count")
                and bool(identities)
                and all(isinstance(value, str) and len(value) == 64 for value in identities)
                and isinstance(content_identities, list)
                and len(content_identities) == series.get("batch_count")
                and content_identities
                and len(set(content_identities)) == 1
                and content_identities[0] == content_identity
                and all(
                    isinstance(value, str) and len(value) == 64
                    for value in content_identities
                )
            )
            for source, target in (
                ("peak_process_rss_bytes", "max_process_rss_bytes"),
                ("peak_temp_bytes", "max_temp_bytes"),
                ("max_window_routes", "max_window_routes"),
                ("max_inflight_cadence_gaps", "max_inflight_cadence_gaps"),
            ):
                value = series.get(source)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError("C1 Phase-W resource telemetry is incomplete")
                resource_maxima[target] = max(resource_maxima[target], value)
            value = series.get("inflight_window_lane_bytes_estimate")
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("C1 Phase-W memory estimate is incomplete")
            estimate = max(estimate, value)
            for candidate in results:
                if not isinstance(candidate, dict):
                    raise ValueError("C1 Phase-W witness result is malformed")
                lane = candidate.get("allowlist_lane")
                interval = candidate.get("report_interval")
                if (
                    lane not in ALLOWED_LANES
                    or not isinstance(interval, list)
                    or len(interval) != 2
                    or not all(isinstance(item, str) for item in interval)
                ):
                    raise ValueError("C1 Phase-W witness key is malformed")
                reference = references.get((coverage, lane, tuple(interval)))
                if reference is None:
                    raise ValueError("C1 Phase-W witness reference is missing")
                comparisons.append(
                    {
                        "coverage": coverage,
                        "allowlist_lane": lane,
                        "report_interval": interval,
                        **compare_witness(reference, candidate),
                    }
                )
        estimates.append(estimate)
        rows.append(
            {
                "batch_size": batch_size,
                "strong_window_seconds": seconds["strong"],
                "weak_window_seconds": seconds["weak"],
                "witness_comparisons": comparisons,
                "snapshot_verified": snapshot_verified,
                **resource_maxima,
                "memory_estimate_monotonic": True,
            }
        )
    monotonic = all(left <= right for left, right in zip(estimates, estimates[1:]))
    for row in rows:
        row["memory_estimate_monotonic"] = monotonic
    return tuple(rows)


def _aggregate_rows(value: Any) -> int:
    if isinstance(value, list):
        return len(value) + sum(_aggregate_rows(item) for item in value)
    if isinstance(value, dict):
        return sum(_aggregate_rows(item) for item in value.values())
    return 0


def _component_digest(result: Mapping[str, Any], components: Sequence[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    framed = (("result", canonical_json_bytes(dict(result))), *components)
    for label, content in framed:
        label_bytes = label.encode("utf-8")
        digest.update(len(label_bytes).to_bytes(8, "big"))
        digest.update(label_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def seal_bundle(
    path: Path,
    *,
    result: Mapping[str, Any],
    component_paths: Mapping[str, Path],
    project_root: Path,
    overlay_diff_sha256: str,
    import_sha256: Mapping[str, str],
) -> dict[str, Any]:
    """Write the complete private C1 bundle and detached bundle digest."""
    required_labels = {"spec", "harness", "driver"}
    if not required_labels <= set(component_paths):
        raise ValueError("C1 seal requires spec, harness, and driver components")
    if overlay_diff_sha256 != "none" and len(overlay_diff_sha256) != 64:
        raise ValueError("C1 overlay diff identity must be none or SHA-256")
    root = project_root.resolve()
    components = []
    component_bytes = []
    for label, source in sorted(component_paths.items()):
        if not label or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for char in label):
            raise ValueError("C1 component label is unsafe")
        resolved = source.resolve()
        try:
            relative = resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError("C1 component must live under the project root") from exc
        if not resolved.is_file():
            raise ValueError("C1 seal component is missing")
        content = resolved.read_bytes()
        components.append(
            {
                "label": label,
                "path": relative.as_posix(),
                "bytes": len(content),
                "sha256": _sha256_bytes(content),
            }
        )
        component_bytes.append((label, content))
    for name, digest in import_sha256.items():
        if not name or len(digest) != 64:
            raise ValueError("C1 import identity must contain named SHA-256 values")
    payload = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "authority": {
            "spec_version": SPEC_VERSION,
            "spec_sha256": SPEC_SHA256,
        },
        "source_identity": {
            "baseline_commit": BASELINE_COMMIT,
            "overlay_diff_sha256": overlay_diff_sha256,
            "import_sha256": dict(sorted(import_sha256.items())),
        },
        "result": dict(result),
        "components": components,
        "seal": {
            "component_set_sha256": _component_digest(result, component_bytes),
            "component_count": len(components),
        },
    }
    _reject_identity_fields(payload)
    if _aggregate_rows(payload) > BUNDLE_MAX_ROWS:
        raise ValueError("C1 bundle exceeds 1,000,000 aggregate rows")
    encoded = canonical_json_bytes(payload) + b"\n"
    if len(encoded) > BUNDLE_MAX_BYTES:
        raise ValueError("C1 bundle exceeds 100 MB")
    private_mkdir(path.parent)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        private_write_text(temporary, encoded.decode("utf-8"))
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    bundle_sha256 = _sha256_file(path)
    detached = path.with_suffix(path.suffix + ".sha256")
    private_write_text(detached, f"{bundle_sha256}  {path.name}\n")
    return {
        "bundle": str(path),
        "bundle_sha256": bundle_sha256,
        "detached": str(detached),
        "component_set_sha256": payload["seal"]["component_set_sha256"],
    }


def _reject_identity_fields(value: Any, *, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold()
            if normalized in _IDENTITY_KEYS:
                raise ValueError(f"C1 bundle contains identity-bearing field at {path}.{key}")
            _reject_identity_fields(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_identity_fields(item, path=f"{path}[{index}]")


def verify_bundle(path: Path, *, project_root: Path | None = None) -> dict[str, Any]:
    size = path.stat().st_size
    if size > BUNDLE_MAX_BYTES:
        raise ValueError("C1 bundle exceeds 100 MB")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("C1 bundle root must be an object")
    if payload.get("schema") != SCHEMA or payload.get("schema_version") != 1:
        raise ValueError("C1 bundle schema is not recognized")
    authority = payload.get("authority")
    if not isinstance(authority, dict):
        raise ValueError("C1 bundle authority is missing")
    if authority.get("spec_version") != SPEC_VERSION:
        raise ValueError("C1 bundle spec version mismatch")
    if authority.get("spec_sha256") != SPEC_SHA256:
        raise ValueError("C1 bundle spec hash mismatch")
    if set(payload) != {
        "schema",
        "schema_version",
        "authority",
        "source_identity",
        "result",
        "components",
        "seal",
    }:
        raise ValueError("C1 bundle contains extra or missing top-level fields")
    source_identity = payload.get("source_identity")
    if not isinstance(source_identity, dict):
        raise ValueError("C1 bundle source identity is missing")
    if source_identity.get("baseline_commit") != BASELINE_COMMIT:
        raise ValueError("C1 bundle baseline commit mismatch")
    overlay = source_identity.get("overlay_diff_sha256")
    if overlay != "none" and (not isinstance(overlay, str) or len(overlay) != 64):
        raise ValueError("C1 bundle overlay diff identity is invalid")
    result = payload.get("result")
    components = payload.get("components")
    seal = payload.get("seal")
    if not isinstance(result, dict) or not isinstance(components, list) or not isinstance(seal, dict):
        raise ValueError("C1 bundle seal structure is incomplete")
    labels = [item.get("label") for item in components if isinstance(item, dict)]
    if len(labels) != len(components) or len(labels) != len(set(labels)):
        raise ValueError("C1 bundle component labels are invalid")
    if not {"spec", "harness", "driver"} <= set(labels):
        raise ValueError("C1 bundle required components are missing")
    root = (project_root or Path(__file__).resolve().parents[1]).resolve()
    component_bytes = []
    for item in components:
        if set(item) != {"label", "path", "bytes", "sha256"}:
            raise ValueError("C1 component manifest row is malformed")
        relative = Path(str(item["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("C1 component path is unsafe")
        component = (root / relative).resolve()
        try:
            component.relative_to(root)
        except ValueError as exc:
            raise ValueError("C1 component path escapes project root") from exc
        if not component.is_file():
            raise ValueError("C1 bundle component is missing")
        content = component.read_bytes()
        if len(content) != item["bytes"] or _sha256_bytes(content) != item["sha256"]:
            raise ValueError("C1 bundle component hash mismatch")
        component_bytes.append((str(item["label"]), content))
    if seal.get("component_count") != len(components):
        raise ValueError("C1 bundle component count mismatch")
    if seal.get("component_set_sha256") != _component_digest(result, component_bytes):
        raise ValueError("C1 bundle component-set digest mismatch")
    _reject_identity_fields(payload)
    rows = _aggregate_rows(payload)
    if rows > BUNDLE_MAX_ROWS:
        raise ValueError("C1 bundle exceeds 1,000,000 aggregate rows")
    bundle_sha256 = _sha256_file(path)
    detached = path.with_suffix(path.suffix + ".sha256")
    expected_detached = f"{bundle_sha256}  {path.name}\n"
    if not detached.is_file() or detached.read_text(encoding="utf-8") != expected_detached:
        raise ValueError("C1 detached bundle digest mismatch")
    return {
        "bundle_sha256": bundle_sha256,
        "bytes": size,
        "aggregate_rows": rows,
        "verified": True,
    }


def _cmd_windows(args: argparse.Namespace) -> int:
    windows = enumerate_windows(args.earliest, args.anchor)
    print(
        canonical_json_bytes(
            {
                "schema": SCHEMA,
                "schema_version": SCHEMA_VERSION,
                "windows": {
                    mode.value: [window.json() for window in items]
                    for mode, items in windows.items()
                },
            }
        ).decode("utf-8")
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    print(
        canonical_json_bytes(
            verify_bundle(args.bundle, project_root=args.project_root)
        ).decode("utf-8")
    )
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    reference = json.loads(args.reference.read_text(encoding="utf-8"))
    candidate_artifact = json.loads(args.candidate.read_text(encoding="utf-8"))
    results = candidate_artifact.get("results")
    if not isinstance(results, list):
        raise ValueError("C1 candidate batch results are missing")
    matches = [
        item
        for item in results
        if isinstance(item, dict)
        and item.get("window_ordinal") == args.window_ordinal
        and item.get("allowlist_lane") == args.allowlist_lane
    ]
    if len(matches) != 1:
        raise ValueError("C1 candidate witness key must match exactly one result")
    comparison = compare_witness(reference, matches[0])
    print(canonical_json_bytes(comparison).decode("utf-8"))
    return 0 if comparison["promotable"] else 2


def _cmd_matrix(args: argparse.Namespace) -> int:
    payload = run_control_matrix(args.project_root, args.output)
    print(
        canonical_json_bytes(
            {
                "all_green": payload["all_green"],
                "obligation_count": payload["obligation_count"],
                "receipt": str(args.output),
            }
        ).decode("utf-8")
    )
    return 0 if payload["all_green"] else 2


def _cmd_phase_w(args: argparse.Namespace) -> int:
    request = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(request, dict) or set(request) != {
        "candidates",
        "strong_shift_count",
        "weak_shift_count",
        "overhead_seconds",
    }:
        raise ValueError("C1 Phase-W request fields are incomplete")
    result = select_wall_candidate(
        request["candidates"],
        strong_shift_count=request["strong_shift_count"],
        weak_shift_count=request["weak_shift_count"],
        overhead_seconds=request["overhead_seconds"],
    )
    atomic_receipt(args.output, result)
    print(canonical_json_bytes(result).decode("utf-8"))
    return 0 if result["selected_batch_size"] is not None else 2


def _cmd_series_receipts(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
    harness = root / "tools" / "dnsblock_c1_harness.py"
    imports = {
        "runner": _sha256_file(root / "sigwood" / "runner.py"),
        "detector": _sha256_file(root / "sigwood" / "detectors" / "dnsblock.py"),
    }
    rows = write_series_receipts(
        artifact,
        receipt_dir=args.receipt_dir,
        mode=WindowMode(args.window_mode),
        overlay_diff_sha256=args.overlay_diff_sha256,
        harness_sha256=_sha256_file(harness),
        imports_sha256=imports,
    )
    index = {
        "artifact_sha256": _sha256_file(args.artifact),
        "window_mode": args.window_mode,
        "receipt_count": len(rows),
        "receipts": rows,
    }
    atomic_receipt(args.index, index)
    print(canonical_json_bytes(index).decode("utf-8"))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    windows = subparsers.add_parser("windows", help="enumerate the frozen window list")
    windows.add_argument("--earliest", type=_instant, required=True)
    windows.add_argument("--anchor", type=_instant, required=True)
    windows.set_defaults(func=_cmd_windows)
    verify = subparsers.add_parser("verify", help="verify an aggregate sealed bundle")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--project-root", type=Path)
    verify.set_defaults(func=_cmd_verify)
    compare = subparsers.add_parser(
        "compare-witness", help="compare one baseline receipt to a batch result"
    )
    compare.add_argument("--reference", type=Path, required=True)
    compare.add_argument("--candidate", type=Path, required=True)
    compare.add_argument("--window-ordinal", type=int, required=True)
    compare.add_argument(
        "--allowlist-lane", choices=ALLOWED_LANES, required=True
    )
    compare.set_defaults(func=_cmd_compare)
    matrix = subparsers.add_parser("matrix", help="run the frozen §12 control index")
    matrix.add_argument("--project-root", type=Path, required=True)
    matrix.add_argument("--output", type=Path, required=True)
    matrix.set_defaults(func=_cmd_matrix)
    phase_w = subparsers.add_parser(
        "phase-w", help="grade the frozen Phase-W wall candidates"
    )
    phase_w.add_argument("--input", type=Path, required=True)
    phase_w.add_argument("--output", type=Path, required=True)
    phase_w.set_defaults(func=_cmd_phase_w)
    receipts = subparsers.add_parser(
        "series-receipts", help="fan out one complete series artifact"
    )
    receipts.add_argument("artifact", type=Path)
    receipts.add_argument("--project-root", type=Path, required=True)
    receipts.add_argument("--receipt-dir", type=Path, required=True)
    receipts.add_argument("--index", type=Path, required=True)
    receipts.add_argument(
        "--window-mode", choices=tuple(mode.value for mode in WindowMode), required=True
    )
    receipts.add_argument("--overlay-diff-sha256", required=True)
    receipts.set_defaults(func=_cmd_series_receipts)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
