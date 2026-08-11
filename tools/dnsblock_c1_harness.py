#!/usr/bin/env python3
"""Internal pre-public product-path harness for planned dnsblock units."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import resource
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from sigwood import runner
from sigwood.common.allowlist import matcher_from_plan, resolve_allowlist_plan
from sigwood.common.finding import DetectorContext, RunSummary, SuppressionSummary
from sigwood.common.loader import DualWindow, PositionalMask
from sigwood.common.output import Reporter
from sigwood.common.paths import private_mkdir, private_write_text
from sigwood.detectors import dnsblock
from sigwood.outputs._serialize import to_jsonable
try:
    from tools.dnsblock_c1_sweep import (
        GridSurvivorAccumulator,
        reduce_repeat_burden,
    )
except ModuleNotFoundError as exc:
    if exc.name != "tools":
        raise
    from dnsblock_c1_sweep import (  # type: ignore[no-redef]
        GridSurvivorAccumulator,
        reduce_repeat_burden,
    )


_FOLD_RSS_GREEN = 1536 * 1024 * 1024
_MIXED_INCREMENT_GREEN = 512 * 1024 * 1024
_WALL_GREEN_SECONDS = 15 * 60
_WATCHDOG_RSS = 8 * 1024 * 1024 * 1024
# PROVISIONAL-PENDING-MEASUREMENT: 3600 exceeds two times the worst observed
# context-free single-window wall (1647s). Freeze measured-plus-margin after
# the context-true rerun.
_PER_WINDOW_WATCHDOG_SECONDS = 60 * 60
# Supervisor ceiling for post-worker reducer/receipt/atomic-write assembly.
# This is never a promotion wall and never relaxes the per-batch deadline.
_ASSEMBLY_OVERHEAD_SECONDS = 600
_WATCHDOG_TERM_GRACE_SECONDS = 5
_JSON_CAPTURE_LIMIT = 8 * 1024 * 1024
_SEMANTIC_DIGEST_SCHEMA = "sigwood.dnsblock.semantic-digest"
_SEMANTIC_DIGEST_VERSION = 1
_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9])(?:/[^\s,;]+|[A-Za-z]:\\[^\s,;]+)")
_PATH_KEYS = frozenset({"artifact", "artifact_path", "output_path", "source_path"})


class BatchWatchdogError(RuntimeError):
    """Bounded supervisor failure without worker traceback or estate identity."""

    def __init__(self, kind: str, ordinal: int):
        super().__init__(f"dnsblock C1 {kind} in batch {ordinal}")
        self.kind = kind
        self.ordinal = ordinal


def _batch_watchdog_seconds(window_count: int) -> int:
    if (
        isinstance(window_count, bool)
        or not isinstance(window_count, int)
        or window_count <= 0
    ):
        raise ValueError("dnsblock C1 watchdog requires a positive window count")
    return _PER_WINDOW_WATCHDOG_SECONDS * window_count


def _series_watchdog_seconds(batch_window_counts: tuple[int, ...]) -> int:
    if not isinstance(batch_window_counts, tuple) or not batch_window_counts:
        raise ValueError("dnsblock C1 watchdog requires non-empty batch window counts")
    return sum(
        _batch_watchdog_seconds(window_count)
        for window_count in batch_window_counts
    ) + _ASSEMBLY_OVERHEAD_SECONDS


_NOTE_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"period coverage is not verifiable from these logs; period counts use data-bearing periods, and burst and recurring activity were not evaluated",
        r"dnsblock: [0-9]+ candidate (?:pair|pairs) withheld — not enough prior history in the loaded window",
        r"dnsblock: arrival analysis needs at least [0-9]+ prior periods; the loaded window has [0-9]+",
        r"dnsblock: first-activity analysis needs [0-9]+ eligible periods; the window has [0-9]+",
        r"dnsblock: burst analysis needs [0-9]+ eligible periods; the window has [0-9]+",
        r"dnsblock: recurring analysis needs every report period strongly covered; [0-9]+ of [0-9]+ were not",
        r"dnsblock: [0-9]+ synchronized first (?:appearance|appearances) withheld \([0-9]+ addresses reached the same family in one period\)",
        r"dnsblock: the allowlist removed [0-9]+ block-outcome (?:row|rows) from the report interval and [0-9]+ from context",
        r"dnsblock: no Pi-hole query rows in the window",
        r"dnsblock: no blocked-name outcomes logged in the window",
        r"dnsblock: all block-outcome rows were removed by the allowlist",
        r"dnsblock: blocked-name activity found, but nothing met the reporting thresholds",
    )
)


def _instant(text: str) -> datetime:
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    value = datetime.fromisoformat(normalized)
    if value.tzinfo is None or value.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include a UTC offset")
    return value.astimezone(timezone.utc)


def _atomic_json(path: Path, payload: dict) -> None:
    private_mkdir(path.parent)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        private_write_text(
            temporary,
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        )
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


class _BoundedTextCapture(io.StringIO):
    """In-memory text sink with an explicit byte ceiling."""

    def __init__(self) -> None:
        super().__init__()
        self._bytes_written = 0

    def write(self, value: str) -> int:
        size = len(value.encode("utf-8"))
        if self._bytes_written + size > _JSON_CAPTURE_LIMIT:
            raise ValueError("dnsblock json render exceeded the harness capture bound")
        written = super().write(value)
        self._bytes_written += size
        return written


def canonical_semantic_payload(payload: dict) -> dict:
    """Version-1 stable subset of an actual JsonHandler payload."""
    summary = payload.get("run_summary")
    if not isinstance(summary, dict):
        summary = {}
    summary_keys = (
        "data_window",
        "record_counts",
        "record_labels",
        "data_size_bytes",
        "detectors_run",
        "detectors_skipped",
        "detectors_failed",
        "notes",
        "data_sources",
        "detector_methods",
        "requested_span",
        "suppression",
    )
    finding_keys = (
        "detector",
        "severity",
        "title",
        "description",
        "next_steps",
        "evidence",
        "data_window",
    )
    findings = payload.get("findings")
    if not isinstance(findings, list):
        findings = []
    canonical = {
        "digest_schema": _SEMANTIC_DIGEST_SCHEMA,
        "digest_version": _SEMANTIC_DIGEST_VERSION,
        "json_schema_version": payload.get("schema_version"),
        "run_summary": {key: summary.get(key) for key in summary_keys},
        "findings": [
            {key: finding.get(key) for key in finding_keys}
            for finding in findings
            if isinstance(finding, dict)
        ],
    }
    return to_jsonable(_exclude_paths(canonical))


def _exclude_paths(value):
    """Drop path fields and neutralize absolute paths inside otherwise-stable prose."""
    if isinstance(value, dict):
        return {
            key: _exclude_paths(item)
            for key, item in value.items()
            if str(key).casefold() not in _PATH_KEYS
        }
    if isinstance(value, list):
        return [_exclude_paths(item) for item in value]
    if isinstance(value, str):
        return _ABSOLUTE_PATH.sub("<path>", value)
    return value


def semantic_digest(payload: dict, *, format_token: str = "json") -> dict:
    canonical = canonical_semantic_payload(payload)
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    findings = canonical["findings"]
    return {
        "schema": _SEMANTIC_DIGEST_SCHEMA,
        "version": _SEMANTIC_DIGEST_VERSION,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "finding_count": len(findings),
        "format": format_token,
    }


def _validate_summary_notes(payload: dict) -> None:
    """Reject any artifact note outside dnsblock's identity-free frozen grammar."""
    notes = payload.get("summary_notes")
    if not isinstance(notes, list):
        raise ValueError("dnsblock artifact summary_notes must be a list")
    cap_lines = {
        f"dnsblock: analysis stopped — {axis} exceeded its bound ({limit}); no findings emitted this run"
        for _token, axis, limit in runner._DNSBLOCK_CAP_NOTES
    }
    for line in notes:
        if not isinstance(line, str) or "\n" in line:
            raise ValueError("dnsblock artifact contains an unsafe summary note")
        if line in cap_lines:
            continue
        if not any(pattern.fullmatch(line) for pattern in _NOTE_PATTERNS):
            raise ValueError("dnsblock artifact contains a non-template summary note")


@contextmanager
def _selected_source(source: Path, manifest: Path | None):
    if manifest is None:
        yield source, None
        return
    members: list[tuple[str, int, str]] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError("corpus manifest row must have path, bytes, and sha256")
        name, size_text, digest = fields
        if Path(name).name != name or len(digest) != 64:
            raise ValueError("corpus manifest contains an unsafe member")
        members.append((name, int(size_text), digest))
    with tempfile.TemporaryDirectory(prefix="dnsblock-u2b-") as temporary:
        staged = Path(temporary)
        for name, expected_size, expected_digest in members:
            path = source / name
            if path.stat().st_size != expected_size or _sha256(path) != expected_digest:
                raise ValueError("corpus member does not match the frozen manifest")
            (staged / name).symlink_to(path)
        try:
            yield staged, {
                "manifest_sha256": _sha256(manifest),
                "member_count": len(members),
                "member_bytes": sum(size for _name, size, _digest in members),
            }
        finally:
            for name, expected_size, expected_digest in members:
                path = source / name
                if (
                    path.stat().st_size != expected_size
                    or _sha256(path) != expected_digest
                ):
                    raise ValueError("corpus member changed during the harness run")


def _request_windows(
    path: Path, *, allowed_counts: tuple[int, ...] | None
) -> tuple[DualWindow, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or set(payload) != {"windows"}:
        raise ValueError("window request must contain exactly one windows field")
    rows = payload["windows"]
    if (
        not isinstance(rows, list)
        or not rows
        or (allowed_counts is not None and len(rows) not in allowed_counts)
    ):
        expected = "a non-empty window series" if allowed_counts is None else "exactly 2, 4, or 8 windows"
        raise ValueError(f"window request must contain {expected}")
    windows = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("batch request window must be an object")
        allowed = {"start", "end", "context_start", "context_end"}
        if not {"start", "end"} <= set(row) or set(row) - allowed:
            raise ValueError("batch request window fields are not recognized")
        context_fields = (row.get("context_start"), row.get("context_end"))
        if (context_fields[0] is None) != (context_fields[1] is None):
            raise ValueError("batch request context requires both endpoints")
        context = (
            (_instant(str(context_fields[0])), _instant(str(context_fields[1])))
            if context_fields[0] is not None
            else None
        )
        windows.append(
            DualWindow(
                (_instant(str(row["start"])), _instant(str(row["end"]))),
                context,
            )
        )
    if len({window.report_interval for window in windows}) != len(windows):
        raise ValueError("batch request windows must be unique")
    return tuple(windows)


def _batch_windows(path: Path) -> tuple[DualWindow, ...]:
    return _request_windows(path, allowed_counts=(2, 4, 8))


def _series_windows(path: Path) -> tuple[DualWindow, ...]:
    return _request_windows(path, allowed_counts=None)


def _partition_series(
    windows: tuple[DualWindow, ...], *, batch_size: int
) -> tuple[tuple[DualWindow, ...], ...]:
    if batch_size not in (2, 4, 8):
        raise ValueError("dnsblock C1 series batch size must be 2, 4, or 8")
    batches = [
        windows[offset : offset + batch_size]
        for offset in range(0, len(windows), batch_size)
    ]
    if tuple(window for batch in batches for window in batch) != windows:
        raise ValueError("dnsblock C1 series partition lost or reordered a window")
    return tuple(batches)


def _render_prepared_json(prepared, *, lane: str, matcher) -> tuple[dict, dict, dict]:
    """Route one prepared result through the real dnsblock + JSON pipeline."""
    context = DetectorContext(
        logs={},
        config={},
        allowlist=matcher,
        data_window=prepared.preflight.report_interval,
        data_sources=["pihole"],
        home_net=[],
    )
    findings = dnsblock.run(context, _prepared=prepared)
    notes = runner._format_dnsblock_summary_notes(prepared)
    rows_kept = int(prepared.preflight.rows_kept)
    rows_suppressed = int(prepared.preflight.rows_suppressed)
    raw_rows = rows_kept + rows_suppressed
    observed_window = prepared.preflight.observed_data_window
    if raw_rows and observed_window is not None:
        observed_start, observed_end = (
            value.astimezone(timezone.utc) for value in observed_window
        )
        rendered_window = (
            f"{observed_start:%Y-%m-%d %H:%M} → "
            f"{observed_end:%Y-%m-%d %H:%M} UTC"
        )
        notes.append(
            f"Pi-hole: {raw_rows:,} rows loaded, 0 in the selected window; "
            f"data spans {rendered_window} - widen with "
            "--since/--days, or --all"
        )
    summary = RunSummary(
        data_window=None,
        record_counts={},
        record_labels={},
        data_size_bytes=prepared.preflight.data_size_bytes,
        detectors_run=["dnsblock"],
        detectors_skipped={},
        notes=notes,
        data_sources=[],
        detector_methods={"dnsblock": None},
        requested_span=None,
        invocation="dnsblock-c1-harness --batch-request",
        generated_at=datetime.now(timezone.utc),
    )
    summary.suppression = SuppressionSummary(
        enabled=lane == "default",
        connections=0,
        domains=0,
        connection_total=0,
        domain_total=0,
    )
    capture = _BoundedTextCapture()
    handler, close_handler, _path = runner._build_output_handler(
        "json",
        None,
        None,
        0,
        stream=capture,
        detectors_run=["dnsblock"],
    )
    reporter = Reporter([handler])
    reporter.begin(summary)
    try:
        reporter.write(findings)
        reporter.end()
    finally:
        close_handler()
    rendered = json.loads(capture.getvalue())
    return (
        rendered,
        semantic_digest(rendered),
        canonical_semantic_payload(rendered)["run_summary"],
    )


def _prepare_render_batch(
    *,
    selected_source: Path,
    windows: tuple[DualWindow, ...],
    effective_config: dict,
    calibration_vector: dnsblock.DnsblockCalibrationVector,
    ordinal_offset: int,
):
    allowlist_plan = resolve_allowlist_plan(effective_config)
    matcher = matcher_from_plan(allowlist_plan, force_off=False)
    lane_masks = {
        "default": lambda frame: runner._positional_allowlist_mask(
            frame, matcher, "dnsblock"
        ),
        "unsuppressed": lambda frame: PositionalMask((True,) * len(frame)),
    }
    started = time.monotonic()
    batch = runner._prepare_dnsblock_calibration_batch(
        source_paths=(selected_source,),
        windows=windows,
        lane_masks=lane_masks,
        dnsblock_mod=dnsblock,
        calibration_vector=calibration_vector,
    )
    results = []
    peak_temp_bytes = 0
    with tempfile.TemporaryDirectory(prefix="dnsblock-c1-batch-") as temporary:
        temporary_path = Path(temporary)
        for (index, lane), prepared in sorted(batch.prepared.items()):
            aggregate_path = temporary_path / f"{index}-{lane}.json"
            runner._write_dnsblock_preflight_artifact(aggregate_path, prepared)
            peak_temp_bytes = max(
                peak_temp_bytes,
                sum(path.stat().st_size for path in temporary_path.iterdir()),
            )
            aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
            _validate_summary_notes(aggregate)
            expected_context = (
                [value.isoformat() for value in windows[index].context_interval]
                if windows[index].context_interval is not None
                else None
            )
            if aggregate.get("preflight", {}).get("context_interval") != expected_context:
                raise ValueError("dnsblock result context interval diverged from its request")
            _rendered, digest, semantic_summary = _render_prepared_json(
                prepared,
                lane=lane,
                matcher=matcher,
            )
            results.append(
                {
                    "window_ordinal": ordinal_offset + index,
                    "allowlist_lane": lane,
                    "report_interval": aggregate["preflight"]["report_interval"],
                    "context_interval": expected_context,
                    "aggregate": aggregate,
                    "semantic_digest": digest,
                    "semantic_summary": semantic_summary,
                }
            )
    elapsed = time.monotonic() - started
    return batch, results, elapsed, peak_temp_bytes


def _window_payload(window: DualWindow) -> dict[str, object]:
    payload: dict[str, object] = {
        "start": window.report_interval[0].isoformat(),
        "end": window.report_interval[1].isoformat(),
    }
    if window.context_interval is not None:
        payload["context_start"] = window.context_interval[0].isoformat()
        payload["context_end"] = window.context_interval[1].isoformat()
    return payload


def _calibration_vector_payload(
    vector: dnsblock.DnsblockCalibrationVector,
) -> dict[str, object]:
    return {
        "arrival_days": vector.arrival_days,
        "arrival_history": vector.arrival_history,
        "burst_absolute": vector.burst_absolute,
        "burst_multiple": vector.burst_multiple,
        "burst_active": vector.burst_active,
        "burst_enabled": vector.burst_enabled,
    }


def _internal_worker(request_path: Path, partial_path: Path) -> int:
    """Execute one already-selected private batch and publish one partial."""
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if not isinstance(request, dict) or set(request) != {
        "schema_version",
        "selected_source",
        "windows",
        "ordinal_offset",
        "calibration_vector",
    }:
        return 70
    if request.get("schema_version") != 1:
        return 70
    source = Path(str(request["selected_source"]))
    rows = request["windows"]
    if not source.exists() or not isinstance(rows, list) or not 1 <= len(rows) <= 8:
        return 70
    windows = []
    for row in rows:
        if not isinstance(row, dict):
            return 70
        context = None
        if row.get("context_start") is not None or row.get("context_end") is not None:
            if row.get("context_start") is None or row.get("context_end") is None:
                return 70
            context = (_instant(str(row["context_start"])), _instant(str(row["context_end"])))
        windows.append(
            DualWindow(
                (_instant(str(row["start"])), _instant(str(row["end"]))),
                context,
            )
        )
    ordinal_offset = request["ordinal_offset"]
    vector_fields = request["calibration_vector"]
    if (
        isinstance(ordinal_offset, bool)
        or not isinstance(ordinal_offset, int)
        or ordinal_offset < 0
        or not isinstance(vector_fields, dict)
    ):
        return 70
    vector = dnsblock.DnsblockCalibrationVector(**vector_fields)
    effective_config = {
        "sigwood": {"root": "", "warn_above": 0, "default_window": "7d"}
    }
    batch, results, elapsed, peak_temp_bytes = _prepare_render_batch(
        selected_source=source,
        windows=tuple(windows),
        effective_config=effective_config,
        calibration_vector=vector,
        ordinal_offset=ordinal_offset,
    )
    survivor_batches = []
    repeat_batches = []
    for (index, _lane), prepared in sorted(batch.prepared.items()):
        survivors = prepared.calibration_survivors
        if survivors is None:
            return 70
        survivor_batches.append(
            {
                "arrival": [list(item) for item in survivors.arrival_memberships],
                "burst": [list(item) for item in survivors.burst_memberships],
            }
        )
        appearances = []
        if prepared.analysis is not None:
            period = ordinal_offset + index
            appearances.extend(
                [f"{item.address}\0{item.family_key}", period, "arrival"]
                for item in prepared.analysis.arrivals
            )
            appearances.extend(
                [f"{item.address}\0{item.family_key}", period, "burst"]
                for item in prepared.analysis.bursts
            )
        repeat_batches.append(appearances)
    _atomic_json(
        partial_path,
        {
            "schema_version": 1,
            "window_count": len(windows),
            "result_count": len(results),
            "snapshot_identity_sha256": batch.snapshot_identity_sha256,
            "content_identity_sha256": batch.content_identity_sha256,
            "pass_wall_seconds": batch.pass_wall_seconds,
            "data_size_bytes": batch.data_size_bytes,
            "max_window_routes": batch.max_window_routes,
            "max_inflight_cadence_gaps": batch.max_inflight_cadence_gaps,
            "worker_elapsed_seconds": elapsed,
            "peak_temp_bytes": peak_temp_bytes,
            "peak_process_rss_bytes": (
                int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
                * (1 if sys.platform == "darwin" else 1024)
            ),
            "results": results,
            "survivor_batches": survivor_batches,
            "repeat_batches": repeat_batches,
        },
    )
    return 0


def _terminate_worker_group(process: subprocess.Popen) -> None:
    """Bounded TERM-to-KILL cancellation followed by an unconditional reap."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=_WATCHDOG_TERM_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _supervised_batch(
    *,
    selected_source: Path,
    windows: tuple[DualWindow, ...],
    calibration_vector: dnsblock.DnsblockCalibrationVector,
    ordinal_offset: int,
    batch_ordinal: int,
    transaction_parent: Path,
    deadline_seconds: float | None = None,
) -> dict:
    """Run one private batch behind an external, process-group watchdog."""
    if deadline_seconds is None:
        deadline_seconds = _batch_watchdog_seconds(len(windows))
    private_mkdir(transaction_parent)
    transaction = Path(
        tempfile.mkdtemp(prefix=".dnsblock-c1-worker-", dir=transaction_parent)
    )
    os.chmod(transaction, 0o700)
    request_path = transaction / "request.json"
    partial_path = transaction / "partial.json"
    request = {
        "schema_version": 1,
        "selected_source": str(selected_source),
        "windows": [_window_payload(window) for window in windows],
        "ordinal_offset": ordinal_offset,
        "calibration_vector": _calibration_vector_payload(calibration_vector),
    }
    private_write_text(
        request_path,
        json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n",
    )
    root = Path(__file__).resolve().parents[1]
    argv = (
        str(Path(sys.executable).absolute()),
        str(Path(__file__).resolve()),
        "--internal-worker-request",
        str(request_path),
        "--internal-worker-partial",
        str(partial_path),
    )
    environment = {
        "HOME": str(Path.home()),
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
        "PYTHONHASHSEED": "0",
        "PYTHONPATH": str(root),
        "TZ": "UTC",
    }
    process = subprocess.Popen(
        argv,
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        try:
            returncode = process.wait(timeout=deadline_seconds)
        except subprocess.TimeoutExpired as exc:
            _terminate_worker_group(process)
            raise BatchWatchdogError("batch_watchdog_timeout", batch_ordinal) from exc
        if returncode != 0:
            raise BatchWatchdogError("worker_failure", batch_ordinal)
        try:
            descriptor = os.open(
                partial_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
        except OSError as exc:
            raise BatchWatchdogError(
                "partial_validation_failure", batch_ordinal
            ) from exc
        with os.fdopen(descriptor, "rb") as stream:
            partial_info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(partial_info.st_mode)
                or stat.S_IMODE(partial_info.st_mode) != 0o600
                or partial_info.st_uid != os.getuid()
                or partial_info.st_nlink != 1
                or partial_info.st_size > 128 * 1024 * 1024
            ):
                raise BatchWatchdogError(
                    "partial_validation_failure", batch_ordinal
                )
            partial_raw = stream.read(128 * 1024 * 1024 + 1)
        if len(partial_raw) > 128 * 1024 * 1024:
            raise BatchWatchdogError("partial_validation_failure", batch_ordinal)
        try:
            partial = json.loads(partial_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BatchWatchdogError(
                "partial_validation_failure", batch_ordinal
            ) from exc
        if (
            not isinstance(partial, dict)
            or partial.get("schema_version") != 1
            or partial.get("window_count") != len(windows)
            or partial.get("result_count") != 2 * len(windows)
            or not isinstance(partial.get("results"), list)
            or not isinstance(partial.get("survivor_batches"), list)
            or not isinstance(partial.get("repeat_batches"), list)
            or len(partial["survivor_batches"]) != 2 * len(windows)
            or len(partial["repeat_batches"]) != 2 * len(windows)
            or isinstance(partial.get("peak_process_rss_bytes"), bool)
            or not isinstance(partial.get("peak_process_rss_bytes"), int)
            or partial["peak_process_rss_bytes"] < 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(partial.get("snapshot_identity_sha256")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(partial.get("content_identity_sha256")))
        ):
            raise BatchWatchdogError("partial_validation_failure", batch_ordinal)
        expected_keys = {
            (ordinal_offset + index, lane)
            for index in range(len(windows))
            for lane in ("default", "unsuppressed")
        }
        observed_keys = set()
        for result in partial["results"]:
            if not isinstance(result, dict):
                raise BatchWatchdogError("partial_validation_failure", batch_ordinal)
            aggregate = result.get("aggregate")
            preflight = aggregate.get("preflight") if isinstance(aggregate, dict) else None
            key = (result.get("window_ordinal"), result.get("allowlist_lane"))
            if (
                key not in expected_keys
                or key in observed_keys
                or not isinstance(preflight, dict)
                or preflight.get("snapshot_identity")
                != partial["snapshot_identity_sha256"]
            ):
                raise BatchWatchdogError("partial_validation_failure", batch_ordinal)
            observed_keys.add(key)
        if observed_keys != expected_keys:
            raise BatchWatchdogError("partial_validation_failure", batch_ordinal)
        return partial
    finally:
        if process.poll() is None:
            _terminate_worker_group(process)
        for path in (partial_path, request_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        try:
            transaction.rmdir()
        except OSError:
            pass


def _run_batch(
    *,
    selected_source: Path,
    artifact: Path,
    request: Path,
    effective_config: dict,
    corpus_facts: dict | None,
    calibration_vector: dnsblock.DnsblockCalibrationVector,
    co_load: int,
) -> int:
    windows = _batch_windows(request)
    batch_deadline_seconds = _batch_watchdog_seconds(len(windows))
    started = time.monotonic()
    try:
        batch = _supervised_batch(
            selected_source=selected_source,
            windows=windows,
            calibration_vector=calibration_vector,
            ordinal_offset=0,
            batch_ordinal=0,
            transaction_parent=artifact.parent,
            deadline_seconds=batch_deadline_seconds,
        )
    except BatchWatchdogError as exc:
        _atomic_json(
            artifact.with_suffix(artifact.suffix + ".timeout.json"),
            {
                "schema_version": 1,
                "watchdog_enforced": True,
                "failure": exc.kind,
                "batch_ordinal": exc.ordinal,
                "per_window_watchdog_seconds": _PER_WINDOW_WATCHDOG_SECONDS,
                "batch_window_count": len(windows),
                "batch_deadline_seconds": batch_deadline_seconds,
            },
        )
        return 124
    elapsed = time.monotonic() - started
    results = batch["results"]
    peak_temp_bytes = batch["peak_temp_bytes"]
    peak_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform != "darwin":
        peak_rss *= 1024
    peak_rss = max(peak_rss, int(batch["peak_process_rss_bytes"]))
    payload = {
        "schema_version": 2,
        "detector": "dnsblock",
        "status": "planned",
        "batch": {
            "window_count": len(windows),
            "allowlist_lanes": ["default", "unsuppressed"],
            "snapshot_identity_sha256": batch["snapshot_identity_sha256"],
            "content_identity_sha256": batch["content_identity_sha256"],
            "elapsed_seconds": elapsed,
            "peak_process_rss_bytes": peak_rss,
            "peak_temp_bytes": peak_temp_bytes,
            "max_window_routes": batch["max_window_routes"],
            "max_inflight_cadence_gaps": batch["max_inflight_cadence_gaps"],
            "inflight_window_lane_bytes_estimate": (
                batch["data_size_bytes"] * len(windows) * 2
            ),
            "rss_green": peak_rss <= _FOLD_RSS_GREEN,
            "rss_limit_bytes": _FOLD_RSS_GREEN,
            "pass_wall_seconds": batch["pass_wall_seconds"],
            "watchdog_enforced": True,
            "co_load": co_load,
            "per_window_watchdog_seconds": _PER_WINDOW_WATCHDOG_SECONDS,
            "batch_deadline_seconds": batch_deadline_seconds,
            "total_elapsed_seconds": elapsed,
            "source_head": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip(),
            "corpus": corpus_facts,
        },
        "results": results,
    }
    _atomic_json(artifact, payload)
    failed = any(
        item["aggregate"]["preflight"]["state"] == "FAILED" for item in results
    )
    return 1 if failed else 0


def _run_series(
    *,
    selected_source: Path,
    artifact: Path,
    request: Path,
    effective_config: dict,
    corpus_facts: dict | None,
    calibration_vector: dnsblock.DnsblockCalibrationVector,
    batch_size: int,
    co_load: int,
) -> int:
    series_started = time.monotonic()
    windows = _series_windows(request)
    batches = _partition_series(windows, batch_size=batch_size)
    batch_window_counts = tuple(len(batch) for batch in batches)
    batch_deadline_seconds_by_batch = tuple(
        _batch_watchdog_seconds(window_count)
        for window_count in batch_window_counts
    )
    series_deadline_seconds = _series_watchdog_seconds(batch_window_counts)
    arrival_survivors = GridSurvivorAccumulator(12)
    burst_survivors = GridSurvivorAccumulator(75)
    repeat_appearances = []
    results = []
    snapshot_identities = []
    content_identities = []
    pass_walls: dict[str, float] = {}
    elapsed = 0.0
    peak_temp_bytes = 0
    max_window_routes = 0
    max_inflight_cadence_gaps = 0
    inflight_window_lane_bytes_estimate = 0
    offset = 0
    batch_worker_walls = []
    worker_peak_rss = 0
    for batch_ordinal, window_batch in enumerate(batches):
        batch_deadline_seconds = batch_deadline_seconds_by_batch[batch_ordinal]
        remaining = series_deadline_seconds - (time.monotonic() - series_started)
        timed_batch_deadline_seconds = min(
            batch_deadline_seconds, max(0.001, remaining)
        )
        try:
            prepared_batch = _supervised_batch(
                selected_source=selected_source,
                windows=window_batch,
                calibration_vector=calibration_vector,
                ordinal_offset=offset,
                batch_ordinal=batch_ordinal,
                transaction_parent=artifact.parent,
                deadline_seconds=timed_batch_deadline_seconds,
            )
        except BatchWatchdogError as exc:
            _atomic_json(
                artifact.with_suffix(artifact.suffix + ".timeout.json"),
                {
                    "schema_version": 1,
                    "watchdog_enforced": True,
                    "failure": exc.kind,
                    "batch_ordinal": exc.ordinal,
                    "per_window_watchdog_seconds": _PER_WINDOW_WATCHDOG_SECONDS,
                    "batch_window_count": len(window_batch),
                    "batch_deadline_seconds": timed_batch_deadline_seconds,
                    "configured_batch_deadline_seconds": batch_deadline_seconds,
                    "batch_deadline_seconds_by_batch": list(
                        batch_deadline_seconds_by_batch
                    ),
                    "series_deadline_seconds": series_deadline_seconds,
                    "completed_batch_count": batch_ordinal,
                },
            )
            return 124
        batch_results = prepared_batch["results"]
        batch_elapsed = float(prepared_batch["worker_elapsed_seconds"])
        batch_worker_walls.append(batch_elapsed)
        batch_temp_bytes = int(prepared_batch["peak_temp_bytes"])
        worker_peak_rss = max(
            worker_peak_rss, int(prepared_batch["peak_process_rss_bytes"])
        )
        snapshot_identities.append(prepared_batch["snapshot_identity_sha256"])
        content_identities.append(prepared_batch["content_identity_sha256"])
        peak_temp_bytes = max(peak_temp_bytes, batch_temp_bytes)
        max_window_routes = max(max_window_routes, prepared_batch["max_window_routes"])
        max_inflight_cadence_gaps = max(
            max_inflight_cadence_gaps,
            prepared_batch["max_inflight_cadence_gaps"],
        )
        inflight_window_lane_bytes_estimate = max(
            inflight_window_lane_bytes_estimate,
            prepared_batch["data_size_bytes"] * len(window_batch) * 2,
        )
        for label, wall in prepared_batch["pass_wall_seconds"]:
            pass_walls[label] = pass_walls.get(label, 0.0) + float(wall)
        for survivor_batch in prepared_batch["survivor_batches"]:
            arrival_survivors.ingest(
                tuple((str(identity), int(mask)) for identity, mask in survivor_batch["arrival"])
            )
            burst_survivors.ingest(
                tuple((str(identity), int(mask)) for identity, mask in survivor_batch["burst"])
            )
        for appearances in prepared_batch["repeat_batches"]:
            repeat_appearances.extend(tuple(item) for item in appearances)
        results.extend(batch_results)
        elapsed += batch_elapsed
        offset += len(window_batch)
    if len(set(content_identities)) != 1:
        _atomic_json(
            artifact.with_suffix(artifact.suffix + ".timeout.json"),
            {
                "schema_version": 1,
                "watchdog_enforced": True,
                "failure": "content_identity_mismatch",
                "batch_ordinal": len(batches),
                "per_window_watchdog_seconds": _PER_WINDOW_WATCHDOG_SECONDS,
                "batch_deadline_seconds_by_batch": list(
                    batch_deadline_seconds_by_batch
                ),
                "series_deadline_seconds": series_deadline_seconds,
                "completed_batch_count": len(batches),
            },
        )
        return 2
    peak_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform != "darwin":
        peak_rss *= 1024
    peak_rss = max(peak_rss, worker_peak_rss)
    payload = {
        "schema_version": 3,
        "detector": "dnsblock",
        "status": "planned",
        "series": {
            "window_count": len(windows),
            "batch_size": batch_size,
            "batch_count": len(batches),
            "batch_window_counts": list(batch_window_counts),
            "batch_partition": {
                "ordering": "contiguous",
                "limit": "at_most_batch_size",
                "tail": "remainder_last",
            },
            "allowlist_lanes": ["default", "unsuppressed"],
            "snapshot_identity_sha256": hashlib.sha256(
                json.dumps(snapshot_identities, separators=(",", ":")).encode()
            ).hexdigest(),
            "batch_snapshot_identities": snapshot_identities,
            "content_identity_sha256": content_identities[0],
            "batch_content_identities": content_identities,
            "elapsed_seconds": elapsed,
            "watchdog_enforced": True,
            "co_load": co_load,
            "per_window_watchdog_seconds": _PER_WINDOW_WATCHDOG_SECONDS,
            "batch_deadline_seconds_by_batch": list(
                batch_deadline_seconds_by_batch
            ),
            "assembly_overhead_seconds": _ASSEMBLY_OVERHEAD_SECONDS,
            "series_deadline_seconds": series_deadline_seconds,
            "batch_worker_wall_seconds": batch_worker_walls,
            "peak_process_rss_bytes": peak_rss,
            "peak_temp_bytes": peak_temp_bytes,
            "max_window_routes": max_window_routes,
            "max_inflight_cadence_gaps": max_inflight_cadence_gaps,
            "inflight_window_lane_bytes_estimate": (
                inflight_window_lane_bytes_estimate
            ),
            "rss_green": peak_rss <= _FOLD_RSS_GREEN,
            "rss_limit_bytes": _FOLD_RSS_GREEN,
            "pass_wall_seconds": sorted(pass_walls.items()),
            "source_head": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip(),
            "corpus": corpus_facts,
        },
        "arrival_survivor_grid": arrival_survivors.aggregate(),
        "burst_survivor_grid": burst_survivors.aggregate(),
        "repeat_burden": reduce_repeat_burden(repeat_appearances),
        "results": results,
    }
    total_elapsed = time.monotonic() - series_started
    assembly_elapsed = max(0.0, total_elapsed - sum(batch_worker_walls))
    payload["series"]["assembly_elapsed_seconds"] = assembly_elapsed
    payload["series"]["total_elapsed_seconds"] = total_elapsed
    if total_elapsed > series_deadline_seconds:
        _atomic_json(
            artifact.with_suffix(artifact.suffix + ".timeout.json"),
            {
                "schema_version": 1,
                "watchdog_enforced": True,
                "failure": "series_watchdog_timeout",
                "batch_ordinal": len(batches),
                "per_window_watchdog_seconds": _PER_WINDOW_WATCHDOG_SECONDS,
                "batch_deadline_seconds_by_batch": list(
                    batch_deadline_seconds_by_batch
                ),
                "series_deadline_seconds": series_deadline_seconds,
                "completed_batch_count": len(batches),
            },
        )
        return 124
    _atomic_json(artifact, payload)
    failed = any(
        item["aggregate"]["preflight"]["state"] == "FAILED" for item in results
    )
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    original_argv = list(argv) if argv is not None else list(sys.argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--internal-worker-request", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--internal-worker-partial", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--internal-legacy", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--pihole-dir", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--since", type=_instant)
    parser.add_argument("--until", type=_instant)
    parser.add_argument("--all", action="store_true", dest="load_all")
    parser.add_argument("--window", default="7d")
    parser.add_argument("--output-format", default="text")
    parser.add_argument("--no-allowlist", action="store_true")
    parser.add_argument("--mixed-baseline-rss", type=int)
    request_group = parser.add_mutually_exclusive_group()
    request_group.add_argument("--batch-request", type=Path)
    request_group.add_argument("--series-request", type=Path)
    parser.add_argument("--series-batch-size", type=int, choices=(2, 4, 8), default=8)
    parser.add_argument("--co-load", type=int, choices=(1, 2), default=1)
    parser.add_argument("--arrival-days", type=int, default=dnsblock.ARRIVAL_DAYS)
    parser.add_argument(
        "--arrival-history", type=int, default=dnsblock.ARRIVAL_HISTORY
    )
    parser.add_argument("--burst-absolute", type=int, default=dnsblock.BURST_ABS)
    parser.add_argument("--burst-multiple", type=int, default=dnsblock.BURST_MULT)
    parser.add_argument("--burst-active", type=int, default=dnsblock.BURST_ACTIVE)
    parser.add_argument("--burst-disabled", action="store_true")
    args = parser.parse_args(argv)
    if args.internal_worker_request is not None or args.internal_worker_partial is not None:
        if (
            args.internal_worker_request is None
            or args.internal_worker_partial is None
            or args.pihole_dir is not None
            or args.artifact is not None
        ):
            parser.error("internal worker invocation is malformed")
        return _internal_worker(
            args.internal_worker_request, args.internal_worker_partial
        )
    if args.pihole_dir is None or args.artifact is None:
        parser.error("--pihole-dir and --artifact are required")
    if args.load_all and (args.since is not None or args.until is not None):
        parser.error("--all cannot be combined with --since/--until")
    private_request = args.batch_request or args.series_request
    if private_request is not None and (
        args.load_all
        or args.since is not None
        or args.until is not None
        or args.no_allowlist
        or args.output_format != "json"
    ):
        parser.error(
            "private requests require JSON output and cannot combine with "
            "--all, --since/--until, or --no-allowlist"
        )
    source = args.pihole_dir.expanduser().resolve()
    artifact = args.artifact.expanduser().resolve()
    if not source.exists():
        parser.error("--pihole-dir does not exist")
    if artifact.exists() and artifact.is_dir():
        parser.error("--artifact must be a file path")

    manifest = args.manifest.expanduser().resolve() if args.manifest else None
    if manifest is not None and (not source.is_dir() or not manifest.is_file()):
        parser.error("--manifest requires a source directory and readable manifest")

    selection = runner.DetectorSelection(
        {"dnsblock": dnsblock},
        ["dnsblock"],
        {},
        vocab={"dnsblock": {}},
    )
    effective_config = {
        "sigwood": {
            "root": "",
            "warn_above": 0,
            "default_window": args.window,
        }
    }
    if private_request is not None:
        request = private_request.expanduser().resolve()
        if not request.is_file():
            parser.error("the private request must name a readable JSON file")
        with _selected_source(source, manifest) as (selected_source, corpus_facts):
            try:
                calibration_vector = dnsblock.DnsblockCalibrationVector(
                    arrival_days=args.arrival_days,
                    arrival_history=args.arrival_history,
                    burst_absolute=args.burst_absolute,
                    burst_multiple=args.burst_multiple,
                    burst_active=args.burst_active,
                    burst_enabled=not args.burst_disabled,
                )
            except ValueError as exc:
                parser.error(str(exc))
            if args.series_request is not None:
                return _run_series(
                    selected_source=selected_source,
                    artifact=artifact,
                    request=request,
                    effective_config=effective_config,
                    corpus_facts=corpus_facts,
                    calibration_vector=calibration_vector,
                    batch_size=args.series_batch_size,
                    co_load=args.co_load,
                )
            return _run_batch(
                selected_source=selected_source,
                artifact=artifact,
                request=request,
                effective_config=effective_config,
                corpus_facts=corpus_facts,
                calibration_vector=calibration_vector,
                co_load=args.co_load,
            )
    if (
        args.arrival_days != dnsblock.ARRIVAL_DAYS
        or args.arrival_history != dnsblock.ARRIVAL_HISTORY
        or args.burst_absolute != dnsblock.BURST_ABS
        or args.burst_multiple != dnsblock.BURST_MULT
        or args.burst_active != dnsblock.BURST_ACTIVE
        or args.burst_disabled
        or args.co_load != 1
    ):
        parser.error("private calibration vectors require a batch or series request")
    if not args.internal_legacy:
        legacy_deadline_seconds = _batch_watchdog_seconds(1)
        root = Path(__file__).resolve().parents[1]
        child_argv = (
            str(Path(sys.executable).absolute()),
            str(Path(__file__).resolve()),
            *original_argv,
            "--internal-legacy",
        )
        environment = {
            "HOME": str(Path.home()),
            "LC_ALL": "C.UTF-8",
            "PATH": os.defpath,
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": str(root),
            "TZ": "UTC",
        }
        process = subprocess.Popen(
            child_argv,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            try:
                return process.wait(timeout=legacy_deadline_seconds)
            except subprocess.TimeoutExpired:
                _terminate_worker_group(process)
                try:
                    artifact.unlink()
                except FileNotFoundError:
                    pass
                _atomic_json(
                    artifact.with_suffix(artifact.suffix + ".timeout.json"),
                    {
                        "schema_version": 1,
                        "watchdog_enforced": True,
                        "failure": "legacy_watchdog_timeout",
                        "batch_ordinal": 0,
                        "per_window_watchdog_seconds": (
                            _PER_WINDOW_WATCHDOG_SECONDS
                        ),
                        "batch_window_count": 1,
                        "batch_deadline_seconds": legacy_deadline_seconds,
                    },
                )
                return 124
        finally:
            if process.poll() is None:
                _terminate_worker_group(process)
    with tempfile.TemporaryDirectory(prefix="dnsblock-u4-evidence-") as evidence_dir:
        evidence_path = Path(evidence_dir) / "aggregate.json"
        with _selected_source(source, manifest) as (selected_source, corpus_facts):
            started = time.monotonic()
            # The harness proves the real Reporter path but never persists or echoes
            # estate identities.  The runner writes a private provisional aggregate;
            # only grammar-validated notes may reach the requested final artifact.
            json_capture = _BoundedTextCapture() if args.output_format == "json" else None
            with open(os.devnull, "w", encoding="utf-8") as report_sink, redirect_stdout(
                json_capture if json_capture is not None else report_sink
            ):
                rc = runner.run(
                    config=effective_config,
                    detect="dnsblock",
                    pihole_dir=selected_source,
                    since=args.since,
                    until=args.until,
                    output_format=args.output_format,
                    no_allowlist=args.no_allowlist,
                    load_all=args.load_all,
                    skip_confirm=True,
                    scope=frozenset({"pihole_dir"}),
                    quiet=True,
                    use_utc=True,
                    _detector_selection=selection,
                    _dnsblock_preflight_path=evidence_path,
                    invocation="dnsblock-c1-harness",
                )
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        _validate_summary_notes(payload)
        rendered_digest = None
        rendered_summary = None
        if json_capture is not None:
            rendered_payload = json.loads(json_capture.getvalue())
            rendered_digest = semantic_digest(rendered_payload)
            rendered_summary = canonical_semantic_payload(rendered_payload)[
                "run_summary"
            ]
    elapsed = time.monotonic() - started
    peak_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform != "darwin":
        peak_rss *= 1024
    if args.mixed_baseline_rss is None:
        rss_green = peak_rss <= _FOLD_RSS_GREEN
        rss_bar = {"kind": "fold_absolute", "limit_bytes": _FOLD_RSS_GREEN}
    else:
        rss_green = peak_rss <= args.mixed_baseline_rss + _MIXED_INCREMENT_GREEN
        rss_bar = {
            "kind": "mixed_incremental",
            "baseline_bytes": args.mixed_baseline_rss,
            "increment_limit_bytes": _MIXED_INCREMENT_GREEN,
        }
    lane = payload["preflight"]["coverage_lane"]
    payload["harness"] = {
        "runner_exit_code": rc,
        "elapsed_seconds": elapsed,
        "peak_process_rss_bytes": peak_rss,
        "rss_green": rss_green,
        "rss_bar": rss_bar,
        "wall_green": elapsed <= _WALL_GREEN_SECONDS,
        "wall_limit_seconds": _WALL_GREEN_SECONDS,
        "watchdog_rss_bytes": _WATCHDOG_RSS,
        "watchdog_seconds": _PER_WINDOW_WATCHDOG_SECONDS,
        "watchdog_enforced": True,
        "per_window_watchdog_seconds": _PER_WINDOW_WATCHDOG_SECONDS,
        "batch_deadline_seconds": _batch_watchdog_seconds(1),
        "co_load": 1,
        "source_head": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip(),
        "config_sha256": hashlib.sha256(
            json.dumps(effective_config, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "corpus": corpus_facts,
        "strong_corpus_recommendation": (
            "retain_manifest_backed_captures"
            if lane == "strong"
            else "reexport_retained_upstream_data_with_manifests_or_keep_strong_channels_dormant"
        ),
    }
    if rendered_digest is not None:
        payload["harness"]["semantic_digest"] = rendered_digest
        payload["harness"]["semantic_summary"] = rendered_summary
    _atomic_json(artifact, payload)
    if rc != 0:
        return rc
    if payload["preflight"]["state"] != "READY":
        return 3
    if not rss_green or elapsed > _WALL_GREEN_SECONDS:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
