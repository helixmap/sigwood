#!/usr/bin/env python3
"""Run the preregistered authentication measurement unit.

This is a development instrument, not a sigwood product surface.  It keeps
private source material and adjudication worksheets in an outside-repository
bundle and emits only aggregate, hash-pinned receipts.  Every phase fails
closed when its prerequisites or frozen inputs do not match.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
import random
import re
import resource
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

import pandas as pd

from sigwood.common import loader
from sigwood.detectors import syslog as syslog_detector
from sigwood.parsers import auth as auth_parser
from sigwood.parsers import syslog as syslog_parser
from sigwood.parsers.auth import AuthDecision, AuthOutcome, extract_decision
from sigwood.parsers.syslog import parse_line, parse_timestamp, strip_program


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHARTER = (
    REPO_ROOT
    / "private"
    / "credible"
    / "AUTH-MEASUREMENT-CHARTER-2026-08-05-rev7-FROZEN.md"
)
FROZEN_CHARTER_SHA256 = (
    "67350330acd2f477cdaa1eb2d169ebcb01bd8e2a4c678c2f0cff58858b3aace3"
)
FROZEN_PARSER_SHA256 = (
    "75392f22c7dd5b471df3c6e428782cb31a6a57aeefbc45dedc3fe21cc8fba0de"
)
SCHEMA_VERSION = 1
SAMPLE_SEED = 20260804
SAMPLE_MAX = 200
SMALL_STRATUM = 30
WINDOW_SECONDS = 7 * 86400.0
WINDOW_STEP_SECONDS = 86400.0
MAX_SLIDING_WINDOWS = 20
EVALUABLE_DECISIONS = 500
CONCENTRATION_FLOOR = 100
LANDING_RUN_FLOOR = 6
FANOUT_SOURCE_FLOOR = 5
FANOUT_ACCOUNT_FLOOR = 5
F7_LIMIT = 25
B4_RATIO_LIMIT = 3.0
F2_SECONDS = 8 * 60.0
F2_RSS_GIB = 4.0
F3_SECONDS = 60.0
F3_RSS_GIB = 1.0

TAXONOMY_CLASSES = frozenset({"COUNT", "ENRICH", "INELIGIBLE"})
CORPUS_IDS = ("estate", "openssh", "linux")


class MeasurementError(RuntimeError):
    """A bounded failure that is safe to show without source details."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Suppress caller-controlled paths from argparse diagnostics."""

    def error(self, message: str) -> None:
        del message
        self.exit(2, "measure-auth: invalid arguments\n")


RecordId = tuple[str, str, int]
EpisodeKey = tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CanonicalRow:
    """One loader-equivalent row with its frozen physical identity."""

    record_id: RecordId
    ts: float
    host: str
    program: str
    raw: str
    message: str


@dataclass(frozen=True, slots=True)
class DecisionRow:
    """Compact eligible decision used by the three measurement lenses."""

    record_id: RecordId
    ts: float
    host: str
    gate: str
    outcome: str
    actor_namespace: str | None
    actor: str | None
    target: str | None
    source: str | None


@dataclass(frozen=True, slots=True)
class Window:
    start: float
    end: float
    right_closed: bool = False

    def contains(self, ts: float) -> bool:
        return self.start <= ts <= self.end if self.right_closed else self.start <= ts < self.end


@dataclass(frozen=True, slots=True)
class LensResult:
    concentration_keys: frozenset[EpisodeKey]
    concentration_near_miss: int
    landing_keys: frozenset[EpisodeKey]
    landing_transitions: tuple[dict[str, Any], ...]
    landing_tie_unresolved: int
    fanout_entities: frozenset[tuple[str, tuple[str, ...]]]
    fanout_source_near_miss: int
    fanout_account_near_miss: int
    eligible_count: int


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _write_json_exclusive(path: Path, value: Any) -> None:
    _write_exclusive(path, _json_bytes(value))


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeError, TypeError, ValueError) as exc:
        raise MeasurementError("a required private state file is unreadable") from exc


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        return False
    return True


def _require_private_bundle_path(path: Path) -> Path:
    resolved = path.resolve()
    if _inside_repo(resolved):
        raise MeasurementError("the private bundle must be outside the repository")
    return resolved


def _receipt_path(bundle: Path, name: str) -> Path:
    return bundle / "receipts" / f"{name}.json"


def _write_receipt(bundle: Path, name: str, payload: Mapping[str, Any]) -> str:
    body = {
        "schema": SCHEMA_VERSION,
        "phase": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    path = _receipt_path(bundle, name)
    _write_json_exclusive(path, body)
    digest = _sha256_path(path)
    _write_exclusive(path.with_suffix(".sha256"), (digest + "\n").encode())
    return digest


def _read_receipt(bundle: Path, name: str) -> dict[str, Any]:
    path = _receipt_path(bundle, name)
    receipt = _read_json(path)
    if not isinstance(receipt, dict) or receipt.get("phase") != name:
        raise MeasurementError("a prerequisite receipt is invalid")
    sidecar = path.with_suffix(".sha256")
    try:
        expected = sidecar.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise MeasurementError("a prerequisite receipt hash is unreadable") from exc
    if expected != _sha256_path(path):
        raise MeasurementError("a prerequisite receipt hash does not match")
    return receipt


def _require_receipts(bundle: Path, *names: str) -> None:
    for name in names:
        _read_receipt(bundle, name)


def _discover_corpus_files(root: Path) -> list[tuple[str, Path]]:
    resolved = root.resolve()
    if resolved.is_file():
        return [(resolved.name, resolved)]
    if not resolved.is_dir():
        raise MeasurementError("a declared corpus is unavailable")
    rows: list[tuple[str, Path]] = []
    try:
        candidates = sorted(resolved.rglob("*"))
    except OSError as exc:
        raise MeasurementError("a declared corpus cannot be listed") from exc
    for candidate in candidates:
        if not candidate.is_file() or candidate.name.startswith("._"):
            continue
        rows.append((candidate.relative_to(resolved).as_posix(), candidate))
    if not rows:
        raise MeasurementError("a declared corpus has no files")
    return rows


def _corpus_entry(root: Path | Sequence[Path]) -> dict[str, Any]:
    if isinstance(root, Path):
        discovered = _discover_corpus_files(root)
        root_value = root.resolve()
    else:
        explicit = sorted(path.resolve() for path in root)
        if not explicit or not all(path.is_file() for path in explicit):
            raise MeasurementError("an explicit corpus file set is invalid")
        common = Path(os.path.commonpath([str(path.parent) for path in explicit]))
        discovered = [
            (path.relative_to(common).as_posix(), path) for path in explicit
        ]
        if len({relative for relative, _path in discovered}) != len(discovered):
            raise MeasurementError("an explicit corpus file set has duplicate identities")
        root_value = common
    files = []
    for relative_path, path in discovered:
        try:
            stat = path.stat()
        except OSError as exc:
            raise MeasurementError("a declared corpus file is unreadable") from exc
        files.append(
            {
                "relative_path": relative_path,
                "path": str(path.resolve()),
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "sha256": _sha256_path(path),
            }
        )
    dates: list[date] = []
    for entry in files:
        match = re.search(r"(?<!\d)(\d{8})(?!\d)", entry["relative_path"])
        if match is None:
            dates = []
            break
        try:
            dates.append(datetime.strptime(match.group(1), "%Y%m%d").date())
        except ValueError:
            dates = []
            break
    calendar_coverage = None
    if len(dates) == len(files) and len(set(dates)) == len(dates):
        ordered_dates = sorted(dates)
        missing_runs = [
            (later - earlier).days - 1
            for earlier, later in zip(ordered_dates, ordered_dates[1:])
            if (later - earlier).days > 1
        ]
        calendar_coverage = {
            "daily_files": len(ordered_dates),
            "first_date": ordered_dates[0].isoformat(),
            "last_date": ordered_dates[-1].isoformat(),
            "calendar_days": (ordered_dates[-1] - ordered_dates[0]).days + 1,
            "missing_days": sum(missing_runs),
            "missing_runs": missing_runs,
            "longest_gap_days": max(missing_runs, default=0),
        }
    return {
        "root": str(root_value),
        "files": files,
        "calendar_coverage": calendar_coverage,
    }


def init_bundle(
    bundle: Path,
    *,
    charter: Path,
    estate: Path | Sequence[Path],
    openssh: Path,
    linux: Path,
) -> dict[str, Any]:
    """Create one immutable run manifest after hashing all declared inputs."""
    resolved = _require_private_bundle_path(bundle)
    if resolved.exists():
        raise MeasurementError("the private bundle target must be new")
    try:
        resolved.mkdir(mode=0o700, parents=False)
        (resolved / "receipts").mkdir(mode=0o700)
        (resolved / "raw").mkdir(mode=0o700)
    except OSError as exc:
        raise MeasurementError("the private bundle could not be created") from exc
    os.chmod(resolved, 0o700)
    charter_path = charter.resolve()
    charter_hash = _sha256_path(charter_path)
    if charter_hash != FROZEN_CHARTER_SHA256:
        raise MeasurementError("the frozen charter hash does not match")
    parser_path = Path(auth_parser.__file__).resolve()
    parser_hash = _sha256_path(parser_path)
    if parser_hash != FROZEN_PARSER_SHA256:
        raise MeasurementError("the frozen authentication parser hash does not match")
    manifest = {
        "schema": SCHEMA_VERSION,
        "charter": {"path": str(charter_path), "sha256": charter_hash},
        "tool": {"path": str(Path(__file__).resolve()), "sha256": _sha256_path(Path(__file__))},
        "parser": {
            "path": str(parser_path),
            "sha256": parser_hash,
        },
        "corpora": {
            "estate": _corpus_entry(estate),
            "openssh": _corpus_entry(openssh),
            "linux": _corpus_entry(linux),
        },
    }
    _write_json_exclusive(resolved / "manifest.json", manifest)
    manifest_hash = _sha256_path(resolved / "manifest.json")
    _write_exclusive(resolved / "manifest.sha256", (manifest_hash + "\n").encode())
    _write_receipt(resolved, "init", {"manifest_sha256": manifest_hash})
    return manifest


def _load_bundle(bundle: Path, *, verify_parser: bool = True) -> tuple[Path, dict[str, Any]]:
    resolved = _require_private_bundle_path(bundle)
    manifest_path = resolved / "manifest.json"
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA_VERSION:
        raise MeasurementError("the private bundle manifest is invalid")
    try:
        expected = (resolved / "manifest.sha256").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise MeasurementError("the private bundle manifest hash is unreadable") from exc
    if expected != _sha256_path(manifest_path):
        raise MeasurementError("the private bundle manifest hash does not match")
    if manifest["charter"]["sha256"] != FROZEN_CHARTER_SHA256:
        raise MeasurementError("the private bundle names the wrong charter")
    if manifest["parser"]["sha256"] != FROZEN_PARSER_SHA256:
        raise MeasurementError("the private bundle names the wrong authentication parser")
    if _sha256_path(Path(__file__)) != manifest["tool"]["sha256"]:
        raise MeasurementError("the measurement tool hash changed")
    if verify_parser and _sha256_path(Path(auth_parser.__file__)) != manifest["parser"]["sha256"]:
        raise MeasurementError("the authentication parser hash changed")
    for corpus_id in CORPUS_IDS:
        for entry in manifest["corpora"][corpus_id]["files"]:
            path = Path(entry["path"])
            try:
                stat = path.stat()
            except OSError as exc:
                raise MeasurementError("a declared corpus file is unavailable") from exc
            if stat.st_size != entry["size"] or stat.st_mtime_ns != entry["mtime_ns"]:
                raise MeasurementError("a declared corpus fingerprint changed")
    _read_receipt(resolved, "init")
    return resolved, manifest


def _manifest_files(manifest: Mapping[str, Any], corpus_id: str) -> list[tuple[str, Path]]:
    return [
        (entry["relative_path"], Path(entry["path"]))
        for entry in manifest["corpora"][corpus_id]["files"]
    ]


def _iter_physical(
    manifest: Mapping[str, Any], corpus_id: str
) -> Iterator[tuple[RecordId, str, Path]]:
    for relative_path, path in _manifest_files(manifest, corpus_id):
        try:
            with loader._open_log(path) as handle:
                for line_number, line in enumerate(handle, 1):
                    yield (corpus_id, relative_path, line_number), line.rstrip("\n"), path
        except (EOFError, OSError) as exc:
            raise MeasurementError("a declared corpus file could not be read") from exc


@contextmanager
def _frozen_parser_clock(reference_iso: str) -> Iterator[None]:
    """Hold the shipped syslog parser at the boundary's clock for one scan."""
    reference = datetime.fromisoformat(reference_iso)
    original = syslog_parser.datetime

    class FrozenParserDatetime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN001
            value = cls(
                reference.year,
                reference.month,
                reference.day,
                reference.hour,
                reference.minute,
                reference.second,
                reference.microsecond,
            )
            return value.replace(tzinfo=tz) if tz is not None else value

    syslog_parser.datetime = FrozenParserDatetime
    try:
        yield
    finally:
        syslog_parser.datetime = original


BOUNDARY_BASELINE_FIELDS = (
    "physical_rows",
    "unassignable_timestamps",
    "calibration_rows",
    "t_first_epoch",
    "t_mid_epoch",
    "t_last_epoch",
)


def _load_boundary_baseline(path: Path) -> tuple[dict[str, Any], str]:
    resolved = path.resolve()
    if _inside_repo(resolved):
        raise MeasurementError("the boundary baseline must remain outside the repository")
    baseline = _read_json(resolved)
    if not isinstance(baseline, dict) or baseline.get("schema") != SCHEMA_VERSION:
        raise MeasurementError("the boundary baseline is invalid")
    if set(BOUNDARY_BASELINE_FIELDS) - set(baseline):
        raise MeasurementError("the boundary baseline is incomplete")
    return baseline, _sha256_path(resolved)


def compute_boundary(
    bundle: Path, *, expected_baseline: Path | None = None
) -> dict[str, Any]:
    """Hash-pin the yearless-parser boundary without inspecting line content."""
    resolved, manifest = _load_bundle(bundle)
    if _receipt_path(resolved, "boundary").exists():
        raise MeasurementError("the boundary phase is already complete")
    first: datetime | None = None
    last: datetime | None = None
    physical_rows = 0
    unassignable = 0
    timestamps: list[float] = []
    timestamp_reference = syslog_parser.datetime.now().isoformat()
    with _frozen_parser_clock(timestamp_reference):
        for _record_id, raw, _path in _iter_physical(manifest, "openssh"):
            physical_rows += 1
            parsed = parse_timestamp(raw)
            if parsed is None:
                unassignable += 1
                continue
            timestamps.append(parsed.timestamp())
            first = parsed if first is None or parsed < first else first
            last = parsed if last is None or parsed > last else last
    if unassignable or first is None or last is None or first > last:
        _write_receipt(
            resolved,
            "boundary-divergence",
            {"physical_rows": physical_rows, "unassignable_timestamps": unassignable},
        )
        raise MeasurementError("OpenSSH contains unassignable timestamps")
    midpoint = first + (last - first) / 2
    midpoint_epoch = midpoint.timestamp()
    payload = {
        "physical_rows": physical_rows,
        "unassignable_timestamps": 0,
        "calibration_rows": sum(timestamp < midpoint_epoch for timestamp in timestamps),
        "t_first": first.isoformat(),
        "t_mid": midpoint.isoformat(),
        "t_last": last.isoformat(),
        "t_first_epoch": first.timestamp(),
        "t_mid_epoch": midpoint_epoch,
        "t_last_epoch": last.timestamp(),
        "timestamp_reference_local": timestamp_reference,
        "timestamp_parser_sha256": _sha256_path(Path(auth_parser.__file__).parent / "syslog.py"),
    }
    if expected_baseline is not None:
        baseline, baseline_hash = _load_boundary_baseline(expected_baseline)
        mismatches = [
            field
            for field in BOUNDARY_BASELINE_FIELDS
            if payload[field] != baseline[field]
        ]
        assertion = {
            "verdict": "PASS" if not mismatches else "FAIL",
            "baseline_sha256": baseline_hash,
            "fields": list(BOUNDARY_BASELINE_FIELDS),
            "mismatches": mismatches,
        }
        payload["baseline_assertion"] = assertion
        if mismatches:
            _write_receipt(resolved, "boundary-divergence", assertion)
            raise MeasurementError("the boundary baseline assertion failed")
    _write_receipt(resolved, "boundary", payload)
    return payload


def _canonical_from_raw(
    record_id: RecordId,
    raw: str,
    path: Path,
) -> CanonicalRow | None:
    parsed = parse_line(raw)
    if parsed is None:
        return None
    timestamp = parsed["ts"]
    host = parsed["host"]
    if host == "unknown":
        host = loader._stem_hostname(path.name)
    return CanonicalRow(
        record_id=record_id,
        ts=timestamp.timestamp() if timestamp is not None else float("nan"),
        host=host,
        program=parsed["program"],
        raw=parsed["raw"],
        message=parsed["message"],
    )


def iter_canonical_rows(
    manifest: Mapping[str, Any],
    corpus_id: str,
    *,
    boundary: Mapping[str, Any] | None = None,
    openssh_scope: str = "calibration",
) -> Iterator[CanonicalRow]:
    """Yield loader-equivalent rows, sealing OpenSSH before content parsing."""
    if corpus_id == "openssh" and boundary is None:
        raise MeasurementError("the OpenSSH boundary receipt is required")
    clock = (
        _frozen_parser_clock(str(boundary["timestamp_reference_local"]))
        if boundary is not None
        else nullcontext()
    )
    with clock:
        for record_id, raw, path in _iter_physical(manifest, corpus_id):
            if corpus_id == "openssh":
                timestamp = parse_timestamp(raw)
                if timestamp is None:
                    raise MeasurementError("OpenSSH contains an unassignable timestamp")
                epoch = timestamp.timestamp()
                midpoint = float(boundary["t_mid_epoch"])
                if openssh_scope == "calibration" and epoch >= midpoint:
                    continue
                if openssh_scope == "validation" and epoch < midpoint:
                    continue
                if openssh_scope not in {"calibration", "validation", "full"}:
                    raise MeasurementError("the OpenSSH scope is invalid")
            row = _canonical_from_raw(record_id, raw, path)
            if row is not None:
                yield row


def _program_arm(program: str) -> str:
    if program == "unknown":
        return "unknown"
    if auth_parser.is_recognized_program(program):
        return program
    return "other-tag"


def classify_structure(row: CanonicalRow) -> tuple[str, str]:
    """Return one total structural dialect/record-type assignment."""
    body = strip_program(row.message)
    audit_a = auth_parser._AUDIT_A_HEAD_RE.match(body)
    if audit_a is not None:
        return "audisp-type", audit_a.group("audit_type")
    audit_b = auth_parser._AUDIT_B_HEAD_RE.match(body)
    if audit_b is not None:
        return "audit-typeless", audit_b.group("audit_type")
    dropbear_types = (
        ("success", auth_parser._DROPBEAR_SUCCESS_RE),
        ("exit-before-auth", auth_parser._DROPBEAR_EXIT_RE),
        ("child", auth_parser._DROPBEAR_CHILD_RE),
    )
    for record_type, pattern in dropbear_types:
        if pattern.fullmatch(body):
            return "dropbear-text", record_type
    if row.program == "dropbear":
        return "dropbear-text", "other"
    if row.program == "sshd(pam_unix)":
        if auth_parser._LEGACY_PAM_MORE_RE.fullmatch(body):
            return "pam-text", "authentication-failure-summary"
        if auth_parser._LEGACY_PAM_AUTH_RE.fullmatch(body):
            return "pam-text", "authentication-failure"
        return "pam-text", "other"
    sshd_types = (
        ("accepted", auth_parser._SSH_ACCEPT_RE),
        ("failed-invalid-user", auth_parser._SSH_FAILED_INVALID_RE),
        ("failed-password", auth_parser._SSH_FAILED_RE),
        ("invalid-user", auth_parser._SSH_INVALID_RE),
        ("maximum-attempts", auth_parser._SSH_MAX_ATTEMPTS_RE),
        ("connection-closed", auth_parser._SSH_CLOSED_RE),
        ("kex-closed", auth_parser._SSH_KEX_RE),
    )
    for record_type, pattern in sshd_types:
        if pattern.fullmatch(body):
            return "sshd-text", record_type
    if row.program in {"sshd", "sshd-session"}:
        if row.program == "sshd" and auth_parser._MODERN_PAM_MORE_RE.fullmatch(body):
            return "pam-text", "authentication-failure-summary"
        if auth_parser._PAM_AUTH_RE.fullmatch(body):
            return "pam-text", "authentication-failure"
        return "sshd-text", "other"
    pam_session = auth_parser._PAM_SESSION_RE.fullmatch(body)
    if pam_session is not None:
        return "pam-text", f"session-{pam_session.group('state')}"
    if auth_parser._PAM_AUTH_RE.fullmatch(body):
        return "pam-text", "authentication-failure"
    sudo = auth_parser._SUDO_PREFIX_RE.fullmatch(body)
    if sudo is not None:
        preamble, values = auth_parser._semicolon_fields(sudo.group("body"))
        if preamble == "user NOT in sudoers" or auth_parser._SUDO_PASSWORD_RE.fullmatch(
            preamble
        ):
            return "pam-text", "sudo-denial"
        if "USER" in values and "COMMAND" in values:
            return "pam-text", "sudo-grant"
    if row.program == "su" and auth_parser._SU_GRANT_RE.fullmatch(body):
        return "pam-text", "su-grant"
    if auth_parser._FAILED_SU_RE.fullmatch(body):
        return "pam-text", "failed-su"
    if row.program == "--" and auth_parser._ROOT_LOGIN_RE.fullmatch(body):
        return "pam-text", "root-login-grant"
    if row.program in {
        "sudo",
        "su",
        "runuser",
        "kscreenlocker_greet",
        "gdm-password]",
    }:
        return "pam-text", "other"
    return "unclassified/non-auth", "other"


def _inventory_key(
    corpus_id: str, row: CanonicalRow
) -> tuple[str, str, str, str]:
    dialect, record_type = classify_structure(row)
    return corpus_id, _program_arm(row.program), dialect, record_type


def taxonomy_inventory(bundle: Path) -> dict[str, Any]:
    """Inventory every structural type without running an auth lens."""
    resolved, manifest = _load_bundle(bundle)
    boundary = _read_receipt(resolved, "boundary")
    if _receipt_path(resolved, "taxonomy-inventory").exists():
        raise MeasurementError("the taxonomy inventory phase is already complete")
    counts: Counter[tuple[str, str, str, str]] = Counter()
    examples: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for corpus_id in CORPUS_IDS:
        scope = "calibration" if corpus_id == "openssh" else "full"
        for row in iter_canonical_rows(
            manifest, corpus_id, boundary=boundary, openssh_scope=scope
        ):
            key = _inventory_key(corpus_id, row)
            counts[key] += 1
            if len(examples[key]) < 3:
                examples[key].append(
                    {
                        "record_id": list(row.record_id),
                        "program": row.program,
                        "raw": row.raw,
                        "message": row.message,
                    }
                )
    example_rows = []
    for key in sorted(examples):
        corpus_id, arm, dialect, record_type = key
        for example in examples[key]:
            example_rows.append(
                json.dumps(
                    {
                        "corpus": corpus_id,
                        "program_arm": arm,
                        "dialect": dialect,
                        "record_type": record_type,
                        **example,
                    },
                    sort_keys=True,
                )
            )
    examples_path = resolved / "raw" / "taxonomy-examples.jsonl"
    _write_exclusive(examples_path, (("\n".join(example_rows) + "\n") if example_rows else "").encode())
    table = [
        {
            "corpus": corpus_id,
            "program_arm": arm,
            "dialect": dialect,
            "record_type": record_type,
            "rows": count,
        }
        for (corpus_id, arm, dialect, record_type), count in sorted(counts.items())
    ]
    payload = {
        "rows": sum(counts.values()),
        "table": table,
        "examples_sha256": _sha256_path(examples_path),
        "observed_type_count": len({(key[2], key[3]) for key in counts}),
    }
    receipt_hash = _write_receipt(resolved, "taxonomy-inventory", payload)
    payload["receipt_sha256"] = receipt_hash
    return payload


def _taxonomy_pair(dialect: str, record_type: str) -> str:
    return f"{dialect}\x1f{record_type}"


def _load_taxonomy_declaration(
    path: Path,
    *,
    inventory_receipt_sha256: str,
    observed_pairs: set[tuple[str, str]],
) -> tuple[dict[str, str], list[dict[str, Any]], list[dict[str, str]], str]:
    resolved = path.resolve()
    if _inside_repo(resolved):
        raise MeasurementError("the taxonomy declaration must remain outside the repository")
    declaration = _read_json(resolved)
    if not isinstance(declaration, dict) or declaration.get("schema") != SCHEMA_VERSION:
        raise MeasurementError("the taxonomy declaration is invalid")
    if declaration.get("inventory_receipt_sha256") != inventory_receipt_sha256:
        raise MeasurementError("the taxonomy declaration names the wrong inventory")
    entries = declaration.get("record_types")
    edges = declaration.get("enrich_edges", [])
    rationale_notes = declaration.get("rationale_notes", [])
    if (
        not isinstance(entries, list)
        or not isinstance(edges, list)
        or not isinstance(rationale_notes, list)
    ):
        raise MeasurementError("the taxonomy declaration is invalid")
    validated_notes: list[dict[str, str]] = []
    note_ids: set[str] = set()
    for note in rationale_notes:
        if not isinstance(note, dict):
            raise MeasurementError("the taxonomy declaration has an invalid rationale")
        note_id = note.get("id")
        text = note.get("text")
        if (
            not isinstance(note_id, str)
            or re.fullmatch(r"[a-z0-9-]+", note_id) is None
            or note_id in note_ids
            or not isinstance(text, str)
            or not text
            or len(text) > 1000
            or "\n" in text
        ):
            raise MeasurementError("the taxonomy declaration has an invalid rationale")
        note_ids.add(note_id)
        validated_notes.append({"id": note_id, "text": text})
    classifications: dict[str, str] = {}
    declared_pairs: set[tuple[str, str]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise MeasurementError("the taxonomy declaration is invalid")
        dialect = entry.get("dialect")
        record_type = entry.get("record_type")
        classification = entry.get("class")
        if (
            not isinstance(dialect, str)
            or not isinstance(record_type, str)
            or classification not in TAXONOMY_CLASSES
        ):
            raise MeasurementError("the taxonomy declaration is invalid")
        pair = (dialect, record_type)
        if pair in declared_pairs:
            raise MeasurementError("the taxonomy declaration contains a duplicate type")
        declared_pairs.add(pair)
        classifications[_taxonomy_pair(*pair)] = classification
    if declared_pairs != observed_pairs:
        raise MeasurementError("the taxonomy declaration is not total and exact")
    enrich_edge_pairs: list[str] = []
    for edge in edges:
        if not isinstance(edge, dict):
            raise MeasurementError("the taxonomy declaration has an invalid edge")
        count_pair = edge.get("count")
        enrich_pair = edge.get("enrich")
        fields = edge.get("key")
        if (
            not isinstance(count_pair, dict)
            or not isinstance(enrich_pair, dict)
            or not isinstance(fields, list)
            or not fields
            or not all(isinstance(field, str) and field for field in fields)
        ):
            raise MeasurementError("the taxonomy declaration has an invalid edge")
        count_key = _taxonomy_pair(
            str(count_pair.get("dialect")), str(count_pair.get("record_type"))
        )
        enrich_key = _taxonomy_pair(
            str(enrich_pair.get("dialect")), str(enrich_pair.get("record_type"))
        )
        if classifications.get(count_key) != "COUNT" or classifications.get(enrich_key) != "ENRICH":
            raise MeasurementError("an ENRICH edge contradicts the declared direction")
        enrich_edge_pairs.append(enrich_key)
    declared_enrich = {
        key for key, classification in classifications.items() if classification == "ENRICH"
    }
    if set(enrich_edge_pairs) != declared_enrich or len(enrich_edge_pairs) != len(
        set(enrich_edge_pairs)
    ):
        raise MeasurementError("every ENRICH type must own exactly one declared edge")
    return classifications, edges, validated_notes, _sha256_path(resolved)


_FIELD = re.compile(
    r"(?<!\S)(?P<key>[A-Za-z_][\w-]*)=(?P<value>\"[^\"]*\"|'[^']*'|\S*)"
)


def _clean_field(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _structural_fields(row: CanonicalRow) -> dict[str, str]:
    body = strip_program(row.message)
    fields = {
        match.group("key"): _clean_field(match.group("value"))
        for match in _FIELD.finditer(body)
    }
    audit_fields, audit_serial = auth_parser._audit_fields(body)
    fields.update(
        {key: _clean_field(value) for key, value in audit_fields.items() if value}
    )
    if audit_serial is not None:
        fields["serial"] = audit_serial
    if "session" not in fields and fields.get("ses"):
        fields["session"] = fields["ses"]
    fields["host"] = row.host.casefold()
    fields["program"] = row.program
    decision = extract_decision(row.message, program=row.program)
    if decision is not None:
        for name in (
            "actor",
            "actor_namespace",
            "target",
            "source",
            "auid",
            "terminal",
            "exe",
            "audit_type",
            "res",
            "session",
            "serial",
        ):
            value = getattr(decision, name)
            if value is not None:
                fields[name] = str(value)
    return fields


def _edge_pair(edge: Mapping[str, Any], side: str) -> str:
    value = edge[side]
    return _taxonomy_pair(str(value["dialect"]), str(value["record_type"]))


def _edge_metrics(
    count_rows: Sequence[Mapping[str, str]],
    enrich_rows: Sequence[Mapping[str, str]],
    fields: Sequence[str],
) -> dict[str, Any]:
    def key_for(values: Mapping[str, str]) -> tuple[str, ...] | None:
        if any(not values.get(field) for field in fields):
            return None
        return tuple(values[field] for field in fields)

    count_keys: dict[tuple[str, ...], list[Mapping[str, str]]] = defaultdict(list)
    present_count = 0
    for values in count_rows:
        key = key_for(values)
        if key is not None:
            present_count += 1
            count_keys[key].append(values)
    present_enrich = 0
    unmatched = 0
    collide = 0
    contradict = 0
    identity_fields = ("actor", "target", "source")
    for values in enrich_rows:
        key = key_for(values)
        if key is None:
            continue
        present_enrich += 1
        matches = count_keys.get(key, [])
        if not matches:
            unmatched += 1
        elif len(matches) >= 2:
            collide += 1
        elif any(
            values.get(field)
            and matches[0].get(field)
            and values[field] != matches[0][field]
            for field in identity_fields
        ):
            contradict += 1
    count_total = len(count_rows)
    enrich_total = len(enrich_rows)
    if count_total == 0 and enrich_total == 0:
        return {
            "count_rows": 0,
            "enrich_rows": 0,
            "present_count_rows": 0,
            "present_enrich_rows": 0,
            "present_count_rate": None,
            "present_enrich_rate": None,
            "unmatched_rows": 0,
            "collide_rows": 0,
            "contradict_rows": 0,
            "defect_rate": None,
            "verdict": "ABSENT",
        }
    defect_rows = unmatched + collide + contradict
    present_count_rate = present_count / count_total if count_total else None
    present_enrich_rate = present_enrich / enrich_total if enrich_total else None
    defect_rate = defect_rows / present_enrich if present_enrich else None
    passes = (
        present_count_rate is not None
        and present_enrich_rate is not None
        and defect_rate is not None
        and present_count_rate >= 0.99
        and present_enrich_rate >= 0.99
        and defect_rate <= 0.005
    )
    return {
        "count_rows": count_total,
        "enrich_rows": enrich_total,
        "present_count_rows": present_count,
        "present_enrich_rows": present_enrich,
        "present_count_rate": present_count_rate,
        "present_enrich_rate": present_enrich_rate,
        "unmatched_rows": unmatched,
        "collide_rows": collide,
        "contradict_rows": contradict,
        "defect_rate": defect_rate,
        "verdict": "PASS" if passes else "FAIL",
    }


def taxonomy_evaluate(bundle: Path, declaration_path: Path) -> dict[str, Any]:
    """Evaluate declared ENRICH directions only after the declaration exists."""
    resolved, manifest = _load_bundle(bundle)
    boundary = _read_receipt(resolved, "boundary")
    inventory = _read_receipt(resolved, "taxonomy-inventory")
    if _receipt_path(resolved, "taxonomy-evaluate").exists():
        raise MeasurementError("the taxonomy evaluation phase is already complete")
    observed_pairs = {
        (entry["dialect"], entry["record_type"]) for entry in inventory["table"]
    }
    inventory_hash = _sha256_path(_receipt_path(resolved, "taxonomy-inventory"))
    classifications, edges, rationale_notes, taxonomy_hash = _load_taxonomy_declaration(
        declaration_path,
        inventory_receipt_sha256=inventory_hash,
        observed_pairs=observed_pairs,
    )
    pair_targets: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for edge_number, edge in enumerate(edges, 1):
        pair_targets[_edge_pair(edge, "count")].append((edge_number, "count"))
        pair_targets[_edge_pair(edge, "enrich")].append((edge_number, "enrich"))
    accumulated: dict[tuple[int, str, str], list[Mapping[str, str]]] = defaultdict(list)
    for corpus_id in CORPUS_IDS:
        scope = "calibration" if corpus_id == "openssh" else "full"
        for row in iter_canonical_rows(
            manifest, corpus_id, boundary=boundary, openssh_scope=scope
        ):
            dialect, record_type = classify_structure(row)
            targets = pair_targets.get(_taxonomy_pair(dialect, record_type), ())
            if not targets:
                continue
            values = _structural_fields(row)
            for edge_number, side in targets:
                accumulated[(edge_number, corpus_id, side)].append(values)

    edge_rows: list[dict[str, Any]] = []
    for edge_number, edge in enumerate(edges, 1):
        fields = tuple(edge["key"])
        for corpus_id in CORPUS_IDS:
            count_rows = accumulated[(edge_number, corpus_id, "count")]
            enrich_rows = accumulated[(edge_number, corpus_id, "enrich")]
            edge_rows.append(
                {
                    "edge": edge_number,
                    "corpus": corpus_id,
                    "count": edge["count"],
                    "enrich": edge["enrich"],
                    "key": list(fields),
                    **_edge_metrics(count_rows, enrich_rows, fields),
                }
            )
    failed_edges = {
        row["edge"] for row in edge_rows if row["verdict"] == "FAIL"
    }
    effective_classifications = dict(classifications)
    fallbacks = []
    for edge_number in sorted(failed_edges):
        edge = edges[edge_number - 1]
        enrich_key = _edge_pair(edge, "enrich")
        effective_classifications[enrich_key] = "COUNT"
        fallbacks.append(
            {
                "edge": edge_number,
                "dialect": edge["enrich"]["dialect"],
                "record_type": edge["enrich"]["record_type"],
                "effective_class": "COUNT",
                "reason": "declared ENRICH edge failed its frozen contract",
            }
        )
    payload = {
        "taxonomy_manifest_sha256": taxonomy_hash,
        "inventory_receipt_sha256": inventory_hash,
        "classifications": [
            {
                "dialect": key.split("\x1f", 1)[0],
                "record_type": key.split("\x1f", 1)[1],
                "class": value,
            }
            for key, value in sorted(effective_classifications.items())
        ],
        "declared_classifications": [
            {
                "dialect": key.split("\x1f", 1)[0],
                "record_type": key.split("\x1f", 1)[1],
                "class": value,
            }
            for key, value in sorted(classifications.items())
        ],
        "edge_metrics": edge_rows,
        "count_fallbacks": fallbacks,
        "rationale_notes": rationale_notes,
        "verdict": "PASS",
    }
    _write_receipt(resolved, "taxonomy-evaluate", payload)
    return payload


def _taxonomy_map(receipt: Mapping[str, Any]) -> dict[str, str]:
    return {
        _taxonomy_pair(entry["dialect"], entry["record_type"]): entry["class"]
        for entry in receipt["classifications"]
    }


def accept_taxonomy(bundle: Path, accepted_sha256: str) -> dict[str, Any]:
    """Pin the exact reviewer-accepted taxonomy hash before downstream work."""
    resolved, _manifest = _load_bundle(bundle)
    evaluated = _read_receipt(resolved, "taxonomy-evaluate")
    if evaluated.get("verdict") != "PASS":
        raise MeasurementError("the taxonomy gate did not pass")
    if accepted_sha256 != evaluated.get("taxonomy_manifest_sha256"):
        raise MeasurementError("the accepted taxonomy hash does not match")
    if _receipt_path(resolved, "taxonomy-accepted").exists():
        existing = _read_receipt(resolved, "taxonomy-accepted")
        if existing.get("taxonomy_manifest_sha256") != accepted_sha256:
            raise MeasurementError("a different taxonomy is already accepted")
        return existing
    payload = {"taxonomy_manifest_sha256": accepted_sha256}
    _write_receipt(resolved, "taxonomy-accepted", payload)
    return payload


def _require_accepted_taxonomy(bundle: Path) -> tuple[dict[str, Any], dict[str, str]]:
    evaluated = _read_receipt(bundle, "taxonomy-evaluate")
    accepted = _read_receipt(bundle, "taxonomy-accepted")
    if accepted.get("taxonomy_manifest_sha256") != evaluated.get("taxonomy_manifest_sha256"):
        raise MeasurementError("the accepted taxonomy hash does not match")
    return evaluated, _taxonomy_map(evaluated)


def _decision_row(row: CanonicalRow, taxonomy: Mapping[str, str]) -> DecisionRow | None:
    dialect, record_type = classify_structure(row)
    if taxonomy.get(_taxonomy_pair(dialect, record_type)) != "COUNT":
        return None
    decision = extract_decision(row.message, program=row.program)
    if decision is None or not decision.is_eligible_decision:
        return None
    return DecisionRow(
        record_id=row.record_id,
        ts=row.ts,
        host=row.host.casefold(),
        gate=(
            f"audit:{decision.audit_type}"
            if decision.audit_type is not None
            else decision.gate
        ),
        outcome=decision.outcome.value,
        actor_namespace=decision.actor_namespace,
        actor=decision.actor,
        target=decision.target,
        source=decision.source,
    )


def _namespaced_actor(decision: DecisionRow) -> tuple[str, str] | None:
    if decision.actor is None:
        return None
    return decision.actor_namespace or "unscoped", decision.actor


def episode_key(decision: DecisionRow) -> EpisodeKey | None:
    """Build the exact target-host/service/gate identity edge and degraded forms."""
    host_gate = (decision.host.casefold(), decision.gate)
    actor = _namespaced_actor(decision)
    if actor is not None and decision.source is not None:
        return (*host_gate, "edge", actor[0], actor[1], decision.source)
    if actor is None and decision.source is not None:
        return (*host_gate, "source", decision.source)
    if actor is not None and decision.source is None:
        return (*host_gate, "actor", actor[0], actor[1])
    return None


def _key_fidelity(key: EpisodeKey) -> str:
    return key[2]


def concentration(
    decisions: Sequence[DecisionRow], window: Window
) -> tuple[frozenset[EpisodeKey], int, dict[str, int]]:
    counts: Counter[EpisodeKey] = Counter()
    for decision in decisions:
        if decision.outcome != AuthOutcome.DENIED.value or not window.contains(decision.ts):
            continue
        key = episode_key(decision)
        if key is not None:
            counts[key] += 1
    findings = frozenset(key for key, count in counts.items() if count >= CONCENTRATION_FLOOR)
    near_miss = max(
        (count for count in counts.values() if count < CONCENTRATION_FLOOR),
        default=0,
    )
    fidelity = Counter(_key_fidelity(key) for key in findings)
    return findings, near_miss, dict(sorted(fidelity.items()))


def landing(
    decisions: Sequence[DecisionRow],
    canonical_rows: Sequence[CanonicalRow],
    window: Window,
) -> tuple[frozenset[EpisodeKey], tuple[dict[str, Any], ...], int]:
    """Enumerate ordinal denial-to-grant transitions and fail closed on ties."""
    grouped: dict[EpisodeKey, list[DecisionRow]] = defaultdict(list)
    for decision in decisions:
        if not window.contains(decision.ts):
            continue
        key = episode_key(decision)
        if key is not None:
            grouped[key].append(decision)
    host_times: dict[str, list[float]] = defaultdict(list)
    for row in canonical_rows:
        if window.contains(row.ts):
            host_times[row.host.casefold()].append(row.ts)
    for values in host_times.values():
        values.sort()

    finding_keys: set[EpisodeKey] = set()
    transitions: list[dict[str, Any]] = []
    tie_count = 0
    for key in sorted(grouped):
        ordered = sorted(grouped[key], key=lambda decision: decision.ts)
        denial_run: list[DecisionRow] = []
        for timestamp, batch_iter in itertools.groupby(
            ordered, key=lambda decision: decision.ts
        ):
            batch = list(batch_iter)
            denials = [
                decision
                for decision in batch
                if decision.outcome == AuthOutcome.DENIED.value
            ]
            grants = [
                decision
                for decision in batch
                if decision.outcome == AuthOutcome.GRANTED.value
            ]
            if not grants:
                denial_run.extend(denials)
                continue
            candidate_run = [*denial_run, *denials]
            if len(candidate_run) < LANDING_RUN_FLOOR:
                denial_run = []
                continue
            transition_rows = sorted(
                [*candidate_run, *grants], key=lambda item: item.record_id
            )
            transition_id = hashlib.sha256(
                _json_bytes([list(item.record_id) for item in transition_rows])
            ).hexdigest()[:20]
            record_ids = [list(item.record_id) for item in transition_rows]
            if denials:
                tie_count += 1
                transitions.append(
                    {
                        "transition_id": transition_id,
                        "status": "tie-unresolved",
                        "run_length": len(candidate_run),
                        "cessation": False,
                        "record_ids": record_ids,
                    }
                )
                denial_run = []
                continue
            finding_keys.add(key)
            later_key_denial = any(
                later.outcome == AuthOutcome.DENIED.value and later.ts > timestamp
                for later in ordered
            )
            later_host_row = any(
                ts > timestamp
                for ts in host_times.get(grants[0].host.casefold(), ())
            )
            transitions.append(
                {
                    "transition_id": transition_id,
                    "status": "established",
                    "run_length": len(candidate_run),
                    "cessation": bool(not later_key_denial and later_host_row),
                    "record_ids": record_ids,
                }
            )
            denial_run = []
    return frozenset(finding_keys), tuple(transitions), tie_count


def fanout(
    decisions: Sequence[DecisionRow], window: Window
) -> tuple[frozenset[tuple[str, tuple[str, ...]]], int, int]:
    source_accounts: dict[str, set[tuple[str, str]]] = defaultdict(set)
    account_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    for decision in decisions:
        if decision.outcome != AuthOutcome.DENIED.value or not window.contains(decision.ts):
            continue
        actor = _namespaced_actor(decision)
        if actor is None or decision.source is None:
            continue
        source_accounts[decision.source].add(actor)
        account_sources[actor].add(decision.source)
    entities: set[tuple[str, tuple[str, ...]]] = set()
    for source, actors in source_accounts.items():
        if len(actors) >= FANOUT_SOURCE_FLOOR:
            entities.add(("source", (source,)))
    for actor, sources in account_sources.items():
        if len(sources) >= FANOUT_ACCOUNT_FLOOR:
            entities.add(("account", actor))
    source_near = max(
        (len(actors) for actors in source_accounts.values() if len(actors) < FANOUT_SOURCE_FLOOR),
        default=0,
    )
    account_near = max(
        (len(sources) for sources in account_sources.values() if len(sources) < FANOUT_ACCOUNT_FLOOR),
        default=0,
    )
    return frozenset(entities), source_near, account_near


def run_lenses(
    decisions: Sequence[DecisionRow],
    canonical_rows: Sequence[CanonicalRow],
    window: Window,
) -> LensResult:
    concentration_keys, concentration_near, _fidelity = concentration(decisions, window)
    landing_keys, transitions, tie_count = landing(decisions, canonical_rows, window)
    fanout_entities, source_near, account_near = fanout(decisions, window)
    return LensResult(
        concentration_keys=concentration_keys,
        concentration_near_miss=concentration_near,
        landing_keys=landing_keys,
        landing_transitions=transitions,
        landing_tie_unresolved=tie_count,
        fanout_entities=fanout_entities,
        fanout_source_near_miss=source_near,
        fanout_account_near_miss=account_near,
        eligible_count=sum(1 for decision in decisions if window.contains(decision.ts)),
    )


def f7_inputs(result: LensResult) -> dict[str, int]:
    """Apply cross-lens suppression only to concentration's F7 input."""
    return {
        "landing": len(result.landing_keys),
        "concentration": len(result.concentration_keys - result.landing_keys),
        "fanout": len(result.fanout_entities),
    }


def b4_verdict(counts: Sequence[int], evaluable: Sequence[bool]) -> str:
    """Apply the frozen full-vector mixture and supported non-zero ratio rule."""
    if len(counts) != len(evaluable) or not counts:
        raise MeasurementError("the stability vector is invalid")
    if any(count == 0 for count in counts) and any(count > 0 for count in counts):
        return "FAIL"
    supported = [
        count for count, has_support in zip(counts, evaluable, strict=True)
        if count > 0 and has_support
    ]
    if all(count == 0 for count in counts) or len(supported) < 5:
        return "UNMEASURABLE"
    return "PASS" if max(supported) / min(supported) <= B4_RATIO_LIMIT else "FAIL"


def sliding_windows(boundary: Mapping[str, Any]) -> tuple[Window, ...]:
    """Return complete 7-day/1-day calibration windows from the recent end."""
    first = float(boundary["t_first_epoch"])
    midpoint = float(boundary["t_mid_epoch"])
    windows: list[Window] = []
    end = midpoint
    while len(windows) < MAX_SLIDING_WINDOWS:
        start = end - WINDOW_SECONDS
        if start < first:
            break
        windows.append(Window(start=start, end=end, right_closed=False))
        end -= WINDOW_STEP_SECONDS
    return tuple(windows)


def natural_window(rows: Sequence[CanonicalRow]) -> Window:
    timestamps = [row.ts for row in rows]
    if not timestamps:
        raise MeasurementError("the natural window cannot be established")
    end = max(timestamps)
    return Window(start=end - WINDOW_SECONDS, end=end, right_closed=True)


def _aggregate_lens_result(result: LensResult) -> dict[str, Any]:
    transitions = Counter(item["status"] for item in result.landing_transitions)
    cessation = sum(
        1 for item in result.landing_transitions
        if item["status"] == "established" and item["cessation"]
    )
    return {
        "eligible_decisions": result.eligible_count,
        "concentration_unsuppressed": len(result.concentration_keys),
        "concentration_near_miss": result.concentration_near_miss,
        "landing_unsuppressed": len(result.landing_keys),
        "landing_transitions": dict(sorted(transitions.items())),
        "landing_cessation_supported": cessation,
        "landing_tie_unresolved": result.landing_tie_unresolved,
        "fanout_unsuppressed": len(result.fanout_entities),
        "fanout_source_near_miss": result.fanout_source_near_miss,
        "fanout_account_near_miss": result.fanout_account_near_miss,
        "f7": f7_inputs(result),
    }


def sample_ordinals(population_size: int, sample_size: int) -> list[int]:
    """Draw the frozen sample over ordinal positions with a fresh seeded RNG."""
    if not 0 <= sample_size <= population_size:
        raise MeasurementError("the sample size is invalid")
    return random.Random(SAMPLE_SEED).sample(range(population_size), sample_size)


def retrieve_ordinal_sample(
    ordered_values: Iterable[RecordId], ordinals: Sequence[int]
) -> list[RecordId]:
    """Retrieve streamed values while preserving random.sample's returned order."""
    wanted: dict[int, int] = {}
    for output_index, ordinal in enumerate(ordinals):
        if ordinal in wanted:
            raise MeasurementError("the ordinal sample contains a duplicate")
        wanted[ordinal] = output_index
    result: list[RecordId | None] = [None] * len(ordinals)
    for ordinal, value in enumerate(ordered_values):
        output_index = wanted.get(ordinal)
        if output_index is not None:
            result[output_index] = value
    if any(value is None for value in result):
        raise MeasurementError("the ordinal sample exceeds its population")
    return [value for value in result if value is not None]


def _sample_size(population_size: int) -> int:
    return min(SAMPLE_MAX, population_size)


def _sample_id(gate: str, record_id: RecordId) -> str:
    return hashlib.sha256(_json_bytes([gate, list(record_id)])).hexdigest()[:24]


def _row_taxonomy_class(row: CanonicalRow, taxonomy: Mapping[str, str]) -> tuple[str, str, str]:
    dialect, record_type = classify_structure(row)
    classification = taxonomy.get(_taxonomy_pair(dialect, record_type))
    if classification is None:
        raise MeasurementError("a canonical row is outside the accepted taxonomy")
    return dialect, record_type, classification


def _honesty_population_pass(
    manifest: Mapping[str, Any],
    boundary: Mapping[str, Any],
    taxonomy: Mapping[str, str],
) -> tuple[
    dict[tuple[str, str, str], list[RecordId]],
    Counter[tuple[str, str, str]],
    Counter[tuple[str, str, str]],
    Counter[tuple[str, str, str]],
    Counter[tuple[str, str]],
    Counter[tuple[str, str, str]],
    Counter[str],
]:
    f1: dict[tuple[str, str, str], list[RecordId]] = defaultdict(list)
    f1b: Counter[tuple[str, str, str]] = Counter()
    arm_rows: Counter[tuple[str, str, str]] = Counter()
    arm_yields: Counter[tuple[str, str, str]] = Counter()
    other_tags: Counter[tuple[str, str]] = Counter()
    observations: Counter[tuple[str, str, str]] = Counter()
    known_declared_gaps: Counter[str] = Counter()
    for corpus_id in CORPUS_IDS:
        scope = "calibration" if corpus_id == "openssh" else "full"
        for row in iter_canonical_rows(
            manifest, corpus_id, boundary=boundary, openssh_scope=scope
        ):
            arm = _program_arm(row.program)
            dialect, _record_type, classification = _row_taxonomy_class(row, taxonomy)
            arm_rows[(corpus_id, arm, dialect)] += 1
            if arm == "other-tag":
                other_tags[(corpus_id, row.program)] += 1
            decision = extract_decision(row.message, program=row.program)
            if decision is not None:
                observations[(corpus_id, arm, dialect)] += 1
            eligible = (
                classification == "COUNT"
                and decision is not None
                and decision.is_eligible_decision
            )
            known_gap = _known_declared_gap(
                dialect, _record_type, classification, decision
            )
            if known_gap is not None:
                known_declared_gaps[known_gap] += 1
            if eligible:
                assert decision is not None
                arm_yields[(corpus_id, arm, dialect)] += 1
                f1[(corpus_id, dialect, decision.outcome.value)].append(row.record_id)
            else:
                f1b[(corpus_id, arm, dialect)] += 1
    return (
        f1,
        f1b,
        arm_rows,
        arm_yields,
        other_tags,
        observations,
        known_declared_gaps,
    )


KNOWN_DECLARED_GAPS = {
    _taxonomy_pair("audisp-type", "AVC"): "AVC",
    _taxonomy_pair("audisp-type", "USER_AUTH"): "USER_AUTH",
    _taxonomy_pair("audisp-type", "USER_ERR"): "USER_ERR",
}


def _known_declared_gap(
    dialect: str,
    record_type: str,
    classification: str,
    decision: AuthDecision | None,
) -> str | None:
    if classification != "COUNT" or (
        decision is not None and decision.is_eligible_decision
    ):
        return None
    return KNOWN_DECLARED_GAPS.get(_taxonomy_pair(dialect, record_type))


def _honesty_samples(
    manifest: Mapping[str, Any],
    boundary: Mapping[str, Any],
    taxonomy: Mapping[str, str],
    f1_population: Mapping[tuple[str, str, str], Sequence[RecordId]],
    f1b_population: Mapping[tuple[str, str, str], int],
) -> list[dict[str, Any]]:
    selected_f1: dict[RecordId, tuple[tuple[str, str, str], int, int]] = {}
    f1_order: dict[tuple[str, str, str], dict[RecordId, int]] = {}
    for stratum, record_ids in sorted(f1_population.items()):
        ordered = sorted(record_ids)
        n = _sample_size(len(ordered))
        sample = random.Random(SAMPLE_SEED).sample(ordered, n)
        f1_order[stratum] = {record_id: index for index, record_id in enumerate(sample)}
        for record_id in sample:
            selected_f1[record_id] = (stratum, len(ordered), n)

    f1b_ordinals = {
        cell: sample_ordinals(population_size, _sample_size(population_size))
        for cell, population_size in sorted(f1b_population.items())
    }
    f1b_positions = {
        cell: {ordinal: index for index, ordinal in enumerate(ordinals)}
        for cell, ordinals in f1b_ordinals.items()
    }
    f1b_seen: Counter[tuple[str, str, str]] = Counter()
    gathered_f1: list[tuple[tuple[str, str, str], int, dict[str, Any]]] = []
    gathered_f1b: list[tuple[tuple[str, str, str], int, dict[str, Any]]] = []
    for corpus_id in CORPUS_IDS:
        scope = "calibration" if corpus_id == "openssh" else "full"
        for row in iter_canonical_rows(
            manifest, corpus_id, boundary=boundary, openssh_scope=scope
        ):
            dialect, record_type, classification = _row_taxonomy_class(row, taxonomy)
            arm = _program_arm(row.program)
            decision = extract_decision(row.message, program=row.program)
            eligible = (
                classification == "COUNT"
                and decision is not None
                and decision.is_eligible_decision
            )
            f1_info = selected_f1.get(row.record_id)
            if f1_info is not None:
                stratum, population_size, sample_size = f1_info
                assert decision is not None
                gathered_f1.append(
                    (
                        stratum,
                        f1_order[stratum][row.record_id],
                        {
                            "sample_id": _sample_id("F1", row.record_id),
                            "gate": "F1",
                            "cell": [corpus_id, dialect],
                            "stratum": [corpus_id, dialect, decision.outcome.value],
                            "population": population_size,
                            "sample_size": sample_size,
                            "record_id": list(row.record_id),
                            "program": row.program,
                            "dialect": dialect,
                            "record_type": record_type,
                            "raw": row.raw,
                            "extracted": asdict(decision),
                        },
                    )
                )
            if eligible:
                continue
            cell = (corpus_id, arm, dialect)
            ordinal = f1b_seen[cell]
            f1b_seen[cell] += 1
            sample_index = f1b_positions[cell].get(ordinal)
            if sample_index is not None:
                known_gap = _known_declared_gap(
                    dialect, record_type, classification, decision
                )
                gathered_f1b.append(
                    (
                        cell,
                        sample_index,
                        {
                            "sample_id": _sample_id("F1b", row.record_id),
                            "gate": "F1b",
                            "cell": list(cell),
                            "stratum": list(cell),
                            "population": f1b_population[cell],
                            "sample_size": len(f1b_ordinals[cell]),
                            "record_id": list(row.record_id),
                            "program": row.program,
                            "dialect": dialect,
                            "record_type": record_type,
                            "taxonomy_class": classification,
                            **(
                                {"known-declared-gap": known_gap}
                                if known_gap is not None
                                else {}
                            ),
                            "raw": row.raw,
                            "extracted": asdict(decision) if decision is not None else None,
                        },
                    )
                )
    gathered_f1.sort(key=lambda item: (item[0], item[1]))
    gathered_f1b.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in gathered_f1] + [item[2] for item in gathered_f1b]


def prepare_honesty(bundle: Path, accepted_taxonomy_sha256: str) -> dict[str, Any]:
    """Freeze the exact F1/F1b samples, keeping raw worksheets private."""
    resolved, manifest = _load_bundle(bundle)
    boundary = _read_receipt(resolved, "boundary")
    accept_taxonomy(resolved, accepted_taxonomy_sha256)
    _evaluated, taxonomy = _require_accepted_taxonomy(resolved)
    if _receipt_path(resolved, "honesty-prepare").exists():
        raise MeasurementError("the honesty sample phase is already complete")
    (
        f1,
        f1b,
        arm_rows,
        arm_yields,
        other_tags,
        observations,
        known_declared_gaps,
    ) = _honesty_population_pass(manifest, boundary, taxonomy)
    routing_defects = sum(
        value
        for (corpus_id, arm, dialect), value in observations.items()
        if arm == "other-tag"
    )
    if routing_defects:
        _write_receipt(
            resolved,
            "honesty-routing-divergence",
            {"other_tag_extraction_yield": routing_defects},
        )
        raise MeasurementError("the outside-roster routing contract was violated")
    samples = _honesty_samples(manifest, boundary, taxonomy, f1, f1b)
    samples_path = resolved / "raw" / "honesty-samples.jsonl"
    _write_exclusive(
        samples_path,
        ("".join(json.dumps(sample, sort_keys=True) + "\n" for sample in samples)).encode(),
    )
    payload = {
        "taxonomy_manifest_sha256": accepted_taxonomy_sha256,
        "sample_seed": SAMPLE_SEED,
        "sample_count": len(samples),
        "samples_sha256": _sha256_path(samples_path),
        "f1_strata": [
            {"corpus": key[0], "dialect": key[1], "outcome": key[2], "population": len(value)}
            for key, value in sorted(f1.items())
        ],
        "f1b_cells": [
            {"corpus": key[0], "program_arm": key[1], "dialect": key[2], "population": value}
            for key, value in sorted(f1b.items())
        ],
        "routing": [
            {
                "corpus": key[0],
                "program_arm": key[1],
                "dialect": key[2],
                "rows": value,
                "observations": observations[key],
                "eligible_yield": arm_yields[key],
                "rejections": value - observations[key],
            }
            for key, value in sorted(arm_rows.items())
        ],
        "other_tag_inventory": [
            {"corpus": key[0], "program": key[1], "rows": value}
            for key, value in sorted(other_tags.items())
        ],
        "known_declared_gap_population": [
            {"record_type": record_type, "rows": rows}
            for record_type, rows in sorted(known_declared_gaps.items())
        ],
    }
    _write_receipt(resolved, "honesty-prepare", payload)
    return payload


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError
                rows.append(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise MeasurementError("a private JSONL input is invalid") from exc
    return rows


def import_honesty_adjudications(bundle: Path, adjudications: Path) -> dict[str, Any]:
    """Strictly import one boolean error verdict per frozen sample."""
    resolved, _manifest = _load_bundle(bundle)
    _require_accepted_taxonomy(resolved)
    prepared = _read_receipt(resolved, "honesty-prepare")
    if _receipt_path(resolved, "honesty").exists():
        raise MeasurementError("the honesty phase is already complete")
    samples_path = resolved / "raw" / "honesty-samples.jsonl"
    if _sha256_path(samples_path) != prepared.get("samples_sha256"):
        raise MeasurementError("the frozen honesty samples changed")
    samples = _read_jsonl(samples_path)
    verdict_rows = _read_jsonl(adjudications.resolve())
    expected = {sample["sample_id"] for sample in samples}
    verdicts: dict[str, bool] = {}
    for row in verdict_rows:
        sample_id = row.get("sample_id")
        error = row.get("error")
        if not isinstance(sample_id, str) or not isinstance(error, bool) or sample_id in verdicts:
            raise MeasurementError("the adjudication set is invalid")
        verdicts[sample_id] = error
    if set(verdicts) != expected:
        raise MeasurementError("the adjudication set is not total and exact")

    f1_strata: dict[tuple[str, str, str], dict[str, int]] = {}
    f1b_cells: dict[tuple[str, str, str], dict[str, int]] = {}
    known_gap_samples: Counter[str] = Counter()
    known_gap_errors: Counter[str] = Counter()
    for sample in samples:
        key = tuple(sample["stratum"])
        bucket = f1_strata if sample["gate"] == "F1" else f1b_cells
        stats = bucket.setdefault(
            key,
            {
                "population": int(sample["population"]),
                "sample_size": int(sample["sample_size"]),
                "errors": 0,
            },
        )
        stats["errors"] += int(verdicts[sample["sample_id"]])
        known_gap = sample.get("known-declared-gap")
        if known_gap is not None:
            if not isinstance(known_gap, str) or not known_gap:
                raise MeasurementError("a frozen honesty sample is invalid")
            known_gap_samples[known_gap] += 1
            known_gap_errors[known_gap] += int(verdicts[sample["sample_id"]])

    f1_cells: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str], list[tuple[str, Mapping[str, int]]]] = defaultdict(list)
    for (corpus_id, dialect, outcome), stats in sorted(f1_strata.items()):
        grouped[(corpus_id, dialect)].append((outcome, stats))
    for (corpus_id, dialect), strata in sorted(grouped.items()):
        total_population = sum(stats["population"] for _outcome, stats in strata)
        rate = sum(
            (stats["population"] / total_population)
            * (stats["errors"] / stats["sample_size"])
            for _outcome, stats in strata
        )
        f1_cells.append(
            {
                "corpus": corpus_id,
                "dialect": dialect,
                "rate": rate,
                "verdict": "PASS" if rate <= 0.01 else "FAIL",
                "strata": [
                    {
                        "outcome": outcome,
                        **stats,
                        "rate": stats["errors"] / stats["sample_size"],
                    }
                    for outcome, stats in strata
                ],
            }
        )
    f1b_report = []
    for (corpus_id, arm, dialect), stats in sorted(f1b_cells.items()):
        rate = stats["errors"] / stats["sample_size"]
        f1b_report.append(
            {
                "corpus": corpus_id,
                "program_arm": arm,
                "dialect": dialect,
                **stats,
                "rate": rate,
                "verdict": "PASS" if rate <= 0.01 else "FAIL",
            }
        )
    verdict = (
        "PASS"
        if all(row["verdict"] == "PASS" for row in f1_cells + f1b_report)
        else "FAIL"
    )
    payload = {
        "adjudications_sha256": _sha256_path(adjudications.resolve()),
        "f1": f1_cells,
        "f1b": f1b_report,
        "known_declared_gaps": [
            {
                "record_type": record_type,
                "sampled": sampled,
                "errors": known_gap_errors[record_type],
            }
            for record_type, sampled in sorted(known_gap_samples.items())
        ],
        "known_declared_gap_population": prepared.get(
            "known_declared_gap_population", []
        ),
        "verdict": verdict,
    }
    _write_receipt(resolved, "honesty", payload)
    return payload


def _rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


def _load_worker_rows(
    manifest: Mapping[str, Any],
    boundary: Mapping[str, Any],
    corpus: str,
) -> list[CanonicalRow]:
    if corpus == "estate":
        return list(
            iter_canonical_rows(manifest, "estate", boundary=boundary, openssh_scope="full")
        )
    if corpus == "openssh-calibration":
        return list(
            iter_canonical_rows(
                manifest, "openssh", boundary=boundary, openssh_scope="calibration"
            )
        )
    if corpus == "openssh-full":
        return list(
            iter_canonical_rows(manifest, "openssh", boundary=boundary, openssh_scope="full")
        )
    raise MeasurementError("the worker corpus is invalid")


def _worker_measure(bundle: Path, corpus: str) -> dict[str, Any]:
    resolved, manifest = _load_bundle(bundle)
    boundary = _read_receipt(resolved, "boundary")
    _evaluated, taxonomy = _require_accepted_taxonomy(resolved)
    canonical_rows = _load_worker_rows(manifest, boundary, corpus)
    baseline_rss = _rss_bytes()
    total_start = time.monotonic()
    extract_start = time.monotonic()
    decisions = [
        decision
        for row in canonical_rows
        if (decision := _decision_row(row, taxonomy)) is not None
    ]
    extract_seconds = time.monotonic() - extract_start
    window = natural_window(canonical_rows)
    concentration_start = time.monotonic()
    concentration_result = concentration(decisions, window)
    concentration_seconds = time.monotonic() - concentration_start
    landing_start = time.monotonic()
    landing_result = landing(decisions, canonical_rows, window)
    landing_seconds = time.monotonic() - landing_start
    fanout_start = time.monotonic()
    fanout_result = fanout(decisions, window)
    fanout_seconds = time.monotonic() - fanout_start
    total_seconds = time.monotonic() - total_start
    peak_rss = _rss_bytes()
    incremental = max(0, peak_rss - baseline_rss)
    result = LensResult(
        concentration_keys=concentration_result[0],
        concentration_near_miss=concentration_result[1],
        landing_keys=landing_result[0],
        landing_transitions=landing_result[1],
        landing_tie_unresolved=landing_result[2],
        fanout_entities=fanout_result[0],
        fanout_source_near_miss=fanout_result[1],
        fanout_account_near_miss=fanout_result[2],
        eligible_count=sum(1 for decision in decisions if window.contains(decision.ts)),
    )
    payload: dict[str, Any] = {
        "corpus": corpus,
        "canonical_rows": len(canonical_rows),
        "eligible_decisions": len(decisions),
        "wall_seconds": total_seconds,
        "incremental_peak_rss_bytes": incremental,
        "incremental_peak_rss_gib": incremental / (2**30),
        "diagnostics": {
            "extraction_seconds": extract_seconds,
            "concentration_seconds": concentration_seconds,
            "landing_seconds": landing_seconds,
            "fanout_seconds": fanout_seconds,
        },
        "natural_window": _aggregate_lens_result(result),
    }
    if corpus == "openssh-full":
        midpoint = float(boundary["t_mid_epoch"])
        validation_rows = [row for row in canonical_rows if row.ts >= midpoint]
        validation_decisions = [decision for decision in decisions if decision.ts >= midpoint]
        validation_window = Window(
            start=midpoint,
            end=float(boundary["t_last_epoch"]),
            right_closed=True,
        )
        validation_result = run_lenses(
            validation_decisions, validation_rows, validation_window
        )
        payload["validation"] = _aggregate_lens_result(validation_result)
        raw_path = resolved / "raw" / "heldback-transitions.jsonl"
        worksheets = _landing_worksheet_rows([validation_result], validation_rows)
        payload["heldback_transitions_sha256"] = _write_private_jsonl(
            raw_path, worksheets
        )
    return payload


def _run_worker(bundle: Path, corpus: str) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "_worker",
        "--bundle",
        str(bundle),
        "--corpus",
        corpus,
    ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise MeasurementError("a fresh measurement worker failed")
    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise MeasurementError("a fresh measurement worker returned invalid output") from exc
    if not isinstance(payload, dict) or payload.get("corpus") != corpus:
        raise MeasurementError("a fresh measurement worker returned invalid output")
    return payload


def measure_honesty_throughput(bundle: Path) -> dict[str, Any]:
    """Run F2 and the unbarred calibration diagnostic in fresh interpreters."""
    resolved, _manifest = _load_bundle(bundle)
    honesty = _read_receipt(resolved, "honesty")
    if honesty.get("verdict") != "PASS":
        raise MeasurementError("extraction honesty did not pass")
    if _receipt_path(resolved, "throughput").exists():
        return _read_receipt(resolved, "throughput")
    estate_runs = [_run_worker(resolved, "estate") for _ in range(3)]
    calibration_runs = [
        _run_worker(resolved, "openssh-calibration") for _ in range(3)
    ]
    estate_seconds = statistics.median(row["wall_seconds"] for row in estate_runs)
    estate_rss = statistics.median(
        row["incremental_peak_rss_gib"] for row in estate_runs
    )
    payload = {
        "estate_natural_window_precondition": (
            "PASS — every F2 worker established a finite canonical estate timestamp "
            "before timing extraction and lenses"
        ),
        "f2": {
            "runs": estate_runs,
            "median_wall_seconds": estate_seconds,
            "median_incremental_peak_rss_gib": estate_rss,
            "verdict": (
                "PASS"
                if estate_seconds <= F2_SECONDS and estate_rss <= F2_RSS_GIB
                else "FAIL"
            ),
        },
        "openssh_calibration_diagnostic": {
            "runs": calibration_runs,
            "median_wall_seconds": statistics.median(
                row["wall_seconds"] for row in calibration_runs
            ),
            "median_incremental_peak_rss_gib": statistics.median(
                row["incremental_peak_rss_gib"] for row in calibration_runs
            ),
            "barred": False,
        },
    }
    _write_receipt(resolved, "throughput", payload)
    return payload


def honesty_phase(
    bundle: Path,
    *,
    accepted_taxonomy_sha256: str,
    adjudications: Path | None,
) -> dict[str, Any]:
    resolved, _manifest = _load_bundle(bundle)
    if not _receipt_path(resolved, "honesty-prepare").exists():
        if adjudications is not None:
            raise MeasurementError("honesty samples must be prepared before adjudication")
        return prepare_honesty(resolved, accepted_taxonomy_sha256)
    accept_taxonomy(resolved, accepted_taxonomy_sha256)
    if not _receipt_path(resolved, "honesty").exists():
        if adjudications is None:
            raise MeasurementError("the frozen honesty samples require adjudication")
        honesty = import_honesty_adjudications(resolved, adjudications)
        if honesty["verdict"] != "PASS":
            return honesty
    return measure_honesty_throughput(resolved)


def _landing_worksheet_rows(
    results: Sequence[LensResult], canonical_rows: Sequence[CanonicalRow]
) -> list[dict[str, Any]]:
    row_by_id = {row.record_id: row for row in canonical_rows}
    merged: dict[str, dict[str, Any]] = {}
    for window_index, result in enumerate(results):
        for transition in result.landing_transitions:
            if transition["status"] != "established":
                continue
            transition_id = transition["transition_id"]
            entry = merged.setdefault(
                transition_id,
                {
                    **transition,
                    "window_indices": [],
                    "source_rows": [],
                },
            )
            entry["window_indices"].append(window_index)
            if not entry["source_rows"]:
                for value in transition["record_ids"]:
                    record_id = (str(value[0]), str(value[1]), int(value[2]))
                    row = row_by_id.get(record_id)
                    if row is not None:
                        entry["source_rows"].append(
                            {"record_id": value, "raw": row.raw}
                        )
    return [merged[key] for key in sorted(merged)]


def _write_private_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> str:
    payload = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
    _write_exclusive(path, payload)
    return _sha256_path(path)


LANDING_VERDICTS = frozenset(
    {
        "valid transition",
        "artifact",
        "structurally valid / attribution unknown",
    }
)


def _strict_categorical_adjudications(
    expected_ids: set[str], path: Path, allowed: frozenset[str]
) -> dict[str, str]:
    verdicts: dict[str, str] = {}
    for row in _read_jsonl(path.resolve()):
        finding_id = row.get("finding_id") or row.get("transition_id")
        verdict = row.get("verdict")
        if (
            not isinstance(finding_id, str)
            or verdict not in allowed
            or finding_id in verdicts
        ):
            raise MeasurementError("the structural adjudication set is invalid")
        verdicts[finding_id] = verdict
    if set(verdicts) != expected_ids:
        raise MeasurementError("the structural adjudication set is not total and exact")
    return verdicts


def prepare_calibration(bundle: Path) -> dict[str, Any]:
    """Run the frozen calibration vector and write private landing evidence."""
    resolved, manifest = _load_bundle(bundle)
    boundary = _read_receipt(resolved, "boundary")
    honesty = _read_receipt(resolved, "honesty")
    throughput = _read_receipt(resolved, "throughput")
    if honesty.get("verdict") != "PASS" or throughput["f2"]["verdict"] != "PASS":
        raise MeasurementError("an upstream unit-level gate did not pass")
    _evaluated, taxonomy = _require_accepted_taxonomy(resolved)
    if _receipt_path(resolved, "calibration-prepare").exists():
        raise MeasurementError("the calibration phase is already prepared")
    canonical_rows = list(
        iter_canonical_rows(
            manifest, "openssh", boundary=boundary, openssh_scope="calibration"
        )
    )
    decisions = [
        decision
        for row in canonical_rows
        if (decision := _decision_row(row, taxonomy)) is not None
    ]
    windows = sliding_windows(boundary)
    if not windows:
        raise MeasurementError("the calibration window vector is empty")
    results = [run_lenses(decisions, canonical_rows, window) for window in windows]
    aggregate = [_aggregate_lens_result(result) for result in results]
    f7_maxima = {
        name: max(row["f7"][name] for row in aggregate)
        for name in ("landing", "concentration", "fanout")
    }
    evaluable = [result.eligible_count >= EVALUABLE_DECISIONS for result in results]
    f8 = {
        "concentration": b4_verdict(
            [len(result.concentration_keys) for result in results], evaluable
        ),
        "fanout": b4_verdict(
            [len(result.fanout_entities) for result in results], evaluable
        ),
    }
    worksheets = _landing_worksheet_rows(results, canonical_rows)
    worksheet_path = resolved / "raw" / "calibration-landing.jsonl"
    worksheet_hash = _write_private_jsonl(worksheet_path, worksheets)
    payload = {
        "vector_size": len(windows),
        "windows": [
            {
                "start": datetime.fromtimestamp(window.start, timezone.utc).isoformat(),
                "end": datetime.fromtimestamp(window.end, timezone.utc).isoformat(),
                **aggregate[index],
            }
            for index, window in enumerate(windows)
        ],
        "f7_maxima": f7_maxima,
        "f7_verdict": (
            "PASS" if all(value <= F7_LIMIT for value in f7_maxima.values()) else "FAIL"
        ),
        "f8": f8,
        "landing_adjudication_count": len(worksheets),
        "landing_worksheet_sha256": worksheet_hash,
    }
    _write_receipt(resolved, "calibration-prepare", payload)
    return payload


def finish_calibration(bundle: Path, adjudications: Path) -> dict[str, Any]:
    resolved, _manifest = _load_bundle(bundle)
    prepared = _read_receipt(resolved, "calibration-prepare")
    if _receipt_path(resolved, "calibration").exists():
        raise MeasurementError("the calibration phase is already complete")
    worksheet_path = resolved / "raw" / "calibration-landing.jsonl"
    if _sha256_path(worksheet_path) != prepared["landing_worksheet_sha256"]:
        raise MeasurementError("the calibration landing worksheet changed")
    worksheet = _read_jsonl(worksheet_path)
    expected = {row["transition_id"] for row in worksheet}
    verdicts = _strict_categorical_adjudications(
        expected, adjudications, LANDING_VERDICTS
    )
    counts = Counter(verdicts.values())
    payload = {
        "prepare_receipt_sha256": _sha256_path(
            _receipt_path(resolved, "calibration-prepare")
        ),
        "landing_adjudications": dict(sorted(counts.items())),
        "landing_verdict": "PASS" if counts["artifact"] == 0 else "FAIL",
        "f7_verdict": prepared["f7_verdict"],
        "f8": prepared["f8"],
    }
    _write_receipt(resolved, "calibration", payload)
    return payload


def calibration_phase(bundle: Path, adjudications: Path | None) -> dict[str, Any]:
    resolved, _manifest = _load_bundle(bundle)
    if not _receipt_path(resolved, "calibration-prepare").exists():
        if adjudications is not None:
            raise MeasurementError("calibration must be prepared before adjudication")
        return prepare_calibration(resolved)
    if adjudications is None:
        raise MeasurementError("the calibration landing set requires adjudication")
    return finish_calibration(resolved, adjudications)


def _natural_rows(
    manifest: Mapping[str, Any], boundary: Mapping[str, Any], corpus_id: str
) -> tuple[list[CanonicalRow], Window]:
    maximum: float | None = None
    for row in iter_canonical_rows(
        manifest, corpus_id, boundary=boundary, openssh_scope="full"
    ):
        if math.isfinite(row.ts):
            maximum = row.ts if maximum is None or row.ts > maximum else maximum
    if maximum is None:
        raise MeasurementError("the natural window cannot be established")
    window = Window(maximum - WINDOW_SECONDS, maximum, right_closed=True)
    rows = [
        row
        for row in iter_canonical_rows(
            manifest, corpus_id, boundary=boundary, openssh_scope="full"
        )
        if window.contains(row.ts)
    ]
    return rows, window


def _finding_id(lens: str, value: Any) -> str:
    return hashlib.sha256(_json_bytes([lens, value])).hexdigest()[:24]


def _estate_worksheet(
    result: LensResult,
    entity_rows: Mapping[tuple[str, str], set[RecordId]],
    canonical_rows: Sequence[CanonicalRow],
) -> list[dict[str, Any]]:
    row_by_id = {row.record_id: row for row in canonical_rows}

    def source_rows(lens: str, finding_id: str) -> list[dict[str, Any]]:
        record_ids = sorted(entity_rows.get((lens, finding_id), set()))
        if lens != "landing":
            record_ids = record_ids[:20]
        return [
            {"record_id": list(record_id), "raw": row_by_id[record_id].raw}
            for record_id in record_ids
            if record_id in row_by_id
        ]

    rows: list[dict[str, Any]] = []
    for key in sorted(result.concentration_keys):
        finding_id = _finding_id("concentration", key)
        rows.append(
            {
                "finding_id": finding_id,
                "lens": "concentration",
                "key": list(key),
                "source_rows": source_rows("concentration", finding_id),
            }
        )
    for entity in sorted(result.fanout_entities):
        finding_id = _finding_id("fanout", entity)
        rows.append(
            {
                "finding_id": finding_id,
                "lens": "fanout",
                "entity": entity,
                "source_rows": source_rows("fanout", finding_id),
            }
        )
    for transition in result.landing_transitions:
        if transition["status"] == "established":
            finding_id = transition["transition_id"]
            rows.append(
                {
                    "finding_id": finding_id,
                    "lens": "landing",
                    **transition,
                    "source_rows": source_rows("landing", finding_id),
                }
            )
    return rows


ESTATE_LENS_VERDICTS = frozenset(
    {
        "pre-adjudicated",
        "confirmed-benign-misfire",
        "unresolved",
        *LANDING_VERDICTS,
    }
)


def _syslog_surface_ids(rows: Sequence[CanonicalRow]) -> set[RecordId]:
    if not rows:
        return set()
    frame = pd.DataFrame(
        [
            {
                "ts": row.ts,
                "host": row.host,
                "program": row.program,
                "raw": row.raw,
                "message": row.message,
            }
            for row in rows
        ]
    )
    configured = syslog_detector.DEFAULT_CONFIG
    mined = syslog_detector._run_drain3(
        frame,
        configured["sim_thresh"],
        configured["depth"],
        configured["parametrize_numeric"],
    )
    scored, _threshold, _frequencies = syslog_detector._score_rarity(
        mined, configured["rarity_pct"], configured["max_count"]
    )
    reboot = scored["message"].astype(str).str.contains(
        syslog_detector.REBOOT_SIGNALS_RE, na=False
    )
    mask = scored["is_anomaly"] | reboot
    return {rows[index].record_id for index, surfaced in enumerate(mask) if surfaced}


def _auth_lens_row_sets(
    result: LensResult, decisions: Sequence[DecisionRow]
) -> dict[tuple[str, str], set[RecordId]]:
    entities: dict[tuple[str, str], set[RecordId]] = defaultdict(set)
    for decision in decisions:
        key = episode_key(decision)
        if key in result.concentration_keys and decision.outcome == AuthOutcome.DENIED.value:
            entities[("concentration", _finding_id("concentration", key))].add(decision.record_id)
        actor = _namespaced_actor(decision)
        if decision.outcome == AuthOutcome.DENIED.value and actor is not None and decision.source is not None:
            source_entity = ("source", (decision.source,))
            account_entity = ("account", actor)
            if source_entity in result.fanout_entities:
                entities[("fanout", _finding_id("fanout", source_entity))].add(decision.record_id)
            if account_entity in result.fanout_entities:
                entities[("fanout", _finding_id("fanout", account_entity))].add(decision.record_id)
    for transition in result.landing_transitions:
        if transition["status"] != "established":
            continue
        entity = ("landing", transition["transition_id"])
        for value in transition["record_ids"]:
            entities[entity].add((str(value[0]), str(value[1]), int(value[2])))
    return entities


def prepare_estate(bundle: Path) -> dict[str, Any]:
    resolved, manifest = _load_bundle(bundle)
    _require_receipts(resolved, "calibration")
    calibration = _read_receipt(resolved, "calibration")
    if calibration.get("landing_verdict") != "PASS":
        raise MeasurementError("calibration found a structural artifact")
    throughput = _read_receipt(resolved, "throughput")
    if throughput["f2"]["verdict"] != "PASS":
        raise MeasurementError("the unit-level throughput gate did not pass")
    boundary = _read_receipt(resolved, "boundary")
    _evaluated, taxonomy = _require_accepted_taxonomy(resolved)
    if _receipt_path(resolved, "estate-prepare").exists():
        raise MeasurementError("the estate phase is already prepared")
    rows, window = _natural_rows(manifest, boundary, "estate")
    decisions = [
        decision for row in rows if (decision := _decision_row(row, taxonomy)) is not None
    ]
    result = run_lenses(decisions, rows, window)
    aggregate = _aggregate_lens_result(result)
    surfaced_ids = _syslog_surface_ids(rows)
    auth_entities = _auth_lens_row_sets(result, decisions)
    auth_rows = set().union(*auth_entities.values()) if auth_entities else set()
    overlap_entities = sum(
        1 for record_ids in auth_entities.values() if record_ids & surfaced_ids
    )
    worksheet = _estate_worksheet(result, auth_entities, rows)
    worksheet_path = resolved / "raw" / "estate-lens-adjudications.jsonl"
    worksheet_hash = _write_private_jsonl(worksheet_path, worksheet)
    payload = {
        "corpus_coverage": manifest["corpora"]["estate"].get(
            "calendar_coverage"
        ),
        "window": {
            "start": datetime.fromtimestamp(window.start, timezone.utc).isoformat(),
            "end": datetime.fromtimestamp(window.end, timezone.utc).isoformat(),
        },
        **aggregate,
        "f7_verdict": (
            "PASS" if all(value <= F7_LIMIT for value in aggregate["f7"].values()) else "FAIL"
        ),
        "syslog_overlap": {
            "auth_lens_entities": len(auth_entities),
            "overlap_entities": overlap_entities,
            "auth_lens_rows": len(auth_rows),
            "overlap_rows": len(auth_rows & surfaced_ids),
        },
        "adjudication_count": len(worksheet),
        "adjudication_worksheet_sha256": worksheet_hash,
    }
    _write_receipt(resolved, "estate-prepare", payload)
    return payload


def finish_estate(bundle: Path, adjudications: Path) -> dict[str, Any]:
    resolved, manifest = _load_bundle(bundle)
    prepared = _read_receipt(resolved, "estate-prepare")
    if _receipt_path(resolved, "estate").exists():
        raise MeasurementError("the estate phase is already complete")
    worksheet_path = resolved / "raw" / "estate-lens-adjudications.jsonl"
    if _sha256_path(worksheet_path) != prepared["adjudication_worksheet_sha256"]:
        raise MeasurementError("the estate adjudication worksheet changed")
    worksheet = _read_jsonl(worksheet_path)
    expected = {row["finding_id"] for row in worksheet}
    verdicts = _strict_categorical_adjudications(
        expected, adjudications, ESTATE_LENS_VERDICTS
    )
    worksheet_by_id = {row["finding_id"]: row for row in worksheet}
    ordinary_verdicts = {
        "pre-adjudicated", "confirmed-benign-misfire", "unresolved"
    }
    for finding_id, verdict in verdicts.items():
        lens = worksheet_by_id[finding_id]["lens"]
        allowed = LANDING_VERDICTS if lens == "landing" else ordinary_verdicts
        if verdict not in allowed:
            raise MeasurementError("an estate adjudication uses the wrong lens vocabulary")
    counts = Counter(verdicts.values())
    parser_hash = _sha256_path(Path(auth_parser.__file__))
    taxonomy = _read_receipt(resolved, "taxonomy-accepted")
    payload = {
        "prepare_receipt_sha256": _sha256_path(_receipt_path(resolved, "estate-prepare")),
        "adjudications": dict(sorted(counts.items())),
        "artifact_free": counts["artifact"] == 0,
        "confirmed_benign_misfires": counts["confirmed-benign-misfire"],
        "verdict": "PASS" if counts["artifact"] == 0 else "CORRECTION_REQUIRED",
        "f7_verdict": prepared["f7_verdict"],
        "parser_sha256": parser_hash,
        "taxonomy_manifest_sha256": taxonomy["taxonomy_manifest_sha256"],
        "corpus_sha256": {
            corpus_id: [entry["sha256"] for entry in manifest["corpora"][corpus_id]["files"]]
            for corpus_id in CORPUS_IDS
        },
    }
    _write_receipt(resolved, "estate", payload)
    if counts["artifact"]:
        return payload
    _write_receipt(
        resolved,
        "instrument-frozen",
        {
            "parser_sha256": parser_hash,
            "taxonomy_manifest_sha256": taxonomy["taxonomy_manifest_sha256"],
            "tool_sha256": manifest["tool"]["sha256"],
        },
    )
    return payload


def estate_phase(bundle: Path, adjudications: Path | None) -> dict[str, Any]:
    resolved, _manifest = _load_bundle(bundle)
    if not _receipt_path(resolved, "estate-prepare").exists():
        if adjudications is not None:
            raise MeasurementError("estate must be prepared before adjudication")
        return prepare_estate(resolved)
    if adjudications is None:
        raise MeasurementError("the estate finding set requires adjudication")
    return finish_estate(resolved, adjudications)


def heldback_phase(bundle: Path) -> dict[str, Any]:
    """Spend validation first, then perform the only full-OpenSSH worker run."""
    resolved, manifest = _load_bundle(bundle)
    _require_receipts(resolved, "estate", "instrument-frozen")
    frozen = _read_receipt(resolved, "instrument-frozen")
    accepted = _read_receipt(resolved, "taxonomy-accepted")
    if frozen.get("parser_sha256") != _sha256_path(Path(auth_parser.__file__)):
        raise MeasurementError("the frozen parser hash does not match")
    if frozen.get("taxonomy_manifest_sha256") != accepted.get("taxonomy_manifest_sha256"):
        raise MeasurementError("the frozen taxonomy hash does not match")
    if frozen.get("tool_sha256") != manifest["tool"]["sha256"]:
        raise MeasurementError("the frozen tool hash does not match")
    spent_path = resolved / "validation-spent.json"
    if spent_path.exists() or _receipt_path(resolved, "heldback").exists():
        raise MeasurementError("the held-back validation pass is already spent")
    _write_json_exclusive(
        spent_path,
        {
            "schema": SCHEMA_VERSION,
            "spent_at": datetime.now(timezone.utc).isoformat(),
            "parser_sha256": frozen["parser_sha256"],
            "taxonomy_manifest_sha256": frozen["taxonomy_manifest_sha256"],
            "tool_sha256": frozen["tool_sha256"],
        },
    )
    try:
        worker = _run_worker(resolved, "openssh-full")
    except MeasurementError:
        _write_receipt(
            resolved,
            "heldback-failure",
            {"validation_spent": True, "retry_permitted": False},
        )
        raise
    f3_pass = (
        worker["wall_seconds"] <= F3_SECONDS
        and worker["incremental_peak_rss_gib"] <= F3_RSS_GIB
    )
    payload = {
        "validation_spent": True,
        "retry_permitted": False,
        "f3": {
            "wall_seconds": worker["wall_seconds"],
            "incremental_peak_rss_bytes": worker["incremental_peak_rss_bytes"],
            "incremental_peak_rss_gib": worker["incremental_peak_rss_gib"],
            "diagnostics": worker["diagnostics"],
            "verdict": "PASS" if f3_pass else "FAIL",
        },
        "validation": worker["validation"],
        "validation_taxonomy_conformance": "PASS",
        "heldback_transitions_sha256": worker["heldback_transitions_sha256"],
        "divergence_policy": "record-only; no repair or gate re-evaluation",
    }
    _write_receipt(resolved, "heldback", payload)
    return payload


def _fmt_number(value: Any, digits: int = 3) -> str:
    if value is None:
        return "UNMEASURABLE"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _results_markdown(
    manifest: Mapping[str, Any],
    boundary: Mapping[str, Any],
    taxonomy: Mapping[str, Any],
    honesty: Mapping[str, Any],
    throughput: Mapping[str, Any],
    calibration_prepare: Mapping[str, Any],
    calibration: Mapping[str, Any],
    estate_prepare: Mapping[str, Any],
    estate: Mapping[str, Any],
    heldback: Mapping[str, Any],
    heldback_adjudications: Mapping[str, int],
) -> str:
    f2 = throughput["f2"]
    f3 = heldback["f3"]
    estate_coverage = estate_prepare.get("corpus_coverage") or {}
    estate_coverage_text = (
        f"{estate_coverage.get('daily_files')} daily files spanning "
        f"{estate_coverage.get('calendar_days')} calendar days "
        f"({estate_coverage.get('first_date')} → {estate_coverage.get('last_date')}), "
        f"{estate_coverage.get('missing_days')} days absent, longest gap "
        f"{estate_coverage.get('longest_gap_days')} days"
        if estate_coverage
        else "calendar continuity unavailable"
    )
    taxonomy_counts = Counter(
        entry["class"] for entry in taxonomy["classifications"]
    )
    rationale_lines = [
        f"- `{note['id']}`: {note['text']}"
        for note in taxonomy.get("rationale_notes", [])
    ]
    lines = [
        "# Authentication Measurement Results — 2026-08-04",
        "",
        "Status: complete under the frozen rev-6 charter. The OpenSSH validation half was read once and is spent.",
        "",
        "## Frozen identity and boundary",
        "",
        f"- Charter SHA-256: `{manifest['charter']['sha256']}`",
        f"- Tool SHA-256: `{manifest['tool']['sha256']}`",
        f"- Parser SHA-256: `{manifest['parser']['sha256']}`",
        f"- Accepted taxonomy SHA-256: `{taxonomy['taxonomy_manifest_sha256']}`",
        f"- `T_first`: `{boundary['t_first']}`",
        f"- `T_mid`: `{boundary['t_mid']}` (immutable time midpoint; the disclosed calibration/validation count imbalance was not rebalanced)",
        f"- `T_last`: `{boundary['t_last']}`",
        f"- Calibration sliding-vector size: `{calibration_prepare['vector_size']}`",
        f"- Estate coverage: {estate_coverage_text}",
        f"- Accepted taxonomy classes: COUNT={taxonomy_counts['COUNT']}, ENRICH={taxonomy_counts['ENRICH']}, INELIGIBLE={taxonomy_counts['INELIGIBLE']}",
        "",
        "## Taxonomy rationale",
        "",
        *(rationale_lines or ["- No declaration rationale notes were recorded."]),
        "",
        "## Barred gates",
        "",
        "| Gate | Measured value | Bar | Verdict |",
        "|---|---:|---:|---|",
        f"| F1 | {len(honesty['f1'])} cells | ≤ 1% each | {honesty['verdict']} |",
        f"| F1b | {len(honesty['f1b'])} cells | ≤ 1% each | {honesty['verdict']} |",
        f"| F2 | {_fmt_number(f2['median_wall_seconds'])} s / {_fmt_number(f2['median_incremental_peak_rss_gib'])} GiB | 480 s / 4 GiB | {f2['verdict']} |",
        f"| F3 | {_fmt_number(f3['wall_seconds'])} s / {_fmt_number(f3['incremental_peak_rss_gib'])} GiB | 60 s / 1 GiB | {f3['verdict']} |",
        f"| F7 calibration | `{calibration_prepare['f7_maxima']}` | each ≤ 25 | {calibration['f7_verdict']} |",
        f"| F7 estate | `{estate_prepare['f7']}` | each ≤ 25 | {estate['f7_verdict']} |",
        f"| F8 concentration | calibration vector | ratio ≤ 3 with support | {calibration['f8']['concentration']} |",
        f"| F8 fan-out | calibration vector | ratio ≤ 3 with support | {calibration['f8']['fanout']} |",
        "",
        "UNMEASURABLE is reported as a support limitation and is not a pass.",
        "",
        "## Decision bands and structural adjudication",
        "",
        f"- Calibration landing adjudications: `{calibration['landing_adjudications']}`",
        f"- Estate adjudications: `{estate['adjudications']}`",
        f"- Held-back landing adjudications: `{dict(sorted(heldback_adjudications.items()))}`",
        f"- Estate syslog overlap: `{estate_prepare['syslog_overlap']}`",
        f"- Validation aggregate: `{heldback['validation']}`",
        f"- Known declared parser-gap population: `{honesty.get('known_declared_gap_population', [])}`",
        f"- Sampled known declared gaps: `{honesty.get('known_declared_gaps', [])}`",
        "",
        "## Corpus claim limits",
        "",
        "The terminal taxonomy is complete only for the declared estate export, LogHub OpenSSH, and LogHub Linux corpora. The estate is a fixed set of daily files with the discontinuous calendar coverage stated above, not a recall corpus or a quietness proof. Every estate window is evaluated against the records actually present; missing calendar days are never imputed. Dedicated Linux audit, linux_secure, journald, and newer audit sourcetypes were not read. LogHub is unlabeled and does not establish real-world recall. A held-back surprise is a divergence for Author ruling, never an in-place repair invitation.",
        "",
        "Lens keys keep `unix_user` and `unix_auid` identities separate. One real principal represented in both namespaces remains two keys and may split below a decision floor rather than aggregate across an unproven identity link. That is the intentional no-merge rule, not evidence for changing a floor.",
        "",
        "No raw line, identity, host, address, or corpus path is reproduced in this record.",
        "",
    ]
    return "\n".join(lines)


def finalize_phase(
    bundle: Path,
    *,
    heldback_adjudications_path: Path,
    output: Path,
) -> dict[str, Any]:
    resolved, manifest = _load_bundle(bundle)
    boundary = _read_receipt(resolved, "boundary")
    taxonomy = _read_receipt(resolved, "taxonomy-evaluate")
    taxonomy_accepted = _read_receipt(resolved, "taxonomy-accepted")
    if taxonomy_accepted.get("taxonomy_manifest_sha256") != taxonomy.get(
        "taxonomy_manifest_sha256"
    ):
        raise MeasurementError("the accepted taxonomy hash does not match")
    honesty = _read_receipt(resolved, "honesty")
    throughput = _read_receipt(resolved, "throughput")
    calibration_prepare = _read_receipt(resolved, "calibration-prepare")
    calibration = _read_receipt(resolved, "calibration")
    estate_prepare = _read_receipt(resolved, "estate-prepare")
    estate = _read_receipt(resolved, "estate")
    heldback = _read_receipt(resolved, "heldback")
    if _receipt_path(resolved, "finalize").exists():
        raise MeasurementError("the measurement unit is already finalized")
    transitions_path = resolved / "raw" / "heldback-transitions.jsonl"
    if _sha256_path(transitions_path) != heldback["heldback_transitions_sha256"]:
        raise MeasurementError("the held-back transition worksheet changed")
    transitions = _read_jsonl(transitions_path)
    expected = {row["transition_id"] for row in transitions}
    heldback_verdicts = _strict_categorical_adjudications(
        expected, heldback_adjudications_path, LANDING_VERDICTS
    )
    heldback_counts = Counter(heldback_verdicts.values())
    destination = output.resolve()
    if destination.exists():
        raise MeasurementError("the aggregate results target already exists")
    if destination.parent != (REPO_ROOT / "private" / "credible").resolve():
        raise MeasurementError("the aggregate results target is outside the approved directory")
    markdown = _results_markdown(
        manifest,
        boundary,
        taxonomy,
        honesty,
        throughput,
        calibration_prepare,
        calibration,
        estate_prepare,
        estate,
        heldback,
        heldback_counts,
    )
    _write_exclusive(destination, markdown.encode())
    os.chmod(destination, 0o644)
    payload = {
        "results_sha256": _sha256_path(destination),
        "heldback_adjudications_sha256": _sha256_path(
            heldback_adjudications_path.resolve()
        ),
        "heldback_landing_adjudications": dict(sorted(heldback_counts.items())),
        "validation_spent": True,
        "f3_verdict": heldback["f3"]["verdict"],
    }
    _write_receipt(resolved, "finalize", payload)
    return payload


def _build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=SafeArgumentParser
    )

    init = commands.add_parser("init")
    init.add_argument("--bundle", required=True, type=Path)
    init.add_argument("--charter", type=Path, default=DEFAULT_CHARTER)
    estate_source = init.add_mutually_exclusive_group(required=True)
    estate_source.add_argument("--estate", type=Path)
    estate_source.add_argument(
        "--estate-file", dest="estate_files", action="append", type=Path
    )
    init.add_argument("--openssh", required=True, type=Path)
    init.add_argument("--linux", required=True, type=Path)

    boundary = commands.add_parser("boundary")
    boundary.add_argument("--bundle", required=True, type=Path)
    boundary.add_argument("--expected-baseline", type=Path)

    for name in ("taxonomy-inventory", "heldback"):
        command = commands.add_parser(name)
        command.add_argument("--bundle", required=True, type=Path)

    taxonomy = commands.add_parser("taxonomy-evaluate")
    taxonomy.add_argument("--bundle", required=True, type=Path)
    taxonomy.add_argument("--manifest", required=True, type=Path)

    honesty = commands.add_parser("honesty")
    honesty.add_argument("--bundle", required=True, type=Path)
    honesty.add_argument("--accepted-taxonomy-sha256", required=True)
    honesty.add_argument("--adjudications", type=Path)

    for name in ("calibration", "estate"):
        command = commands.add_parser(name)
        command.add_argument("--bundle", required=True, type=Path)
        command.add_argument("--adjudications", type=Path)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--bundle", required=True, type=Path)
    finalize.add_argument("--heldback-adjudications", required=True, type=Path)
    finalize.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT
        / "private"
        / "credible"
        / "AUTH-MEASUREMENT-RESULTS-2026-08-04.md",
    )

    worker = commands.add_parser("_worker")
    worker.add_argument("--bundle", required=True, type=Path)
    worker.add_argument(
        "--corpus",
        required=True,
        choices=("estate", "openssh-calibration", "openssh-full"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "init":
            init_bundle(
                args.bundle,
                charter=args.charter,
                estate=args.estate_files if args.estate_files is not None else args.estate,
                openssh=args.openssh,
                linux=args.linux,
            )
        elif args.command == "boundary":
            compute_boundary(args.bundle, expected_baseline=args.expected_baseline)
        elif args.command == "taxonomy-inventory":
            taxonomy_inventory(args.bundle)
        elif args.command == "taxonomy-evaluate":
            taxonomy_evaluate(args.bundle, args.manifest)
        elif args.command == "honesty":
            honesty_phase(
                args.bundle,
                accepted_taxonomy_sha256=args.accepted_taxonomy_sha256,
                adjudications=args.adjudications,
            )
        elif args.command == "calibration":
            calibration_phase(args.bundle, args.adjudications)
        elif args.command == "estate":
            estate_phase(args.bundle, args.adjudications)
        elif args.command == "heldback":
            heldback_phase(args.bundle)
        elif args.command == "finalize":
            finalize_phase(
                args.bundle,
                heldback_adjudications_path=args.heldback_adjudications,
                output=args.output,
            )
        elif args.command == "_worker":
            print(json.dumps(_worker_measure(args.bundle, args.corpus), sort_keys=True))
            return 0
        else:
            raise MeasurementError("the requested phase is invalid")
    except (MeasurementError, OSError, ValueError, KeyError, TypeError):
        print("measure-auth: phase failed; inspect the private bundle", file=sys.stderr)
        return 2
    print(f"measure-auth: phase={args.command} status=complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
