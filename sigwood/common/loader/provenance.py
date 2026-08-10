"""Strict exporter-provenance schema parsing and content validation.

The exporter owns mutation.  This loader-owned module defines the shared schema,
rejects ambiguous JSON, and publishes only typed downgrade-or-trust facts.
"""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import stat
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from sigwood.common.loader.types import (
    AvailabilityReason,
    AvailabilityState,
    ExportAvailability,
)


PROVENANCE_MANIFEST_NAME = ".sigwood-export-provenance.json"
PROVENANCE_LOCK_NAME = ".sigwood-export-provenance.lock"
PROVENANCE_STAGE_PREFIX = ".sigwood-export-stage-"
PROVENANCE_SCHEMA_VERSION = 1
MAX_PROVENANCE_BYTES = 256 * 1024 * 1024
MAX_AVAILABILITY_SPANS = 100_000

_MANIFEST_KEYS = frozenset({"schema_version", "generation", "written_at", "entries"})
_ENTRY_KEYS = frozenset({
    "schema_version",
    "content_sha256",
    "size_bytes",
    "requested_start_utc",
    "requested_end_utc",
    "request_zone",
    "tzdata_version",
    "exporter",
    "backend",
    "completion",
})
_HEX = frozenset("0123456789abcdef")


class ProvenanceManifestError(ValueError):
    """The manifest cannot safely establish any availability fact."""


class _DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True)
class ProvenanceEntry:
    schema_version: int
    content_sha256: str
    size_bytes: int
    requested_start_utc: datetime
    requested_end_utc: datetime
    request_zone: str | None
    tzdata_version: str | None
    exporter: str
    backend: str
    completion: str


@dataclass(frozen=True)
class ProvenanceManifest:
    schema_version: int
    generation: int
    written_at: datetime
    entries: dict[str, ProvenanceEntry]


def is_reserved_provenance_path(path: Path) -> bool:
    """Return whether any path component belongs to the reserved namespace."""
    return any(
        part in {PROVENANCE_MANIFEST_NAME, PROVENANCE_LOCK_NAME}
        or part.startswith(PROVENANCE_STAGE_PREFIX)
        for part in Path(path).parts
    )


def reject_explicit_reserved_path(path: Path) -> None:
    """Give explicit reserved-artifact input an actionable answer."""
    if is_reserved_provenance_path(path):
        raise ValueError(
            f"{path} is a reserved sigwood provenance artifact, not a log input; "
            "select the exported data file or its containing directory"
        )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON number is outside the finite float range")
    return parsed


def _strict_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProvenanceManifestError(f"invalid {field}")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ProvenanceManifestError(f"invalid {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ProvenanceManifestError(f"invalid {field}")
    return parsed.astimezone(timezone.utc)


def _contains_control(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def utc_text(value: datetime) -> str:
    """Canonical UTC instant used by the manifest wire format."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("provenance timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_text(value: object, field: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ProvenanceManifestError(f"invalid {field}")
    if _contains_control(value):
        raise ProvenanceManifestError(f"invalid {field}")
    return value


def _safe_basename(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 255:
        raise ProvenanceManifestError("invalid entry basename")
    if value in {".", ".."} or "/" in value or "\\" in value:
        raise ProvenanceManifestError("invalid entry basename")
    if Path(value).name != value or is_reserved_provenance_path(Path(value)):
        raise ProvenanceManifestError("invalid entry basename")
    if _contains_control(value):
        raise ProvenanceManifestError("invalid entry basename")
    return value


def _parse_entry(value: object) -> ProvenanceEntry:
    if not isinstance(value, dict) or set(value) != _ENTRY_KEYS:
        raise ProvenanceManifestError("invalid provenance entry shape")
    version = value["schema_version"]
    if isinstance(version, bool) or version != PROVENANCE_SCHEMA_VERSION:
        raise ProvenanceManifestError("unsupported provenance entry version")
    digest = value["content_sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(ch not in _HEX for ch in digest)
    ):
        raise ProvenanceManifestError("invalid content_sha256")
    size = value["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ProvenanceManifestError("invalid size_bytes")
    start = _strict_utc(value["requested_start_utc"], "requested_start_utc")
    end = _strict_utc(value["requested_end_utc"], "requested_end_utc")
    if end <= start:
        raise ProvenanceManifestError("provenance interval must be half-open and positive")
    request_zone = _safe_text(value["request_zone"], "request_zone", nullable=True)
    tzdata_version = _safe_text(
        value["tzdata_version"], "tzdata_version", nullable=True,
    )
    exporter = _safe_text(value["exporter"], "exporter")
    backend = _safe_text(value["backend"], "backend")
    completion = _safe_text(value["completion"], "completion")
    assert exporter is not None and backend is not None and completion is not None
    return ProvenanceEntry(
        schema_version=version,
        content_sha256=digest,
        size_bytes=size,
        requested_start_utc=start,
        requested_end_utc=end,
        request_zone=request_zone,
        tzdata_version=tzdata_version,
        exporter=exporter,
        backend=backend,
        completion=completion,
    )


def parse_manifest_bytes(raw: bytes) -> ProvenanceManifest:
    """Parse one bounded duplicate-free manifest into immutable entries."""
    if len(raw) > MAX_PROVENANCE_BYTES:
        raise ProvenanceManifestError("provenance manifest exceeds the byte limit")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProvenanceManifestError("malformed provenance manifest") from exc
    if not isinstance(value, dict) or set(value) != _MANIFEST_KEYS:
        raise ProvenanceManifestError("invalid provenance manifest shape")
    version = value["schema_version"]
    generation = value["generation"]
    if isinstance(version, bool) or version != PROVENANCE_SCHEMA_VERSION:
        raise ProvenanceManifestError("unsupported provenance manifest version")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise ProvenanceManifestError("invalid provenance generation")
    written_at = _strict_utc(value["written_at"], "written_at")
    entries_value = value["entries"]
    if not isinstance(entries_value, dict):
        raise ProvenanceManifestError("invalid provenance entries")
    if len(entries_value) > MAX_AVAILABILITY_SPANS:
        raise ProvenanceManifestError("provenance manifest exceeds the entry limit")
    entries: dict[str, ProvenanceEntry] = {}
    for raw_name, raw_entry in entries_value.items():
        entries[_safe_basename(raw_name)] = _parse_entry(raw_entry)
    return ProvenanceManifest(version, generation, written_at, entries)


def read_manifest(path: Path) -> ProvenanceManifest:
    """Read one regular, non-symlink manifest under the byte ceiling."""
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
    except FileNotFoundError:
        raise
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ProvenanceManifestError(
                "provenance manifest is not a regular file"
            ) from exc
        raise
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ProvenanceManifestError(
                "provenance manifest is not a regular file"
            )
        if info.st_size > MAX_PROVENANCE_BYTES:
            raise ProvenanceManifestError(
                "provenance manifest exceeds the byte limit"
            )
        raw = stream.read(MAX_PROVENANCE_BYTES + 1)
    return parse_manifest_bytes(raw)


def _entry_value(entry: ProvenanceEntry) -> dict[str, Any]:
    return {
        "schema_version": entry.schema_version,
        "content_sha256": entry.content_sha256,
        "size_bytes": entry.size_bytes,
        "requested_start_utc": utc_text(entry.requested_start_utc),
        "requested_end_utc": utc_text(entry.requested_end_utc),
        "request_zone": entry.request_zone,
        "tzdata_version": entry.tzdata_version,
        "exporter": entry.exporter,
        "backend": entry.backend,
        "completion": entry.completion,
    }


def canonical_manifest_bytes(manifest: ProvenanceManifest) -> bytes:
    """Serialize the validated schema canonically with one trailing LF."""
    value = {
        "schema_version": manifest.schema_version,
        "generation": manifest.generation,
        "written_at": utc_text(manifest.written_at),
        "entries": {
            name: _entry_value(entry)
            for name, entry in sorted(manifest.entries.items())
        },
    }
    # Re-validate so the writer cannot create a shape the loader would reject.
    raw = (json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("utf-8")
    parse_manifest_bytes(raw)
    return raw


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
    )
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError(errno.EINVAL, "provenance object is not a regular file")
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _unknown(path: Path, reason: AvailabilityReason) -> ExportAvailability:
    return ExportAvailability(
        path=path.resolve(strict=False),
        state=AvailabilityState.UNKNOWN,
        reason=reason,
    )


def validate_selected_files(files: Iterable[Path]) -> tuple[ExportAvailability, ...]:
    """Validate manifests for the exact selected file population."""
    selected = [Path(path) for path in files]
    if len(selected) > MAX_AVAILABILITY_SPANS:
        return tuple(
            _unknown(path, AvailabilityReason.RESOURCE_LIMIT)
            for path in selected
        )
    by_parent: dict[Path, list[Path]] = {}
    for path in selected:
        by_parent.setdefault(path.parent, []).append(path)
    facts: dict[Path, ExportAvailability] = {}
    for parent, paths in by_parent.items():
        manifest_path = parent / PROVENANCE_MANIFEST_NAME
        try:
            manifest = read_manifest(manifest_path)
        except FileNotFoundError:
            for path in paths:
                facts[path] = _unknown(path, AvailabilityReason.MANIFEST_MISSING)
            continue
        except ProvenanceManifestError:
            for path in paths:
                facts[path] = _unknown(path, AvailabilityReason.MANIFEST_MALFORMED)
            continue
        except OSError:
            for path in paths:
                facts[path] = _unknown(path, AvailabilityReason.MANIFEST_UNREADABLE)
            continue
        for path in paths:
            entry = manifest.entries.get(path.name)
            if entry is None:
                facts[path] = _unknown(path, AvailabilityReason.ENTRY_MISSING)
                continue
            if entry.completion != "success":
                facts[path] = _unknown(path, AvailabilityReason.INCOMPLETE)
                continue
            try:
                info = path.lstat()
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_size != entry.size_bytes
                ):
                    facts[path] = _unknown(path, AvailabilityReason.BINDING_MISMATCH)
                    continue
                digest = hash_file(path)
            except OSError:
                facts[path] = _unknown(path, AvailabilityReason.UNREADABLE)
                continue
            if digest != entry.content_sha256:
                facts[path] = _unknown(path, AvailabilityReason.BINDING_MISMATCH)
                continue
            facts[path] = ExportAvailability(
                path=path.resolve(strict=False),
                state=AvailabilityState.TRUSTED,
                reason=AvailabilityReason.TRUSTED,
                interval=(entry.requested_start_utc, entry.requested_end_utc),
                manifest_generation=manifest.generation,
                backend=entry.backend,
                request_zone=entry.request_zone,
                tzdata_version=entry.tzdata_version,
            )
    return tuple(facts[path] for path in selected)
