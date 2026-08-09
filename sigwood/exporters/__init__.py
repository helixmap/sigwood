"""Log exporter orchestrator - backend, query, and output-path resolution.

Public entry point:
    run_export(config, backend, query_names, since, until, out, verbose,
               *, skip_confirm=False, use_utc=False)

Architecture:
    This module owns query resolution, backend selection, output-path naming,
    and the fetch/write loop. It does not know any backend's internals.

    Each backend is a module under exporters/ that exposes exactly four
    module-level callables (duck-typed - no base class, no registry file):

        is_configured(backend_cfg)  -> bool
            Used during auto-select to decide whether this backend is offerable.

        summary_descriptor(backend_cfg)  -> str
            Rendered into the `Backend :` line of the final summary, e.g.
            "host:port" for Splunk or "s3://bucket/prefix" for a future
            object-store backend.

        fetch(query_config, backend_config, since, until, verbose,
              *, skip_confirm=False) -> (rows, fetch_meta)
            fetch_meta carries at least {"units": int, "unit_label": str};
            that work-unit pair MUST be invariant across queries within the
            same (since, until) window for a given backend. The orchestrator
            enforces this because work-unit count is a property of the window,
            not the individual query.
            An optional ``notes`` list carries backend-authored, user-facing
            disclosures that the orchestrator prints after the affected result.
            skip_confirm bypasses any backend-side cost prompt; backends that
            have no prompt (Splunk) accept and ignore it.

        write(rows, outpath, verbose) -> (int, dict)
            Returns ``(line_count, write_meta)``. ``write_meta`` MUST carry at
            least ``{"bytes": int, "paths": list[Path]}`` - bytes is the total
            on-disk size summed across whatever files the backend produced,
            paths lists every file written (single-element when the backend
            does not split; ordered ``[_part01, _part02, …]`` when it does).
            The orchestrator never reaches into the writer's private split
            machinery - it reads the contract.

    Optional module-level hooks the orchestrator consults if present:

        implicit_default_query() -> dict
            Used when a backend has no per-query stanza (e.g. CloudTrail has
            no SPL). Returned dict becomes the synthetic "default" query.

        OUTPUT_EXTENSION: str
            Extension applied to auto-named output files. Default ".log".
            CloudTrail uses ".json.log".

    Adding a new backend means: (1) drop a module under exporters/ that
    implements those four callables; (2) add its name to _KNOWN_BACKENDS;
    (3) add a branch in _load_backend(). Nothing else changes here.

    Splunk's hourly chunking helper (_build_hour_windows) is private to
    splunk.py and is not reachable from this orchestrator.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import fcntl
import os
import shutil
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import uuid4

# ExportAborted lives in common.errors so runner.py and exporter backends can
# both raise it without creating a runner ↔ exporter dependency. Re-exported
# here so `from sigwood.exporters import ExportAborted` still works for
# existing call sites and external code.
from sigwood.common.display import (
    compact_home,
    fmt_compact_span,
    fmt_window,
    hidden_cursor,
    human_bytes,
    liveness,
    plural,
    set_display_utc,
    set_narration_enabled,
)
from sigwood.common.errors import ExportAborted, UsageError  # noqa: F401
from sigwood.common.loader.provenance import (
    PROVENANCE_LOCK_NAME,
    PROVENANCE_MANIFEST_NAME,
    PROVENANCE_SCHEMA_VERSION,
    PROVENANCE_STAGE_PREFIX,
    ProvenanceEntry,
    ProvenanceManifest,
    ProvenanceManifestError,
    canonical_manifest_bytes,
    hash_file,
    is_reserved_provenance_path,
    read_manifest,
)
from sigwood.common.paths import (
    be_like_water,
    effective_root,
    private_mkdir,
    private_open,
    private_write_bytes,
    resolve_path,
)
from sigwood.common.sanitize import strip_control


def _backend_cfg(config: dict[str, Any], name: str) -> dict[str, Any]:
    """Return the [export.<name>] stanza, or an empty dict if absent.

    Single read-site for backend config - keeps every fetch / is_configured /
    summary_descriptor / query lookup honest to the [export.<backend>] shape.
    """
    return config.get("export", {}).get(name, {})


def _normalize_end_of_day_until(until: datetime) -> datetime:
    """Normalize 23:59:xx (produced by --days) to next midnight for chunk alignment."""
    if until.hour == 23 and until.minute == 59 and until.second >= 58:
        return until.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    return until


def _resolve_export_window(
    since: datetime | None,
    until: datetime | None,
    *,
    display_now: datetime,
) -> tuple[datetime, datetime]:
    """Resolve the exporter's paired one-day default around supplied endpoints."""
    effective_until = (
        _normalize_end_of_day_until(until) if until is not None else None
    )
    if since is None and effective_until is None:
        today_midnight = display_now.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        resolved_since = today_midnight - timedelta(days=1)
        resolved_until = today_midnight
    elif since is None:
        assert effective_until is not None
        resolved_since = effective_until - timedelta(days=1)
        resolved_until = effective_until
    elif effective_until is None:
        resolved_since = since
        resolved_until = display_now
    else:
        resolved_since = since
        resolved_until = effective_until

    if resolved_until <= resolved_since:
        raise UsageError(
            f"export window is empty: "
            f"{fmt_window((resolved_since, resolved_until))}. "
            "The window start must be earlier than its end."
        )
    return resolved_since, resolved_until


_KNOWN_BACKENDS = ("splunk", "cloudtrail")


def _request_zone_identity(use_utc: bool) -> str | None:
    """Return the display/request interpretation zone without guessing."""
    if use_utc:
        return "Etc/UTC"
    env_zone = os.environ.get("TZ", "")
    candidates: list[str] = []
    if env_zone and not env_zone.startswith(":"):
        candidates.append(env_zone)
    try:
        resolved = Path("/etc/localtime").resolve(strict=True)
    except OSError:
        resolved = None
    if resolved is not None:
        parts = resolved.parts
        if "zoneinfo" in parts:
            index = len(parts) - 1 - list(reversed(parts)).index("zoneinfo")
            candidates.append("/".join(parts[index + 1:]))
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    except ImportError:
        return None
    for candidate in candidates:
        if not candidate or candidate.startswith("/"):
            continue
        try:
            ZoneInfo(candidate)
        except (ValueError, OSError, ZoneInfoNotFoundError):
            continue
        return candidate
    return None


def _tzdata_version() -> str | None:
    """Return an installed tzdata identity when one is inspectable."""
    try:
        value = importlib.metadata.version("tzdata")
    except importlib.metadata.PackageNotFoundError:
        value = ""
    if value:
        return value[:256]
    candidates = (
        Path("/usr/share/zoneinfo/tzdata.zi"),
        Path("/usr/share/zoneinfo/+VERSION"),
        Path("/var/db/timezone/zoneinfo/+VERSION"),
    )
    for path in candidates:
        try:
            with path.open("r", encoding="utf-8", errors="strict") as stream:
                first = stream.readline(512).strip()
        except (OSError, UnicodeError):
            continue
        if first.startswith("# version "):
            first = first.removeprefix("# version ").strip()
        if first and len(first) <= 256 and not any(ord(ch) < 0x20 for ch in first):
            return first
    return None


def _fsync_file(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _new_stage_directory(parent: Path) -> Path:
    private_mkdir(parent)
    for _ in range(10):
        candidate = parent / f"{PROVENANCE_STAGE_PREFIX}{uuid4().hex}"
        try:
            private_mkdir(candidate)
        except FileExistsError:
            continue
        return candidate
    raise OSError("could not create a unique export staging directory")


def _validate_staged_write(
    stage_dir: Path,
    write_meta: dict[str, Any],
) -> list[tuple[Path, Path, int, str]]:
    raw_paths = write_meta.get("paths")
    if (
        not isinstance(raw_paths, list)
        or not raw_paths
        or any(not isinstance(path, Path) for path in raw_paths)
    ):
        raise ValueError("exporter backend returned invalid write metadata paths")
    staged: list[tuple[Path, Path, int, str]] = []
    names: set[str] = set()
    for path in raw_paths:
        if path.parent != stage_dir or path.name in names:
            raise ValueError("exporter backend returned an escaping or duplicate path")
        try:
            info = path.lstat()
        except OSError as exc:
            raise ValueError("exporter backend returned a missing output path") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError("exporter backend output is not a regular file")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("exporter backend output is not private (expected 0600)")
        names.add(path.name)
        staged.append((path, stage_dir.parent / path.name, info.st_size, hash_file(path)))
    declared_bytes = write_meta.get("bytes")
    if (
        isinstance(declared_bytes, bool)
        or not isinstance(declared_bytes, int)
        or declared_bytes != sum(item[2] for item in staged)
    ):
        raise ValueError("exporter backend returned inconsistent write byte metadata")
    return staged


def _commit_export_provenance(
    staged: list[tuple[Path, Path, int, str]],
    *,
    since: datetime,
    until: datetime,
    backend: str,
    request_zone: str | None,
    tzdata_version: str | None,
) -> dict[str, Any]:
    parent = staged[0][1].parent
    if any(final.parent != parent for _, final, _, _ in staged):
        raise ValueError("one backend write returned files in multiple directories")
    requested_start = since.astimezone(timezone.utc)
    requested_end = until.astimezone(timezone.utc)
    entries = {
        final.name: ProvenanceEntry(
            schema_version=PROVENANCE_SCHEMA_VERSION,
            content_sha256=digest,
            size_bytes=size,
            requested_start_utc=requested_start,
            requested_end_utc=requested_end,
            request_zone=request_zone,
            tzdata_version=tzdata_version,
            exporter="sigwood",
            backend=backend,
            completion="success",
        )
        for _, final, size, digest in staged
    }
    # Validate the complete entry shape before acquiring the lock or replacing
    # any final data.  In particular, a backend-returned reserved/control-bearing
    # basename must never fail only after it has already mutated the destination.
    canonical_manifest_bytes(ProvenanceManifest(
        schema_version=PROVENANCE_SCHEMA_VERSION,
        generation=1,
        written_at=datetime.now(timezone.utc),
        entries=entries,
    ))
    lock_path = parent / PROVENANCE_LOCK_NAME
    manifest_path = parent / PROVENANCE_MANIFEST_NAME
    stage_dir = staged[0][0].parent
    staged_manifest = stage_dir / PROVENANCE_MANIFEST_NAME
    with private_open(lock_path, encoding="utf-8") as lock_stream:
        if not stat.S_ISREG(os.fstat(lock_stream.fileno()).st_mode):
            raise ValueError("export provenance lock is not a regular file")
        fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
        try:
            try:
                current = read_manifest(manifest_path)
            except FileNotFoundError:
                generation = 0
                merged: dict[str, ProvenanceEntry] = {}
            except ProvenanceManifestError as exc:
                raise ValueError(
                    f"could not update {manifest_path}: existing provenance "
                    "manifest is malformed"
                ) from exc
            else:
                generation = current.generation
                merged = dict(current.entries)
            merged.update(entries)
            for staged_path, final_path, _, _ in staged:
                _fsync_file(staged_path)
                os.replace(staged_path, final_path)
            manifest = ProvenanceManifest(
                schema_version=PROVENANCE_SCHEMA_VERSION,
                generation=generation + 1,
                written_at=datetime.now(timezone.utc),
                entries=merged,
            )
            private_write_bytes(staged_manifest, canonical_manifest_bytes(manifest))
            _fsync_file(staged_manifest)
            os.replace(staged_manifest, manifest_path)
            _fsync_directory(parent)
        finally:
            fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)
    return {
        "bytes": sum(item[2] for item in staged),
        "paths": [item[1] for item in staged],
    }


def run_export(
    config: dict[str, Any],
    backend: str | None,
    query_names: list[str],
    since: datetime | None,
    until: datetime | None,
    out: str | None,
    verbose: bool,
    *,
    skip_confirm: bool = False,
    use_utc: bool = False,
) -> None:
    """Pull log data from an external system and write to local flat files.

    Args:
        config: Loaded config dict (from common/config.py).
        backend: Backend name ("splunk", etc.) or None to auto-select.
        query_names: Named queries to run. An empty list auto-selects only when
            exactly one query is defined.
        since: Start of window. When both endpoints are absent, the pair is
            yesterday/today at display-timezone midnight. When only since is
            present, the end is the current instant.
        until: End of window. When only until is present, the start is one day
            earlier. See ``since`` for the both-absent default.
        out: Raw CLI --out string (preserves trailing slash) or None.
            be_like_water decides file-vs-directory inside the cascade.
        verbose: Threaded to fetch() / write() for backend-internal use
            (e.g. CloudTrail's list-phase line at level >= 1). The narration
            grammar keeps stdout terse and identical across levels - no
            per-query SPL block, no auto-select chatter.
        skip_confirm: When True, skip any backend-side cost prompts (e.g. the
            CloudTrail egress guard). Threaded from the CLI's --yes / -y flag.
        use_utc: Display timezone for the window narration AND the anchor for
            the no-timeframe default window above. Set at entry; the window
            handed to backends stays timezone-aware either way.
    """
    set_narration_enabled(True)
    with hidden_cursor():
        return _run_export(
            config,
            backend,
            query_names,
            since,
            until,
            out,
            verbose,
            skip_confirm=skip_confirm,
            use_utc=use_utc,
        )


def _run_export(
    config: dict[str, Any],
    backend: str | None,
    query_names: list[str],
    since: datetime | None,
    until: datetime | None,
    out: str | None,
    verbose: bool,
    *,
    skip_confirm: bool = False,
    use_utc: bool = False,
) -> None:
    # Display timezone for the window narration line. Set at entry so
    # programmatic callers inherit it; the CLI export path resolved the same
    # value before parsing the timeframe.
    set_display_utc(use_utc)

    # Resolve one paired default. An unqualified export remains yesterday in
    # the display timezone; a supplied endpoint owns the missing endpoint.
    display_now = (
        datetime.now(timezone.utc) if use_utc else datetime.now().astimezone()
    )
    since, until = _resolve_export_window(
        since, until, display_now=display_now
    )

    # Resolve backend and load its module
    resolved_backend = _resolve_backend(config, backend)
    backend_module = _load_backend(resolved_backend)

    # Resolve queries (backends with no per-query config supply a synthetic
    # default via implicit_default_query()).
    resolved_queries = _resolve_queries(
        config, resolved_backend, query_names, backend_module=backend_module
    )

    # Guard: an explicit file path target is incompatible with multiple queries.
    # Re-expressed in terms of be_like_water's verdict - never .suffix.
    if out is not None:
        cli_resolved = be_like_water(out)
        if cli_resolved.is_file and len(resolved_queries) > 1:
            raise ValueError(
                f"cannot use an explicit file path ({cli_resolved.path}) with "
                f"multiple queries - specify a directory"
            )

    window_str = fmt_window((since, until))

    # Fetch and write each query. fetch() returns (rows, fetch_meta); the
    # orchestrator keeps the first query's fetch_meta as the run-level work-unit
    # descriptor and asserts later queries agree (the metadata is a property of
    # the window, not the query). write() returns (line_count, write_meta) where
    # write_meta carries {"bytes": int, "paths": list[Path]} - the orchestrator
    # is backend-neutral and does not know about splitting.
    extension = getattr(backend_module, "OUTPUT_EXTENSION", ".log")
    backend_cfg = _backend_cfg(config, resolved_backend)
    sigwood_cfg = config.get("sigwood", {})
    root = effective_root(config)

    # Resolve every query's output path up front so the header line can land
    # before the first fetch. NO bulk-fetch pre-pass - each query streams
    # fetch → write in turn so a long export doesn't hold every result set in
    # RAM, the first result line appears promptly, and a later query's failure
    # doesn't void earlier successfully-written queries.
    plan: list[tuple[str, dict[str, Any], Path]] = []
    for query_name, query_cfg in resolved_queries:
        outpath = _resolve_output_path(
            query_cfg, out, since, until, query_name,
            extension=extension,
            backend_config=backend_cfg,
            sigwood_config=sigwood_cfg,
            root=root,
        )
        if is_reserved_provenance_path(outpath):
            raise ValueError(
                f"{outpath} is reserved for sigwood export provenance; "
                "choose another export path"
            )
        plan.append((query_name, query_cfg, outpath))

    # Header - single plain stdout line. No box, no seplines, NO color, no
    # auto-select chatter on stderr.
    print(
        f"sigwood export · {resolved_backend} "
        f"({strip_control(backend_module.summary_descriptor(backend_cfg))})"
    )

    def _span_str() -> str:
        """Duration-only span for the window line. The work-unit count moved to
        the live fetch bar - narration carries the human duration only."""
        total_secs = (until - since).total_seconds()
        # _resolve_export_window guarantees a positive duration before orchestration.
        if total_secs % 86400 == 0:
            n_days = int(total_secs / 86400)
            return f"{n_days} {plural(n_days, 'day')}"
        return fmt_compact_span(until - since)

    def _emit_result_line(
        query_name: str, n_written: int, write_meta: dict[str, Any],
        fallback_path: Path,
    ) -> tuple[int, int]:
        """Print the ONE per-query result line and return (n_written, bytes)."""
        paths = list(write_meta.get("paths") or [fallback_path])
        bytes_written = int(write_meta.get("bytes", 0))
        path_display = compact_home(paths[0])
        if len(paths) > 1:
            path_display += f" (+{len(paths) - 1} more)"
        print(
            f"{strip_control(query_name)} · {n_written:,} lines · "
            f"{human_bytes(bytes_written)} → {strip_control(path_display)}"
        )
        return n_written, bytes_written

    # window line lands BEFORE the first fetch - its bounds + span are known
    # from since/until alone (no bulk pre-fetch). The work-unit count rides the
    # live fetch bar instead.
    print(f"window: {window_str}  ·  {_span_str()}")

    grand_lines = 0
    grand_bytes = 0
    run_fetch_meta: dict[str, Any] | None = None
    n_queries = len(plan)
    request_zone = _request_zone_identity(use_utc)
    tzdata_version = _tzdata_version()

    # One uniform streaming loop: fetch → validate/agree fetch_meta → write →
    # the one result line. Streaming preserves partial-success durability
    # (earlier queries are on disk before later queries even start) and keeps
    # peak memory near one query's result set, not N.
    for query_name, query_cfg, outpath in plan:
        rows, fetch_meta = backend_module.fetch(
            query_cfg, backend_cfg, since, until, verbose,
            skip_confirm=skip_confirm,
        )
        if run_fetch_meta is None:
            run_fetch_meta = fetch_meta
            try:
                _ = fetch_meta["units"]
                _ = fetch_meta["unit_label"]
            except (KeyError, TypeError) as exc:
                raise ValueError(
                    f"exporter backend '{resolved_backend}' returned invalid "
                    f"fetch metadata - missing 'units' or 'unit_label'"
                ) from exc
        elif (fetch_meta.get("units"), fetch_meta.get("unit_label")) != (
            run_fetch_meta.get("units"), run_fetch_meta.get("unit_label")
        ):
            raise ValueError(
                f"exporter backend '{resolved_backend}' returned inconsistent fetch "
                f"metadata across queries for the same window - this is a backend bug"
            )
        notes = fetch_meta.get("notes", ())
        if (
            isinstance(notes, (str, bytes))
            or not isinstance(notes, (list, tuple))
            or any(not isinstance(note, str) for note in notes)
        ):
            raise ValueError(
                f"exporter backend '{resolved_backend}' returned invalid fetch "
                "metadata - 'notes' must be a list of strings"
            )
        stage_dir = _new_stage_directory(outpath.parent)
        try:
            staged_outpath = stage_dir / outpath.name
            n_written, staged_meta = backend_module.write(
                rows, staged_outpath, verbose,
            )
            rows = None  # type: ignore[assignment]
            staged = _validate_staged_write(stage_dir, staged_meta)
            write_meta = _commit_export_provenance(
                staged,
                since=since,
                until=until,
                backend=resolved_backend,
                request_zone=request_zone,
                tzdata_version=tzdata_version,
            )
        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)
        nl, nb = _emit_result_line(query_name, n_written, write_meta, outpath)
        for note in notes:
            print(f"note: {strip_control(note)}")
        grand_lines += nl
        grand_bytes += nb

    # Tally line only when there is more than one query to total.
    if n_queries > 1:
        print(
            f"done · {n_queries} {plural(n_queries, 'query', 'queries')} · "
            f"{grand_lines:,} lines · {human_bytes(grand_bytes)}"
        )


def _resolve_backend(config: dict[str, Any], backend: str | None) -> str:
    """Resolve which backend to use based on config and explicit request.

    Each backend module decides for itself whether its config section is
    sufficient via ``is_configured(backend_cfg)``. The orchestrator iterates
    _KNOWN_BACKENDS, asks each, and collects the names that say yes.
    """
    configured: list[str] = []
    for name in _KNOWN_BACKENDS:
        try:
            module = _load_backend(name)
        except ValueError:
            # Backend listed as known but not yet implemented (e.g. cloudtrail
            # before its module lands). Not auto-selectable.
            continue
        if module.is_configured(_backend_cfg(config, name)):
            configured.append(name)

    if backend is None:
        if len(configured) == 1:
            # The new header (printed by run_export) names the backend - no
            # stray pre-fetch chatter on auto-select.
            return configured[0]
        elif len(configured) == 0:
            raise ValueError(
                "no export backend configured - add a [export.splunk] section "
                "with a host, or run: sigwood init"
            )
        else:
            available = ", ".join(sorted(configured))
            raise ValueError(
                f"multiple backends configured: {available} - "
                f"specify one: sigwood export <backend>"
            )

    if backend not in _KNOWN_BACKENDS:
        available = ", ".join(_KNOWN_BACKENDS)
        raise ValueError(f"unknown backend '{backend}' - available: {available}")

    module = _load_backend(backend)  # may raise "not yet implemented" - that's correct
    if not module.is_configured(_backend_cfg(config, backend)):
        raise ValueError(
            f"backend '{backend}' is not configured - "
            f"add a [export.{backend}] section (see config_example.toml)"
        )
    return backend


def _resolve_queries(
    config: dict[str, Any],
    backend: str,
    query_names: list[str],
    *,
    backend_module: ModuleType | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """Resolve query names to (name, config) pairs.

    Empty query_names auto-selects only when exactly one query is defined.
    Multiple defined queries with no name given raise ValueError.

    If the backend has no queries configured AND exposes an
    ``implicit_default_query()`` hook, a synthetic single "default" query is
    used (this is how CloudTrail - which has no per-query SPL - participates).
    """
    queries: dict[str, Any] = _backend_cfg(config, backend).get("query", {})
    if (not queries
            and backend_module is not None
            and hasattr(backend_module, "implicit_default_query")):
        queries = {"default": backend_module.implicit_default_query()}

    if not query_names:
        if len(queries) == 1:
            name = next(iter(queries))
            return [(name, queries[name])]
        elif len(queries) == 0:
            raise ValueError(
                f"no queries defined under [export.{backend}.query] - "
                f"add a [export.{backend}.query.<name>] section"
            )
        else:
            available = ", ".join(sorted(queries))
            raise ValueError(
                f"multiple queries for backend '{backend}': {available} - "
                f"specify one: sigwood export {backend} <query>"
            )

    result = []
    for name in query_names:
        if name not in queries:
            available = ", ".join(sorted(queries))
            raise ValueError(
                f"query '{name}' not found in [export.{backend}.query] - "
                f"available: {available}"
            )
        result.append((name, queries[name]))
    return result


def _resolve_output_path(
    query_config: dict[str, Any],
    cli_out: str | None,
    since: datetime,
    until: datetime,
    query_name: str,
    *,
    extension: str = ".log",
    backend_config: dict[str, Any] | None = None,
    sigwood_config: dict[str, Any] | None = None,
    root: str = "",
) -> Path:
    """Resolve the final output path for a single query result.

    Five-tier cascade (most-specific wins):
      1. cli_out                              (--out, expanded with root="" - shell semantics)
      2. query_config["export_dir"]           (per-query - finest grain; config, root applies)
      3. backend_config["export_dir"]         ([export.<backend>].export_dir; config, root applies)
      4. sigwood_config["export_dir"]         (global default; config, root applies)
      5. "."                                  (CWD floor - literal, not a resolved value)

    The winning target string is passed through ``be_like_water`` to decide
    file vs directory. For a FILE verdict the path is returned as-is; for a
    DIRECTORY verdict an auto-name is appended.

    **Per-source auto-segmentation of the global base.** When the global tier
    (4) wins, ``[sigwood].export_dir`` is treated as a directory BASE and each
    export is written to ``<base>/<source>/`` (``source = output_basename or
    query_name`` - the log-family the admin chose, NOT the transport backend),
    so sigwood never builds the flat pile its own discovery globs cross-read.
    The global base is a directory base regardless of disk state (it ships with
    a trailing slash; a file-shaped global base is meaningless as a multi-source
    base). Every other tier - CLI ``--out``, an explicit per-query / per-backend
    ``export_dir``, and the CWD floor - is the LITERAL final dir and does NOT
    segment. The ``from_global_base`` flag returned by ``_pick_export_target``
    is the sole signal; callers never see it.

    ``extension`` is appended to the auto-named filename and is supplied by the
    backend via its optional ``OUTPUT_EXTENSION`` module attribute.

    ``root`` is the SIGWOOD_ROOT for relative config paths; the caller reads it once
    via ``effective_root(config)`` and threads it in.
    """
    # Compute the source basename ONCE, up front: it drives both the directory
    # segment (global tier) and the auto-named filename.
    basename = query_config.get("output_basename") or query_name
    target, from_global_base = _pick_export_target(
        cli_out, query_config, backend_config, sigwood_config, root=root,
    )
    if from_global_base:
        # Segment the global base BEFORE be_like_water: normalize to exactly one
        # trailing separator, then append the source segment with directory
        # intent. ``Path(basename).name`` is defensive - basename is a bare
        # log-family name by contract, and ``.name`` collapses any stray
        # separator so a segment can never escape the base. The trailing slash
        # yields a be_like_water DIRECTORY verdict even when <base>/<source>/
        # does not exist yet (ladder rule 1), so it still auto-names.
        target = target.rstrip("/") + "/" + Path(basename).name + "/"
    resolved = be_like_water(target)
    if resolved.is_file:
        return resolved.path
    return resolved.path / _auto_filename(basename, since, until, extension=extension)


def _pick_export_target(
    cli: str | None,
    query: dict[str, Any] | None,
    backend: dict[str, Any] | None,
    sigwood: dict[str, Any] | None,
    *,
    root: str = "",
) -> tuple[str, bool]:
    """Return ``(target, from_global_base)`` for the five-tier cascade.

    ``target`` is the first set target STRING across the cascade;
    ``from_global_base`` is True iff the WINNING tier is
    ``sigwood["export_dir"]`` (tier 4) - the only tier that auto-segments per
    source (see ``_resolve_output_path``). It is a real returned bool, not an
    overloaded sentinel, and is consumed ONLY by ``_resolve_output_path``;
    callers and backend modules never reason about it.

    Preserves trailing slashes by working in strings, not Paths. CLI tier
    resolves with root="" (shell semantics - ~-expansion only); the three
    config tiers resolve through ``resolve_path(value, root)`` so SIGWOOD_ROOT
    applies. The CWD floor stays a literal "." even though
    ``resolve_path("", root)`` returns None for empty config values. Every
    config tier - per-query, per-backend, and global - uses the single
    ``export_dir`` key.
    """
    if cli is not None:
        resolved = resolve_path(cli, "")
        if resolved is not None:
            return resolved, False
    for stanza, key, is_global in [
        (query, "export_dir", False),
        (backend, "export_dir", False),
        (sigwood, "export_dir", True),
    ]:
        if stanza:
            value = stanza.get(key)
            if value:
                resolved = resolve_path(value, root)
                if resolved is not None:
                    return resolved, is_global
    return ".", False


def _auto_filename(
    basename: str,
    since: datetime,
    until: datetime,
    *,
    extension: str = ".log",
) -> str:
    """Derive an output filename from the time window.

    Whole-day windows (both endpoints at midnight, integer days):
        {basename}_{YYYYMMDD}_{N}d{extension}

    All other windows (partial day, arbitrary range):
        {basename}_{YYYYMMDD}_to_{YYYYMMDD_HHh}{extension}
    """
    local_since = since.astimezone() if since.tzinfo else since
    local_until = until.astimezone() if until.tzinfo else until

    start_str = local_since.strftime("%Y%m%d")

    since_at_midnight = (
        local_since.hour == 0 and local_since.minute == 0 and local_since.second == 0
    )
    until_at_midnight = (
        local_until.hour == 0 and local_until.minute == 0 and local_until.second == 0
    )

    if since_at_midnight and until_at_midnight:
        n_days = int((local_until - local_since).total_seconds() // 86400)
        if n_days >= 1:
            return f"{basename}_{start_str}_{n_days}d{extension}"

    end_str = local_until.strftime("%Y%m%d_%Hh")
    return f"{basename}_{start_str}_to_{end_str}{extension}"


def _load_backend(backend_name: str) -> ModuleType:
    """Import and return the backend module for the given backend name."""
    if backend_name == "splunk":
        from sigwood.exporters import splunk as splunk_module
        return splunk_module
    if backend_name == "cloudtrail":
        from sigwood.exporters import cloudtrail as cloudtrail_module
        return cloudtrail_module
    raise ValueError(f"backend '{backend_name}' is not yet implemented")
