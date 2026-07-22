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
            fetch_meta carries at least {"units": int, "unit_label": str} and
            MUST be invariant across queries within the same (since, until)
            window for a given backend - work-unit count is a property of the
            window, not the individual query. The orchestrator enforces this.
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

# ExportAborted lives in common.errors so runner.py and exporter backends can
# both raise it without creating a runner ↔ exporter dependency. Re-exported
# here so `from sigwood.exporters import ExportAborted` still works for
# existing call sites and external code.
from sigwood.common.display import (
    compact_home,
    fmt_window,
    hidden_cursor,
    human_bytes,
    liveness,
    plural,
    set_display_utc,
    set_narration_enabled,
)
from sigwood.common.errors import ExportAborted  # noqa: F401  (re-export)
from sigwood.common.paths import be_like_water, effective_root, resolve_path
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


_KNOWN_BACKENDS = ("splunk", "cloudtrail")


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
        query_names: Named queries to run. Empty list uses default/single logic.
        since: Start of window, or None to use yesterday 00:00:00 in the
            display timezone (local, or UTC under --utc / use_utc).
        until: End of window, or None to use today 00:00:00 in the display
            timezone.
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

    # Apply timeframe defaults independently - anchored on display-timezone
    # midnights, so an unqualified export means the same "yesterday" the
    # rendered window shows.
    display_now = (
        datetime.now(timezone.utc) if use_utc else datetime.now().astimezone()
    )
    today_midnight = display_now.replace(hour=0, minute=0, second=0, microsecond=0)
    if since is None:
        since = today_midnight - timedelta(days=1)   # yesterday 00:00:00 display-tz
    if until is None:
        until = today_midnight                        # today 00:00:00 display-tz (exclusive end)
    until = _normalize_end_of_day_until(until)

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
        if total_secs > 0 and total_secs % 86400 == 0:
            n_days = int(total_secs / 86400)
            return f"{n_days} {plural(n_days, 'day')}"
        return f"{max(int(total_secs / 3600), 1)}h"

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
        n_written, write_meta = backend_module.write(rows, outpath, verbose)
        rows = None  # type: ignore[assignment]
        nl, nb = _emit_result_line(query_name, n_written, write_meta, outpath)
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

    Empty query_names uses auto-selection: "default" if it exists, or the only
    defined query. Multiple defined queries with no name given raises ValueError.

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
        if "default" in queries:
            return [("default", queries["default"])]
        elif len(queries) == 1:
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
