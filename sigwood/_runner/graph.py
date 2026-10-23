"""Graph source loading, window selection, payload assembly, and rendering."""
from __future__ import annotations

import math
import os
import shlex
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from sigwood.common.config import parse_window_span, validate_table_sections
from sigwood.common.display import (
    default_window_advisory,
    hidden_cursor,
    set_display_utc,
    set_narration_enabled,
    to_display_timezone,
)
from sigwood.common.errors import GraphEmpty, GraphSourceUnreadable
from sigwood.common.loader import FileSpan
from sigwood.common.paths import private_mkdir, private_write_text
from sigwood.common.sanitize import strip_control
from sigwood.common.sources import GraphKindSpec


def _graph_source_label(paths: Sequence[Path]) -> str:
    """Return an aggregate source identity for graph metadata/control signals."""
    if not paths:
        return "graph source"
    return ", ".join(strip_control(path.name) for path in paths)


def _graph_contributing_file_meta(
    spans: Sequence[FileSpan],
    t0: float,
    t1: float,
) -> dict[str, str | int]:
    """Return source provenance for files overlapping the final graph window."""
    contributing = [
        span for span in spans
        if span.last_ts >= t0 and span.first_ts <= t1
    ]
    selected = contributing or list(spans)
    paths = sorted(
        (span.path for span in selected),
        key=lambda path: os.path.abspath(path),
    )
    if not paths:
        return {"file_sample": "", "file_count": 0, "common_dir": ""}

    absolute = [os.path.abspath(path) for path in paths]
    sample = strip_control(Path(absolute[0]).name)
    try:
        common = (
            str(Path(absolute[0]).parent)
            if len(absolute) == 1
            else os.path.commonpath(absolute)
        )
    except (OSError, ValueError):
        common = ""
    return {
        "file_sample": sample,
        "file_count": len(paths),
        "common_dir": strip_control(common),
    }


def _graph_date_dir_window(
    source_inputs: Sequence[Path], *, use_utc: bool,
) -> tuple[datetime, datetime] | None:
    """Return one display-day window for an exact date-named Zeek directory."""
    if len(source_inputs) != 1:
        return None
    target = source_inputs[0]
    try:
        if not target.is_dir():
            return None
        parsed = date.fromisoformat(target.name)
        from sigwood.common import loader
        if loader._zeek_date_subdirs(target):
            return None
    except (OSError, ValueError):
        return None

    start = datetime(parsed.year, parsed.month, parsed.day)
    end = start.replace(hour=23, minute=59, second=59)
    if use_utc:
        return (
            start.replace(tzinfo=timezone.utc),
            end.replace(tzinfo=timezone.utc),
        )
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def _graph_hunt_hint(
    payload: dict[str, Any],
    *,
    spec: GraphKindSpec,
    source_inputs: Sequence[Path],
    has_explicit_inputs: bool,
) -> str | None:
    """Compose one paste-safe hunt command for a graph artifact's exact frame."""
    from sigwood.common import loader

    if (
        spec.source_key == "zeek_dir"
        and has_explicit_inputs
        and any(
            path.is_file() and not loader._file_matches_pattern(path, spec.pattern)
            for path in source_inputs
        )
    ):
        return None

    meta = payload["meta"]
    since = math.floor(float(meta["t0"]))
    until = math.ceil(float(meta["t1"]))
    since_text = to_display_timezone(
        datetime.fromtimestamp(since, tz=timezone.utc),
    ).isoformat(timespec="seconds")
    until_text = to_display_timezone(
        datetime.fromtimestamp(until, tz=timezone.utc),
    ).isoformat(timespec="seconds")
    quoted_inputs = " ".join(
        shlex.quote(os.path.abspath(path)) for path in source_inputs
    )
    return (
        f"sigwood hunt {quoted_inputs} --since={since_text} "
        f"--until={until_text}"
    )


def run_graph(
    config: dict[str, Any],
    *,
    kind: str,
    inputs: str | Path | Sequence[str | Path] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    output_file: Path | None = None,
    stream: Any = None,
    load_all: bool = False,
    skip_confirm: bool = False,
    quiet: bool = False,
    use_utc: bool = False,
    show_progress: bool = True,
) -> Path | None:
    """Build and render one same-kind graph bucket.

    The CLI owns sniffing, fan-out, target selection, dry-run, and final exit
    precedence. This runner entry owns exactly one already-selected graph kind:
    it resolves raw/config source inputs, asks the loader for its full
    :class:`LoadResult`, applies the shared Zeek default-window policy, builds a
    payload without allowlist construction, and writes one exact HTML target or
    supplied stream. There is deliberately no ``dry_run`` argument here.
    ``skip_confirm`` remains a compatibility no-op because graph density is
    bounded by build-time degradation instead of a record-count prompt.
    """
    set_narration_enabled(not quiet)
    with hidden_cursor():
        return _run_graph(
            config,
            kind=kind,
            inputs=inputs,
            since=since,
            until=until,
            output_file=output_file,
            stream=stream,
            load_all=load_all,
            skip_confirm=skip_confirm,
            quiet=quiet,
            use_utc=use_utc,
            show_progress=show_progress,
        )


def _run_graph(
    config: dict[str, Any],
    *,
    kind: str,
    inputs: str | Path | Sequence[str | Path] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    output_file: Path | None = None,
    stream: Any = None,
    load_all: bool = False,
    skip_confirm: bool = False,
    quiet: bool = False,
    use_utc: bool = False,
    show_progress: bool = True,
) -> Path | None:
    from sigwood.common import loader
    from sigwood.graph import get_builder
    from sigwood.graph._core import (
        _format_degrade_note,
        attach_hunt_hint,
        validate_config,
    )
    from sigwood.outputs.graph import render_graph_html

    validate_table_sections(config, ("sigwood", "graph"))
    set_display_utc(use_utc)
    if output_file is not None and stream is not None:
        raise ValueError("output_file and stream are mutually exclusive")

    # get_builder is the public graph dispatch/validation seam. Derive source
    # facts from the same ordered declaration so adding a graph kind cannot create
    # a CLI/runner routing ladder.
    builder = get_builder(kind)
    spec, source_inputs = runner.resolve_graph_source(config, kind, inputs=inputs)
    if not source_inputs:
        raise ValueError(
            f"{spec.source_key} not configured - pass a PATH or "
            f"set [sigwood].{spec.source_key} in your config"
        )
    for path in source_inputs:
        if not path.exists():
            raise ValueError(f"{path}: not found")

    graph_config = validate_config(config.get("graph", {}))
    source_label = _graph_source_label(source_inputs)
    needed_logs = {spec.pattern: spec.source_key}
    source_dirs = {spec.source_key: source_inputs}
    # Only a caller-supplied input carries the graph kind assertion. Config
    # fallback files remain ordinary source inputs and keep filename discovery
    # policy, so a misconfigured dns.log can never be treated as conn merely
    # because a programmatic caller requested the conn builder.
    from sigwood.common.sources import graph_has_explicit_inputs
    has_explicit_inputs = graph_has_explicit_inputs(inputs)
    trusted_files = [
        path for path in source_inputs
        if has_explicit_inputs and path.is_file()
    ]

    # Graph windows through the same universal resolver as analyze. The resolver's
    # non-empty return is the one authoritative fact for artifact disclosure;
    # it holds across dated-select, flat-trim, and flat-floor window shapes. A
    # flat floor selects files only - the post-load trim owns the row window.
    cfg_sigwood = config.get("sigwood", {})
    default_spec = cfg_sigwood.get("default_window", "7d")
    operator_since, operator_until = since, until
    date_dir_note: str | None = None
    if (
        spec.source_key == "zeek_dir"
        and since is None
        and until is None
        and not load_all
        and parse_window_span(default_spec) is not None
    ):
        date_dir_window = _graph_date_dir_window(
            source_inputs, use_utc=use_utc,
        )
        if date_dir_window is not None:
            since, until = date_dir_window
            date_dir_note = (
                f"windowed to {source_inputs[0].name} "
                "(date-named directory) - pass --all or --since/--until to change"
            )
            if kind == "conn":
                date_dir_note += (
                    "; connections that began before that day are not shown"
                )
    load_windows = loader.resolve_load_windows(
        needed_logs,
        source_dirs,
        default_spec,
        since=since,
        until=until,
        load_all=load_all,
    )
    allow_tail_trim = (
        operator_since is None
        and operator_until is None
        and not load_all
        and parse_window_span(default_spec) is not None
        and date_dir_note is None
        and not load_windows
    )
    default_window_note = date_dir_note
    source_windows: dict[str, tuple[datetime | None, datetime | None]] | None = None
    file_select_windows: (
        dict[str, tuple[datetime | None, datetime | None]] | None
    ) = None
    flat_span: timedelta | None = None
    keep_null = False
    if load_windows:
        window = load_windows[0]
        open_ended = (
            window.trim_span is None
            and window.select_window is not None
            and window.select_window[1] is None
        )
        default_window_note = default_window_advisory(
            default_spec, open_ended=open_ended,
        )
        if window.trim_span is None and window.select_window is not None:
            source_windows = {spec.source_key: window.select_window}
        elif window.trim_span is not None:
            flat_span = window.trim_span
            keep_null = window.keep_null
            if window.select_window is not None:
                file_select_windows = {
                    spec.source_key: window.select_window,
                }

    load_result = loader.load_required_logs(
        needed_logs,
        source_dirs,
        since,
        until,
        source_windows=source_windows,
        show_progress=show_progress and not quiet,
        file_select_windows=file_select_windows,
        trusted_files={spec.pattern: trusted_files},
    )
    if flat_span is not None:
        load_result = loader.apply_default_window(
            load_result, [spec.pattern], flat_span, keep_null=keep_null,
        )
    for warning in load_result.warnings:
        runner._estderr(warning)
    if not quiet:
        for pattern, info in load_result.rotation_skips.items():
            if info.fallback:
                label = runner._pattern_human_label(needed_logs[pattern], pattern)
                runner._estderr(runner._rotation_fallback_line(label, info))

    # Strict graph accounting deliberately happens before the clean-empty
    # branch: an unreadable requested source is operationally incomplete even
    # if a sibling yielded an artifact-shaped frame.
    permission_error = runner._permission_denied_run_error(
        load_result, needed_logs, strict=True,
    )
    if permission_error is not None:
        raise GraphSourceUnreadable(kind, source_label, permission_error)

    frame = load_result.logs.get(spec.pattern)
    date_window_widened = False
    if (frame is None or frame.empty) and date_dir_note is not None:
        retry_result = loader.load_required_logs(
            needed_logs,
            source_dirs,
            None,
            None,
            show_progress=show_progress and not quiet,
            trusted_files={spec.pattern: trusted_files},
        )
        for warning in retry_result.warnings:
            runner._estderr(warning)
        retry_permission_error = runner._permission_denied_run_error(
            retry_result, needed_logs, strict=True,
        )
        if retry_permission_error is not None:
            raise GraphSourceUnreadable(
                kind, source_label, retry_permission_error,
            )
        load_result = retry_result
        frame = load_result.logs.get(spec.pattern)
        if frame is not None and not frame.empty:
            default_window_note = None
            date_window_widened = True

    if frame is None or frame.empty:
        selected = since is not None or until is not None or bool(load_windows)
        reason = "no records in selected window" if selected else "no parseable records"
        raise GraphEmpty(kind, source_label, reason)

    with runner.liveness(f"building {kind} graph", enabled=not quiet):
        payload = builder(
            frame,
            config=graph_config,
            source_label=source_label,
            default_window_note=default_window_note,
            display_utc=use_utc,
            trim_sparse_edges=allow_tail_trim,
        )
    payload["meta"]["date_window_widened"] = date_window_widened
    degrade_note = _format_degrade_note(payload["meta"])
    payload["meta"]["degrade_note"] = degrade_note
    if degrade_note is not None and not quiet:
        runner._estderr(degrade_note)
    if not quiet:
        for note_key in ("band_loss_note", "straddler_note"):
            note = payload["meta"].get(note_key)
            if note:
                runner._estderr(str(note))
    graph_meta = payload["meta"]
    graph_meta.update(_graph_contributing_file_meta(
        load_result.file_spans.get(spec.pattern, ()),
        float(graph_meta["t0"]),
        float(graph_meta["t1"]),
    ))
    attach_hunt_hint(
        payload,
        _graph_hunt_hint(
            payload,
            spec=spec,
            source_inputs=source_inputs,
            has_explicit_inputs=has_explicit_inputs,
        ),
    )
    html = render_graph_html(payload)

    # Do not create a directory or touch an exact target until the loader,
    # builder, and strict JSON-in-script renderer have all succeeded.
    if output_file is not None:
        private_mkdir(output_file.parent)
        private_write_text(output_file, html, encoding="utf-8", newline="")
        return output_file
    if stream is None:
        stream = sys.stdout
    stream.write(html)
    return None



# Bind the module after defining the re-exports so either import order works.
# Collaborator attributes are resolved only when the functions run.
import sigwood.runner as runner
