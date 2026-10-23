"""Digest source loading, temporal summaries, card assembly, and rendering."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from sigwood.common.display import (
    default_window_advisory,
    fmt_timestamp,
    fmt_window,
    hidden_cursor,
    set_display_utc,
    set_narration_enabled,
)
from sigwood.common.errors import DigestEmpty
from sigwood.common.sanitize import strip_control
from sigwood.common.sources import resolve_digest_source


def _ts_confidence(frame: pd.DataFrame) -> bool:
    """True iff the frame's ``ts`` column can support a representative timeline.

    Both conditions must hold:

    1. ``parsed / total >= _DIGEST_TS_CONFIDENCE_FLOOR`` (default 0.80) -
       the parseable-ts fraction is high enough that the histogram bins
       reflect the bulk of the records.
    2. ``max(ts) - min(ts) > 0`` - the non-NaN timestamps span more than a
       single instant; otherwise the histogram collapses to one bin and
       lies about the timeline.

    Both failure modes (low-coverage AND zero-span) render the same bare
    ``(timeline unavailable)`` line - there is no footer disclosure in the
    flat card grammar, so a differentiated reason has no place to render.
    """
    total = int(len(frame))
    if "ts" not in frame.columns or total == 0:
        return False
    ts = frame["ts"].dropna()
    parsed = int(len(ts))
    if parsed / total < runner._DIGEST_TS_CONFIDENCE_FLOOR:
        return False
    if parsed == 0:
        return False
    span = float(ts.max()) - float(ts.min())
    if span <= 0:
        return False
    return True


def _compute_histogram(
    ts: pd.Series,
    data_window: tuple[datetime, datetime],
) -> tuple[list[int], str, int]:
    """Adaptive-binning temporal histogram over a timestamp series.

    Returns ``(counts, unit, peak)``:

    - ``counts`` is a list of per-bin event counts spanning data_window.
    - ``unit`` is ``"hr"`` for spans <= 48 hours, else ``"day"``.
    - ``peak`` is the maximum bin value (0 when there are no events).

    Without unit-aware binning, a 30-day window with hourly bars produces
    720 useless bars; a 1-hour window with daily bars produces one. Both
    fail to communicate shape - hence the adaptive switch.

    The right edge is INCLUSIVE: the window is treated as ``[start, end]``
    so that an event at exactly ``data_window[1]`` (the max-ts event when
    ``data_window`` is derived from ``min(ts)/max(ts)``) lands in the
    final bin instead of being silently dropped when the span lands on an
    exact bin boundary. Callers must pass ``data_window`` such that
    ``data_window[1] >= max(ts)``; the lone production caller (run_digest)
    satisfies this by deriving ``data_window`` from the same loaded frame.

    A zero-span window (``start == end``) with non-empty ``ts`` emits a
    single bin holding the full count - appropriate for single-record
    digests, or frames whose events all share one timestamp.
    """
    start, end = data_window
    span_seconds = (end - start).total_seconds()

    cleaned = ts.dropna().astype(float)
    if cleaned.empty or span_seconds < 0:
        return [], "hr", 0
    if span_seconds == 0:
        # All events share a single timestamp - emit one bin holding the count.
        n = int(len(cleaned))
        return [n], "hr", n

    span_hours = span_seconds / 3600.0
    if span_hours <= runner._HISTOGRAM_HOURLY_THRESHOLD_HOURS:
        unit = "hr"
        bin_seconds = 3600
    else:
        unit = "day"
        bin_seconds = 86400

    bin_count = max(1, -(-int(span_seconds) // bin_seconds))  # ceiling division
    start_epoch = start.timestamp()
    offsets = ((cleaned - start_epoch) // bin_seconds).astype("int64")
    # Drop pre-window events, then collapse the inclusive right edge: events
    # at exactly data_window[1] yield offset == bin_count when the span is an
    # exact multiple of bin_seconds - fold those into the final bin instead
    # of filtering them out.
    offsets = offsets[offsets >= 0]
    offsets = offsets.where(offsets < bin_count, bin_count - 1)
    value_counts = offsets.value_counts().sort_index()
    counts = [int(value_counts.get(i, 0)) for i in range(bin_count)]
    if len(counts) > runner._HISTOGRAM_MAX_BINS:
        # Cap output width by folding adjacent bins by sum. The unit label
        # stays nominal - each glyph now spans several hr/day - but the peak
        # anchor recomputed below stays truthful to the drawn bars.
        group_size = -(-len(counts) // runner._HISTOGRAM_MAX_BINS)
        counts = [
            sum(counts[i:i + group_size])
            for i in range(0, len(counts), group_size)
        ]
    peak = max(counts) if counts else 0
    return counts, unit, peak


def _emit_inter_card_separator(stream: Any) -> None:
    """Emit the 40-col inter-card rule with bracketing blank lines."""
    target = stream if stream is not None else sys.stdout
    print(file=target)
    print(runner._DIGEST_INTER_CARD_RULE, file=target)
    print(file=target)


def _render_blob_for_path(
    blob_path: Path,
    *,
    stream: Any = None,
    output_dir: Path | None = None,
    output_file: Path | None = None,
    verbose_level: int = 0,
    leading_separator: bool = False,
) -> None:
    """Profile a single file via the blob digest path and render the card.

    Shared by the canonical blob branch (schema == "blob": sniff routed a
    path to the blob floor) and the defensive fallback in the recognised-
    schema path (item 2: a summariser raise on a recognised schema falls
    through to a blob card for the same file instead of aborting the fan-
    out).

    Caller verifies that ``blob_path`` is a regular file before invoking.
    Output routing (stream / output_dir / output_file / verbose) is the
    same shape ``run_digest`` itself uses; the fallback caller threads its
    own values so the blob card lands on the same fan-out stream and
    --out target as the original card would have.

    ``leading_separator`` is the single-owner emission seam for blob cards.
    This function owns the rule for BOTH the top-level blob route AND the
    summariser-failure fallback - ``run_digest`` never emits when handing
    off to the fallback, it just threads the flag here. Emission happens
    immediately before ``handler.render_blob(card)`` so a separator only
    ever precedes a card that reaches its render call.
    """
    from sigwood.digest import blob as _blob_summarizer
    card = _blob_summarizer.summarize_blob(blob_path)

    handler, close_handler, _written = runner._build_output_handler(
        "text", output_dir, output_file, verbose_level, stream=stream,
    )
    try:
        from sigwood.outputs.text import TextHandler
        if not isinstance(handler, TextHandler):
            raise RuntimeError(
                "digest blob: _build_output_handler did not return a "
                f"TextHandler (got {type(handler).__name__})"
            )
        if leading_separator:
            _emit_inter_card_separator(stream)
        handler.render_blob(card)
    finally:
        close_handler()


def run_digest(
    config: dict[str, Any],
    zeek_dir: str | Path | None = None,
    pihole_dir: str | Path | None = None,
    syslog_dir: str | Path | None = None,
    cloudtrail_dir: str | Path | None = None,
    blob_path: Path | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    output_format: str = "text",
    output_dir: Path | None = None,
    output_file: Path | None = None,
    stream: Any = None,
    verbose_level: int = 0,
    dry_run: bool = False,
    load_all: bool = False,
    skip_confirm: bool = False,
    schema: str = "conn",
    fallback_blob_path: Path | None = None,
    leading_separator: bool = False,
    show_progress: bool = True,
    quiet: bool = False,
    use_utc: bool = False,
) -> None:
    """Digest entry point - orient-before-the-hunt for a single schema.

    Loads the source frame, computes spine ambient facts and a temporal
    histogram, dispatches to the schema summariser, assembles a DigestCard,
    and renders it. Does NOT build a RunPlan, does NOT run the allowlist
    loop, does NOT produce Findings.

    Pre-allowlist tap: the loaded frame is consumed BEFORE the allowlist
    seam. Allowlisted infrastructure (resolvers, pollers) is part of what's
    in the pile and stays on the sonar. This function MUST NOT call
    build_matcher or AllowlistMatcher.filter_df.

    Source-dir parameters (``zeek_dir`` / ``pihole_dir`` / ``syslog_dir`` /
    ``cloudtrail_dir``) are EXPLICIT OVERRIDES with ``None`` meaning
    "no override." Pass a string or ``Path``;
    ``sigwood.common.sources.resolve_digest_source`` owns the per-schema
    candidate ladder, wrong-key + XOR + not-configured errors (byte-preserved
    from the previous in-line strings), and is the SOLE site that converts
    a source-dir string to a Path. CLI callers thread raw parsed strings;
    programmatic callers can pass already-resolved ``Path``s or let ``None``
    fall back to ``config["sigwood"][candidate]`` (SIGWOOD_ROOT applied).

    ``leading_separator`` drives the multi-card inter-card rule. The CLI
    fan-out sets it from ``rendered > 0`` after a previous card committed
    to render. Single-owner emission: run_digest emits for schema cards
    (immediately before handler.render_digest); on the summariser-failure
    fallback arm it threads the flag through to _render_blob_for_path
    (which owns blob emission) and does NOT emit itself.
    """
    set_narration_enabled(not quiet)
    with hidden_cursor():
        return _run_digest(
            config,
            zeek_dir=zeek_dir,
            pihole_dir=pihole_dir,
            syslog_dir=syslog_dir,
            cloudtrail_dir=cloudtrail_dir,
            blob_path=blob_path,
            since=since,
            until=until,
            output_format=output_format,
            output_dir=output_dir,
            output_file=output_file,
            stream=stream,
            verbose_level=verbose_level,
            dry_run=dry_run,
            load_all=load_all,
            skip_confirm=skip_confirm,
            schema=schema,
            fallback_blob_path=fallback_blob_path,
            leading_separator=leading_separator,
            show_progress=show_progress,
            quiet=quiet,
            use_utc=use_utc,
        )


def _run_digest(
    config: dict[str, Any],
    zeek_dir: str | Path | None = None,
    pihole_dir: str | Path | None = None,
    syslog_dir: str | Path | None = None,
    cloudtrail_dir: str | Path | None = None,
    blob_path: Path | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    output_format: str = "text",
    output_dir: Path | None = None,
    output_file: Path | None = None,
    stream: Any = None,
    verbose_level: int = 0,
    dry_run: bool = False,
    load_all: bool = False,
    skip_confirm: bool = False,
    schema: str = "conn",
    fallback_blob_path: Path | None = None,
    leading_separator: bool = False,
    show_progress: bool = True,
    quiet: bool = False,
    use_utc: bool = False,
) -> None:
    # Display timezone for the card's window/histogram rendering. Set at entry
    # for programmatic callers; the CLI digest path has already set it (its
    # output file is named CLI-side, before this function runs) - same value.
    set_display_utc(use_utc)

    if output_format != "text":
        raise ValueError(
            f"digest currently supports only --format=text (got {output_format!r})"
        )
    if schema not in ("conn", "dns", "syslog", "weird", "cloudtrail", "blob"):
        raise ValueError(f"digest: unsupported schema {schema!r}")

    # -q folds into the loader-bar gate: the fan-out already passes
    # show_progress=False on a multi-file run; quiet suppresses it on any run.
    # The loader bars are run_digest's only runner-owned informational stderr
    # (no liveness / default-window advisory / phase_separator here).
    show_progress = show_progress and not quiet

    # The blob path is reached ONLY via the CLI sniff router, never via an
    # operator token (there is no `digest blob PATH` token). The blob
    # terminal branch is small by design: profile the single file and hand
    # off to _render_blob_for_path, which builds + renders the card. No
    # loader, no allowlist, no histogram, no DigestCard - blob has no
    # parsed frame.
    if schema == "blob":
        if blob_path is None:
            raise ValueError(
                "digest blob: PATH not provided - pass a positional PATH"
            )
        if not blob_path.is_file():
            raise ValueError(f"digest blob: not a file: {blob_path}")

        if dry_run:
            print("sigwood  ·  digest  ·  dry run")
            print(runner._SEP)
            print(f"  {'schema:':<{runner._BANNER_LABEL_WIDTH}} blob")
            print(f"  {'path:':<{runner._BANNER_LABEL_WIDTH}} {strip_control(blob_path)}")
            print(f"  {'window:':<{runner._BANNER_LABEL_WIDTH}} (none - blob extracts no fields)")
            print(runner._SEP)
            return

        _render_blob_for_path(
            blob_path,
            stream=stream,
            output_dir=output_dir,
            output_file=output_file,
            verbose_level=verbose_level,
            leading_separator=leading_separator,
        )
        return

    if blob_path is not None:
        raise ValueError(
            f"digest {schema}: blob_path is only valid for the blob schema"
        )

    cfg_sigwood = config.get("sigwood", {})

    # Single owner of digest source resolution. resolve_digest_source runs the
    # per-schema candidate ladder + wrong-key / XOR / not-configured guards
    # with byte-preserved error strings, and is the SOLE site that converts
    # a source-dir string to a Path on the digest path.
    ds = resolve_digest_source(
        config, schema,
        overrides={
            "zeek_dir": zeek_dir,
            "syslog_dir": syslog_dir,
            "pihole_dir": pihole_dir,
            "cloudtrail_dir": cloudtrail_dir,
        },
    )
    feed = ds.feed
    source_dir = ds.directory
    source_key = ds.source_key
    pattern, empty_columns = runner._DIGEST_PATTERN_AND_EMPTY[(schema, source_key)]

    from sigwood.common import loader

    # Default-window resolution is Zeek-ONLY on the digest path (the
    # boundedness rule): non-Zeek digest directories (pihole/syslog/cloudtrail)
    # load full and filter by an explicit window only. The caller-side gate below
    # IS the behavior-preservation point - digest invokes the SHARED resolver
    # (loader.resolve_load_windows) for the Zeek source alone, NOT a duplicate
    # engine. dated → open-ended (since, None); flat / mixed → post-load trim_span.
    dated_window: tuple[datetime, datetime | None] | None = None
    flat_span: timedelta | None = None
    keep_null = False
    default_window_note: str | None = None
    if source_key == "zeek_dir":
        default_spec = cfg_sigwood.get("default_window", "7d")
        _digest_windows = loader.resolve_load_windows(
            {pattern: source_key}, {source_key: [source_dir]}, default_spec,
            since=since, until=until, load_all=load_all,
        )
        if _digest_windows:
            w = _digest_windows[0]
            dated_window = w.select_window if w.trim_span is None else None
            flat_span = w.trim_span
            keep_null = w.keep_null
            # Resolver returned a window → this unqualified Zeek digest got
            # truncated. Disclose it on the card. The gate is the resolver
            # return (we are inside `if _digest_windows:`), NOT the derived
            # dated_window/flat_span locals - it must still hold if the
            # resolver grows another valid window shape.
            default_window_note = default_window_advisory(
                default_spec,
                open_ended=(
                    dated_window is not None and dated_window[1] is None
                ),
            )

    if dry_run:
        print("sigwood  ·  digest  ·  dry run")
        print(runner._SEP)
        print(f"  {'schema:':<{runner._BANNER_LABEL_WIDTH}} {schema}")
        if feed is not None:
            print(f"  {'feed:':<{runner._BANNER_LABEL_WIDTH}} {feed}")
        print(f"  {source_key + ':':<{runner._BANNER_LABEL_WIDTH}} {strip_control(source_dir)}")
        if dated_window is not None:
            dated_since, dated_until = dated_window
            dated_label = (
                fmt_window((dated_since, dated_until))
                if dated_until is not None
                else f"{fmt_timestamp(dated_since)} → end of data"
            )
            print(
                f"  {'window:':<{runner._BANNER_LABEL_WIDTH}} {dated_label}  "
                "(dated default)"
            )
        elif flat_span is not None:
            print(
                f"  {'window:':<{runner._BANNER_LABEL_WIDTH}} last "
                f"{cfg_sigwood.get('default_window', '7d')} of available data  (flat default)"
            )
        elif since is not None or until is not None:
            since_str = fmt_timestamp(since) if since else "beginning of data"
            until_str = fmt_timestamp(until) if until else "end of data"
            print(f"  {'window:':<{runner._BANNER_LABEL_WIDTH}} {since_str} → {until_str}")
        elif load_all:
            print(f"  {'window:':<{runner._BANNER_LABEL_WIDTH}} all available data (--all)")
        else:
            print(f"  {'window:':<{runner._BANNER_LABEL_WIDTH}} all available data")
        print(runner._SEP)
        return

    needed_logs = {pattern: source_key}
    # Digest compat: load_required_logs is list-only. Wrap [source_dir] for
    # the degenerate one-element case - card-per-file behavior unchanged,
    # the union plumbing runs as a single-element passthrough.
    source_dirs = {source_key: [source_dir]}
    source_windows = (
        {source_key: dated_window} if dated_window is not None else None
    )
    pre_prompted = False
    if not skip_confirm and runner._warn_above(cfg_sigwood) > 0:
        if source_key == "zeek_dir" and source_dir.is_file():
            previews = {pattern: loader.PatternPreview(
                source=source_key, discovered=(source_dir,), selected=(source_dir,),
            )}
        else:
            previews = loader.preview_required_files(
                needed_logs, source_dirs, since, until,
                source_windows=source_windows,
                verbose=verbose_level >= 1,
            )
        estimates = loader.estimate_population(previews)
        pre_prompted = runner._confirm_large_dataset(
            sum(item.records for item in estimates.values()), cfg_sigwood,
            skip_confirm=False, estimate=tuple(estimates.values()),
        )

    # Single-file Zeek bypass: the file was already content-identified by sniff;
    # discover_zeek_files' fnmatch(basename, pattern) gate is meaningless for an
    # explicitly-named single file and was dropping date-prefixed Zeek logs
    # (e.g. 2026-06-09.conn.log) into zero-row cards. Pi-hole, syslog, and
    # CloudTrail loaders already accept explicit files without a basename gate;
    # only the Zeek path needs the bypass. discover_zeek_files itself is
    # unchanged - the detect path still uses its single-file gate as a type
    # check.
    if source_key == "zeek_dir" and source_dir.is_file():
        s_since, s_until = (
            dated_window if dated_window is not None else (since, until)
        )
        warnings: list[str] = []
        try:
            data_size_bytes = source_dir.stat().st_size
        except OSError:
            data_size_bytes = 0
        df = loader.load_logs(
            source_dir.parent, pattern, s_since, s_until,
            _files=[source_dir], _warnings=warnings,
            show_progress=show_progress,
        )
        # Preserve schema-warning parity with load_required_logs so
        # malformed-but-parseable Zeek single files behave identically on the
        # bypass and directory paths.
        schema_warning = loader._schema_warning(pattern, df)
        if schema_warning:
            warnings.append(schema_warning)
        logs = {pattern: df}
        record_counts = {pattern: len(df)} if not df.empty else {}
        load_result = loader.LoadResult(
            logs=logs,
            record_counts=record_counts,
            data_window=loader._data_window(logs),
            warnings=warnings,
            data_size_bytes=data_size_bytes,
        )
    else:
        load_result = loader.load_required_logs(
            needed_logs,
            source_dirs,
            since,
            until,
            verbose=(verbose_level >= 1),
            source_windows=source_windows,
            show_progress=show_progress,
        )

    if flat_span is not None:
        load_result = loader.apply_default_window(
            load_result, [pattern], flat_span, keep_null=keep_null,
        )

    for warning in load_result.warnings:
        runner._estderr(f"{warning}")

    total_records = sum(load_result.record_counts.values())
    if not pre_prompted:
        runner._confirm_large_dataset(
            total_records, cfg_sigwood, skip_confirm=skip_confirm,
        )

    if load_result.data_window is not None:
        data_window = load_result.data_window
    elif since or until:
        data_window = (
            since or datetime.now(timezone.utc),
            until or datetime.now(timezone.utc),
        )
    else:
        _now = datetime.now(timezone.utc)
        data_window = (_now, _now)

    # data_sources / notes are the RunSummary banner inputs; the flat
    # digest card has no banner, so they are not consumed here.
    # Reference it so unused-arg checkers stay quiet.
    _ = runner._derive_data_sources(needed_logs, load_result.record_counts)

    # Identity line 1 always carries the source's name - file or directory.
    # Directory-mode bare-config digest gets a sensible identity even though
    # the source is a multi-file load.
    source_name = source_dir.name

    # Pre-allowlist tap - pull the frame straight out of load_result.
    # NO build_matcher. NO AllowlistMatcher.filter_df. Digest is the orient
    # step; allowlisted infrastructure (resolvers, pollers) is part of
    # what's in here and stays on the sonar.
    #
    # Frame is the source of truth for whether a schema card can render.
    # Empty frame → DigestEmpty (control signal, NOT a ValueError). The
    # file was understood - it simply had no parseable records. The CLI
    # narrates this distinctly from a real per-path failure. Applies ONLY
    # to the recognized-schema path; blob has its own terminal branch
    # above and an empty FILE was already caught at sniff time as
    # state="empty" in the CLI fan-out.
    frame = load_result.logs.get(pattern)
    if frame is None or frame.empty:
        raise DigestEmpty(basename=source_dir.name, schema=schema)
    # empty_columns reserved for any future tolerant-load path; the
    # current contract is "recognized schema must have at least one row
    # to render a card", enforced by the raise above.
    _ = empty_columns

    # Timestamp-confidence gate (now boolean). Below the floor OR with a
    # zero non-NaN span, the timeline would overstate coverage - dash the
    # identity-line window AND signal timeline_unavailable to the
    # renderer, which emits the bare "(timeline unavailable)" histogram
    # replacement. Both former failure modes (low coverage AND zero span)
    # render identically; the flat card has no footer surface to
    # differentiate them.
    if _ts_confidence(frame):
        histogram_counts, histogram_unit, histogram_peak = _compute_histogram(
            frame["ts"], data_window,
        )
        timeline_unavailable = False
    else:
        data_window = (None, None)
        histogram_counts = []
        histogram_unit = "hr"
        histogram_peak = 0
        timeline_unavailable = True

    from sigwood import digest
    from sigwood.common.finding import DigestCard

    # Narrow defence-in-depth wrap (item 2): summariser dispatch + body +
    # DigestCard construction. If the summariser raises on a pathological
    # frame (e.g. a duplicate `src` column producing pandas' "Grouper for
    # 'src' not 1-dimensional"), fall through to a blob card for the same
    # file rather than aborting the fan-out. Scope discipline:
    #   - DOES catch summariser raises and DigestCard-construction raises.
    #   - DOES NOT catch loader/parser errors (above this wrap).
    #   - DOES NOT catch DigestEmpty (raised above; control signal).
    #   - DOES NOT catch handler/render errors (below this wrap).
    #   - DOES NOT catch BaseException - KeyboardInterrupt / SystemExit
    #     propagate.
    # Bare-config callers (no single-file fallback path available) pass
    # fallback_blob_path=None and the exception re-raises to the caller's
    # existing ValueError arm.
    try:
        summarizer = digest.get_summarizer(schema)
        if schema in ("dns", "syslog"):
            body = summarizer(frame, feed)
        else:
            body = summarizer(frame)
        card = DigestCard(
            schema=schema,
            source_name=source_name,
            data_window=data_window,
            record_count=total_records,
            histogram_counts=histogram_counts,
            histogram_unit=histogram_unit,
            histogram_peak=histogram_peak,
            zone1_extras=body["zone1_extras"],
            insights=body["insights"],
            fields=body["fields"],
            data_size_bytes=load_result.data_size_bytes,
            timeline_unavailable=timeline_unavailable,
            default_window_note=default_window_note,
        )
    except Exception as exc:
        if fallback_blob_path is None:
            raise
        # One-line stderr breadcrumb. Default mode uses fixed tool-authored
        # text; verbose mode appends the existing exception class/message,
        # bounded before the normal stderr sanitizer sees it.
        breadcrumb = (
            f"digest: {fallback_blob_path.name}: recognized as {schema}; "
            "summary could not be built; profiling bytes instead"
        )
        if verbose_level >= 1:
            exc_text = str(exc)
            if len(exc_text) > 200:
                exc_text = f"{exc_text[:199]}…"
            breadcrumb += f" ({type(exc).__name__}: {exc_text})"
        runner._estderr(breadcrumb)
        # Separator single-owner: _render_blob_for_path owns blob-card
        # emission. We thread the flag and do NOT emit here, or the run
        # would print two rules around the same fallback card.
        _render_blob_for_path(
            fallback_blob_path,
            stream=stream,
            output_dir=output_dir,
            output_file=output_file,
            verbose_level=verbose_level,
            leading_separator=leading_separator,
        )
        return

    handler, close_handler, _written = runner._build_output_handler(
        "text", output_dir, output_file, verbose_level, stream=stream,
    )
    try:
        from sigwood.outputs.text import TextHandler
        if not isinstance(handler, TextHandler):
            raise RuntimeError(
                "digest: _build_output_handler did not return a TextHandler "
                f"(got {type(handler).__name__})"
            )
        if leading_separator:
            _emit_inter_card_separator(stream)
        handler.render_digest(card)
    finally:
        close_handler()


# Bind the facade after the re-exported definitions so either import order works.
import sigwood.runner as runner
