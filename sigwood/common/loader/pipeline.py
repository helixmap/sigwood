"""The uniform load pipeline - ``run_load`` + the ``_SOURCE_LOADERS`` registry.

The protected core: every detector source-family load flows through ``run_load``
(progress wrap, coverage tracking, default-window filtering, verbose-gated
wrong-family skips, read-corruption handling - written ONCE). A new format = one
``SourceLoader`` in ``_SOURCE_LOADERS`` → it inherits the treatment by
construction and cannot diverge by happenstance. ``_open_log`` / ``progress`` are
reached through the package facade so test monkeypatches take effect here.
"""

from __future__ import annotations

import gzip
import itertools
import json
import lzma
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

import pandas as pd

import sigwood.common.loader as _loader  # facade: _open_log / progress patch-through (call-time only)
from sigwood.common.config import parse_window_span
from sigwood.common.sanitize import strip_control
from sigwood.common.loader.diagnostics import (
    _cloudtrail_parse_warning,
    _log_type,
    _permission_denied_message,
    _schema_warning,
    _zeek_bad_lines_warning,
    _zeek_file_parse_warning,
    _zeek_file_read_warning,
    _zeek_message_value_warning,
    _zeek_rename_collision_warning,
    _zeek_no_records_warning,
)
from sigwood.common.loader.discovery import (
    _default_resolve_window,
    _dir_has_regular_files,
    _discover_syslog_files,
    _flat_resolve_window,
    _stem_hostname,
    _syslog_files,
    _zeek_resolve_window,
    discover_cloudtrail_files,
    discover_zeek_files,
)
from sigwood.common.loader.io import (
    BoundedLogicalRecordReader,
    _safe_resolve,
    _union_dedupe,
)
from sigwood.common.loader.fold import (
    FoldExecution,
    build_source_snapshot,
    chunks_from_rows,
    execute_sink_plan,
    open_snapshot_text,
)
from sigwood.common.loader.journal import (
    _discover_journal_capture,
    _journal_read_error,
    _journal_strategy_parse,
)
from sigwood.common.loader.provenance import (
    reject_explicit_reserved_path,
    validate_selected_files,
)
from sigwood.common.loader.sniff import _is_ndjson, _looks_binary
from sigwood.common.loader.types import (
    _CLOUDTRAIL_COLUMNS,
    _PIHOLE_COLUMNS,
    _SYSLOG_COLUMNS,
    CoverageTracker,
    DirectorySkipInfo,
    FileSpan,
    LoadQuality,
    DecodedChunk,
    DualWindow,
    MAX_CHUNK_DECODED_BYTES,
    MAX_CHUNK_ROWS,
    LoadResult,
    PermissionSkipInfo,
    RotationSkipInfo,
    PreparedStatus,
    SinkPlan,
    SnapshotFile,
    SourceFileQuality,
    SourceSnapshot,
    SourceCoverage,
    _coerce_usable_ts,
    _data_window,
    _is_infinite_ts,
    _is_out_of_range_ts,
)
from sigwood.common.loader.windowing import (
    LoadWindow,
    _apply_ts_filter,
    _missing_ts,
    _rotation_windowed_files,
    is_bounded,
)
from sigwood.parsers.cloudtrail import parse_event as _parse_cloudtrail_event
from sigwood.parsers.dnsmasq import parse_line as _parse_dnsmasq_line
from sigwood.parsers.syslog import parse_line as _parse_syslog_line
from sigwood.parsers.zeek import (
    _COLLISION_MAPS,
    _has_rename_collision,
    _normalize_conn_df,
    _normalize_dns_df,
    _normalize_ssl_df,
    _normalize_weird_df,
    _normalize_x509_df,
    _normalize_zeek_syslog_df,
    empty_canonical_frame,
)
from sigwood.parsers.zeek_tsv import parse_tsv_log as _parse_tsv_log


@dataclass(frozen=True)
class SourceLoader:
    """Per-source-family load strategy consumed by ``run_load``.

    The strategy carries the thin per-family description; the uniform
    behavior - progress, coverage, windowing, corruption-handling, verbose-
    gated wrong-family skip - lives in ``run_load``. A new format = one
    ``SourceLoader`` in ``_SOURCE_LOADERS`` → inherits the treatment by
    construction.

    Fields:
      - ``discover``: window-aware file discovery for a single input path.
      - ``mode``: ``"stream"`` yields canonical row dicts; ``"frame"`` returns
        a pre-filter DataFrame (Zeek, normalized later).
      - ``parse(line_iter, *, path, warnings)``: format-specific decode given
        the progress-wrapped line iterator AND the per-file context
        (``path`` for hostname stems / file identity; ``warnings`` as the
        content-parse warning sink).
      - ``ts_policy``: ``"keep"`` (NaN-ts rows bypass the window) or
        ``"drop"`` (NaN-ts rows discarded before windowing). Each entry
        carries a rationale comment at registration.
      - ``columns``: stream-mode empty-frame stability list; ``None`` for
        frame-mode. Frame-mode (Zeek) preserves today's bare ``pd.DataFrame()``
        on date-pruned / empty / all-filtered - Zeek's non-empty columns
        come from parse + normalize, not a static list.
      - ``should_skip(path)``: wrong-family guard returning a skip message
        (printed to stderr only under ``verbose=True``) or ``None`` to keep.
        Optional; ``None`` means never skip.
      - ``normalize(df, pattern, *, warnings=None)``: post-assembly normalize hook
        (``_NORMALIZER_MAP`` dispatch for Zeek; ``None`` for the flat
        loaders).
      - ``unit``: progress bar unit label.
      - ``window_select(files, since, until, *, verbose)``: OPTIONAL ordinal-
        rotation peek-prune (flat syslog / pihole). Returns
        ``(selected, RotationSkipInfo)``. ``None`` (Zeek / CloudTrail) means no
        windowing of discovered candidates - the loader keeps today's behavior
        verbatim. Defaulted so non-flat registry entries and programmatic
        constructions do not churn.
      - ``records_file_spans``: whether kept finite timestamp extrema may expose
        this source's file path through ``LoadResult.file_spans``. Journal opts
        out because its private capture path must never leave the loader.
      - ``records_directory_denials``: whether ``discover`` accepts the private
        caller-owned directory-denial sink. All four filesystem families opt in
        for their configured input root; CloudTrail recursive child denials stay
        outside that root-probe contract.
    """

    discover: Callable[[Path, str, datetime | None, datetime | None], list[Path]]
    mode: str  # "stream" | "frame"
    parse: Callable[..., Any]
    ts_policy: str  # "keep" | "drop"
    columns: list[str] | None
    should_skip: Callable[[Path], str | None] | None
    normalize: Callable[..., pd.DataFrame] | None
    unit: str = " lines"
    # Signature: (files, since, until, *, verbose) -> (selected, RotationSkipInfo).
    # `Callable[...]` because the real callable has a keyword-only `verbose` arg
    # that the parameter-list form cannot express.
    window_select: Callable[..., tuple[list[Path], RotationSkipInfo]] | None = None
    # Whether the auto-default window applies to this family. Default True
    # (zeek/syslog/pihole). CloudTrail opts OUT - aws is baseline-relative
    # (novelty/weirdness needs full history), so the recent-slice auto-window
    # defeats it; explicit windows still apply (resolved before the default).
    default_window_eligible: bool = True
    # How this family resolves its default window: (strategy, dirs, pattern, span)
    # -> (select_window, trim_span). ``None`` = the universal default
    # (_default_resolve_window: load full + post-load trim). A source with special
    # temporal semantics (dated Zeek dirs, flat rotation-peek) declares its resolver
    # HERE, on the entry - zero runner edits. The owning strategy is passed in so a
    # resolver can reach ``strategy.discover`` without a registry import.
    resolve_window: Callable[..., tuple[Any, timedelta | None]] | None = None
    # Per-strategy WARN-skip hook (flat families): (path) -> warn message | None.
    # Distinct from ``should_skip`` - a binary/undecodable SELECTED flat file is
    # skipped with a DEFAULT-VISIBLE ``load_result.warnings`` entry (NOT the
    # verbose-only wrong-family skip), so a misnamed binary never becomes drain3
    # "soup". Trailing/defaulted → existing constructions unaffected; None = no hook.
    warn_skip: Callable[[Path], str | None] | None = None
    # Optional operator-facing identity for private/internal materializations.
    # The pipeline owns the descriptor because display.progress has no strategy
    # context. None preserves the path-name wording for every existing source.
    display_label: str | None = None
    # Optional translator for source-owned read failures. A live producer can
    # classify its private capture I/O without entering file-permission metadata;
    # ordinary file families retain the generic warning/skip behavior.
    read_error_factory: Callable[[BaseException], BaseException] | None = None
    # Whether this strategy may publish file-path timestamp spans in LoadResult.
    # Trailing/defaulted keeps ordinary file strategies and test constructions on.
    records_file_spans: bool = True
    # See the class docstring. False preserves programmatic strategy callables
    # and non-filesystem strategies that do not accept the private sink.
    records_directory_denials: bool = False

    def discover_paths(
        self,
        path: Path,
        pattern: str,
        since: datetime | None,
        until: datetime | None,
        *,
        _directory_skips: (
            dict[tuple[str, Path], DirectorySkipInfo] | None
        ) = None,
    ) -> list[Path]:
        """Invoke this strategy's discovery with its declared sink capability."""
        if self.records_directory_denials:
            return self.discover(
                path,
                pattern,
                since,
                until,
                _directory_skips=_directory_skips,
            )
        return self.discover(path, pattern, since, until)


def _zeek_records_from_lines(line_iter: Any) -> list[dict[str, Any]]:
    """Iterate ``line_iter`` and return Zeek NDJSON records.

    Skips blank and ``#``-comment lines, drops records with ``ts is None`` or
    malformed JSON. Shared by ``_parse_ndjson_file`` (path-driven NDJSON
    parse) and the Zeek strategy's NDJSON branch (line-iter-driven).
    """
    records: list[dict[str, Any]] = []
    for line in line_iter:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError, OverflowError, RecursionError):
            continue
        if not isinstance(record, dict):
            continue
        if record.get("ts") is None:
            continue
        records.append(record)
    return records


def _records_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    """Construct a Zeek frame without leaking oversized JSON-int failures."""
    try:
        return pd.DataFrame(records)
    except OverflowError:
        # pandas' dtype inference can overflow on a valid JSON integer far
        # beyond native float range. Object preservation lets the canonical
        # timestamp/metric seams classify it without a raw parser traceback.
        return pd.DataFrame(records, dtype=object)


def _zeek_parse_from_lines(
    line_iter: Any,
    *,
    path: Path | None = None,
    warnings: list[str] | None = None,
) -> pd.DataFrame:
    """Prefix-preserving NDJSON-vs-TSV dispatch for a Zeek line iterator.

    A one-line peek would discard ``#separator`` / ``#fields``
    / ``#types`` directives that ``parse_tsv_log`` requires. This helper
    accumulates a ``prefix`` list of every consumed line while scanning, so the
    parser sees the full header block.

    Decision rule:
      - NDJSON when the FIRST non-blank, non-comment line starts with ``{``.
      - TSV when ``#separator`` appears anywhere in the scanned ``prefix``.
      - Bare empty ``DataFrame`` otherwise (header-only / empty / non-Zeek
        stub) - preserves today's bare-frame shape for date-pruned / empty /
        all-filtered Zeek paths.

    Parse runs over ``itertools.chain(prefix, line_iter)`` so EVERY consumed
    line - header directives included - reaches the parser. Header-only TSV
    files retain their header block; ``parse_tsv_log`` produces whatever it
    makes of header-only input today.

    ``warnings`` opts the TSV branch into per-line tolerance: malformed data
    lines are skipped via the ``parse_tsv_log`` sink and disclosed as ONE
    warning per file (a live/mid-write TSV tail is routine). A sink-carrying
    call MUST also pass ``path`` (the warning names the file); sink-less
    callers stay strict.

    A file that yields zero records from at least one data line - non-Zeek
    text with no ``#separator``, unparseable NDJSON, or rows without ``ts`` -
    is disclosed via ``_zeek_no_records_warning`` when a sink is passed; empty
    and comment-only input stays silent (absence, not unreadable data). The
    NDJSON branch keeps its per-line silent skip either way.
    """
    prefix: list[str] = []
    is_ndjson: bool | None = None
    has_separator = False
    for line in line_iter:
        prefix.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if stripped.startswith("#separator"):
                has_separator = True
            continue
        # First non-blank, non-comment line decides NDJSON.
        is_ndjson = stripped.startswith("{")
        break
    rest = itertools.chain(prefix, line_iter)
    if is_ndjson:
        records = _zeek_records_from_lines(rest)
        if not records and warnings is not None:
            assert path is not None, "a warnings sink requires path"
            warnings.append(_zeek_no_records_warning(path))
        return _records_frame(records)
    if has_separator:
        if warnings is not None:
            sink: list[tuple[int, str]] = []
            df = _parse_tsv_log(rest, bad_lines=sink)
            if sink:
                assert path is not None, "a warnings sink requires path"
                warnings.append(_zeek_bad_lines_warning(path, sink))
            return df
        return _parse_tsv_log(rest)
    # Bare frame: header-only / empty stub stays silent (absence); a seen data
    # line that is neither NDJSON nor TSV is disclosed as zero-yield.
    if is_ndjson is False and warnings is not None:
        assert path is not None, "a warnings sink requires path"
        warnings.append(_zeek_no_records_warning(path))
    return pd.DataFrame()


def _parse_ndjson_file(path: Path, show_progress: bool = True) -> pd.DataFrame:
    """Parse a single Zeek NDJSON log file, return unfiltered Zeek-native DataFrame."""
    with _loader._open_log(path) as fh:
        line_iter = BoundedLogicalRecordReader(
            _loader.progress(
                fh,
                desc=f"loaded {strip_control(path.name)}",
                show_progress=show_progress,
                unit=" lines",
            )
        )
        records = _zeek_records_from_lines(line_iter)
    return _records_frame(records)


def _parse_lines(lines: list[str]) -> list[dict[str, Any]]:
    """Parse NDJSON lines, skipping blanks and Zeek comment headers."""
    result: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError, OverflowError, RecursionError):
            continue
        if isinstance(record, dict):
            result.append(record)
    return result


def load_zeek_log(
    path: Path,
    since: datetime | None = None,
    until: datetime | None = None,
    show_progress: bool = True,
) -> pd.DataFrame:
    """Parse a single Zeek NDJSON log file and return a DataFrame.

    Handles plain and gzip-compressed files transparently.
    Applies timeframe filter on the ts field if since/until are provided.
    """
    return _apply_ts_filter(
        _parse_ndjson_file(path, show_progress=show_progress), since, until
    )


def _events_from_whole_document(
    text: str,
    path: Path,
    _warnings: list[str] | None,
) -> list[dict]:
    """Parse ``text`` as a single JSON document and extract its event list.

    Accepts three shapes: ``{"Records": [...]}`` envelope, a bare ``[...]`` list,
    or a bare ``{...}`` single event. Total parse failure or any other shape
    appends a warning and returns an empty list.
    """
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError, OverflowError, RecursionError):
        if _warnings is not None:
            _warnings.append(_cloudtrail_parse_warning(path))
        return []

    if isinstance(doc, dict):
        records = doc.get("Records")
        if isinstance(records, list):
            return [e for e in records if isinstance(e, dict)]
        # Bare single-event dict.
        return [doc]
    if isinstance(doc, list):
        return [e for e in doc if isinstance(e, dict)]

    if _warnings is not None:
        _warnings.append(_cloudtrail_parse_warning(path))
    return []


# Zeek normalization lives in sigwood.parsers.zeek; loader keeps dispatch here.
# Covers Zeek NDJSON formats only. Syslog is handled by load_syslog() - see parsers/syslog.py.

# Map from log type → normalizer function. Add an entry here (alongside a new
# _normalize_*_df function) when implementing each new Zeek log source.
_NORMALIZER_MAP: dict[str, Callable[[pd.DataFrame], pd.DataFrame]] = {
    "conn":   _normalize_conn_df,
    "dns":    _normalize_dns_df,
    "syslog": _normalize_zeek_syslog_df,
    "ssl":    _normalize_ssl_df,
    "x509":   _normalize_x509_df,
    "weird":  _normalize_weird_df,
}


# ─────────────────────────────────────────────────────────────────────────────
# run_load - the uniform load pipeline + per-source SourceLoader strategies
#
# Every detector source-family load flows through ``run_load``: progress
# wrapping, coverage tracking, default-window filtering, verbose-gated
# wrong-family skips, and read-corruption handling are written ONCE. A new
# format = one ``SourceLoader`` in ``_SOURCE_LOADERS`` - it inherits the
# treatment by construction and cannot diverge by happenstance.
#
# Stream strategies (syslog / pihole / cloudtrail) yield canonical row dicts;
# frame strategies (zeek) return a pre-window DataFrame that the pipeline
# windows + normalises. NaN-ts policy is declared per strategy:
# ``ts_policy="drop"`` (zeek + cloudtrail - unparseable timestamps are not
# trustworthy data) vs ``ts_policy="keep"`` (syslog + pihole - RFC 3164's
# year-guess can lose a timestamp without making the LINE less useful).
# ─────────────────────────────────────────────────────────────────────────────


def _zeek_strategy_parse(line_iter, *, path, warnings):
    """Zeek strategy parse: prefix-preserving NDJSON-vs-TSV dispatch.

    Threads ``path`` and ``warnings`` through so a sink-carrying load gets
    per-line TSV tolerance with a per-file disclosure; an unrecognized
    (non-NDJSON, non-TSV) stream still degrades to a bare DataFrame rather
    than a warning.
    """
    return _zeek_parse_from_lines(line_iter, path=path, warnings=warnings)


def _zeek_normalize(
    df: pd.DataFrame,
    pattern: str,
    *,
    warnings: list[str] | None = None,
) -> pd.DataFrame:
    """Apply the Zeek per-log-type normaliser when the pattern has one."""
    log_type = _log_type(pattern)
    if log_type in _NORMALIZER_MAP:
        before = len(df)
        collision_map = _COLLISION_MAPS.get(log_type)
        if collision_map is not None and _has_rename_collision(df.columns, collision_map):
            # normalize runs post-concat, OUTSIDE run_load's per-file parse
            # containment, so raising here would abort the whole run - every
            # sibling detector included - on one malformed file. Empty the
            # frame and disclose instead.
            if warnings is not None:
                warnings.append(_zeek_rename_collision_warning(pattern, before))
            return empty_canonical_frame(log_type)
        normalized = _NORMALIZER_MAP[log_type](df)
        dropped = before - len(normalized)
        if log_type == "syslog" and dropped > 0 and warnings is not None:
            warnings.append(_zeek_message_value_warning(pattern, dropped))
        return normalized
    return df


def _syslog_strategy_parse(line_iter, *, path, warnings):  # noqa: ARG001
    """Syslog stream parse: yield canonical rows with float/NaN ``ts``.

    Host derivation prefers the in-content host (``parse_host``: field 2 for
    ISO-8601, field 4 for RFC 3164, or ``"unknown"`` when the selected layout
    is too short); it falls back to the filename stem (``_stem_hostname``) only
    when the line is hostless. Applies uniformly to every stream file, with the
    per-host-file case preserved by the fallback. ``ts`` is converted to float
    seconds, or ``float('nan')`` when the line has no parseable supported
    timestamp - KEEP policy applies at the pipeline.
    """
    stem = _stem_hostname(path.name)
    for line in line_iter:
        record = _parse_syslog_line(line.rstrip("\n"))
        if record is None:
            continue
        in_content = record["host"]
        host = in_content if in_content != "unknown" else stem
        ts_dt = record["ts"]
        ts_float = ts_dt.timestamp() if ts_dt is not None else float("nan")
        yield {
            "ts":      ts_float,
            "host":    host,
            "program": record["program"],
            "raw":     record["raw"],
            "message": record["message"],
        }


def _pihole_strategy_parse(line_iter, *, path, warnings):  # noqa: ARG001
    """Pi-hole stream parse: yield canonical rows with float/NaN ``ts``.

    Hostname is taken from the filename stem unconditionally (Pi-hole logs
    are per-host). ``ts`` is float seconds or ``float('nan')`` - KEEP policy.
    """
    stem = _stem_hostname(path.name)
    for line in line_iter:
        record = _parse_dnsmasq_line(line.rstrip("\n"))
        if record is None:
            continue
        record["host"] = stem
        ts_dt = record["ts"]
        record["ts"] = ts_dt.timestamp() if ts_dt is not None else float("nan")
        yield record


def _cloudtrail_strategy_parse(line_iter, *, path, warnings):
    """CloudTrail stream parse: SINGLE-iterator sniff + dispatch yielding rows.

    The single-iterator invariant: the pipeline wraps ``fh`` → ``line_iter`` once;
    EVERY branch (first-line sniff, NDJSON stream, envelope/pretty multi-line,
    bare-list) consumes from the SAME wrapped iterator so the progress bar's
    line count reflects actual INPUT lines, never re-reading ``fh``.

    Content-parse failures (malformed JSON) append
    ``_cloudtrail_parse_warning(path)`` to the ``warnings`` sink - the
    content-parse-vs-read-corruption split preserved (read-corruption stays
    on the pipeline's ``_zeek_file_read_warning`` rail).
    """
    first_line = None
    for line in line_iter:
        if line.strip():
            first_line = line
            break
    if first_line is None:
        return

    try:
        first_value = json.loads(first_line)
    except json.JSONDecodeError:
        # First line is a fragment of a pretty-printed multi-line document.
        if hasattr(line_iter, "collect_document"):
            full_text = line_iter.collect_document(first_line)
            if full_text is None:
                return
        else:
            full_text = first_line + "".join(line_iter)
        for event in _events_from_whole_document(full_text, path, warnings):
            row = _parse_cloudtrail_event(event)
            if row is not None:
                yield row
        return
    # JSONDecodeError subclasses ValueError, so this must follow the fragment
    # branch above to preserve pretty-printed multi-line document routing.
    except (ValueError, OverflowError, RecursionError):
        if warnings is not None:
            warnings.append(_cloudtrail_parse_warning(path))
        return

    if isinstance(first_value, dict):
        if "Records" in first_value:
            # Envelope: accumulate rest from the same wrapped iterator.
            if hasattr(line_iter, "collect_document"):
                full_text = line_iter.collect_document(first_line)
                if full_text is None:
                    return
            else:
                full_text = first_line + "".join(line_iter)
            for event in _events_from_whole_document(full_text, path, warnings):
                row = _parse_cloudtrail_event(event)
                if row is not None:
                    yield row
            return
        # NDJSON: seed events with this first dict (do NOT drop it), then
        # stream the rest, silently skipping undecodable lines.
        row = _parse_cloudtrail_event(first_value)
        if row is not None:
            yield row
        for line in line_iter:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except (
                json.JSONDecodeError,
                ValueError,
                OverflowError,
                RecursionError,
            ):
                continue
            if isinstance(evt, dict):
                row = _parse_cloudtrail_event(evt)
                if row is not None:
                    yield row
        return

    if isinstance(first_value, list):
        # Bare-list one-line document. Any trailing content is malformed; the
        # JSON value is the document.
        for e in first_value:
            if isinstance(e, dict):
                row = _parse_cloudtrail_event(e)
                if row is not None:
                    yield row
        return

    # First-line is a JSON primitive - not a valid CloudTrail event shape.
    # Treat as a parse failure.
    if warnings is not None:
        warnings.append(_cloudtrail_parse_warning(path))
    return


def _syslog_should_skip(path: Path) -> str | None:
    """Wrong-family guard for ``syslog_dir``: skip NDJSON and Zeek TSV.

    PRESERVES today's asymmetry - syslog skips NDJSON (an operator dropping
    a Zeek NDJSON ``syslog.log`` here would garble through RFC 3164) AND
    Zeek-TSV (the ``#separator`` directive is the strong signal). The
    pipeline gates the returned message on ``verbose=True``.
    """
    if _is_ndjson(path):
        return f"syslog_dir: skipping {path.name} - looks like NDJSON, not syslog"
    with _loader._open_log(path) as fh:
        head = list(itertools.islice(fh, 8))
    if any(ln.startswith("#separator") for ln in head):
        return (
            f"syslog_dir: skipping {path.name} - looks like Zeek TSV, "
            "not flat syslog (Zeek logs belong in zeek_dir)"
        )
    return None


def _pihole_should_skip(path: Path) -> str | None:
    """Wrong-family guard for ``pihole_dir``: skip NDJSON ONLY.

    PRESERVES today's asymmetry - Pi-hole guards NDJSON but NOT Zeek TSV
    (there's no real-world case of a Zeek TSV landing in a pihole_dir; a
    blanket TSV skip here would be a behavior change).
    """
    if _is_ndjson(path):
        return f"pihole_dir: skipping {path.name} - looks like NDJSON, not dnsmasq"
    return None


def _flat_warn_undecodable(src: str, path: Path) -> str | None:
    """Shared body for the flat-family ``warn_skip`` hooks: warn + skip a SELECTED
    file that reads as binary / undecodable text. ``src`` is the source key (the
    existing skip-message prefix). One message-builder so the wording cannot drift
    between the two flat families. Module-private - the two named wrappers below
    are the package surface.
    """
    if _looks_binary(path):
        return f"{src}: skipping {path.name} - looks binary or won't decode as text"
    return None


def _syslog_warn_undecodable(path: Path) -> str | None:
    """``warn_skip`` for ``syslog_dir`` - see ``_flat_warn_undecodable``."""
    return _flat_warn_undecodable("syslog_dir", path)


def _pihole_warn_undecodable(path: Path) -> str | None:
    """``warn_skip`` for ``pihole_dir`` - see ``_flat_warn_undecodable``."""
    return _flat_warn_undecodable("pihole_dir", path)


def run_load(
    strategy: SourceLoader,
    files: list[Path],
    pattern: str,
    since: datetime | None,
    until: datetime | None,
    *,
    show_progress: bool = True,
    verbose: bool = False,
    _warnings: list[str] | None = None,
    _coverage: dict | None = None,
    _permission_skips: dict[str, PermissionSkipInfo] | None = None,
    _file_spans: list[FileSpan] | None = None,
    _quality: LoadQuality | None = None,
) -> pd.DataFrame:
    """The uniform load pipeline. Owns progress wrap, coverage tracking,
    windowing, corruption rail, verbose-gated wrong-family skip.

    Does NOT own byte accounting - ``load_required_logs`` sums ``stat`` over
    the deduped ``files`` in its uniform loop.

    Stream mode (syslog / pihole / cloudtrail):
      Strategy ``parse`` yields canonical row dicts; the pipeline applies the
      ts policy + window per row and assembles a column-stable DataFrame
      (``strategy.columns``) on the way out.

    Frame mode (zeek):
      Strategy ``parse`` returns a pre-filter DataFrame; the pipeline
      observes the pre-filter frame, windows via ``_apply_ts_filter`` (which
      drops NaN-ts then trims - that IS the drop policy), and optionally
      normalises post-concat. Empty paths return bare ``pd.DataFrame()`` -
      Zeek's empty shape is preserved exactly (no forced columns). A frame
      parse that raises ``ValueError`` (e.g. a live/mid-write Zeek TSV with a
      broken header) skips THAT file and continues - so a sink-less call
      (``_warnings=None``) never raises on malformed TSV content: it gets
      whole-file containment, while a sink-carrying call gets per-line
      tolerance plus a warning.

    Coverage: ``_coverage["coverage"]`` is written iff the returned frame is
    empty AND the tracker has something to say (no-files-read /
    files-but-zero-valid-ts / valid-rows-all-excluded-by-window). A populated
    load short-circuits via ``mark_kept`` and writes nothing.
    """
    tracker = CoverageTracker()
    if not files:
        if _coverage is not None:
            sc = tracker.coverage(True)
            if sc is not None:
                _coverage["coverage"] = sc
        if strategy.mode == "stream":
            return pd.DataFrame(columns=strategy.columns)
        return pd.DataFrame()

    since_ts = since.timestamp() if since else None
    until_ts = until.timestamp() if until else None

    # The full pre-skip list owns one rendered-label decision for the call;
    # basename identity stays exact after control stripping.
    stripped_names = [strip_control(path.name) for path in files]
    ambiguous = len(set(stripped_names)) != len(stripped_names)

    def _qualified_label(path: Path) -> str | None:
        if not ambiguous or not path.parent.name:
            return None
        return strip_control(f"{path.parent.name}/{path.name}")

    rows: list[dict] = []
    frames: list[pd.DataFrame] = []
    attempted = 0
    permission_paths: list[Path] = []

    for path in files:
        file_rows: list[dict] = []
        file_first_ts: float | None = None
        file_last_ts: float | None = None
        file_span: FileSpan | None = None
        attempted_this_file = False
        try:
            # warn_skip (flat binary/undecodable) runs BEFORE should_skip, inside
            # the try so a corrupt-during-peek read lands on the corruption rail.
            # Unlike should_skip it is DEFAULT-VISIBLE (a load_result.warnings
            # entry, not a verbose-only stderr line); like should_skip it does NOT
            # call note_file_read, so coverage stays honest.
            if strategy.warn_skip is not None:
                warn_msg = strategy.warn_skip(path)
                if warn_msg is not None:
                    if _warnings is not None:
                        _warnings.append(warn_msg)
                    continue
            # should_skip is inside the try so a corrupt compressed file
            # caught during its head sniff lands on the read-corruption rail,
            # not a raw traceback.
            if strategy.should_skip is not None:
                skip_msg = strategy.should_skip(path)
                if skip_msg is not None:
                    # Quiet default - print only under verbose. Preserves the
                    # NDJSON/Zeek-TSV skip-message tests. ``note_file_read``
                    # is NOT fired for a skipped file so the coverage
                    # disclosure doesn't mislead.
                    if verbose:
                        print(strip_control(skip_msg), file=sys.stderr)
                    continue
            attempted_this_file = True
            attempted += 1
            tracker.note_file_read()
            with _loader._open_log(path) as fh:
                line_iter = BoundedLogicalRecordReader(
                    _loader.progress(
                        fh,
                        desc=(
                            "loaded "
                            + strip_control(
                                strategy.display_label
                                or _qualified_label(path)
                                or path.name
                            )
                        ),
                        show_progress=show_progress,
                        unit=strategy.unit,
                    )
                )
                if strategy.mode == "stream":
                    for row in strategy.parse(
                        line_iter, path=path, warnings=_warnings
                    ):
                        kept_ts: float | None = None
                        ts = row["ts"]
                        if _is_infinite_ts(ts):
                            # Infinity is invalid at every policy boundary. It
                            # is distinct from a NaN timestamp, which a
                            # keep-policy source intentionally retains.
                            continue
                        if _missing_ts(ts):
                            tracker.observe(None)
                            if strategy.ts_policy == "drop":
                                continue
                            # keep policy - NaN-ts row bypasses the window
                            # (an unfilterable line stays in the frame).
                        else:
                            if _is_out_of_range_ts(ts):
                                continue
                            normalized_ts = _coerce_usable_ts(ts)
                            if normalized_ts is None:
                                continue
                            row["ts"] = normalized_ts
                            tracker.observe(normalized_ts)
                            if since_ts is not None and normalized_ts < since_ts:
                                continue
                            if until_ts is not None and normalized_ts > until_ts:
                                continue
                            kept_ts = normalized_ts
                        file_rows.append(row)
                        if strategy.records_file_spans and kept_ts is not None:
                            if file_first_ts is None or kept_ts < file_first_ts:
                                file_first_ts = kept_ts
                            if file_last_ts is None or kept_ts > file_last_ts:
                                file_last_ts = kept_ts
                        tracker.mark_kept()
                else:  # frame mode
                    try:
                        pre = strategy.parse(
                            line_iter, path=path, warnings=_warnings
                        )
                    except (ValueError, OverflowError) as exc:
                        # A malformed frame-mode file (e.g. a live/mid-write
                        # Zeek TSV, or one with a broken header) skips THIS
                        # file only - never aborts the run. The skip is
                        # unconditional; only the warning is sink-gated.
                        if _warnings is not None:
                            _warnings.append(_zeek_file_parse_warning(path, exc))
                        continue
                    tracker.observe_frame(pre)
                    post = _apply_ts_filter(pre, since, until)
                    if not post.empty:
                        frames.append(post)
                        if strategy.records_file_spans:
                            file_span = FileSpan(
                                path,
                                float(post["ts"].min()),
                                float(post["ts"].max()),
                            )
                        tracker.mark_kept()
                if _quality is not None:
                    _quality.decoded_records += line_iter.decoded_records
                    _quality.decoded_bytes += line_iter.decoded_bytes
                    _quality.skipped_oversize += line_iter.skipped_oversize
                if line_iter.skipped_oversize and _warnings is not None:
                    noun = "record" if line_iter.skipped_oversize == 1 else "records"
                    _warnings.append(
                        f"{strip_control(path.name)}: skipped "
                        f"{line_iter.skipped_oversize} oversized logical {noun} "
                        "(limit 1 MiB)"
                    )
        except PermissionError as exc:
            if strategy.read_error_factory is not None:
                raise strategy.read_error_factory(exc) from None
            if not attempted_this_file:
                attempted += 1
            permission_paths.append(path)
            if _warnings is not None:
                _warnings.append(_permission_denied_message(path))
            continue
        except (EOFError, gzip.BadGzipFile, lzma.LZMAError, OSError) as exc:
            if strategy.read_error_factory is not None:
                raise strategy.read_error_factory(exc) from None
            # ``_open_log`` returns a lazy reader; corruption may surface only
            # at the trailer after many valid-looking lines. Discard the
            # per-file buffer so the warning is honest (a "skipped with
            # warning" file MUST contribute zero rows), and skip with the
            # standard read-warning. Distinct from CloudTrail's content-parse
            # warning rail (``_cloudtrail_parse_warning``).
            if _warnings is not None:
                _warnings.append(
                    _zeek_file_read_warning(
                        path,
                        exc,
                        display_label=strategy.display_label or _qualified_label(path),
                    )
                )
            continue
        if _quality is not None:
            _quality.committed_files += 1
        if strategy.mode == "stream":
            if (
                strategy.records_file_spans
                and file_first_ts is not None
                and file_last_ts is not None
            ):
                file_span = FileSpan(path, file_first_ts, file_last_ts)
            rows.extend(file_rows)
        if _file_spans is not None and file_span is not None:
            _file_spans.append(file_span)

    if _permission_skips is not None and permission_paths:
        _permission_skips[pattern] = PermissionSkipInfo(
            discovered=attempted,
            denied=len(permission_paths),
            paths=tuple(permission_paths),
        )
    if _quality is not None:
        _quality.attempted_files += attempted

    if strategy.mode == "stream":
        if not rows:
            if _coverage is not None:
                sc = tracker.coverage(True)
                if sc is not None:
                    _coverage["coverage"] = sc
            return pd.DataFrame(columns=strategy.columns)
        if _coverage is not None:
            sc = tracker.coverage(False)
            if sc is not None:
                _coverage["coverage"] = sc
        return pd.DataFrame(rows, columns=strategy.columns)

    # Frame mode (Zeek): concat with TODAY's behavior - bare empty, no forced
    # columns. Zeek's non-empty columns come from parse + normalize.
    result = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    normalized_to_empty = False
    if strategy.normalize is not None and not result.empty:
        result = strategy.normalize(result, pattern, warnings=_warnings)
        normalized_to_empty = result.empty
    if _coverage is not None:
        if normalized_to_empty and _log_type(pattern) in {"conn", "dns", "syslog"}:
            # Parsed rows that normalization rejects are a parse gap, not "no
            # files read"; the runner must not suggest a wider window for
            # content it correctly rejected. This covers syslog message-value
            # drops and conn/dns source-to-canonical rename collisions.
            _coverage["coverage"] = SourceCoverage(0, None)
        else:
            sc = tracker.coverage(result.empty)
            if sc is not None:
                _coverage["coverage"] = sc
    return result


def _chunk_from_frame(
    frame: pd.DataFrame,
    decoded_bytes: int,
    first_ordinal: int,
    window: DualWindow,
) -> DecodedChunk:
    """Normalize positional identity and derive instant-membership vectors."""
    frame = frame.reset_index(drop=True)
    report: list[bool] = []
    context: list[bool] = []
    for value in frame.get("ts", pd.Series(index=frame.index, dtype=float)).tolist():
        try:
            in_report, in_context = window.membership(float(value))
        except (TypeError, ValueError, OverflowError, OSError):
            in_report, in_context = False, False
        report.append(in_report)
        context.append(in_context)
    return DecodedChunk(
        frame=frame,
        decoded_bytes=decoded_bytes,
        report_mask=tuple(report),
        context_mask=tuple(context),
        first_ordinal=first_ordinal,
    )


def _fold_stream_chunks(
    strategy: SourceLoader,
    item: SnapshotFile,
    window: DualWindow,
    warnings: list[str],
    quality_out: dict[Path, SourceFileQuality],
) -> Iterator[DecodedChunk]:
    """Parse a stream strategy once and emit canonical bounded chunks."""
    with open_snapshot_text(item) as handle:
        reader = BoundedLogicalRecordReader(handle)
        parsed = iter(strategy.parse(reader, path=item.path, warnings=warnings))
        prior_bytes = 0

        def rows() -> Iterator[tuple[dict[str, Any], int]]:
            nonlocal prior_bytes
            for row in parsed:
                consumed = reader.decoded_bytes - prior_bytes
                prior_bytes = reader.decoded_bytes
                ts = row.get("ts")
                if _is_infinite_ts(ts) or _is_out_of_range_ts(ts):
                    continue
                if _missing_ts(ts):
                    if strategy.ts_policy == "drop":
                        continue
                else:
                    normalized = _coerce_usable_ts(ts)
                    if normalized is None:
                        continue
                    row["ts"] = normalized
                yield row, consumed

        yield from chunks_from_rows(
            rows(),
            columns=strategy.columns,
            window=window,
            keep_null=strategy.ts_policy == "keep",
        )
        if reader.skipped_oversize:
            noun = "record" if reader.skipped_oversize == 1 else "records"
            warnings.append(
                f"{strip_control(item.path.name)}: skipped "
                f"{reader.skipped_oversize} oversized logical {noun} (limit 1 MiB)"
            )
        quality_out[item.path] = SourceFileQuality(
            decoded_records=reader.decoded_records,
            decoded_bytes=reader.decoded_bytes,
            skipped_oversize=reader.skipped_oversize,
        )


def _fold_zeek_chunks(
    strategy: SourceLoader,
    item: SnapshotFile,
    pattern: str,
    window: DualWindow,
    warnings: list[str],
    quality_out: dict[Path, SourceFileQuality],
    message_drops_out: dict[Path, int],
) -> Iterator[DecodedChunk]:
    """Bound Zeek NDJSON/TSV before DataFrame construction."""
    aggregate_message_drops = _log_type(pattern) == "syslog"
    message_drops = 0

    def normalize(raw: pd.DataFrame) -> pd.DataFrame:
        nonlocal message_drops
        if strategy.normalize is None:
            return raw
        post = strategy.normalize(
            raw,
            pattern,
            warnings=None if aggregate_message_drops else warnings,
        )
        if aggregate_message_drops:
            message_drops += len(raw) - len(post)
        return post

    with open_snapshot_text(item) as handle:
        reader = BoundedLogicalRecordReader(handle)
        prefix: list[str] = []
        prefix_bytes = 0
        first_data: str | None = None
        first_data_bytes = 0
        has_separator = False
        for line in reader:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                first_data = line
                first_data_bytes = reader.last_record_bytes
                break
            prefix.append(line)
            prefix_bytes += reader.last_record_bytes
            if stripped.startswith("#separator"):
                has_separator = True
            if prefix_bytes > MAX_CHUNK_DECODED_BYTES:
                raise ValueError("Zeek header exceeds the decoded chunk byte limit")
        if first_data is None:
            return

        ordinal = 0
        is_ndjson = first_data.lstrip().startswith("{")
        if is_ndjson:
            buffered: list[tuple[dict[str, Any], int]] = []
            buffered_bytes = prefix_bytes
            parsed_records = 0

            def flush() -> DecodedChunk | None:
                nonlocal ordinal, buffered, buffered_bytes
                if not buffered:
                    return None
                raw = _records_frame([row for row, _ in buffered])
                post = normalize(raw)
                chunk = _chunk_from_frame(post, buffered_bytes, ordinal, window)
                ordinal += len(post)
                buffered = []
                buffered_bytes = 0
                return chunk

            for line, size in itertools.chain(
                [(first_data, first_data_bytes)],
                ((line, reader.last_record_bytes) for line in reader),
            ):
                records = _zeek_records_from_lines([line])
                if not records:
                    continue
                parsed_records += 1
                if buffered and (
                    len(buffered) >= MAX_CHUNK_ROWS
                    or buffered_bytes + size > MAX_CHUNK_DECODED_BYTES
                ):
                    chunk = flush()
                    if chunk is not None:
                        yield chunk
                buffered.append((records[0], size))
                buffered_bytes += size
            chunk = flush()
            if chunk is not None:
                yield chunk
            if parsed_records == 0:
                warnings.append(_zeek_no_records_warning(item.path))
        elif has_separator:
            data_lines: list[str] = []
            decoded = prefix_bytes
            bad_lines_all: list[tuple[int, str]] = []
            prior_data_lines = 0

            def flush_tsv() -> DecodedChunk | None:
                nonlocal ordinal, data_lines, decoded, prior_data_lines
                if not data_lines:
                    return None
                bad_lines: list[tuple[int, str]] = []
                raw = _parse_tsv_log(itertools.chain(prefix, data_lines), bad_lines=bad_lines)
                bad_lines_all.extend(
                    (line_number + prior_data_lines, reason)
                    for line_number, reason in bad_lines
                )
                post = normalize(raw)
                chunk = _chunk_from_frame(post, decoded, ordinal, window)
                ordinal += len(post)
                prior_data_lines += len(data_lines)
                data_lines = []
                decoded = 0
                return chunk

            for line, size in itertools.chain(
                [(first_data, first_data_bytes)],
                ((line, reader.last_record_bytes) for line in reader),
            ):
                if line.startswith("#close"):
                    break
                if data_lines and (
                    len(data_lines) >= MAX_CHUNK_ROWS
                    or decoded + size > MAX_CHUNK_DECODED_BYTES
                ):
                    chunk = flush_tsv()
                    if chunk is not None:
                        yield chunk
                data_lines.append(line)
                decoded += size
            chunk = flush_tsv()
            if chunk is not None:
                yield chunk
            if bad_lines_all:
                warnings.append(_zeek_bad_lines_warning(item.path, bad_lines_all))
        else:
            warnings.append(_zeek_no_records_warning(item.path))

        if reader.skipped_oversize:
            noun = "record" if reader.skipped_oversize == 1 else "records"
            warnings.append(
                f"{strip_control(item.path.name)}: skipped "
                f"{reader.skipped_oversize} oversized logical {noun} (limit 1 MiB)"
            )
        quality_out[item.path] = SourceFileQuality(
            decoded_records=reader.decoded_records,
            decoded_bytes=reader.decoded_bytes,
            skipped_oversize=reader.skipped_oversize,
        )
        message_drops_out[item.path] = message_drops


def run_folded_source(
    strategy: SourceLoader,
    snapshot: SourceSnapshot,
    pattern: str,
    window: DualWindow,
    plan: SinkPlan,
    *,
    warnings: list[str] | None = None,
) -> FoldExecution:
    """Run one snapshot through independent frame/fold sinks transactionally."""
    warning_sink = warnings if warnings is not None else []
    file_quality: dict[Path, SourceFileQuality] = {}
    message_value_drops: dict[Path, int] = {}

    def chunks(item: SnapshotFile) -> Iterable[DecodedChunk]:
        if strategy.mode == "stream":
            return _fold_stream_chunks(
                strategy, item, window, warning_sink, file_quality
            )
        return _fold_zeek_chunks(
            strategy,
            item,
            pattern,
            window,
            warning_sink,
            file_quality,
            message_value_drops,
        )

    execution = execute_sink_plan(snapshot, plan, chunks)
    total_message_drops = sum(message_value_drops.values())
    if total_message_drops:
        warning_sink.append(
            _zeek_message_value_warning(pattern, total_message_drops)
        )
    execution.file_quality = {
        item.path: file_quality.get(item.path, SourceFileQuality())
        for item in snapshot.files
    }
    return execution


# Source-family strategy registry. A new format = one entry here → inherits
# the run_load pipeline (progress, coverage, windowing, corruption handling,
# verbose-gated skip) by construction.
#
# ts_policy rationale per family:
#   zeek + cloudtrail = drop. An unparseable Zeek timestamp / CloudTrail
#     eventTime is not trustworthy data; drop before windowing.
#   syslog + pihole   = keep. RFC 3164's year-guess can lose a timestamp
#     without making the LINE less useful (e.g. for drain3 templating /
#     reboot detection); keep + bypass the window.
_SOURCE_LOADERS: dict[str, SourceLoader] = {
    "zeek_dir": SourceLoader(
        discover=discover_zeek_files,
        mode="frame",
        parse=_zeek_strategy_parse,
        ts_policy="drop",
        columns=None,
        should_skip=None,
        normalize=_zeek_normalize,
        # Dated dirs → precise window, no trim; flat / mixed → load full + trim.
        resolve_window=_zeek_resolve_window,
        records_directory_denials=True,
    ),
    "syslog_dir": SourceLoader(
        # Content-gated discovery - the strategy lambda only adapts the
        # signature; _discover_syslog_files is the single discovery body.
        discover=lambda p, pattern, since, until, *, _directory_skips=None: (
            _discover_syslog_files(p, _directory_skips=_directory_skips)
        ),
        mode="stream",
        parse=_syslog_strategy_parse,
        ts_policy="keep",
        columns=_SYSLOG_COLUMNS,
        should_skip=_syslog_should_skip,
        warn_skip=_syslog_warn_undecodable,
        normalize=None,
        window_select=_rotation_windowed_files,
        # Peek rotation candidates → conservative (floor, None) + post-load trim.
        resolve_window=_flat_resolve_window,
        records_directory_denials=True,
    ),
    "pihole_dir": SourceLoader(
        discover=lambda p, pattern, since, until, *, _directory_skips=None: (
            _syslog_files(p, pattern, _directory_skips=_directory_skips)
        ),
        mode="stream",
        parse=_pihole_strategy_parse,
        ts_policy="keep",
        columns=_PIHOLE_COLUMNS,
        should_skip=_pihole_should_skip,
        warn_skip=_pihole_warn_undecodable,
        normalize=None,
        window_select=_rotation_windowed_files,
        resolve_window=_flat_resolve_window,
        records_directory_denials=True,
    ),
    "cloudtrail_dir": SourceLoader(
        discover=lambda p, pattern, since, until, *, _directory_skips=None: (
            discover_cloudtrail_files(p, _directory_skips=_directory_skips)
        ),
        mode="stream",
        parse=_cloudtrail_strategy_parse,
        ts_policy="drop",
        columns=_CLOUDTRAIL_COLUMNS,
        should_skip=None,
        normalize=None,
        # aws is baseline-relative - opt CloudTrail OUT of the auto-default window
        # (an explicit --since/--until still narrows it).
        default_window_eligible=False,
        records_directory_denials=True,
    ),
    "journal": SourceLoader(
        # The producer's lock-protected active-capture registry is the gate;
        # no filename or content recognizer can route arbitrary JSON here.
        discover=_discover_journal_capture,
        mode="stream",
        parse=_journal_strategy_parse,
        ts_policy="drop",
        columns=_SYSLOG_COLUMNS,
        should_skip=None,
        normalize=None,
        display_label="system journal",
        read_error_factory=_journal_read_error,
        records_file_spans=False,
    ),
}


def discover_for_source_key(
    source_key: str,
    directory: Path,
    pattern: str,
    *,
    _directory_skips: (
        dict[tuple[str, Path], DirectorySkipInfo] | None
    ) = None,
) -> list[Path]:
    """Discover one source family's matching files without a time window.

    Source-family discovery stays owned by the registered loader strategy.
    Callers that need a directory probe use this generic entry point instead
    of branching on a family-specific helper.
    """
    strategy = _SOURCE_LOADERS.get(source_key)
    if strategy is None:
        raise ValueError(
            f"unknown source key {source_key!r} - no loader is registered"
        )
    discover_paths = getattr(strategy, "discover_paths", None)
    if discover_paths is None:
        # Preserve the lightweight registry seam used by graph contributors;
        # only SourceLoader declarations participate in denial metadata.
        return strategy.discover(directory, pattern, None, None)
    return discover_paths(
        directory,
        pattern,
        None,
        None,
        _directory_skips=_directory_skips,
    )


def load_logs(
    directory: Path,
    pattern: str,
    since: datetime | None = None,
    until: datetime | None = None,
    _files: list[Path] | None = None,
    _warnings: list[str] | None = None,
    show_progress: bool = True,
    _coverage: dict | None = None,
) -> pd.DataFrame:
    """Discover and load all matching Zeek log files from directory into a single DataFrame.

    Thin shim over ``run_load`` with the ``zeek_dir`` strategy. ``_files`` short-
    circuits discovery (digest single-file Zeek bypass + multi-positional
    dedupe both rely on this); when ``None``, ``discover_zeek_files`` runs
    against ``directory`` with the same window-prune behavior as before.
    Signature is preserved byte-compatible for the ~20 callers.

    _warnings: optional warning sink for per-file operational read failures.
    _coverage: optional out-param. When the returned frame is empty, the loader
        writes ``_coverage["coverage"] = SourceCoverage(...)`` describing the
        pre-window read (None if data survived).
    """
    strategy = _SOURCE_LOADERS["zeek_dir"]
    files = (
        _files
        if _files is not None
        else discover_zeek_files(directory, pattern, since, until)
    )
    return run_load(
        strategy, files, pattern, since, until,
        show_progress=show_progress, verbose=False,
        _warnings=_warnings, _coverage=_coverage,
    )


def load_syslog(
    directory: Path,
    since: datetime | None = None,
    until: datetime | None = None,
    verbose: bool = False,
    _files: list[Path] | None = None,
    _warnings: list[str] | None = None,
    show_progress: bool = True,
    _coverage: dict | None = None,
) -> pd.DataFrame:
    """Discover and load syslog files into a column-stable DataFrame.

    Thin shim over ``run_load`` with the ``syslog_dir`` strategy. Supports a
    directory (per-host files / flat file) or a single file. Wrong-family
    files (NDJSON, Zeek TSV) are skipped via the strategy's ``should_skip``;
    the skip message reaches stderr ONLY when ``verbose=True``. NaN-ts rows
    are KEPT and bypass the window. Returns a column-stable empty frame
    (``_SYSLOG_COLUMNS``) when no rows survive.
    """
    strategy = _SOURCE_LOADERS["syslog_dir"]
    files = _files if _files is not None else _discover_syslog_files(directory)
    return run_load(
        strategy, files, "", since, until,
        show_progress=show_progress, verbose=verbose,
        _warnings=_warnings, _coverage=_coverage,
    )


def load_pihole(
    directory: Path,
    since: datetime | None = None,
    until: datetime | None = None,
    verbose: bool = False,
    _files: list[Path] | None = None,
    _warnings: list[str] | None = None,
    show_progress: bool = True,
    _coverage: dict | None = None,
) -> pd.DataFrame:
    """Discover and load dnsmasq/Pi-hole log files into a column-stable DataFrame.

    Thin shim over ``run_load`` with the ``pihole_dir`` strategy. Wrong-family
    NDJSON files are skipped (Zeek TSV is NOT - Pi-hole's wrong-family
    asymmetry preserved). NaN-ts rows are KEPT and bypass the window.
    Returns a column-stable empty frame (``_PIHOLE_COLUMNS``) when no rows
    survive.
    """
    strategy = _SOURCE_LOADERS["pihole_dir"]
    files = _files if _files is not None else _syslog_files(directory, "pihole*.log*")
    return run_load(
        strategy, files, "", since, until,
        show_progress=show_progress, verbose=verbose,
        _warnings=_warnings, _coverage=_coverage,
    )


def load_cloudtrail(
    path: Path,
    since: datetime | None = None,
    until: datetime | None = None,
    verbose: bool = False,
    _files: list[Path] | None = None,
    _warnings: list[str] | None = None,
    show_progress: bool = True,
    _coverage: dict | None = None,
) -> pd.DataFrame:
    """Discover and load CloudTrail event files into a canonical-schema DataFrame.

    Thin shim over ``run_load`` with the ``cloudtrail_dir`` strategy. Single-
    iterator wire-shape sniff (NDJSON / envelope / bare-list) preserved by
    the strategy's ``parse``. Events with unparseable ``eventTime`` are
    DROPPED before windowing. Bad files (compressed corruption) warn and
    skip; malformed-JSON content failures append
    ``_cloudtrail_parse_warning`` to ``_warnings`` (distinct rail from the
    read-corruption ``_zeek_file_read_warning``). Returns a column-stable
    empty frame (``_CLOUDTRAIL_COLUMNS``) when no rows survive.

    Note: ``verbose`` is accepted for signature compatibility but is unused
    (the strategy has no ``should_skip``); CloudTrail's per-file content
    warnings ride ``_warnings`` rather than stderr.
    """
    strategy = _SOURCE_LOADERS["cloudtrail_dir"]
    files = _files if _files is not None else discover_cloudtrail_files(path)
    return run_load(
        strategy, files, "", since, until,
        show_progress=show_progress, verbose=verbose,
        _warnings=_warnings, _coverage=_coverage,
    )


def load_required_logs(
    needed_logs: dict[str, str],
    source_dirs: dict[str, list[Path]],
    since: datetime | None = None,
    until: datetime | None = None,
    verbose: bool = False,
    source_windows: dict[str, tuple[datetime | None, datetime | None]] | None = None,
    show_progress: bool = True,
    file_select_windows: dict[str, tuple[datetime | None, datetime | None]] | None = None,
    trusted_files: Mapping[str, Sequence[Path]] | None = None,
    sink_plans: Mapping[str, SinkPlan] | None = None,
    dual_windows: Mapping[str, DualWindow] | None = None,
    prepared_snapshots: Mapping[str, SourceSnapshot] | None = None,
    _directory_skips: (
        dict[tuple[str, Path], DirectorySkipInfo] | None
    ) = None,
) -> LoadResult:
    """Load all patterns required by a run plan and return data plus metadata.

    ``source_dirs`` is keyed by source family (``zeek_dir`` / ``syslog_dir`` /
    ``pihole_dir`` / ``cloudtrail_dir``); each value is a LIST of inputs (each
    a directory or an explicit file) contributed by positionals, the
    ``--<family>-dir`` flag, and config fallback. The loader iterates each
    family's inputs, runs the EXISTING per-input discovery, concatenates the
    results, dedupes by ``.resolve()`` preserving first-seen order, and loads
    the union. Single-input (one-element list) behavior is byte-identical
    with the prior scalar shape.

    ``source_windows`` overrides ``(since, until)`` per source key. This lets
    the runner apply a Zeek-derived default window to Zeek loads only,
    leaving syslog/pihole unwindowed when the user gave no explicit timeframe.
    It is the PRECISE window: it row-filters at ``run_load`` AND prunes discovery
    (dated-Zeek date-dir pruning, explicit operator windows).

    ``file_select_windows`` is a CONSERVATIVE file-selection-only floor per source
    key (the flat default-window floor). It feeds the rotation-peek
    (``window_select``) ONLY, never ``run_load`` - the authoritative post-load trim
    (``apply_default_window``) does the row windowing. Decoupling the two prevents a
    flat floor (anchored on a PEEKED ``f_max``) from over-pruning real rows at load
    when the file supplying ``f_max`` peeks fine but fails to load. A source absent
    from this map falls back to its ``source_windows`` entry for file selection too.

    ``trusted_files`` is an optional pattern-keyed mapping of explicit FILE
    inputs whose content router already asserted their source kind. These files
    bypass only filename-based discovery gates; they still traverse the normal
    parse, window, normalization, warning, coverage, byte-accounting, and
    permission-accounting path. It is keyed by pattern because one source
    family can load multiple patterns.

    ``prepared_snapshots`` reuses an exact content-bound population for a later
    fold pass. A prepared pattern bypasses discovery, rotation selection, and
    snapshot recapture; the existing fold verifier still checks every captured
    byte boundary. Patterns absent from the mapping retain the ordinary path.

    ``_directory_skips`` is the caller-owned plan sink for pre-candidate input-root
    listing denials. Discovery updates it by ``(source, realpath)``; it is not
    copied into ``LoadResult``. CloudTrail does not claim recursive-child coverage.
    """
    logs: dict[str, pd.DataFrame] = {}
    record_counts: dict[str, int] = {}
    warnings: list[str] = []
    data_size_bytes = 0
    coverage: dict[str, SourceCoverage] = {}
    rotation_skips: dict[str, RotationSkipInfo] = {}
    permission_skips: dict[str, PermissionSkipInfo] = {}
    file_spans: dict[str, tuple[FileSpan, ...]] = {}
    quality: dict[str, LoadQuality] = {}
    source_windows = source_windows or {}
    file_select_windows = file_select_windows or {}
    trusted_files = trusted_files or {}
    sink_plans = sink_plans or {}
    dual_windows = dual_windows or {}
    prepared_snapshots = prepared_snapshots or {}
    snapshots: dict[str, SourceSnapshot] = {}
    fold_results: dict[str, dict[str, Any]] = {}
    prepared_status: dict[str, PreparedStatus] = {}
    availability = {}
    snapshot_cache: dict[
        tuple[str, tuple[Path, ...], datetime | None, datetime | None],
        SourceSnapshot,
    ] = {}

    for pattern, source in needed_logs.items():
        paths = source_dirs.get(source) or []
        trusted = list(trusted_files.get(pattern, ()))
        prepared_snapshot = prepared_snapshots.get(pattern)
        if not paths and not trusted and prepared_snapshot is None:
            warnings.append(f"{source} not configured - {pattern} not loaded")
            continue

        # Explicit paths bypass parts of filename-based discovery by design,
        # but the provenance namespace is never log input.  Enforce that
        # exception before source-specific routing so flat-file inputs cannot
        # slip past the discovery-layer guard.
        for explicit_path in [*paths, *trusted]:
            reject_explicit_reserved_path(explicit_path)

        strategy = _SOURCE_LOADERS.get(source)
        if strategy is None:
            raise ValueError(
                f"unknown source key {source!r} for pattern {pattern!r} - "
                "no loader is registered for it"
            )

        s_since, s_until = source_windows.get(source, (since, until))

        skip_info: RotationSkipInfo | None = None
        if prepared_snapshot is not None:
            if prepared_snapshot.source != source:
                raise ValueError(
                    f"prepared snapshot for {pattern!r} belongs to "
                    f"{prepared_snapshot.source!r}, not {source!r}"
                )
            files = [item.path for item in prepared_snapshot.files]
            resolved_files = {_safe_resolve(path) for path in files}
            unexpected_trusted = [
                path for path in trusted if _safe_resolve(path) not in resolved_files
            ]
            if unexpected_trusted:
                raise ValueError(
                    f"trusted file is outside prepared snapshot for {pattern!r}"
                )
        elif strategy.window_select is None:
            # Zeek / CloudTrail: normal inputs retain their existing discovery
            # behavior. Trusted explicit files bypass only a discovery name-gate
            # (for example, an arbitrarily named but sniff-approved Zeek file),
            # then converge on the same deduped run_load path.
            trusted_resolved = {_safe_resolve(p) for p in trusted}
            files_per_input = [
                [p] if _safe_resolve(p) in trusted_resolved
                else strategy.discover_paths(
                    p,
                    pattern,
                    s_since,
                    s_until,
                    _directory_skips=_directory_skips,
                )
                for p in paths
            ]
            input_resolved = {_safe_resolve(p) for p in paths}
            extra_trusted = [
                p for p in trusted if _safe_resolve(p) not in input_resolved
            ]
            files = _union_dedupe([*files_per_input, extra_trusted])
        else:
            # Flat (syslog / pihole) - ordinal-rotation peek-prune of the
            # directory-discovered candidates. Explicit FILES the operator named
            # are partitioned out, protected from BOTH the windowing input and
            # the skip count, and always loaded.
            file_inputs = _union_dedupe([
                [p for p in paths if p.is_file()],
                trusted,
            ])
            dir_inputs = [p for p in paths if p.is_dir()]
            dir_candidates = _union_dedupe([
                strategy.discover_paths(
                    d,
                    pattern,
                    s_since,
                    s_until,
                    _directory_skips=_directory_skips,
                )
                for d in dir_inputs
            ])
            # Silent-miss disclosure, forked by source. syslog discovery is
            # content-gated, so "zero candidates from a dir that holds files"
            # means nothing matched a supported syslog format - distinct from
            # pihole's
            # filename-pattern mismatch. Either way a security tool must not
            # swallow it silently. Explicit files load regardless and never
            # reach this check.
            if dir_inputs and not dir_candidates:
                if source == "syslog_dir":
                    # Cheap iterdir presence check (NO sniff, NO `*.log*` test) so
                    # an extensionless-only dir is disclosed, not dropped silently.
                    # Directory path(s) only - never a per-file name list.
                    offending = [d for d in dir_inputs if _dir_has_regular_files(d)]
                    if offending:
                        names = ", ".join(str(d) for d in offending)
                        warnings.append(
                            f"syslog_dir: nothing in {names} looks like syslog "
                            f"(RFC 3164 or ISO-8601) - nothing loaded "
                            f"(check the path)."
                        )
                elif any(_syslog_files(d, "*.log*") for d in dir_inputs):
                    warnings.append(
                        f"{source}: directory has .log files but none match "
                        f"{pattern!r} - not loaded (check the log file naming)."
                    )
            explicit_resolved = {_safe_resolve(p) for p in file_inputs}
            dir_for_window = [
                p for p in dir_candidates
                if _safe_resolve(p) not in explicit_resolved
            ]
            # The rotation-peek selects FILES off the conservative file-selection
            # floor (the flat default-window floor); run_load below row-filters on
            # the PRECISE window only. A source absent from file_select_windows
            # falls back to its precise window, so explicit operator windows peek
            # and row-filter on the same tuple (byte-identical to before).
            fs_since, fs_until = file_select_windows.get(source, (s_since, s_until))
            if (fs_since or fs_until) and dir_for_window:
                selected_dir, skip_info = strategy.window_select(
                    dir_for_window, fs_since, fs_until, verbose=verbose
                )
            else:
                selected_dir = dir_for_window
            files = _union_dedupe([file_inputs, selected_dir])

        availability[pattern] = validate_selected_files(files)

        captured_sizes = (
            {item.path: item.stat_bytes for item in prepared_snapshot.files}
            if prepared_snapshot is not None
            else {}
        )
        for path in files:
            try:
                if path.is_file():
                    data_size_bytes += (
                        captured_sizes[path]
                        if path in captured_sizes
                        else path.stat().st_size
                    )
            except OSError as exc:
                if strategy.read_error_factory is not None:
                    raise strategy.read_error_factory(exc) from None
                # The read loop records permission and corruption outcomes;
                # an unreadable file simply has no reliable size to add.
                continue

        cov_dict: dict = {}
        pattern_spans: list[FileSpan] = []
        pattern_quality = LoadQuality()
        sink_plan = sink_plans.get(pattern)
        if sink_plan is not None and sink_plan.requires_snapshot:
            dual_window = dual_windows.get(pattern)
            if dual_window is None:
                raise ValueError(f"fold plan for {pattern!r} requires a DualWindow")
            snapshot_key = (
                source,
                tuple(_safe_resolve(path) for path in files),
                s_since,
                s_until,
            )
            snapshot = prepared_snapshot or snapshot_cache.get(snapshot_key)
            if snapshot is None:
                snapshot = build_source_snapshot(
                    files,
                    source,
                    scan_interval=(s_since, s_until),
                )
                snapshot_cache[snapshot_key] = snapshot
            execution = run_folded_source(
                strategy,
                snapshot,
                pattern,
                dual_window,
                sink_plan,
                warnings=warnings,
            )
            quality_snapshot = replace(
                snapshot,
                files=tuple(
                    replace(
                        item,
                        quality=execution.file_quality.get(
                            item.path,
                            SourceFileQuality(),
                        ),
                    )
                    for item in snapshot.files
                ),
            )
            snapshots[pattern] = quality_snapshot
            fold_results[pattern] = execution.results
            for channel, status in execution.statuses.items():
                if channel in prepared_status:
                    raise ValueError(f"duplicate fold channel {channel!r}")
                prepared_status[channel] = status
            warnings.extend(execution.file_errors)
            df = execution.frame
            if strategy.records_file_spans:
                pattern_spans.extend(
                    FileSpan(path, span[0], span[1])
                    for path, span in execution.file_spans.items()
                )
            if df.empty:
                if not snapshot.files:
                    cov_dict["coverage"] = SourceCoverage(None, None)
                elif execution.observed_valid_rows == 0:
                    cov_dict["coverage"] = SourceCoverage(0, None)
                elif sink_plan.preserve_frame and execution.observed_span is not None:
                    cov_dict["coverage"] = SourceCoverage(
                        execution.observed_valid_rows,
                        (
                            datetime.fromtimestamp(
                                execution.observed_span[0],
                                tz=timezone.utc,
                            ),
                            datetime.fromtimestamp(
                                execution.observed_span[1],
                                tz=timezone.utc,
                            ),
                        ),
                    )
            pattern_quality.attempted_files = execution.attempted_files
            pattern_quality.committed_files = execution.committed_files
            pattern_quality.decoded_records = sum(
                item.decoded_records for item in execution.file_quality.values()
            )
            pattern_quality.decoded_bytes = sum(
                item.decoded_bytes for item in execution.file_quality.values()
            )
            pattern_quality.skipped_oversize = sum(
                item.skipped_oversize for item in execution.file_quality.values()
            )
        else:
            df = run_load(
                strategy, files, pattern, s_since, s_until,
                show_progress=show_progress, verbose=verbose,
                _warnings=warnings, _coverage=cov_dict,
                _permission_skips=permission_skips,
                _file_spans=pattern_spans,
                _quality=pattern_quality,
            )
        quality[pattern] = pattern_quality
        if pattern_spans:
            file_spans[pattern] = tuple(pattern_spans)

        if skip_info is not None:
            rotation_skips[pattern] = skip_info

        logs[pattern] = df
        if not df.empty:
            record_counts[pattern] = len(df)

        if "coverage" in cov_dict:
            coverage[pattern] = cov_dict["coverage"]

        warning = _schema_warning(pattern, df)
        if warning:
            warnings.append(warning)

    return LoadResult(
        logs=logs,
        record_counts=record_counts,
        data_window=_data_window(logs),
        warnings=warnings,
        data_size_bytes=data_size_bytes,
        coverage=coverage,
        rotation_skips=rotation_skips,
        permission_skips=permission_skips,
        file_spans=file_spans,
        quality=quality,
        snapshots=snapshots,
        fold_results=fold_results,
        prepared_status=prepared_status,
        availability=availability,
    )


def resolve_load_windows(
    needed_sources: dict[str, str],
    source_dirs: dict[str, list[Path]],
    default_spec: str,
    *,
    since: datetime | None,
    until: datetime | None,
    load_all: bool,
    pre_resolved_windows: Mapping[str, LoadWindow] | None = None,
    _directory_skips: (
        dict[tuple[str, Path], DirectorySkipInfo] | None
    ) = None,
) -> list[LoadWindow]:
    """Resolve the universal default window into ONE ``LoadWindow`` per family.

    The SINGLE window-policy entry point both ``run()`` and ``run_digest()`` call -
    it replaced the runner's per-family name-ladder and the digest twin. Returns
    ``[]`` (no default window engaged anywhere) when the operator gave an explicit
    window, passed ``--all``, or ``default_window`` is empty/"all"/invalid.

    Otherwise builds one :class:`LoadWindow` per source family that is in
    ``needed_sources`` (the plan's pattern→source map), configured in
    ``source_dirs``, UNBOUNDED (any directory in the bucket), AND eligible
    (``default_window_eligible`` - CloudTrail opts out, baseline-relative). Each
    family's OWN strategy resolves the ``(select_window, trim_span)`` via its
    declared ``resolve_window`` (or :func:`_default_resolve_window` when it declares
    none - load full + trim, the universal default a new flat source inherits with
    zero runner edits). ``keep_null`` is read straight off ``strategy.ts_policy``.

    ``needed_sources`` carries the pattern→source map so the flat resolver recovers
    the detector glob per family (``pattern``) - first pattern per family, without
    reintroducing a source-name branch.

    ``_directory_skips`` is the same caller-owned sink used at plan and load
    time; denial-aware resolvers update it without changing custom strategy
    call signatures.
    """
    if load_all or since is not None or until is not None:
        return []
    span = parse_window_span(default_spec)
    if span is None:
        return []
    injected = dict(pre_resolved_windows or {})
    invalid_keys = set(injected) - {"journal"}
    if invalid_keys:
        raise ValueError("pre-resolved windows are supported only for journal")
    if "journal" in injected and (
        not isinstance(injected["journal"], LoadWindow)
        or injected["journal"].source != "journal"
    ):
        raise ValueError("pre-resolved journal window has the wrong source")

    # Families present in the plan, stable order, deduped.
    planned_sources: list[str] = []
    for src in needed_sources.values():
        if src not in planned_sources:
            planned_sources.append(src)

    if "journal" in injected:
        if "journal" not in planned_sources or not source_dirs.get("journal"):
            raise ValueError(
                "pre-resolved journal window requires an in-plan configured source"
            )

    windows: list[LoadWindow] = []
    for source in planned_sources:
        dirs = source_dirs.get(source)
        if source in injected:
            # The producer's exact default window wins before the temporary
            # explicit capture is classified as bounded. Preserve object identity.
            windows.append(injected[source])
            continue
        if not dirs or is_bounded(dirs):
            continue
        strategy = _SOURCE_LOADERS.get(source)
        # Declared opt-out: CloudTrail (baseline-relative) produces NO default
        # window → loads full on unqualified runs. Explicit windows still apply
        # (handled before this function via the since/until short-circuit).
        if strategy is None or not strategy.default_window_eligible:
            continue
        # First pattern per family - matches the prior name-ladder; the flat
        # resolver anchors its conservative floor from DIRECTORY candidates only.
        pattern = next(
            (p for p, s in needed_sources.items() if s == source), "*.log*"
        )
        resolver = strategy.resolve_window or _default_resolve_window
        if (
            _directory_skips is None
            or not strategy.records_directory_denials
        ):
            # Preserve the callable contract for programmatic/custom strategies.
            select_window, trim_span = resolver(strategy, dirs, pattern, span)
        else:
            select_window, trim_span = resolver(
                strategy,
                dirs,
                pattern,
                span,
                _directory_skips=_directory_skips,
            )
        keep_null = strategy.ts_policy == "keep"
        windows.append(LoadWindow(source, select_window, trim_span, keep_null))
    return windows
