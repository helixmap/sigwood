"""Run planning, source and window resolution, previews, and population preparation."""
from __future__ import annotations

import importlib
import pkgutil
import sys
import time
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Collection, Iterator, Mapping, Sequence

import pandas as pd

if TYPE_CHECKING:
    from sigwood.common.loader import types as load_types

from sigwood.common.config import DEFAULT_DETECT_SPEC, get_detector_config, parse_window_span
from sigwood.common.display import (
    compact_path_list as _compact_path_list, cursor_visible, default_window_advisory,
    fmt_timestamp, fmt_window, group_skips, human_bytes, plural,
)
from sigwood.common.errors import ExportAborted
from sigwood.common.finding import Declined, Preparation, PreparedPopulation
from sigwood.common.loader import (
    CoverageDecision, DirectorySkipInfo, DualWindow, ExportAvailability, PositionalMask,
)
from sigwood.common.sources import (
    ResolvedSources, SyslogDecisionReason, SyslogIntent, SyslogProbeDecision,
    SyslogProvider, SyslogProviderDecision, declared_source_patterns as _declared_source_patterns,
    syslog_lane_detectors,
)
from sigwood.common.sanitize import strip_control


@dataclass(frozen=True)
class RunPlan:
    """Detector plan plus pre-load source-directory omission facts."""

    detectors: dict[str, Any]
    selected: list[str]
    will_run: list[str]
    skipped: dict[str, str]
    needed_logs: dict[str, str]
    directory_skips: dict[tuple[str, Path], DirectorySkipInfo] = field(
        default_factory=dict,
    )


@dataclass(frozen=True)
class DetectorSelection:
    """Detector discovery, vocabulary, and selection before source probing."""

    detectors: dict[str, Any]
    selected: list[str]
    import_failures: dict[str, str]
    used_default: bool = False
    vocab: dict[str, Any] = field(default_factory=dict)


def _discovery_liveness(discovery: Any | None, *, quiet: bool) -> Any:
    """The planning-phase spinner, entered only when the shared inventory runs.

    Observation can take a while on a large directory, so the inventory path
    shows a delayed spinner around planning. Without a discovery context the
    phase sequence is exactly the historical one.
    """
    if discovery is None:
        return nullcontext()
    return runner.liveness("finding log files", delay=0.5, enabled=not quiet)


def _source_dirs_for_provider(
    resolved: ResolvedSources,
    provider: SyslogProvider,
    *,
    journal_path: Path | None = None,
) -> dict[str, list[Path]]:
    """Build the loader map with at most one local system-log carrier."""
    source_dirs: dict[str, list[Path]] = {}
    for key in ("zeek_dir", "pihole_dir", "cloudtrail_dir"):
        paths = list(getattr(resolved, key))
        if paths:
            source_dirs[key] = paths
    if provider is SyslogProvider.FILES and resolved.syslog_dir:
        source_dirs["syslog_dir"] = list(resolved.syslog_dir)
    elif provider is SyslogProvider.JOURNAL:
        if journal_path is None:
            return source_dirs
        source_dirs["journal"] = [journal_path]
    return source_dirs


def _emit_syslog_skip_diagnostic(
    plan: RunPlan,
    decision: SyslogProviderDecision,
    intent: SyslogIntent,
) -> None:
    """Explain the local provider when a selected lane detector is skipped."""
    if (
        not any(
            name in plan.skipped
            for name in syslog_lane_detectors(plan.selected, plan.detectors)
        )
        or not intent.report_local_lane
    ):
        return
    if decision.provider is SyslogProvider.OFF:
        runner._estderr("system logs: local lane off")
    elif decision.provider is SyslogProvider.FILES:
        runner._estderr("system logs: no eligible flat files found")


@dataclass(frozen=True)
class _RunWindows:
    """The windows a run loads with, resolved once from its final plan."""

    populations: dict[str, Any] | None
    load_windows: list[Any]
    source_windows: dict[str, tuple[datetime | None, datetime | None]] | None
    file_select_windows: dict[str, tuple[datetime | None, datetime | None]] | None
    policies: dict[str, Any]
    history_floors: dict[str, tuple[datetime, str]]


def _resolve_run_windows(
    plan: RunPlan,
    source_dirs: dict[str, list[Path]],
    *,
    inventory: Any | None,
    default_spec: str,
    load_all: bool,
    since: datetime | None,
    until: datetime | None,
    pre_resolved_windows: Mapping[str, Any] | None = None,
) -> _RunWindows:
    """Resolve a run's windows from its final plan, for the load and its preview.

    This is the one owner of the populations published from the final
    post-arbitration plan, the resolver's windows and the reason it recorded
    for each family, the precise and file-selection maps, and the history
    aperture a selected detector widens file selection by. Both the load and
    the dry-run preview call it, so the preview selects with the load's windows.
    """
    from sigwood.common import loader

    # Published only now, from the final post-arbitration plan, so a population
    # can never describe a provider the run did not choose.
    populations = (
        inventory.populations(plan.needed_logs, source_dirs)
        if inventory is not None
        else None
    )
    policies: dict[str, Any] = {}
    load_windows = loader.resolve_load_windows(
        plan.needed_logs,
        source_dirs,
        default_spec,
        load_all=load_all,
        since=since,
        until=until,
        pre_resolved_windows=pre_resolved_windows,
        _directory_skips=plan.directory_skips,
        _discovery=populations,
        _policies=policies,
    )
    source_windows = (
        {
            window.source: window.select_window
            for window in load_windows
            if window.select_window is not None and window.trim_span is None
        }
        or None
    )
    file_select_windows = (
        {
            window.source: window.select_window
            for window in load_windows
            if window.select_window is not None and window.trim_span is not None
        }
        or None
    )
    history_floors: dict[str, tuple[datetime, str]] = {}
    dnsblock_mod = (
        plan.detectors.get("dnsblock") if "dnsblock" in plan.will_run else None
    )
    dnsblock_population = (
        getattr(dnsblock_mod, "PREPARED_POPULATION", None)
        if dnsblock_mod is not None else None
    )
    if (dnsblock_population is not None
            and dnsblock_population.pattern == runner._PIHOLE_PATTERN
            and file_select_windows is not None):
        pihole_file_window = file_select_windows.get("pihole_dir")
        if pihole_file_window is not None:
            floor, upper = pihole_file_window
            if floor is not None:
                widened = floor - timedelta(days=dnsblock_mod.ARRIVAL_HISTORY)
                file_select_windows = {
                    **file_select_windows,
                    "pihole_dir": (widened, upper),
                }
                history_floors["pihole_dir"] = (widened, dnsblock_mod.DETECTOR_NAME)
    return _RunWindows(
        populations=populations,
        load_windows=load_windows,
        source_windows=source_windows,
        file_select_windows=file_select_windows,
        policies=policies,
        history_floors=history_floors,
    )


@dataclass(frozen=True)
class _FamilyPreview:
    """One source family's preview, unioned across its patterns by real path."""

    discovered: tuple[Path, ...]
    selected: tuple[Path, ...]
    not_selected: tuple[Path, ...]
    discovered_bytes: int
    discovered_unsized: tuple[Path, ...]
    selected_bytes: int
    selected_unsized: tuple[Path, ...]


@dataclass(frozen=True)
class _DryRunPreview:
    """What a run would select, computed by the load's own window and selection owners."""

    windows: _RunWindows
    families: dict[str, _FamilyPreview]
    warnings: tuple[str, ...]
    fallback_lines: tuple[str, ...]
    estimates: dict[str, Any] = field(default_factory=dict)


def _dry_run_preview(
    plan: RunPlan,
    source_dirs: dict[str, list[Path]],
    *,
    inventory: Any | None,
    default_spec: str,
    load_all: bool,
    since: datetime | None,
    until: datetime | None,
    virtual_sources: Collection[tuple[str, str]],
    verbose: bool,
) -> _DryRunPreview:
    """Select each family's files the way the run would, without loading them.

    The windows come from ``_resolve_run_windows`` and the files from the
    loader's own selector, so the preview cannot disagree with the run it
    describes. A virtual ``(source, pattern)`` pair has no files to select,
    so it gets none. The bounded estimate samples selected bytes without
    parsing, hashing, validating or capturing them.
    """
    from sigwood.common import loader

    windows = runner._resolve_run_windows(
        plan,
        source_dirs,
        inventory=inventory,
        default_spec=default_spec,
        load_all=load_all,
        since=since,
        until=until,
    )
    needed = {
        pattern: source
        for pattern, source in plan.needed_logs.items()
        if (source, pattern) not in virtual_sources
    }
    previews = loader.preview_required_files(
        needed,
        source_dirs,
        since,
        until,
        source_windows=windows.source_windows,
        file_select_windows=windows.file_select_windows,
        discovered_candidates=windows.populations,
        verbose=verbose,
        _directory_skips=plan.directory_skips,
    )
    by_source: dict[str, list[Any]] = {}
    for preview in previews.values():
        by_source.setdefault(preview.source, []).append(preview)
    families: dict[str, _FamilyPreview] = {}
    for source, items in by_source.items():
        # One file can serve several patterns of a family; it is one file here,
        # and a file another pattern selects is never called unselected.
        discovered = loader._union_dedupe([list(item.discovered) for item in items])
        selected = loader._union_dedupe([list(item.selected) for item in items])
        selected_real = {loader._safe_resolve(path) for path in selected}
        not_selected = tuple(
            path for path in discovered
            if loader._safe_resolve(path) not in selected_real
        )
        discovered_bytes, discovered_unsized = loader.on_disk_bytes(discovered)
        selected_bytes, selected_unsized = loader.on_disk_bytes(selected)
        families[source] = _FamilyPreview(
            discovered=tuple(discovered),
            selected=tuple(selected),
            not_selected=not_selected,
            discovered_bytes=discovered_bytes,
            discovered_unsized=discovered_unsized,
            selected_bytes=selected_bytes,
            selected_unsized=selected_unsized,
        )
    warnings = tuple(
        line for preview in previews.values() for line in preview.warnings
    )
    fallback_lines = tuple(
        runner._rotation_fallback_line(
            runner._pattern_human_label(preview.source, pattern), preview.rotation_skip,
        )
        for pattern, preview in previews.items()
        if preview.rotation_skip is not None and preview.rotation_skip.fallback
    )
    return _DryRunPreview(
        windows=windows,
        families=families,
        warnings=warnings,
        fallback_lines=fallback_lines,
        estimates=loader.estimate_population(previews),
    )


@dataclass
class _PopulationPreparation:
    declaration: PreparedPopulation
    host: _PreparationHost
    preparation: Preparation


def _preparation_cause(value: object, capture_paths: tuple[str, ...]) -> str:
    """Remove ephemeral source paths before composing preparation diagnostics."""
    text = str(value)
    for path in sorted(capture_paths, key=len, reverse=True):
        if path:
            text = text.replace(path, "system journal capture")
    return strip_control(text.splitlines()[0] if text.splitlines() else "")


def _population_interval(
    available_start: datetime | None, available_end: datetime | None, *,
    since: datetime | None, until: datetime | None, load_all: bool,
    default_spec: str, now: datetime,
) -> tuple[datetime, datetime]:
    """Resolve the inclusive report interval from requested and observed bounds."""
    if since is not None and until is not None:
        return since, until
    if load_all:
        end = available_end or now
        return available_start or end, end
    if since is not None:
        return since, max(since, available_end or now)
    if until is not None:
        return min(available_start or until, until), until
    end = available_end or now
    span = parse_window_span(default_spec)
    return (end - span if span is not None else available_start or end), end


class _PreparationHost:
    """Per-detector access to the loader under one resolved run plan."""

    def __init__(self, name: str, pattern: str, config: dict[str, Any], plan: RunPlan,
                 load_args: dict[str, Any], load_windows: list[Any], allowlist: Any,
                 load_all: bool, default_spec: str, quiet: bool,
                 upper_bound_bytes: int | None = None, *,
                 no_allowlist: bool = False,
                 progress_path: Path | None = None) -> None:
        from sigwood.common import loader
        self.name, self.pattern, self.config = name, pattern, config
        declared_sources = [req["source"] for req in (
            *getattr(plan.detectors[name], "REQUIRED_LOGS", ()),
            *getattr(plan.detectors[name], "OPTIONAL_LOGS", ()),
        ) if req["pattern"] == pattern]
        self.source_key = plan.needed_logs.get(pattern) or next(
            (source for source in declared_sources if load_args["source_dirs"].get(source)),
            declared_sources[0],
        )
        report_start, report_end = (load_args.get("source_windows") or {}).get(
            self.source_key, (load_args["since"], load_args["until"])
        )
        self.report_window = DualWindow((
            report_start or datetime.min.replace(tzinfo=timezone.utc),
            report_end or datetime.max.replace(tzinfo=timezone.utc),
        ))
        self._planned = pattern in plan.needed_logs
        self._args = dict(load_args)
        self._args["source_dirs"] = {
            key: list(paths) for key, paths in load_args["source_dirs"].items()
        }
        self._allowlist = allowlist
        self._no_allowlist = no_allowlist
        self._progress_path = progress_path
        self.load_all, self.quiet = load_all, quiet
        self._default_spec = default_spec
        self.exact_window = not any(
            w.source == self.source_key and w.trim_span is not None for w in load_windows
        )
        self.explicit_file = any(
            p.is_file() for p in self._args["source_dirs"].get(self.source_key, ())
        )
        preview_args = {k: v for k, v in self._args.items() if k != "show_progress"}
        preview = loader.preview_required_files({pattern: self.source_key}, **preview_args)
        self.local_files = len(preview[pattern].selected)
        self.upper_bound_bytes = upper_bound_bytes
        self.sibling_needs_frame = any(
            other != name and any(
                req["pattern"] == pattern
                for req in (*getattr(plan.detectors[other], "REQUIRED_LOGS", ()),
                            *getattr(plan.detectors[other], "OPTIONAL_LOGS", ()))
            ) for other in plan.will_run
        )
        self.registration = None
        self.final_wall_seconds = 0.0
        self.timings: dict[str, float] = {}

    def fold(self, sink_plan: load_types.SinkPlan, dual_window: DualWindow, *,
             prepared_snapshot: load_types.SourceSnapshot | None = None,
             tail_policy: str = "whole") -> load_types.LoadResult:
        """Run one source pass, retaining diagnostics only in its returned facts."""
        from sigwood.common import loader
        return loader.load_required_logs(
            {self.pattern: self.source_key}, **self._args,
            sink_plans={self.pattern: sink_plan}, dual_windows={self.pattern: dual_window},
            prepared_snapshots=({self.pattern: prepared_snapshot} if prepared_snapshot else {}),
            snapshot_tail_policies={self.pattern: tail_policy}, progress_verb="indexed",
        )

    def mask(self, frame: pd.DataFrame) -> PositionalMask:
        """Apply the run matcher to this detector channel."""
        if self._no_allowlist:
            return PositionalMask((True,) * len(frame))
        return runner._positional_allowlist_mask(frame, self._allowlist, self.name)

    def window(self, available_start: datetime | None,
               available_end: datetime | None
               ) -> tuple[DualWindow, tuple[datetime, datetime]]:
        """Resolve observed bounds, defaulting to now; not a first-pass window."""
        interval = _population_interval(
            available_start, available_end, since=self._args["since"],
            until=self._args["until"], load_all=self.load_all,
            default_spec=self._default_spec, now=datetime.now(timezone.utc),
        )
        window = runner._resolve_fold_dual_window(
            interval, available_start=available_start,
            bounded_explicit=(self.explicit_file or self._args["since"] is not None
                              or self._args["until"] is not None), load_all=self.load_all,
        )
        return window, interval

    def coverage(self, facts: tuple[ExportAvailability, ...],
                 report_interval: tuple[datetime, datetime]) -> CoverageDecision:
        return runner._select_coverage_lane(facts, report_interval)

    def progress(self, *, snapshot_identity: str,
                 report_interval: tuple[datetime, datetime], block_status: Any,
                 pass_wall_seconds: tuple[tuple[str, float], ...]) -> None:
        if self._progress_path is not None:
            runner._write_dnsblock_preflight_progress(
                self._progress_path, snapshot_identity=snapshot_identity,
                report_interval=report_interval, block_status=block_status,
                pass_wall_seconds=pass_wall_seconds,
            )

    def final(self, sink_plan: load_types.SinkPlan, dual_window: DualWindow, *,
              prepared_snapshot: load_types.SourceSnapshot) -> None:
        """Register one provisional final pass."""
        if not self._planned:
            raise ValueError("cannot register a pattern absent from the load plan")
        if self.registration is not None:
            raise ValueError("a preparation may register its final load only once")
        self.registration = (sink_plan, dual_window, prepared_snapshot)

    @contextmanager
    def timer(self, name: str) -> Iterator[None]:
        """Accumulate elapsed seconds for a named preparation operation."""
        started = time.monotonic()
        try:
            yield
        finally:
            self.timings[name] = self.timings.get(name, 0.0) + time.monotonic() - started


def _suppression_contribution(frame: pd.DataFrame, matcher: Any):
    """Measure scope-blind coverage once, shared by folds and ordinary frames."""
    from sigwood.common.finding import SuppressionContribution
    if "query" in frame.columns:
        return SuppressionContribution(domains=matcher.count_domain_suppressed(frame),
                                       domain_total=len(frame))
    connections = matcher.count_numeric_suppressed(frame) if "src" in frame.columns else 0
    rows, hosts = matcher.count_host_suppressed(frame) if "host" in frame.columns else (0, ())
    return SuppressionContribution(
        connections=connections, connection_total=len(frame) if "src" in frame.columns else 0,
        host_rows=rows, host_total=len(frame) if "host" in frame.columns else 0,
        matched_hosts=frozenset(hosts),
    )


def _merge_suppression(left: Any, right: Any):
    from sigwood.common.finding import SuppressionContribution
    return SuppressionContribution(
        left.connections + right.connections, left.domains + right.domains,
        left.connection_total + right.connection_total, left.domain_total + right.domain_total,
        left.host_rows + right.host_rows, left.host_total + right.host_total,
        left.matched_hosts | right.matched_hosts,
    )


def _suppression_sink(name: str, matcher: Any):
    from sigwood.common.finding import SuppressionContribution
    from sigwood.common.loader.types import FoldDelta, FoldSink, PositionalMask
    def consume(delta, chunk, mask):
        frame = chunk.frame.loc[list(chunk.report_mask)]
        value = _merge_suppression(delta.value, _suppression_contribution(frame, matcher))
        size = sys.getsizeof(value.matched_hosts) + sum(sys.getsizeof(h) for h in value.matched_hosts)
        return FoldDelta(value, size)
    return FoldSink(
        f"{runner._SUPPRESSION_CHANNEL}:{name}", lambda: FoldDelta(SuppressionContribution(), 0),
        consume, SuppressionContribution, lambda state, delta: _merge_suppression(state, delta.value),
        lambda frame: PositionalMask((True,) * len(frame)),
    )


def _record_preparation_disposition(
    name: str, declaration: PreparedPopulation, disposition: Declined,
    failures: dict[str, str], notes: list[str], capture_paths: tuple[str, ...], *,
    unrecovered: bool = False,
) -> None:
    from sigwood.common.finding import DeclineReason
    cause = _preparation_cause(disposition.cause, capture_paths)
    if unrecovered or not declaration.recoverable:
        reason = cause or disposition.reason.value
        failures[name] = f"prep error - {reason}"
        runner._estderr(f"{name}: {failures[name]}")
    elif disposition.reason is not DeclineReason.INELIGIBLE:
        detail = f" - {cause}" if cause else ""
        notes.append(f"{name}: prepared load {disposition.reason.value}{detail}; "
                     "analysis ran on the full frame")


def _prepare_populations(
    plan: RunPlan, load_args: dict[str, Any], load_windows: list[Any], config: dict,
    allowlist: Any, load_all: bool, default_spec: str, quiet: bool,
    capture_paths: tuple[str, ...], suppression_enabled: bool = False,
    population_estimates: Mapping[str, Any] | None = None,
    no_allowlist: bool = False,
    dnsblock_preflight_path: Path | None = None,
) -> tuple[dict[str, _PopulationPreparation], dict[str, str], list[str]]:
    from sigwood.common.finding import Declined, DeclineReason, Preparation, PreparedPopulation
    declarations = {}
    owners: dict[str, str] = {}
    for name in plan.will_run:
        declaration = getattr(plan.detectors[name], "PREPARED_POPULATION", None)
        if declaration is None:
            continue
        if not isinstance(declaration, PreparedPopulation):
            raise ValueError(f"{name}: invalid prepared population declaration")
        pattern = declaration.pattern
        declared = {r["pattern"] for r in (
            *getattr(plan.detectors[name], "REQUIRED_LOGS", ()),
            *getattr(plan.detectors[name], "OPTIONAL_LOGS", ()),
        )}
        if pattern not in declared:
            raise ValueError(f"{name}: prepared pattern {pattern!r} is not in the load plan")
        if pattern in owners:
            raise ValueError(f"{owners[pattern]} and {name} both prepare {pattern!r}")
        owners[pattern] = name
        declarations[name] = declaration
    committed, failures, notes = {}, {}, []
    for name, declaration in declarations.items():
        mod = plan.detectors[name]
        try:
            det_cfg = get_detector_config(config, name, getattr(mod, "DEFAULT_CONFIG", {}))
            if hasattr(mod, "validate_config"):
                mod.validate_config(det_cfg)
        except Exception as exc:
            _record_preparation_disposition(name, declaration, Declined(DeclineReason.FAILED, str(exc).strip() or type(exc).__name__),
                                            failures, notes, capture_paths, unrecovered=True)
            continue
        try:
            estimate = (population_estimates or {}).get(declaration.pattern)
            host = _PreparationHost(name, declaration.pattern, det_cfg, plan, load_args,
                                    load_windows, allowlist, load_all, default_spec, quiet,
                                    upper_bound_bytes=(estimate.upper_bound_bytes if estimate is not None else None),
                                    no_allowlist=no_allowlist,
                                    progress_path=(dnsblock_preflight_path if name == "dnsblock" else None))
            prepared = declaration.prepare(host)
            if isinstance(prepared, Declined):
                _record_preparation_disposition(name, declaration, prepared, failures, notes,
                                                capture_paths)
            elif isinstance(prepared, Preparation):
                if host.registration is None:
                    raise ValueError("preparation returned without registering a final load")
                final_plan, _, _ = host.registration
                if (declaration.pattern == runner._LOCAL_SYSLOG_PATTERN
                        and final_plan.admit is not None
                        and prepared.arbitration_hosts is None):
                    raise ValueError("local syslog admission requires population arbitration hosts")
                channels = [sink.channel for sink in final_plan.folds]
                if final_plan.admit is not None:
                    channels.append(final_plan.admit.channel)
                if any(c == runner._SUPPRESSION_CHANNEL or c.startswith(runner._SUPPRESSION_CHANNEL + ":")
                       for c in channels):
                    raise ValueError("preparation uses a reserved coverage channel")
                # Admission replaces the ordinary frame, so its source-wide
                # coverage needs a fold channel. A fold-only plan that drops
                # its frame keeps the established empty banner denominator.
                if suppression_enabled and final_plan.admit is not None:
                    from dataclasses import replace
                    _, window, snapshot = host.registration
                    host.registration = (replace(final_plan, folds=(
                        *final_plan.folds, runner._suppression_sink(name, allowlist),
                    )), window, snapshot)
                committed[name] = _PopulationPreparation(declaration, host, prepared)
            else:
                raise ValueError("prepare must return Preparation or Declined")
        except Exception as exc:
            _record_preparation_disposition(name, declaration, Declined(DeclineReason.FAILED, str(exc).strip() or type(exc).__name__),
                                            failures, notes, capture_paths)
    return committed, failures, notes


def _population_load_maps(
    committed: dict[str, _PopulationPreparation],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    plans, windows, snapshots = {}, {}, {}
    for item in committed.values():
        pattern = item.declaration.pattern
        plans[pattern], windows[pattern], snapshots[pattern] = item.host.registration
    return plans, windows, snapshots


def _recover_populations(
    result: load_types.LoadResult, committed: dict[str, _PopulationPreparation],
    failures: dict[str, str], notes: list[str], capture_paths: tuple[str, ...],
) -> load_types.LoadResult:
    from sigwood.common import loader
    from sigwood.common.finding import Declined, DeclineReason
    for name, item in list(committed.items()):
        plan, _, _ = item.host.registration
        status = result.prepared_status.get(plan.admit.channel) if plan.admit is not None else None
        admission_failed = plan.admit is not None and (
            status is None or status.state is loader.PreparedState.FAILED
        )
        coverage_channels = [sink.channel for sink in plan.folds
                             if sink.channel.startswith(runner._SUPPRESSION_CHANNEL + ":")]
        coverage_failed = any(result.prepared_status.get(channel) is None or
                              result.prepared_status[channel].state is not loader.PreparedState.READY
                              for channel in coverage_channels)
        expected_files = item.preparation.expected_committed_files
        outcomes = result.file_outcomes.get(item.declaration.pattern)
        files_failed = expected_files is not None and (
            outcomes is None or outcomes.committed != expected_files
        )
        if not admission_failed and not coverage_failed and not files_failed:
            continue
        pattern = item.declaration.pattern
        reload = loader.load_required_logs({pattern: item.host.source_key}, **item.host._args)
        result = loader.replace_pattern_load(result, pattern, plan, reload)
        del committed[name]
        _record_preparation_disposition(
            name, item.declaration, Declined(DeclineReason.FAILED,
                "committed file set changed" if files_failed else
                "population coverage unavailable" if coverage_failed else
                status.cause if status is not None else "final admission unavailable"),
            failures, notes, capture_paths,
        )
    return result


def _plan_and_load(
    *,
    detect_spec: str | None,
    selection: DetectorSelection,
    source_dirs: dict[str, list[Path]],
    scope: frozenset[str] | None,
    provider_decision: SyslogProviderDecision,
    syslog_intent: SyslogIntent,
    default_spec: str,
    load_all: bool,
    since: datetime | None,
    until: datetime | None,
    verbose_level: int,
    quiet: bool,
    allowlist: Any,
    pre_resolved_windows: Mapping[str, Any] | None = None,
    dnsblock_preflight_path: Path | None = None,
    no_allowlist: bool = False,
    discovery: Any | None = None,
    recursive_retry: str | None = None,
    preparation_config: dict | None = None,
    preparation_suppression_enabled: bool = False,
    capture_paths: tuple[str, ...] = (),
    cfg_sigwood: dict[str, Any] | None = None,
    skip_confirm: bool = False,
) -> runner._LoadedPlan | int:
    """Build the final plan and eagerly load its one-provider source map.

    With a ``discovery`` context the plan is built from its inventory, which
    is first asked here, after the system-log provider is decided. Coverage
    facts print before any detector skip line, and the observed populations,
    published from the final plan, feed window resolution and every load pass.
    """
    from sigwood.common import loader

    inventory = discovery.inventory if discovery is not None else None
    with _discovery_liveness(discovery, quiet=quiet):
        plan = runner.build_run_plan(
            detect_spec=detect_spec,
            zeek_dir=source_dirs.get("zeek_dir"),
            syslog_dir=source_dirs.get("syslog_dir"),
            pihole_dir=source_dirs.get("pihole_dir"),
            cloudtrail_dir=source_dirs.get("cloudtrail_dir"),
            journal=source_dirs.get("journal"),
            scope=scope,
            selection=selection,
            inventory=inventory,
        )
    coverage_lines: tuple[runner.Note, ...] = ()
    if discovery is not None:
        span = (
            parse_window_span(default_spec)
            if not load_all and since is None and until is None else None
        )
        coverage_lines = tuple(
            runner._discovery_coverage_lines(
                discovery, plan, source_dirs, default_span=span, dry_run=False,
                recursive_retry=recursive_retry,
            )
        )
        for line in coverage_lines:
            runner._estderr(line.text)
        if not plan.will_run:
            # No report will render, so the denial notes it would carry go here.
            for line in runner._unowned_directory_skip_lines(plan, source_dirs):
                runner._estderr(line.text)
    _emit_syslog_skip_diagnostic(plan, provider_decision, syslog_intent)
    runner._warn_skips(plan.skipped)
    if not plan.will_run:
        if plan.skipped:
            runner._estderr(
                "no detectors could run - check required log source paths in config "
                "or CLI overrides"
            )
            return 1
        runner._estderr("no detectors to run - the detect spec selected none")
        return 0

    windows = runner._resolve_run_windows(
        plan,
        source_dirs,
        inventory=inventory,
        default_spec=default_spec,
        load_all=load_all,
        since=since,
        until=until,
        pre_resolved_windows=pre_resolved_windows,
    )
    populations = windows.populations
    load_windows = windows.load_windows
    source_windows = windows.source_windows
    file_select_windows = windows.file_select_windows
    if load_windows and not quiet:
        open_ended = any(
            window.trim_span is None
            and window.select_window is not None
            and window.select_window[1] is None
            for window in load_windows
        )
        runner._estderr(default_window_advisory(
            default_spec, open_ended=open_ended,
        ))
    load_args = dict(source_dirs=source_dirs, since=since, until=until,
                     verbose=verbose_level >= 1, source_windows=source_windows,
                     show_progress=not quiet, file_select_windows=file_select_windows,
                     _directory_skips=plan.directory_skips, discovered_candidates=populations)
    large_dataset_prompted = False
    gate_config = cfg_sigwood or {}
    previews = loader.preview_required_files(
        plan.needed_logs, source_dirs, since, until,
        source_windows=source_windows,
        file_select_windows=file_select_windows,
        discovered_candidates=populations,
        verbose=verbose_level >= 1,
        _directory_skips=plan.directory_skips,
    )
    estimates = loader.estimate_population(previews)
    if not skip_confirm and _warn_above(gate_config) > 0:
        large_dataset_prompted = runner._confirm_large_dataset(
            sum(item.records for item in estimates.values()), gate_config,
            skip_confirm=False,
            estimate=tuple(estimates.values()),
        )
    committed, preparation_failures, preparation_notes = _prepare_populations(
        plan, load_args, load_windows, preparation_config or {}, allowlist,
        load_all, default_spec, quiet, capture_paths, preparation_suppression_enabled,
        population_estimates=estimates,
        no_allowlist=no_allowlist,
        dnsblock_preflight_path=dnsblock_preflight_path,
    )
    declared_plans, declared_windows, declared_snapshots = _population_load_maps(committed)
    report_interval = (
        (since, until) if since is not None and until is not None else None
    )
    final_started = time.monotonic()
    load_result = loader.load_required_logs(
        plan.needed_logs,
        source_dirs,
        since,
        until,
        sink_plans=declared_plans, dual_windows=declared_windows,
        prepared_snapshots=declared_snapshots,
        verbose=verbose_level >= 1,
        source_windows=source_windows,
        show_progress=not quiet,
        file_select_windows=file_select_windows,
        _directory_skips=plan.directory_skips,
        discovered_candidates=populations,
    )
    final_wall_seconds = time.monotonic() - final_started
    for item in committed.values():
        item.host.final_wall_seconds = final_wall_seconds
    load_result = _recover_populations(
        load_result, committed, preparation_failures, preparation_notes, capture_paths,
    )
    coverage_decisions = {
        pattern: runner._select_coverage_lane(
            load_result.availability.get(pattern, ()), report_interval,
        )
        for pattern in plan.needed_logs
    }
    if discovery is not None:
        unselected = runner._unselected_retained_lines(discovery, plan, load_result)
        for line in unselected:
            runner._estderr(line.text)
        coverage_lines = (*coverage_lines, *unselected)
    return runner._LoadedPlan(
        plan=plan,
        source_dirs=source_dirs,
        load_result=load_result,
        load_windows=load_windows,
        default_spec=default_spec,
        coverage_decisions=coverage_decisions,
        coverage_lines=coverage_lines,
        population_preparations=committed,
        preparation_failures=preparation_failures,
        preparation_notes=preparation_notes,
        large_dataset_prompted=large_dataset_prompted,
    )


def _build_dual_window(
    report_interval: tuple[datetime, datetime],
    context_interval: tuple[datetime, datetime] | None = None,
) -> DualWindow:
    """Runner-owned constructor; loader types validate the temporal contract."""
    return DualWindow(report_interval, context_interval)


def discover_detectors(
    *,
    _failures: dict[str, str] | None = None,
    _vocab: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Scan sigwood/detectors/ and return available detector modules by name.

    ``_failures`` is an optional caller-owned sink: when present, a module
    whose import raises ImportError is recorded as ``{module_name: first line
    of the error}`` instead of vanishing silently. The key is the pkgutil
    MODULE name, not DETECTOR_NAME - a module that failed to import cannot be
    asked for its DETECTOR_NAME (the two are equal for every shipped
    detector). The catch stays ImportError-only: a missing dependency is the
    declared recoverable class; any other failure (e.g. a syntax error in a
    corrupt module) raises loudly.

    ``_vocab`` is a separate optional caller-owned sink populated during the
    same scan. Successfully imported detector modules record ``DEFAULT_CONFIG``
    (including planned stubs, before status filtering); ImportError module names
    record ``None`` because their vocabulary cannot be read.
    """
    detectors: dict[str, Any] = {}
    for _finder, name, _ispkg in pkgutil.iter_modules(runner._detectors_pkg.__path__):
        try:
            mod = importlib.import_module(f"{runner._detectors_pkg.__name__}.{name}")
        except ImportError as exc:
            if _failures is not None:
                msg = str(exc).strip()
                _failures[name] = msg.splitlines()[0] if msg else type(exc).__name__
            if _vocab is not None:
                _vocab[name] = None
            continue
        if not hasattr(mod, "DETECTOR_NAME"):
            continue
        detector_name = mod.DETECTOR_NAME
        if _vocab is not None:
            _vocab[detector_name] = getattr(mod, "DEFAULT_CONFIG", None)
        if getattr(mod, "STATUS", "available") == "available":
            detectors[detector_name] = mod
    return detectors


def select_detectors(
    detect_spec: str | None,
    detectors: dict[str, Any] | None = None,
) -> DetectorSelection:
    """Resolve detector selection without inspecting source availability."""
    import_failures: dict[str, str] = {}
    vocab: dict[str, Any] = {}
    if detectors is not None:
        all_detectors = detectors
        vocab.update({
            name: getattr(mod, "DEFAULT_CONFIG", None)
            for name, mod in detectors.items()
        })
    else:
        all_detectors = runner.discover_detectors(
            _failures=import_failures,
            _vocab=vocab,
        )
    effective_spec = str(detect_spec or DEFAULT_DETECT_SPEC)
    default_members = sorted(
        name
        for name, mod in all_detectors.items()
        if getattr(mod, "IN_DEFAULT_HUNT", False)
    )
    tokens = _spec_tokens(effective_spec)
    selected = resolve_detect(
        effective_spec,
        sorted(all_detectors),
        import_failed=sorted(import_failures),
        default_members=default_members,
    )
    return DetectorSelection(
        all_detectors,
        selected,
        import_failures,
        used_default="default" in tokens,
        vocab=vocab,
    )


def _as_path_list(value: Path | list[Path] | None) -> list[Path]:
    """Normalize a build_run_plan / _print_dry_run source-dir param.

    Accepts None (absent), a scalar Path (degenerate one-element list), or a
    list of Paths (the canonical multi-input shape). Returns a list - empty
    means absent. Lets callers and tests pass either form without juggling
    the boundary; the internal pipeline operates on lists only. SAME
    normalization shape as ``runner.run`` accepting ``str | Path | Sequence
    | None`` at its outer boundary, propagated inward.
    """
    if value is None:
        return []
    if isinstance(value, Path):
        return [value]
    return list(value)


def build_run_plan(
    detect_spec: str | None,
    zeek_dir: Path | list[Path] | None = None,
    syslog_dir: Path | list[Path] | None = None,
    pihole_dir: Path | list[Path] | None = None,
    cloudtrail_dir: Path | list[Path] | None = None,
    journal: Path | list[Path] | None = None,
    detectors: dict[str, Any] | None = None,
    scope: frozenset[str] | None = None,
    selection: DetectorSelection | None = None,
    virtual_sources: frozenset[tuple[str, str]] = frozenset(),
    *,
    inventory: Any | None = None,
) -> RunPlan:
    """Resolve detector selection, required-log skips, and log patterns to load.

    Each source-dir parameter accepts ``None`` (absent), a scalar ``Path``
    (degenerate one-element list), or a list of ``Path``s (the canonical
    multi-input shape from the resolver). Plan-time satisfiability uses the
    SAME discovery helpers the loader uses (``discover_zeek_files``,
    ``discover_cloudtrail_files``, ``_syslog_files``); plan and loader MUST
    discover the same universe. A detector whose module import failed at
    discovery is skipped with an ``import failed - <reason>`` entry - never
    silently dropped, never reported as unknown. ``scope`` (the run's
    positional-scoping signal) only refines skip WORDING - a family scoped out
    by positional targets reads as out-of-scope, not "not configured".
    Zeek/syslog directory listing denials accumulate in the plan-owned sink so
    skipped detectors get the permission cause and partial reports retain the
    missing-directory disclosure through later window/load probes.

    With an ``inventory`` (the analyze run's ``DiscoveryInventory``), every
    input of every source a selected detector declares is observed before any
    satisfiability answer is reduced, so an early success or an early failed
    requirement can never leave a later input, or its denial, unobserved.
    Every later question is then answered from those observations. Reasons and
    selection outcomes are the same either way.
    """
    resolved_selection = selection or runner.select_detectors(detect_spec, detectors)
    import_failures = resolved_selection.import_failures
    all_detectors = resolved_selection.detectors
    selected = resolved_selection.selected

    source_map: dict[str, list[Path]] = {}
    zeek_paths = _as_path_list(zeek_dir)
    syslog_paths = _as_path_list(syslog_dir)
    pihole_paths = _as_path_list(pihole_dir)
    cloudtrail_paths = _as_path_list(cloudtrail_dir)
    journal_paths = _as_path_list(journal)
    if zeek_paths:
        source_map["zeek_dir"] = zeek_paths
    if syslog_paths:
        source_map["syslog_dir"] = syslog_paths
    if pihole_paths:
        source_map["pihole_dir"] = pihole_paths
    if cloudtrail_paths:
        source_map["cloudtrail_dir"] = cloudtrail_paths
    if journal_paths:
        source_map["journal"] = journal_paths

    will_run: list[str] = []
    skipped: dict[str, str] = {}
    directory_skips: dict[tuple[str, Path], DirectorySkipInfo] = {}
    if inventory is not None:
        declared = _declared_source_patterns(
            [name for name in selected if name not in import_failures],
            all_detectors,
            virtual_sources,
        )
        for source, patterns in declared.items():
            if not inventory.supports(source):
                continue
            for path in source_map.get(source, []):
                for pattern in patterns:
                    inventory.candidates(
                        source, path, pattern, _directory_skips=directory_skips,
                    )
    for name in selected:
        # An import-failed name is absent from all_detectors - skip it before
        # the required-logs check (which would KeyError). The reason does not
        # embed the detector name; both render surfaces prefix it.
        if name in import_failures:
            skipped[name] = f"import failed - {import_failures[name]}"
            continue
        reason = _check_required_logs(
            all_detectors[name],
            source_map,
            scope,
            virtual_sources,
            _directory_skips=directory_skips,
            inventory=inventory,
        )
        if reason:
            skipped[name] = reason
        else:
            will_run.append(name)

    # Only include OPTIONAL_LOGS patterns that are actually satisfiable, to avoid
    # loading empty frames for optional sources that happen to be configured but have
    # no matching files (e.g. zeek_dir present but no dns*.log* when pihole satisfied).
    needed_logs: dict[str, str] = {}
    for name in will_run:
        mod = all_detectors[name]
        for req in getattr(mod, "REQUIRED_LOGS", []):
            _claim_needed_log(needed_logs, req["pattern"], req["source"])
        for req in getattr(mod, "OPTIONAL_LOGS", []):
            if _is_optional_satisfiable(
                req,
                source_map,
                virtual_sources,
                _directory_skips=directory_skips,
                inventory=inventory,
            ):
                _claim_needed_log(needed_logs, req["pattern"], req["source"])

    return RunPlan(
        detectors=all_detectors,
        selected=selected,
        will_run=will_run,
        skipped=skipped,
        needed_logs=needed_logs,
        directory_skips=directory_skips,
    )


def _detector_token(detectors_run: list[str]) -> str | None:
    """Auto-name token from the detectors that ran: 1 → the name; ≥2 →
    ``<first>-plus<K>`` (K = total − 1); 0 → None (token omitted)."""
    names = list(detectors_run)
    if not names:
        return None
    return names[0] if len(names) == 1 else f"{names[0]}-plus{len(names) - 1}"


def _spec_tokens(spec: str) -> list[str]:
    """Tokenize a detector selection spec with forgiving comma/space syntax."""
    return [t.strip() for t in spec.replace(",", " ").split() if t.strip()]


def resolve_detect(
    spec: str,
    available: list[str],
    *,
    import_failed: Collection[str] = (),
    default_members: Collection[str] = (),
) -> list[str]:
    """Resolve a detect= spec (default, all, list, exclusions) against detectors.

    Examples:
      "default"           → curated default members
      "all"               → all available names (sorted)
      "dns, beacon"       → ["dns", "beacon"]
      "default,!beacon"   → curated members except beacon
      "all,!dns,!syslog"  → all except dns and syslog

    Every token other than the reserved "default" and "all" keywords - inclusion
    or "!"-exclusion alike - must name an available detector; unknown names raise
    ValueError listing every unknown token (a typo'd exclusion silently running a
    detector would be a coverage loss, so exclusions validate too). A spec that
    tokenises to nothing (e.g. whitespace-only) resolves to an empty selection,
    not an error.

    ``import_failed`` names detectors whose module import failed at discovery
    (see ``discover_detectors``). A failed name is a KNOWN token - includable
    (so the run plan can disclose the skip), excludable (the natural workaround
    for a broken detector), and appended after the available names under "all" or
    "default" - never reported as an unknown detector. The unknown-name error
    still lists only available names.
    """
    tokens = _spec_tokens(spec)

    unknown: list[str] = []
    for token in tokens:
        name = token[1:] if token.startswith("!") else token
        if (
            name not in {"all", "default"}
            and name not in available
            and name not in import_failed
            and name not in unknown
        ):
            unknown.append(name)
    if unknown:
        names = ", ".join(f"'{n}'" for n in unknown)
        raise ValueError(
            f"unknown {plural(len(unknown), 'detector')} {names}"
            f" - available: {', '.join(available)}"
        )

    inclusions: list[str] = []
    exclusions: set[str] = set()

    for token in tokens:
        if token.startswith("!"):
            exclusions.add(token[1:])
        elif token == "default":
            inclusions.extend(default_members)
            inclusions.extend(
                name for name in import_failed if name not in inclusions
            )
        elif token == "all":
            # Replace with all available, plus the import-failed names so the
            # plan can disclose their skips (appended after, order-stable).
            inclusions = list(available) + [n for n in import_failed if n not in available]
        elif token in available or token in import_failed:
            inclusions.append(token)

    # Deduplicate while preserving order, then apply exclusions
    seen: set[str] = set()
    result: list[str] = []
    for name in inclusions:
        if name not in seen and name not in exclusions:
            seen.add(name)
            result.append(name)

    return result


def _any_input_yields_files(
    source: str,
    paths: list[Path],
    pattern: str,
    *,
    _directory_skips: (
        dict[tuple[str, Path], DirectorySkipInfo] | None
    ) = None,
    inventory: Any | None = None,
) -> bool:
    """Plan-time discovery lockstep with the LOADER for one family.

    Per-family mapping (matches ``load_required_logs``):

    - ``zeek_dir``      → ``discover_zeek_files(input, pattern)`` per input
    - ``cloudtrail_dir``→ its registered recursive discovery per input
    - ``syslog_dir``    → ``_discover_syslog_files(input)`` per input - the LOADER
      content-sniffs syslog DIRECTORY candidates (RHEL/Fedora streams carry no
      ``.log`` suffix; ``dnf.log`` etc. would be mis-claimed by a filename glob),
      so plan-time MUST too (one-universe rail). A ``/var/log`` holding only
      ``dnf.log`` reports syslog NOT satisfiable → the detector skips with its
      actionable "not found" message instead of garbage.
    - ``pihole_dir``    → its registered ``_syslog_files(input, pattern)`` per
      input - the LOADER threads the detector's pattern (``pihole*.log*``) into
      ``_syslog_files`` for DIRECTORY discovery, so plan-time MUST too. An
      explicit FILE still routes as ``[path]`` regardless of pattern, so a
      content-routed Pi-hole input named e.g. ``events.log`` is NOT plan-rejected.

    Returns True iff ANY input yields at least one file.

    With an ``inventory`` the answer comes from its observations of every
    input, the same selection the loader will run; a missing input still
    contributes nothing.
    """
    from sigwood.common.loader import (
        _discover_syslog_files,
        discover_for_source_key,
        discover_zeek_files,
    )
    if inventory is not None and inventory.supports(source):
        answers = [
            bool(inventory.candidates(
                source, p, pattern, _directory_skips=_directory_skips,
            ))
            for p in paths
        ]
        return any(answers)
    for p in paths:
        if not p.exists():
            continue
        if source == "zeek_dir":
            if discover_zeek_files(
                p,
                pattern,
                _directory_skips=_directory_skips,
            ):
                return True
        elif source == "cloudtrail_dir":
            if discover_for_source_key(
                source,
                p,
                pattern,
                _directory_skips=_directory_skips,
            ):
                return True
        elif source == "syslog_dir":
            if _discover_syslog_files(
                p, _directory_skips=_directory_skips,
            ):
                return True
        elif source == "pihole_dir":
            if discover_for_source_key(
                source,
                p,
                pattern,
                _directory_skips=_directory_skips,
            ):
                return True
        elif source == "journal":
            if discover_for_source_key(
                "journal",
                p,
                pattern,
                _directory_skips=_directory_skips,
            ):
                return True
        else:
            # Defensive: unknown source key. Fall back to plain glob over
            # directories so an unrecognized future family doesn't silently
            # plan-skip. The loader will raise the actionable error.
            if p.is_file():
                return True
            if list(p.glob(pattern)):
                return True
    return False


def _is_optional_satisfiable(
    req: dict[str, str],
    source_map: dict[str, Path | list[Path]],
    virtual_sources: frozenset[tuple[str, str]] = frozenset(),
    *,
    _directory_skips: (
        dict[tuple[str, Path], DirectorySkipInfo] | None
    ) = None,
    inventory: Any | None = None,
) -> bool:
    """Return True if an OPTIONAL_LOGS entry has files available to load."""
    source = req["source"]
    if (source, req["pattern"]) in virtual_sources:
        return True
    paths = _as_path_list(source_map.get(source))
    if not paths:
        return False
    return _any_input_yields_files(
        source,
        paths,
        req["pattern"],
        _directory_skips=_directory_skips,
        inventory=inventory,
    )


def _directory_denial_reason(
    source: str,
    paths: Sequence[Path],
    directory_skips: dict[tuple[str, Path], DirectorySkipInfo] | None,
) -> str | None:
    """Return bounded skip copy when a configured input was unlistable."""
    if not directory_skips:
        return None
    configured: set[Path] = set()
    for path in paths:
        try:
            configured.add(path.resolve())
        except OSError:
            configured.add(path)
    denied = [
        info.path
        for (source_key, resolved), info in directory_skips.items()
        if source_key == source and resolved in configured
    ]
    if not denied:
        return None
    rendered = _compact_path_list(denied)
    if len(denied) == 1:
        return (
            f"{source} directory could not be listed (permission denied): "
            f"{rendered}"
        )
    return (
        f"{source} directories could not be listed (permission denied): "
        f"{rendered}"
    )


def _check_required_logs(
    detector_module: Any,
    source_map: dict[str, Path | list[Path]],
    scope: frozenset[str] | None = None,
    virtual_sources: frozenset[tuple[str, str]] = frozenset(),
    *,
    _directory_skips: (
        dict[tuple[str, Path], DirectorySkipInfo] | None
    ) = None,
    inventory: Any | None = None,
) -> str | None:
    """Return None if all REQUIRED_LOGS are available, or a human-readable reason if not.

    ``scope`` is the run's positional-scoping signal (None = unconstrained).
    A source family absent BECAUSE the operator's positional targets scoped it
    out must not read as "not configured" - the operator may have pointed
    straight at a directory containing that family's files; the reason
    names the scoping, not a config gap.
    """
    for req in getattr(detector_module, "REQUIRED_LOGS", []):
        source = req["source"]
        pattern = req["pattern"]

        if (source, pattern) in virtual_sources:
            continue

        paths = _as_path_list(source_map.get(source))
        if not paths:
            if scope is not None and source not in scope:
                return f"{source} outside this run's positional scope"
            return f"{source} not configured"

        # Existence skip-reason mirrors single-input behavior on a one-element
        # list: report the missing path. With multiple inputs, satisfiability
        # is "ANY input yields files" - _any_input_yields_files handles
        # per-input existence checks (skips non-existent), so we only emit a
        # not-found skip when NO input yields anything.
        if not _any_input_yields_files(
            source,
            paths,
            pattern,
            _directory_skips=_directory_skips,
            inventory=inventory,
        ):
            denial_reason = _directory_denial_reason(
                source, paths, _directory_skips,
            )
            if denial_reason is not None:
                return denial_reason
            if len(paths) == 1:
                p = paths[0]
                if not p.exists():
                    return _not_found_reason(source, p)
                if source == "cloudtrail_dir":
                    # Preserve the family-specific wording for the no-events
                    # skip path - recursive AWSLogs/<acct>/CloudTrail/<region>/
                    # discovery means a plain "pattern not found" reads
                    # confusingly.
                    return f"no CloudTrail JSON logs found in {p}"
                return f"{pattern} not found in {p}"
            # Multi-input - name the family rather than a single path.
            return f"{pattern} not found in any configured {source} input"

    if getattr(detector_module, "REQUIRES_ONE_OF_OPTIONAL", False):
        for opt in getattr(detector_module, "OPTIONAL_LOGS", []):
            if _is_optional_satisfiable(
                opt,
                source_map,
                virtual_sources,
                _directory_skips=_directory_skips,
                inventory=inventory,
            ):
                return None
        for opt in getattr(detector_module, "OPTIONAL_LOGS", []):
            source = opt["source"]
            denial_reason = _directory_denial_reason(
                source,
                _as_path_list(source_map.get(source)),
                _directory_skips,
            )
            if denial_reason is not None:
                return denial_reason
        # The reason NEVER embeds the detector name - both render surfaces prefix
        # it (the doubled-name skip-line bug class), so the fallback carries none.
        return getattr(
            detector_module,
            "REQUIRES_ONE_OF_OPTIONAL_REASON",
            "no source available",
        )

    return None


def _not_found_reason(source: str, path: Path) -> str:
    """The single-input skip reason for a configured input that does not exist."""
    return f"{source} {path} not found"


def _claim_needed_log(
    needed_logs: dict[str, str], pattern: str, source: str
) -> None:
    """Add one load claim while rejecting different-source pattern collisions."""
    existing = needed_logs.get(pattern)
    if existing is None:
        needed_logs[pattern] = source
        return
    if existing != source:
        raise ValueError(
            f"log pattern {pattern!r} is claimed by both {existing} and {source} - "
            "source arbitration must select one provider"
        )


def _status_entry_display(p: Path) -> str:
    """Render one source input for the dry-run block."""
    status = "found" if p.exists() else "not found"
    return f"{p}  ({status})"


def _print_family_block(label: str, paths: list[Path], formatter) -> None:
    """Render one source-family block in the dry-run output.

    Empty list  → ``{label:<15}  not configured``.
    One input   → ``{label:<15}  {formatter(input)}``.
    Multi-input → the first entry rides the label line, subsequent entries
    indent under it at the same value column (17 chars: 15-char LEFT-justified
    label + 2-space gutter). NEVER emits a Python list repr.

    Labels are LEFT-justified to match the window/detectors/skipped block.
    """
    head = f"{label + ':':<{runner._BANNER_LABEL_WIDTH}}"
    indent = " " * runner._BANNER_LABEL_WIDTH  # matches the left-justified label width
    if not paths:
        print(f"{head}  not configured")
        return
    entries = [strip_control(formatter(p)) for p in paths]
    print(f"{head}  {entries[0]}")
    for e in entries[1:]:
        print(f"{indent}  {e}")


def _explicit_window_text(since: datetime | None, until: datetime | None) -> str:
    """An explicit time window as the dry run states it."""
    if since and until:
        return fmt_window((since, until))
    since_str = fmt_timestamp(since) if since else "beginning of data"
    until_str = fmt_timestamp(until) if until else "end of data"
    return f"{since_str} → {until_str}"


def _size_text(total: int, unsized: Sequence[Path]) -> str:
    """On-disk bytes, never presented as complete when some files had no size."""
    text = human_bytes(total)
    if unsized:
        n = len(unsized)
        text += f" plus {n:,} {plural(n, 'file')} of unknown size"
    return text


def _family_policy_text(
    reason: Any,
    window: Any | None,
    *,
    since: datetime | None,
    until: datetime | None,
    default_spec: str,
    history: tuple[datetime, str] | None,
    journal: bool,
) -> str:
    """One family's time policy, as the window resolver decided it.

    ``reason`` is the resolver's own record for the family. A journal provider
    has no capture in a dry run, so its active default is stated as the rule
    the capture applies, never as an exact window. A family the resolver gave
    no window is never shown an invented span.
    """
    from sigwood.common.loader import WindowPolicyReason as Reason

    if reason is Reason.EXPLICIT:
        return f"explicit window: {_explicit_window_text(since, until)}"
    if reason is Reason.ALL:
        return "full input (--all)"
    if reason is Reason.DEFAULT_DISABLED:
        return "full input (default window disabled)"
    if journal:
        return (
            f"default {default_spec}: the {default_spec} before the journal's "
            "newest entry, set when the journal is read"
        )
    if reason is Reason.NAMED_FILES:
        return "full input (named files only)"
    if reason is Reason.EXEMPT:
        return "full input (this source takes no default window)"
    if reason is Reason.RESOLVED and window is not None:
        if window.trim_span is None and window.select_window is None:
            # A window with neither bound nor trim reads everything; say so
            # rather than describe a trim that does not exist.
            return "full input (no default window resolved)"
        if window.trim_span is None:
            # The dated floor is midnight UTC of the earliest selected date
            # directory, so its UTC date names that directory exactly.
            floor = window.select_window[0]
            text = (
                f"default {default_spec}: date directories from "
                f"{floor.astimezone(timezone.utc).date().isoformat()} onward "
                f"(rows from {fmt_timestamp(floor)}), with any non-date "
                "subdirectories"
            )
        elif window.select_window is None:
            text = (
                f"default {default_spec}: loads in full, then keeps the last "
                f"{default_spec} of this source's newest data"
            )
        else:
            text = (
                f"default {default_spec}: keeps the last {default_spec} of this "
                "source's newest data after loading"
            )
        if history is not None:
            text += (
                f"; file selection reaches back to {fmt_timestamp(history[0])} "
                f"for {history[1]}'s history"
            )
        return text
    return "full input (no default window resolved)"


def _print_family_preview(
    source: str,
    configured: Sequence[Path],
    *,
    used: bool,
    preview: "_DryRunPreview | None",
    since: datetime | None,
    until: datetime | None,
    default_spec: str,
    journal: bool = False,
) -> None:
    """The policy and file lines under one family block of the dry run.

    A family no runnable detector reads is labelled unused, never described as
    outside a window. Counts are the family's files after the union of its
    patterns; a file no selection takes is stated with the full count even when
    the path list is abbreviated.
    """
    pad = runner._BANNER_LABEL_WIDTH - 2
    if not used:
        if configured or journal:
            print(f"  {'':<{pad}}  not used by any detector that can run")
        return
    if preview is None:
        return
    window = next(
        (w for w in preview.windows.load_windows if w.source == source), None,
    )
    policy = _family_policy_text(
        preview.windows.policies.get(source),
        window,
        since=since,
        until=until,
        default_spec=default_spec,
        history=preview.windows.history_floors.get(source),
        journal=journal,
    )
    print(f"  {'policy:':<{pad}}  {strip_control(policy)}")
    family = preview.families.get(source)
    if family is None:
        return
    print(
        f"  {'files:':<{pad}}  {len(family.discovered):,} discovered "
        f"({_size_text(family.discovered_bytes, family.discovered_unsized)}); "
        f"{len(family.selected):,} selected "
        f"({_size_text(family.selected_bytes, family.selected_unsized)})"
    )
    if family.not_selected:
        n = len(family.not_selected)
        print(
            f"  {'not selected:':<{pad}}  {n:,} {plural(n, 'file')} outside this "
            f"run's window ({_compact_path_list(family.not_selected)})"
        )


def _print_dry_run(
    zeek_dir: Path | list[Path] | None,
    syslog_dir: Path | list[Path] | None,
    pihole_dir: Path | list[Path] | None,
    cloudtrail_dir: Path | list[Path] | None,
    since: datetime | None,
    until: datetime | None,
    load_all: bool,
    will_run: list[str],
    skipped: dict[str, str],
    opt_in: Sequence[str] = (),
    syslog_intent: SyslogIntent | None = None,
    syslog_probe: SyslogProbeDecision | None = None,
    preview: "_DryRunPreview | None" = None,
    default_spec: str = "7d",
    used_sources: Collection[str] = frozenset(),
    warn_config: dict[str, Any] | None = None,
) -> None:
    print("sigwood  ·  threat hunt  ·  dry run")
    print(runner._SEP_DOUBLE)

    # Left-justified 15-char label field (width of the widest label,
    # "cloudtrail_dir:") plus a two-space gutter - labels flush-left, every value
    # shares one column (col 17) across the source-dir lines AND the
    # window/detectors/skipped lines below. Multi-input buckets stack additional
    # entries under that value column. Boundary accepts scalar Path / list / None
    # - same normalization shape as build_run_plan, so test callers passing
    # scalar Path or None work without juggling the wire shape.
    def family(source: str, paths: Sequence[Path], *, journal: bool = False) -> None:
        _print_family_preview(
            source,
            paths,
            used=source in used_sources,
            preview=preview,
            since=since,
            until=until,
            default_spec=default_spec,
            journal=journal,
        )

    zeek_paths = _as_path_list(zeek_dir)
    _print_family_block("zeek_dir", zeek_paths, _status_entry_display)
    family("zeek_dir", zeek_paths)
    if (
        syslog_intent is not None
        and syslog_probe is not None
        and syslog_intent.report_local_lane
    ):
        system_logs, fallback = _dry_syslog_display(syslog_intent, syslog_probe)
        print(f"{'system logs:':<{runner._BANNER_LABEL_WIDTH}}  {strip_control(system_logs)}")
        if fallback:
            print(
                f"{'system fallback:':<{runner._BANNER_LABEL_WIDTH}}  "
                f"{strip_control(fallback)}"
            )
        if syslog_probe.provider is SyslogProvider.JOURNAL:
            family("journal", (), journal=True)
        elif syslog_probe.provider is SyslogProvider.FILES:
            family("syslog_dir", _as_path_list(syslog_dir))
    else:
        syslog_paths = _as_path_list(syslog_dir)
        _print_family_block("syslog_dir", syslog_paths, _status_entry_display)
        family("syslog_dir", syslog_paths)
    pihole_paths = _as_path_list(pihole_dir)
    _print_family_block("pihole_dir", pihole_paths, _status_entry_display)
    family("pihole_dir", pihole_paths)
    cloudtrail_paths = _as_path_list(cloudtrail_dir)
    _print_family_block("cloudtrail_dir", cloudtrail_paths, _status_entry_display)
    family("cloudtrail_dir", cloudtrail_paths)

    if load_all:
        window_value = "all available data (--all)"
    elif since or until:
        window_value = _explicit_window_text(since, until)
    elif parse_window_span(default_spec) is None:
        window_value = "all available data (default window disabled)"
    else:
        # Configured is all the run-level row can say; each family's own line
        # states whether the default applies to it.
        window_value = f"{strip_control(default_spec)} default configured"
        if used_sources:
            window_value += "; each source above states its own policy"
    print(f"{'window:':<{runner._BANNER_LABEL_WIDTH}}  {window_value}")
    if preview is not None:
        estimate = tuple(preview.estimates.values())
        records = sum(item.records for item in estimate)
        basis = "exact" if all(item.records_basis == "exact" for item in estimate) else "estimated"
        uncounted = sum(item.uncounted_files for item in estimate)
        warn_above = _warn_above(warn_config or {})
        prompt = "disabled" if warn_above <= 0 else ("yes" if records > warn_above else "no")
        detail = f"{records:,} records ({basis})"
        if uncounted:
            detail += f"; {uncounted} {plural(uncounted, 'file')} uncounted"
        print(f"{'population:':<{runner._BANNER_LABEL_WIDTH}}  {detail}; large-input prompt: {prompt}")

    if will_run:
        print(f"{'detectors:':<{runner._BANNER_LABEL_WIDTH}}  {'  '.join(will_run)}")
    elif skipped:
        print(
            f"{'detectors:':<{runner._BANNER_LABEL_WIDTH}}  "
            "(none can run - required logs unavailable; a real run exits 1)"
        )
    else:
        print(f"{'detectors:':<{runner._BANNER_LABEL_WIDTH}}  (none - detect spec selected none)")

    # Promote the shipped raw-equality grouping without changing dry-run bytes.
    for reason, names in group_skips(skipped):
        print(f"{'skipped:':<{runner._BANNER_LABEL_WIDTH}}  {', '.join(names)} - {strip_control(reason)}")

    if opt_in:
        names = strip_control(", ".join(opt_in))
        print(
            f"{'opt-in:':<{runner._BANNER_LABEL_WIDTH}}  {names} - not in the default hunt "
            "(--detect=all runs everything)"
        )

    print(runner._SEP_DOUBLE)
    print("dry run - remove --dry-run to analyze")


def _dry_syslog_display(
    intent: SyslogIntent,
    decision: SyslogProbeDecision,
) -> tuple[str, str | None]:
    """Return dry-run provider and optional not-loaded fallback copy."""
    paths = _compact_path_list(intent.flat_paths)
    fallback = f"{paths} (not loaded)" if paths else None
    reason = decision.reason
    if decision.provider is SyslogProvider.OFF:
        return "off", None
    if decision.provider is SyslogProvider.JOURNAL:
        if reason is SyslogDecisionReason.PROBE_AUTO_READY:
            value = (
                "journal (auto candidate; accessible; full usable-row decision "
                "occurs on the real run)"
            )
        elif reason is SyslogDecisionReason.PROBE_JOURNAL_EMPTY:
            value = "journal (selected; query empty)"
        else:
            value = "journal (selected; accessible)"
        return value, fallback

    base = f"files {paths}" if paths else "files"
    if reason is SyslogDecisionReason.PROBE_AUTO_EMPTY:
        detail = "auto fallback; journal query empty"
    elif reason is SyslogDecisionReason.PROBE_AUTO_MISSING:
        detail = "auto fallback; journal unavailable"
    elif reason is SyslogDecisionReason.PROBE_AUTO_FAILURE:
        detail = "auto fallback; journal unavailable"
        if decision.diagnostic:
            detail += f" - {decision.diagnostic}"
    elif reason in (
        SyslogDecisionReason.EXPLICIT_FILES,
        SyslogDecisionReason.EXPLICIT_PATH_FILES,
    ):
        detail = "explicit"
    else:
        detail = "configured"
    return f"{base} ({detail})", None


def _warn_above(cfg_sigwood: dict[str, Any]) -> int:
    """The runner's single default lookup for the large-input advisory."""
    return cfg_sigwood.get("warn_above", 50_000_000)


def _confirm_large_dataset(
    total_records: int,
    cfg_sigwood: dict[str, Any],
    *,
    skip_confirm: bool,
    estimate: tuple[Any, ...] | None = None,
) -> bool:
    """Apply the advisory large-dataset gate shared by analyze and digest.

    The gate fires only when ``[sigwood].warn_above`` is positive, the record
    count exceeds it, and the operator did not pass ``--yes``. A zero or
    negative threshold disables the prompt. EOF or Ctrl-C is a decline.
    Declines raise ``ExportAborted`` for the CLI to translate to exit 0.
    """
    warn_above = _warn_above(cfg_sigwood)
    if warn_above <= 0 or total_records <= warn_above or skip_confirm:
        return False
    if estimate is None:
        message = f"Loaded {total_records:,} records. This may take a while. Continue? [y/N] "
    else:
        exact = all(item.records_basis == "exact" for item in estimate)
        selected = sum(item.selected_files for item in estimate)
        uncounted = sum(item.uncounted_files for item in estimate)
        disk_bytes = sum(item.on_disk_bytes for item in estimate)
        if exact:
            lead = f"{total_records:,} records"
        else:
            file_label = "file" if selected == 1 else "files"
            disk_label = human_bytes(disk_bytes)
            lead = (f"About {total_records:,} records "
                    f"(estimated from {selected} {file_label}, {disk_label} on disk)")
        if uncounted:
            file_label = "file" if uncounted == 1 else "files"
            lead += f"; {uncounted} {file_label} could not be counted"
        if uncounted:
            message = f"{lead}. This can take a long time and a lot of memory. Continue? [y/N] "
        else:
            message = f"{lead}, which can take a long time and a lot of memory. Continue? [y/N] "
    try:
        with cursor_visible():
            answer = input(message)
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip().lower() not in ("y", "yes"):
        raise ExportAborted("sigwood: aborted by user")
    return True


def _relative_to(path: Path, root: Path) -> Path:
    """``path`` relative to ``root`` when it is beneath it, else unchanged."""
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def _safe_real(path: Path) -> Path:
    """Realpath for comparison; the path itself when it cannot be resolved."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


import sigwood.runner as runner
