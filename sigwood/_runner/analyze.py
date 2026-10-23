"""Analyze orchestration, detector contexts, reporting and diagnostics."""
from __future__ import annotations

from typing import Any
from sigwood.common.loader import AvailabilityState
from sigwood.common.loader import CoverageDecision
from sigwood.common.loader import CoverageDecisionReason
from sigwood.common.loader import CoverageLane
from sigwood.common.config import DEFAULT_DETECT_SPEC
from sigwood.common.finding import Declined
from sigwood.common.finding import DetectorContext
from sigwood.common.loader import DualWindow
from contextlib import ExitStack
from sigwood.common.loader import ExportAvailability
from sigwood.common.finding import Finding
from typing import Mapping
from sigwood.common.output import OutputHandler
from pathlib import Path
from sigwood.common.loader import PositionalMask
from sigwood.common.output import Reporter
from sigwood.common.finding import RunSummary
from typing import Sequence
from sigwood.common.sources import SyslogDecisionReason
from sigwood.common.syslog_mode import SyslogMode
from sigwood.common.sources import SyslogProvider
from sigwood.common.sources import SyslogProviderDecision
from sigwood.common.sources import arbitrate_syslog_capture
from sigwood.common.sources import arbitrate_syslog_probe
from sigwood.common.display import compact_home
from dataclasses import dataclass
from datetime import date
from datetime import datetime
from sigwood.common.config import detector_disclosure_lines
from dataclasses import field
from sigwood.common.config import get_detector_config
from sigwood.common.display import group_skips
from sigwood.common.display import hidden_cursor
from sigwood.common.config import parse_window_span
import pandas as pd
from sigwood.common.display import phase_separator
from sigwood.common.display import plural
from sigwood.common.paths import private_mkdir
from sigwood.common.paths import private_open
from dataclasses import replace
from sigwood.common.sources import resolve_analyze_sources
from sigwood.common.display import set_display_utc
from sigwood.common.display import set_narration_enabled
from sigwood.common.sanitize import strip_control
import sys
from sigwood.common.sources import syslog_lane_detectors
from datetime import timedelta
from datetime import timezone
from sigwood.common.display import to_display_timezone
from sigwood.common.paths import unique_path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sigwood.common.loader import types as load_types
    from .planning import DetectorSelection


@dataclass(frozen=True)
class _LoadedPlan:
    """Eager load result and planning facts retained after source cleanup."""

    plan: runner.RunPlan
    source_dirs: dict[str, list[Path]]
    load_result: Any
    load_windows: list[Any]
    default_spec: str
    coverage_decisions: dict[str, CoverageDecision]
    coverage_lines: tuple[runner.Note, ...] = ()
    population_preparations: dict[str, Any] = field(default_factory=dict)
    preparation_failures: dict[str, str] = field(default_factory=dict)
    preparation_notes: list[str] = field(default_factory=list)
    large_dataset_prompted: bool = False


def _select_coverage_lane(
    facts: Sequence[ExportAvailability],
    report_interval: tuple[datetime, datetime] | None,
) -> CoverageDecision:
    """Select STRONG only from complete content-bound interval coverage.

    U2a deliberately refuses to infer an interval from loaded rows.  U2b may
    supply a later authoritative interval; until then unbounded shapes are WEAK.
    """
    if report_interval is None:
        return CoverageDecision(
            CoverageLane.WEAK,
            CoverageDecisionReason.INTERVAL_UNBOUNDED,
            None,
        )
    report_start, report_end = report_interval
    if (
        report_start.tzinfo is None
        or report_end.tzinfo is None
        or report_start.utcoffset() is None
        or report_end.utcoffset() is None
        or report_end <= report_start
    ):
        return CoverageDecision(
            CoverageLane.WEAK,
            CoverageDecisionReason.INTERVAL_UNBOUNDED,
            report_interval,
        )
    if not facts:
        return CoverageDecision(
            CoverageLane.WEAK,
            CoverageDecisionReason.NO_OBJECTS,
            report_interval,
        )
    def _valid_interval(fact: ExportAvailability) -> bool:
        if fact.state is not AvailabilityState.TRUSTED or fact.interval is None:
            return False
        start, end = fact.interval
        return (
            start.tzinfo is not None
            and end.tzinfo is not None
            and start.utcoffset() is not None
            and end.utcoffset() is not None
            and end > start
        )

    if any(not _valid_interval(fact) for fact in facts):
        return CoverageDecision(
            CoverageLane.WEAK,
            CoverageDecisionReason.OBJECT_UNKNOWN,
            report_interval,
        )
    ordered = sorted(fact.interval for fact in facts if fact.interval is not None)
    merged: list[tuple[datetime, datetime]] = []
    for start, end in ordered:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        elif end > merged[-1][1]:
            merged[-1] = (merged[-1][0], end)
    complete = any(
        start <= report_start and end >= report_end
        for start, end in merged
    )
    return CoverageDecision(
        CoverageLane.STRONG if complete else CoverageLane.WEAK,
        (
            CoverageDecisionReason.COMPLETE
            if complete
            else CoverageDecisionReason.INTERVAL_GAP
        ),
        report_interval,
        tuple(merged),
    )


def run(
    config: dict[str, Any],
    detect: str | None = None,
    zeek_dir: str | Path | Sequence[str | Path] | None = None,
    syslog_dir: str | Path | Sequence[str | Path] | None = None,
    pihole_dir: str | Path | Sequence[str | Path] | None = None,
    cloudtrail_dir: str | Path | Sequence[str | Path] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    output_format: str = "text",
    output_dir: Path | None = None,
    verbose_level: int = 0,
    dry_run: bool = False,
    no_allowlist: bool = False,
    load_all: bool = False,
    skip_confirm: bool = False,
    output_file: Path | None = None,
    scope: frozenset[str] | None = None,
    quiet: bool = False,
    use_utc: bool = False,
    syslog_source: object | None = None,
    _detector_selection: DetectorSelection | None = None,
    _dnsblock_preflight_path: Path | None = None,
    invocation: str | None = None,
    *,
    discovery: Any | None = None,
    recursive_retry: str | None = None,
) -> int:
    """Main entry point for a detection run. Called by CLI dispatch functions.

    Source-dir parameters (``zeek_dir`` / ``syslog_dir`` / ``pihole_dir`` /
    ``cloudtrail_dir``) are EXPLICIT OVERRIDES accepting either a scalar
    (``str`` / ``Path``) or a sequence of scalars (multi-positional analyze).
    ``None`` means "no override." Scalar callers are degenerate one-element
    lists downstream - byte-identical with the prior single-Path contract.
    Resolution happens inside ``sigwood.common.sources.resolve_sources``
    via the single ``_resolve_one`` site (per-element). CLI callers thread
    raw parsed strings or per-family lists; programmatic callers can pass
    already-resolved ``Path``s, lists thereof, or let ``None`` fall back to
    ``config["sigwood"][key]`` (SIGWOOD_ROOT applied).

    ``scope`` is the SOLE scoping signal. ``None`` = unconstrained (every
    configured source-dir is eligible). A ``frozenset`` of source-dir keys
    restricts config-fallback to those keys - sibling source-dirs stay
    ``None`` and are NOT loaded. An override outside ``scope`` still wins
    (operator widening). The CLI sets ``scope`` from a positional PATH's
    routed source; the previous ``None``-as-scoped-out wire shape is
    retired.

    ``skip_confirm`` bypasses the advisory large-dataset prompt (controlled by
    ``[sigwood].warn_above``); ``warn_above = 0`` disables the prompt. Threaded
    from the CLI's ``--yes`` / ``-y`` flag. Has no effect on safety-critical
    actions - there are none today; advisory prompts only.

    ``output_file`` is the be_like_water FILE verdict - an exact file path for
    the report, used as-is. When set it takes precedence over ``output_dir`` (the
    DIRECTORY verdict; the runner auto-names inside it). With both None there is
    no surprise file: text / json / csv / html stream to stdout, and pdf streams
    to ``stdout.buffer`` on a pipe but raises on a terminal (binary safety).

    ``discovery`` is the CLI's ``AnalyzeDiscovery`` context. With it, planning,
    window resolution, every load pass and the dry-run read one shared
    inventory of observed inputs, and the run discloses its directory coverage.
    ``None`` keeps the ordinary per-consumer discovery and adds no coverage
    disclosure, so programmatic callers are unchanged.

    ``recursive_retry`` is the operator's own command with ``--recursive``
    inserted, already quoted and checked by the CLI, or ``None``. It is offered
    once, after the coverage notices, when an input the invocation supplied has
    subdirectories the run did not search. The runner never reads argv.
    """
    set_narration_enabled(not quiet)
    with hidden_cursor():
        return _run_analyze(
            config=config,
            detect=detect,
            zeek_dir=zeek_dir,
            syslog_dir=syslog_dir,
            pihole_dir=pihole_dir,
            cloudtrail_dir=cloudtrail_dir,
            since=since,
            until=until,
            output_format=output_format,
            output_dir=output_dir,
            verbose_level=verbose_level,
            dry_run=dry_run,
            no_allowlist=no_allowlist,
            load_all=load_all,
            skip_confirm=skip_confirm,
            output_file=output_file,
            scope=scope,
            quiet=quiet,
            use_utc=use_utc,
            syslog_source=syslog_source,
            _detector_selection=_detector_selection,
            _dnsblock_preflight_path=_dnsblock_preflight_path,
            invocation=invocation,
            discovery=discovery,
            recursive_retry=recursive_retry,
        )


def _run_analyze(
    config: dict[str, Any],
    detect: str | None = None,
    zeek_dir: str | Path | Sequence[str | Path] | None = None,
    syslog_dir: str | Path | Sequence[str | Path] | None = None,
    pihole_dir: str | Path | Sequence[str | Path] | None = None,
    cloudtrail_dir: str | Path | Sequence[str | Path] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    output_format: str = "text",
    output_dir: Path | None = None,
    verbose_level: int = 0,
    dry_run: bool = False,
    no_allowlist: bool = False,
    load_all: bool = False,
    skip_confirm: bool = False,
    output_file: Path | None = None,
    scope: frozenset[str] | None = None,
    quiet: bool = False,
    use_utc: bool = False,
    syslog_source: object | None = None,
    _detector_selection: runner.DetectorSelection | None = None,
    _dnsblock_preflight_path: Path | None = None,
    invocation: str | None = None,
    *,
    discovery: Any | None = None,
    recursive_retry: str | None = None,
) -> int:
    cfg_sigwood = config.get("sigwood", {})
    home_net = runner.resolve_home_net(config)

    # Display timezone for every render surface this run touches (banner,
    # findings, report auto-name date). Set at entry so the dry-run banner and
    # all later render work inherit it - programmatic callers included.
    set_display_utc(use_utc)

    detect_spec = detect if detect is not None else cfg_sigwood.get(
        "detect", DEFAULT_DETECT_SPEC
    )
    with runner.liveness("loading detectors", enabled=not quiet):
        selection = _detector_selection or runner.select_detectors(detect_spec)

    detectors_cfg = config.get("detectors", {})
    if isinstance(detectors_cfg, Mapping):
        for line in detector_disclosure_lines(detectors_cfg, selection.vocab):
            _estderr(line)

    analyze_sources = resolve_analyze_sources(
        config,
        overrides={
            "zeek_dir": zeek_dir,
            "syslog_dir": syslog_dir,
            "pihole_dir": pihole_dir,
            "cloudtrail_dir": cloudtrail_dir,
        },
        scope=scope,
        syslog_source=syslog_source,
        local_lane_selected=bool(
            syslog_lane_detectors(selection.selected, selection.detectors)
        ),
    )
    resolved = analyze_sources.resolved
    syslog_intent = analyze_sources.syslog
    zeek_dirs = resolved.zeek_dir
    syslog_dirs = resolved.syslog_dir
    pihole_dirs = resolved.pihole_dir
    cloudtrail_dirs = resolved.cloudtrail_dir

    if dry_run:
        probe_result = None
        if (
            syslog_intent.local_lane_eligible
            and syslog_intent.mode in (SyslogMode.AUTO, SyslogMode.JOURNAL)
        ):
            probe_result = runner.probe_journal(since=since, until=until)
        probe_decision = arbitrate_syslog_probe(syslog_intent, probe_result)
        if (
            probe_decision.reason is SyslogDecisionReason.PROBE_AUTO_FAILURE
            and probe_decision.diagnostic
        ):
            _estderr(f"system journal: {probe_decision.diagnostic}")
        dry_sources = runner._source_dirs_for_provider(
            resolved, probe_decision.provider
        )
        dry_default_spec: str = cfg_sigwood.get("default_window", "7d")
        with runner._discovery_liveness(discovery, quiet=quiet):
            plan = runner.build_run_plan(
                detect_spec=detect_spec,
                zeek_dir=dry_sources.get("zeek_dir"),
                syslog_dir=dry_sources.get("syslog_dir"),
                pihole_dir=dry_sources.get("pihole_dir"),
                cloudtrail_dir=dry_sources.get("cloudtrail_dir"),
                scope=syslog_intent.adjusted_scope,
                selection=selection,
                virtual_sources=probe_decision.virtual_sources,
                inventory=discovery.inventory if discovery is not None else None,
            )
            # The preview's window peeks and selection belong to the same
            # planning phase, so they run inside its spinner.
            preview = (
                runner._dry_run_preview(
                    plan,
                    dry_sources,
                    inventory=discovery.inventory if discovery is not None else None,
                    default_spec=dry_default_spec,
                    load_all=load_all,
                    since=since,
                    until=until,
                    virtual_sources=probe_decision.virtual_sources,
                    verbose=verbose_level >= 1,
                )
                if plan.will_run
                else None
            )
        if discovery is not None:
            dry_span = (
                parse_window_span(cfg_sigwood.get("default_window", "7d"))
                if not load_all and since is None and until is None else None
            )
            for line in runner._discovery_coverage_lines(
                discovery, plan, dry_sources, default_span=dry_span, dry_run=True,
                recursive_retry=recursive_retry,
            ):
                _estderr(line.text)
            # A dry run renders no report, so its denial notes go to stderr.
            for line in runner._unowned_directory_skip_lines(plan, dry_sources):
                _estderr(line.text)
        if preview is not None:
            # The selection warnings a load would print, so a dry run is not
            # silent where the run warns.
            for line in preview.warnings:
                _estderr(line)
            if not quiet:
                for line in preview.fallback_lines:
                    _estderr(line)
        opt_in = runner._default_opt_in_remainder(plan, selection, detect_spec)
        runner._print_dry_run(
            zeek_dir=zeek_dirs,
            syslog_dir=syslog_dirs,
            pihole_dir=pihole_dirs,
            cloudtrail_dir=cloudtrail_dirs,
            since=since,
            until=until,
            load_all=load_all,
            will_run=plan.will_run,
            skipped=plan.skipped,
            opt_in=opt_in,
            syslog_intent=syslog_intent,
            syslog_probe=probe_decision,
            preview=preview,
            default_spec=dry_default_spec,
            used_sources=frozenset(plan.needed_logs.values()),
            warn_config=cfg_sigwood,
        )
        return 0

    from sigwood.common import loader
    from sigwood.common.allowlist import matcher_from_plan, resolve_allowlist_plan
    from sigwood.common.finding import SuppressionSummary

    default_spec: str = cfg_sigwood.get("default_window", "7d")
    default_span = None
    if not load_all and since is None and until is None:
        default_span = parse_window_span(default_spec)

    # One matcher for the entire run. Folded detectors receive positional masks
    # from this exact instance; ordinary detector preparation and suppression
    # accounting reuse it after loading.
    allowlist_plan = resolve_allowlist_plan(config)
    allowlist = matcher_from_plan(allowlist_plan, force_off=no_allowlist)

    decision: SyslogProviderDecision
    loaded_or_rc: _LoadedPlan | int | None = None
    capture_paths: tuple[str, ...] = ()
    with ExitStack() as captures:
        prepared = None
        journal_error = None
        if (
            syslog_intent.local_lane_eligible
            and syslog_intent.mode in (SyslogMode.AUTO, SyslogMode.JOURNAL)
        ):
            try:
                with runner.liveness("reading system journal", enabled=not quiet):
                    prepared = captures.enter_context(
                        loader.prepare_journal_capture(
                            since=since,
                            until=until,
                            default_span=default_span,
                        )
                    )
            except loader.JournalError as exc:
                if syslog_intent.mode is SyslogMode.JOURNAL:
                    raise
                journal_error = exc

        if prepared is not None:
            capture_paths = (str(prepared.capture_path), str(prepared.capture_path.parent))
        decision = arbitrate_syslog_capture(
            syslog_intent, capture=prepared, error=journal_error
        )
        runner._emit_syslog_decision_warnings(decision)
        if decision.provider is SyslogProvider.JOURNAL:
            assert prepared is not None
            source_dirs = runner._source_dirs_for_provider(
                resolved,
                decision.provider,
                journal_path=prepared.capture_path,
            )
            pre_resolved = (
                {"journal": prepared.load_window}
                if prepared.load_window is not None
                else None
            )
            loaded_or_rc = runner._plan_and_load(
                detect_spec=detect_spec,
                selection=selection,
                source_dirs=source_dirs,
                scope=syslog_intent.adjusted_scope,
                provider_decision=decision,
                syslog_intent=syslog_intent,
                default_spec=default_spec,
                load_all=load_all,
                since=since,
                until=until,
                verbose_level=verbose_level,
                quiet=quiet,
                allowlist=allowlist,
                pre_resolved_windows=pre_resolved,
                dnsblock_preflight_path=_dnsblock_preflight_path,
                no_allowlist=no_allowlist,
                discovery=discovery,
                recursive_retry=recursive_retry,
                preparation_config=config, capture_paths=capture_paths,
                preparation_suppression_enabled=(not no_allowlist) and allowlist_plan.master_enabled,
                cfg_sigwood=cfg_sigwood, skip_confirm=skip_confirm,
            )

        if decision.provider is not SyslogProvider.JOURNAL:
            source_dirs = runner._source_dirs_for_provider(resolved, decision.provider)
            loaded_or_rc = runner._plan_and_load(
                detect_spec=detect_spec,
                selection=selection,
                source_dirs=source_dirs,
                scope=syslog_intent.adjusted_scope,
                provider_decision=decision,
                syslog_intent=syslog_intent,
                default_spec=default_spec,
                load_all=load_all,
                since=since,
                until=until,
                verbose_level=verbose_level,
                quiet=quiet,
                allowlist=allowlist,
                dnsblock_preflight_path=_dnsblock_preflight_path,
                no_allowlist=no_allowlist,
                discovery=discovery,
                recursive_retry=recursive_retry,
                preparation_config=config, capture_paths=capture_paths,
                preparation_suppression_enabled=(not no_allowlist) and allowlist_plan.master_enabled,
                cfg_sigwood=cfg_sigwood, skip_confirm=skip_confirm,
            )

        assert loaded_or_rc is not None
        if isinstance(loaded_or_rc, int):
            return loaded_or_rc
        plan = loaded_or_rc.plan
        source_dirs = dict(loaded_or_rc.source_dirs)
        source_dirs.pop("journal", None)
        load_result = loaded_or_rc.load_result
        load_windows = loaded_or_rc.load_windows
        _default_spec = loaded_or_rc.default_spec
        default_window_active = bool(load_windows)

        # Post-load precise trim for every family whose default window engaged with a
        # load-full / conservative select-window (flat peek-prune, cloudtrail
        # load-full, flat/mixed Zeek). Dated-Zeek families carry trim_span=None - their
        # select_window already cut exactly at load. keep_null is wired from the
        # source's loader policy, so keep-policy families (syslog/pihole) retain
        # unparseable-ts rows through the implicit window exactly as through an
        # explicit one. Mixed file+dir trims the named file's rows WITH the bucket.
        for w in load_windows:
            if w.trim_span is None:
                continue
            family_patterns = [
                p for p, src in plan.needed_logs.items() if src == w.source
            ]
            load_result = loader.apply_default_window(
                load_result, family_patterns, w.trim_span, keep_null=w.keep_null,
            )
        arbitration_hosts = next((item.preparation.arbitration_hosts
            for item in loaded_or_rc.population_preparations.values()
            if item.declaration.pattern == runner._LOCAL_SYSLOG_PATTERN), None)
        if arbitration_hosts is None:
            load_result, syslog_arbitration = runner._arbitrate_cross_feed_syslog(load_result)
        else:
            load_result, syslog_arbitration = runner._arbitrate_cross_feed_syslog(
                load_result, local_hosts=arbitration_hosts,
            )
        loaded_or_rc = replace(loaded_or_rc, load_result=load_result)
        logs = load_result.logs

        for warning in load_result.warnings:
            _estderr(f"{warning}")

        # Rotation FALLBACK disclosure on stderr (quiet-gated): the fallback decision
        # is only known mid-load (load_result.rotation_skips), so this "why did that
        # read the whole archive" line lands just after the slow read. The SAME
        # formatter feeds RunSummary.notes (the report), so the two surfaces cannot
        # drift; the normal prune stays report-only. Loader records, runner formats.
        if not quiet:
            for line in runner._rotation_fallback_lines(load_result, plan):
                _estderr(line)

        permission_error = _permission_denied_run_error(load_result, plan.needed_logs)
        if permission_error is not None:
            raise ValueError(permission_error)

        # ONE captured `now` for the data-window fallback, requested_span, and
        # run-summary provenance so they cannot drift across separate clock reads.
        # The fallback window is for DetectorContext ONLY (detectors receive a real
        # window by contract); the run summary carries the loader's window verbatim.
        now = datetime.now(timezone.utc)
        if load_result.data_window is not None:
            data_window = load_result.data_window
        elif since or until:
            data_window = (since or now, until or now)
        else:
            data_window = (now, now)

        # The window the operator asked for, used by the data-found underfill
        # parenthetical. Default-window active → the configured spec; explicit
        # since&until → their span; since only → since→now; until-only / --all /
        # bounded full-load → None (unconstrained).
        requested_span: timedelta | None
        if default_window_active:
            requested_span = parse_window_span(_default_spec)
        elif since is not None and until is not None:
            requested_span = until - since
        elif since is not None:
            requested_span = now - since
        else:
            requested_span = None
        # No real data window (load yielded nothing the renderer can place - e.g. all
        # rows unparseable-ts under keep policy) → force requested_span None so the
        # underfill parenthetical cannot render a confident comparison over data that
        # does not exist. The legitimate single-event case keeps a real (ts, ts)
        # data_window and is unaffected.
        if load_result.data_window is None:
            requested_span = None

        total_records = sum(load_result.record_counts.values())
        if not loaded_or_rc.large_dataset_prompted:
            runner._confirm_large_dataset(
                total_records, cfg_sigwood, skip_confirm=skip_confirm,
            )

        # Build run summary and begin output before the detector loop so the banner
        # ("Data found:", "Records:", "Detectors:") appears before analysis starts.
        data_sources = runner._derive_data_sources(plan.needed_logs, load_result.record_counts)
        # Resolve the allowlist plan once before note assembly. New Beacon failure-cause
        # notes inspect the exact post-allowlist view the detector will receive; the two
        # older source-shape notes below deliberately retain their raw-loaded population.
        # Both remain pre-loop, so RunSummary is still complete before reporter.begin().
        suppression_enabled = (not no_allowlist) and allowlist_plan.master_enabled
        prepared_contexts: dict[str, DetectorContext] = {}
        prepared_auth: Any | None = None
        # The default window is announced pre-load on stderr (and the data-found
        # parenthetical carries the data-vs-requested span), so no prose default-window
        # note rides the run summary.
        notes: list[runner.Note] = []
        if "auth" in plan.will_run:
            auth_mod = plan.detectors["auth"]
            auth_cfg = get_detector_config(
                config, "auth", getattr(auth_mod, "DEFAULT_CONFIG", {}),
            )
            try:
                auth_context = runner._prepare_detector_context(
                    auth_mod,
                    "auth",
                    logs,
                    allowlist,
                    auth_cfg,
                    data_window,
                    data_sources,
                    home_net,
                )
            except Exception:
                # Pre-loop disclosure is best-effort. The contained detector loop
                # retries prep so a note failure cannot suppress auth itself.
                pass
            else:
                prepared_contexts["auth"] = auth_context
                try:
                    prepared_auth = auth_mod._prepare(auth_context)
                    auth_facts = auth_mod.summary_facts(
                        auth_context, _prepared=prepared_auth,
                    )
                except Exception:
                    # The detector still runs from the successfully prepared context;
                    # only the optional disclosure vanishes.
                    prepared_auth = None
                    pass
                else:
                    notes.extend(runner._format_auth_summary_notes(auth_facts))
        prepared_declared = _finish_populations(
            loaded_or_rc, logs, allowlist, data_window, data_sources, home_net,
            prepared_contexts, capture_paths,
        )
        notes.extend([runner.Note("preparation", line, "preparation-seam") for line in loaded_or_rc.preparation_notes])
    prepared_dnsblock = prepared_declared.get("dnsblock")
    if _dnsblock_preflight_path is not None:
        if prepared_dnsblock is None:
            raise ValueError("dnsblock preflight artifact requested without dnsblock")
        runner._write_dnsblock_preflight_artifact(_dnsblock_preflight_path, prepared_dnsblock)
    if prepared_dnsblock is not None:
        notes.extend(runner._format_dnsblock_summary_notes(prepared_dnsblock))
    nudge = runner._dns_nudge(data_sources)
    if nudge:
        notes.append(nudge)
    aws_below_note = runner._aws_below_floor_note(plan, logs, config)
    if aws_below_note:
        notes.append(aws_below_note)
    # The aws --all riders key on CloudTrail ACTUALLY being narrowed (an explicit
    # window) - NOT run-level default-window activity. CloudTrail opts out of the
    # auto-default window, so a mixed unqualified run (dns/syslog windowed) loads
    # it FULL and must not be told to widen.
    cloudtrail_narrowed = since is not None or until is not None
    aws_window_note = runner._aws_window_note(plan, cloudtrail_narrowed=cloudtrail_narrowed)
    if aws_window_note:
        notes.append(aws_window_note)
    aws_no_interactive_note = runner._aws_no_interactive_note(
        plan, logs, cloudtrail_narrowed=cloudtrail_narrowed
    )
    if aws_no_interactive_note:
        notes.append(aws_no_interactive_note)
    beacon_note_logs: dict[str, pd.DataFrame] | None = logs
    beacon_df = logs.get("conn*.log*")
    if "beacon" in plan.will_run and beacon_df is not None and not beacon_df.empty:
        try:
            filtered_beacon_df = allowlist.filter_df(beacon_df, "beacon")
        except Exception:
            # Do not derive a causal note from the raw frame when suppression could
            # not produce Beacon's actual view. The ordinary detector prep repeats
            # this operation inside its containment and records the actionable
            # ``prep error`` without letting pre-loop summary assembly escape.
            beacon_note_logs = None
        else:
            beacon_note_logs = dict(logs)
            beacon_note_logs["conn*.log*"] = filtered_beacon_df
    if beacon_note_logs is not None:
        notes.extend(runner._beacon_eligibility_notes(plan, beacon_note_logs, home_net))
    exfil_note_logs: dict[str, pd.DataFrame] | None = logs
    exfil_df = logs.get("conn*.log*")
    if "exfil" in plan.will_run and exfil_df is not None and not exfil_df.empty:
        try:
            filtered_exfil_df = allowlist.filter_df(exfil_df, "exfil")
        except Exception:
            # Do not infer a fidelity cause from the raw frame when the detector's
            # actual post-allowlist view is unavailable. The contained detector
            # loop records the actionable preparation error independently.
            exfil_note_logs = None
        else:
            exfil_note_logs = dict(logs)
            exfil_note_logs["conn*.log*"] = filtered_exfil_df
    if exfil_note_logs is not None:
        notes.extend(runner._exfil_eligibility_notes(plan, exfil_note_logs, home_net, config))
    ssl_note_logs: dict[str, pd.DataFrame] | None = logs
    ssl_df = logs.get("ssl*.log*")
    if "ssl" in plan.will_run and ssl_df is not None and not ssl_df.empty:
        try:
            filtered_ssl_df = allowlist.filter_df(ssl_df, "ssl")
        except Exception:
            # Never infer a fidelity cause from the raw frame when the
            # detector's actual post-allowlist view is unavailable; the
            # contained loop reports the preparation error independently.
            ssl_note_logs = None
        else:
            ssl_note_logs = dict(logs)
            ssl_note_logs["ssl*.log*"] = filtered_ssl_df
    if ssl_note_logs is not None:
        notes.extend(runner._ssl_eligibility_notes(plan, ssl_note_logs, home_net))
    beacon_floor_note = runner._beacon_min_connections_note(plan, config)
    if beacon_floor_note:
        notes.append(beacon_floor_note)
    beacon_non_established_note = runner._beacon_non_established_note(plan, logs)
    if beacon_non_established_note:
        notes.append(beacon_non_established_note)
    beacon_span_note = runner._beacon_span_note(plan, logs, requested_span)
    if beacon_span_note:
        notes.append(beacon_span_note)
    home_net_note = runner._home_net_note(plan, config, home_net)
    if home_net_note:
        notes.append(home_net_note)
    default_opt_in_note = runner._default_opt_in_note(plan, selection, detect_spec)
    if default_opt_in_note:
        notes.append(default_opt_in_note)
    syslog_provider_note = runner._syslog_provider_note(decision, syslog_intent, plan)
    if syslog_provider_note:
        notes.append(syslog_provider_note)
    if syslog_arbitration is not None:
        host_count, row_count = syslog_arbitration
        notes.append(
            runner.Note("arbitration", f"system logs: {host_count:,} {plural(host_count, 'host')} carried by "
            "both the local feed and Zeek syslog.log - kept the local rows "
            f"({row_count:,} Zeek {plural(row_count, 'row')} set aside)", "syslog")
        )
    # Source-dir overlap disclosure: when two IN-PLAN families resolve to the
    # same directory, flat discovery globs cross-read it (one log surfaced as
    # another's finding). Derives from already-resolved source_dirs + plan, like
    # the home_net note above. Appended before the coverage/rotation extends,
    # which are deliberately last.
    if discovery is None or not discovery.recursive:
        # A recursive run states actual shared candidates among its coverage
        # lines instead: an equal directory there no longer implies a cross-read.
        notes.extend(runner._source_overlap_notes(source_dirs, plan))
    # Source-coverage disclosure: for each planned source that contributed 0
    # in-window rows, append a note (SPAN / BARE / silent per the parse-gap
    # vs window-gap tri-state in CoverageTracker). Reads the merged coverage
    # written by the runner-side flat-default block above (when fired).
    notes.extend(runner._zero_window_coverage_notes(load_result, plan, load_all=load_all))
    # Directory coverage facts the shared inventory established (unsearched
    # children, unreadable entries, inputs that were missing or empty). They
    # were printed on stderr at planning; the report carries the same lines.
    notes.extend(loaded_or_rc.coverage_lines)
    # A source directory omitted before file discovery is a plan fact rather
    # than LoadResult metadata. Partial runs remain successful, but every
    # report format with notes must disclose that the directory was absent.
    notes.extend(runner._directory_skip_notes(plan))
    # Partial permission denial remains a successful run, but the saved report
    # must disclose rows that could not be read. Total denial raised above,
    # before summary assembly can reach this helper.
    notes.extend(runner._permission_skip_notes(load_result, plan))
    # Flat rotation-peek disclosure: one note per windowed pattern that fell back
    # to a full read or skipped out-of-window rotation files. Additive, appended last.
    notes.extend(runner._rotation_skip_notes(load_result, plan))
    detector_methods = {
        name: getattr(plan.detectors[name], "DETECTOR_METHOD", None)
        for name in plan.will_run
    }
    detector_missions = {}
    for name in plan.will_run:
        mission = getattr(plan.detectors[name], "DETECTOR_MISSION", None)
        if isinstance(mission, str) and mission.strip():
            detector_missions[name] = mission
    record_labels = {
        pattern: runner._pattern_human_label(plan.needed_logs[pattern], pattern)
        for pattern in load_result.record_counts
        if pattern in plan.needed_logs
    }
    run_summary = RunSummary(
        # The loader's window verbatim - None when no loaded rows establish a
        # window (the render surfaces answer "none"/null; the fabricated
        # fallback local feeds DetectorContext only).
        data_window=load_result.data_window,
        record_counts=load_result.record_counts,
        record_labels=record_labels,
        data_size_bytes=load_result.data_size_bytes,
        detectors_run=plan.will_run,
        detectors_skipped=plan.skipped,
        detectors_failed=dict(loaded_or_rc.preparation_failures),
        notes=runner.flatten_notes(notes),
        data_sources=data_sources,
        detector_methods=detector_methods,
        detector_missions=detector_missions,
        requested_span=requested_span,
        invocation=invocation,
        generated_at=now,
    )

    # Suppression disclosure - scope-blind coverage over DISTINCT loaded frames
    # (NOT the per-detector loop, which filters the shared conn frame 3× and would
    # triple-count). Skip the O(N) string-map entirely when suppression is off so
    # `allowlist: off` renders without a wasted pass over huge frames.
    suppressed_connections = 0
    suppressed_domains = 0
    host_rows = 0
    matched_hosts: set[str] = set()
    # Row-based denominators per kind, accumulated in the SAME pass and over the
    # SAME eligible frames as the numerators, so the banner percentage matches the
    # row-count numerator (count_*_suppressed count rows, not distinct values).
    connection_total = 0
    domain_total = 0
    host_total = 0
    if suppression_enabled:
        with runner.liveness("scanning allowlist coverage", enabled=not quiet):
            for _pat, _df in load_result.logs.items():
                channel = next((value for key, value in load_result.fold_results.get(_pat, {}).items()
                                if key.startswith(runner._SUPPRESSION_CHANNEL + ":")), None)
                contribution = channel if channel is not None else runner._suppression_contribution(_df, allowlist)
                suppressed_domains += contribution.domains
                domain_total += contribution.domain_total
                suppressed_connections += contribution.connections
                connection_total += contribution.connection_total
                host_rows += contribution.host_rows
                host_total += contribution.host_total
                matched_hosts.update(contribution.matched_hosts)
    run_summary.suppression = SuppressionSummary(
        enabled=suppression_enabled,
        connections=suppressed_connections,
        domains=suppressed_domains,
        connection_total=connection_total,
        domain_total=domain_total,
        host_rows=host_rows,
        host_total=host_total,
        hosts_matched=len(matched_hosts),
    )
    # Malformed-pattern advisory - a flat-list `re:` body that fails to compile is
    # dropped from matching (it would otherwise raise mid-run); surface it as a
    # per-pattern STATUS note naming the file:line. `run_summary.notes` is the
    # same list assembled above; append before `reporter.begin`. Gated on
    # `suppression_enabled`: a `--no-allowlist` / master-off run builds an empty
    # matcher (no malformed set), and a per-name-disabled list is never loaded -
    # so only patterns from ACTIVE lists this run are reported.
    if suppression_enabled:
        for mp in allowlist.malformed_patterns:
            where = compact_home(mp.source) if mp.source else "?"
            if mp.lineno is not None:
                where = f"{where}:{mp.lineno}"
            run_summary.notes.append(
                f"allowlist: {where}: malformed pattern skipped ({mp.pattern})"
            )

    max_per_detector = int(
        config.get("sigwood", {}).get("max_findings_per_detector", 100)
    )
    handler, close_handler, written_path = runner._build_output_handler(
        output_format, output_dir, output_file, verbose_level,
        max_findings_per_detector=max_per_detector,
        detectors_run=run_summary.detectors_run,
    )
    reporter = Reporter([handler])
    # Cross-stream phase boundary: close the transient stderr load phase so the
    # stdout banner is cleanly separated (tty-gated; no-op when piped). The
    # stdout report owns no cross-stream-only separator - see phase_separator.
    # Under -q the stderr load phase emits nothing, so there is no boundary to close.
    if not quiet:
        phase_separator()
    reporter.begin(run_summary)

    # ── Run detectors ─────────────────────────────────────────────────────────
    all_findings: list[Finding] = []
    dispatch_prepared = dict(prepared_declared)
    if prepared_auth is not None:
        dispatch_prepared["auth"] = prepared_auth

    for name in plan.will_run:
        if name in run_summary.detectors_failed:
            continue
        mod = plan.detectors[name]
        det_cfg = get_detector_config(config, name, getattr(mod, "DEFAULT_CONFIG", {}))

        # Per-detector prep + run, scoped to accurate error labels. Prep
        # (filter_df + DetectorContext construction) is the runner's
        # responsibility; a prep failure is "prep error", NOT "detector
        # error" - separation-of-powers detail. For the non-syslog
        # branch, both prep and run live INSIDE liveness(...) so the
        # spinner appears as soon as the operator-visible work begins.
        #
        # syslog stays outside the outer spinner branch: its inner
        # drain3 tqdm bar owns its stderr line, and an outer spinner
        # would fight for the same row. Prep moves into the syslog
        # branch too for consistency but stays outside its own
        # liveness wrapper.
        if name == "syslog":
            try:
                ctx = prepared_contexts.get(name)
                if ctx is None:
                    ctx = runner._prepare_detector_context(
                        mod, name, logs, allowlist, det_cfg,
                        data_window, data_sources, home_net,
                    )
            except Exception as exc:
                _estderr(f"{name}: prep error - {exc}")
                run_summary.detectors_failed[name] = _failure_reason("prep error", exc)
                continue
            try:
                findings = _run_declared(mod, name, ctx, dispatch_prepared)
            except Exception as exc:
                _estderr(f"{name}: detector error - {exc}")
                run_summary.detectors_failed[name] = _failure_reason("detector error", exc)
                findings = []
        else:
            with runner.liveness(f"running {name}", enabled=not quiet) as _ln:
                try:
                    ctx = prepared_contexts.get(name)
                    if ctx is None:
                        ctx = runner._prepare_detector_context(
                            mod, name, logs, allowlist, det_cfg,
                            data_window, data_sources, home_net,
                        )
                except Exception as exc:
                    # Prep failed BEFORE the detector even started - no
                    # seal (the "no false seal" path from
                    # tests/test_display.py:120-130); liveness's normal
                    # teardown clears the spinner line.
                    _estderr(f"{name}: prep error - {exc}")
                    run_summary.detectors_failed[name] = _failure_reason("prep error", exc)
                    continue
                try:
                    findings = _run_declared(mod, name, ctx, dispatch_prepared)
                    # The seal is a terse live completion record - "this
                    # detector finished" - NOT a tally. The report header
                    # is the single authoritative count surface
                    # (carries the H/M/L/I breakdown, survives redirect).
                    # Empty case stays informative: the detector ran and
                    # found nothing. ASCII-only per display.py's spinner
                    # discipline.
                    _ln.seal(
                        f"{name}: done"
                        if findings
                        else f"{name}: nothing"
                    )
                except Exception as exc:
                    _estderr(f"{name}: detector error - {exc}")
                    run_summary.detectors_failed[name] = _failure_reason("detector error", exc)
                    findings = []

        all_findings.extend(findings)

    try:
        render_liveness = not quiet and (
            written_path is not None or not runner._stream_isatty(sys.stdout)
        )
        with runner.liveness("rendering report", enabled=render_liveness):
            reporter.write(all_findings)
            reporter.end()
    finally:
        close_handler()

    # Report a written file ONLY after the report fully rendered AND the stream
    # closed cleanly - a raise above skips this, so construction never claims a
    # write. stdout / pipe runs (written_path is None) report nothing; -q
    # suppresses the status line; --dry-run returned long before this point.
    if written_path is not None and not quiet:
        _estderr(f"wrote report to {compact_home(written_path)}")
    # A selected detector that crashed (prep or run) is a partial run failure:
    # the report rendered and the loop continued, but the exit code must not
    # read as a clean night - a scheduled run alerts on nonzero. The
    # per-detector stderr line above is the explanation; the report / json
    # feed carry the same failures via run_summary.detectors_failed.
    if run_summary.detectors_failed:
        return 1
    return 0


def _finish_populations(
    loaded: _LoadedPlan, logs: dict[str, pd.DataFrame], allowlist: Any,
    data_window: tuple[datetime, datetime], data_sources: list[str], home_net: list[str],
    prepared_contexts: dict[str, DetectorContext], capture_paths: tuple[str, ...],
) -> dict[str, Any]:
    from sigwood.common.finding import Declined, DeclineReason, FinalResult
    prepared = {}
    result = loaded.load_result
    for name, item in loaded.population_preparations.items():
        try:
            ctx = runner._prepare_detector_context(loaded.plan.detectors[name], name, logs,
                                           allowlist, item.host.config, data_window,
                                           data_sources, home_net)
            pattern = item.declaration.pattern
            sink_plan, _, _ = item.host.registration
            channels = {sink.channel for sink in sink_plan.folds}
            if sink_plan.admit is not None:
                channels.add(sink_plan.admit.channel)
            final = FinalResult(pattern,
                {c: s for c, s in result.prepared_status.items() if c in channels},
                result.fold_results.get(pattern, {}), result.snapshots.get(pattern),
                result.availability.get(pattern, ()), result.population.get(pattern),
                result.file_outcomes.get(pattern))
            prepared[name] = item.preparation.finish(ctx, final)
            prepared_contexts[name] = ctx
        except Exception as exc:
            runner._record_preparation_disposition(name, item.declaration,
                Declined(DeclineReason.FAILED, str(exc).strip() or type(exc).__name__), loaded.preparation_failures,
                loaded.preparation_notes, capture_paths, unrecovered=True)
    return prepared


def _run_declared(mod: Any, name: str, ctx: DetectorContext,
                  prepared: dict[str, Any]) -> list[Finding]:
    if name in prepared:
        return mod.run(ctx, _prepared=prepared[name])
    return mod.run(ctx)


def _prepare_detector_context(
    mod: Any,
    name: str,
    logs: dict[str, Any],
    allowlist: Any,
    det_cfg: dict[str, Any],
    data_window: tuple[datetime, datetime],
    data_sources: list[str],
    home_net: list[str],
) -> DetectorContext:
    """Build the per-detector filtered view + DetectorContext.

    Prep run per detector inside the detector loop:
    each detector gets its own filtered copy of the shared log frames
    (so independent ``filter_df`` results never mutate the shared dict),
    keyed by the patterns the detector itself declares via
    ``REQUIRED_LOGS`` + ``OPTIONAL_LOGS``.

    Lives in the runner - NOT moved into detector code - because
    ``allowlist.filter_df`` is suppression, and suppression stays in the
    runner per the filter-before-analyze rail.

    Verbose is intentionally absent: detector context carries no
    verbosity; the result set is verbosity-invariant by construction.
    """
    if hasattr(mod, "validate_config"):
        mod.validate_config(det_cfg)
    det_patterns = {
        req["pattern"]
        for req in list(getattr(mod, "REQUIRED_LOGS", []))
        + list(getattr(mod, "OPTIONAL_LOGS", []))
    }
    filtered_logs: dict[str, Any] = {}
    for pattern, df in logs.items():
        if pattern in det_patterns and not df.empty:
            filtered_logs[pattern] = allowlist.filter_df(df, name)
        else:
            filtered_logs[pattern] = df
    return DetectorContext(
        logs=filtered_logs,
        config=det_cfg,
        allowlist=allowlist,
        data_window=data_window,
        data_sources=data_sources,
        home_net=home_net,
    )


def _positional_allowlist_mask(
    frame: pd.DataFrame,
    allowlist: Any,
    channel: str,
) -> PositionalMask:
    """Build one duplicate-index-safe keep mask for a bounded chunk.

    Suppression stays in the runner. The matcher receives a unique positional
    index, and its surviving positions are projected back to a boolean vector;
    no second resident filtered frame crosses the fold boundary.
    """
    positional = frame.reset_index(drop=True)
    filtered = allowlist.filter_df(positional, channel)
    surviving = set(int(value) for value in filtered.index)
    if any(value < 0 or value >= len(positional) for value in surviving):
        raise ValueError("allowlist returned a non-positional row index")
    return PositionalMask(tuple(i in surviving for i in range(len(positional))))


def _resolve_fold_dual_window(
    report_interval: tuple[datetime, datetime],
    *,
    available_start: datetime | None,
    bounded_explicit: bool,
    load_all: bool,
) -> DualWindow:
    """Apply the D-02 pre-roll aperture without changing report membership."""
    report_start, _ = report_interval
    if load_all or bounded_explicit or available_start is None:
        return runner._build_dual_window(report_interval)
    context_end = report_start - timedelta(microseconds=1)
    if available_start > context_end:
        return runner._build_dual_window(report_interval)
    return runner._build_dual_window(
        report_interval,
        (available_start, context_end),
    )


def _failure_reason(phase: str, exc: Exception) -> str:
    """The recorded reason for a failed detector: ``<phase> - <first line>``.

    ``phase`` is ``"prep error"`` or ``"detector error"`` - the same labels
    the live stderr lines carry, so the stored reason and the narration
    cannot drift. First line only (an exception message can be multi-line);
    an empty message falls back to the exception type name (the
    ``discover_detectors`` import-failure shape). The reason never embeds
    the detector name - every render surface prefixes it.
    """
    msg = str(exc).strip()
    first = msg.splitlines()[0] if msg else type(exc).__name__
    return f"{phase} - {first}"


def _build_output_handler(
    output_format: str,
    output_dir: Path | None,
    output_file: Path | None,
    verbose_level: int,
    stream: Any = None,
    *,
    max_findings_per_detector: int = 100,
    detectors_run: list[str] = (),
) -> tuple[OutputHandler, Any, Path | None]:
    """Create the output handler, a stream-close callback, and the written path.

    Returns ``(handler, close_handler, written_path)``. ``written_path`` is the
    Path of the file actually written for FILE / DIRECTORY targets, or ``None``
    for stdout / pipe / caller-owned-stream targets - the analyze caller reports
    it only after the report fully renders and the stream closes cleanly.

    ``output_file`` is the be_like_water FILE verdict - an EXACT path, used as-is
    (never collision-suffixed). ``output_dir`` is the DIRECTORY verdict - the
    runner auto-names inside it via ``unique_path`` + ``_report_basename``. With
    BOTH None there is no surprise file: text / json / csv / html stream to
    stdout; pdf streams to ``stdout.buffer`` on a pipe and raises on a tty.

    ``stream`` is the caller-owned TextIO seam used by the digest fan-out: the
    CLI resolves a shared ``--out`` target once and passes the open stream here so
    N cards concatenate into one file. Stream-backed text only; caller owns the
    stream lifetime; close callback is a no-op; ``written_path`` is None (the CLI
    reports digest paths itself).

    ``verbose_level`` is the single 0/1/2 dial. The READING surfaces (text / html
    / pdf) honor all three levels AND take the ``max_findings_per_detector`` cap;
    json / csv are verbosity-invariant and NEVER capped. ``detectors_run`` names
    the auto-named report (the DIRECTORY branch only).
    """
    from sigwood.common.output import get_handler

    handler_cls = get_handler(output_format)
    # text / html / pdf are the cap-bearing reading surfaces; json / csv are not.
    cap_kw = (
        {"max_findings_per_detector": max_findings_per_detector}
        if output_format in ("text", "html", "pdf")
        else {}
    )

    # 1. Caller-owned stream (digest fan-out) - text only; no open, no close, no
    #    path (the CLI reports digest paths). output_dir / output_file are None.
    if stream is not None:
        handler = handler_cls(stream=stream, verbose_level=verbose_level, **cap_kw)
        return handler, (lambda: None), None

    # 2. Explicit FILE verdict - the EXACT path, never collision-suffixed.
    if output_file is not None:
        private_mkdir(output_file.parent)
        if output_format in ("html", "pdf"):
            handler = handler_cls(output_path=output_file, verbose_level=verbose_level, **cap_kw)
            return handler, (lambda: None), output_file
        opened = private_open(output_file, encoding="utf-8", newline="")
        handler = handler_cls(stream=opened, verbose_level=verbose_level, **cap_kw)
        return handler, opened.close, output_file

    # 3. DIRECTORY verdict - auto-name inside it (collision-suffixed).
    if output_dir is not None:
        private_mkdir(output_dir)
        path = unique_path(output_dir, _report_basename(output_format, detectors_run))
        if output_format in ("html", "pdf"):
            handler = handler_cls(output_path=path, verbose_level=verbose_level, **cap_kw)
            return handler, (lambda: None), path
        opened = private_open(path, encoding="utf-8", newline="")
        handler = handler_cls(stream=opened, verbose_level=verbose_level, **cap_kw)
        return handler, opened.close, path

    # 4. No target → stdout (the surprise-file class is deleted).
    if output_format == "pdf":
        # Binary: refuse a terminal (defensive - the CLI already fails fast for
        # the analyze path; this covers programmatic runner.run callers). A
        # non-tty stdout without a binary `.buffer` (e.g. a StringIO from a
        # programmatic caller) can't take pdf bytes either - same actionable error.
        from sigwood.outputs.pdf import PDF_TTY_ERROR
        if sys.stdout.isatty():
            raise ValueError(PDF_TTY_ERROR)
        buf = getattr(sys.stdout, "buffer", None)
        if buf is None:
            raise ValueError(PDF_TTY_ERROR)
        handler = handler_cls(stream=buf, verbose_level=verbose_level, **cap_kw)
        return handler, (lambda: None), None
    if output_format == "html":
        handler = handler_cls(stream=sys.stdout, verbose_level=verbose_level, **cap_kw)
        return handler, (lambda: None), None
    # text / json / csv → stdout.
    handler = handler_cls(stream=sys.stdout, verbose_level=verbose_level, **cap_kw)
    return handler, (lambda: None), None


def _report_basename(output_format: str, detectors_run: list[str] = ()) -> str:
    """Auto-named analyze report basename ``sigwood-report_<token>_<YYYYMMDD>.<ext>``.

    The date renders in the display timezone - the same zone the report's own
    timestamps use (``run()`` sets the display switch at entry, before any
    naming work). The collision suffix is ``unique_path``'s job, not this
    function's."""
    ext = "txt" if output_format == "text" else output_format
    date = to_display_timezone(datetime.now(timezone.utc)).strftime("%Y%m%d")
    token = runner._detector_token(detectors_run)
    stem = f"sigwood-report_{token}_{date}" if token else f"sigwood-report_{date}"
    return f"{stem}.{ext}"


def _estderr(line: str) -> None:
    """Emit one runner diagnostic line to stderr with terminal control bytes stripped.

    Untrusted filenames, directory names, and exception text from a scanned tree reach
    these diagnostics; a name embedding ESC / OSC / BEL could forge or hide terminal
    output. Every runner-owned diagnostic stderr print routes through here, so
    neutralization holds by construction. tqdm / liveness / progress own their own
    display path (common/display.py) and are deliberately NOT routed through this helper.
    """
    print(strip_control(line), file=sys.stderr)


def _warn_skips(skipped: Mapping[str, str]) -> None:
    """Group raw-identical plan reasons, then emit each stderr composition."""
    for reason, names in group_skips(skipped):
        _warn_skipped(names, reason)


def _warn_skipped(detector_names: Sequence[str], reason: str) -> None:
    """Print one canonical stderr warning for a raw-identical skip group."""
    if len(detector_names) == 1:
        _estderr(f"{reason} - skipping {detector_names[0]} detection")
        return
    _estderr(f"{reason} - skipping detectors: {', '.join(detector_names)}")


def _permission_denied_run_error(
    load_result: Any,
    needed_logs: Mapping[str, str],
    *,
    strict: bool = False,
) -> str | None:
    """Return permission detail using the shared loader accounting.

    Analyze remains partial-tolerant: a loaded record anywhere means a denied
    sibling does not turn the whole detector run into an error. Graph artifacts
    are stricter: one unreadable source makes its bucket operationally
    incomplete even when other rows rendered, so ``strict=True`` reports every
    discovered denial for the graph CLI's per-bucket exit ledger.
    """
    if not strict and sum(load_result.record_counts.values()) > 0:
        return None
    for pattern, source_key in needed_logs.items():
        info = load_result.permission_skips.get(pattern)
        if info is None or info.discovered <= 0:
            continue
        if strict and info.denied > 0:
            label = runner._pattern_human_label(source_key, pattern)
            if info.denied == info.discovered:
                n = info.discovered
                return (
                    f"{label}: all {n} discovered {plural(n, 'file')} "
                    "permission denied - grant your user read access and retry"
                )
            return (
                f"{label}: {info.denied} of {info.discovered} discovered "
                f"{plural(info.discovered, 'file')} permission denied - grant "
                "your user read access and retry"
            )
        if info.denied == info.discovered:
            n = info.discovered
            label = runner._pattern_human_label(source_key, pattern)
            return (
                f"{label}: all {n} discovered {plural(n, 'file')} "
                "permission denied - grant your user read access and retry"
            )
    return None


def _arbitrate_cross_feed_syslog(
    load_result: "loader.LoadResult",
    *, local_hosts: frozenset[str] | None = None,
) -> tuple["loader.LoadResult", tuple[int, int] | None]:
    """Keep the local carrier for hosts also present in Zeek syslog."""
    # These contract patterns are claimed only by the syslog lane. Provider
    # arbitration has already selected the one local carrier behind ``*.log*``.
    local = load_result.logs.get(runner._LOCAL_SYSLOG_PATTERN)
    zeek = load_result.logs.get("syslog*.log*")
    if zeek is None or zeek.empty or "host" not in zeek.columns:
        return load_result, None
    if local_hosts is None:
        if local is None or "host" not in local.columns:
            return load_result, None
        local_hosts = set(local["host"].astype(str).str.lower().unique())
    local_hosts = set(local_hosts) - {"unknown"}
    if not local_hosts:
        return load_result, None

    folded_zeek_hosts = zeek["host"].astype(str).str.lower()
    drop_mask = folded_zeek_hosts.isin(local_hosts)
    dropped_rows = int(drop_mask.sum())
    if dropped_rows == 0:
        return load_result, None

    arbitrated_hosts = int(folded_zeek_hosts[drop_mask].nunique())
    logs = load_result.logs.copy()
    logs["syslog*.log*"] = zeek[~drop_mask].copy()
    return replace(load_result, logs=logs), (arbitrated_hosts, dropped_rows)


import sigwood.runner as runner
