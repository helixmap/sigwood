"""Orchestrates detector execution: discovery, log loading, context assembly, and output.

Responsibilities:
- Auto-discover detectors by scanning sigwood/detectors/ for modules with DETECTOR_NAME
- Resolve the detect= selection (default, all, explicit list, exclusion syntax)
- Check REQUIRED_LOGS availability; skip with warning if missing
- Load logs and assemble DetectorContext for each detector
- Collect list[Finding] from each detector's run()
- Hand findings to Reporter
"""

from __future__ import annotations

import importlib
import math
import os
import pkgutil
import shlex
import sys
from contextlib import ExitStack
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Collection, Mapping, Sequence

import pandas as pd

import sigwood.detectors as _detectors_pkg
from sigwood.common.config import (
    DEFAULT_DETECT_SPEC,
    get_detector_config,
    parse_window_span,
    validate_table_sections,
)
from sigwood.common.display import (
    TEXT_RULE,
    TEXT_RULE_DOUBLE,
    TEXT_RULE_WIDTH,
    _stream_isatty,
    compact_home,
    cursor_visible,
    default_window_advisory,
    fmt_compact_span,
    fmt_timestamp,
    fmt_window,
    hidden_cursor,
    liveness,
    phase_separator,
    plural,
    set_display_utc,
    set_narration_enabled,
    to_display_timezone,
)
from sigwood.common.errors import (
    DigestEmpty,
    ExportAborted,
    GraphEmpty,
    GraphSourceUnreadable,
)
from sigwood.common.finding import DetectorContext, Finding, RunSummary
from sigwood.common.journal_probe import probe_journal
from sigwood.common.loader import JournalCaptureOutcome
from sigwood.common.output import OutputHandler, Reporter
from sigwood.common.paths import (
    private_mkdir,
    private_open,
    private_write_text,
    unique_path,
)
from sigwood.common.sources import (
    GraphKindSpec,
    ResolvedSources,
    SyslogDecisionReason,
    SyslogIntent,
    SyslogProbeDecision,
    SyslogProvider,
    SyslogProviderDecision,
    arbitrate_syslog_capture,
    arbitrate_syslog_probe,
    resolve_digest_source,
    resolve_graph_source,
    resolve_analyze_sources,
)
from sigwood.common.sanitize import strip_control
from sigwood.common.syslog_mode import SyslogMode

_WIDTH = TEXT_RULE_WIDTH
_SEP = TEXT_RULE
_SEP_DOUBLE = TEXT_RULE_DOUBLE

# Single banner-label field width - one column for every dry-run label so no
# caller hand-rolls padding math.
_BANNER_LABEL_WIDTH = 15

# Full-fidelity DNS source labels. When any of these are in data_sources the
# Zeek evangelization nudge is suppressed. BIND9 and others join this set when
# their parsers land.
_RICH_DNS_SOURCES = {"zeek_dns"}


@dataclass(frozen=True)
class RunPlan:
    """Detector execution plan produced before loading any log data."""

    detectors: dict[str, Any]
    selected: list[str]
    will_run: list[str]
    skipped: dict[str, str]
    needed_logs: dict[str, str]


@dataclass(frozen=True)
class DetectorSelection:
    """Detector discovery and detect-spec resolution before source probing."""

    detectors: dict[str, Any]
    selected: list[str]
    import_failures: dict[str, str]
    used_default: bool = False


@dataclass(frozen=True)
class _LoadedPlan:
    """Eager load result and planning facts retained after source cleanup."""

    plan: RunPlan
    source_dirs: dict[str, list[Path]]
    load_result: Any
    load_windows: list[Any]
    default_spec: str


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
    invocation: str | None = None,
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
            invocation=invocation,
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
    _detector_selection: DetectorSelection | None = None,
    invocation: str | None = None,
) -> int:
    cfg_sigwood = config.get("sigwood", {})

    # Display timezone for every render surface this run touches (banner,
    # findings, report auto-name date). Set at entry so the dry-run banner and
    # all later render work inherit it - programmatic callers included.
    set_display_utc(use_utc)

    detect_spec = detect if detect is not None else cfg_sigwood.get(
        "detect", DEFAULT_DETECT_SPEC
    )
    with liveness("loading detectors", enabled=not quiet):
        selection = _detector_selection or select_detectors(detect_spec)

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
        syslog_selected="syslog" in selection.selected,
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
            probe_result = probe_journal(since=since, until=until)
        probe_decision = arbitrate_syslog_probe(syslog_intent, probe_result)
        if (
            probe_decision.reason is SyslogDecisionReason.PROBE_AUTO_FAILURE
            and probe_decision.diagnostic
        ):
            _estderr(f"system journal: {probe_decision.diagnostic}")
        dry_sources = _source_dirs_for_provider(
            resolved, probe_decision.provider
        )
        plan = build_run_plan(
            detect_spec=detect_spec,
            zeek_dir=dry_sources.get("zeek_dir"),
            syslog_dir=dry_sources.get("syslog_dir"),
            pihole_dir=dry_sources.get("pihole_dir"),
            cloudtrail_dir=dry_sources.get("cloudtrail_dir"),
            scope=syslog_intent.adjusted_scope,
            selection=selection,
            virtual_sources=probe_decision.virtual_sources,
        )
        opt_in = _default_opt_in_remainder(plan, selection, detect_spec)
        _print_dry_run(
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
        )
        return 0

    from sigwood.common import loader
    from sigwood.common.allowlist import matcher_from_plan, resolve_allowlist_plan
    from sigwood.common.finding import SuppressionSummary

    default_spec: str = cfg_sigwood.get("default_window", "7d")
    default_span = None
    if not load_all and since is None and until is None:
        default_span = parse_window_span(default_spec)

    decision: SyslogProviderDecision
    loaded_or_rc: _LoadedPlan | int | None = None
    with ExitStack() as captures:
        prepared = None
        journal_error = None
        if (
            syslog_intent.local_lane_eligible
            and syslog_intent.mode in (SyslogMode.AUTO, SyslogMode.JOURNAL)
        ):
            try:
                with liveness("reading system journal", enabled=not quiet):
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

        decision = arbitrate_syslog_capture(
            syslog_intent, capture=prepared, error=journal_error
        )
        _emit_syslog_decision_warnings(decision)
        if decision.provider is SyslogProvider.JOURNAL:
            assert prepared is not None
            source_dirs = _source_dirs_for_provider(
                resolved,
                decision.provider,
                journal_path=prepared.capture_path,
            )
            pre_resolved = (
                {"journal": prepared.load_window}
                if prepared.load_window is not None
                else None
            )
            loaded_or_rc = _plan_and_load(
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
                pre_resolved_windows=pre_resolved,
            )

    if decision.provider is not SyslogProvider.JOURNAL:
        source_dirs = _source_dirs_for_provider(resolved, decision.provider)
        loaded_or_rc = _plan_and_load(
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
        )

    assert loaded_or_rc is not None
    if isinstance(loaded_or_rc, int):
        return loaded_or_rc
    plan = loaded_or_rc.plan
    source_dirs = loaded_or_rc.source_dirs
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
    load_result, syslog_arbitration = _arbitrate_cross_feed_syslog(load_result)
    logs = load_result.logs

    for warning in load_result.warnings:
        _estderr(f"{warning}")

    # Rotation FALLBACK disclosure on stderr (quiet-gated): the fallback decision
    # is only known mid-load (load_result.rotation_skips), so this "why did that
    # read the whole archive" line lands just after the slow read. The SAME
    # formatter feeds RunSummary.notes (the report), so the two surfaces cannot
    # drift; the normal prune stays report-only. Loader records, runner formats.
    if not quiet:
        for line in _rotation_fallback_lines(load_result, plan):
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
    _confirm_large_dataset(
        total_records, cfg_sigwood, skip_confirm=skip_confirm,
    )

    # Build run summary and begin output before the detector loop so the banner
    # ("Data found:", "Records:", "Detectors:") appears before analysis starts.
    data_sources = _derive_data_sources(plan.needed_logs, load_result.record_counts)
    # The default window is announced pre-load on stderr (and the data-found
    # parenthetical carries the data-vs-requested span), so no prose default-window
    # note rides the run summary.
    notes: list[str] = []
    nudge = _dns_nudge(data_sources)
    if nudge:
        notes.append(nudge)
    aws_below_note = _aws_below_floor_note(plan, logs, config)
    if aws_below_note:
        notes.append(aws_below_note)
    # The aws --all riders key on CloudTrail ACTUALLY being narrowed (an explicit
    # window) - NOT run-level default-window activity. CloudTrail opts out of the
    # auto-default window, so a mixed unqualified run (dns/syslog windowed) loads
    # it FULL and must not be told to widen.
    cloudtrail_narrowed = since is not None or until is not None
    aws_window_note = _aws_window_note(plan, cloudtrail_narrowed=cloudtrail_narrowed)
    if aws_window_note:
        notes.append(aws_window_note)
    aws_no_interactive_note = _aws_no_interactive_note(
        plan, logs, cloudtrail_narrowed=cloudtrail_narrowed
    )
    if aws_no_interactive_note:
        notes.append(aws_no_interactive_note)
    beacon_non_established_note = _beacon_non_established_note(plan, logs)
    if beacon_non_established_note:
        notes.append(beacon_non_established_note)
    beacon_span_note = _beacon_span_note(plan, logs, requested_span)
    if beacon_span_note:
        notes.append(beacon_span_note)
    home_net_note = _home_net_note(plan, config)
    if home_net_note:
        notes.append(home_net_note)
    default_opt_in_note = _default_opt_in_note(plan, selection, detect_spec)
    if default_opt_in_note:
        notes.append(default_opt_in_note)
    syslog_provider_note = _syslog_provider_note(decision, syslog_intent, plan)
    if syslog_provider_note:
        notes.append(syslog_provider_note)
    if syslog_arbitration is not None:
        host_count, row_count = syslog_arbitration
        notes.append(
            f"system logs: {host_count:,} {plural(host_count, 'host')} carried by "
            "both the local feed and Zeek syslog.log - kept the local rows "
            f"({row_count:,} Zeek {plural(row_count, 'row')} set aside)"
        )
    # Source-dir overlap disclosure: when two IN-PLAN families resolve to the
    # same directory, flat discovery globs cross-read it (one log surfaced as
    # another's finding). Derives from already-resolved source_dirs + plan, like
    # the home_net note above. Appended before the coverage/rotation extends,
    # which are deliberately last.
    notes.extend(_source_overlap_notes(source_dirs, plan))
    # Source-coverage disclosure: for each planned source that contributed 0
    # in-window rows, append a note (SPAN / BARE / silent per the parse-gap
    # vs window-gap tri-state in CoverageTracker). Appended LAST so the
    # existing notes' relative order is preserved and the disclosure is
    # additive only. Reads the merged coverage written by the runner-side
    # flat-default block above (when fired).
    notes.extend(_zero_window_coverage_notes(load_result, plan))
    # Flat rotation-peek disclosure: one note per windowed pattern that fell back
    # to a full read or skipped out-of-window rotation files. Additive, appended last.
    notes.extend(_rotation_skip_notes(load_result, plan))
    detector_methods = {
        name: getattr(plan.detectors[name], "DETECTOR_METHOD", None)
        for name in plan.will_run
    }
    run_summary = RunSummary(
        # The loader's window verbatim - None when no loaded rows establish a
        # window (the render surfaces answer "none"/null; the fabricated
        # fallback local feeds DetectorContext only).
        data_window=load_result.data_window,
        record_counts=load_result.record_counts,
        data_size_bytes=load_result.data_size_bytes,
        detectors_run=plan.will_run,
        detectors_skipped=plan.skipped,
        notes=notes,
        data_sources=data_sources,
        detector_methods=detector_methods,
        requested_span=requested_span,
        invocation=invocation,
        generated_at=now,
    )

    # Resolve the allowlist plan ONCE and build the matcher HERE - the detector
    # loop reuses it, and the banner's suppression line is computed from the SAME
    # object so the readout cannot drift. `allowlist_plan` is distinct from `plan`
    # (the RunPlan); do not conflate them.
    allowlist_plan = resolve_allowlist_plan(config)
    allowlist = matcher_from_plan(allowlist_plan, force_off=no_allowlist)
    suppression_enabled = (not no_allowlist) and allowlist_plan.master_enabled
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
        with liveness("scanning allowlist coverage", enabled=not quiet):
            for _pat, _df in load_result.logs.items():
                if _df.empty:
                    continue
                if "query" in _df.columns:
                    suppressed_domains += allowlist.count_domain_suppressed(_df)
                    domain_total += len(_df)
                else:
                    if "src" in _df.columns:
                        suppressed_connections += allowlist.count_numeric_suppressed(_df)
                        connection_total += len(_df)
                    if "host" in _df.columns:
                        count, hosts = allowlist.count_host_suppressed(_df)
                        host_rows += count
                        host_total += len(_df)
                        matched_hosts.update(hosts)
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
    handler, close_handler, written_path = _build_output_handler(
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
    home_net = list(config.get("sigwood", {}).get("home_net", []))
    all_findings: list[Finding] = []

    for name in plan.will_run:
        mod = plan.detectors[name]
        det_cfg = get_detector_config(config, name, getattr(mod, "DEFAULT_CONFIG", {}))

        # Per-detector prep + run, scoped to honest error labels. Prep
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
                ctx = _prepare_detector_context(
                    mod, name, logs, allowlist, det_cfg,
                    data_window, data_sources, home_net,
                )
            except Exception as exc:
                _estderr(f"{name}: prep error - {exc}")
                run_summary.detectors_failed[name] = _failure_reason("prep error", exc)
                continue
            try:
                findings = mod.run(ctx)
            except Exception as exc:
                _estderr(f"{name}: detector error - {exc}")
                run_summary.detectors_failed[name] = _failure_reason("detector error", exc)
                findings = []
        else:
            with liveness(f"running {name}", enabled=not quiet) as _ln:
                try:
                    ctx = _prepare_detector_context(
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
                    findings = mod.run(ctx)
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
            written_path is not None or not _stream_isatty(sys.stdout)
        )
        with liveness("rendering report", enabled=render_liveness):
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


def _emit_syslog_decision_warnings(decision: SyslogProviderDecision) -> None:
    """Emit completeness warnings without applying the quiet status gate."""
    if (
        decision.reason is SyslogDecisionReason.AUTO_FAILURE
        and decision.diagnostic
    ):
        _estderr(f"system journal: {decision.diagnostic}")
    for warning in decision.warnings:
        _estderr(warning)


def _emit_syslog_skip_diagnostic(
    plan: RunPlan,
    decision: SyslogProviderDecision,
    intent: SyslogIntent,
) -> None:
    """Explain the local-provider half before the combined syslog skip."""
    if "syslog" not in plan.skipped or not intent.report_local_lane:
        return
    if decision.provider is SyslogProvider.OFF:
        _estderr("system logs: local lane off")
    elif decision.provider is SyslogProvider.FILES:
        _estderr("system logs: no eligible flat files found")


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
    pre_resolved_windows: Mapping[str, Any] | None = None,
) -> _LoadedPlan | int:
    """Build the final plan and eagerly load its one-provider source map."""
    from sigwood.common import loader

    plan = build_run_plan(
        detect_spec=detect_spec,
        zeek_dir=source_dirs.get("zeek_dir"),
        syslog_dir=source_dirs.get("syslog_dir"),
        pihole_dir=source_dirs.get("pihole_dir"),
        cloudtrail_dir=source_dirs.get("cloudtrail_dir"),
        journal=source_dirs.get("journal"),
        scope=scope,
        selection=selection,
    )
    _emit_syslog_skip_diagnostic(plan, provider_decision, syslog_intent)
    for name, reason in plan.skipped.items():
        _warn_skipped(name, reason)
    if not plan.will_run:
        if plan.skipped:
            _estderr(
                "no detectors could run - check required log source paths in config "
                "or CLI overrides"
            )
            return 1
        _estderr("no detectors to run - the detect spec selected none")
        return 0

    load_windows = loader.resolve_load_windows(
        plan.needed_logs,
        source_dirs,
        default_spec,
        load_all=load_all,
        since=since,
        until=until,
        pre_resolved_windows=pre_resolved_windows,
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
    if load_windows and not quiet:
        _estderr(default_window_advisory(default_spec))
    load_result = loader.load_required_logs(
        plan.needed_logs,
        source_dirs,
        since,
        until,
        verbose=verbose_level >= 1,
        source_windows=source_windows,
        show_progress=not quiet,
        file_select_windows=file_select_windows,
    )
    return _LoadedPlan(
        plan=plan,
        source_dirs=source_dirs,
        load_result=load_result,
        load_windows=load_windows,
        default_spec=default_spec,
    )


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


def discover_detectors(*, _failures: dict[str, str] | None = None) -> dict[str, Any]:
    """Scan sigwood/detectors/ and return available detector modules by name.

    ``_failures`` is an optional caller-owned sink: when present, a module
    whose import raises ImportError is recorded as ``{module_name: first line
    of the error}`` instead of vanishing silently. The key is the pkgutil
    MODULE name, not DETECTOR_NAME - a module that failed to import cannot be
    asked for its DETECTOR_NAME (the two are equal for every shipped
    detector). The catch stays ImportError-only: a missing dependency is the
    declared recoverable class; any other failure (e.g. a syntax error in a
    corrupt module) raises loudly.
    """
    detectors: dict[str, Any] = {}
    for _finder, name, _ispkg in pkgutil.iter_modules(_detectors_pkg.__path__):
        try:
            mod = importlib.import_module(f"{_detectors_pkg.__name__}.{name}")
        except ImportError as exc:
            if _failures is not None:
                msg = str(exc).strip()
                _failures[name] = msg.splitlines()[0] if msg else type(exc).__name__
            continue
        if hasattr(mod, "DETECTOR_NAME") and getattr(mod, "STATUS", "available") == "available":
            detectors[mod.DETECTOR_NAME] = mod
    return detectors


def select_detectors(
    detect_spec: str | None,
    detectors: dict[str, Any] | None = None,
) -> DetectorSelection:
    """Resolve detector selection without inspecting source availability."""
    import_failures: dict[str, str] = {}
    all_detectors = (
        detectors
        if detectors is not None
        else discover_detectors(_failures=import_failures)
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
    """
    resolved_selection = selection or select_detectors(detect_spec, detectors)
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
    for name in selected:
        # An import-failed name is absent from all_detectors - skip it before
        # the required-logs check (which would KeyError). The reason does not
        # embed the detector name; both render surfaces prefix it.
        if name in import_failures:
            skipped[name] = f"import failed - {import_failures[name]}"
            continue
        reason = _check_required_logs(
            all_detectors[name], source_map, scope, virtual_sources
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
            if _is_optional_satisfiable(req, source_map, virtual_sources):
                _claim_needed_log(needed_logs, req["pattern"], req["source"])

    return RunPlan(
        detectors=all_detectors,
        selected=selected,
        will_run=will_run,
        skipped=skipped,
        needed_logs=needed_logs,
    )


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


def _detector_token(detectors_run: list[str]) -> str | None:
    """Auto-name token from the detectors that ran: 1 → the name; ≥2 →
    ``<first>-plus<K>`` (K = total − 1); 0 → None (token omitted)."""
    names = list(detectors_run)
    if not names:
        return None
    return names[0] if len(names) == 1 else f"{names[0]}-plus{len(names) - 1}"


def _report_basename(output_format: str, detectors_run: list[str] = ()) -> str:
    """Auto-named analyze report basename ``sigwood-report_<token>_<YYYYMMDD>.<ext>``.

    The date renders in the display timezone - the same zone the report's own
    timestamps use (``run()`` sets the display switch at entry, before any
    naming work). The collision suffix is ``unique_path``'s job, not this
    function's."""
    ext = "txt" if output_format == "text" else output_format
    date = to_display_timezone(datetime.now(timezone.utc)).strftime("%Y%m%d")
    token = _detector_token(detectors_run)
    stem = f"sigwood-report_{token}_{date}" if token else f"sigwood-report_{date}"
    return f"{stem}.{ext}"


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
    source: str, paths: list[Path], pattern: str,
) -> bool:
    """Plan-time discovery lockstep with the LOADER for one family.

    Per-family mapping (matches ``load_required_logs``):

    - ``zeek_dir``      → ``discover_zeek_files(input, pattern)`` per input
    - ``cloudtrail_dir``→ ``discover_cloudtrail_files(input)`` per input
    - ``syslog_dir``    → ``_discover_syslog_files(input)`` per input - the LOADER
      content-sniffs syslog DIRECTORY candidates (RHEL/Fedora streams carry no
      ``.log`` suffix; ``dnf.log`` etc. would be mis-claimed by a filename glob),
      so plan-time MUST too (one-universe rail). A ``/var/log`` holding only
      ``dnf.log`` reports syslog NOT satisfiable → the detector skips with its
      actionable "not found" message instead of garbage.
    - ``pihole_dir``    → ``_syslog_files(input, pattern)`` per input - the LOADER
      threads the detector's pattern (``pihole*.log*``) into ``_syslog_files``
      for DIRECTORY discovery, so plan-time MUST too. An explicit FILE still
      routes as ``[path]`` regardless of pattern, so a content-routed Pi-hole
      input named e.g. ``events.log`` is NOT plan-rejected.

    Returns True iff ANY input yields at least one file.
    """
    from sigwood.common.loader import (
        _discover_syslog_files,
        _syslog_files,
        discover_for_source_key,
        discover_cloudtrail_files,
        discover_zeek_files,
    )
    for p in paths:
        if not p.exists():
            continue
        if source == "zeek_dir":
            if discover_zeek_files(p, pattern):
                return True
        elif source == "cloudtrail_dir":
            if discover_cloudtrail_files(p):
                return True
        elif source == "syslog_dir":
            if _discover_syslog_files(p):
                return True
        elif source == "pihole_dir":
            if _syslog_files(p, pattern):
                return True
        elif source == "journal":
            if discover_for_source_key("journal", p, pattern):
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
) -> bool:
    """Return True if an OPTIONAL_LOGS entry has files available to load."""
    source = req["source"]
    if (source, req["pattern"]) in virtual_sources:
        return True
    paths = _as_path_list(source_map.get(source))
    if not paths:
        return False
    return _any_input_yields_files(source, paths, req["pattern"])


def _check_required_logs(
    detector_module: Any,
    source_map: dict[str, Path | list[Path]],
    scope: frozenset[str] | None = None,
    virtual_sources: frozenset[tuple[str, str]] = frozenset(),
) -> str | None:
    """Return None if all REQUIRED_LOGS are available, or a human-readable reason if not.

    ``scope`` is the run's positional-scoping signal (None = unconstrained).
    A source family absent BECAUSE the operator's positional targets scoped it
    out must not read as "not configured" - the operator may have pointed
    straight at a directory containing that family's files; the honest reason
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
        if not _any_input_yields_files(source, paths, pattern):
            if len(paths) == 1:
                p = paths[0]
                if not p.exists():
                    return f"{source} {p} not found"
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
            if _is_optional_satisfiable(opt, source_map, virtual_sources):
                return None
        # The reason NEVER embeds the detector name - both render surfaces prefix
        # it (the doubled-name skip-line bug class), so the fallback carries none.
        return getattr(
            detector_module,
            "REQUIRES_ONE_OF_OPTIONAL_REASON",
            "no source available",
        )

    return None


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


def _estderr(line: str) -> None:
    """Emit one runner diagnostic line to stderr with terminal control bytes stripped.

    Untrusted filenames, directory names, and exception text from a scanned tree reach
    these diagnostics; a name embedding ESC / OSC / BEL could forge or hide terminal
    output. Every runner-owned diagnostic stderr print routes through here, so
    neutralization holds by construction. tqdm / liveness / progress own their own
    display path (common/display.py) and are deliberately NOT routed through this helper.
    """
    print(strip_control(line), file=sys.stderr)


def _warn_skipped(detector_name: str, reason: str) -> None:
    """Print a skip warning to stderr in the canonical format."""
    _estderr(f"{reason} - skipping {detector_name} detection")


# The shipped-Zeek connection/dns/syslog primary log patterns. The dry-run zeek_dir
# count discovers through the same loader helper the hunt uses (discover_zeek_files),
# so a dated zeekctl tree (YYYY-MM-DD/ + current/) is counted the way it will actually
# be loaded - not just its immediate file children.
_ZEEK_DRYRUN_PATTERNS = ("conn*.log*", "dns*.log*", "syslog*.log*")


def _zeek_entry_display(p: Path) -> str:
    """Render one zeek_dir input for the dry-run block.

    A DIRECTORY shows ``{path}  (N files, X.X MB)`` where N/size come from the
    loader's ``discover_zeek_files`` union over the shipped patterns, so a dated
    zeekctl layout is counted (not just immediate file children); an unreadable
    tree shows ``{path}  (unreadable)`` (truth unknown, never a raw traceback). A
    FILE shows ``{path}  (X.X MB)``; a non-existent path shows ``{path}  - not found``.
    """
    from sigwood.common.loader import discover_zeek_files

    if not p.exists():
        return f"{p}  - not found"
    if p.is_dir():
        discovered: dict[Path, Path] = {}
        try:
            for pattern in _ZEEK_DRYRUN_PATTERNS:
                for f in discover_zeek_files(p, pattern):
                    discovered[f.resolve()] = f
        except OSError:
            return f"{p}  (unreadable)"   # discovery failed - truth unknown, not empty
        total = 0
        for f in discovered.values():
            try:
                total += f.stat().st_size
            except OSError:
                pass  # a file denied/removed mid-scan - skip its bytes, keep the count
        return f"{p}  ({len(discovered)} files, {total / 1_048_576:.1f} MB)"
    try:
        size_mb = p.stat().st_size / 1_048_576
        return f"{p}  ({size_mb:.1f} MB)"
    except OSError:
        return f"{p}"


def _status_entry_display(p: Path) -> str:
    """Render one syslog/pihole/cloudtrail input for the dry-run block."""
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
    head = f"{label + ':':<{_BANNER_LABEL_WIDTH}}"
    indent = " " * _BANNER_LABEL_WIDTH  # matches the left-justified label width
    if not paths:
        print(f"{head}  not configured")
        return
    entries = [strip_control(formatter(p)) for p in paths]
    print(f"{head}  {entries[0]}")
    for e in entries[1:]:
        print(f"{indent}  {e}")


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
) -> None:
    print("sigwood  ·  threat hunt  ·  dry run")
    print(_SEP_DOUBLE)

    # Left-justified 15-char label field (width of the widest label,
    # "cloudtrail_dir:") plus a two-space gutter - labels flush-left, every value
    # shares one column (col 17) across the source-dir lines AND the
    # window/detectors/skipped lines below. Multi-input buckets stack additional
    # entries under that value column. Boundary accepts scalar Path / list / None
    # - same normalization shape as build_run_plan, so test callers passing
    # scalar Path or None work without juggling the wire shape.
    _print_family_block("zeek_dir", _as_path_list(zeek_dir), _zeek_entry_display)
    if (
        syslog_intent is not None
        and syslog_probe is not None
        and syslog_intent.report_local_lane
    ):
        system_logs, fallback = _dry_syslog_display(syslog_intent, syslog_probe)
        print(f"{'system logs:':<{_BANNER_LABEL_WIDTH}}  {strip_control(system_logs)}")
        if fallback:
            print(
                f"{'system fallback:':<{_BANNER_LABEL_WIDTH}}  "
                f"{strip_control(fallback)}"
            )
    else:
        _print_family_block(
            "syslog_dir", _as_path_list(syslog_dir), _status_entry_display
        )
    _print_family_block("pihole_dir", _as_path_list(pihole_dir), _status_entry_display)
    _print_family_block(
        "cloudtrail_dir", _as_path_list(cloudtrail_dir), _status_entry_display,
    )

    if load_all:
        window_value = "all available data (--all)"
    elif since and until:
        window_value = fmt_window((since, until))
    elif since or until:
        since_str = fmt_timestamp(since) if since else "beginning of data"
        until_str = fmt_timestamp(until) if until else "end of data"
        window_value = f"{since_str} → {until_str}"
    else:
        window_value = "all available data"
    print(f"{'window:':<{_BANNER_LABEL_WIDTH}}  {window_value}")

    if will_run:
        print(f"{'detectors:':<{_BANNER_LABEL_WIDTH}}  {'  '.join(will_run)}")
    elif skipped:
        print(f"{'detectors:':<{_BANNER_LABEL_WIDTH}}  (none - required logs unavailable)")
    else:
        print(f"{'detectors:':<{_BANNER_LABEL_WIDTH}}  (none - detect spec selected none)")

    # Group detectors by skip reason for compact display
    by_reason: dict[str, list[str]] = {}
    for name, reason in skipped.items():
        by_reason.setdefault(reason, []).append(name)

    for reason, names in by_reason.items():
        print(f"{'skipped:':<{_BANNER_LABEL_WIDTH}}  {', '.join(names)} - {strip_control(reason)}")

    if opt_in:
        names = strip_control(", ".join(opt_in))
        print(
            f"{'opt-in:':<{_BANNER_LABEL_WIDTH}}  {names} - not in the default hunt "
            "(--detect=all runs everything)"
        )

    print(_SEP_DOUBLE)
    print("dry run - remove --dry-run to analyze")


def _dry_syslog_display(
    intent: SyslogIntent,
    decision: SyslogProbeDecision,
) -> tuple[str, str | None]:
    """Return dry-run provider and optional not-loaded fallback copy."""
    paths = _compact_syslog_paths(intent.flat_paths)
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


def _confirm_large_dataset(
    total_records: int,
    cfg_sigwood: dict[str, Any],
    *,
    skip_confirm: bool,
) -> None:
    """Apply the advisory large-dataset gate shared by analyze and digest.

    The gate fires only when ``[sigwood].warn_above`` is positive, the record
    count exceeds it, and the operator did not pass ``--yes``. A zero or
    negative threshold disables the prompt. EOF or Ctrl-C is a decline.
    Declines raise ``ExportAborted`` for the CLI to translate to exit 0.
    """
    warn_above: int = cfg_sigwood.get("warn_above", 10_000_000)
    if warn_above <= 0 or total_records <= warn_above or skip_confirm:
        return
    try:
        with cursor_visible():
            answer = input(
                f"{total_records:,} records found. This may take a while. "
                "Continue? [y/N] "
            )
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip().lower() not in ("y", "yes"):
        raise ExportAborted("sigwood: aborted by user")


def _derive_data_sources(
    needed_logs: dict[str, str],
    record_counts: dict[str, int],
) -> list[str]:
    """Return sorted data_source labels for patterns that produced non-empty data."""
    from sigwood.common.loader import _log_type

    labels: set[str] = set()
    for pattern, count in record_counts.items():
        if count <= 0:
            continue
        source = needed_logs.get(pattern)
        if source is None:
            continue
        if source == "zeek_dir":
            lt = _log_type(pattern)
            if lt is not None:
                labels.add(f"zeek_{lt}")
        elif source == "syslog_dir":
            labels.add("syslog_raw")
        elif source == "pihole_dir":
            labels.add("dnsmasq_dns")
        elif source == "cloudtrail_dir":
            labels.add("cloudtrail_raw")
        elif source == "journal":
            labels.add("syslog_journal")
    return sorted(labels)


def _pattern_human_label(source_key: str, pattern: str) -> str:
    """Operator-language label for one (source_key, pattern) tuple.

    USED BY: the source-coverage disclosure note (``_zero_window_coverage_notes``).
    DISTINCT FROM: ``_derive_data_sources``, which emits internal
    ``data_sources`` tokens (``"zeek_dns"`` / ``"dnsmasq_dns"`` / ``"syslog_raw"``
    / ``"cloudtrail_raw"``) consumed by the Zeek-evangelization nudge matcher and
    other internal channels - those token strings stay byte-identical there.

    Labels: ``Pi-hole`` / ``syslog`` / ``CloudTrail`` / ``Zeek <log_type>``.
    """
    from sigwood.common.loader import _log_type

    if source_key == "pihole_dir":
        return "Pi-hole"
    if source_key == "syslog_dir":
        return "syslog"
    if source_key == "cloudtrail_dir":
        return "CloudTrail"
    if source_key == "journal":
        return "system journal"
    if source_key == "zeek_dir":
        lt = _log_type(pattern)
        return f"Zeek {lt}" if lt is not None else "Zeek"
    return source_key


def _zero_window_coverage_notes(
    load_result: "loader.LoadResult",
    plan: RunPlan,
) -> list[str]:
    """Return disclosure notes for planned sources that contributed 0 in-window rows.

    Honesty rail - coverage counts VALID-ts rows only:
      - ``full_rows > 0`` → SPAN note (count + span + widen suggestion), or
        count-only when no valid span survived (degenerate; defensive).
      - ``full_rows is None`` and ``source_key == "zeek_dir"`` → BARE note
        ("files found, 0 records …"). The BARE arm is **zeek_dir-only**: for
        syslog/pihole/cloudtrail, "no files read" means a wrong-family skip
        or an empty directory - neither is a window gap the operator can fix
        with ``--since/--days``, and the existing per-source warnings already
        cover it.
      - ``full_rows == 0`` → NO note (parse gap; widen advice would mislead).
      - Pattern not loaded at all (source unconfigured) → NO note (the
        loader already warns ``"{source} not configured - {pattern} not loaded"``).
    """
    out: list[str] = []
    for pattern, source_key in plan.needed_logs.items():
        if load_result.record_counts.get(pattern, 0) != 0:
            continue
        if pattern not in load_result.logs:
            # Source unconfigured for this pattern - loader already warned.
            continue
        cov = load_result.coverage.get(pattern)
        # Parse gap → silent (would otherwise tell the operator to widen
        # the window on a file with no valid timestamps - misleading).
        if cov is not None and cov.full_rows == 0:
            continue
        label = _pattern_human_label(source_key, pattern)
        if cov is None or cov.full_rows is None:
            if source_key != "zeek_dir":
                continue
            out.append(
                f"{label}: files found, 0 records in the selected window - "
                "widen with --since/--days, or --all"
            )
            continue
        if cov.full_span is not None:
            start, end = cov.full_span
            out.append(
                f"{label}: {cov.full_rows:,} rows loaded, 0 in the selected "
                f"window; data spans {fmt_window((start, end))} - "
                "widen with --since/--days, or --all"
            )
        else:
            out.append(
                f"{label}: {cov.full_rows:,} rows loaded, 0 in the selected "
                "window - widen with --since/--days, or --all"
            )
    return out


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
            label = _pattern_human_label(source_key, pattern)
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
            label = _pattern_human_label(source_key, pattern)
            return (
                f"{label}: all {n} discovered {plural(n, 'file')} "
                "permission denied - grant your user read access and retry"
            )
    return None


def _rotation_fallback_line(label: str, info: "loader.RotationSkipInfo") -> str:
    """The one fallback-disclosure string, shared by the report note
    (``_rotation_skip_notes``) and the post-load stderr signal
    (``_rotation_fallback_lines``) - so the two surfaces are byte-identical.

    The two CONTENT-overlap reasons additionally warn of double-counting:
    rotation dedup is by path, not content, so a full read may count
    overlapping / duplicate rows twice (inflating syslog rarity/burst + digest
    stats). Gross disorder ("rotation order not monotonic") reorders without
    duplicating, so it does NOT get the clause.
    """
    if info.fallback_reason == "overlapping export windows":
        return (
            f"{label}: overlapping export windows - read the full archive "
            "(windowing skipped; overlapping rows may be counted twice)"
        )
    if info.fallback_reason == "duplicate rotation files":
        return (
            f"{label}: duplicate rotation files - read the full archive "
            "(windowing skipped; duplicate rows may be counted twice)"
        )
    return (  # "rotation order not monotonic" or None → existing wording
        f"{label}: rotation order not monotonic - read the full archive "
        "(windowing skipped)"
    )


def _rotation_skip_notes(
    load_result: "loader.LoadResult",
    plan: RunPlan,
) -> list[str]:
    """Return disclosure notes (the REPORT surface) for flat patterns windowed by
    rotation-peek.

    The loader records a ``RotationSkipInfo`` per windowed pattern; the runner
    formats the prose (the loader never imports the runner). Reuses
    ``_pattern_human_label`` for the operator-language source name.

    - ``fallback`` → the shared ``_rotation_fallback_line`` (also fed to the
      post-load stderr signal, so report and stderr cannot drift). Fallback WINS:
      it is data-true at the pattern level (``skipped == 0``), so the skip-summary
      cannot also fire.
    - else ``skipped > 0`` → "loaded L of L+S rotation files; S skipped outside
      the selected window (by rotation order)." NEUTRAL "outside" is truthful
      for both the ``--since`` older-tail skip and the ``--until`` too-new
      leading skip (a bounded run can skip both under one count).
    - else → no note.
    """
    out: list[str] = []
    for pattern, info in load_result.rotation_skips.items():
        label = _pattern_human_label(plan.needed_logs[pattern], pattern)
        if info.fallback:
            out.append(_rotation_fallback_line(label, info))
        elif info.skipped > 0:
            out.append(
                f"{label}: loaded {info.loaded} of {info.loaded + info.skipped} "
                f"rotation files; {info.skipped} skipped outside the selected "
                "window (by rotation order)"
            )
    return out


def _rotation_fallback_lines(
    load_result: "loader.LoadResult",
    plan: RunPlan,
) -> list[str]:
    """Just the FALLBACK lines (every ``info.fallback`` reason), for the post-load
    stderr "why did this read the whole archive" signal. Shares
    ``_rotation_fallback_line`` with the report note. The normal prune stays
    report-only - its per-file counts are too verbose for the live stream.
    """
    out: list[str] = []
    for pattern, info in load_result.rotation_skips.items():
        if info.fallback:
            label = _pattern_human_label(plan.needed_logs[pattern], pattern)
            out.append(_rotation_fallback_line(label, info))
    return out


_SYSLOG_PATH_DISPLAY_CAP = 3
_SYSLOG_PATH_CHAR_CAP = 256


def _compact_syslog_paths(paths: Sequence[Path]) -> str:
    """Render a bounded, terminal-safe local file-fallback path list."""
    rendered = [
        strip_control(compact_home(path))[:_SYSLOG_PATH_CHAR_CAP]
        for path in paths[:_SYSLOG_PATH_DISPLAY_CAP]
    ]
    text = ", ".join(rendered)
    omitted = len(paths) - len(rendered)
    if omitted > 0:
        text += f" (+{omitted} more)"
    return text


def _bounded_warning_rider(warnings: Sequence[str]) -> str | None:
    """Render one producer warning plus a bounded omitted-warning count."""
    if not warnings:
        return None
    first = strip_control(warnings[0])[:512]
    if len(warnings) > 1:
        first += f" (+{len(warnings) - 1} more)"
    return first


def _syslog_provider_note(
    decision: SyslogProviderDecision,
    intent: SyslogIntent,
    plan: RunPlan,
) -> str | None:
    """Return the one bounded system-log provider disclosure for the report."""
    if not intent.report_local_lane:
        return None
    paths = _compact_syslog_paths(intent.flat_paths)
    fallback = f"{paths} fallback not loaded" if paths else "no file fallback configured"
    warning = _bounded_warning_rider(decision.warnings)

    if decision.provider is SyslogProvider.OFF:
        return "system logs: off"
    if decision.provider is SyslogProvider.JOURNAL:
        if decision.reason is SyslogDecisionReason.AUTO_JOURNAL:
            if decision.legacy_migrated:
                detail = (
                    "auto from legacy config; set syslog_source=\"files\" to keep "
                    f"file-only behavior; {fallback}"
                )
            else:
                detail = f"auto; {fallback}"
        elif decision.reason is SyslogDecisionReason.EXPLICIT_JOURNAL:
            detail = f"explicit; {fallback}"
        else:
            detail = f"configured; {fallback}"
        if decision.capture_outcome is JournalCaptureOutcome.CLEAN_EMPTY:
            detail += "; journal had no entries in the selected window"
        elif decision.capture_outcome is JournalCaptureOutcome.NO_USABLE:
            detail += "; journal had no usable entries in the selected window"
        if warning:
            detail += f"; {warning}"
        return f"system logs: journal ({detail})"

    base = f"system logs: files {paths}" if paths else "system logs: files"
    if decision.reason in (
        SyslogDecisionReason.EXPLICIT_PATH_FILES,
        SyslogDecisionReason.EXPLICIT_FILES,
    ):
        detail = "explicit"
    elif decision.reason is SyslogDecisionReason.CONFIGURED_FILES:
        detail = "configured"
    elif decision.reason is SyslogDecisionReason.AUTO_MISSING:
        detail = "auto; journal unavailable"
    elif decision.reason is SyslogDecisionReason.AUTO_CLEAN_EMPTY:
        detail = "auto; journal had no entries in the selected window"
    elif decision.reason is SyslogDecisionReason.AUTO_NO_USABLE:
        detail = "auto; journal had no usable entries in the selected window"
    else:
        detail = "auto; journal unavailable"
        if decision.diagnostic:
            detail += f" - {strip_control(decision.diagnostic)[:512]}"
    if "syslog_dir" not in plan.needed_logs.values():
        detail += "; no eligible syslog files found"
    if warning:
        detail += f"; {warning}"
    return f"{base} ({detail})"


def _arbitrate_cross_feed_syslog(
    load_result: "loader.LoadResult",
) -> tuple["loader.LoadResult", tuple[int, int] | None]:
    """Keep the local carrier for hosts also present in Zeek syslog."""
    # These contract patterns are claimed only by the syslog lane. Provider
    # arbitration has already selected the one local carrier behind ``*.log*``.
    local = load_result.logs.get("*.log*")
    zeek = load_result.logs.get("syslog*.log*")
    if local is None or zeek is None or zeek.empty:
        return load_result, None
    if "host" not in local.columns or "host" not in zeek.columns:
        return load_result, None

    local_hosts = set(local["host"].astype(str).str.lower().unique()) - {"unknown"}
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


def _dns_nudge(data_sources: list[str]) -> str | None:
    """Return the Zeek evangelization note when only low-fidelity DNS data was loaded."""
    ds = set(data_sources)
    if "dnsmasq_dns" in ds and ds.isdisjoint(_RICH_DNS_SOURCES):
        return (
            "running on Pi-hole/dnsmasq logs - RTT, TTL, and connection correlation "
            "unavailable. Add Zeek for richer DNS analysis and conn.log correlation."
        )
    return None


def _default_opt_in_remainder(
    plan: RunPlan,
    selection: DetectorSelection,
    detect_spec: object | None,
) -> list[str]:
    """Return opt-in detectors omitted by a default-participating selection.

    Explicit exclusions are operator intent and never read as curation. This
    pre-loop disclosure helper is defensive: optional module metadata cannot
    abort an otherwise valid hunt.
    """
    if not selection.used_default:
        return []
    try:
        tokens = _spec_tokens(str(detect_spec or DEFAULT_DETECT_SPEC))
        exclusions = {
            token[1:] for token in tokens if token.startswith("!")
        }
        return sorted(
            name
            for name, mod in plan.detectors.items()
            if not getattr(mod, "IN_DEFAULT_HUNT", False)
            and name not in plan.selected
            and name not in exclusions
        )
    except Exception:
        return []


def _default_opt_in_note(
    plan: RunPlan,
    selection: DetectorSelection,
    detect_spec: object | None,
) -> str | None:
    """Build the default-hunt opt-in disclosure for RunSummary.notes."""
    try:
        remainder = _default_opt_in_remainder(plan, selection, detect_spec)
        if not remainder:
            return None
        action = "run it" if len(remainder) == 1 else "run them"
        names = ", ".join(remainder)
    except Exception:
        return None
    return (
        f"default hunt - not run: {names} "
        f"(opt-in; {action} by name or with --detect=all)"
    )


def _aws_below_floor_note(
    plan: RunPlan,
    logs: dict[str, pd.DataFrame],
    config: dict[str, Any],
) -> str | None:
    """RunSummary note disclosing principals below the aws min_events floor.

    Pure derivation from the loaded CloudTrail frame via the detector's
    public ``below_floor_count`` helper. Called BEFORE the detector loop -
    detector-side state (a module cache populated inside run()) would be
    stale at this point. Returns None when aws is not in the plan, when the
    helper is missing (defensive), when no frame is loaded, or when count == 0.
    """
    if "aws" not in plan.will_run:
        return None
    mod = plan.detectors.get("aws")
    if mod is None or not hasattr(mod, "below_floor_count"):
        return None
    df = logs.get("*.json*")
    if df is None or df.empty:
        return None
    aws_cfg = get_detector_config(config, "aws", getattr(mod, "DEFAULT_CONFIG", {}))
    default_min = getattr(mod, "DEFAULT_CONFIG", {}).get("min_events", 50)
    min_events = aws_cfg.get("min_events", default_min)
    count = mod.below_floor_count(df, min_events)
    if count <= 0:
        return None
    return (
        f"aws: {count} interactive {plural(count, 'principal')} below the "
        f"min_events floor {plural(count, 'was', 'were')} not scored - the quiet "
        "tail of low-volume actors was not examined"
    )


def _aws_window_note(
    plan: RunPlan, *, cloudtrail_narrowed: bool = False
) -> str | None:
    """First-seen labels are relative to the loaded window - name the limitation.

    Fires whenever aws ran, regardless of whether any bursts were emitted. The
    methodology limitation is worth knowing even if this run produced no
    burst findings, because the absence is itself window-dependent.

    The ``--all`` rider is keyed to CLOUDTRAIL ACTUALLY being narrowed (an
    explicit --since/--until), NOT run-level default-window activity: CloudTrail
    opts out of the auto-default window, so on a mixed unqualified run
    (dns/syslog windowed) it loaded FULL and widening would not help. Rides the
    EXISTING note (no new note, no position change).
    """
    if "aws" not in plan.will_run:
        return None
    note = (
        "aws: first-seen actions are first-seen within this loaded window - an "
        "action that is routinely used but absent earlier in the window reads "
        "as first-seen."
    )
    if cloudtrail_narrowed:
        note += " Run with --all for a full-baseline analysis."
    return note


def _aws_no_interactive_note(
    plan: RunPlan,
    logs: dict[str, pd.DataFrame],
    *,
    cloudtrail_narrowed: bool,
) -> str | None:
    """Disclose the silent aws "nothing" when events loaded but zero are
    interactive-lane (aws.run returns [] with no finding).

    Pure derivation via the detector's public ``interactive_count`` helper
    (mirrors ``_aws_below_floor_note``). Fires when aws is planned, the
    ``*.json*`` frame is non-empty, and no event is interactive-lane. The
    ``--all`` suffix is conditional on ``cloudtrail_narrowed`` - widening only
    helps when an explicit window narrowed the load; on an unqualified run
    CloudTrail already loaded full, so widening cannot surface interactive
    events that do not exist.
    """
    if "aws" not in plan.will_run:
        return None
    mod = plan.detectors.get("aws")
    if mod is None or not hasattr(mod, "interactive_count"):
        return None
    df = logs.get("*.json*")
    if df is None or df.empty:
        return None
    if mod.interactive_count(df) != 0:
        return None
    note = (
        f"aws: {len(df)} CloudTrail {plural(len(df), 'event')} loaded but none are "
        "interactive-lane - aws scores only interactive activity, so nothing was analyzed"
    )
    if cloudtrail_narrowed:
        note += " - run with --all for full history"
    return note


def _beacon_non_established_note(
    plan: RunPlan,
    logs: dict[str, pd.DataFrame],
) -> str | None:
    """Disclose when beacon's established-only gate excluded most loaded connections.

    Pure derivation via the detector's public ``non_established_share`` helper, which is
    defensive on a conn_state-absent frame. Called BEFORE the detector loop - outside the
    detector's error containment - so it must not raise. The row floor is checked BEFORE the
    share so an empty or tiny frame never divides into a spurious ratio.
    """
    if "beacon" not in plan.will_run:
        return None
    mod = plan.detectors.get("beacon")
    if mod is None or not hasattr(mod, "non_established_share"):
        return None
    if not hasattr(mod, "_NON_ESTABLISHED_NOTE_MIN_ROWS") or not hasattr(
        mod, "_NON_ESTABLISHED_NOTE_SHARE"
    ):
        return None
    df = logs.get("conn*.log*")
    if df is None or df.empty:
        return None
    non_est, total = mod.non_established_share(df)
    if total < mod._NON_ESTABLISHED_NOTE_MIN_ROWS:
        return None
    if non_est / total < mod._NON_ESTABLISHED_NOTE_SHARE:
        return None
    pct = 100.0 * non_est / total
    return (
        f"beacon: {non_est} of {total} {plural(total, 'connection')} ({pct:.0f}%) were "
        "not in an established state and were not scored - a periodic retry pattern to a "
        "dead or blocked host is not detected"
    )


def _beacon_span_note(
    plan: RunPlan,
    logs: dict[str, pd.DataFrame],
    requested_span: timedelta | None,
) -> str | None:
    """Disclose when the analyzed conn span is too short to resolve a jittered beacon.

    Resolving a jittered periodic beacon needs roughly a week of span; the
    runner reads beacon's ``_MIN_RELIABLE_SPAN_DAYS`` and the defensive
    ``analyzed_span_seconds`` helper. Called BEFORE the detector loop - outside the
    detector's error containment - so it must not raise; the helper returns its 0.0
    no-measurement sentinel on any unreadable frame.

    Fires only on a POSITIVE analyzed span below the floor: a 0.0 span (absent / malformed
    / single-row ts) stays silent. The narrowed/unbounded fork mirrors ``_aws_window_note``'s
    --all rider - a bounded lookback (requested_span set) can be widened; an unbounded run
    already loaded all it has.
    """
    if "beacon" not in plan.will_run:
        return None
    mod = plan.detectors.get("beacon")
    if mod is None or not hasattr(mod, "analyzed_span_seconds"):
        return None
    if not hasattr(mod, "_MIN_RELIABLE_SPAN_DAYS"):
        return None
    df = logs.get("conn*.log*")
    if df is None or df.empty:
        return None
    span_s = mod.analyzed_span_seconds(df)
    if span_s <= 0.0:
        return None
    days = mod._MIN_RELIABLE_SPAN_DAYS
    if span_s >= days * 86400:
        return None
    span = fmt_compact_span(timedelta(seconds=span_s))
    if requested_span is not None:
        return (
            f"beacon: analyzed {span} of data - resolving a jittered beacon needs "
            f"about {days} {plural(days, 'day')} of span; widen with --all or a longer lookback"
        )
    return (
        f"beacon: only {span} of data available - resolving a jittered beacon needs "
        f"about {days} {plural(days, 'day')} of span"
    )


def _home_net_note(plan: RunPlan, config: dict[str, Any]) -> str | None:
    """RunSummary note disclosing the internal networks in effect for scan.

    Fires only when scan is in plan.will_run. Distinguishes default-vs-declared
    by reading the ``__user_set__`` provenance sidecar attached by the config
    loader - a pure value comparison would misclassify a user who declares the
    RFC1918 list verbatim as "default". When the operator did not declare
    home_net (no config file, or config file omits the key), the parenthetical
    fires; when they did declare it, the note states their value plainly.
    """
    if "scan" not in plan.will_run:
        return None
    home_net = list(config.get("sigwood", {}).get("home_net", []))
    if not home_net:
        return None
    rendered = ", ".join(home_net)
    user_set = config.get("__user_set__", {}).get("sigwood", set())
    if "home_net" in user_set:
        return f"internal networks: {rendered}"
    return (
        f"internal networks: {rendered} "
        "(RFC1918 default - set home_net in config to override)"
    )


def _source_overlap_notes(
    source_dirs: dict[str, list[Path]], plan: RunPlan,
) -> list[str]:
    """RunSummary notes when two IN-PLAN source families resolve to one directory.

    The contamination vector: flat discovery globs overlap (``syslog`` discovers
    with the catch-all ``*.log*``), so a directory shared by two families has its
    files parsed by each front-end - one log can surface as another's finding.
    This is a plan-time disclosure, derived from already-resolved sources (same
    posture as ``_home_net_note``), not a load-time check.

    Binding rails:

    - **Eligibility = in-plan families only.** Derived from
      ``set(plan.needed_logs.values())``, NOT every non-empty resolved bucket.
      A family configured-and-resolved but not selected (no detector in the run
      reads it) cannot contaminate, so two dirs colliding while only one family
      is planned does NOT warn. Optional multi-source detectors add only their
      satisfiable patterns to ``needed_logs``, so the note follows what the
      loader will actually read.
    - **Directories only.** Explicit FILE inputs are out of scope - the vector
      is dir-glob overlap, not a shared named file. Per-family duplicate inputs
      collapse (a key is recorded once per directory).
    - **Equal-dir ONLY (v1).** Flat discovery is non-recursive, so the shipped
      default (``syslog_dir=/var/log`` containing ``zeek_dir=/var/log/zeek``)
      does NOT contaminate and MUST NOT warn - nesting is deliberately out of
      scope. (CloudTrail's ``rglob`` makes nested cloudtrail an acknowledged
      deferred edge.)
    - **Deterministic ordering.** ``source_dirs`` is built in canonical key order
      by ``run`` (zeek, syslog, pihole, cloudtrail); first-seen preservation here
      keeps the rendered family list deterministic. ≥3 families at one dir → one
      note listing all.
    """
    in_plan = set(plan.needed_logs.values())
    by_dir: dict[Path, list[str]] = {}
    for key, paths in source_dirs.items():
        if key not in in_plan:
            continue
        for p in paths:
            if not p.is_dir():            # explicit files out of scope
                continue
            try:
                resolved = p.resolve()
            except OSError:
                continue
            families = by_dir.setdefault(resolved, [])
            if key not in families:       # collapse per-family duplicate inputs
                families.append(key)

    notes: list[str] = []
    for resolved, families in by_dir.items():
        if len(families) >= 2:
            notes.append(
                f"{', '.join(families)} resolve to the same directory "
                f"({resolved}): files there matching more than one source's "
                "patterns are parsed by each, which can surface one log as "
                "another's finding. Point them at separate directories - global "
                "exports now auto-segment per source."
            )
    return notes


# ─────────────────────────────────────────────────────────────────────────────
# digest verb - orient-before-the-hunt
#
# run_digest() and the helpers below are a parallel entry point to run(). They
# share the loader, output-handler-building, and _derive_data_sources. Default-
# window resolution goes through the SAME loader.resolve_load_windows +
# loader.apply_default_window that run() uses.
# Digest default-windowing stays Zeek-ONLY (the caller-side gate below): non-Zeek
# digest directories load full. Pinned by the
# Zeek-directory golden plus the programmatic non-Zeek load-full tests.
# ─────────────────────────────────────────────────────────────────────────────

_HISTOGRAM_HOURLY_THRESHOLD_HOURS = 48
_HISTOGRAM_MAX_BINS = 60


# Timestamp-confidence floor for digest cards. When the parseable-ts fraction
# falls below this floor (or the non-NaN span is zero), the digest banner
# window dashes and the histogram line renders "(timeline unavailable)" -
# the card refuses to draw a timeline it cannot trust. Set at 80% per the
# confident-but-wrong defects gate: lower risks rendering a confident
# timeline on junk timestamps; higher would erase orientation when a small
# fraction of a syslog batch is corrupt.
_DIGEST_TS_CONFIDENCE_FLOOR: float = 0.80


def _ts_confidence(frame: pd.DataFrame) -> bool:
    """True iff the frame's ``ts`` column can support an honest timeline.

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
    if parsed / total < _DIGEST_TS_CONFIDENCE_FLOOR:
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
    if span_hours <= _HISTOGRAM_HOURLY_THRESHOLD_HOURS:
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
    if len(counts) > _HISTOGRAM_MAX_BINS:
        # Cap output width by folding adjacent bins by sum. The unit label
        # stays nominal - each glyph now spans several hr/day - but the peak
        # anchor recomputed below stays truthful to the drawn bars.
        group_size = -(-len(counts) // _HISTOGRAM_MAX_BINS)
        counts = [
            sum(counts[i:i + group_size])
            for i in range(0, len(counts), group_size)
        ]
    peak = max(counts) if counts else 0
    return counts, unit, peak


_DNS_ZEEK_EMPTY_COLUMNS = [
    "ts", "src", "query", "resolver", "rtt", "ttl", "rcode", "answer", "tc",
    "qtype",
]
_DNS_PIHOLE_EMPTY_COLUMNS = [
    "ts", "src", "query", "event_type", "qtype", "dst", "answer",
    "validation", "host", "raw", "message",
]
_CONN_EMPTY_COLUMNS = [
    "src", "dst", "port", "proto", "ts", "bytes", "conn_state", "local_orig",
]
_SYSLOG_EMPTY_COLUMNS = ["ts", "host", "program", "raw", "message"]
_CLOUDTRAIL_EMPTY_COLUMNS = [
    "ts", "principal", "lane", "read_write",
    "event_source", "event_name", "identity_type",
    "source_ip", "error_code", "aws_region", "event_id", "raw",
]


# (schema, source_key) → (loader glob pattern, empty-frame column set).
# Mechanical mapping kept inline alongside run_digest because it's runner
# plumbing - pattern + columns are runner/loader concerns, NOT source-
# resolution ownership (DigestSource just carries the directory + feed +
# source_key).
_DIGEST_PATTERN_AND_EMPTY: dict[tuple[str, str], tuple[str, list[str]]] = {
    ("conn",       "zeek_dir"):       ("conn*.log*",   _CONN_EMPTY_COLUMNS),
    ("dns",        "zeek_dir"):       ("dns*.log*",    _DNS_ZEEK_EMPTY_COLUMNS),
    ("dns",        "pihole_dir"):     ("pihole*.log*", _DNS_PIHOLE_EMPTY_COLUMNS),
    ("syslog",    "syslog_dir"):      ("*.log*",       _SYSLOG_EMPTY_COLUMNS),
    ("syslog",    "zeek_dir"):        ("syslog*.log*", _SYSLOG_EMPTY_COLUMNS),
    ("cloudtrail", "cloudtrail_dir"): ("*.json*",      _CLOUDTRAIL_EMPTY_COLUMNS),
}


# Inter-card separator emitted between adjacent rendered cards on a multi-card
# run (stdout fan-out or --out concatenation). 40 columns of U+2500 BOX
# DRAWINGS LIGHT HORIZONTAL, flush-left, with one blank line above and one
# blank line below. Single-card runs (one positional, or a multi-positional
# run where only one path reaches render-commit) draw no rule at all - the
# emit fires only when ``leading_separator=True``, which the CLI sets from
# ``rendered > 0`` AFTER a prior card's run_digest return.
_DIGEST_INTER_CARD_RULE: str = "─" * 40


def _emit_inter_card_separator(stream: Any) -> None:
    """Emit the 40-col inter-card rule with bracketing blank lines."""
    target = stream if stream is not None else sys.stdout
    print(file=target)
    print(_DIGEST_INTER_CARD_RULE, file=target)
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

    handler, close_handler, _written = _build_output_handler(
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


def _graph_source_label(paths: Sequence[Path]) -> str:
    """Return an aggregate source identity for graph metadata/control signals."""
    if not paths:
        return "graph source"
    return ", ".join(strip_control(path.name) for path in paths)


def _graph_discovered_file_meta(
    spec: GraphKindSpec,
    source_inputs: Sequence[Path],
    *,
    trusted_files: Sequence[Path],
) -> dict[str, str | int]:
    """Return graph provenance from the loader's discovery candidate universe."""
    from sigwood.common import loader

    trusted_resolved = {loader._safe_resolve(path) for path in trusted_files}
    per_input: list[list[Path]] = []
    for path in source_inputs:
        if loader._safe_resolve(path) in trusted_resolved:
            per_input.append([path])
            continue
        try:
            per_input.append(
                loader.discover_for_source_key(
                    spec.source_key, path, spec.pattern,
                )
            )
        except OSError:
            per_input.append([])

    discovered = sorted(
        loader._union_dedupe(per_input),
        key=lambda path: os.path.abspath(path),
    )
    if not discovered:
        return {"file_sample": "", "file_count": 0, "common_dir": ""}

    absolute = [os.path.abspath(path) for path in discovered]
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
        "file_count": len(discovered),
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
    spec, source_inputs = resolve_graph_source(config, kind, inputs=inputs)
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
        default_window_note = default_window_advisory(default_spec)
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
        _estderr(warning)
    if not quiet:
        for pattern, info in load_result.rotation_skips.items():
            if info.fallback:
                label = _pattern_human_label(needed_logs[pattern], pattern)
                _estderr(_rotation_fallback_line(label, info))

    # Strict graph accounting deliberately happens before the clean-empty
    # branch: an unreadable requested source is operationally incomplete even
    # if a sibling yielded an artifact-shaped frame.
    permission_error = _permission_denied_run_error(
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
            _estderr(warning)
        retry_permission_error = _permission_denied_run_error(
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

    with liveness(f"building {kind} graph", enabled=not quiet):
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
        _estderr(degrade_note)
    if not quiet:
        for note_key in ("band_loss_note", "straddler_note"):
            note = payload["meta"].get(note_key)
            if note:
                _estderr(str(note))
    payload["meta"].update(
        _graph_discovered_file_meta(
            spec, source_inputs, trusted_files=trusted_files,
        )
    )
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
    if schema not in ("conn", "dns", "syslog", "cloudtrail", "blob"):
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
            print(_SEP)
            print(f"  {'schema:':<{_BANNER_LABEL_WIDTH}} blob")
            print(f"  {'path:':<{_BANNER_LABEL_WIDTH}} {strip_control(blob_path)}")
            print(f"  {'window:':<{_BANNER_LABEL_WIDTH}} (none - blob extracts no fields)")
            print(_SEP)
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
    pattern, empty_columns = _DIGEST_PATTERN_AND_EMPTY[(schema, source_key)]

    from sigwood.common import loader

    # Default-window resolution is Zeek-ONLY on the digest path (the
    # boundedness rule): non-Zeek digest directories (pihole/syslog/cloudtrail)
    # load full and filter by an explicit window only. The caller-side gate below
    # IS the behavior-preservation point - digest invokes the SHARED resolver
    # (loader.resolve_load_windows) for the Zeek source alone, NOT a duplicate
    # engine. dated → precise (since, until); flat / mixed → post-load trim_span.
    dated_window: tuple[datetime, datetime] | None = None
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
            default_window_note = default_window_advisory(default_spec)

    if dry_run:
        print("sigwood  ·  digest  ·  dry run")
        print(_SEP)
        print(f"  {'schema:':<{_BANNER_LABEL_WIDTH}} {schema}")
        if feed is not None:
            print(f"  {'feed:':<{_BANNER_LABEL_WIDTH}} {feed}")
        print(f"  {source_key + ':':<{_BANNER_LABEL_WIDTH}} {strip_control(source_dir)}")
        if dated_window is not None:
            print(
                f"  {'window:':<{_BANNER_LABEL_WIDTH}} {fmt_window(dated_window)}  "
                "(dated default)"
            )
        elif flat_span is not None:
            print(
                f"  {'window:':<{_BANNER_LABEL_WIDTH}} last "
                f"{cfg_sigwood.get('default_window', '7d')} of available data  (flat default)"
            )
        elif since is not None or until is not None:
            since_str = fmt_timestamp(since) if since else "beginning of data"
            until_str = fmt_timestamp(until) if until else "end of data"
            print(f"  {'window:':<{_BANNER_LABEL_WIDTH}} {since_str} → {until_str}")
        elif load_all:
            print(f"  {'window:':<{_BANNER_LABEL_WIDTH}} all available data (--all)")
        else:
            print(f"  {'window:':<{_BANNER_LABEL_WIDTH}} all available data")
        print(_SEP)
        return

    needed_logs = {pattern: source_key}
    # Digest compat: load_required_logs is list-only. Wrap [source_dir] for
    # the degenerate one-element case - card-per-file behavior unchanged,
    # the union plumbing runs as a single-element passthrough.
    source_dirs = {source_key: [source_dir]}
    source_windows = (
        {source_key: dated_window} if dated_window is not None else None
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
        _estderr(f"{warning}")

    total_records = sum(load_result.record_counts.values())
    _confirm_large_dataset(
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
    _ = _derive_data_sources(needed_logs, load_result.record_counts)

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
    # zero non-NaN span, the timeline cannot be drawn honestly - dash the
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
        # One-line stderr breadcrumb - verbose-gated so the raw exception
        # text does not leak to default-mode users (the "actionable
        # messages, never raw exceptions" rail). Default runs see the
        # blob card as the whole story; --verbose retains the breadcrumb
        # for debugging.
        if verbose_level >= 1:
            _estderr(
                f"digest: {fallback_blob_path.name}: summariser failed "
                f"({type(exc).__name__}: {exc}); falling back to blob"
            )
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

    handler, close_handler, _written = _build_output_handler(
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
