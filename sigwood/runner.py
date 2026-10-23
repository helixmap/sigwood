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

import sys
from collections import Counter
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import asdict, dataclass, field, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Collection, Iterator, Mapping, Sequence


import sigwood.detectors as _detectors_pkg

if TYPE_CHECKING:
    from sigwood.era.report import EraCard, SelectionEvidence, SpanHonesty
    from sigwood.common.loader import types as load_types
from sigwood.common.config import (
    DEFAULT_DETECT_SPEC,
    detector_disclosure_lines,
    get_detector_config,
    parse_window_span,
    resolve_home_net,
    validate_table_sections,
)
from sigwood.common.display import (
    TEXT_RULE,
    TEXT_RULE_DOUBLE,
    TEXT_RULE_WIDTH,
    _stream_isatty,
    _suppression_pct,
    compact_home,
    compact_path_list as _compact_path_list,
    cursor_visible,
    default_window_advisory,
    fmt_compact_span,
    fmt_timestamp,
    fmt_window,
    group_skips,
    human_bytes,
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
from sigwood.common.finding import (
    DetectorContext, Finding, RunSummary, PreparedPopulation, Preparation, Declined,
)
from sigwood.common.journal_probe import probe_journal
from sigwood.common.loader import (
    AvailabilityState,
    CoverageDecision,
    CoverageDecisionReason,
    CoverageLane,
    DirectorySkipInfo,
    DiscoveryFact,
    DiscoveryFactKind,
    DualWindow,
    ExportAvailability,
    FileOutcomeKind,
    FileSpan,
    JournalCaptureOutcome,
    PositionalMask,
    PreparedState,
    RootFact,
    RootFactKind,
)
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
    declared_source_patterns as _declared_source_patterns,
    resolve_digest_source,
    resolve_graph_source,
    resolve_analyze_sources,
    syslog_lane_detectors,
)
from sigwood.common.sanitize import strip_control
from sigwood.common.syslog_mode import SyslogMode

_PIHOLE_PATTERN = "pihole*.log*"
_LOCAL_SYSLOG_PATTERN = "*.log*"

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


from sigwood._runner.planning import (
    RunPlan,
    DetectorSelection,
    _discovery_liveness,
    _source_dirs_for_provider,
    _emit_syslog_skip_diagnostic,
    _RunWindows,
    _resolve_run_windows,
    _FamilyPreview,
    _DryRunPreview,
    _dry_run_preview,
    _PopulationPreparation,
    _preparation_cause,
    _population_interval,
    _PreparationHost,
    _suppression_contribution,
    _merge_suppression,
    _suppression_sink,
    _record_preparation_disposition,
    _prepare_populations,
    _population_load_maps,
    _recover_populations,
    _plan_and_load,
    _build_dual_window,
    discover_detectors,
    select_detectors,
    _as_path_list,
    build_run_plan,
    _detector_token,
    _spec_tokens,
    resolve_detect,
    _any_input_yields_files,
    _is_optional_satisfiable,
    _directory_denial_reason,
    _check_required_logs,
    _not_found_reason,
    _claim_needed_log,
    _status_entry_display,
    _print_family_block,
    _explicit_window_text,
    _size_text,
    _family_policy_text,
    _print_family_preview,
    _print_dry_run,
    _dry_syslog_display,
    _warn_above,
    _confirm_large_dataset,
    _relative_to,
    _safe_real,
)


from sigwood._runner.dnsblock_harness import (
    DnsblockCalibrationBatch,
    _prepare_dnsblock_calibration_batch,
    _pack_dnsblock_calibration_work,
    _write_dnsblock_evidence_payload,
    _write_dnsblock_preflight_progress,
    _write_dnsblock_preflight_artifact,
)





from sigwood._runner.analyze import (
    _LoadedPlan,
    _select_coverage_lane,
    run,
    _run_analyze,
    _finish_populations,
    _run_declared,
    _prepare_detector_context,
    _positional_allowlist_mask,
    _resolve_fold_dual_window,
    _failure_reason,
    _build_output_handler,
    _report_basename,
    _estderr,
    _warn_skips,
    _warn_skipped,
    _permission_denied_run_error,
    _arbitrate_cross_feed_syslog,
)








from sigwood._runner.era import (
    EraHarnessReceipt,
    EraOracleReceipt,
    _era_warning_class,
    _era_closure_config,
    _run_era_identity_oracle,
    _era_horizon_abstaining_cards,
    _run_era_harness,
    _confirm_era_work,
    run_era,
    _run_era_resource_measurement,
    _run_era_oracle_measurement,
)





# Reasoned operator-safety defaults for the public whole-archive verb.  They
# are deliberately not configuration: Era's planner owns the archive span.
_ERA_CONFIRM_COMPRESSED_BYTES = 1 << 30
_ERA_SHORT_CALENDAR_DAYS = 84






































from sigwood._runner.notes import (
    Note,
    flatten_notes,
    _emit_syslog_decision_warnings,
    _derive_data_sources,
    _pattern_human_label,
    _zero_window_coverage_notes,
    _permission_skip_notes,
    _directory_skip_notes,
    _render_directory_skips,
    _qualify_unsearched,
    _merge_facts,
    _render_coverage_fact,
    _discovery_coverage_lines,
    _root_fact_lines,
    _unselected_retained_lines,
    _layout_policy_lines,
    _shared_candidate_lines,
    _render_root_fact,
    _denial_owned_keys,
    _unowned_directory_skip_lines,
    _rotation_fallback_line,
    _rotation_skip_notes,
    _rotation_fallback_lines,
    _bounded_warning_rider,
    _syslog_provider_note,
    _dns_nudge,
    _default_opt_in_remainder,
    _default_opt_in_note,
    _dnsblock_cap_note,
    _format_dnsblock_summary_notes,
    _format_auth_summary_notes,
    _aws_below_floor_note,
    _aws_window_note,
    _aws_no_interactive_note,
    _ssl_facts,
    _ssl_visibility_line,
    _ssl_zero_findings_line,
    _ssl_eligibility_notes,
    _exfil_eligibility_notes,
    _beacon_eligibility_notes,
    _beacon_min_connections_note,
    _beacon_non_established_note,
    _beacon_span_note,
    _home_net_note,
    _source_overlap_notes,
)
































_SUPPRESSION_CHANNEL = "sigwood.suppression-coverage"







































































































































































# ── Directory coverage disclosure (analyze discovery inventory) ─────────────
#
# The loader-owned inventory decides, family by family, what each input's
# selection left unread and builds those facts. This composer only coordinates
# them with the statements other owners already make, qualifies unsearched
# children against the run's other inputs, and renders bounded text. Facts that
# already have an owner are left to it: directory listing denials
# (DirectorySkipInfo / _directory_skip_notes), load-time file denials
# (_permission_skip_notes), the loader's flat-family silent-miss warnings, and
# the single-input "not found" skip reason. Values are filesystem paths and
# counts only; every path goes through _compact_path_list, which strips controls
# and bounds length.
































_OUTCOME_PHRASES: dict[FileOutcomeKind, tuple[str, str]] = {
    FileOutcomeKind.OUTSIDE: ("file of another log type", "files of other log types"),
    FileOutcomeKind.EMPTY: ("empty file", "empty files"),
    FileOutcomeKind.EXCLUDED: ("file excluded by name", "files excluded by name"),
    FileOutcomeKind.UNRECOGNIZED: ("unrecognized file", "unrecognized files"),
    FileOutcomeKind.REJECTED: (
        "file named outside its family's patterns",
        "files named outside their family's patterns",
    ),
    FileOutcomeKind.UNREADABLE: ("unreadable file", "unreadable files"),
}






































_DNSBLOCK_CAP_NOTES: tuple[tuple[str, str, str], ...] = (
    ("association cells exceed", "association cells", "10,000,000"),
    ("address-name pairs exceed", "address-name pairs", "500,000"),
    ("pair-period cells exceed", "pair-period cells", "5,000,000"),
    ("name-date cells exceed", "name-date cells", "2,000,000"),
    ("address-date cells exceed", "address-date cells", "1,000,000"),
    ("names exceed", "names", "100,000"),
    ("addresses exceed", "addresses", "20,000"),
    ("families exceed", "families", "50,000"),
    ("coverage spans exceed", "coverage spans", "100,000"),
    ("worklist exceeds", "worklist entries", "50,000"),
    ("per-window routes exceed", "per-window routes", "1,000,000"),
    ("retained strings exceed", "retained strings", "256 MiB"),
    ("findings exceed", "findings", "1,000"),
    ("cadence gaps exceed", "cadence gaps", "10,000"),
)





















































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


from sigwood._runner.digest import (
    _ts_confidence,
    _compute_histogram,
    _emit_inter_card_separator,
    _render_blob_for_path,
    run_digest,
    _run_digest,
)




_DNS_ZEEK_EMPTY_COLUMNS = [
    "ts", "src", "query", "resolver", "rtt", "ttl", "rcode", "answer", "tc",
    "qtype",
]
_DNS_PIHOLE_EMPTY_COLUMNS = [
    "ts", "src", "query", "event_type", "qtype", "host",
]
_CONN_EMPTY_COLUMNS = [
    "src", "dst", "port", "proto", "ts", "bytes", "conn_state", "local_orig",
]
_SYSLOG_EMPTY_COLUMNS = ["ts", "host", "program", "raw", "message"]
_WEIRD_EMPTY_COLUMNS = ["ts", "name", "src", "source"]
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
    ("dns",        "pihole_dir"):     (_PIHOLE_PATTERN, _DNS_PIHOLE_EMPTY_COLUMNS),
    ("syslog",    "syslog_dir"):      (_LOCAL_SYSLOG_PATTERN,       _SYSLOG_EMPTY_COLUMNS),
    ("syslog",    "zeek_dir"):        ("syslog*.log*", _SYSLOG_EMPTY_COLUMNS),
    ("weird",      "zeek_dir"):       ("weird*.log*",  _WEIRD_EMPTY_COLUMNS),
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






from sigwood._runner.graph import (
    _graph_source_label,
    _graph_contributing_file_meta,
    _graph_date_dir_window,
    _graph_hunt_hint,
    run_graph,
    _run_graph,
)
