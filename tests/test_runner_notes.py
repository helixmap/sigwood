"""Internal disclosure metadata stays separate from public operator strings."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace as NS

import pandas as pd
import pytest

from sigwood import runner
from sigwood.common import loader
from sigwood.common.sources import (
    SyslogIntent, SyslogProviderDecision, SyslogProvider, SyslogDecisionReason,
)
from sigwood.common.syslog_mode import ConfiguredSyslogMode, SyslogMode
from sigwood.detectors import syslog
from tests.test_dnsblock_arrival_cadence import _prepared


KINDS = (
    "coverage", "eligibility", "provider", "window", "nudge", "opt-in", "home-net",
    "allowlist", "preparation", "rotation", "permission", "directory", "overlap",
    "arbitration", "summary",
)


def test_note_is_frozen_and_does_not_masquerade_as_text():
    note = runner.Note("coverage", "one line", "loader")
    assert (note.kind, note.text, note.provenance) == ("coverage", "one line", "loader")
    with pytest.raises(FrozenInstanceError):
        note.text = "changed"
    assert note != "one line"
    with pytest.raises(TypeError):
        "line" in note
    for kind in KINDS:
        assert runner.Note(kind, "", "plan").kind == kind
    with pytest.raises(ValueError, match="unknown note kind"):
        runner.Note("unregistered", "line", "plan")


def test_flatten_is_strict_and_preserves_every_position():
    notes = [runner.Note("coverage", "same", "loader"),
             runner.Note("summary", "", "auth"),
             runner.Note("coverage", "same", "inventory")]
    assert runner.flatten_notes(notes) == ["same", "", "same"]
    assert runner.flatten_notes(()) == []
    assert len(runner.flatten_notes(notes)) == len(notes)
    with pytest.raises(AttributeError):
        runner.flatten_notes(["unconverted ingress"])


CASES = (
    ("_zero_window_coverage_notes", {"coverage"}, "loader"),
    ("_permission_skip_notes", {"permission"}, "loader"),
    ("_directory_skip_notes", {"directory"}, "plan"),
    ("_discovery_coverage_lines", {"coverage"}, "inventory"),
    ("_unselected_retained_lines", {"coverage"}, "inventory"),
    ("_unowned_directory_skip_lines", {"directory"}, "plan"),
    ("_rotation_skip_notes", {"rotation"}, "loader"),
    ("_syslog_provider_note", {"provider"}, "syslog-provider"),
    ("_dns_nudge", {"nudge"}, "loader"),
    ("_default_opt_in_note", {"opt-in"}, "plan"),
    ("_format_dnsblock_summary_notes", {"coverage", "eligibility", "allowlist", "summary"}, "dnsblock"),
    ("_format_auth_summary_notes", {"summary", "allowlist"}, "auth"),
    ("_aws_below_floor_note", {"eligibility"}, "aws"),
    ("_aws_window_note", {"window"}, "plan"),
    ("_aws_no_interactive_note", {"eligibility"}, "aws"),
    ("_ssl_eligibility_notes", {"eligibility"}, "ssl"),
    ("_exfil_eligibility_notes", {"eligibility"}, "exfil"),
    ("_beacon_eligibility_notes", {"eligibility"}, "beacon"),
    ("_beacon_min_connections_note", {"eligibility"}, "beacon"),
    ("_beacon_non_established_note", {"eligibility"}, "beacon"),
    ("_beacon_span_note", {"window"}, "beacon"),
    ("_home_net_note", {"home-net"}, "config"),
    ("_source_overlap_notes", {"overlap"}, "plan"),
)


def _dnsblock_notes():
    prepared = _prepared()
    facts = replace(
        prepared.analysis.notes, insufficient_history_pairs=2,
        raw_query_rows=5, raw_block_report_rows=3, filtered_block_report_rows=2,
        raw_block_context_rows=0, filtered_block_context_rows=0,
        entity_findings=0, context_findings=0,
    )
    return runner._format_dnsblock_summary_notes(replace(
        prepared, analysis=replace(prepared.analysis, notes=facts),
    ))


def _auth_notes():
    from sigwood.detectors import auth
    from tests.test_auth_runner_notes import _context, _failure
    return runner._format_auth_summary_notes(auth.summary_facts(
        _context([_failure(1, source="192.0.2.80")]),
    ))


def _emit(name, root):
    path = root / "source"
    path.mkdir()
    child = path / "child"
    child.mkdir()
    denied = loader.DirectorySkipInfo("syslog_dir", path)
    plan = runner.RunPlan({"syslog": syslog}, ["syslog"], ["syslog"], {},
                          {"*.log*": "syslog_dir"})
    denial_plan = replace(plan, directory_skips={("syslog_dir", path): denied})
    empty_load = loader.LoadResult({}, {})
    discovery = NS(
        recursive=False, provenance=lambda *a: "invocation",
        inventory=NS(supports=lambda _: True, input_facts=lambda *a, **k: [
            loader.DiscoveryFact(loader.DiscoveryFactKind.UNSEARCHED_CHILDREN,
                                 "syslog_dir", path, (child,), 1),
        ]),
    )
    unreadable = loader.RootFact(
        loader.RootFactKind.UNREADABLE_FILES, path, (path / "messages.2",), 1,
        "EACCES", family="syslog_dir",
    )
    beacon = NS(
        DEFAULT_CONFIG={"min_connections": 1}, _MIN_SCORABLE_SAMPLES=5,
        _NON_ESTABLISHED_NOTE_MIN_ROWS=1, _NON_ESTABLISHED_NOTE_SHARE=0.5,
        _MIN_RELIABLE_SPAN_DAYS=7,
        scoring_eligibility=lambda *a: {"missing_columns": ("src",), "rows_total": 1},
        non_established_share=lambda *a: (9, 10), analyzed_span_seconds=lambda *a: 3600,
    )
    aws = NS(DEFAULT_CONFIG={"min_events": 50}, below_floor_count=lambda *a: 5,
             interactive_count=lambda *a: 0)
    ssl = NS(eligibility=lambda *a: {"rows_eligible": 1, "cert_visible_rows": 1})
    exfil = NS(DEFAULT_CONFIG={}, eligibility=lambda *a: {
        "missing_columns": ("resp_bytes",), "rows_total": 1,
    })
    detectors = {"beacon": beacon, "aws": aws, "ssl": ssl, "exfil": exfil}
    detector_plan = runner.RunPlan(detectors, list(detectors), [*detectors, "scan"], {}, {})
    frame = pd.DataFrame([{"ts": 1}])
    logs = {"conn*.log*": frame, "ssl*.log*": frame, "*.json*": frame}
    intent = SyslogIntent(ConfiguredSyslogMode(SyslogMode.OFF, False),
                          SyslogMode.OFF, False, False, True, True, True, None, ())
    optional_plan = runner.RunPlan({"optional": NS(IN_DEFAULT_HUNT=False)}, [], [], {}, {})
    calls = {
        "_zero_window_coverage_notes": lambda: runner._zero_window_coverage_notes(
            loader.LoadResult({"*.log*": frame}, {"*.log*": 0},
                              coverage={"*.log*": loader.SourceCoverage(5, None)}), plan),
        "_permission_skip_notes": lambda: runner._permission_skip_notes(
            loader.LoadResult({}, {}, permission_skips={"*.log*": loader.PermissionSkipInfo(2, 1, (path / "messages",))}), plan),
        "_directory_skip_notes": lambda: runner._directory_skip_notes(denial_plan),
        "_discovery_coverage_lines": lambda: runner._discovery_coverage_lines(
            discovery, plan, {"syslog_dir": [path]}),
        "_unselected_retained_lines": lambda: runner._unselected_retained_lines(
            NS(inventory=NS(root_facts=lambda: [unreadable])), plan, empty_load),
        "_unowned_directory_skip_lines": lambda: runner._unowned_directory_skip_lines(
            denial_plan, {"syslog_dir": [path]}),
        "_rotation_skip_notes": lambda: runner._rotation_skip_notes(loader.LoadResult(
            {}, {}, rotation_skips={"*.log*": loader.RotationSkipInfo(2, 1, False)}), plan),
        "_syslog_provider_note": lambda: runner._syslog_provider_note(
            SyslogProviderDecision(SyslogProvider.OFF, SyslogDecisionReason.CONFIGURED_OFF), intent, plan),
        "_dns_nudge": lambda: runner._dns_nudge(["dnsmasq_dns"]),
        "_default_opt_in_note": lambda: runner._default_opt_in_note(
            optional_plan, runner.DetectorSelection(optional_plan.detectors, [], {}, used_default=True), "default"),
        "_format_dnsblock_summary_notes": _dnsblock_notes,
        "_format_auth_summary_notes": _auth_notes,
        "_aws_below_floor_note": lambda: runner._aws_below_floor_note(detector_plan, logs, {}),
        "_aws_window_note": lambda: runner._aws_window_note(detector_plan),
        "_aws_no_interactive_note": lambda: runner._aws_no_interactive_note(
            detector_plan, logs, cloudtrail_narrowed=True),
        "_ssl_eligibility_notes": lambda: runner._ssl_eligibility_notes(detector_plan, logs, []),
        "_exfil_eligibility_notes": lambda: runner._exfil_eligibility_notes(detector_plan, logs, [], {}),
        "_beacon_eligibility_notes": lambda: runner._beacon_eligibility_notes(detector_plan, logs, []),
        "_beacon_min_connections_note": lambda: runner._beacon_min_connections_note(detector_plan, {}),
        "_beacon_non_established_note": lambda: runner._beacon_non_established_note(detector_plan, logs),
        "_beacon_span_note": lambda: runner._beacon_span_note(detector_plan, logs, timedelta(days=1)),
        "_home_net_note": lambda: runner._home_net_note(detector_plan, {}, ["192.0.2.0/24"]),
        "_source_overlap_notes": lambda: runner._source_overlap_notes(
            {"zeek_dir": [path], "syslog_dir": [path]},
            replace(plan, needed_logs={"conn*.log*": "zeek_dir", "*.log*": "syslog_dir"})),
    }
    return calls[name]()


@pytest.mark.parametrize("name,kinds,provenance", CASES, ids=[c[0] for c in CASES])
def test_composer_outputs_carry_the_declared_metadata(name, kinds, provenance, tmp_path):
    emitted = _emit(name, tmp_path)
    notes = emitted if isinstance(emitted, list) else [emitted]
    assert notes and all(isinstance(note, runner.Note) for note in notes)
    assert {note.kind for note in notes} == kinds
    assert {note.provenance for note in notes} == {provenance}
    assert all(note.kind in KINDS and isinstance(note.text, str) and note.text for note in notes)


def test_empty_and_defensive_composers_keep_silent_results():
    plan = runner.RunPlan({}, [], [], {}, {})
    assert runner._permission_skip_notes(loader.LoadResult({}, {}), plan) == []
    assert runner._directory_skip_notes(plan) == []
    assert runner._rotation_skip_notes(loader.LoadResult({}, {}), plan) == []
    assert runner._aws_below_floor_note(plan, {}, {}) is None
    assert runner._aws_window_note(plan) is None
    assert runner._aws_no_interactive_note(plan, {}, cloudtrail_narrowed=False) is None
    assert runner._beacon_eligibility_notes(plan, {}, []) == []
    assert runner._exfil_eligibility_notes(plan, {}, [], {}) == []
    assert runner._ssl_eligibility_notes(plan, {}, []) == []
    assert runner._dns_nudge(["zeek_dns"]) is None
