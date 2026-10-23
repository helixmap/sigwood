"""Keep runner collaborators replaceable through the importable facade.

Runner and loader internals are excluded from the supported detector API.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import importlib
import inspect
import json
from pathlib import Path
import sys

import pytest

import sigwood.runner as runner
import sigwood.cli as cli


_ROOT = Path(__file__).resolve().parents[1]


def _import_violations(source: str, relative: str) -> list[str]:
    path = Path(relative)
    parts = path.parts
    internal = '_runner' in parts
    facade = path.as_posix() == 'sigwood/runner.py'
    errors = []

    class Policy(ast.NodeVisitor):
        depth = 0

        def visit_FunctionDef(self, node):
            self.depth += 1
            self.generic_visit(node)
            self.depth -= 1

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Import(self, node):
            for alias in node.names:
                if alias.name == 'sigwood._runner' or alias.name.startswith('sigwood._runner.'):
                    if not facade:
                        errors.append(f'{relative}:{node.lineno}: package import outside facade')

        def visit_ImportFrom(self, node):
            if node.level:
                base = list(parts[:-node.level])
                module = '.'.join(base + ((node.module or '').split('.') if node.module else []))
            else:
                module = node.module or ''
            reaches_package = module == 'sigwood._runner' or module.startswith('sigwood._runner.')
            reaches_package |= module == 'sigwood' and any(a.name == '_runner' for a in node.names)
            if reaches_package and not facade and not (internal and node.level):
                errors.append(f'{relative}:{node.lineno}: package import outside facade')
            binds_facade = module == 'sigwood.runner' or (
                module == 'sigwood' and any(a.name == 'runner' for a in node.names))
            if internal and not self.depth and binds_facade:
                errors.append(f'{relative}:{node.lineno}: facade name bound before call time')

    Policy().visit(ast.parse(source))
    return errors


def test_runner_module_is_not_shadowed_by_a_package():
    assert not (_ROOT / 'sigwood/runner').exists()
    assert Path(runner.__file__).name == 'runner.py'
    assert (_ROOT / 'sigwood/_runner/__init__.py').is_file()


def test_runner_import_policy():
    errors = []
    for path in sorted((_ROOT / 'sigwood').rglob('*.py')):
        errors.extend(_import_violations(path.read_text(), path.relative_to(_ROOT).as_posix()))
    assert not errors, '\n'.join(errors)


_FORBIDDEN_IMPORTS = [
    ('sigwood/cli.py', 'import sigwood._runner'),
    ('sigwood/cli.py', 'import sigwood._runner as implementation'),
    ('sigwood/outputs/text.py', 'import sigwood._runner.graph'),
    ('sigwood/outputs/text.py', 'import sigwood._runner.graph as implementation'),
    ('sigwood/cli.py', 'from sigwood import _runner'),
    ('sigwood/cli.py', 'from sigwood import _runner as implementation'),
    ('sigwood/cli.py', 'from sigwood._runner import graph'),
    ('sigwood/cli.py', 'from sigwood._runner import graph as implementation'),
    ('sigwood/cli.py', 'from sigwood._runner.graph import build'),
    ('sigwood/cli.py', 'from sigwood._runner.graph import build as implementation'),
    ('sigwood/cli.py', 'from . import _runner'),
    ('sigwood/outputs/text.py', 'from .._runner.graph import build'),
    ('sigwood/_runner/graph.py', 'from sigwood.runner import run'),
    ('sigwood/_runner/graph.py', 'from sigwood.runner import run as implementation'),
    ('sigwood/_runner/graph.py', 'from sigwood import runner'),
    ('sigwood/_runner/graph.py', 'from sigwood import runner as facade'),
    ('sigwood/_runner/nested/graph.py', 'from ...runner import run'),
]


@pytest.mark.parametrize('relative,source', _FORBIDDEN_IMPORTS)
def test_runner_import_policy_rejects_early_or_external_bindings(tmp_path, relative, source):
    module = tmp_path / relative
    module.parent.mkdir(parents=True)
    module.write_text(source + '\n')
    assert _import_violations(module.read_text(), relative)


@pytest.mark.parametrize('relative,source', [
    ('sigwood/runner.py', 'from sigwood._runner.graph import build'),
    ('sigwood/_runner/graph.py', 'import sigwood.runner as runner\ndef build():\n return runner.run()'),
    ('sigwood/_runner/graph.py', 'def build():\n from sigwood.runner import run\n return run()'),
    ('sigwood/_runner/graph.py', 'def build():\n from sigwood import runner\n return runner.run()'),
    ('sigwood/_runner/graph.py', 'from . import planning'),
    ('sigwood/_runner/nested/graph.py', 'from ..planning import build'),
])
def test_runner_import_policy_allows_call_time_and_internal_imports(relative, source):
    assert not _import_violations(source, relative)


def test_runner_callable_surface_and_signature():
    assert {name for name, value in vars(runner).items() if callable(value)} == _CALLABLES
    assert str(inspect.signature(runner.run)) == _RUN_SIGNATURE


_SEAMS = [
    '_arbitrate_cross_feed_syslog', '_build_output_handler', '_confirm_era_work',
    '_confirm_large_dataset', '_detectors_pkg', '_dry_run_preview', '_permission_skip_notes',
    '_plan_and_load', '_positional_allowlist_mask', '_prepare_detector_context',
    '_resolve_run_windows', '_run_era_harness', '_stream_isatty', '_suppression_sink',
    'build_run_plan', 'discover_detectors', 'liveness', 'probe_journal',
    'resolve_graph_source', 'resolve_home_net', 'run', 'run_digest', 'run_era',
    'run_graph', 'select_detectors',
]


def _inputs(root: Path):
    zeek = root / 'zeek'
    zeek.mkdir()
    rows = [{'_path': 'conn', 'ts': 1780315200 + i, 'uid': f'CFACADE{i}',
             'id.orig_h': '192.168.1.37', 'id.resp_h': '198.51.100.20',
             'id.orig_p': 50000 + i, 'id.resp_p': 443, 'proto': 'tcp',
             'duration': 1.0, 'orig_bytes': 128, 'resp_bytes': 64,
             'conn_state': 'SF'} for i in range(4)]
    (zeek / 'conn.log').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    flat = root / 'flat'
    flat.mkdir()
    (flat / 'system.log').write_text(
        '2026-06-01T12:00:00Z host.example app: original message\n'
        '2026-06-01T12:00:01Z host.example app: second message\n')
    (zeek / 'syslog.log').write_text(json.dumps({
        '_path': 'syslog', 'ts': 1780315200, 'uid': 'CSYSLOG',
        'id.orig_h': '192.0.2.10', 'id.orig_p': 50001,
        'id.resp_h': '198.51.100.20', 'id.resp_p': 514, 'proto': 'udp',
        'facility': 'DAEMON', 'severity': 'INFO',
        'message': '2026-06-01T12:00:02Z host.example app: carried twice',
    }) + '\n')
    pihole = root / 'pihole'
    pihole.mkdir()
    (pihole / 'pihole.log').write_text(''.join(
        f'Jun {day:2d} 12:00:00 dnsmasq[1]: query[A] ads.example.com from 192.0.2.10\n'
        f'Jun {day:2d} 12:00:01 dnsmasq[1]: gravity blocked ads.example.com is 0.0.0.0\n'
        for day in range(1, 29)))
    archive = root / 'archive'
    dated = archive / '2026-06-01'
    dated.mkdir(parents=True)
    (dated / 'conn.log').write_bytes((zeek / 'conn.log').read_bytes())
    config = root / 'config.toml'
    config.write_text(
        '[sigwood]\nroot = ' + json.dumps(str(root)) + '\n'
        'zeek_dir = ' + json.dumps(str(zeek)) + '\n'
        'syslog_dir = ' + json.dumps(str(flat)) + '\n'
        'pihole_dir = ' + json.dumps(str(pihole)) + '\n'
        'syslog_source = "files"\ndefault_window = "all"\nwarn_above = 1\n'
        '[detectors.beacon]\nmin_connections = 1\n')
    return config, zeek, flat, pihole, archive


@pytest.mark.parametrize('seam', _SEAMS, ids=_SEAMS)
def test_facade_interception(seam, tmp_path, monkeypatch, capsys, request):
    config, zeek, flat, pihole, archive = _inputs(tmp_path)
    output = tmp_path / 'report.json'
    calls = []
    original = getattr(runner, seam)
    if seam == '_detectors_pkg':
        package = tmp_path / 'facade_canary_detectors'
        package.mkdir()
        (package / '__init__.py').write_text('')
        (package / 'witness.py').write_text(
            'DETECTOR_NAME="witness"\nSTATUS="available"\nIN_DEFAULT_HUNT=True\n'
            'REQUIRED_LOGS=[{"source":"zeek_dir","pattern":"conn*.log*"}]\n'
            'OPTIONAL_LOGS=[]\nDEFAULT_CONFIG={}\ndef run(context): return []\n')
        monkeypatch.syspath_prepend(str(tmp_path))
        for name in tuple(sys.modules):
            if name == 'facade_canary_detectors' or name.startswith('facade_canary_detectors.'):
                monkeypatch.delitem(sys.modules, name)
        importlib.invalidate_caches()
        monkeypatch.setattr(runner, seam, importlib.import_module('facade_canary_detectors'))
        def clear_package():
            for name in tuple(sys.modules):
                if name == 'facade_canary_detectors' or name.startswith('facade_canary_detectors.'):
                    sys.modules.pop(name, None)
        request.addfinalizer(clear_package)
    elif seam == 'liveness':
        @contextmanager
        def spy(*args, **kwargs):
            calls.append('enter')
            with original(*args, **kwargs) as line:
                yield line
            calls.append('exit')
        monkeypatch.setattr(runner, seam, spy)
    else:
        def spy(*args, **kwargs):
            calls.append(True)
            return original(*args, **kwargs)
        monkeypatch.setattr(runner, seam, spy)

    args = ['hunt', '--detect=beacon', '--format=json', '--out=' + str(output)]
    if seam in ('_confirm_era_work', '_run_era_harness', 'run_era'):
        args = ['era', str(archive), '--out=' + str(tmp_path / 'era.txt')]
    elif seam in ('resolve_graph_source', 'run_graph'):
        args = ['graph', 'conn', '--out=' + str(tmp_path / 'graph.html')]
    elif seam == 'run_digest':
        args = ['digest', str(zeek / 'conn.log'), '--out=' + str(tmp_path / 'digest.txt')]
    elif seam in ('_dry_run_preview', '_resolve_run_windows'):
        args = ['hunt', '--detect=beacon', '--zeek-dir=' + str(zeek), '--dry-run']
    elif seam == 'probe_journal':
        executable = tmp_path / 'bin' / 'journalctl'
        executable.parent.mkdir()
        executable.write_text(f'#!{sys.executable}\nimport json\nprint(json.dumps({{"__REALTIME_TIMESTAMP":"1780315200000000","MESSAGE":"message","_HOSTNAME":"host.example"}}))\n')
        executable.chmod(0o700)
        monkeypatch.setenv('PATH', str(executable.parent))
        args = ['hunt', '--detect=syslog', '--syslog-source=journal', '--dry-run']
    elif seam == '_positional_allowlist_mask':
        args = ['dnsblock', str(pihole), '--format=json', '--out=' + str(output)]
    elif seam == '_suppression_sink':
        from sigwood.detectors import syslog, syslog_preparation
        # Tiny inputs stay on the prepared route for this interception witness.
        monkeypatch.setattr(syslog_preparation, 'SMALL_INPUT_BYTES', 0)
        monkeypatch.setattr(syslog_preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
        real_syslog = syslog.run
        prepared = []
        def observe(context, _prepared=None):
            prepared.append(_prepared is not None)
            return real_syslog(context, _prepared=_prepared)
        monkeypatch.setattr(syslog, 'run', observe)
        args = ['syslog', str(flat / 'system.log'), '--format=json', '--out=' + str(output)]
    elif seam == '_arbitrate_cross_feed_syslog':
        args = ['syslog', '--format=json', '--out=' + str(output)]
    elif seam == '_detectors_pkg':
        args = ['hunt', '--detect=default', '--format=json', '--out=' + str(output)]
    elif seam == '_stream_isatty':
        args = ['hunt', '--detect=beacon', '--out=-']
    elif seam == '_permission_skip_notes':
        blocked = zeek / 'conn.log.1'
        blocked.write_bytes((zeek / 'conn.log').read_bytes())
        actual_open = Path.open
        def open_path(path, *args, **kwargs):
            if path == blocked:
                raise PermissionError(13, 'permission denied', str(path))
            return actual_open(path, *args, **kwargs)
        monkeypatch.setattr(Path, 'open', open_path)

    invocation = [*args, '--config=' + str(config), '-y']
    request.node.user_properties.append(('cli_argv', json.dumps(invocation)))
    cli.main(invocation)
    if seam == '_detectors_pkg':
        observed = json.loads(output.read_text())['run_summary']['detectors_run']
        assert 'witness' in observed, f'facade collaborator was bypassed: {seam}'
    else:
        assert calls, f'facade collaborator was bypassed: {seam}'
        if seam == 'liveness':
            assert calls.count('enter') == calls.count('exit')
        if seam == '_suppression_sink':
            assert prepared == [True]
    captured = capsys.readouterr()
    assert 'Traceback' not in captured.err
    if output.exists():
        report = json.loads(output.read_text())
        assert isinstance(report['findings'], list)
        if seam == '_permission_skip_notes':
            assert any('permission denied' in note for note in report['run_summary']['notes'])
        if seam == '_arbitrate_cross_feed_syslog':
            assert any('kept the local rows' in note for note in report['run_summary']['notes'])


_CALLABLES = {'Any',
 'Note',
 'flatten_notes',
 'AvailabilityState',
 'Callable',
 'Collection',
 'Counter',
 'CoverageDecision',
 'CoverageDecisionReason',
 'CoverageLane',
 'Declined',
 'DetectorContext',
 'DetectorSelection',
 'DigestEmpty',
 'DirectorySkipInfo',
 'DiscoveryFact',
 'DiscoveryFactKind',
 'DnsblockCalibrationBatch',
 'DualWindow',
 'EraHarnessReceipt',
 'EraOracleReceipt',
 'ExitStack',
 'ExportAborted',
 'ExportAvailability',
 'FileOutcomeKind',
 'FileSpan',
 'Finding',
 'GraphEmpty',
 'GraphKindSpec',
 'GraphSourceUnreadable',
 'Iterator',
 'JournalCaptureOutcome',
 'Mapping',
 'OutputHandler',
 'Path',
 'PositionalMask',
 'Preparation',
 'PreparedPopulation',
 'PreparedState',
 'Reporter',
 'ResolvedSources',
 'RootFact',
 'RootFactKind',
 'RunPlan',
 'RunSummary',
 'Sequence',
 'SyslogDecisionReason',
 'SyslogIntent',
 'SyslogMode',
 'SyslogProbeDecision',
 'SyslogProvider',
 'SyslogProviderDecision',
 '_DryRunPreview',
 '_FamilyPreview',
 '_LoadedPlan',
 '_PopulationPreparation',
 '_PreparationHost',
 '_RunWindows',
 '_any_input_yields_files',
 '_arbitrate_cross_feed_syslog',
 '_as_path_list',
 '_aws_below_floor_note',
 '_aws_no_interactive_note',
 '_aws_window_note',
 '_beacon_eligibility_notes',
 '_beacon_min_connections_note',
 '_beacon_non_established_note',
 '_beacon_span_note',
 '_bounded_warning_rider',
 '_build_dual_window',
 '_build_output_handler',
 '_check_required_logs',
 '_claim_needed_log',
 '_compact_path_list',
 '_compute_histogram',
 '_confirm_era_work',
 '_confirm_large_dataset',
 '_declared_source_patterns',
 '_default_opt_in_note',
 '_default_opt_in_remainder',
 '_denial_owned_keys',
 '_derive_data_sources',
 '_detector_token',
 '_directory_denial_reason',
 '_directory_skip_notes',
 '_discovery_coverage_lines',
 '_discovery_liveness',
 '_dns_nudge',
 '_dnsblock_cap_note',
 '_dry_run_preview',
 '_dry_syslog_display',
 '_emit_inter_card_separator',
 '_emit_syslog_decision_warnings',
 '_emit_syslog_skip_diagnostic',
 '_era_closure_config',
 '_era_horizon_abstaining_cards',
 '_era_warning_class',
 '_estderr',
 '_exfil_eligibility_notes',
 '_explicit_window_text',
 '_failure_reason',
 '_family_policy_text',
 '_finish_populations',
 '_format_auth_summary_notes',
 '_format_dnsblock_summary_notes',
 '_graph_contributing_file_meta',
 '_graph_date_dir_window',
 '_graph_hunt_hint',
 '_graph_source_label',
 '_home_net_note',
 '_is_optional_satisfiable',
 '_layout_policy_lines',
 '_merge_facts',
 '_merge_suppression',
 '_not_found_reason',
 '_pack_dnsblock_calibration_work',
 '_pattern_human_label',
 '_permission_denied_run_error',
 '_permission_skip_notes',
 '_plan_and_load',
 '_population_interval',
 '_population_load_maps',
 '_positional_allowlist_mask',
 '_preparation_cause',
 '_prepare_detector_context',
 '_prepare_dnsblock_calibration_batch',
 '_prepare_populations',
 '_print_dry_run',
 '_print_family_block',
 '_print_family_preview',
 '_qualify_unsearched',
 '_record_preparation_disposition',
 '_recover_populations',
 '_relative_to',
 '_render_blob_for_path',
 '_render_coverage_fact',
 '_render_directory_skips',
 '_render_root_fact',
 '_report_basename',
 '_resolve_fold_dual_window',
 '_resolve_run_windows',
 '_root_fact_lines',
 '_rotation_fallback_line',
 '_rotation_fallback_lines',
 '_rotation_skip_notes',
 '_run_analyze',
 '_run_declared',
 '_run_digest',
 '_run_era_harness',
 '_run_era_identity_oracle',
 '_run_era_oracle_measurement',
 '_run_era_resource_measurement',
 '_run_graph',
 '_safe_real',
 '_select_coverage_lane',
 '_shared_candidate_lines',
 '_size_text',
 '_source_dirs_for_provider',
 '_source_overlap_notes',
 '_spec_tokens',
 '_ssl_eligibility_notes',
 '_ssl_facts',
 '_ssl_visibility_line',
 '_ssl_zero_findings_line',
 '_status_entry_display',
 '_stream_isatty',
 '_suppression_contribution',
 '_suppression_pct',
 '_suppression_sink',
 '_syslog_provider_note',
 '_ts_confidence',
 '_unowned_directory_skip_lines',
 '_unselected_retained_lines',
 '_warn_above',
 '_warn_skipped',
 '_warn_skips',
 '_write_dnsblock_evidence_payload',
 '_write_dnsblock_preflight_artifact',
 '_write_dnsblock_preflight_progress',
 '_zero_window_coverage_notes',
 'arbitrate_syslog_capture',
 'arbitrate_syslog_probe',
 'asdict',
 'build_run_plan',
 'compact_home',
 'contextmanager',
 'cursor_visible',
 'dataclass',
 'date',
 'datetime',
 'default_window_advisory',
 'detector_disclosure_lines',
 'discover_detectors',
 'field',
 'fmt_compact_span',
 'fmt_timestamp',
 'fmt_window',
 'get_detector_config',
 'group_skips',
 'hidden_cursor',
 'human_bytes',
 'liveness',
 'nullcontext',
 'parse_window_span',
 'phase_separator',
 'plural',
 'private_mkdir',
 'private_open',
 'private_write_text',
 'probe_journal',
 'replace',
 'resolve_analyze_sources',
 'resolve_detect',
 'resolve_digest_source',
 'resolve_graph_source',
 'resolve_home_net',
 'run',
 'run_digest',
 'run_era',
 'run_graph',
 'select_detectors',
 'set_display_utc',
 'set_narration_enabled',
 'strip_control',
 'syslog_lane_detectors',
 'timedelta',
 'timezone',
 'to_display_timezone',
 'unique_path',
 'validate_table_sections'}
_RUN_SIGNATURE = "(config: 'dict[str, Any]', detect: 'str | None' = None, zeek_dir: 'str | Path | Sequence[str | Path] | None' = None, syslog_dir: 'str | Path | Sequence[str | Path] | None' = None, pihole_dir: 'str | Path | Sequence[str | Path] | None' = None, cloudtrail_dir: 'str | Path | Sequence[str | Path] | None' = None, since: 'datetime | None' = None, until: 'datetime | None' = None, output_format: 'str' = 'text', output_dir: 'Path | None' = None, verbose_level: 'int' = 0, dry_run: 'bool' = False, no_allowlist: 'bool' = False, load_all: 'bool' = False, skip_confirm: 'bool' = False, output_file: 'Path | None' = None, scope: 'frozenset[str] | None' = None, quiet: 'bool' = False, use_utc: 'bool' = False, syslog_source: 'object | None' = None, _detector_selection: 'DetectorSelection | None' = None, _dnsblock_preflight_path: 'Path | None' = None, invocation: 'str | None' = None, *, discovery: 'Any | None' = None, recursive_retry: 'str | None' = None) -> 'int'"
