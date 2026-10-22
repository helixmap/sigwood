"""Transactional indexing preserves online templates and canonical ordinals."""
from contextlib import nullcontext
from dataclasses import replace
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from sigwood.common.loader import DecodedChunk, FoldDelta, PositionalMask
from sigwood.common.loader.fold import FoldAbstention
from sigwood.detectors import syslog, syslog_preparation as preparation


@pytest.fixture(autouse=True)
def keep_small_route_out_of_preparation_fixtures(monkeypatch):
    # Existing tiny fixtures verify the prepared route's internals. The measured
    # size gate has its own test below.
    monkeypatch.setattr(preparation, 'SMALL_INPUT_BYTES', 0)


def host():
    return SimpleNamespace(timer=lambda _: nullcontext(), mask=lambda df: PositionalMask((True,) * len(df)))


def facts():
    return preparation._Facts(syslog._new_miner(0.5, 4, True, syslog._template_masks()))


def test_measured_small_input_declines_before_indexing(monkeypatch):
    from sigwood.common.finding import Declined, DeclineReason
    monkeypatch.setattr(preparation, 'SMALL_INPUT_BYTES', 14 * 1024 * 1024)
    def fold(*args, **kwargs):
        raise AssertionError('indexing must not start for a proven small input')
    h = SimpleNamespace(sibling_needs_frame=False, exact_window=True,
                        local_files=True, upper_bound_bytes=14 * 1024 * 1024,
                        config={}, fold=fold)
    assert preparation.prepare(h) == Declined(DeclineReason.INELIGIBLE, 'small input')


@pytest.mark.parametrize('bound', [14 * 1024 * 1024 + 1, None])
def test_above_cutoff_or_unknown_bound_reaches_prepared_scan(monkeypatch, bound):
    monkeypatch.setattr(preparation, 'SMALL_INPUT_BYTES', 14 * 1024 * 1024)

    class ReachedFold(Exception):
        pass

    def fold(*args, **kwargs):
        raise ReachedFold

    h = SimpleNamespace(sibling_needs_frame=False, exact_window=True,
                        local_files=True, upper_bound_bytes=bound, config={},
                        report_window=None, fold=fold, mask=lambda frame: frame)
    with pytest.raises(ReachedFold):
        preparation.prepare(h)


def chunk(messages, *, start=0, report=None):
    frame = pd.DataFrame({'ts': [1.] * len(messages), 'host': ['host.example'] * len(messages),
                          'program': ['service'] * len(messages), 'raw': messages, 'message': messages})
    return DecodedChunk(frame, 10 * len(messages), tuple(report or [True] * len(messages)),
                        (False,) * len(messages), start, file_key='fixture')


def test_index_matches_ordinary_online_assignments_and_exclusion_ordinals():
    state = facts()
    sink = preparation.templates_sink(host(), state)
    value = chunk(['alpha beta one', 'excluded message', 'alpha beta two', 'suppressed message'])
    value = replace(value, report_mask=(True, False, True, True))
    delta = sink.consume(sink.seed_file(), value, PositionalMask((True, True, True, False)))
    sink.commit_file(state, delta)
    ids, versions = state.arrays['fixture']
    ordinary = syslog._run_drain3(value.frame.iloc[[0, 2]], 0.5, 4, True)
    assert ids.tolist() == [ordinary.template_id.iloc[0], -1, ordinary.template_id.iloc[1], -1]
    assert [state.texts[int(v)] for v in versions if v >= 0] == ordinary.template_str.tolist()
    assert state.hosts == {'host.example': 2}
    assert state.arbitration == {'host.example'}
    assert ids.dtype == versions.dtype == np.int32


def test_nan_host_arbitration_uses_runner_string_identity():
    state = facts()
    sink = preparation.templates_sink(host(), state)
    value = chunk(['event with missing host'])
    value.frame['host'] = np.nan
    delta = sink.consume(sink.seed_file(), value, PositionalMask((True,)))
    assert delta.value.arbitration == {'nan'}
    assert delta.value.hosts == {'unknown': 1}


def test_abort_restores_mutation_new_cluster_and_online_text_reuse():
    state = facts()
    state.mine('alpha beta one')
    before = state.miner.drain.id_to_cluster[1].get_template()
    texts, index = list(state.texts), dict(state.index)
    sink = preparation.templates_sink(host(), state)
    delta = sink.seed_file()
    sink.consume(delta, chunk(['alpha beta two', 'unrelated new content longer', 'alpha beta three']),
                 PositionalMask((True, True, True)))
    sink.abort_file(state)
    assert state.miner.drain.id_to_cluster[1].get_template() == before
    assert len(state.miner.drain.id_to_cluster) == 1
    assert state.texts == texts and state.index == index
    assert not state.arrays and not state.counts and not state.hosts


@pytest.mark.parametrize('bad_position', [1, 2])
def test_multifile_executor_rolls_back_syslog_middle_or_last(tmp_path, bad_position):
    from sigwood.common import loader
    paths = [tmp_path / f'{i}.log' for i in range(3)]
    for path in paths:
        path.write_text('snapshot\n')
    messages = [['alpha beta one'], ['alpha beta two'], ['distinct final message']]
    good_messages = [message for i, batch in enumerate(messages)
                     if i != bad_position for message in batch]
    state = facts()
    sink = preparation.templates_sink(host(), state)

    def chunks(item):
        index = paths.index(item.path)
        yield replace(chunk(messages[index]), file_key='')
        if index == bad_position:
            yield replace(chunk(['brand new cluster created before read failure'], start=1),
                          file_key='')
            raise OSError('corrupt tail')

    result = loader.execute_sink_plan(
        loader.build_source_snapshot(paths, 'flat'), loader.SinkPlan((sink,)), chunks)
    assert result.file_errors == (f'{bad_position}.log: corrupt tail',)
    assert result.frame.message.tolist() == good_messages
    ordinary = syslog._run_drain3(chunk(good_messages).frame, 0.5, 4, True)
    assert set(state.arrays) == {str(p.resolve()) for i, p in enumerate(paths)
                                 if i != bad_position}
    ids = [int(tid) for pair in state.arrays.values() for tid in pair[0]]
    texts = [state.texts[int(version)] for pair in state.arrays.values() for version in pair[1]]
    assert ids == ordinary.template_id.tolist()
    assert texts == ordinary.template_str.tolist()
    assert dict(state.counts) == ordinary.template_id.value_counts().to_dict()
    assert sum(state.hosts.values()) == len(good_messages)
    assert len(state.miner.drain.id_to_cluster) == len(set(ids))


def test_runner_oversize_prepared_matches_ordinary(tmp_path, monkeypatch):
    import json
    from sigwood import runner
    from sigwood.common.loader.limits import MAX_LOGICAL_RECORD_BYTES
    from tests.syslog_shape_cases import fixed_clock
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    path = tmp_path / 'source.log'
    path.write_text('x' * (MAX_LOGICAL_RECORD_BYTES + 1) + '\n'
                    '2020-01-01T00:00:00Z host.example app: valid message\n')
    observed = []
    original_run = syslog.run

    def run(context, _prepared=None):
        observed.append(_prepared is not None)
        if _prepared is not None:
            assert sum(_prepared.freq.values()) == 1
        return original_run(context, _prepared)

    monkeypatch.setattr(syslog, 'run', run)
    outputs = []
    with fixed_clock():
        for enabled in (True, False):
            if not enabled:
                monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
            target = tmp_path / 'report.json'
            assert runner.run(
                config={'sigwood': {'detect': 'syslog'}}, detect='syslog', syslog_dir=path,
                load_all=True, no_allowlist=True, quiet=True, skip_confirm=True,
                output_format='json', output_file=target) == 0
            value = json.loads(target.read_text())
            outputs.append((value['findings'], value['run_summary']))
    assert observed == [True, False]
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize('bad_position', [1, 2])
def test_corrupt_gzip_rotation_matches_clean_prepared_run(tmp_path, monkeypatch, capsys, bad_position):
    import gzip
    from sigwood import runner
    from sigwood.common.loader import fold
    from tests.syslog_shape_cases import fixed_clock, exact
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    monkeypatch.setattr(fold, 'MAX_CHUNK_ROWS', 256)
    paths = [tmp_path / f'{i}.log' for i in range(3)]
    paths[bad_position] = paths[bad_position].with_suffix('.log.gz')
    for i, path in enumerate(paths):
        body = f'2020-01-01T00:00:00Z host.example app: distinct rotation {i}\n'
        if i == bad_position:
            path.write_bytes(gzip.compress((body * 10000).encode())[:-5])
        else:
            path.write_text(body)
    consumed_bad = []
    original_sink = preparation.templates_sink

    def sink(*args):
        value = original_sink(*args)
        consume = value.consume
        def observe(delta, decoded, mask):
            if decoded.file_key == str(paths[bad_position].resolve()):
                consumed_bad.append(len(decoded.frame))
            return consume(delta, decoded, mask)
        return replace(value, consume=observe)

    monkeypatch.setattr(preparation, 'templates_sink', sink)
    outcomes = []
    original_run = syslog.run
    def run(context, _prepared=None):
        assert _prepared is not None
        assert sum(_prepared.freq.values()) == 2
        value = original_run(context, _prepared)
        outcomes.append(exact(value, tmp_path))
        return value
    monkeypatch.setattr(syslog, 'run', run)
    with fixed_clock():
        for inputs in (paths, [p for i, p in enumerate(paths) if i != bad_position]):
            assert runner.run(
                config={'sigwood': {'detect': 'syslog'}}, detect='syslog', syslog_dir=inputs,
                load_all=True, no_allowlist=True, quiet=True, skip_confirm=True,
                output_format='json', output_file=tmp_path / 'report.json') == 0
    assert consumed_bad, 'corrupt input must reach the miner before its read failure'
    assert outcomes[0] == outcomes[1]
    assert capsys.readouterr().err.count(paths[bad_position].name) == 1


def test_abort_hook_failure_recovers_with_one_note_and_ordinary_findings(tmp_path, monkeypatch):
    import gzip
    import json
    from sigwood import runner
    from sigwood.common.loader import fold

    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    monkeypatch.setattr(fold, 'MAX_CHUNK_ROWS', 256)
    good = tmp_path / '0.log'
    bad = tmp_path / '1.log.gz'
    good.write_text('2020-01-01T00:00:00Z host.example app: surviving event\n')
    bad.write_bytes(gzip.compress(
        b'2020-01-01T00:00:00Z host.example app: aborted event\n' * 10000)[:-5])
    original_sink = preparation.templates_sink
    aborts = []

    def sink(*args):
        value = original_sink(*args)
        def fail(_state):
            aborts.append(True)
            raise RuntimeError('injected abort-hook failure')
        return replace(value, abort_file=fail)

    monkeypatch.setattr(preparation, 'templates_sink', sink)
    original_run = syslog.run
    def run(context, _prepared=None):
        assert _prepared is None
        return original_run(context)
    monkeypatch.setattr(syslog, 'run', run)
    reports = []
    for enabled in (True, False):
        if not enabled:
            monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
        target = tmp_path / 'report.json'
        assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
            syslog_dir=[good, bad], load_all=True, quiet=True, no_allowlist=True,
            skip_confirm=True, output_format='json', output_file=target) == 0
        data = json.loads(target.read_text())
        assert not data['run_summary']['detectors_failed']
        for finding in data['findings']:
            finding.pop('ts_generated', None)
        notes = data['run_summary']['notes']
        recovery = [n for n in notes if 'prepared load' in n]
        assert len(recovery) == int(enabled)
        if enabled:
            assert 'abort error' in recovery[0]
            assert 'analysis ran on the full frame' in recovery[0]
        reports.append((data['findings'], [n for n in notes if n not in recovery]))
    assert aborts
    assert reports[0] == reports[1]


def test_unknown_file_key_still_fails_admission():
    state = facts()
    state.aborted_files = frozenset({'known-bad'})
    admit = preparation.candidates(state, set())
    assert admit.admit(replace(chunk(['ignored']), file_key='known-bad')).empty
    with pytest.raises(KeyError):
        admit.admit(replace(chunk(['unknown']), file_key='unknown'))


@pytest.mark.parametrize('change_host', [False, True])
def test_file_outcome_mismatch_recovers_before_finish(tmp_path, monkeypatch, change_host):
    import json
    from sigwood import runner
    from sigwood.common import loader
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    source = tmp_path / 'source.log'
    source.write_text('2020-01-01T00:00:00Z host.example app: original\n')
    zeek = tmp_path / 'zeek'
    zeek.mkdir()
    (zeek / 'syslog.log').write_text(''.join(
        json.dumps({'ts': 1577836800., 'host': name, 'app_name': 'app',
                    'message': f'2020-01-01T00:00:00Z {name} app: remote event',
                    'facility': 'USER', 'severity': 'INFO'}) + '\n'
        for name in ('host.example', 'other.example')))
    original_load = loader.load_required_logs
    calls = []
    def load(*args, **kwargs):
        value = original_load(*args, **kwargs)
        calls.append(value)
        if 'syslog.candidates' in value.prepared_status:
            if change_host:
                source.write_text('2020-01-01T00:00:00Z other.example app: replacement\n')
            # Simulate differing transactions with stable file bytes.
            value = replace(value, file_outcomes={
                **value.file_outcomes, '*.log*': loader.FileOutcomes()})
        return value
    monkeypatch.setattr(loader, 'load_required_logs', load)
    original_run = syslog.run
    def run(context, _prepared=None):
        assert _prepared is None
        assert context.logs['*.log*'].host.tolist() == [
            'other.example' if change_host else 'host.example']
        assert context.logs['syslog*.log*'].host.tolist() == [
            'host.example' if change_host else 'other.example']
        return original_run(context)
    monkeypatch.setattr(syslog, 'run', run)
    target = tmp_path / 'result.json'
    assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
                      syslog_dir=source, zeek_dir=zeek, load_all=True, quiet=True, no_allowlist=True,
                      output_format='json', output_file=target) == 0
    summary = json.loads(target.read_text())['run_summary']
    assert not summary['detectors_failed']
    assert sum('committed file set changed' in note for note in summary['notes']) == 1
    assert len(calls) == 3  # pass one, candidate pass, ordinary reload


def test_exclusions_across_chunks_preserve_online_text_and_ordinals():
    state = facts()
    sink = preparation.templates_sink(host(), state)
    first = chunk(['excluded before', 'alpha beta one', 'suppressed boundary'])
    first = replace(first, report_mask=(False, True, True))
    second = chunk(['excluded boundary', 'alpha beta two', 'suppressed after'], start=3)
    second = replace(second, report_mask=(False, True, True))
    delta = sink.consume(sink.seed_file(), first, PositionalMask((True, True, False)))
    delta = sink.consume(delta, second, PositionalMask((True, True, False)))
    sink.commit_file(state, delta)
    ordinary = syslog._run_drain3(
        pd.concat([first.frame.iloc[[1]], second.frame.iloc[[1]]]), 0.5, 4, True)
    ids, versions = state.arrays['fixture']
    assert ids[[0, 2, 3, 5]].tolist() == [-1] * 4
    assert versions[[0, 2, 3, 5]].tolist() == [-1] * 4
    assert ids[[1, 4]].tolist() == ordinary.template_id.tolist()
    admission = preparation.candidates(state, set(ordinary.template_id))
    admitted = pd.concat([admission.admit(first), admission.admit(second)])
    assert admitted.message.tolist() == ['alpha beta one', 'alpha beta two']
    assert admitted.template_str.tolist() == ordinary.template_str.tolist()


@pytest.mark.parametrize('slot', ['pairs', 'hosts', 'arbitration'])
def test_each_identity_container_enforces_distinct_limit(monkeypatch, slot):
    monkeypatch.setattr(preparation, 'MAX_DELTA_IDENTITY_KEYS', 1)
    delta = preparation._File()
    container = getattr(delta, slot)
    one, two = (('host.example', 'service'), ('other.example', 'service')) if slot == 'pairs' else ('host.example', 'other.example')
    delta.retain(container, one)
    previous = delta.identity_bytes
    delta.retain(container, one)
    assert delta.identity_bytes == previous
    with pytest.raises(FoldAbstention, match='identity count'):
        delta.retain(container, two)


def test_all_suppressed_rows_still_enforce_arbitration_identity_cap(monkeypatch):
    monkeypatch.setattr(preparation, 'MAX_DELTA_IDENTITY_KEYS', 1)
    state = facts()
    sink = preparation.templates_sink(host(), state)
    value = chunk(['suppressed one', 'suppressed two'])
    value.frame['host'] = ['one.example', 'two.example']
    delta = sink.seed_file()
    with pytest.raises(FoldAbstention, match='identity count'):
        sink.consume(delta, value, PositionalMask((False, False)))
    assert delta.value.arbitration == {'one.example'}
    assert not delta.value.pairs
    assert not delta.value.hosts
    assert not state.texts
    assert not state.arrays


def test_long_program_is_checked_with_short_host(monkeypatch):
    monkeypatch.setattr(preparation, 'MAX_IDENTITY_KEY_BYTES', 100)
    delta = preparation._File()
    with pytest.raises(FoldAbstention, match='identity key'):
        delta.retain(delta.pairs, ('h', 'p' * 101))


def test_template_id_range(monkeypatch):
    state = facts()
    monkeypatch.setattr(state.miner, 'add_log_message', lambda _: {'cluster_id': 2**31, 'template_mined': 'text'})
    with pytest.raises(FoldAbstention, match='template id range'):
        state.mine('text')


def test_candidates_keep_online_text_and_never_sentinels():
    state = facts()
    sink = preparation.templates_sink(host(), state)
    value = chunk(['normal event', 'rare event unique', 'Linux version skipped'])
    delta = sink.consume(sink.seed_file(), value, PositionalMask((True, True, False)))
    sink.commit_file(state, delta)
    tid = int(state.arrays['fixture'][0][1])
    result = preparation.candidates(state, {tid}).admit(value)
    assert result.message.tolist() == ['rare event unique']
    assert result.template_id.dtype == np.int64


@pytest.mark.parametrize('bounds', [({}, 3), ({'load_all': True}, 3),
    ({'since': '2020-01-02T00:00:00Z'}, 2),
    ({'until': '2020-01-02T00:00:00Z'}, 2),
    ({'since': '2020-01-02T00:00:00Z', 'until': '2020-01-02T00:00:00Z'}, 1)])
def test_historical_runner_window_matches_ordinary(tmp_path, monkeypatch, bounds):
    # Keep this small fixture on the prepared route; density has dedicated pins.
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    from datetime import datetime
    from sigwood import runner
    from tests.syslog_shape_cases import fixed_clock, exact
    options, expected = bounds
    options = {key: datetime.fromisoformat(value.replace('Z', '+00:00')) if isinstance(value, str) else value
               for key, value in options.items()}
    path = tmp_path / 'historical.log'
    path.write_text(''.join(f'2020-01-0{day}T00:00:00Z host.example service: event number {day}\n'
                            for day in range(1, 4)))
    seen = []
    original = syslog.run
    def run(context, _prepared=None):
        result = original(context, _prepared=_prepared)
        seen.append((_prepared, len(context.logs['*.log*']), exact(result, tmp_path)))
        return result
    monkeypatch.setattr(syslog, 'run', run)
    with fixed_clock():
        for prepared in (True, False):
            if not prepared:
                monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
            code = runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
                              syslog_dir=path, no_allowlist=True, quiet=True, skip_confirm=True,
                              output_format='json', output_file=tmp_path / f'{prepared}.json', **options)
            assert code == 0
    assert seen[0][0] is not None
    assert sum(seen[0][0].freq.values()) == expected
    assert seen[1][1] == expected
    assert seen[0][2] == seen[1][2]


def test_empty_candidates_preserve_population_and_noncandidate_endpoints(tmp_path, monkeypatch):
    import json
    from sigwood import runner
    path = tmp_path / 'source.log'
    path.write_text(''.join(
        f'2020-01-0{day}T00:00:00Z host.example service: routine heartbeat\n'
        for day in range(1, 4)))
    seen = []
    original = syslog.run
    def run(context, _prepared=None):
        seen.append((_prepared is not None, len(context.logs['*.log*'])))
        return original(context, _prepared)
    monkeypatch.setattr(syslog, 'run', run)
    reports = []
    for enabled in (True, False):
        if not enabled:
            monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
        target = tmp_path / 'report.json'
        assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
            syslog_dir=path, load_all=True, quiet=True, no_allowlist=True,
            skip_confirm=True, output_format='json', output_file=target) == 0
        data = json.loads(target.read_text())
        summary = data['run_summary']
        assert not summary['detectors_failed']
        assert summary['record_counts'] == {'*.log*': 3}
        assert summary['data_window'] == [
            '2020-01-01T00:00:00+00:00', '2020-01-03T00:00:00+00:00']
        reports.append((data['findings'], summary['notes']))
    assert seen == [(True, 0), (False, 3)]
    assert reports[0] == reports[1]


@pytest.mark.parametrize('quiet', [True, False])
def test_runner_narrates_index_then_load(tmp_path, monkeypatch, quiet):
    from sigwood import runner
    from sigwood.common import loader
    path = tmp_path / 'source.log'
    path.write_text('2020-01-01T00:00:00Z host.example app: one event\n')
    seen = []
    original = loader.progress
    def progress(values, **kwargs):
        seen.append((kwargs.get('desc'), kwargs.get('show_progress')))
        return original(values, **kwargs)
    monkeypatch.setattr(loader, 'progress', progress)
    assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
                      syslog_dir=path, quiet=quiet, no_allowlist=True, skip_confirm=True,
                      output_format='json', output_file=tmp_path / 'report.json') == 0
    assert [desc.split()[0] for desc, _ in seen] == ['indexed', 'loaded']
    assert all(enabled is (not quiet) for _, enabled in seen)


def test_runner_qualifies_repeated_basenames_on_both_passes(tmp_path, monkeypatch):
    from sigwood import runner
    from sigwood.common import loader
    paths = []
    for name in ('host-a', 'host-b'):
        directory = tmp_path / name
        directory.mkdir()
        path = directory / 'messages.log'
        path.write_text(f'2020-01-01T00:00:00Z {name} app: distinct event\n')
        paths.append(path)
    seen = []
    original = loader.progress
    def progress(values, **kwargs):
        seen.append(kwargs.get('desc'))
        return original(values, **kwargs)
    monkeypatch.setattr(loader, 'progress', progress)
    assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
                      syslog_dir=paths, load_all=True, quiet=True,
                      no_allowlist=True, skip_confirm=True,
                      output_format='json', output_file=tmp_path / 'report.json') == 0
    assert seen == ['indexed host-a/messages.log', 'indexed host-b/messages.log',
                    'loaded host-a/messages.log', 'loaded host-b/messages.log']


@pytest.mark.parametrize('case', ['flat', 'corrupt', 'window', 'nan', 'all_nan', 'filtered'])
def test_runner_oracle_inputs_equal_ordinary(tmp_path, monkeypatch, case):
    import json
    from sigwood import runner
    from tests.syslog_shape_cases import prepare as fixture, fixed_clock
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    dispatched = []
    original_run = syslog.run
    def observe(context, _prepared=None):
        dispatched.append(_prepared is not None)
        return original_run(context, _prepared=_prepared)
    monkeypatch.setattr(syslog, 'run', observe)
    with fixed_clock():
        _, _, paths, since, until = fixture(case, tmp_path / 'input')
        outputs = []
        for enabled in (True, False):
            if not enabled:
                monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
            target = tmp_path / 'report.json'
            code = runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
                              syslog_dir=paths, since=since, until=until, load_all=True,
                              no_allowlist=True, quiet=True, skip_confirm=True,
                              output_format='json', output_file=target)
            assert code == 0
            result = json.loads(target.read_text())
            summary = result['run_summary']
            outputs.append((result['findings'], {key: summary[key] for key in (
                'record_counts', 'record_labels', 'data_size_bytes', 'data_window',
                'detectors_run', 'detectors_skipped', 'detectors_failed', 'notes')}))
        assert outputs[0] == outputs[1]
        assert dispatched == [True, False]


def test_prepared_syslog_skips_binary_and_wrong_family_like_ordinary(tmp_path, monkeypatch, capsys):
    import json
    from sigwood import runner
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    good = tmp_path / 'good.log'
    binary = tmp_path / 'binary.log'
    ndjson = tmp_path / 'ndjson.log'
    tsv = tmp_path / 'tsv.log'
    good.write_text('2020-01-01T00:00:00Z host.example app: distinct event\n')
    binary.write_bytes(b'\x00\x01\x02\x00')
    ndjson.write_text('{"ts":1577836800,"message":"not flat syslog"}\n')
    tsv.write_text('#separator \\x09\n#fields\tts\thost\tmessage\n')
    inputs = [good, binary, ndjson, tsv]
    original_run = syslog.run
    dispatched = []
    def run(context, _prepared=None):
        dispatched.append(_prepared is not None)
        return original_run(context, _prepared=_prepared)
    monkeypatch.setattr(syslog, 'run', run)
    reports = []
    for enabled in (True, False):
        if not enabled:
            monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
        assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
                          syslog_dir=inputs, load_all=True, quiet=True,
                          no_allowlist=True, skip_confirm=True,
                          output_format='json', output_file=tmp_path / 'report.json') == 0
        data = json.loads((tmp_path / 'report.json').read_text())
        for finding in data['findings']:
            finding.pop('ts_generated', None)
        summary = data['run_summary']
        reports.append((data['findings'], {key: summary[key] for key in (
            'record_counts', 'record_labels', 'data_window', 'notes')},
            capsys.readouterr().err))
    assert dispatched == [True, False]
    assert reports[0] == reports[1]
    assert reports[0][1]['record_counts'] == {'*.log*': 1}
    assert 'binary.log' in reports[0][2]


def test_prepared_syslog_preserves_rotation_note(tmp_path, monkeypatch):
    import json
    from datetime import datetime, timezone
    from sigwood import runner
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    for index, day in enumerate((10, 8, 2)):
        name = 'syslog.log' if index == 0 else f'syslog.log.{index}'
        (tmp_path / name).write_text(
            f'Jun {day:>2} 12:00:00 host.example app: event {index}\n')
    original_run = syslog.run
    dispatched = []
    def run(context, _prepared=None):
        dispatched.append(_prepared is not None)
        return original_run(context, _prepared=_prepared)
    monkeypatch.setattr(syslog, 'run', run)
    notes = []
    for enabled in (True, False):
        if not enabled:
            monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
        assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
            syslog_dir=tmp_path,
            since=datetime(2026, 6, 5, tzinfo=timezone.utc),
            until=datetime(2026, 6, 9, tzinfo=timezone.utc),
            quiet=True, no_allowlist=True, skip_confirm=True,
            output_format='json', output_file=tmp_path / 'report.json') == 0
        notes.append(json.loads((tmp_path / 'report.json').read_text())['run_summary']['notes'])
    assert dispatched == [True, False]
    assert notes[0] == notes[1]
    assert any('rotation files' in note for note in notes[0])


def test_journal_resolved_window_matches_ordinary(tmp_path, monkeypatch):
    # Keep this small fixture on the prepared route; density has dedicated pins.
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    import json
    import sys
    from datetime import datetime, timezone
    from sigwood import runner
    from sigwood.common.loader import journal
    from tests.syslog_shape_cases import fixed_clock
    script = tmp_path / 'journalctl'
    records = [{'__REALTIME_TIMESTAMP': str(1791979200000000 + i * 1000000),
                'MESSAGE': f'event number {i}', '_HOSTNAME': 'host.example',
                'SYSLOG_IDENTIFIER': 'app'} for i in range(3)]
    script.write_text(f'#!{sys.executable}\nimport json\nfor r in {records!r}: print(json.dumps(r))\n')
    script.chmod(0o700)
    monkeypatch.setattr(journal, 'resolve_journalctl', lambda: str(script))
    original = syslog.PREPARED_POPULATION
    windows, dispatched = [], []
    def prepare(host):
        windows.append(host.report_window.report_interval)
        return original.prepare(host)
    monkeypatch.setattr(syslog, 'PREPARED_POPULATION', replace(original, prepare=prepare))
    run_original = syslog.run
    def run(context, _prepared=None):
        dispatched.append(_prepared)
        return run_original(context, _prepared)
    monkeypatch.setattr(syslog, 'run', run)
    bounds = (datetime(2026, 10, 14, 12, 0, 1, tzinfo=timezone.utc),
              datetime(2026, 10, 14, 12, 0, 2, tzinfo=timezone.utc))
    outputs = []
    with fixed_clock():
        for enabled in (True, False):
            if not enabled:
                monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
            target = tmp_path / 'report.json'
            assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
                syslog_source='journal', since=bounds[0], until=bounds[1],
                quiet=True, no_allowlist=True, skip_confirm=True,
                output_format='json', output_file=target) == 0
            result = json.loads(target.read_text())
            outputs.append((result['findings'], result['run_summary']['record_counts']))
    assert windows == [bounds]
    assert dispatched[0] is not None
    assert outputs[0] == outputs[1]
    assert outputs[0][1] == {'*.log*': 2}
    assert not journal._ACTIVE_CAPTURES


@pytest.mark.parametrize('ending,appendix', [('\n', '2020-01-03T00:00:00Z host.example app: appended\n'),
                                          ('', ' completed\n'), ('', '')])
def test_append_keeps_captured_whole_tail(tmp_path, monkeypatch, ending, appendix):
    # Keep this small fixture on the prepared route; density has dedicated pins.
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    from sigwood import runner
    from tests.syslog_shape_cases import fixed_clock, exact
    path = tmp_path / 'source.log'
    path.write_text('2020-01-01T00:00:00Z host.example app: first\n'
                    '2020-01-02T00:00:00Z host.example app: second' + ending)
    declaration = syslog.PREPARED_POPULATION
    seen = []
    original_run = syslog.run
    def run(context, _prepared=None):
        result = original_run(context, _prepared)
        seen.append((_prepared, exact(result, tmp_path)))
        return result
    monkeypatch.setattr(syslog, 'run', run)
    def prepare(host):
        value = declaration.prepare(host)
        with path.open('a') as stream:
            stream.write(appendix)
        return value
    with fixed_clock():
        monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
        kwargs = dict(config={'sigwood': {'detect': 'syslog'}}, detect='syslog', syslog_dir=path,
                      quiet=True, no_allowlist=True, skip_confirm=True, output_format='json',
                      output_file=tmp_path / 'report.json')
        assert runner.run(**kwargs) == 0
        monkeypatch.setattr(syslog, 'PREPARED_POPULATION', replace(declaration, prepare=prepare))
        assert runner.run(**kwargs) == 0
    assert seen[1][0] is not None
    assert sum(seen[1][0].freq.values()) == 2
    assert seen[0][1] == seen[1][1]


@pytest.mark.parametrize('mutation', ['replacement', 'truncate'])
@pytest.mark.parametrize('fmt', ['json', 'text'])
def test_snapshot_replacement_recovers_before_finish(tmp_path, monkeypatch, mutation, fmt):
    # Keep this small fixture on the prepared route; density has dedicated pins.
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    import json
    from sigwood import runner
    path = tmp_path / 'source.log'
    path.write_text('2020-01-01T00:00:00Z host.example app: original\n')
    declaration = syslog.PREPARED_POPULATION
    def prepare(host):
        value = declaration.prepare(host)
        if mutation == 'replacement':
            replacement = path.with_suffix('.replacement')
            replacement.write_text('2020-01-02T00:00:00Z other.example app: replacement\n')
            replacement.replace(path)
        else:
            path.write_text('')
        def forbidden(*args):
            pytest.fail('recovered admission must not finish')
        return replace(value, finish=forbidden)
    monkeypatch.setattr(syslog, 'PREPARED_POPULATION', replace(declaration, prepare=prepare))
    original_run = syslog.run
    def run(context, _prepared=None):
        assert _prepared is None
        if mutation == 'replacement':
            assert context.logs['*.log*'].host.tolist() == ['other.example']
        else:
            assert context.logs['*.log*'].empty
        return original_run(context)
    monkeypatch.setattr(syslog, 'run', run)
    target = tmp_path / f'report.{fmt}'
    assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog', syslog_dir=path,
                      quiet=True, no_allowlist=True, output_format=fmt, output_file=target) == 0
    if fmt == 'json':
        assert sum('prepared load failed' in note for note in json.loads(target.read_text())['run_summary']['notes']) == 1
    else:
        assert target.read_text().count('prepared load failed') == 1


@pytest.mark.parametrize('local,extra,expected', [
    ({1: 1, 2: 2, 3: 3}, [4] * 10 + [5] * 10, {1, 2}),
    ({1: 2, 2: 3, 3: 4}, [4, 5, 6], {4, 5, 6}),
])
def test_finish_applies_union_percentile_in_both_directions(local, extra, expected):
    from collections import Counter
    state = facts()
    state.counts = Counter(local)
    state.texts = ['online text']
    state.mine = lambda message: (int(message), 0)
    frame = pd.DataFrame({'message': extra, 'host': ['other.example'] * len(extra),
                          'program': ['service'] * len(extra)})
    ctx = SimpleNamespace(logs={'syslog*.log*': frame}, config={'rarity_pct': 50, 'max_count': 3})
    result = preparation.finish(state, host(), ctx, None)
    assert result.rare_ids == expected
    assert all(local.get(tid, 0) <= 3 for tid in result.rare_ids)


def test_template_version_range():
    state = facts()
    state.texts = type('FullTable', (), {'__len__': lambda self: 2**31})()
    state.miner = SimpleNamespace(add_log_message=lambda _: {'cluster_id': 1, 'template_mined': 'new'})
    with pytest.raises(FoldAbstention, match='template version range'):
        state.mine('new')


def test_preparation_facts_released_before_detector_dispatch(tmp_path, monkeypatch):
    # Keep this small fixture on the prepared route; density has dedicated pins.
    monkeypatch.setattr(preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    import weakref
    from sigwood import runner
    references = []
    original_facts = preparation._Facts
    def capture(*args, **kwargs):
        value = original_facts(*args, **kwargs)
        references.append(weakref.ref(value))
        return value
    monkeypatch.setattr(preparation, '_Facts', capture)
    original_run = syslog.run
    def run(context, _prepared=None):
        assert _prepared is not None
        assert references and all(ref() is None for ref in references)
        return original_run(context, _prepared)
    monkeypatch.setattr(syslog, 'run', run)
    path = tmp_path / 'source.log'
    path.write_text('2020-01-01T00:00:00Z host.example service: event\n')
    assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
                      syslog_dir=path, quiet=True, no_allowlist=True, skip_confirm=True,
                      output_format='json', output_file=tmp_path / 'report.json') == 0

@pytest.mark.parametrize('rare_rows,declines', [(59, False), (60, True), (61, True)])
def test_dense_boundary_releases_facts_before_fallback(monkeypatch, rare_rows, declines):
    from collections import Counter
    import weakref
    from sigwood.common.finding import Declined, DeclineReason
    from sigwood.common.loader.types import PreparedState, FileOutcomes
    references = []
    original = preparation._Facts
    def capture(*args, **kwargs):
        value = original(*args, **kwargs)
        references.append(weakref.ref(value))
        return value
    monkeypatch.setattr(preparation, '_Facts', capture)
    def fold(plan, *args, **kwargs):
        state = plan.folds[0].seed_run()
        state.counts = Counter({i: 1 for i in range(rare_rows)})
        state.counts[1000] = 100 - rare_rows
        return SimpleNamespace(prepared_status={'syslog.templates': SimpleNamespace(state=PreparedState.READY)},
                               fold_results={'fixture': state}, snapshots={'fixture': object()},
                               file_outcomes={'fixture': FileOutcomes()})
    registrations = []
    h = SimpleNamespace(sibling_needs_frame=False, exact_window=True, local_files=True,
                        upper_bound_bytes=None,
                        config={'max_count': 1}, report_window=object(), pattern='fixture',
                        fold=fold, mask=lambda df: None, timer=lambda _: nullcontext(),
                        final=lambda *args, **kwargs: registrations.append(args))
    result = preparation.prepare(h)
    if declines:
        assert result == Declined(DeclineReason.INELIGIBLE, 'dense candidates')
        assert not registrations
        assert all(ref() is None for ref in references)
    else:
        assert not isinstance(result, Declined)
        assert len(registrations) == 1


def test_auth_sibling_declines_preparation_and_preserves_reports(tmp_path, monkeypatch):
    import json
    from sigwood import runner
    from sigwood.common.finding import Declined, DeclineReason
    path = tmp_path / 'source.log'
    path.write_text(
        '2020-01-01T00:00:00Z host.example sshd: Failed password for root from 192.0.2.1 port 2222 ssh2\n')
    observed = []
    original_prepare = preparation.prepare
    def prepare(h):
        value = original_prepare(h)
        observed.append(value)
        return value
    monkeypatch.setattr(syslog, 'PREPARED_POPULATION',
                        replace(syslog.PREPARED_POPULATION, prepare=prepare))
    original_run = syslog.run
    def run(context, _prepared=None):
        assert _prepared is None
        return original_run(context)
    monkeypatch.setattr(syslog, 'run', run)
    reports = []
    for enabled in (True, False):
        if not enabled:
            monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
        target = tmp_path / 'report.json'
        assert runner.run(config={'sigwood': {'detect': 'syslog,auth'}},
            detect='syslog,auth', syslog_dir=path, load_all=True,
            quiet=True, no_allowlist=True, skip_confirm=True,
            output_format='json', output_file=target) == 0
        data = json.loads(target.read_text())
        assert not data['run_summary']['detectors_failed']
        assert set(data['run_summary']['detectors_run']) == {'syslog', 'auth'}
        for finding in data['findings']:
            finding.pop('ts_generated', None)
        reports.append((data['findings'], data['run_summary']['notes']))
    assert observed == [Declined(DeclineReason.INELIGIBLE, 'a sibling consumes the pattern')]
    assert reports[0] == reports[1]


@pytest.mark.parametrize('failure', ['reducer', 'byte_cap', 'identity_count', 'identity_bytes'])
def test_index_failure_recovers_with_one_note_and_ordinary_findings(tmp_path, monkeypatch, failure):
    import json
    from sigwood import runner
    if failure == 'identity_count':
        monkeypatch.setattr(preparation, 'MAX_DELTA_IDENTITY_KEYS', 0)
    elif failure == 'identity_bytes':
        monkeypatch.setattr(preparation, 'MAX_IDENTITY_KEY_BYTES', 1)
    original_sink = preparation.templates_sink
    def sink(*args):
        value = original_sink(*args)
        if failure == 'byte_cap':
            return replace(value, max_file_delta_bytes=1)
        if failure.startswith('identity_'):
            return value
        def fail(*args):
            raise RuntimeError('injected reducer failure')
        return replace(value, consume=fail)
    monkeypatch.setattr(preparation, 'templates_sink', sink)
    original_run = syslog.run
    def run(context, _prepared=None):
        assert _prepared is None
        assert len(context.logs['*.log*']) == 1
        return original_run(context)
    monkeypatch.setattr(syslog, 'run', run)
    path = tmp_path / 'source.log'
    path.write_text('2020-01-01T00:00:00Z host.example service: unique event\n')
    reports = []
    for enabled in (True, False):
        if not enabled:
            monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
        target = tmp_path / 'report.json'
        assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
            syslog_dir=path, load_all=True, quiet=True, no_allowlist=True,
            skip_confirm=True, output_format='json', output_file=target) == 0
        data = json.loads(target.read_text())
        assert not data['run_summary']['detectors_failed']
        for finding in data['findings']:
            finding.pop('ts_generated', None)
        notes = data['run_summary']['notes']
        recovery = [n for n in notes if 'prepared load' in n]
        assert len(recovery) == int(enabled)
        if enabled:
            assert 'analysis ran on the full frame' in recovery[0]
            if failure == 'identity_count':
                assert 'identity count' in recovery[0]
            elif failure == 'identity_bytes':
                assert 'identity key' in recovery[0]
        reports.append((data['findings'], [n for n in notes if n not in recovery]))
    assert reports[0] == reports[1]


def test_dense_runner_declines_without_note_and_matches_ordinary(tmp_path, monkeypatch):
    import json
    import weakref
    from sigwood import runner
    references = []
    original_facts = preparation._Facts
    def capture(*args, **kwargs):
        value = original_facts(*args, **kwargs)
        references.append(weakref.ref(value))
        return value
    monkeypatch.setattr(preparation, '_Facts', capture)
    original_run = syslog.run
    def run(context, _prepared=None):
        assert _prepared is None
        assert all(ref() is None for ref in references)
        return original_run(context)
    monkeypatch.setattr(syslog, 'run', run)
    path = tmp_path / 'source.log'
    path.write_text('2020-01-01T00:00:00Z host.example service: unique event\n')
    outputs = []
    for enabled in (True, False):
        if not enabled:
            monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
        target = tmp_path / 'report.json'
        assert runner.run(config={'sigwood': {'detect': 'syslog'}}, detect='syslog',
            syslog_dir=path, quiet=True, no_allowlist=True, skip_confirm=True,
            output_format='json', output_file=target) == 0
        data = json.loads(target.read_text())
        for finding in data['findings']:
            finding.pop('ts_generated', None)
        outputs.append((data['findings'], data['run_summary']['notes']))
    assert outputs[0] == outputs[1]
