"""Population coverage survives admission and recovers on an unusable fold."""
from dataclasses import replace
import json

import pytest

from sigwood import runner
from sigwood.detectors import syslog, syslog_preparation
from tests.test_suppression_disclosure import _host_suppression_env
from tests.syslog_shape_cases import fixed_clock


@pytest.fixture(autouse=True)
def keep_coverage_fixtures_prepared(monkeypatch):
    # These tiny fixtures exercise admission coverage; density is tested separately.
    monkeypatch.setattr(syslog_preparation, 'DENSE_CANDIDATE_SHARE', 1.01)
    monkeypatch.setattr(syslog_preparation, 'SMALL_INPUT_BYTES', 0)


@pytest.mark.parametrize('failure', [None, 'raise', 'abstain'])
def test_population_suppression_equals_ordinary_after_recovery(tmp_path, monkeypatch, failure):
    from sigwood.common.loader.fold import FoldAbstention
    config, flat, zeek = _host_suppression_env(tmp_path)
    original = runner._suppression_sink
    channels = []
    def sink(name, matcher):
        value = original(name, matcher)
        channels.append(value.channel)
        if failure:
            def fail(*args):
                if failure == 'abstain':
                    raise FoldAbstention('coverage fixture abstained')
                raise ValueError('coverage fixture failed')
            value = replace(value, consume=fail)
        return value
    monkeypatch.setattr(runner, '_suppression_sink', sink)
    outputs = []
    with fixed_clock():
        for prepared in (True, False):
            if not prepared:
                monkeypatch.setattr(syslog, 'PREPARED_POPULATION', None)
            target = tmp_path / 'report.json'
            assert runner.run(config, detect='syslog', syslog_dir=flat, zeek_dir=zeek,
                              syslog_source='files', quiet=True, skip_confirm=True,
                              output_format='json', output_file=target) == 0
            outputs.append(json.loads(target.read_text()))
    assert channels == ['sigwood.suppression-coverage:syslog']
    assert outputs[0]['findings'] == outputs[1]['findings']
    assert outputs[0]['run_summary']['suppression'] == outputs[1]['run_summary']['suppression']
    notes = outputs[0]['run_summary']['notes']
    assert sum('prepared load failed' in n for n in notes) == bool(failure)


def test_suppression_off_never_attaches_coverage_sink(tmp_path, monkeypatch):
    config, flat, zeek = _host_suppression_env(tmp_path)
    def forbidden(*args):
        pytest.fail('suppression off must attach no sink')
    monkeypatch.setattr(runner, '_suppression_sink', forbidden)
    assert runner.run(config, detect='syslog', syslog_dir=flat, zeek_dir=zeek,
                      syslog_source='files', quiet=True, no_allowlist=True,
                      output_format='json', output_file=tmp_path / 'report.json') == 0


def test_coverage_channels_are_unique_per_declarer():
    assert runner._suppression_sink('one', None).channel != runner._suppression_sink('two', None).channel


@pytest.mark.parametrize('reserved', ['sigwood.suppression-coverage', 'sigwood.suppression-coverage:pretend'])
def test_reserved_coverage_channel_refuses_preparation(tmp_path, monkeypatch, reserved):
    config, flat, zeek = _host_suppression_env(tmp_path)
    original = syslog.PREPARED_POPULATION
    def prepare(host):
        value = original.prepare(host)
        plan, window, snapshot = host.registration
        host.registration = (replace(plan, admit=replace(plan.admit, channel=reserved)), window, snapshot)
        return value
    monkeypatch.setattr(syslog, 'PREPARED_POPULATION', replace(original, prepare=prepare))
    target = tmp_path / 'report.json'
    assert runner.run(config, detect='syslog', syslog_dir=flat, zeek_dir=zeek,
                      syslog_source='files', quiet=True, no_allowlist=True,
                      output_format='json', output_file=target) == 0
    summary = json.loads(target.read_text())['run_summary']
    assert any('reserved coverage channel' in note for note in summary['notes'])
    assert not summary['detectors_failed']
