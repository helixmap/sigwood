"""Exact behavior and caller-frame contracts across syslog memory changes."""
import json
from pathlib import Path

import pytest
import pandas as pd

from sigwood.common.loader.pipeline import SourceLoader, run_load

from tests.syslog_shape_cases import CASES, run_case


@pytest.mark.parametrize('case', CASES)
def test_frozen_shape(case, tmp_path, restore_display_utc):
    expected = {}
    for path in sorted((Path(__file__).parent / 'fixtures/syslog_shape').glob('*.json')):
        cases = json.loads(path.read_text())['cases']
        assert not expected.keys() & cases.keys()
        expected.update(cases)
    assert run_case(case, tmp_path / case) == expected[case]


@pytest.mark.parametrize('columns', [
    ['ts', 'host', 'program', 'message', 'absent'],
    ['message', 'ts', 'message'],
    [],
])
def test_stream_constructor_preserves_ragged_rows(tmp_path, columns):
    rows = [
        {'ts': 1.0, 'host': 'one.example', 'program': None, 'message': 'first'},
        {'ts': 2.0, 'host': None, 'message': None},
        {'ts': 3.0, 'program': 'service', 'message': 'third'},
    ]
    paths = [tmp_path / 'first.log', tmp_path / 'second.log']
    paths[0].write_text(json.dumps(rows[0]) + '\n')
    paths[1].write_text(''.join(json.dumps(row) + '\n' for row in rows[1:]))

    def parse(lines, *, path, warnings):
        for line in lines:
            yield json.loads(line)

    strategy = SourceLoader(
        discover=lambda *args, **kwargs: [], mode='stream', parse=parse,
        ts_policy='keep', columns=columns, should_skip=None, normalize=None,
    )
    actual = run_load(strategy, paths, '*.log', None, None, show_progress=False)
    expected = pd.DataFrame(rows, columns=columns)
    pd.testing.assert_frame_equal(actual, expected, check_exact=True)
    assert [value is None for value in actual.to_numpy().flat] == [
        value is None for value in expected.to_numpy().flat
    ]


def test_stream_loads_keep_identity_values_after_error(tmp_path):
    path = tmp_path / 'events.log'
    path.write_text('fixture\n')
    rows = [
        {'ts': 1.0, 'host': 'first.example', 'program': 'service'},
        {'ts': 2.0, 'host': None, 'program': 7},
        {'ts': 3.0, 'host': ['unhashable'], 'program': None},
    ]
    fail = True

    def parse(lines, *, path, warnings):
        for row in rows:
            yield dict(row)
        if fail:
            raise RuntimeError('source interrupted')

    strategy = SourceLoader(
        discover=lambda *args, **kwargs: [], mode='stream', parse=parse,
        ts_policy='keep', columns=['ts', 'host', 'program'],
        should_skip=None, normalize=None,
    )
    with pytest.raises(RuntimeError, match='source interrupted'):
        run_load(strategy, [path], '*.log', None, None, show_progress=False)
    fail = False
    first = run_load(strategy, [path], '*.log', None, None, show_progress=False)
    pd.testing.assert_frame_equal(first, pd.DataFrame(rows), check_exact=True)
    rows[0]['host'] = 'second.example'
    second = run_load(strategy, [path], '*.log', None, None, show_progress=False)
    pd.testing.assert_frame_equal(second, pd.DataFrame(rows), check_exact=True)
    assert first.loc[0, 'host'] == 'first.example'


@pytest.mark.parametrize('copy_on_write', [False, True])
def test_rarity_helper_preserves_caller_frame(copy_on_write):
    from sigwood.detectors.syslog import _score_rarity

    frame = pd.DataFrame({
        'template_id': [1, 1, 1, 1, 2, 2, 3],
        'message': ['event'] * 7,
    }, index=list('abcdefg'))
    frame.attrs['source'] = 'synthetic'
    expected = frame.copy(deep=True)
    with pd.option_context('mode.copy_on_write', copy_on_write):
        scored, threshold, counts = _score_rarity(frame, 100, 2)
        assert threshold == 2
        assert counts == {1: 4, 2: 2, 3: 1}
        assert scored['is_anomaly'].tolist() == [False] * 4 + [True] * 3
        pd.testing.assert_frame_equal(frame, expected, check_exact=True)
        scored.loc['a', 'message'] = 'changed'
        scored.loc['a', 'template_id'] = 9
        pd.testing.assert_frame_equal(frame, expected, check_exact=True)


@pytest.mark.parametrize('copy_on_write', [False, True])
@pytest.mark.parametrize('filtered', [False, True])
def test_transaction_source_preserves_filter_and_ownership(copy_on_write, filtered):
    from sigwood.detectors.syslog import _transaction_source

    if filtered:
        frame = pd.DataFrame({
            'ts': ['1.25', 'invalid', None, '4', '5', '6'],
            'host': ['alpha.example', 'beta.example', 'gamma.example',
                     None, 'unknown', 'delta.example'],
            'message': ['one', 'two', 'three', 'four', 'five', 'six'],
        }, index=[7, 7, 9, 9, 11, 11])
        expected = pd.DataFrame({
            'ts': [1.25, 6.0],
            'host': ['alpha.example', 'delta.example'],
            'message': ['one', 'six'],
        }, index=[0, 5])
    else:
        frame = pd.DataFrame({
            'ts': ['1.25', '6.0'],
            'host': ['alpha.example', 'delta.example'],
            'message': ['one', 'six'],
        }, index=[7, 7])
        expected = pd.DataFrame({
            'ts': [1.25, 6.0],
            'host': ['alpha.example', 'delta.example'],
            'message': ['one', 'six'],
        })
    frame.attrs['source'] = expected.attrs['source'] = 'synthetic'
    caller = frame.copy(deep=True)
    with pd.option_context('mode.copy_on_write', copy_on_write):
        source = _transaction_source(frame)
        pd.testing.assert_frame_equal(source, expected, check_exact=True)
        pd.testing.assert_frame_equal(frame, caller, check_exact=True)
        source.loc[0, ['ts', 'host', 'message']] = [99.0, 'changed.example', 'changed']
        pd.testing.assert_frame_equal(frame, caller, check_exact=True)
