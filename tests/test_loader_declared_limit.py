"""Declared reducer budgets remain local to their channel."""
from dataclasses import replace

import pytest

from sigwood.common import loader
from sigwood.common.loader.limits import MAX_DECLARED_FILE_DELTA_BYTES, MAX_FILE_DELTA_BYTES
from tests.test_loader_fold import _chunk, _count_sink


@pytest.mark.parametrize('value', [0, -1, True, 1.5, MAX_DECLARED_FILE_DELTA_BYTES + 1])
def test_invalid_declared_limit(value):
    with pytest.raises(ValueError, match='declared file delta limit'):
        replace(_count_sink('count'), max_file_delta_bytes=value)


@pytest.mark.parametrize('extra', [0, 1])
def test_declared_ceiling_is_independent_of_default(tmp_path, extra):
    path = tmp_path / 'events.log'
    path.write_text('event\n')
    snapshot = loader.build_source_snapshot([path], 'syslog_dir', tail_policy='whole')
    declared = replace(_count_sink('declared', bytes_=MAX_DECLARED_FILE_DELTA_BYTES + extra),
                       max_file_delta_bytes=MAX_DECLARED_FILE_DELTA_BYTES)
    ordinary = _count_sink('ordinary', bytes_=MAX_FILE_DELTA_BYTES + 1)
    result = loader.execute_sink_plan(snapshot, loader.SinkPlan((declared, ordinary)),
                                      lambda item: iter([_chunk()]))
    expected = loader.PreparedState.ABSTAINED if extra else loader.PreparedState.READY
    assert result.statuses['declared'].state is expected
    assert result.statuses['ordinary'].state is loader.PreparedState.ABSTAINED
    assert result.statuses['ordinary'].cause == 'file delta exceeds 256 MiB'
    if extra:
        assert result.statuses['declared'].cause == 'file delta exceeds 2 GiB'
