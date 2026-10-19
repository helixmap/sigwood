"""Measurement invariants for independent syslog memory samples."""
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tools import bench_syslog_memory as bench
from tools.gen_syslog_corpus import generate


def test_peak_units():
    assert bench.rss_bytes(1234, 'Darwin') == 1234
    assert bench.rss_bytes(1234, 'Linux') == 1263616
    with pytest.raises(ValueError):
        bench.rss_bytes(1234, 'unsupported')


def test_independent_child_peak_and_exit(tmp_path):
    args = dict(cwd=tmp_path, env=dict(os.environ), stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
    first = bench.measure_child([sys.executable, '-c', 'x = bytearray(256 * 1024 * 1024)'], **args)
    second = bench.measure_child([sys.executable, '-c', 'raise SystemExit(7)'], **args)
    assert first['exit_status'] == 0
    assert second['exit_status'] == 7
    assert first['peak_rss_bytes'] > second['peak_rss_bytes'] + 128 * 1024 * 1024


def test_corpus_floor_uses_mined_population(tmp_path):
    from sigwood.common import loader
    from sigwood.detectors import syslog
    path = tmp_path / 'messages.log'
    path.write_text(''.join(f'Oct 14 12:00:00 host.example worker: finished job{i}\n' for i in range(20)))
    args = SimpleNamespace(input=path, expected_rows=20, min_hosts=0, min_programs=0,
                           min_rare_fraction=.99)
    with pytest.raises(RuntimeError, match='rare population floor'):
        bench.validate(args, loader, syslog, dict(syslog.DEFAULT_CONFIG))


def test_generator_reproducible_and_no_overwrite(tmp_path):
    first, second = tmp_path / 'first.log', tmp_path / 'second.log'
    generate(first, 50, 'hicand', 7)
    generate(second, 50, 'hicand', 7)
    assert first.read_bytes() == second.read_bytes()
    with pytest.raises(FileExistsError):
        generate(first, 50, 'hicand', 7)
