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
    # Reproduce a large pytest/loaded-detector parent even in a focused run.
    # Keep these resident pages alive through both child measurements.
    parent_memory = bytearray(384 * 1024 * 1024)
    parent_memory[::4096] = b'x' * (len(parent_memory) // 4096)
    args = dict(cwd=tmp_path, env=dict(os.environ), stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
    first = bench.measure_child([sys.executable, '-c', 'x = bytearray(256 * 1024 * 1024)'], **args)
    second = bench.measure_child([sys.executable, '-c', 'raise SystemExit(7)'], **args)
    assert first['exit_status'] == 0
    assert second['exit_status'] == 7
    assert first['peak_rss_bytes'] > second['peak_rss_bytes'] + 128 * 1024 * 1024
    assert len(parent_memory) == 384 * 1024 * 1024


def test_child_context_and_streams(tmp_path):
    env = dict(os.environ, BENCH_TEST_VALUE='inherited')
    with (tmp_path / 'stdout').open('wb') as stdout, (tmp_path / 'stderr').open('wb') as stderr:
        result = bench.measure_child(
            [sys.executable, '-c',
             'import os, sys; from os import read; print(os.environ["BENCH_TEST_VALUE"]); '
             'print(os.getcwd(), file=sys.stderr); assert read(0, 1) == b""'],
            cwd=tmp_path, env=env, stdout=stdout, stderr=stderr)
    assert result['exit_status'] == 0
    assert (tmp_path / 'stdout').read_text().strip() == 'inherited'
    assert (tmp_path / 'stderr').read_text().strip() == str(tmp_path.resolve())


def test_child_signal_status(tmp_path):
    import signal
    result = bench.measure_child(
        [sys.executable, '-c', 'import os, signal; os.kill(os.getpid(), signal.SIGTERM)'],
        cwd=tmp_path, env=dict(os.environ), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    assert result['exit_status'] == -signal.SIGTERM


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
