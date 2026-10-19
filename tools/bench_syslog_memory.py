#!/usr/bin/env python3
"""Measure syslog memory with independent CLI peaks and allocation snapshots."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def rss_bytes(raw: int, system: str) -> int:
    if system == 'Darwin':
        return raw
    if system == 'Linux':
        return raw * 1024
    raise ValueError('peak RSS normalization supports macOS and Linux')


def current_rss() -> int:
    return int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(os.getpid())], text=True)) * 1024


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    temporary.replace(path)


def source_hashes(root: Path) -> dict[str, str]:
    paths = sorted((root / 'sigwood').rglob('*.py'))
    return {str(path.relative_to(root)): file_hash(path) for path in paths}


def modules(root: Path):
    sys.path.insert(0, str(root))
    from sigwood.common import loader
    from sigwood.detectors import syslog
    if Path(syslog.__file__).resolve() != root / 'sigwood/detectors/syslog.py':
        raise RuntimeError('measurement imported a different source tree')
    return loader, syslog


def config_text(settings: dict, directory: Path) -> str:
    lines = ['[sigwood]', f'root = {json.dumps(str(directory))}', 'zeek_dir = ""',
             'syslog_dir = ""', 'pihole_dir = ""', 'cloudtrail_dir = ""',
             'syslog_source = "files"', 'warn_above = 0', 'home_net = []',
             '[allowlist]', 'enabled = false', '[detectors.syslog]']
    lines.extend(f'{key} = {json.dumps(value)}' for key, value in settings.items())
    return '\n'.join(lines) + '\n'


def effective_environment() -> dict[str, str]:
    env = dict(os.environ)
    for key in ('SIGWOOD_ROOT', 'PYTHONPATH'):
        env.pop(key, None)
    env.update(TZ='UTC', PYTHONHASHSEED='0', OMP_NUM_THREADS='1',
               OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1', NUMBA_NUM_THREADS='1')
    return env


# Start the measured process from a fresh, small interpreter. On Linux the RSS
# of a large launching parent can become the child's pre-exec high-water mark.
# Measure the grandchild, not this supervisor, and never import detector modules
# here. Keep this code in the harness so its hash covers the measurement route.
_PEAK_SUPERVISOR = '''
import json
import os
import subprocess
import sys
import time

started = time.perf_counter()
child = subprocess.Popen(sys.argv[2:])
_, status, usage = os.wait4(child.pid, 0)
child.returncode = os.waitstatus_to_exitcode(status)
with open(sys.argv[1], 'w') as stream:
    json.dump({'exit_status': child.returncode, 'peak_rss_raw': usage.ru_maxrss,
               'elapsed_seconds': time.perf_counter() - started}, stream)
'''


def measure_child(command, *, cwd: Path, env: dict, stdout, stderr) -> dict:
    """Reap one measured child through an isolated, lightweight supervisor."""
    with tempfile.TemporaryDirectory(prefix='syslog-peak-') as temp:
        result = Path(temp) / 'usage.json'
        subprocess.run([sys.executable, '-I', '-c', _PEAK_SUPERVISOR,
                        str(result), *command], cwd=cwd, env=env,
                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                       check=True)
        measured = json.loads(result.read_text())
    measured['peak_rss_bytes'] = rss_bytes(measured['peak_rss_raw'], platform.system())
    return measured


def peak(args, settings: dict) -> dict:
    samples = []
    with tempfile.TemporaryDirectory(prefix='syslog-memory-') as temp:
        directory = Path(temp)
        config = directory / 'config.toml'
        config.write_text(config_text(settings, directory))
        for sample in range(args.samples):
            report = directory / f'report-{sample}.json'
            command = [sys.executable, '-m', 'sigwood', 'syslog', str(args.input),
                       '-q', '--format=json', f'--config={config}', f'--out={report}']
            # wait4 owns reaping; no concurrent subprocess waiter or cumulative
            # RUSAGE_CHILDREN value participates in an individual sample.
            with (directory / 'stdout').open('wb') as stdout, (directory / 'stderr').open('wb') as stderr:
                measured = measure_child(command, cwd=args.root, env=effective_environment(),
                                         stdout=stdout, stderr=stderr)
            if measured['exit_status']:
                raise RuntimeError(f'CLI sample {sample + 1} failed with status {measured["exit_status"]}')
            result = json.loads(report.read_text())
            summary = result['run_summary']
            if 'syslog' not in summary['detectors_run'] or summary['detectors_failed']:
                raise RuntimeError('CLI sample did not complete syslog detection')
            counts = summary['record_counts']
            rows = sum(counts.values())
            if args.expected_rows is not None and rows != args.expected_rows:
                raise RuntimeError(f'CLI loaded {rows} rows, expected {args.expected_rows}')
            samples.append({'sample': sample + 1, **measured,
                            'peak_rss_mib': measured['peak_rss_bytes'] / 2**20,
                            'record_counts': counts, 'data_window': summary['data_window'],
                            'finding_count': len(result['findings'])})
    return {'samples': samples,
            'median_peak_rss_bytes': statistics.median(s['peak_rss_bytes'] for s in samples),
            'median_elapsed_seconds': statistics.median(s['elapsed_seconds'] for s in samples)}


def validate(args, loader, detector, settings: dict) -> dict:
    from drain3.masking import MaskingInstruction
    frame = loader.load_syslog(args.input, show_progress=False)
    if args.expected_rows is not None and len(frame) != args.expected_rows:
        raise RuntimeError('corpus loaded row count differs from expectation')
    mined = detector.mine_templates(
        (str(message) for message in frame['message']),
        sim_thresh=settings['sim_thresh'], depth=settings['depth'],
        parametrize_numeric=settings['parametrize_numeric'], show_progress=False,
        masking_instructions=[
            MaskingInstruction(detector.LONG_HEX_MASK_PATTERN, detector.LONG_HEX_MASK_NAME),
            MaskingInstruction(detector.HEX_PAIRS_MASK_PATTERN, detector.HEX_PAIRS_MASK_NAME)])
    import pandas as pd
    scored, threshold, counts = detector._score_rarity(
        pd.DataFrame({'template_id': mined.template_ids}), settings['rarity_pct'], settings['max_count'])
    rare = int(scored['is_anomaly'].sum())
    pending = [mined.miner.drain.root_node]
    leaf_sizes = []
    while pending:
        node = pending.pop()
        pending.extend(node.key_to_child_node.values())
        if not node.key_to_child_node and node.cluster_ids:
            leaf_sizes.append(len(node.cluster_ids))
    stats = {'rows': len(frame), 'hosts': int(frame.host.nunique()),
             'programs': int(frame.program.nunique()), 'templates': len(counts),
             'rare_rows': rare, 'rare_fraction': rare / len(frame) if len(frame) else 0,
             'threshold': threshold, 'tree_nonempty_leaves': len(leaf_sizes),
             'tree_max_leaf_slots': max(leaf_sizes, default=0),
             'tree_median_leaf_slots': statistics.median(leaf_sizes) if leaf_sizes else 0,
             'message_token_counts': dict(sorted(Counter(len(str(s).split()) for s in frame.message).items())),
             'assignment_sha256': hashlib.sha256(json.dumps(mined.template_ids).encode()).hexdigest(),
             'online_text_sha256': hashlib.sha256(json.dumps(mined.template_strs).encode()).hexdigest()}
    if stats['hosts'] < args.min_hosts or stats['programs'] < args.min_programs:
        raise RuntimeError(f'identity corpus floor failed: {stats}')
    if stats['rare_fraction'] < args.min_rare_fraction:
        raise RuntimeError(f'rare population floor failed: {stats}')
    return stats


def attribute(args, loader, detector, settings: dict) -> dict:
    from sigwood.common.finding import DetectorContext
    records = []
    previous = None
    previous_live = 0

    def probe(name: str) -> None:
        nonlocal previous, previous_live
        live, interval_peak = tracemalloc.get_traced_memory()
        rss = current_rss()
        snapshot = tracemalloc.take_snapshot()
        differences = (snapshot.compare_to(previous, 'lineno') if previous else
                       snapshot.statistics('lineno'))
        sites = []
        for item in differences:
            location = item.traceback[0]
            filename = Path(location.filename)
            if filename.is_relative_to(args.root):
                label = str(filename.relative_to(args.root))
            elif '/site-packages/' in str(filename):
                label = str(filename).split('/site-packages/', 1)[1]
            else:
                label = filename.name
            sites.append({'file': label, 'line': location.lineno,
                          'bytes': getattr(item, 'size_diff', item.size),
                          'count': getattr(item, 'count_diff', item.count)})
            if len(sites) == 15:
                break
        records.append({'stage': name, 'live_bytes': live, 'live_delta_bytes': live - previous_live,
                        'interval_peak_bytes': interval_peak, 'rss_bytes': rss, 'sites': sites})
        previous = snapshot
        previous_live = live
        tracemalloc.reset_peak()

    if not hasattr(detector, '_MEMORY_PROBE'):
        raise RuntimeError('attribute requires the instrumentation hook in the measured tree')
    old_probe = detector._MEMORY_PROBE
    tracemalloc.start()
    try:
        probe('start')
        frame = loader.load_syslog(args.input, show_progress=False)
        if 'template_id' in frame or 'template_str' in frame:
            raise RuntimeError('attribution requires an ordinary unmined frame')
        if args.expected_rows is not None and len(frame) != args.expected_rows:
            raise RuntimeError('attribution row count differs from expectation')
        stamps = frame.ts.dropna()
        window = (datetime.fromtimestamp(float(stamps.min()), timezone.utc),
                  datetime.fromtimestamp(float(stamps.max()), timezone.utc))
        probe('post_load')
        detector._MEMORY_PROBE = probe
        findings = detector.run(DetectorContext.unsuppressed(
            {'*.log*': frame}, config=settings, data_window=window))
        probe('returned')
        return {'rows': len(frame), 'finding_count': len(findings), 'stages': records,
                'forced_gc': False, 'data_window': [item.isoformat() for item in window]}
    finally:
        detector._MEMORY_PROBE = old_probe
        tracemalloc.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('peak', 'attribute', 'validate'))
    parser.add_argument('input', type=Path)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--expected-rows', type=int)
    parser.add_argument('--min-hosts', type=int, default=0)
    parser.add_argument('--min-programs', type=int, default=0)
    parser.add_argument('--min-rare-fraction', type=float, default=0)
    args = parser.parse_args()
    if args.samples < 1 or not 0 <= args.min_rare_fraction <= 1:
        parser.error('invalid sample count or rare fraction')
    args.root = args.root.resolve()
    args.input = args.input.resolve(strict=True)
    args.output = args.output.resolve()
    if args.output.exists():
        parser.error('output already exists; use a new measurement path')
    os.environ['TZ'] = 'UTC'
    time.tzset()
    loader, detector = modules(args.root)
    settings = dict(detector.DEFAULT_CONFIG)
    before = source_hashes(args.root)
    input_hash = file_hash(args.input)
    record = {'schema_version': 1, 'mode': args.mode, 'started_at': datetime.now(timezone.utc).isoformat(),
              'platform': platform.platform(), 'python': platform.python_version(),
              'versions': {name: importlib.metadata.version(name) for name in ('pandas', 'numpy', 'drain3')},
              'input_sha256': input_hash, 'input_bytes': args.input.stat().st_size,
              'source_sha256': before, 'harness_sha256': file_hash(Path(__file__)),
              'effective_syslog_config': settings, 'timezone': {'TZ': os.environ['TZ'], 'tzname': time.tzname},
              'rfc3164_rule': 'current local year; timestamps over seven days in the future roll back one year',
              'masking': [[detector.LONG_HEX_MASK_PATTERN, detector.LONG_HEX_MASK_NAME],
                          [detector.HEX_PAIRS_MASK_PATTERN, detector.HEX_PAIRS_MASK_NAME]]}
    git = subprocess.run(['git', '-C', str(args.root), 'rev-parse', 'HEAD'], capture_output=True, text=True)
    record['git_ref'] = git.stdout.strip() if git.returncode == 0 else None
    started = time.perf_counter()
    try:
        if args.mode == 'peak':
            record['result'] = peak(args, settings)
        elif args.mode == 'validate':
            record['result'] = validate(args, loader, detector, settings)
        else:
            record['result'] = attribute(args, loader, detector, settings)
        if before != source_hashes(args.root) or input_hash != file_hash(args.input):
            raise RuntimeError('input or source changed during measurement')
        record['status'] = 'complete'
    except Exception as error:
        record['status'] = 'failed'
        record['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        record['elapsed_seconds'] = time.perf_counter() - started
        atomic_json(args.output, record)


if __name__ == '__main__':
    main()
