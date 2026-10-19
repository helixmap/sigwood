"""Small deterministic cases shared by the syslog oracle and its explicit writer."""
from __future__ import annotations

import copy
import dataclasses
import gzip
import importlib
import json
import math
import os
import sys
import time
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd

from sigwood.common import loader
from sigwood.common.finding import DetectorContext
from sigwood.detectors import auth, syslog

NOW = datetime(2026, 10, 18, 12, tzinfo=timezone.utc)
WINDOW = (datetime(2026, 10, 14, tzinfo=timezone.utc), NOW)
CASES = ('flat', 'corrupt', 'window', 'nan', 'empty', 'filtered', 'journal',
         'zeek', 'mixed', 'hunt', 'mutation', 'pihole', 'pihole_missing',
         'pihole_nan', 'pihole_corrupt', 'cloudtrail', 'cloudtrail_missing',
         'cloudtrail_nan', 'cloudtrail_corrupt', 'all_nan', 'pihole_all_nan')


class FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)

    @classmethod
    def today(cls):
        return cls.now()


@contextmanager
def fixed_clock():
    modules = ('sigwood.parsers.syslog', 'sigwood.parsers.dnsmasq',
               'sigwood.detectors.syslog', 'sigwood.detectors.auth', 'sigwood.runner',
               'sigwood.common.loader.windowing', 'sigwood.common.display')
    previous_tz = os.environ.get('TZ')
    os.environ['TZ'] = 'UTC'
    time.tzset()
    patches = []
    try:
        for name in modules:
            module = importlib.import_module(name)
            if hasattr(module, 'datetime'):
                binding = patch.object(module, 'datetime', FrozenDateTime)
                binding.start()
                patches.append(binding)
        yield
    finally:
        for binding in reversed(patches):
            binding.stop()
        if previous_tz is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = previous_tz
        time.tzset()


def exact(value, root: Path):
    if value is pd.NA:
        return {'missing': 'pandas_na'}
    if value is pd.NaT:
        return {'missing': 'NaT'}
    if isinstance(value, np.generic):
        return exact(value.item(), root)
    if isinstance(value, float):
        return {'float': value.hex() if math.isfinite(value) else repr(value)}
    if isinstance(value, datetime):
        return {'datetime': value.isoformat()}
    if isinstance(value, Enum):
        return exact(value.value, root)
    if isinstance(value, Path):
        return str(value).replace(str(root), '<root>')
    if isinstance(value, str):
        return value.replace(str(root), '<root>')
    if dataclasses.is_dataclass(value):
        return {field.name: exact(getattr(value, field.name), root) for field in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {str(key): exact(item, root) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [exact(item, root) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(exact(item, root) for item in value)
    if value is None or isinstance(value, (int, bool)):
        return value
    raise TypeError(f'unsupported oracle value: {type(value).__name__}')


def frame_snapshot(frame: pd.DataFrame, root: Path):
    return {'columns': exact(frame.columns.tolist(), root),
            'column_names': exact(list(frame.columns.names), root),
            'dtypes': [str(dtype) for dtype in frame.dtypes],
            'index': exact(frame.index.tolist(), root), 'index_dtype': str(frame.index.dtype),
            'index_type': type(frame.index).__name__, 'index_names': list(frame.index.names),
            'values': exact(list(frame.itertuples(index=False, name=None)), root),
            'nulls': frame.isna().values.tolist(), 'attrs': exact(frame.attrs, root)}


def load_snapshot(result, root):
    keys = ('record_counts', 'data_window', 'warnings', 'data_size_bytes', 'coverage',
            'rotation_skips', 'permission_skips', 'file_spans', 'quality')
    return {'logs': {key: frame_snapshot(frame, root) for key, frame in result.logs.items()},
            **{key: exact(getattr(result, key), root) for key in keys}}


def write_file(path: Path, content: str, *, corrupt=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if corrupt:
        path.write_bytes(gzip.compress(content.encode(), mtime=0)[:-5])
    else:
        path.write_text(content)
    os.utime(path, (NOW.timestamp(), NOW.timestamp()))
    return path


def flat_lines():
    bodies = ['worker: task finished alpha', 'worker: task finished beta',
              'kernel: Linux version synthetic',
              'sshd[123]: Accepted publickey for user from 192.0.2.10 port 2222 ssh2',
              'sudo[124]: user : COMMAND=/usr/bin/true',
              'sshd[123]: pam_unix(sshd:session): session closed for user user']
    return ''.join(f'Oct 14 12:0{i}:00 host.example {body}\n' for i, body in enumerate(bodies))


def prepare(case: str, root: Path):
    kind = case.split('_')[0]
    since = until = None
    if kind == 'pihole':
        source, pattern = 'pihole_dir', 'pihole.log*'
        content = 'Oct 14 12:00:00 dnsmasq[1]: query[A] host.example from 192.0.2.1\n'
        if case.endswith('missing'):
            content += 'Oct 14 12:00:01 dnsmasq[1]: cached host.example is 192.0.2.2\n'
        if case.endswith('nan'):
            content = 'bad clock dnsmasq[1]: query[A] host.example from 192.0.2.1\n'
        if case == 'pihole_all_nan':
            content = 'Feb 30 12:00:00 dnsmasq[1]: query[A] host.example from 192.0.2.1\n'
        path = write_file(root / 'pihole.log', content)
    elif kind == 'cloudtrail':
        source, pattern = 'cloudtrail_dir', '*.json*'
        event = {'eventTime': '2026-10-14T12:00:00Z', 'eventSource': 's3.amazonaws.com',
                 'eventName': 'GetObject', 'sourceIPAddress': '192.0.2.10',
                 'userIdentity': {'type': 'IAMUser', 'userName': 'example-user'}}
        if case.endswith('missing'):
            event.pop('userIdentity')
            event.pop('sourceIPAddress')
        if case.endswith('nan'):
            event['eventTime'] = 'invalid'
        content = json.dumps(event) + '\n'
        path = write_file(root / 'events.json', content)
    elif case == 'journal':
        source, pattern = 'journal', '*.log*'
        content = ''.join(json.dumps({'__REALTIME_TIMESTAMP': str(1791979200000000 + i * 1000000),
                                      'MESSAGE': text, '_HOSTNAME': 'host.example',
                                      'SYSLOG_IDENTIFIER': 'worker'}) + '\n'
                          for i, text in enumerate(('task finished alpha', 'task finished beta')))
        path = write_file(root / 'capture.jsonl', content)
    elif case == 'zeek':
        source, pattern = 'zeek_dir', 'syslog*.log*'
        content = ''.join(json.dumps({'ts': 1791979200.0 + i, 'host': '192.0.2.1',
                                      'app_name': 'worker', 'message': text,
                                      'facility': 'USER', 'severity': 'INFO'}) + '\n'
                          for i, text in enumerate(('task finished alpha', 'task finished beta')))
        path = write_file(root / 'syslog.log', content)
    else:
        source, pattern = 'syslog_dir', '*.log*'
        content = flat_lines()
        if case == 'empty':
            content = ''
        elif case == 'nan':
            content += 'unparseable timestamp worker: something happened\n'
        elif case == 'all_nan':
            content = 'Feb 30 12:00:00 host.example worker: task finished alpha\n'
        elif case == 'window':
            since, until = datetime(2026, 10, 14, 12, 2, tzinfo=timezone.utc), NOW
        elif case == 'filtered':
            since, until = NOW, NOW
        path = write_file(root / 'messages.log', content)
    inputs = [path]
    if case == 'corrupt' or case.endswith('_corrupt'):
        # Enough decoded bytes to yield rows before the trailer error is observed.
        broken = write_file(root / (path.name + '.1.gz'), content * 3000, corrupt=True)
        sibling = write_file(root / ('later-' + path.name), content)
        inputs.extend((broken, sibling))
    return source, pattern, inputs, since, until


def run_case(case: str, root: Path):
    import sigwood.runner as runner
    from sigwood.common import config as cfg
    root.mkdir(parents=True, exist_ok=True)
    with fixed_clock():
        if case in ('mixed', 'hunt'):
            flat = root / 'flat'
            zeek = root / 'zeek'
            _, _, flat_paths, _, _ = prepare('flat', flat)
            prepare('zeek', zeek)
            config_path = write_file(root / 'config.toml',
                '[sigwood]\nroot = ""\nwarn_above = 0\nzeek_dir = ""\nsyslog_dir = ""\n'
                'pihole_dir = ""\ncloudtrail_dir = ""\nsyslog_source = "files"\n'
                '[allowlist]\nenabled = false\n')
            output = root / 'report.json'
            code = runner.run(cfg.load(config_path), detect='syslog' if case == 'mixed' else 'syslog,auth',
                              syslog_dir=flat_paths, zeek_dir=[zeek], load_all=True, quiet=True,
                              output_format='json', output_file=output, no_allowlist=True)
            assert code == 0
            result = json.loads(output.read_text())
            # Full findings and population metadata, excluding invocation/runtime telemetry.
            summary = result['run_summary']
            return exact({'findings': result['findings'], 'summary': {key: summary[key] for key in
                          ('record_counts', 'record_labels', 'data_size_bytes', 'data_window',
                           'detectors_run', 'detectors_skipped', 'detectors_failed', 'notes')}}, root)
        if case == 'mutation':
            messages = ['worker: task finished alpha', 'worker: task finished beta']
            frame = pd.DataFrame([{'ts': 1791979200.0 + i * 3600, 'host': f'192.0.2.{i + 1}',
                                   'program': 'worker', 'raw': message, 'message': message}
                                  for i, message in enumerate(messages)])
            result_snapshot = None
            settings = {'rarity_pct': 100, 'max_count': 2}
        else:
            source, pattern, inputs, since, until = prepare(case, root)
            if case == 'journal':
                from sigwood.common.loader import journal
                executable = write_file(root / 'journalctl',
                    f'#!{sys.executable}\nprint({inputs[0].read_text()!r}, end="")\n')
                executable.chmod(0o700)
                with patch.object(journal, 'resolve_journalctl', return_value=str(executable)):
                    with loader.prepare_journal_capture(since=WINDOW[0], until=NOW,
                                                        default_span=timedelta(days=7)) as capture:
                        result = loader.load_required_logs({pattern: source},
                            {source: [capture.capture_path]}, show_progress=False)
            else:
                result = loader.load_required_logs({pattern: source}, {source: inputs}, since=since,
                                                   until=until, show_progress=False)
            result_snapshot = load_snapshot(result, root)
            if case.startswith(('pihole', 'cloudtrail')):
                return result_snapshot
            frame = result.logs.get(pattern, pd.DataFrame())
            settings = {}
        frozen = frame.copy(deep=True)
        frozen.attrs = copy.deepcopy(frame.attrs)
        key = 'syslog*.log*' if case == 'zeek' else '*.log*'
        context = DetectorContext.unsuppressed({key: frame}, config=settings, data_window=WINDOW)
        findings = syslog.run(context)
        for _ in range(2):
            pd.testing.assert_frame_equal(frame, frozen, check_exact=True)
            assert frame.attrs == frozen.attrs
            assert exact(syslog.run(context), root) == exact(findings, root)
        auth.run(DetectorContext.unsuppressed({key: frame}, data_window=WINDOW))
        pd.testing.assert_frame_equal(frame, frozen, check_exact=True)
        assert frame.attrs == frozen.attrs
        return {'loader': result_snapshot, 'findings': exact(findings, root),
                'input_after_sibling': frame_snapshot(frame, root)}
