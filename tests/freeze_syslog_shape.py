#!/usr/bin/env python3
"""Explicitly capture synthetic syslog expectations from an unchanged source tree."""
import argparse
import importlib.util
import json
import sys
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', action='store_true', required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cases', help='Comma-separated case names; omitted selects all')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('expectations already exist; the writer never overwrites them')
    source = args.source_root.resolve()
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.path.insert(0, str(source))
    spec = importlib.util.spec_from_file_location('syslog_shape_cases', Path(__file__).with_name('syslog_shape_cases.py'))
    cases_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cases_module)
    from sigwood.detectors import syslog
    if Path(syslog.__file__).resolve() != source / 'sigwood/detectors/syslog.py':
        raise RuntimeError('oracle imported the wrong source tree')
    with tempfile.TemporaryDirectory(prefix='syslog-shape-') as temp:
        names = args.cases.split(',') if args.cases else cases_module.CASES
        if any(name not in cases_module.CASES for name in names):
            parser.error('unknown case name')
        cases = {name: cases_module.run_case(name, Path(temp) / name) for name in names}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump({'cases': cases}, stream, indent=2, allow_nan=False)
        stream.write('\n')


if __name__ == '__main__':
    main()
