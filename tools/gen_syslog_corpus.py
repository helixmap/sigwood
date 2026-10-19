#!/usr/bin/env python3
"""Generate deterministic synthetic syslog inputs for memory measurements."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import datetime, timedelta
from pathlib import Path


def letters(value: int) -> str:
    """Encode an integer without digits or long hexadecimal tokens."""
    result = ''
    while True:
        result = chr(97 + value % 26) + result
        value //= 26
        if not value:
            return result


def generate(path: Path, rows: int, kind: str, seed: int) -> None:
    rng = random.Random(seed)
    start = datetime(2026, 10, 14)
    lengths = [size for size in range(3, 27) for _ in range(360 // size)]
    with path.open('x', encoding='utf-8') as stream:
        for i in range(rows):
            stamp = (start + timedelta(seconds=i * 172800 / rows)).strftime('%b %e %H:%M:%S')
            if kind == 'hicand':
                # The default tree indexes length and the first token. Spread
                # populations across both, with fewer rows at larger token counts.
                # All remaining tokens differ, keeping similarity below threshold.
                size = rng.choice(lengths)
                unique = letters(i + seed * rows)
                program = 'q' + letters(rng.randrange(90))
                body = ' '.join(f'{letters(j)}q{unique}' for j in range(size - 1))
                host = f'host{rng.randrange(4)}.example'
            else:
                host = f'host{i % 4000}.example'
                program = 'service' + letters((i * 17) % 4000)
                body = f'worker task finished job{rng.randrange(100000)}'
            stream.write(f'{stamp} {host} {program}: {body}\n')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=('hicard', 'hicand'))
    parser.add_argument('output', type=Path)
    parser.add_argument('--rows', type=int, default=800000)
    parser.add_argument('--seed', type=int, default=7)
    args = parser.parse_args()
    if args.rows < 1:
        parser.error('rows must be positive')
    generate(args.output, args.rows, args.kind, args.seed)
    print(json.dumps({'kind': args.kind, 'rows': args.rows, 'seed': args.seed,
                      'length_weights': {size: 360 // size for size in range(3, 27)} if args.kind == 'hicand' else None,
                      'bytes': args.output.stat().st_size,
                      'sha256': hashlib.sha256(args.output.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
