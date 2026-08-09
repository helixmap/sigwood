"""Subprocess helper for the real exporter provenance lock test."""

from __future__ import annotations

import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from sigwood.common.paths import private_write_bytes
from sigwood.exporters import (
    _commit_export_provenance,
    _new_stage_directory,
    _validate_staged_write,
)


def main() -> int:
    parent = Path(sys.argv[1])
    basename = sys.argv[2]
    payload = sys.argv[3].encode("utf-8")
    gate = Path(sys.argv[4])
    stage = _new_stage_directory(parent)
    try:
        staged_path = stage / basename
        private_write_bytes(staged_path, payload)
        staged = _validate_staged_write(
            stage,
            {"bytes": len(payload), "paths": [staged_path]},
        )
        deadline = time.monotonic() + 10
        while not gate.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("concurrency gate timed out")
            time.sleep(0.01)
        _commit_export_provenance(
            staged,
            since=datetime(2026, 8, 1, tzinfo=timezone.utc),
            until=datetime(2026, 8, 2, tzinfo=timezone.utc),
            backend="splunk",
            request_zone="Etc/UTC",
            tzdata_version=None,
        )
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
