"""Positional contracts shared by ordinary and admitted chunk consumers."""
from datetime import datetime, timezone

from sigwood.common.loader.fold import chunks_from_rows
from sigwood.common.loader.types import DualWindow
import sigwood.common.loader.fold as fold


def test_ordinals_count_outside_report_and_restart_per_file(monkeypatch):
    monkeypatch.setattr(fold, "MAX_CHUNK_ROWS", 2)
    window = DualWindow((datetime.fromtimestamp(10, timezone.utc),
                         datetime.fromtimestamp(20, timezone.utc)))
    for _ in range(2):
        chunks = list(chunks_from_rows(
            [({"ts": n}, 1) for n in (1, 11, 12, 30, 15)],
            columns=["ts"], window=window,
        ))
        assert [c.first_ordinal for c in chunks] == [0, 2, 4]
        assert [c.report_mask for c in chunks] == [(False, True), (True, False), (True,)]
