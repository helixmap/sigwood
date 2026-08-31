from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

import sigwood.common.loader as loader


UTC = timezone.utc
MODULE_PATH = Path(__file__).parents[1] / "tools" / "era_fold_gate.py"
SPEC = importlib.util.spec_from_file_location("era_fold_gate", MODULE_PATH)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


def _chunk(rows: int = 1) -> loader.DecodedChunk:
    return loader.DecodedChunk(
        pd.DataFrame({"ts": [1.0] * rows}),
        rows,
        (True,) * rows,
        (False,) * rows,
        0,
    )


def test_calibration_capacity_witnesses_derive_from_loader_limit():
    limit = loader.MAX_FILE_DELTA_BYTES // gate.BYTES_PER_RECORD
    assert gate.MAX_CALIBRATION_RECORDS == limit
    assert gate._can_admit(limit - 1, 1)
    assert gate._can_admit(limit, 0)
    assert not gate._can_admit(limit, 1)


def test_calibration_one_over_cap_abstains_before_allocating(monkeypatch):
    delta = loader.FoldDelta(gate.CalibrationState(), 0)
    monkeypatch.setattr(gate, "MAX_CALIBRATION_RECORDS", 0)
    monkeypatch.setattr(
        gate,
        "_payload_for",
        lambda *_: (_ for _ in ()).throw(AssertionError("must not allocate")),
    )
    with pytest.raises(loader.FoldAbstention, match="256 MiB"):
        gate._consume(delta, _chunk(), loader.PositionalMask((True,)))


def test_calibration_keeps_prior_payloads_without_recopying_them():
    first = gate._consume(
        loader.FoldDelta(gate.CalibrationState(), 0),
        _chunk(),
        loader.PositionalMask((True,)),
    )
    second = gate._consume(
        first,
        _chunk(),
        loader.PositionalMask((True,)),
    )
    assert second.value.parts[0] is first.value.parts[0]
    assert second.resident_bytes == 2 * gate.BYTES_PER_RECORD


def test_loader_chunk_limits_admit_exact_cap_and_reject_limit_plus_one():
    exact_rows = pd.DataFrame(index=range(loader.MAX_CHUNK_ROWS))
    exact = loader.DecodedChunk(
        exact_rows,
        0,
        (True,) * loader.MAX_CHUNK_ROWS,
        (False,) * loader.MAX_CHUNK_ROWS,
        0,
    )
    assert exact.frame.empty
    assert len(exact.frame) == loader.MAX_CHUNK_ROWS

    with pytest.raises(ValueError, match="row limit"):
        loader.DecodedChunk(
            pd.DataFrame(index=range(loader.MAX_CHUNK_ROWS + 1)), 0, (), (), 0
        )

    loader.DecodedChunk(pd.DataFrame(), loader.MAX_CHUNK_DECODED_BYTES, (), (), 0)
    with pytest.raises(ValueError, match="byte limit"):
        loader.DecodedChunk(
            pd.DataFrame(), loader.MAX_CHUNK_DECODED_BYTES + 1, (), (), 0
        )


def test_calibration_sink_is_frame_free_and_transactional(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text('{"ts": 1.0, "id.orig_h": "192.0.2.1"}\n', encoding="utf-8")
    snapshot = loader.build_source_snapshot([path], "zeek_dir")
    window = loader.DualWindow(
        (datetime(1970, 1, 1, tzinfo=UTC), datetime(1970, 1, 2, tzinfo=UTC))
    )
    execution = loader.run_folded_source(
        __import__("sigwood.common.loader.pipeline", fromlist=["_SOURCE_LOADERS"])._SOURCE_LOADERS["zeek_dir"],
        snapshot,
        "conn*.log*",
        window,
        loader.SinkPlan((gate.calibration_sink(),), preserve_frame=False),
    )
    assert execution.frame.empty
    assert execution.statuses[gate.CHANNEL].state is loader.PreparedState.READY
    assert execution.results[gate.CHANNEL].records == 1
    assert execution.results[gate.CHANNEL].report_window_records == 1


def test_cap_abstention_commits_no_partial_file_result(tmp_path, monkeypatch):
    path = tmp_path / "conn.log"
    path.write_text('{"ts": 1.0, "id.orig_h": "192.0.2.1"}\n', encoding="utf-8")
    snapshot = loader.build_source_snapshot([path], "zeek_dir")
    window = loader.DualWindow(
        (datetime(1970, 1, 1, tzinfo=UTC), datetime(1970, 1, 2, tzinfo=UTC))
    )
    monkeypatch.setattr(gate, "MAX_CALIBRATION_RECORDS", 0)
    execution = loader.run_folded_source(
        __import__("sigwood.common.loader.pipeline", fromlist=["_SOURCE_LOADERS"])._SOURCE_LOADERS[
            "zeek_dir"
        ],
        snapshot,
        "conn*.log*",
        window,
        loader.SinkPlan((gate.calibration_sink(),), preserve_frame=False),
    )
    assert execution.statuses[gate.CHANNEL].state is loader.PreparedState.ABSTAINED
    assert gate.CHANNEL not in execution.results
