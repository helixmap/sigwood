from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

import sigwood.common.loader as loader
import sigwood.common.loader.pipeline as pipeline
from sigwood.runner import (
    _build_dual_window,
    _positional_allowlist_mask,
    _resolve_fold_dual_window,
)


UTC = timezone.utc


def _window() -> loader.DualWindow:
    start = datetime(2026, 1, 2, tzinfo=UTC)
    return loader.DualWindow(
        (start, start + timedelta(days=1)),
        (start - timedelta(days=1), start - timedelta(microseconds=1)),
    )


def _chunk(value: str = "kept") -> loader.DecodedChunk:
    frame = pd.DataFrame({"ts": [datetime(2026, 1, 2, tzinfo=UTC).timestamp()], "value": [value]})
    return loader.DecodedChunk(frame, 10, (True,), (False,), 0)


def _count_sink(channel: str, *, fail: bool = False, bytes_: int = 1) -> loader.FoldSink:
    def consume(delta, chunk, mask):
        if fail:
            raise RuntimeError("boom")
        return loader.FoldDelta(delta.value + sum(mask.keep), bytes_)

    return loader.FoldSink(
        channel=channel,
        seed_file=lambda: loader.FoldDelta(0, 0),
        consume=consume,
        seed_run=lambda: 0,
        commit_file=lambda run, delta: run + delta.value,
        mask=lambda frame: loader.PositionalMask(tuple(True for _ in range(len(frame)))),
    )


def test_dual_window_requires_strictly_earlier_context():
    start = datetime(2026, 1, 2, tzinfo=UTC)
    with pytest.raises(ValueError, match="strictly before"):
        loader.DualWindow((start, start), (start - timedelta(days=1), start))
    window = _build_dual_window(
        (start, start + timedelta(hours=1)),
        (start - timedelta(hours=1), start - timedelta(microseconds=1)),
    )
    assert window.membership(start.timestamp()) == (True, False)
    assert window.membership((start - timedelta(seconds=1)).timestamp()) == (False, True)


@pytest.mark.parametrize(
    ("bounded_explicit", "load_all"),
    [(True, False), (False, True)],
)
def test_bounded_explicit_and_all_never_gain_implicit_context(
    bounded_explicit,
    load_all,
):
    start = datetime(2026, 1, 2, tzinfo=UTC)
    window = _resolve_fold_dual_window(
        (start, start + timedelta(days=1)),
        available_start=start - timedelta(days=2),
        bounded_explicit=bounded_explicit,
        load_all=load_all,
    )
    assert window.context_interval is None


def test_unbounded_fold_context_ends_one_microsecond_before_report():
    start = datetime(2026, 1, 2, tzinfo=UTC)
    available = start - timedelta(days=2)
    window = _resolve_fold_dual_window(
        (start, start + timedelta(days=1)),
        available_start=available,
        bounded_explicit=False,
        load_all=False,
    )
    assert window.context_interval == (available, start - timedelta(microseconds=1))


def test_positional_allowlist_mask_ignores_duplicate_source_index():
    class Matcher:
        def filter_df(self, frame, channel):
            assert channel == "lane"
            return frame.iloc[[0, 2]].copy()

    frame = pd.DataFrame({"query": ["a", "b", "c"]}, index=[7, 7, 7])
    assert _positional_allowlist_mask(frame, Matcher(), "lane").keep == (True, False, True)


def test_common_record_limit_exact_and_one_over_are_constant_derived():
    exact = "x" * loader.MAX_LOGICAL_RECORD_BYTES
    over = "x" * (loader.MAX_LOGICAL_RECORD_BYTES + 1)
    reader = loader.BoundedLogicalRecordReader([exact, over, "ok"])
    assert list(reader) == [exact, "ok"]
    assert reader.skipped_oversize == 1


def test_multiline_document_uses_same_common_record_limit():
    first = "{\n"
    rest = "x" * loader.MAX_LOGICAL_RECORD_BYTES
    reader = loader.BoundedLogicalRecordReader([first, rest, "}\n"])
    assert next(reader) == first
    assert reader.collect_document(first) is None
    assert reader.skipped_oversize == 1


def test_chunk_caps_exact_and_one_over_without_giant_allocation():
    class SizedFrame:
        def __init__(self, rows):
            self.rows = rows

        def __len__(self):
            return self.rows

    loader.DecodedChunk(
        SizedFrame(loader.MAX_CHUNK_ROWS),
        loader.MAX_CHUNK_DECODED_BYTES,
        (False,) * loader.MAX_CHUNK_ROWS,
        (False,) * loader.MAX_CHUNK_ROWS,
        0,
    )
    with pytest.raises(ValueError, match="row limit"):
        loader.DecodedChunk(
            SizedFrame(loader.MAX_CHUNK_ROWS + 1),
            0,
            (False,) * (loader.MAX_CHUNK_ROWS + 1),
            (False,) * (loader.MAX_CHUNK_ROWS + 1),
            0,
        )
    with pytest.raises(ValueError, match="byte limit"):
        loader.DecodedChunk(SizedFrame(0), loader.MAX_CHUNK_DECODED_BYTES + 1, (), (), 0)


def test_keep_policy_null_timestamp_remains_in_report_frame():
    chunks = list(
        loader.chunks_from_rows(
            [({"ts": float("nan"), "value": "kept"}, 4)],
            columns=["ts", "value"],
            window=_window(),
            keep_null=True,
        )
    )
    assert chunks[0].report_mask == (True,)
    assert chunks[0].context_mask == (False,)


def test_snapshot_ignores_append_but_refuses_prefix_mutation(tmp_path):
    path = tmp_path / "live.log"
    path.write_text("one\ntwo\npartial", encoding="utf-8")
    snapshot = loader.build_source_snapshot([path], "flat")
    item = snapshot.files[0]
    assert item.readable_bytes == len("one\ntwo\n".encode())
    with path.open("a", encoding="utf-8") as handle:
        handle.write(" tail")
    loader.verify_snapshot_file(item)
    with loader.open_snapshot_text(item) as handle:
        assert handle.read() == "one\ntwo\n"
    data = path.read_bytes()
    path.write_bytes(b"X" + data[1:])
    with pytest.raises(loader.SnapshotMutationError, match="content changed"):
        loader.verify_snapshot_file(item)


def test_snapshot_refuses_equal_size_equal_mtime_rewrite(tmp_path):
    path = tmp_path / "stable.log"
    path.write_text("aaaa\n", encoding="utf-8")
    snapshot = loader.build_source_snapshot([path], "flat")
    item = snapshot.files[0]
    path.write_text("bbbb\n", encoding="utf-8")
    os.utime(path, ns=(item.mtime_ns, item.mtime_ns))
    with pytest.raises(loader.SnapshotMutationError, match="content changed"):
        loader.verify_snapshot_file(item)


def test_line_snapshot_excludes_unterminated_only_record(tmp_path):
    path = tmp_path / "growing.log"
    path.write_text("partial", encoding="utf-8")
    item = loader.build_source_snapshot([path], "pihole_dir").files[0]
    assert item.readable_bytes == 0
    with loader.open_snapshot_text(item) as handle:
        assert handle.read() == ""


def test_snapshot_ordered_dedupe_and_content_identity(tmp_path):
    first = tmp_path / "one.log"
    second = tmp_path / "two.log"
    first.write_text("1\n", encoding="utf-8")
    second.write_text("2\n", encoding="utf-8")
    snapshot = loader.build_source_snapshot([first, first, second], "flat")
    assert [item.path for item in snapshot.files] == [first, second]
    assert len(snapshot.identity_sha256) == 64
    assert len(snapshot.content_identity_sha256) == 64


def test_snapshot_content_identity_excludes_only_scan_interval(tmp_path):
    path = tmp_path / "one.log"
    path.write_text("1\n", encoding="utf-8")
    first = datetime(2026, 1, 1, tzinfo=UTC)
    second = datetime(2026, 2, 1, tzinfo=UTC)
    left = loader.build_source_snapshot([path], "flat", scan_interval=(first, second))
    right = loader.build_source_snapshot([path], "flat", scan_interval=(second, None))
    assert left.identity_sha256 != right.identity_sha256
    assert left.content_identity_sha256 == right.content_identity_sha256


def test_snapshot_scan_bound_identity_keeps_pre_c1_canonical_bytes(tmp_path):
    path = tmp_path / "one.log"
    path.write_text("1\n", encoding="utf-8")
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 2, 1, tzinfo=UTC)
    snapshot = loader.build_source_snapshot([path], "flat", scan_interval=(start, end))
    item = snapshot.files[0]
    old_payload = [
        {
            "resolved": str(item.resolved_path),
            "source": item.source,
            "device": item.device,
            "inode": item.inode,
            "compressed": item.compressed,
            "stat_bytes": item.stat_bytes,
            "mtime_ns": item.mtime_ns,
            "readable_bytes": item.readable_bytes,
            "sha256": item.content_sha256,
            "scan": [start.isoformat(), end.isoformat()],
        }
    ]
    encoded = json.dumps(old_payload, sort_keys=True, separators=(",", ":")).encode()
    assert snapshot.identity_sha256 == hashlib.sha256(encoded).hexdigest()


def test_prepared_snapshot_reuse_performs_no_rediscovery_or_recapture(
    tmp_path, monkeypatch,
):
    path = tmp_path / "pihole.log"
    path.write_text(
        "Jan  2 00:00:00 dnsmasq[1]: query[A] a.example from 192.0.2.1\n",
        encoding="utf-8",
    )
    start = datetime(2026, 1, 1, tzinfo=UTC)
    window = loader.DualWindow((start, start + timedelta(days=2)))
    needed = {"pihole*.log*": "pihole_dir"}
    first = loader.load_required_logs(
        needed,
        {"pihole_dir": [path]},
        sink_plans={
            "pihole*.log*": loader.SinkPlan((_count_sink("first"),))
        },
        dual_windows={"pihole*.log*": window},
        show_progress=False,
    )
    snapshot = first.snapshots["pihole*.log*"]
    monkeypatch.setitem(
        pipeline._SOURCE_LOADERS,
        "pihole_dir",
        replace(
            pipeline._SOURCE_LOADERS["pihole_dir"],
            discover=lambda *a, **k: pytest.fail(
                "prepared population must not rediscover"
            ),
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "build_source_snapshot",
        lambda *a, **k: pytest.fail("prepared population must not recapture"),
    )
    second = loader.load_required_logs(
        needed,
        {},
        sink_plans={
            "pihole*.log*": loader.SinkPlan((_count_sink("second"),))
        },
        dual_windows={"pihole*.log*": window},
        prepared_snapshots={"pihole*.log*": snapshot},
        show_progress=False,
    )
    assert second.snapshots["pihole*.log*"].identity_sha256 == snapshot.identity_sha256
    assert second.fold_results["pihole*.log*"]["second"] == 1


def test_prepared_snapshot_rejects_source_mismatch(tmp_path):
    path = tmp_path / "one.log"
    path.write_text("one\n", encoding="utf-8")
    snapshot = loader.build_source_snapshot([path], "syslog_dir")
    with pytest.raises(ValueError, match="belongs to"):
        loader.load_required_logs(
            {"pihole*.log*": "pihole_dir"},
            {},
            sink_plans={"pihole*.log*": loader.SinkPlan((_count_sink("x"),))},
            dual_windows={"pihole*.log*": _window()},
            prepared_snapshots={"pihole*.log*": snapshot},
            show_progress=False,
        )


def test_file_transaction_discards_corrupt_file_and_commits_sibling(tmp_path):
    bad = tmp_path / "bad.log"
    good = tmp_path / "good.log"
    bad.write_text("bad\n", encoding="utf-8")
    good.write_text("good\n", encoding="utf-8")
    snapshot = loader.build_source_snapshot([bad, good], "flat")

    def chunks(item):
        yield _chunk(item.path.stem)
        if item.path == bad:
            raise OSError("truncated")

    result = loader.execute_sink_plan(
        snapshot,
        loader.SinkPlan((_count_sink("ok"),), preserve_frame=True),
        chunks,
    )
    assert result.results == {"ok": 1}
    assert result.frame["value"].tolist() == ["good"]
    assert result.file_errors == ("bad.log: truncated",)


def test_snapshot_mutation_fails_fold_and_discards_all_partial_state(tmp_path):
    path = tmp_path / "live.log"
    path.write_text("one\n", encoding="utf-8")
    snapshot = loader.build_source_snapshot([path], "flat")

    def chunks(item):
        yield _chunk()
        path.write_text("two\n", encoding="utf-8")

    result = loader.execute_sink_plan(
        snapshot,
        loader.SinkPlan((_count_sink("lane"),)),
        chunks,
    )
    assert result.results == {}
    assert result.frame.empty
    assert result.statuses["lane"] == loader.PreparedStatus(
        loader.PreparedState.FAILED,
        "snapshot mutation",
    )


def test_snapshot_mutation_stops_source_but_keeps_prior_frame_sibling(tmp_path):
    first = tmp_path / "first.log"
    changed = tmp_path / "changed.log"
    remainder = tmp_path / "remainder.log"
    for path in (first, changed, remainder):
        path.write_text(f"{path.stem}\n", encoding="utf-8")
    snapshot = loader.build_source_snapshot(
        [first, changed, remainder],
        "flat",
    )
    attempted = []

    def chunks(item):
        attempted.append(item.path)
        yield _chunk(item.path.stem)
        if item.path == changed:
            changed.write_text("mutated\n", encoding="utf-8")

    result = loader.execute_sink_plan(
        snapshot,
        loader.SinkPlan((_count_sink("lane"),), preserve_frame=True),
        chunks,
    )
    assert attempted == [first, changed]
    assert result.frame["value"].tolist() == ["first"]
    assert result.results == {}
    assert result.statuses["lane"] == loader.PreparedStatus(
        loader.PreparedState.FAILED,
        "snapshot mutation",
    )
    assert result.attempted_files == 2
    assert result.committed_files == 1
    assert len(result.file_errors) == 1
    assert "changed.log" in result.file_errors[0]


def test_fold_failure_and_cap_abstention_preserve_frame_sibling(tmp_path):
    path = tmp_path / "one.log"
    path.write_text("one\n", encoding="utf-8")
    snapshot = loader.build_source_snapshot([path], "flat")
    plan = loader.SinkPlan(
        (
            _count_sink("good"),
            _count_sink("at_cap", bytes_=loader.MAX_FILE_DELTA_BYTES),
            _count_sink("failed", fail=True),
            _count_sink("capped", bytes_=loader.MAX_FILE_DELTA_BYTES + 1),
        ),
        preserve_frame=True,
    )
    result = loader.execute_sink_plan(snapshot, plan, lambda item: [_chunk()])
    assert result.results == {"good": 1, "at_cap": 1}
    assert result.statuses["failed"].state is loader.PreparedState.FAILED
    assert result.statuses["capped"].state is loader.PreparedState.ABSTAINED
    assert result.frame["value"].tolist() == ["kept"]


def test_cancellation_propagates_without_commit(tmp_path):
    path = tmp_path / "one.log"
    path.write_text("one\n", encoding="utf-8")
    snapshot = loader.build_source_snapshot([path], "flat")
    commits = []
    sink = loader.FoldSink(
        "lane",
        lambda: loader.FoldDelta(0, 0),
        lambda delta, chunk, mask: loader.FoldDelta(1, 1),
        lambda: 0,
        lambda run, delta: commits.append(delta.value) or delta.value,
        lambda frame: loader.PositionalMask((True,)),
    )

    def chunks(item):
        yield _chunk()
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        loader.execute_sink_plan(snapshot, loader.SinkPlan((sink,)), chunks)
    assert commits == []


def test_run_folded_stream_routes_frame_and_fold_from_same_snapshot(tmp_path):
    path = tmp_path / "events.log"
    start = datetime(2026, 1, 2, tzinfo=UTC)
    rows = [
        {"ts": start.timestamp(), "value": "report"},
        {"ts": (start - timedelta(hours=1)).timestamp(), "value": "context"},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def parse(lines, *, path, warnings):
        for line in lines:
            yield json.loads(line)

    strategy = pipeline.SourceLoader(
        discover=lambda *args, **kwargs: [],
        mode="stream",
        parse=parse,
        ts_policy="drop",
        columns=["ts", "value"],
        should_skip=None,
        normalize=None,
    )
    snapshot = loader.build_source_snapshot([path], "flat")
    result = loader.run_folded_source(
        strategy,
        snapshot,
        "*.log",
        _window(),
        loader.SinkPlan((_count_sink("lane"),), preserve_frame=True),
    )
    assert result.results == {"lane": 2}
    assert result.frame["value"].tolist() == ["report"]


def test_folded_and_ordinary_oversize_parity(tmp_path):
    path = tmp_path / "events.log"
    start = datetime(2026, 1, 2, tzinfo=UTC)
    oversize = "x" * (loader.MAX_LOGICAL_RECORD_BYTES + 1)
    path.write_text(oversize + "\n" + json.dumps({"ts": start.timestamp(), "value": "ok"}) + "\n")

    def parse(lines, *, path, warnings):
        for line in lines:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

    strategy = pipeline.SourceLoader(
        discover=lambda *args, **kwargs: [],
        mode="stream",
        parse=parse,
        ts_policy="drop",
        columns=["ts", "value"],
        should_skip=None,
        normalize=None,
    )
    ordinary_warnings = []
    ordinary_quality = loader.LoadQuality()
    ordinary = loader.run_load(
        strategy,
        [path],
        "*.log",
        None,
        None,
        show_progress=False,
        _warnings=ordinary_warnings,
        _quality=ordinary_quality,
    )
    folded_warnings = []
    folded = loader.run_folded_source(
        strategy,
        loader.build_source_snapshot([path], "flat"),
        "*.log",
        _window(),
        loader.SinkPlan((_count_sink("lane"),)),
        warnings=folded_warnings,
    )
    pd.testing.assert_frame_equal(ordinary, folded.frame)
    assert ordinary.to_json(orient="split") == folded.frame.to_json(orient="split")
    assert ordinary_quality.skipped_oversize == 1
    assert ordinary_warnings == folded_warnings


@pytest.mark.parametrize(
    "body",
    [
        '{"ts":1767312000,"value":"a"}\n{"ts":1767312001,"value":"b"}\n',
        "#separator \\x09\n#fields\tts\tvalue\n#types\ttime\tstring\n1767312000\ta\n1767312001\tb\n#close\n",
    ],
    ids=["ndjson", "tsv"],
)
def test_zeek_fold_chunks_match_ordinary_frame(tmp_path, body):
    path = tmp_path / "weird.log"
    path.write_text(body, encoding="utf-8")
    strategy = pipeline._SOURCE_LOADERS["zeek_dir"]
    ordinary = loader.run_load(
        strategy,
        [path],
        "weird.log",
        None,
        None,
        show_progress=False,
        _warnings=[],
    )
    start = datetime.fromtimestamp(1767312000, tz=UTC)
    folded = loader.run_folded_source(
        strategy,
        loader.build_source_snapshot([path], "zeek_dir"),
        "weird.log",
        loader.DualWindow((start, start + timedelta(seconds=1))),
        loader.SinkPlan((_count_sink("lane"),)),
        warnings=[],
    )
    pd.testing.assert_frame_equal(
        ordinary.reset_index(drop=True),
        folded.frame.reset_index(drop=True),
        check_dtype=False,
    )
    assert folded.results == {"lane": 2}


def test_zeek_fold_ndjson_zero_yield_matches_ordinary_warning(tmp_path):
    path = tmp_path / "dns.log"
    path.write_text('{"broken"\n{"also"\n', encoding="utf-8")
    strategy = pipeline._SOURCE_LOADERS["zeek_dir"]
    ordinary_warnings = []
    ordinary = loader.run_load(
        strategy,
        [path],
        "dns*.log*",
        None,
        None,
        show_progress=False,
        _warnings=ordinary_warnings,
    )
    folded_warnings = []
    folded = loader.run_folded_source(
        strategy,
        loader.build_source_snapshot([path], "zeek_dir"),
        "dns*.log*",
        _window(),
        loader.SinkPlan((_count_sink("lane"),)),
        warnings=folded_warnings,
    )
    assert ordinary.empty
    assert folded.frame.empty
    assert folded.results == {"lane": 0}
    assert folded_warnings == ordinary_warnings == [
        "dns.log: no Zeek records found - is this a Zeek log?"
    ]


def test_zeek_fold_aggregates_syslog_message_warning_across_chunks(
    tmp_path,
    monkeypatch,
):
    first = tmp_path / "syslog.log"
    second = tmp_path / "syslog.1.log"
    first.write_text(
        json.dumps({"ts": 1767312000, "message": None})
        + "\n"
        + json.dumps({"ts": 1767312001, "message": "first"})
        + "\n",
        encoding="utf-8",
    )
    second.write_text(
        json.dumps({"ts": 1767312001, "message": 7})
        + "\n"
        + json.dumps({"ts": 1767312002, "message": "second"})
        + "\n",
        encoding="utf-8",
    )
    paths = [first, second]
    strategy = pipeline._SOURCE_LOADERS["zeek_dir"]
    ordinary_warnings = []
    ordinary = loader.run_load(
        strategy,
        paths,
        "syslog*.log*",
        None,
        None,
        show_progress=False,
        _warnings=ordinary_warnings,
    )
    monkeypatch.setattr(pipeline, "MAX_CHUNK_ROWS", 1)
    folded_warnings = []
    folded = loader.run_folded_source(
        strategy,
        loader.build_source_snapshot(paths, "zeek_dir"),
        "syslog*.log*",
        loader.DualWindow(
            (
                datetime.fromtimestamp(1767312000, tz=UTC),
                datetime.fromtimestamp(1767312002, tz=UTC),
            )
        ),
        loader.SinkPlan((_count_sink("lane"),), preserve_frame=True),
        warnings=folded_warnings,
    )
    pd.testing.assert_frame_equal(
        ordinary.reset_index(drop=True),
        folded.frame.reset_index(drop=True),
        check_dtype=False,
    )
    assert folded_warnings == ordinary_warnings == [
        "syslog.log: skipped 2 rows with a missing or non-text message"
    ]


def test_frame_only_load_does_not_build_content_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "events.log"
    path.write_text("x\n", encoding="utf-8")

    def parse(lines, *, path, warnings):
        for line in lines:
            yield {"ts": 1.0, "value": line.strip()}

    strategy = pipeline.SourceLoader(
        discover=lambda *args, **kwargs: [path],
        mode="stream",
        parse=parse,
        ts_policy="drop",
        columns=["ts", "value"],
        should_skip=None,
        normalize=None,
    )
    monkeypatch.setitem(pipeline._SOURCE_LOADERS, "test_source", strategy)
    monkeypatch.setattr(
        pipeline,
        "build_source_snapshot",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("snapshot tax")),
    )
    result = loader.load_required_logs(
        {"*.log": "test_source"},
        {"test_source": [path]},
        show_progress=False,
    )
    assert result.logs["*.log"]["value"].tolist() == ["x"]


def test_load_required_logs_fold_path_publishes_snapshot_status_and_result(tmp_path, monkeypatch):
    path = tmp_path / "events.log"
    start = datetime(2026, 1, 2, tzinfo=UTC)
    path.write_text(json.dumps({"ts": start.timestamp(), "value": "x"}) + "\n")

    def parse(lines, *, path, warnings):
        for line in lines:
            yield json.loads(line)

    strategy = pipeline.SourceLoader(
        discover=lambda *args, **kwargs: [path],
        mode="stream",
        parse=parse,
        ts_policy="drop",
        columns=["ts", "value"],
        should_skip=None,
        normalize=None,
    )
    monkeypatch.setitem(pipeline._SOURCE_LOADERS, "test_source", strategy)
    result = loader.load_required_logs(
        {"*.log": "test_source"},
        {"test_source": [path]},
        show_progress=False,
        sink_plans={"*.log": loader.SinkPlan((_count_sink("lane"),))},
        dual_windows={"*.log": _window()},
    )
    assert result.fold_results == {"*.log": {"lane": 1}}
    assert result.prepared_status["lane"].state is loader.PreparedState.READY
    assert result.snapshots["*.log"].files[0].path == path
    assert result.snapshots["*.log"].files[0].quality.decoded_records == 1
    assert result.quality["*.log"].committed_files == 1
    assert result.file_spans["*.log"][0].path == path
    assert result.logs["*.log"]["value"].tolist() == ["x"]


def test_folded_empty_report_preserves_pre_window_coverage(tmp_path, monkeypatch):
    path = tmp_path / "events.log"
    ts = datetime(2025, 1, 1, tzinfo=UTC).timestamp()
    path.write_text(json.dumps({"ts": ts, "value": "context"}) + "\n")

    def parse(lines, *, path, warnings):
        for line in lines:
            yield json.loads(line)

    strategy = pipeline.SourceLoader(
        discover=lambda *args, **kwargs: [path],
        mode="stream",
        parse=parse,
        ts_policy="drop",
        columns=["ts", "value"],
        should_skip=None,
        normalize=None,
    )
    monkeypatch.setitem(pipeline._SOURCE_LOADERS, "test_source", strategy)
    result = loader.load_required_logs(
        {"*.log": "test_source"},
        {"test_source": [path]},
        show_progress=False,
        sink_plans={"*.log": loader.SinkPlan((_count_sink("lane"),))},
        dual_windows={
            "*.log": loader.DualWindow(
                (
                    datetime(2026, 1, 1, tzinfo=UTC),
                    datetime(2026, 1, 2, tzinfo=UTC),
                ),
                (
                    datetime(2025, 1, 1, tzinfo=UTC),
                    datetime(2025, 12, 31, tzinfo=UTC),
                ),
            )
        },
    )
    assert result.logs["*.log"].empty
    assert result.coverage["*.log"].full_rows == 1
    assert result.coverage["*.log"].full_span is not None


def test_folded_discarded_frame_does_not_claim_window_exclusion(
    tmp_path, monkeypatch
):
    """A deliberately discarded frame is not evidence of window exclusion."""
    path = tmp_path / "events.log"
    ts = datetime(2026, 1, 1, 12, tzinfo=UTC).timestamp()
    path.write_text(json.dumps({"ts": ts, "value": "kept"}) + "\n")

    def parse(lines, *, path, warnings):
        for line in lines:
            yield json.loads(line)

    strategy = pipeline.SourceLoader(
        discover=lambda *args, **kwargs: [path],
        mode="stream",
        parse=parse,
        ts_policy="drop",
        columns=["ts", "value"],
        should_skip=None,
        normalize=None,
    )
    monkeypatch.setitem(pipeline._SOURCE_LOADERS, "test_source", strategy)
    result = loader.load_required_logs(
        {"*.log": "test_source"},
        {"test_source": [path]},
        show_progress=False,
        sink_plans={
            "*.log": loader.SinkPlan(
                (_count_sink("lane"),), preserve_frame=False
            )
        },
        dual_windows={
            "*.log": loader.DualWindow(
                (
                    datetime(2026, 1, 1, tzinfo=UTC),
                    datetime(2026, 1, 2, tzinfo=UTC),
                )
            )
        },
    )
    assert result.logs["*.log"].empty
    assert result.fold_results["*.log"]["lane"] == 1
    assert "*.log" not in result.coverage


@pytest.mark.parametrize("explicit", [False, True], ids=["rotation-directory", "explicit-file"])
def test_real_pihole_route_preserves_frame_population_for_fold_plan(tmp_path, explicit):
    active = tmp_path / "pihole.log"
    rotated = tmp_path / "pihole.log.1"
    active.write_text(
        "Jun  1 12:00:00 dnsmasq[1]: query[A] current.test from 192.0.2.1\n",
        encoding="utf-8",
    )
    rotated.write_text(
        "May 31 12:00:00 dnsmasq[1]: query[A] prior.test from 192.0.2.2\n",
        encoding="utf-8",
    )
    source_input = active if explicit else tmp_path
    needed = {"pihole*.log*": "pihole_dir"}
    sources = {"pihole_dir": [source_input]}
    ordinary = loader.load_required_logs(needed, sources, show_progress=False)
    folded = loader.load_required_logs(
        needed,
        sources,
        show_progress=False,
        sink_plans={"pihole*.log*": loader.SinkPlan((_count_sink("lane"),))},
        dual_windows={
            "pihole*.log*": loader.DualWindow(
                (
                    datetime(2020, 1, 1, tzinfo=UTC),
                    datetime(2030, 1, 1, tzinfo=UTC),
                )
            )
        },
    )
    pd.testing.assert_frame_equal(
        ordinary.logs["pihole*.log*"].reset_index(drop=True),
        folded.logs["pihole*.log*"].reset_index(drop=True),
    )
    assert folded.fold_results["pihole*.log*"]["lane"] == len(
        ordinary.logs["pihole*.log*"]
    )
