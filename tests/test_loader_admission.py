"""Transactional report admission and population metadata at the loader boundary."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import gzip
import os

import pandas as pd
import pytest

from sigwood.common.loader import fold, pipeline, types as t, windowing

UTC = timezone.utc
START = datetime(2026, 1, 2, tzinfo=UTC)
PATTERN = "*.log*"


def window():
    return t.DualWindow((START, START + timedelta(days=1)))


def chunk(values=(0, 1, 2), report=None, key=""):
    frame = pd.DataFrame({"ts": [START.timestamp() + n for n in values],
                          "value": list(values)})
    return t.DecodedChunk(frame, 10, report or (True,) * len(frame),
                          (False,) * len(frame), 0, file_key=key)


def admission(callback=None):
    return t.AdmitSink("candidate", callback or (lambda c: c.frame.assign(extra=1)),
                       ("ts", "value", "extra"))


def snapshot(tmp_path, count=1):
    paths = []
    for i in range(count):
        path = tmp_path / f"source-{i}.log"
        path.write_text("record\n")
        paths.append(path)
    return fold.build_source_snapshot(paths, "syslog_dir")


def sink(name="counter", abort=None, seen=None):
    def consume(delta, c, mask):
        if seen is not None:
            seen.append((c.file_key, c.frame.copy()))
        return t.FoldDelta(delta.value + len(c.frame), 1)
    return t.FoldSink(name, lambda: t.FoldDelta(0, 0), consume, lambda: 0,
                      lambda state, delta: state + delta.value,
                      lambda frame: t.PositionalMask((True,) * len(frame)), abort)


def execute(tmp_path, callback=None, chunks=None, folds=()):
    snap = snapshot(tmp_path)
    return fold.execute_sink_plan(snap, t.SinkPlan(folds, admit=admission(callback)),
                                  lambda item: iter(chunks if chunks is not None else [chunk()]))


def test_admission_selects_report_subset_and_keeps_population(tmp_path):
    result = execute(tmp_path, lambda c: c.frame.iloc[[2]].assign(extra=7),
                     [chunk(report=(True, False, True))])
    assert result.frame.value.tolist() == [2]
    assert result.frame.extra.tolist() == [7]
    assert result.population == t.PopulationFacts(2, (START, START + timedelta(seconds=2)))
    assert next(iter(result.file_spans.values())) == (START.timestamp(), START.timestamp() + 2)
    assert result.statuses["candidate"].state is t.PreparedState.READY


@pytest.mark.parametrize("bad", ["outside", "order", "duplicate", "foreign", "columns", "values", "type", "exception", "mutate", "bool"])
def test_admission_rejects_invalid_selection_without_harming_folds(tmp_path, bad):
    seen = []
    def callback(c):
        result = c.frame.assign(extra=1)
        if bad == "outside": return result.iloc[[1]]
        if bad == "order": return result.iloc[[2, 0]]
        if bad == "duplicate": return result.iloc[[0, 0]]
        if bad == "foreign": return result.iloc[[0]].set_axis([99])
        if bad == "columns": return result[["extra", "ts", "value"]]
        if bad == "values": return result.iloc[[0]].assign(value=99)
        if bad == "type": return [1]
        if bad == "exception": raise ValueError("first cause")
        if bad == "bool": return result.iloc[[0]].set_axis([True])
        c.frame.loc[0, "value"] = 99
        return c.frame.iloc[[0]].assign(extra=1)
    result = execute(tmp_path, callback, [chunk(report=(True, False, True))], (sink(seen=seen),))
    assert result.statuses["candidate"].state is t.PreparedState.FAILED
    assert result.statuses["counter"].state is t.PreparedState.READY
    assert result.results["counter"] == 3
    assert seen[0][1].value.tolist() == [0, 1, 2]
    assert result.frame.empty
    assert list(result.frame.columns) == ["ts", "value", "extra"]
    assert result.population.rows == 2


@pytest.mark.parametrize("shape", ["empty-file", "reject-all", "no-files", "failed"])
def test_declared_empty_schema(tmp_path, shape):
    snap = snapshot(tmp_path, 0 if shape == "no-files" else 1)
    calls = []
    def callback(c):
        calls.append(c)
        if shape == "failed": raise RuntimeError("failed")
        return c.frame.iloc[:0].assign(extra=pd.Series(dtype=int))
    result = fold.execute_sink_plan(snap, t.SinkPlan(admit=admission(callback)),
                                    lambda item: [] if shape == "empty-file" else [chunk()])
    assert result.frame.empty
    assert list(result.frame.columns) == ["ts", "value", "extra"]
    assert bool(calls) == (shape in {"reject-all", "failed"})
    assert result.population.rows == (3 if calls else 0)
    assert result.statuses["candidate"].state is (t.PreparedState.FAILED if shape == "failed" else t.PreparedState.READY)


def test_failure_discards_prior_files_and_preserves_first_cause(tmp_path):
    snap = snapshot(tmp_path, 3)
    calls = []
    def callback(c):
        calls.append(c.file_key)
        if len(calls) == 2: raise RuntimeError("first cause")
        return c.frame.assign(extra=1)
    result = fold.execute_sink_plan(snap, t.SinkPlan((sink(),), admit=admission(callback)), lambda item: [chunk()])
    assert len(calls) == 2
    assert result.frame.empty
    assert "first cause" in result.statuses["candidate"].cause
    assert result.population.rows == 9
    assert result.results["counter"] == 9


@pytest.mark.parametrize("failure", ["read", "mutation", "foreign"])
def test_abort_on_file_discard_and_population_rollback(tmp_path, failure):
    snap = snapshot(tmp_path)
    calls = []
    def source(item):
        yield chunk()
        if failure == "read": raise OSError("read failed")
        if failure == "foreign": yield chunk(key="foreign")
        else: item.path.write_text("edited\n")
    result = fold.execute_sink_plan(snap, t.SinkPlan((sink(abort=lambda state: calls.append(state) or state),), admit=admission()), source)
    assert calls == [0]
    assert result.population.rows == 0
    assert result.frame.empty
    assert not result.file_spans
    assert result.committed_files == 0
    assert result.statuses["counter"].state is (t.PreparedState.FAILED if failure == "mutation" else t.PreparedState.READY)


def test_abort_exception_is_channel_local_and_returned_state_is_retained(tmp_path):
    snap = snapshot(tmp_path, 2)
    def abort(state): raise ValueError("abort broke")
    def source(item):
        yield chunk()
        if item == snap.files[0]: raise OSError("read failed")
    result = fold.execute_sink_plan(snap, t.SinkPlan((sink("bad", abort), sink("good", lambda state: state + 10))), source)
    assert result.statuses["bad"].state is t.PreparedState.FAILED
    assert "abort broke" in result.statuses["bad"].cause
    assert result.statuses["good"].state is t.PreparedState.READY
    assert result.results["good"] == 13


def test_cancellation_propagates(tmp_path):
    def callback(c): raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt): execute(tmp_path, callback)


def test_executor_stamps_empty_file_identity(tmp_path):
    seen = []
    result = execute(tmp_path, folds=(sink(seen=seen),))
    assert seen[0][0] == str((tmp_path / "source-0.log").resolve())
    assert result.population.rows == 3


def test_channels_are_unique_across_fold_and_admission():
    with pytest.raises(ValueError, match="unique"):
        t.SinkPlan((sink("candidate"),), admit=admission())


def load_admitted(tmp_path, select, lines=None):
    path = tmp_path / "input.log"
    path.write_text(lines if lines is not None else
                    "2026-01-02T00:00:00Z node app: first\n2026-01-02T00:00:10Z node app: second\n")
    columns = tuple(pipeline._SOURCE_LOADERS["syslog_dir"].columns) + ("extra",)
    admit = t.AdmitSink("candidate", lambda c: select(c.frame).assign(extra=1), columns)
    return pipeline.load_required_logs(
        {PATTERN: "syslog_dir"}, {"syslog_dir": [path]},
        trusted_files={PATTERN: [path]}, show_progress=False,
        sink_plans={PATTERN: t.SinkPlan(admit=admit)}, dual_windows={PATTERN: window()},
    )


@pytest.mark.parametrize("keep", [False, True])
def test_admission_only_pipeline_population_and_default_window(tmp_path, keep):
    result = load_admitted(tmp_path, lambda df: df.iloc[[0]] if keep else df.iloc[:0])
    expected = (START, START + timedelta(seconds=10))
    assert result.record_counts == {PATTERN: 2}
    assert result.data_window == expected
    assert result.population[PATTERN] == t.PopulationFacts(2, expected)
    assert PATTERN not in result.coverage
    assert result.file_spans[PATTERN][0].first_ts == START.timestamp()
    changed = windowing.apply_default_window(result, [PATTERN], timedelta(seconds=1), keep_null=True)
    assert changed.population == result.population
    assert changed.record_counts == result.record_counts
    assert changed.data_window == expected
    pd.testing.assert_frame_equal(changed.logs[PATTERN], result.logs[PATTERN])
    assert replace(result, warnings=["note"]).population == result.population


def test_mixed_population_window_anchors_ordinary_sibling():
    first = pd.DataFrame({"ts": [START.timestamp()], "value": [1]})
    ordinary = pd.DataFrame({"ts": [START.timestamp(), START.timestamp() + 9]})
    facts = t.PopulationFacts(20, (START, START + timedelta(seconds=10)))
    result = t.LoadResult({"admitted": first, "ordinary": ordinary}, {}, population={"admitted": facts})
    changed = windowing.apply_default_window(result, ["admitted", "ordinary"], timedelta(seconds=2), keep_null=True)
    assert changed.record_counts == {"admitted": 20, "ordinary": 1}
    assert changed.data_window == facts.window
    assert len(changed.logs["admitted"]) == 1


def test_null_population_has_count_without_fabricated_window(tmp_path):
    c = chunk()
    c.frame["ts"] = float("nan")
    result = execute(tmp_path, lambda c: c.frame.iloc[:0].assign(extra=1), [c])
    assert result.population == t.PopulationFacts(3, None)
    counts, win = t._population_metadata({PATTERN: result.frame}, {PATTERN: result.population})
    assert counts == {PATTERN: 3}
    assert win is None


@pytest.mark.parametrize("policy", ["prefix", "whole"])
@pytest.mark.parametrize("terminated", [False, True])
def test_tail_policy_stays_at_captured_bytes_across_append(tmp_path, policy, terminated):
    path = tmp_path / "tail.log"
    text = "first\nsecond" + ("\n" if terminated else "")
    path.write_text(text)
    snap = fold.build_source_snapshot([path], "syslog_dir", tail_policy=policy)
    expected = text if terminated or policy == "whole" else "first\n"
    for _ in range(2):
        with fold.open_snapshot_text(snap.files[0]) as handle: assert handle.read() == expected
        with path.open("a") as handle: handle.write(" appended\n")
        fold.verify_snapshot_file(snap.files[0])


@pytest.mark.parametrize("policy", ["prefix", "whole"])
@pytest.mark.parametrize("mutation", ["replace", "truncate", "edit"])
def test_snapshot_rejects_mutation_under_both_policies(tmp_path, policy, mutation):
    path = tmp_path / "source.log"
    path.write_text("first\n")
    item = fold.build_source_snapshot([path], "syslog_dir", tail_policy=policy).files[0]
    if mutation == "replace":
        other = tmp_path / "other.log"; other.write_text("first\n"); other.replace(path)
    elif mutation == "truncate": path.write_text("")
    else:
        path.write_text("other\n"); os.utime(path, ns=(item.mtime_ns, item.mtime_ns))
    with pytest.raises(fold.SnapshotMutationError):
        with fold.open_snapshot_text(item): pass


@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("policy", ["prefix", "whole"])
def test_two_pass_scan_counts(tmp_path, monkeypatch, compressed, policy):
    path = tmp_path / ("source.log.gz" if compressed else "source.log")
    text = "2026-01-02T00:00:00Z node app: record\n"
    if compressed:
        with gzip.open(path, "wt") as handle: handle.write(text)
    else: path.write_text(text)
    calls = {"hash": 0, "boundary": 0, "decode": 0}
    def count(owner, name, key):
        original = getattr(owner, name)
        def wrapped(*args, **kwargs):
            calls[key] += 1
            return original(*args, **kwargs)
        monkeypatch.setattr(owner, name, wrapped)
    count(fold, "_hash_prefix", "hash")
    count(fold, "_plain_readable_boundary", "boundary")
    count(pipeline, "open_snapshot_text", "decode")
    snap = fold.build_source_snapshot([path], "syslog_dir", tail_policy=policy)
    assert calls["hash"] == 1
    for pass_no in range(2):
        pipeline.run_folded_source(pipeline._SOURCE_LOADERS["syslog_dir"], snap, PATTERN, window(), t.SinkPlan((sink(),)))
        assert calls["hash"] == 1 + (pass_no + 1) * 2
    assert calls == {"hash": 5, "boundary": int(not compressed and policy == "prefix"), "decode": 2}


def test_build_identity_recheck_rejects_replaced_file(tmp_path, monkeypatch):
    path = tmp_path / "source.log"; path.write_text("first\n")
    original = fold._hash_prefix
    def replace_after_hash(file, size):
        digest = original(file, size)
        other = tmp_path / "replacement.log"; other.write_text("first\n"); other.replace(file)
        return digest
    monkeypatch.setattr(fold, "_hash_prefix", replace_after_hash)
    with pytest.raises(fold.SnapshotMutationError):
        fold.build_source_snapshot([path], "syslog_dir", tail_policy="whole")


@pytest.mark.parametrize("source", ["stream", "tsv", "ndjson"])
def test_production_chunks_have_file_keys_and_file_local_ordinals(tmp_path, monkeypatch, source):
    monkeypatch.setattr(fold, "MAX_CHUNK_ROWS", 2)
    monkeypatch.setattr(pipeline, "MAX_CHUNK_ROWS", 2)
    paths = []
    for file_no in range(2):
        path = tmp_path / f"input-{file_no}.log"
        if source == "stream":
            text = "".join(f"2026-01-02T00:00:0{i}Z node app: record {i}\n" for i in range(5))
        elif source == "tsv":
            text = "#separator \\x09\n#path\tsyslog\n#fields\tts\thost\tapp_name\tmessage\n#types\ttime\tstring\tstring\tstring\n"
            text += "".join(f"{START.timestamp() + i}\tnode\tapp\trecord {i}\n" for i in range(5))
        else:
            import json
            text = "".join(json.dumps({"ts": START.timestamp() + i, "host": "node", "app_name": "app", "message": f"record {i}"}) + "\n" for i in range(5))
        path.write_text(text)
        paths.append(path)
    family = "syslog_dir" if source == "stream" else "zeek_dir"
    pattern = PATTERN if source == "stream" else "syslog.log"
    snap = fold.build_source_snapshot(paths, family)
    seen = []
    def consume(delta, c, mask):
        seen.append((c.file_key, c.first_ordinal))
        return t.FoldDelta(0, 0)
    counter = replace(sink(), consume=consume)
    result = pipeline.run_folded_source(pipeline._SOURCE_LOADERS[family], snap, pattern, window(), t.SinkPlan((counter,)))
    assert not result.file_errors
    assert seen == [(str(path.resolve()), ordinal) for path in paths for ordinal in (0, 2, 4)]


@pytest.mark.parametrize("shape", ["no-files", "empty-file", "outside", "null"])
def test_pipeline_empty_and_parse_gap_coverage(tmp_path, monkeypatch, shape):
    path = tmp_path / "input.log"
    path.write_text("2026-01-02T00:00:00Z node app: record\n" if shape != "empty-file" else "")
    snap = fold.build_source_snapshot([] if shape == "no-files" else [path], "syslog_dir")
    columns = tuple(pipeline._SOURCE_LOADERS["syslog_dir"].columns) + ("extra",)
    if shape == "null":
        strategy = pipeline._SOURCE_LOADERS["syslog_dir"]
        def parse(reader, **kwargs):
            for _ in reader:
                yield dict.fromkeys(strategy.columns) | {"ts": float("nan"), "message": "message", "host": "node", "program": "app"}
        monkeypatch.setitem(pipeline._SOURCE_LOADERS, "syslog_dir", replace(strategy, parse=parse))
    target_window = t.DualWindow((START + timedelta(days=2), START + timedelta(days=3))) if shape == "outside" else window()
    result = pipeline.load_required_logs(
        {PATTERN: "syslog_dir"}, {"syslog_dir": [path]}, show_progress=False,
        prepared_snapshots={PATTERN: snap},
        sink_plans={PATTERN: t.SinkPlan(admit=t.AdmitSink("candidate", lambda c: c.frame.iloc[:0].assign(extra=1), columns))},
        dual_windows={PATTERN: target_window},
    )
    assert result.logs[PATTERN].empty
    assert list(result.logs[PATTERN].columns) == list(columns)
    assert not result.warnings, result.warnings
    assert result.population[PATTERN].rows == (1 if shape == "null" else 0)
    assert result.population[PATTERN].window is None
    if shape == "null":
        assert PATTERN not in result.coverage
    else:
        cov = result.coverage[PATTERN]
        assert cov.full_rows == (None if shape == "no-files" else 1 if shape == "outside" else 0)


def test_admission_schema_survives_conn_empty_fallback(tmp_path):
    snap = snapshot(tmp_path, 0)
    columns = ("ts", "extra")
    result = pipeline.run_folded_source(
        pipeline._SOURCE_LOADERS["zeek_dir"], snap, "conn.log", window(),
        t.SinkPlan(admit=t.AdmitSink("candidate", lambda c: c.frame, columns)),
    )
    assert list(result.frame.columns) == list(columns)
    assert result.statuses["candidate"].state is t.PreparedState.READY


def test_foreign_identity_rolls_back_only_failed_file(tmp_path):
    snap = snapshot(tmp_path, 3)
    seen = []
    aborts = []
    def source(item):
        if item == snap.files[1]:
            yield chunk(key="foreign")
        else:
            yield chunk()
    result = fold.execute_sink_plan(snap, t.SinkPlan((sink(abort=lambda state: aborts.append(state) or state),),
        admit=admission(lambda c: seen.append(c.file_key) or c.frame.assign(extra=1))), source)
    assert seen == [str(item.resolved_path) for item in (snap.files[0], snap.files[2])]
    assert aborts == [3]
    assert result.population.rows == 6
    assert result.results["counter"] == 6
    assert len(result.frame) == 6


@pytest.mark.parametrize("compressed", [True, False])
def test_whole_unchanged_frames_match_default_on_terminated_input(tmp_path, compressed):
    path = tmp_path / ("source.log.gz" if compressed else "source.log")
    text = "2026-01-02T00:00:00Z node app: record\n"
    if compressed:
        with gzip.open(path, "wt") as handle: handle.write(text)
    else: path.write_text(text)
    results = []
    for policy in ("prefix", "whole"):
        snap = fold.build_source_snapshot([path], "syslog_dir", tail_policy=policy)
        results.append(pipeline.run_folded_source(pipeline._SOURCE_LOADERS["syslog_dir"], snap, PATTERN, window(), t.SinkPlan((sink(),))))
    pd.testing.assert_frame_equal(results[0].frame, results[1].frame)
    assert results[0].results == results[1].results


def test_nested_object_mutation_cannot_falsify_membership_or_alter_fold(tmp_path):
    original = chunk()
    original.frame["raw"] = [{"value": n} for n in range(3)]
    seen = []
    def callback(c):
        c.frame.loc[0, "raw"]["value"] = 99
        return c.frame.assign(extra=1)
    admit = t.AdmitSink("candidate", callback, ("ts", "value", "raw", "extra"))
    result = fold.execute_sink_plan(snapshot(tmp_path), t.SinkPlan((sink(seen=seen),), admit=admit), lambda item: [original])
    assert result.statuses["candidate"].state is t.PreparedState.FAILED
    assert original.frame.loc[0, "raw"] == {"value": 0}
    assert seen[0][1].loc[0, "raw"] == {"value": 0}


def test_explicit_declared_empty_callback_is_a_valid_subset(tmp_path):
    result = execute(tmp_path, lambda c: pd.DataFrame(columns=["ts", "value", "extra"]))
    assert result.statuses["candidate"].state is t.PreparedState.READY
    assert result.population.rows == 3
    assert result.frame.empty
