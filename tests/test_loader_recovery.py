"""Pattern replacement retains precise accounting for independent source loads."""
from dataclasses import replace

import pandas as pd
import pytest

from sigwood.common import loader
from sigwood.common.loader import types as t


def result(patterns):
    frames = {name: pd.DataFrame({"ts": [float(index)]}) for index, name in enumerate(patterns)}
    contributions = {name: t.PatternContribution(10 + index, ("same.log: unreadable",))
                     for index, name in enumerate(patterns)}
    counts, window = t._population_metadata(frames, {})
    return t.LoadResult(frames, counts, window, warnings=["same.log: unreadable"] * len(patterns),
                        data_size_bytes=sum(c.data_size_bytes for c in contributions.values()),
                        contributions=contributions)


@pytest.mark.parametrize("present", [True, False])
def test_replacement_removes_only_owned_pattern_and_channels(present):
    old, fresh = result(["bad", "keep"]), result(["bad"])
    fields = ["coverage", "rotation_skips", "permission_skips", "file_spans", "quality",
              "snapshots", "fold_results", "availability"]
    for field in fields:
        setattr(old, field, {"bad": object(), "keep": object()})
        setattr(fresh, field, {"bad": object()} if present else {})
    old.prepared_status = {"bad.admit": t.PreparedStatus(t.PreparedState.FAILED),
                           "other": t.PreparedStatus(t.PreparedState.READY)}
    fresh.contributions["bad"] = t.PatternContribution(44, ("reload warning",))
    fresh.data_size_bytes, fresh.warnings = 44, ["reload warning"]
    plan = t.SinkPlan((), admit=t.AdmitSink("bad.admit", lambda c: c.frame, ("ts",)))
    rebuilt = loader.replace_pattern_load(old, "bad", plan, fresh)
    assert rebuilt.data_size_bytes == 55
    assert rebuilt.warnings == ["reload warning", "same.log: unreadable"]
    assert rebuilt.prepared_status == {"other": old.prepared_status["other"]}
    assert rebuilt.logs["keep"] is old.logs["keep"]
    assert rebuilt.logs["bad"] is fresh.logs["bad"]
    for field in fields:
        assert getattr(rebuilt, field)["keep"] is getattr(old, field)["keep"]
        if present:
            assert getattr(rebuilt, field)["bad"] is getattr(fresh, field)["bad"]
        else:
            assert "bad" not in getattr(rebuilt, field)
    assert old.data_size_bytes == 21
    assert old.warnings == ["same.log: unreadable"] * 2


def test_replacement_requires_complete_accounting():
    old = result(["bad"])
    fresh = replace(old, contributions={})
    with pytest.raises(ValueError, match="contributions"):
        loader.replace_pattern_load(old, "bad", t.SinkPlan(()), fresh)


def test_loader_contributions_cover_missing_and_selected_inputs(tmp_path):
    source = tmp_path / "sample.log"
    source.write_text("2026-01-02T00:00:00Z fixture-host app: event\n")
    loaded = loader.load_required_logs({"*.log*": "syslog_dir", "dns*.log*": "zeek_dir"},
                                      {"syslog_dir": [source]}, show_progress=False)
    assert list(loaded.contributions) == ["*.log*", "dns*.log*"]
    assert loaded.data_size_bytes == source.stat().st_size
    assert loaded.contributions["dns*.log*"].data_size_bytes == 0
    assert loaded.warnings == [w for c in loaded.contributions.values() for w in c.warnings]
    assert loaded.contributions["dns*.log*"].warnings
