"""B+D: the named window model - one LoadWindow type, one resolve_load_windows
resolver shared by run() and run_digest(), and the contributor contract (a new
source declares its temporal policy on ONE registry entry - zero runner edits,
zero new accessor, zero digest twin).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import sigwood.common.loader as loader
from sigwood import runner


# ── resolve_load_windows - short-circuits ────────────────────────────────────


def test_resolve_load_windows_short_circuits_on_explicit_window(tmp_path):
    d = tmp_path / "zeek"
    d.mkdir()
    sources = {"conn*.log*": "zeek_dir"}
    dirs = {"zeek_dir": [d]}
    since = datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert loader.resolve_load_windows(
        sources, dirs, "1d", since=since, until=None, load_all=False
    ) == []
    assert loader.resolve_load_windows(
        sources, dirs, "1d", since=None, until=None, load_all=True
    ) == []
    # empty/"all"/invalid default spec → no windows
    assert loader.resolve_load_windows(
        sources, dirs, "all", since=None, until=None, load_all=False
    ) == []


def test_resolve_load_windows_skips_bounded_file_input(tmp_path):
    f = tmp_path / "conn.log"
    f.write_text("{}\n", encoding="utf-8")
    assert loader.resolve_load_windows(
        {"conn*.log*": "zeek_dir"}, {"zeek_dir": [f]}, "1d",
        since=None, until=None, load_all=False,
    ) == []


def test_resolve_load_windows_injects_journal_by_identity_and_plan_order(tmp_path):
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    (zeek / "conn.log").write_text("{}\n", encoding="utf-8")
    capture = tmp_path / "system-journal.jsonl"
    capture.write_text("", encoding="utf-8")
    exact = loader.LoadWindow(
        "journal",
        (
            datetime(2026, 6, 1, tzinfo=timezone.utc),
            datetime(2026, 6, 2, tzinfo=timezone.utc),
        ),
        None,
        False,
    )

    windows = loader.resolve_load_windows(
        {"conn*.log*": "zeek_dir", "*.log*": "journal"},
        {"zeek_dir": [zeek], "journal": [capture]},
        "1d",
        since=None,
        until=None,
        load_all=False,
        pre_resolved_windows={"journal": exact},
    )

    assert len(windows) == 2
    assert windows[1] is exact
    assert [window.source for window in windows] == ["zeek_dir", "journal"]


@pytest.mark.parametrize(
    ("needed", "dirs", "injected"),
    [
        ({"*.log*": "journal"}, {"journal": [Path("capture")]},
         {"syslog_dir": loader.LoadWindow("syslog_dir", None, None, True)}),
        ({"*.log*": "journal"}, {"journal": [Path("capture")]},
         {"journal": loader.LoadWindow("syslog_dir", None, None, True)}),
        ({"*.log*": "journal"}, {"journal": [Path("capture")]},
         {"journal": object()}),
        ({"*.log*": "syslog_dir"}, {"journal": [Path("capture")]},
         {"journal": loader.LoadWindow("journal", None, None, False)}),
        ({"*.log*": "journal"}, {},
         {"journal": loader.LoadWindow("journal", None, None, False)}),
    ],
)
def test_resolve_load_windows_rejects_invalid_journal_injection(
    needed, dirs, injected
):
    with pytest.raises(ValueError):
        loader.resolve_load_windows(
            needed,
            dirs,
            "1d",
            since=None,
            until=None,
            load_all=False,
            pre_resolved_windows=injected,
        )


def test_resolve_load_windows_short_circuit_ignores_injection_validation():
    invalid = {"not-journal": loader.LoadWindow("not-journal", None, None, True)}
    assert loader.resolve_load_windows(
        {},
        {},
        "1d",
        since=datetime(2026, 6, 1, tzinfo=timezone.utc),
        until=None,
        load_all=False,
        pre_resolved_windows=invalid,
    ) == []
    assert loader.resolve_load_windows(
        {},
        {},
        "all",
        since=None,
        until=None,
        load_all=False,
        pre_resolved_windows=invalid,
    ) == []


# ── per-family resolution shapes (the strategy resolver bodies) ───────────────


def test_resolve_load_windows_zeek_dated_precise_no_trim(tmp_path):
    """Dated Zeek layout → precise (since, until) select_window, trim_span None."""
    zd = tmp_path / "zeek"
    zd.mkdir()
    (zd / "2026-01-05").mkdir()
    windows = loader.resolve_load_windows(
        {"conn*.log*": "zeek_dir"}, {"zeek_dir": [zd]}, "1d",
        since=None, until=None, load_all=False,
    )
    assert len(windows) == 1
    w = windows[0]
    assert w.source == "zeek_dir"
    assert w.select_window == (
        datetime(2026, 1, 5, 0, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 1, 5, 23, 59, 59, tzinfo=timezone.utc),
    )
    assert w.trim_span is None
    assert w.keep_null is False  # zeek drops unparseable-ts rows


def test_resolve_load_windows_zeek_flat_load_full_trim(tmp_path):
    """Flat Zeek layout → load full (select_window None) + post-load trim_span."""
    zd = tmp_path / "zeek"
    zd.mkdir()
    (zd / "conn.log").write_text("{}\n", encoding="utf-8")  # flat, no dated subdirs
    windows = loader.resolve_load_windows(
        {"conn*.log*": "zeek_dir"}, {"zeek_dir": [zd]}, "1d",
        since=None, until=None, load_all=False,
    )
    assert len(windows) == 1
    w = windows[0]
    assert w.select_window is None
    assert w.trim_span == timedelta(days=1)


def test_resolve_load_windows_flat_family_conservative_floor(tmp_path):
    """syslog → conservative (floor, None) select_window + precise trim_span;
    keep_null True (syslog retains unparseable-ts rows through the implicit window)."""
    sd = tmp_path / "syslog"
    sd.mkdir()
    (sd / "messages").write_text(
        "Jun  5 12:00:00 host kernel: line\n", encoding="utf-8"
    )
    span = timedelta(days=1)
    windows = loader.resolve_load_windows(
        {"*.log*": "syslog_dir"}, {"syslog_dir": [sd]}, "1d",
        since=None, until=None, load_all=False,
    )
    assert len(windows) == 1
    w = windows[0]
    assert w.select_window is not None and w.select_window[1] is None
    assert w.select_window[0] == loader._peek_first_ts(sd / "messages") - span
    assert w.trim_span == span
    assert w.keep_null is True


def test_resolve_load_windows_cloudtrail_opts_out(tmp_path):
    """CloudTrail is baseline-relative → default_window_eligible False → no window."""
    ct = tmp_path / "ct"
    ct.mkdir()
    (ct / "events.json").write_text("[]\n", encoding="utf-8")
    assert loader.resolve_load_windows(
        {"*.json*": "cloudtrail_dir"}, {"cloudtrail_dir": [ct]}, "1d",
        since=None, until=None, load_all=False,
    ) == []


# ── the contributor contract (Doneness #2) ───────────────────────────────────


def _fake_flat_source(**overrides) -> loader.SourceLoader:
    """A hypothetical new flat source: ONE registry entry declaring only the
    genuinely-variable bits - NO resolve_window, NO window_select, default
    default_window_eligible=True. The fixture for the zero-runner-edits contract."""
    base = loader.SourceLoader(
        discover=lambda p, pattern, since, until: (
            sorted(p.glob("*.log")) if p.is_dir() else [p]
        ),
        mode="stream",
        parse=lambda line_iter, *, path, warnings: iter(()),
        ts_policy="keep",
        columns=["ts", "message"],
        should_skip=None,
        normalize=None,
    )
    return replace(base, **overrides) if overrides else base


def test_contributor_contract_new_source_inherits_universal_default(
    tmp_path, monkeypatch
):
    """A new flat source declaring NO resolve_window inherits the universal default
    window (load full + post-load trim) with zero runner edits, zero new accessor,
    and zero digest twin - resolved by the ONE resolve_load_windows entry point."""
    monkeypatch.setitem(loader._SOURCE_LOADERS, "fake_dir", _fake_flat_source())
    d = tmp_path / "fakesrc"
    d.mkdir()
    windows = loader.resolve_load_windows(
        {"*.log": "fake_dir"}, {"fake_dir": [d]}, "1d",
        since=None, until=None, load_all=False,
    )
    assert len(windows) == 1
    w = windows[0]
    assert w.source == "fake_dir"
    assert w.select_window is None        # universal default = load full
    assert w.trim_span == timedelta(days=1)
    assert w.keep_null is True            # read straight off ts_policy="keep"


def test_contributor_contract_new_source_can_opt_out(tmp_path, monkeypatch):
    """A baseline-relative new source opts out via default_window_eligible=False on
    its entry (the cloudtrail pattern) - still zero runner edits, no source-name
    branch - and mints no LoadWindow."""
    monkeypatch.setitem(
        loader._SOURCE_LOADERS,
        "fake_dir",
        _fake_flat_source(default_window_eligible=False),
    )
    d = tmp_path / "fakesrc"
    d.mkdir()
    assert loader.resolve_load_windows(
        {"*.log": "fake_dir"}, {"fake_dir": [d]}, "1d",
        since=None, until=None, load_all=False,
    ) == []


# ── digest preservation: window resolution is Zeek-ONLY (caller-side gate) ─────


def test_digest_window_resolution_is_zeek_only(tmp_path, monkeypatch, capsys):
    """run_digest invokes the SHARED resolver for the Zeek source ONLY; non-Zeek
    digest directories (syslog/cloudtrail) never resolve a default window → load
    full, exactly as before the twin was deleted. Pinned via a spy on the one
    resolver, exercised on the dry-run path (window resolution runs pre-load)."""
    calls: list[Any] = []
    real = loader.resolve_load_windows

    def spy(needed_sources, *a, **k):
        calls.append(needed_sources)
        return real(needed_sources, *a, **k)

    monkeypatch.setattr(loader, "resolve_load_windows", spy)

    zd = tmp_path / "zeek"
    zd.mkdir()
    runner.run_digest(
        config={"sigwood": {"zeek_dir": str(zd)}}, schema="conn", dry_run=True
    )
    assert len(calls) == 1, "zeek digest resolves the default window"

    calls.clear()
    sd = tmp_path / "syslog"
    sd.mkdir()
    runner.run_digest(
        config={"sigwood": {"syslog_dir": str(sd)}}, schema="syslog", dry_run=True
    )
    ct = tmp_path / "ct"
    ct.mkdir()
    runner.run_digest(
        config={"sigwood": {"cloudtrail_dir": str(ct)}},
        schema="cloudtrail", dry_run=True,
    )
    assert calls == [], "non-Zeek digests never resolve a default window (load full)"
