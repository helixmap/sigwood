"""Unit tests for runner helper functions: _derive_data_sources, _dns_nudge, and build_run_plan."""

from __future__ import annotations

import gzip
import io
import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

import sigwood.runner as runner
from sigwood.common.display import TEXT_RULE_WIDTH, default_window_advisory
from sigwood.runner import (
    _DIGEST_TS_CONFIDENCE_FLOOR,
    _aws_no_interactive_note,
    _aws_window_note,
    _check_required_logs,
    _derive_data_sources,
    _dns_nudge,
    _is_optional_satisfiable,
    _print_dry_run,
    _source_overlap_notes,
    _ts_confidence,
    RunPlan,
    build_run_plan,
)


# ── _derive_data_sources ──────────────────────────────────────────────────────

def test_derive_data_sources_zeek_conn_and_dns() -> None:
    needed = {
        "conn*.log*": "zeek_dir",
        "dns*.log*": "zeek_dir",
    }
    counts = {"conn*.log*": 1000, "dns*.log*": 500}
    assert _derive_data_sources(needed, counts) == ["zeek_conn", "zeek_dns"]


def test_derive_data_sources_syslog() -> None:
    needed = {"*.log*": "syslog_dir"}
    counts = {"*.log*": 200}
    assert _derive_data_sources(needed, counts) == ["syslog_raw"]


def test_derive_data_sources_excludes_zero_count() -> None:
    needed = {
        "conn*.log*": "zeek_dir",
        "dns*.log*": "zeek_dir",
    }
    # dns has zero records - must not appear in output
    counts = {"conn*.log*": 50, "dns*.log*": 0}
    assert _derive_data_sources(needed, counts) == ["zeek_conn"]


def test_derive_data_sources_pihole() -> None:
    needed = {"*.log*": "pihole_dir"}
    counts = {"*.log*": 100}
    assert _derive_data_sources(needed, counts) == ["dnsmasq_dns"]


def test_derive_data_sources_cloudtrail() -> None:
    needed = {"*.json": "cloudtrail_dir"}
    counts = {"*.json": 75}
    assert _derive_data_sources(needed, counts) == ["cloudtrail_raw"]


def test_derive_data_sources_unknown_pattern_skipped() -> None:
    # Patterns not in needed_logs produce no label
    needed = {"conn*.log*": "zeek_dir"}
    counts = {"conn*.log*": 10, "mystery*.log*": 5}
    assert _derive_data_sources(needed, counts) == ["zeek_conn"]


def test_derive_data_sources_empty_record_counts() -> None:
    needed = {"conn*.log*": "zeek_dir"}
    assert _derive_data_sources(needed, {}) == []


# ── _dns_nudge ────────────────────────────────────────────────────────────────

def test_dns_nudge_fires_for_dnsmasq_alone() -> None:
    result = _dns_nudge(["dnsmasq_dns"])
    assert result is not None
    assert "Pi-hole" in result or "dnsmasq" in result


def test_dns_nudge_fires_for_dnsmasq_with_non_rich_zeek_source() -> None:
    # zeek_conn is not a rich DNS source - nudge should still fire
    result = _dns_nudge(["dnsmasq_dns", "zeek_conn"])
    assert result is not None


def test_dns_nudge_suppressed_when_zeek_dns_present() -> None:
    assert _dns_nudge(["zeek_dns"]) is None


def test_dns_nudge_suppressed_when_zeek_dns_and_dnsmasq_both_present() -> None:
    assert _dns_nudge(["dnsmasq_dns", "zeek_dns"]) is None


def test_dns_nudge_suppressed_when_no_dns_at_all() -> None:
    assert _dns_nudge(["zeek_conn", "syslog_raw"]) is None


def test_dry_run_uses_shared_text_rule_width(capsys) -> None:
    _print_dry_run(
        zeek_dir=None,
        syslog_dir=None,
        pihole_dir=None,
        cloudtrail_dir=None,
        since=None,
        until=None,
        load_all=False,
        will_run=[],
        skipped={},
    )
    lines = capsys.readouterr().out.splitlines()
    # The dry-run banner is bracketed by DOUBLE rules (run-summary/dry-run polish).
    rule_lines = [line for line in lines if set(line) == {"═"}]

    assert rule_lines
    assert all(len(line) == TEXT_RULE_WIDTH for line in rule_lines)


def test_dry_run_lists_cloudtrail_dir(tmp_path: Path, capsys) -> None:
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    _print_dry_run(
        zeek_dir=None,
        syslog_dir=None,
        pihole_dir=None,
        cloudtrail_dir=cloudtrail_dir,
        since=None,
        until=None,
        load_all=False,
        will_run=[],
        skipped={},
    )
    out = capsys.readouterr().out
    assert "cloudtrail_dir:" in out
    assert str(cloudtrail_dir) in out
    assert "found" in out


# ── DNS run-plan resolution - four source cases ───────────────────────────────

# The reason carries NO detector name - both render surfaces prefix it (no double-name).
_SKIP_REASON = "no DNS source found (need zeek_dir dns logs or pihole_dir logs)"


def _dns_mod() -> SimpleNamespace:
    return SimpleNamespace(
        REQUIRED_LOGS=[],
        OPTIONAL_LOGS=[
            {"source": "zeek_dir",   "pattern": "dns*.log*"},
            {"source": "pihole_dir", "pattern": "pihole*.log*"},
        ],
        REQUIRES_ONE_OF_OPTIONAL=True,
        REQUIRES_ONE_OF_OPTIONAL_REASON=_SKIP_REASON,
    )


def _beacon_mod() -> SimpleNamespace:
    return SimpleNamespace(
        REQUIRED_LOGS=[{"source": "zeek_dir", "pattern": "conn*.log*"}],
        OPTIONAL_LOGS=[],
    )


def test_dns_plan_neither_source_skipped() -> None:
    plan = build_run_plan(
        "all", zeek_dir=None, syslog_dir=None, pihole_dir=None,
        detectors={"dns": _dns_mod()},
    )
    assert plan.will_run == []
    assert plan.skipped["dns"] == _SKIP_REASON


def test_dns_plan_zeek_only_runs(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "dns.log").write_text("", encoding="utf-8")

    plan = build_run_plan(
        "all", zeek_dir=zeek_dir, syslog_dir=None, pihole_dir=None,
        detectors={"dns": _dns_mod()},
    )

    assert "dns" in plan.will_run
    assert "dns" not in plan.skipped
    assert plan.needed_logs == {"dns*.log*": "zeek_dir"}


def test_dns_plan_pihole_only_runs(tmp_path: Path) -> None:
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text("", encoding="utf-8")

    plan = build_run_plan(
        "all", zeek_dir=None, syslog_dir=None, pihole_dir=pihole_dir,
        detectors={"dns": _dns_mod()},
    )

    assert "dns" in plan.will_run
    assert "dns" not in plan.skipped
    assert plan.needed_logs == {"pihole*.log*": "pihole_dir"}


def test_dns_plan_both_sources_runs(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "dns.log").write_text("", encoding="utf-8")
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text("", encoding="utf-8")

    plan = build_run_plan(
        "all", zeek_dir=zeek_dir, syslog_dir=None, pihole_dir=pihole_dir,
        detectors={"dns": _dns_mod()},
    )

    assert "dns" in plan.will_run
    assert plan.needed_logs.get("dns*.log*") == "zeek_dir"
    assert plan.needed_logs.get("pihole*.log*") == "pihole_dir"


def test_dns_plan_zeek_no_dns_files_pihole_satisfies(tmp_path: Path) -> None:
    """When zeek_dir has no dns*.log* but pihole_dir does, only pihole pattern is loaded."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text("", encoding="utf-8")  # no dns*.log*
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text("", encoding="utf-8")

    plan = build_run_plan(
        "all", zeek_dir=zeek_dir, syslog_dir=None, pihole_dir=pihole_dir,
        detectors={"dns": _dns_mod()},
    )

    assert "dns" in plan.will_run
    assert plan.needed_logs == {"pihole*.log*": "pihole_dir"}
    assert "dns*.log*" not in plan.needed_logs


def test_dns_plan_beacon_regression(tmp_path: Path) -> None:
    """Adding pihole_dir=None does not affect a detector with normal REQUIRED_LOGS."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text("", encoding="utf-8")

    plan = build_run_plan(
        "all", zeek_dir=zeek_dir, syslog_dir=None, pihole_dir=None,
        detectors={"beacon": _beacon_mod()},
    )

    assert "beacon" in plan.will_run
    assert "beacon" not in plan.skipped


# ── data_sources via _derive_data_sources on plan.needed_logs ─────────────────

def test_data_sources_dns_zeek_only(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "dns.log").write_text("", encoding="utf-8")
    plan = build_run_plan(
        "all", zeek_dir=zeek_dir, syslog_dir=None, pihole_dir=None,
        detectors={"dns": _dns_mod()},
    )
    assert _derive_data_sources(plan.needed_logs, {"dns*.log*": 500}) == ["zeek_dns"]


def test_data_sources_dns_pihole_only(tmp_path: Path) -> None:
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text("", encoding="utf-8")
    plan = build_run_plan(
        "all", zeek_dir=None, syslog_dir=None, pihole_dir=pihole_dir,
        detectors={"dns": _dns_mod()},
    )
    assert _derive_data_sources(plan.needed_logs, {"pihole*.log*": 100}) == ["dnsmasq_dns"]


def test_data_sources_dns_both(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "dns.log").write_text("", encoding="utf-8")
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text("", encoding="utf-8")
    plan = build_run_plan(
        "all", zeek_dir=zeek_dir, syslog_dir=None, pihole_dir=pihole_dir,
        detectors={"dns": _dns_mod()},
    )
    counts = {"dns*.log*": 500, "pihole*.log*": 100}
    assert _derive_data_sources(plan.needed_logs, counts) == ["dnsmasq_dns", "zeek_dns"]


def test_data_sources_dns_neither() -> None:
    plan = build_run_plan(
        "all", zeek_dir=None, syslog_dir=None, pihole_dir=None,
        detectors={"dns": _dns_mod()},
    )
    assert _derive_data_sources(plan.needed_logs, {}) == []


# ── Stage 4: pattern-aware single-file satisfiability ─────────────────────────


def _beacon_mod():
    import sigwood.detectors.beacon as beacon
    return beacon


def _dns_real_mod():
    import sigwood.detectors.dns as dns
    return dns


def test_check_required_logs_zeek_file_matching_pattern_passes(tmp_path: Path) -> None:
    f = tmp_path / "conn.log"
    f.write_text("", encoding="utf-8")
    assert _check_required_logs(_beacon_mod(), {"zeek_dir": f}) is None


def test_check_required_logs_zeek_file_wrong_pattern_skips(tmp_path: Path) -> None:
    """beacon /path/to/dns.log → skipped (pattern conn*.log* doesn't match dns.log)."""
    f = tmp_path / "dns.log"
    f.write_text("", encoding="utf-8")
    reason = _check_required_logs(_beacon_mod(), {"zeek_dir": f})
    assert reason is not None
    assert "conn*.log*" in reason and "not found" in reason


def test_is_optional_satisfiable_zeek_file_matches_dns_pattern(tmp_path: Path) -> None:
    """sigwood dns /path/to/dns.log → DNS optional path satisfied."""
    f = tmp_path / "dns.log"
    f.write_text("", encoding="utf-8")
    req = {"source": "zeek_dir", "pattern": "dns*.log*"}
    assert _is_optional_satisfiable(req, {"zeek_dir": f}) is True


# ── CloudTrail source threading ───────────────────────────────────────────────

def _cloudtrail_mod() -> SimpleNamespace:
    """Fake aws-family detector requiring cloudtrail_dir for satisfiability tests."""
    return SimpleNamespace(
        DETECTOR_NAME="fakeaws",
        STATUS="available",
        REQUIRED_LOGS=[{"source": "cloudtrail_dir", "pattern": "*.json*"}],
        OPTIONAL_LOGS=[],
    )


def test_check_required_logs_cloudtrail_native_nested_tree_passes(
    tmp_path: Path,
) -> None:
    """Native AWSLogs/<acct>/CloudTrail/<region>/YYYY/MM/DD/ tree resolves via
    discover_cloudtrail_files - not via raw directory.glob (which is non-recursive)."""
    nested = (
        tmp_path
        / "AWSLogs" / "123456789012" / "CloudTrail" / "us-east-1"
        / "2026" / "06" / "01"
    )
    nested.mkdir(parents=True)
    (nested / "events.json.gz").write_bytes(b"placeholder")

    reason = _check_required_logs(_cloudtrail_mod(), {"cloudtrail_dir": tmp_path})
    assert reason is None


def test_check_required_logs_cloudtrail_empty_dir_returns_reason(
    tmp_path: Path,
) -> None:
    empty = tmp_path / "empty-ct"
    empty.mkdir()

    reason = _check_required_logs(_cloudtrail_mod(), {"cloudtrail_dir": empty})
    assert reason is not None
    assert "no CloudTrail JSON logs found" in reason
    assert str(empty) in reason


def test_build_run_plan_threads_cloudtrail_dir_into_source_map(
    tmp_path: Path,
) -> None:
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    (cloudtrail_dir / "events.json.log").write_text("{}\n", encoding="utf-8")

    plan = build_run_plan(
        "all",
        zeek_dir=None, syslog_dir=None, pihole_dir=None,
        cloudtrail_dir=cloudtrail_dir,
        detectors={"fakeaws": _cloudtrail_mod()},
    )

    assert "fakeaws" in plan.will_run
    assert plan.needed_logs == {"*.json*": "cloudtrail_dir"}


def test_runner_cloudtrail_integration_lights_data_sources(
    tmp_path: Path, capture_summary, monkeypatch
) -> None:
    """End-to-end load contract: a detector requiring cloudtrail_dir drives the
    load through runner.run, and the resulting RunSummary.data_sources contains
    "cloudtrail_raw". This proves the runner wires plan → load → context →
    data_sources for a cloudtrail_dir detector."""
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    event = {
        "eventTime":       "2026-06-01T12:00:00Z",
        "eventSource":     "s3.amazonaws.com",
        "eventName":       "GetObject",
        "eventID":         "integration-test-event",
        "awsRegion":       "us-east-1",
        "sourceIPAddress": "192.0.2.10",
        "userIdentity": {
            "type":     "IAMUser",
            "userName": "placeholder-user",
            "arn":      "arn:aws:iam::123456789012:user/placeholder-user",
        },
        "readOnly": True,
    }
    (cloudtrail_dir / "events.json.log").write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )

    captured_ctx: dict = {}

    def _fake_run(ctx):
        captured_ctx["ctx"] = ctx
        return []

    fakeaws = SimpleNamespace(
        DETECTOR_NAME="fakeaws",
        STATUS="available",
        REQUIRED_LOGS=[{"source": "cloudtrail_dir", "pattern": "*.json*"}],
        OPTIONAL_LOGS=[],
        DEFAULT_CONFIG={},
        run=_fake_run,
    )
    monkeypatch.setattr(runner, "discover_detectors", lambda **_: {"fakeaws": fakeaws})

    runner.run(
        config={"sigwood": {"detect": "fakeaws"}},
        cloudtrail_dir=cloudtrail_dir,
    )

    s = capture_summary["summary"]
    assert s.data_sources == ["cloudtrail_raw"]
    assert s.record_counts.get("*.json*", 0) == 1

    ctx = captured_ctx["ctx"]
    df = ctx.logs["*.json*"]
    from sigwood.common.loader import _CLOUDTRAIL_COLUMNS
    assert list(df.columns) == _CLOUDTRAIL_COLUMNS
    assert df.iloc[0]["event_id"] == "integration-test-event"


# ── Stage 4: integration tests - drive runner.run() end-to-end ────────────────


def _write_ndjson(path: Path, records: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


_TS_JAN1 = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
_TS_JAN5 = datetime(2026, 1, 5, tzinfo=timezone.utc).timestamp()


def _conn(ts: float) -> dict:
    return {
        "ts": ts,
        "id.orig_h": "192.0.2.10",
        "id.resp_h": "198.51.100.20",
        "id.resp_p": 443,
        "proto": "tcp",
    }


def _make_dated_zeek(tmp_path: Path, dates_records: dict[str, list[dict]]) -> Path:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    for d, records in dates_records.items():
        sub = zeek_dir / d
        sub.mkdir()
        _write_ndjson(sub / "conn.log", records)
    return zeek_dir


def _make_flat_zeek(tmp_path: Path, records: list[dict]) -> Path:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "conn.log", records)
    return zeek_dir


@pytest.fixture
def capture_summary(monkeypatch):
    """Patch _build_output_handler to capture RunSummary instead of rendering."""
    captured: dict = {}

    class _CapHandler:
        def begin(self, rs): captured["summary"] = rs
        def write(self, fs): captured["findings"] = fs
        def end(self): pass

    def _fake_build(
        output_format, output_dir, output_file, verbose_level, stream=None, *,
        max_findings_per_detector=100, detectors_run=(),
    ):
        return _CapHandler(), (lambda: None), None

    monkeypatch.setattr("sigwood.runner._build_output_handler", _fake_build)
    return captured


_BEACON_ONLY = {"sigwood": {"detect": "beacon", "default_window": "1d"}}


def test_runner_dated_default_filters_to_newest_date(tmp_path, capture_summary, capsys):
    zeek_dir = _make_dated_zeek(tmp_path, {
        "2026-01-01": [_conn(_TS_JAN1)],
        "2026-01-05": [_conn(_TS_JAN5)],
    })
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 1
    # The prose default-window note moved to a pre-load stderr announcement.
    assert "default window: last 1d" in capsys.readouterr().err
    assert not any("Default window" in n for n in s.notes)


def test_runner_dated_current_spool_rows_counted_with_explicit_since(
    tmp_path, capture_summary,
):
    """Explicit --since on a dated tree counts rows that live only in current/
    - the live spool joins the windowed discovery universe (real seam, no
    mocks)."""
    zeek_dir = _make_dated_zeek(tmp_path, {
        "2026-01-01": [_conn(_TS_JAN1)],
    })
    current = zeek_dir / "current"
    current.mkdir()
    _write_ndjson(current / "conn.log", [_conn(_TS_JAN5), _conn(_TS_JAN5 + 1)])

    runner.run(
        config=_BEACON_ONLY, zeek_dir=zeek_dir,
        since=datetime(2026, 1, 5, tzinfo=timezone.utc),
    )
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 2


def test_runner_dated_current_tsv_truncated_tail_completes(
    tmp_path, capture_summary, capsys,
):
    """A live-shaped TSV in current/ (truncated tail - routine mid-write state)
    under an explicit window: the run completes, the fresh clean rows are
    counted, and the malformed-line warning is disclosed on stderr."""
    zeek_dir = _make_dated_zeek(tmp_path, {
        "2026-01-05": [_conn(_TS_JAN5)],
    })
    current = zeek_dir / "current"
    current.mkdir()
    (current / "conn.log").write_text(
        "#separator \\x09\n"
        "#set_separator ,\n"
        "#empty_field (empty)\n"
        "#unset_field -\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n"
        f"{_TS_JAN5 + 60}\tC1\t192.0.2.10\t1234\t198.51.100.20\t443\ttcp\n"
        f"{_TS_JAN5 + 61}\tC2\t192.0.2.10\t1235\t198.51.100.20\t443\ttcp\n"
        f"{_TS_JAN5 + 62}\tC3\t192.0.2.",  # truncated mid-write tail
        encoding="utf-8",
    )

    runner.run(
        config=_BEACON_ONLY, zeek_dir=zeek_dir,
        since=datetime(2026, 1, 5, tzinfo=timezone.utc),
        until=datetime(2026, 1, 6, tzinfo=timezone.utc),
    )
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 3
    err = capsys.readouterr().err
    assert "conn.log: skipped 1 malformed line (first at line 9)" in err


def test_runner_dated_default_7d_with_sparse_dirs(tmp_path, capture_summary):
    zeek_dir = _make_dated_zeek(tmp_path, {
        "2026-01-01": [_conn(_TS_JAN1)],
        "2026-01-05": [_conn(_TS_JAN5)],
    })
    config = {"sigwood": {"detect": "beacon", "default_window": "7d"}}
    runner.run(config=config, zeek_dir=zeek_dir)
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 2


def test_runner_flat_default_filters_to_last_span(tmp_path, capture_summary, capsys):
    zeek_dir = _make_flat_zeek(tmp_path, [_conn(_TS_JAN1), _conn(_TS_JAN5)])
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 1
    assert "default window: last 1d" in capsys.readouterr().err
    assert not any("Default window" in n for n in s.notes)


def test_runner_default_window_advisory_byte_identical_to_helper(
    tmp_path, capture_summary, capsys
):
    """run()'s pre-load stderr advisory emits EXACTLY
    display.default_window_advisory(spec). The digest card note reuses the
    same helper, so analyze and digest can never drift (parity)."""
    zeek_dir = _make_flat_zeek(tmp_path, [_conn(_TS_JAN1), _conn(_TS_JAN5)])
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)
    assert default_window_advisory("1d") in capsys.readouterr().err


def test_runner_bounded_single_file_loads_everything_no_note(
    tmp_path, capture_summary, capsys
):
    f = tmp_path / "conn.log"
    _write_ndjson(f, [_conn(_TS_JAN1), _conn(_TS_JAN5)])
    runner.run(config=_BEACON_ONLY, zeek_dir=f)
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 2
    assert not any("Default window" in n for n in s.notes)
    assert "Default window" not in capsys.readouterr().err


def test_runner_populates_detector_methods_for_will_run(tmp_path, capture_summary):
    """RunSummary.detector_methods carries the MethodTag for every
    detector in plan.will_run. Beacon's tag is FFT (named=True)."""
    from sigwood.common.finding import MethodTag
    f = tmp_path / "conn.log"
    _write_ndjson(f, [_conn(_TS_JAN1)])
    runner.run(config=_BEACON_ONLY, zeek_dir=f)
    s = capture_summary["summary"]
    assert s.detectors_run == ["beacon"]
    assert s.detector_methods.get("beacon") == MethodTag("FFT", named=True)


def test_runner_load_all_on_single_file_silent_noop(tmp_path, capture_summary):
    """--all on a BOUNDED single file: loads all, emits no default-window note, no error."""
    f = tmp_path / "conn.log"
    _write_ndjson(f, [_conn(_TS_JAN1), _conn(_TS_JAN5)])
    runner.run(config=_BEACON_ONLY, zeek_dir=f, load_all=True)
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 2
    assert not any("Default window" in n for n in s.notes)


def test_runner_explicit_since_suppresses_default_window_note(
    tmp_path, capture_summary, capsys
):
    zeek_dir = _make_dated_zeek(tmp_path, {
        "2026-01-01": [_conn(_TS_JAN1)],
        "2026-01-05": [_conn(_TS_JAN5)],
    })
    runner.run(
        config=_BEACON_ONLY,
        zeek_dir=zeek_dir,
        since=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        until=datetime(2026, 1, 5, 23, 59, 59, tzinfo=timezone.utc),
    )
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 2
    assert not any("Default window" in n for n in s.notes)
    assert "Default window" not in capsys.readouterr().err


def test_runner_load_all_overrides_default_window(tmp_path, capture_summary, capsys):
    zeek_dir = _make_dated_zeek(tmp_path, {
        "2026-01-01": [_conn(_TS_JAN1)],
        "2026-01-05": [_conn(_TS_JAN5)],
    })
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir, load_all=True)
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 2
    assert not any("Default window" in n for n in s.notes)
    assert "Default window" not in capsys.readouterr().err


def test_runner_default_window_empty_string_disables(tmp_path, capture_summary):
    zeek_dir = _make_dated_zeek(tmp_path, {
        "2026-01-01": [_conn(_TS_JAN1)],
        "2026-01-05": [_conn(_TS_JAN5)],
    })
    config = {"sigwood": {"detect": "beacon", "default_window": ""}}
    runner.run(config=config, zeek_dir=zeek_dir)
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 2
    assert not any("Default window" in n for n in s.notes)


# ── Source-coverage disclosure notes ──────────────────────────────────────────
#
# Each test drives runner.run end-to-end and inspects RunSummary.notes for the
# user-facing disclosure note. The HUMAN label (`Pi-hole` / `syslog` /
# `CloudTrail` / `Zeek <log_type>`) is asserted explicitly - and the parallel
# `data_sources` token string (`dnsmasq_dns` / `zeek_dns` / `syslog_raw` /
# `cloudtrail_raw`) is asserted ABSENT from the note text, to pin against
# internal-token leaks.


def _has_coverage_note(notes, *, starts_with, forbidden_token=None):
    """Return the disclosure note that starts with the given human label; fail
    fast if any note starts with a forbidden internal-token prefix."""
    for n in notes:
        if forbidden_token is not None and n.startswith(forbidden_token + ":"):
            raise AssertionError(
                f"note leaked internal token {forbidden_token!r}: {n!r}"
            )
    matches = [n for n in notes if n.startswith(starts_with + ":")]
    assert matches, (
        f"no note starting with {starts_with!r} found in: {notes!r}"
    )
    return matches[0]


def test_runner_dated_zeek_outside_window_emits_bare_note(
    tmp_path, capture_summary,
):
    """Dated-Zeek date-pruned: every dated subdir falls outside the requested
    window. `discover_zeek_files` returns no files; the loader early-returns
    empty; coverage = (None, None) → runner emits the BARE note. Detector
    still RUNS (not skipped)."""
    zeek_dir = _make_dated_zeek(tmp_path, {
        "2025-01-01": [_conn(datetime(2025, 1, 1, tzinfo=timezone.utc).timestamp())],
    })
    runner.run(
        config=_BEACON_ONLY, zeek_dir=zeek_dir,
        since=datetime(2030, 1, 1, tzinfo=timezone.utc),
        until=datetime(2030, 12, 31, tzinfo=timezone.utc),
    )
    s = capture_summary["summary"]
    note = _has_coverage_note(s.notes, starts_with="Zeek conn",
                              forbidden_token="zeek_conn")
    assert "files found" in note
    assert "widen with --since/--days" in note
    # Detector RAN - beacon is in detectors_run, just produced no findings
    # (because the loaded frame was empty).
    assert s.detectors_run == ["beacon"]


def test_runner_flat_zeek_per_pattern_trim_emits_span_note(
    tmp_path, capture_summary,
):
    """Flat Zeek dir, DEFAULT window, stale dns*.log* alongside
    fresh conn*.log*. The combined-max window derived from conn's max ts
    trims dns to empty. The runner-side flat-default instrumentation
    writes per-pattern coverage; dns gets a SPAN note labelled "Zeek dns:"
    (not "zeek_dns:").

    Detector selection: "beacon,dns" so BOTH patterns are in plan.needed_logs
    (the per-pattern trim only fires when more than one Zeek pattern is in
    the subset - that is the entire shape under test).
    """
    from datetime import datetime as _dt

    # FRESH window is anchored to NOW so the default 1d window keeps conn
    # alive; STALE window is well outside the 1d span so dns trims to empty.
    fresh_ts = _dt.now(timezone.utc).timestamp()
    stale_ts = fresh_ts - 30 * 24 * 3600  # 30 days before fresh

    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "conn.log", [_conn(fresh_ts)])
    _write_ndjson(zeek_dir / "dns.log", [{
        "ts": stale_ts,
        "id.orig_h": "192.0.2.10",
        "query": "example.test",
        "qclass": 1,
    }])

    runner.run(
        config={"sigwood": {"detect": "beacon, dns", "default_window": "1d"}},
        zeek_dir=zeek_dir,
    )
    s = capture_summary["summary"]
    # conn ran in-window (used as the max-ts anchor), dns trimmed to empty.
    assert s.record_counts.get("dns*.log*", 0) == 0
    assert s.record_counts.get("conn*.log*", 0) == 1
    note = _has_coverage_note(s.notes, starts_with="Zeek dns",
                              forbidden_token="zeek_dns")
    assert "rows loaded" in note
    assert "data spans" in note
    assert "widen with --since/--days" in note


def test_runner_populated_run_emits_no_coverage_note(tmp_path, capture_summary):
    """Happy path: a populated single-file Zeek load produces NO disclosure
    note. The mark_kept short-circuit means LoadResult.coverage is empty for
    populated patterns."""
    f = tmp_path / "conn.log"
    _write_ndjson(f, [_conn(_TS_JAN1)])
    runner.run(config=_BEACON_ONLY, zeek_dir=f)
    s = capture_summary["summary"]
    # No coverage note for any label.
    for label in ("Zeek conn", "Zeek dns", "Pi-hole", "syslog", "CloudTrail"):
        assert not any(n.startswith(label + ":") for n in s.notes), (
            f"unexpected coverage note for {label}: {s.notes!r}"
        )


def test_runner_empty_zeek_file_no_coverage_note(tmp_path, capture_summary):
    """An empty Zeek file (rotation artifact) reads but yields no
    valid-ts rows. coverage = (0, None) → PARSE-GAP arm → NO note. Telling
    the operator to widen the window on an empty file would mislead."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text("", encoding="utf-8")
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)
    s = capture_summary["summary"]
    # No Zeek conn coverage note despite the empty file + empty frame.
    assert not any(n.startswith("Zeek conn:") for n in s.notes), s.notes


# ── Malformed domain-pattern advisory (runner seam) ───────────────────────────
#
# A malformed `re:` body in a CONFIGURED domain list is dropped at matcher build
# (it would otherwise raise mid-run) and surfaced as ONE RunSummary STATUS note
# naming the ORIGINAL file:line. Crosses the real seam (real runner.run + the
# real allowlist resolver) so the "scanning allowlist coverage" phase is proven
# not to crash on the malformed-but-dropped engine.


def test_runner_malformed_domain_pattern_emits_note(tmp_path, capture_summary):
    from datetime import datetime as _dt

    # Real DNS frame so the coverage scan (count_domain_suppressed) actually
    # executes over the malformed-dropped engine.
    fresh_ts = _dt.now(timezone.utc).timestamp()
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "dns.log", [{
        "ts": fresh_ts,
        "id.orig_h": "192.0.2.10",
        "query": "example.test",
        "qclass": 1,
    }])

    # A configured domain list whose malformed `re:` is NOT on line 1 - pins the
    # ORIGINAL line number through the line-aware loader.
    bad = tmp_path / "domains_bad.txt"
    bad.write_text("# header comment\nre:(badopen\n", encoding="utf-8")

    runner.run(
        config={
            "sigwood": {"detect": "dns", "default_window": "1d"},
            # Disable shipped domain lists so the only active list is ours - the
            # note assertion is then deterministic.
            "allowlist": {
                "lists": {"common": False, "devices": False, "homelab": False},
                "domain_patterns": [str(bad)],
            },
        },
        zeek_dir=zeek_dir,
    )
    s = capture_summary["summary"]
    malformed = [n for n in s.notes if n.startswith("allowlist:") and "malformed" in n]
    assert len(malformed) == 1, s.notes
    note = malformed[0]
    assert "domains_bad.txt:2:" in note          # ORIGINAL lineno (after the comment)
    assert "malformed pattern skipped (re:(badopen)" in note


def test_runner_no_allowlist_suppresses_malformed_note(tmp_path, capture_summary):
    """`--no-allowlist` builds an empty matcher (no malformed set) → no note,
    even though the configured file has a malformed pattern."""
    fresh_ts = datetime.now(timezone.utc).timestamp()
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "dns.log", [{
        "ts": fresh_ts, "id.orig_h": "192.0.2.10", "query": "example.test", "qclass": 1,
    }])
    bad = tmp_path / "domains_bad.txt"
    bad.write_text("# header\nre:(badopen\n", encoding="utf-8")

    runner.run(
        config={
            "sigwood": {"detect": "dns", "default_window": "1d"},
            "allowlist": {"domain_patterns": [str(bad)]},
        },
        zeek_dir=zeek_dir,
        no_allowlist=True,
    )
    s = capture_summary["summary"]
    assert not any("malformed" in n for n in s.notes), s.notes


# ── Mock-based runner tests (stale Pi-hole / parse-gap CT / multi-source) ────
#
# These cases need precise control over LoadResult.coverage shape that the
# parser layer doesn't make easy to fixture (year-guessing in dnsmasq /
# multi-pattern coverage assembly). Mocking load_required_logs lets each test
# pin one coverage scenario through runner.run + the capture_summary fixture
# while still exercising the full runner-side note assembly.


@pytest.fixture
def mock_load_required_logs(monkeypatch):
    """Override loader.load_required_logs to return a hand-built LoadResult."""
    from sigwood.common import loader as _loader

    def _install(load_result):
        def _fake(*args, **kwargs):
            return load_result
        monkeypatch.setattr(_loader, "load_required_logs", _fake)
    return _install


def _ts_window_span():
    """A representative full-data span used in mocked SPAN-coverage tests."""
    return (
        datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc),
        datetime(2025, 6, 5, 0, 0, 0, tzinfo=timezone.utc),
    )


def test_runner_stale_pihole_emits_pihole_span_note(
    tmp_path, capture_summary, mock_load_required_logs,
):
    """Motivating bug: dns both-mode, Pi-hole archive timestamped weeks ago
    and the window picks up nothing. SPAN note labelled "Pi-hole:" - must
    NOT leak the internal "dnsmasq_dns:" token. Pi-hole isn't in
    data_sources (record_counts==0), so the Zeek-evangelization nudge does
    NOT fire (data_sources is byte-identical to a Zeek-only run)."""
    from sigwood.common.loader import LoadResult, SourceCoverage

    # Build minimal Zeek dns + Pi-hole dirs so the plan picks both patterns.
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "dns.log", [{
        "ts": _TS_JAN5, "id.orig_h": "192.0.2.10",
        "query": "example.test", "qclass": 1,
    }])
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    (pihole_dir / "pihole.log").write_text(
        "Jun  1 12:00:00 dnsmasq[1]: query[A] x.test from 192.0.2.10\n",
        encoding="utf-8",
    )

    zeek_dns_df = pd.DataFrame({
        "ts": [_TS_JAN5], "src": ["192.0.2.10"],
        "query": ["example.test"], "qclass": [1],
    })
    pihole_empty = pd.DataFrame(columns=_PIHOLE_COLUMNS_FOR_MOCK)
    span = _ts_window_span()
    fake_lr = LoadResult(
        logs={"dns*.log*": zeek_dns_df, "pihole*.log*": pihole_empty},
        record_counts={"dns*.log*": 1},  # pihole = 0
        data_window=(
            datetime.fromtimestamp(_TS_JAN5, tz=timezone.utc),
            datetime.fromtimestamp(_TS_JAN5, tz=timezone.utc),
        ),
        warnings=[],
        data_size_bytes=0,
        coverage={"pihole*.log*": SourceCoverage(15_400_000, span)},
    )
    mock_load_required_logs(fake_lr)

    runner.run(
        config={"sigwood": {"detect": "dns", "default_window": ""}},
        zeek_dir=zeek_dir, pihole_dir=pihole_dir,
        since=datetime(2026, 6, 1, tzinfo=timezone.utc),
        until=datetime(2026, 6, 3, tzinfo=timezone.utc),
    )
    s = capture_summary["summary"]
    note = _has_coverage_note(s.notes, starts_with="Pi-hole",
                              forbidden_token="dnsmasq_dns")
    assert "15,400,000 rows loaded" in note
    assert "data spans" in note
    assert "widen with --since/--days" in note
    # Pi-hole NOT in data_sources (record_counts==0) → nudge does not fire,
    # and data_sources is unchanged (only the Zeek dns label).
    assert "zeek_dns" in s.data_sources
    assert "dnsmasq_dns" not in s.data_sources
    assert not any("Pi-hole/dnsmasq logs" in n for n in s.notes)


def test_runner_parse_gap_cloudtrail_emits_no_note(
    tmp_path, capture_summary, mock_load_required_logs,
):
    """CloudTrail file with all-unparseable eventTime → coverage = (0, None)
    → runner emits NO note (parse-gap arm)."""
    from sigwood.common.loader import LoadResult, SourceCoverage

    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    (ct_dir / "events.json.log").write_text("{}", encoding="utf-8")

    empty_ct = pd.DataFrame(columns=_CT_COLUMNS_FOR_MOCK)
    fake_lr = LoadResult(
        logs={"*.json*": empty_ct},
        record_counts={},
        data_window=None,
        warnings=[],
        data_size_bytes=0,
        coverage={"*.json*": SourceCoverage(0, None)},
    )
    mock_load_required_logs(fake_lr)

    runner.run(
        config={"sigwood": {"detect": "aws"}}, cloudtrail_dir=ct_dir,
    )
    s = capture_summary["summary"]
    # No CloudTrail (or any other) coverage note.
    for label in ("CloudTrail", "Zeek conn", "Pi-hole", "syslog"):
        assert not any(n.startswith(label + ":") for n in s.notes), (
            f"unexpected coverage note for {label}: {s.notes!r}"
        )


def test_runner_wrong_family_syslog_skip_no_coverage_note(
    tmp_path, capture_summary, mock_load_required_logs,
):
    """A deliberately-skipped wrong-family file (NDJSON in syslog_dir)
    surfaces as the loader's existing skip behavior; the runner MUST NOT
    emit a window-disclosure note for it. At the loader level the tracker
    writes SourceCoverage(None, None) (note_file_read never fired), but the
    runner's BARE-note arm is zeek_dir-only - so syslog produces no note."""
    from sigwood.common.loader import LoadResult, SourceCoverage

    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    # Plan-time satisfiability now content-sniffs (Item E), so the on-disk file
    # must pass the gate; the LOAD is mocked below to simulate the wrong-family
    # skip (empty frame + SourceCoverage(None, None)).
    (syslog_dir / "host.log").write_text(
        "<134>May 31 12:00:00 host-a kernel: x\n", encoding="utf-8"
    )

    empty_syslog = pd.DataFrame(
        columns=["ts", "host", "program", "raw", "message"]
    )
    fake_lr = LoadResult(
        logs={"*.log*": empty_syslog},
        record_counts={},
        data_window=None,
        warnings=[],
        data_size_bytes=0,
        # The wrong-family skip leaves the tracker with no note_file_read
        # calls; coverage(True) → SourceCoverage(None, None).
        coverage={"*.log*": SourceCoverage(None, None)},
    )
    mock_load_required_logs(fake_lr)

    runner.run(
        config={"sigwood": {"detect": "syslog"}}, syslog_dir=syslog_dir,
    )
    s = capture_summary["summary"]
    # No "syslog:" coverage note (BARE arm is zeek_dir-only).
    assert not any(n.startswith("syslog:") for n in s.notes), s.notes


def test_runner_explicit_binary_syslog_warns_skips_no_coverage_note(
    tmp_path, capture_summary, capsys,
):
    """An EXPLICIT binary syslog FILE (bypasses content-sniff discovery, loads as
    [path]) is warn-skipped: the DEFAULT-VISIBLE warning prints to stderr, the load
    is empty with NO findings, and NO 'syslog:' widen-the-window coverage note fires
    (the warn rides load_result.warnings, NOT the coverage channel - so the
    wrong-family no-coverage-note contract holds for binary too)."""
    binfile = tmp_path / "messages"
    binfile.write_bytes(b"\x00\x00binary garbage\x00" * 50)

    runner.run(config=_SYSLOG_ONLY, syslog_dir=binfile)

    s = capture_summary["summary"]
    findings = capture_summary["findings"]
    err = capsys.readouterr().err
    assert (
        "syslog_dir: skipping messages - looks binary or won't decode as text" in err
    )
    assert findings == []
    assert not any(n.startswith("syslog:") for n in s.notes), s.notes


def test_runner_unconfigured_source_no_coverage_note(
    tmp_path, capture_summary,
):
    """A pattern not loaded (source unconfigured) → loader warns via its
    existing "{source} not configured - {pattern} not loaded" warning; the
    disclosure note MUST NOT fire (would duplicate the warning).

    Driven by detect=dns with only zeek_dir configured (no pihole_dir);
    DNS plan needs both patterns but pihole_dir is absent.
    """
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "dns.log", [{
        "ts": _TS_JAN5, "id.orig_h": "192.0.2.10",
        "query": "example.test", "qclass": 1,
    }])

    runner.run(
        config={"sigwood": {"detect": "dns", "default_window": ""}},
        zeek_dir=zeek_dir,
        # pihole_dir omitted entirely
    )
    s = capture_summary["summary"]
    # Loader emits the "pihole_dir not configured" warning, but the
    # disclosure note (Pi-hole: …) does NOT fire.
    assert not any(n.startswith("Pi-hole:") for n in s.notes), s.notes


def test_runner_mixed_data_and_permission_denied_source_does_not_abort(
    tmp_path,
    capture_summary,
    mock_load_required_logs,
    capsys,
):
    """Loaded data wins: permission-denied siblings warn without aborting."""
    from sigwood.common.loader import LoadResult, PermissionSkipInfo

    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "dns.log", [{
        "ts": _TS_JAN5, "id.orig_h": "192.0.2.10",
        "query": "example.test", "qclass": 1,
    }])
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    denied = pihole_dir / "pihole.log"
    denied.write_text("unreadable placeholder\n", encoding="utf-8")

    dns_df = pd.DataFrame([{
        "ts": _TS_JAN5,
        "src": "192.0.2.10",
        "query": "example.test",
        "qtype": 1,
    }])
    pihole_df = pd.DataFrame(
        columns=["ts", "src", "query", "event_type", "qtype",
                 "dst", "answer", "validation", "host", "raw", "message"]
    )
    fake_lr = LoadResult(
        logs={"dns*.log*": dns_df, "pihole*.log*": pihole_df},
        record_counts={"dns*.log*": 1},
        data_window=(
            datetime.fromtimestamp(_TS_JAN5, tz=timezone.utc),
            datetime.fromtimestamp(_TS_JAN5, tz=timezone.utc),
        ),
        warnings=[
            "pihole.log: permission denied - owned loguser:logreaders "
            "(mode 0640); add your user to the 'logreaders' group "
            "(sudo usermod -aG logreaders $USER) and log back in"
        ],
        permission_skips={
            "pihole*.log*": PermissionSkipInfo(
                discovered=1, denied=1, paths=(denied,),
            ),
        },
    )
    mock_load_required_logs(fake_lr)

    runner.run(
        config={"sigwood": {"detect": "dns", "default_window": ""}},
        zeek_dir=zeek_dir,
        pihole_dir=pihole_dir,
    )

    s = capture_summary["summary"]
    err = capsys.readouterr().err
    assert s is not None
    assert s.record_counts == {"dns*.log*": 1}
    assert "pihole.log: permission denied" in err


def test_runner_appends_disclosure_after_home_net_note(
    tmp_path, capture_summary, mock_load_required_logs,
):
    """Note ordering preserved: the new disclosure note appends LAST in the
    notes list, after _home_net_note (so the existing notes' relative order
    is byte-identical)."""
    from sigwood.common.loader import LoadResult, SourceCoverage

    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    (ct_dir / "events.json.log").write_text("{}", encoding="utf-8")

    empty_ct = pd.DataFrame(columns=_CT_COLUMNS_FOR_MOCK)
    span = _ts_window_span()
    fake_lr = LoadResult(
        logs={"*.json*": empty_ct},
        record_counts={},
        data_window=None,
        warnings=[],
        data_size_bytes=0,
        coverage={"*.json*": SourceCoverage(42, span)},
    )
    mock_load_required_logs(fake_lr)

    runner.run(
        config={"sigwood": {"detect": "aws"}}, cloudtrail_dir=ct_dir,
    )
    s = capture_summary["summary"]
    ct_note_idx = next(
        (i for i, n in enumerate(s.notes) if n.startswith("CloudTrail:")),
        None,
    )
    assert ct_note_idx is not None, f"no CloudTrail note in {s.notes!r}"
    # No "_home_net" or other internal-prefixed notes follow the disclosure.
    # The disclosure must be at or after the index of any pre-existing note.
    # Simpler invariant: it's the LAST note (or among the last).
    assert ct_note_idx == len(s.notes) - 1, (
        f"CloudTrail note not last (idx={ct_note_idx}, len={len(s.notes)}): "
        f"{s.notes!r}"
    )


# Column lists needed by the mocked LoadResult fixtures above.
_PIHOLE_COLUMNS_FOR_MOCK = [
    "ts", "host", "program", "client", "qtype", "query", "answer",
    "rcode", "raw", "message", "event_type",
]
_CT_COLUMNS_FOR_MOCK = [
    "ts", "eventTime", "eventSource", "eventName", "eventID", "awsRegion",
    "sourceIPAddress", "principal", "lane", "read_write", "errorCode",
    "raw",
]


# The two staging-dir tests below are the Stage 4 vs Stage 3 differential:
# Stage 3 includes non-date child dirs in the no-window branch; Stage 4 bare runs
# are windowed (skipping them) but --all reverts to the no-window branch.

def test_runner_default_window_skips_real_nondate_subdir(tmp_path, capture_summary):
    """Bare run with dated dirs + staging/ → only dated dir loaded (windowed branch)."""
    zeek_dir = _make_dated_zeek(tmp_path, {"2026-01-05": [_conn(_TS_JAN5)]})
    staging = zeek_dir / "staging"
    staging.mkdir()
    _write_ndjson(staging / "conn.log", [_conn(_TS_JAN1)])
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 1


def test_runner_load_all_includes_real_nondate_subdir(tmp_path, capture_summary):
    """--all with dated dirs + staging/ → both dirs loaded (no-window branch)."""
    zeek_dir = _make_dated_zeek(tmp_path, {"2026-01-05": [_conn(_TS_JAN5)]})
    staging = zeek_dir / "staging"
    staging.mkdir()
    _write_ndjson(staging / "conn.log", [_conn(_TS_JAN1)])
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir, load_all=True)
    s = capture_summary["summary"]
    assert s.record_counts.get("conn*.log*", 0) == 2


# ── Zeek default window must not leak into other sources ─────────────────────────

def test_runner_default_window_no_leak_from_unplanned_family(
    tmp_path, capture_summary, capsys
):
    """detect=syslog with zeek_dir configured: a CONFIGURED-but-not-in-plan family
    (zeek_dir) is never loaded or windowed (no conn count). The universal default
    window engages on syslog - its OWN family - anchoring on syslog's own max-ts.

    Under the universal window, syslog gets its OWN
    1d window: the Jan 1 row falls outside (Jan 5 − 1d) and is trimmed; the
    unplanned Zeek family stays out of the load entirely, so its window can
    never leak into syslog.
    """
    # Current year so RFC 3164 syslog parsing (which assumes current year) is recent.
    year = datetime.now(timezone.utc).year

    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    newest = zeek_dir / f"{year}-01-05"
    newest.mkdir()
    _write_ndjson(newest / "conn.log", [_conn(_TS_JAN5)])

    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "host.log").write_text(
        f"Jan  1 00:00:01 host kernel: old line\n"
        f"Jan  5 00:00:01 host kernel: new line\n",
        encoding="utf-8",
    )

    runner.run(
        config={"sigwood": {"detect": "syslog", "default_window": "1d"}},
        zeek_dir=zeek_dir, syslog_dir=syslog_dir,
    )

    s = capture_summary["summary"]
    assert "conn*.log*" not in s.record_counts, \
        "zeek_dir is not in the plan for detect=syslog - must not load"
    assert s.record_counts.get("*.log*", 0) == 1, \
        "syslog's OWN universal default window keeps only the in-window row"
    assert "default window: last 1d" in capsys.readouterr().err
    assert not any("Default window" in n for n in s.notes)


def test_runner_default_window_applies_to_all_families_in_mixed_run(
    tmp_path, capture_summary, capsys
):
    """Mixed run (beacon + syslog) with default window: EVERY in-plan family is
    windowed on its own anchor - Zeek conn to the newest dated dir, syslog to its
    own last-1d. (Old behavior windowed Zeek only; the window is now universal.)"""
    year = datetime.now(timezone.utc).year

    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    # Derive conn row ts from the SAME `year` as the dir names: the Zeek default
    # window is derived from the dir NAME, so hardcoded 2026 rows would be filtered
    # out (window misses them) on a 2027+ box.
    old = zeek_dir / f"{year}-01-01"
    old.mkdir()
    _write_ndjson(old / "conn.log", [
        _conn(datetime(year, 1, 1, tzinfo=timezone.utc).timestamp())
    ])
    new = zeek_dir / f"{year}-01-05"
    new.mkdir()
    _write_ndjson(new / "conn.log", [
        _conn(datetime(year, 1, 5, tzinfo=timezone.utc).timestamp())
    ])

    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "host.log").write_text(
        "Jan  1 00:00:01 host kernel: old line\n"
        "Jan  5 00:00:01 host kernel: new line\n",
        encoding="utf-8",
    )

    runner.run(
        config={"sigwood": {"detect": "beacon,syslog", "default_window": "1d"}},
        zeek_dir=zeek_dir, syslog_dir=syslog_dir,
    )

    s = capture_summary["summary"]
    assert "default window: last 1d" in capsys.readouterr().err
    assert not any("Default window" in n for n in s.notes)
    assert s.record_counts.get("conn*.log*", 0) == 1, \
        "Zeek conn rows filtered to newest dated dir only"
    assert s.record_counts.get("*.log*", 0) == 1, \
        "syslog rows windowed to its OWN last-1d (Jan 1 trimmed)"


# ── universal default window: flat (syslog/pihole) + cloudtrail families ──────


def test_runner_syslog_default_window_trims_and_keeps_nan_ts(
    tmp_path, capture_summary, capsys
):
    """The universal default window engages on a flat syslog DIRECTORY: rows older
    than (max-ts − 1d) are trimmed, the in-window row survives, AND a row with an
    unparseable timestamp (NaN ts, keep-policy) survives the trim (keep-null)."""
    year = datetime.now(timezone.utc).year  # noqa: F841 (documents the year-guess)
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "host.log").write_text(
        "Jun  1 12:00:00 host kernel: old line\n"   # outside last-1d → trimmed
        "Jun  5 12:00:00 host kernel: new line\n"   # in window → kept
        "Xxx  1 12:00:00 host kernel: nan line\n",  # NaN ts → kept (keep policy)
        encoding="utf-8",
    )
    runner.run(
        config={"sigwood": {"detect": "syslog", "default_window": "1d"}},
        syslog_dir=syslog_dir,
    )
    s = capture_summary["summary"]
    assert "default window: last 1d" in capsys.readouterr().err
    assert s.record_counts.get("*.log*", 0) == 2, \
        "in-window row + NaN-ts row survive; the old row is trimmed"


def test_runner_flat_family_explicit_file_is_bounded_no_window(
    tmp_path, capture_summary, capsys
):
    """A flat family given an explicit FILE is BOUNDED - load full, no default
    window, no stderr announcement (boundedness generalizes to every family)."""
    f = tmp_path / "host.log"
    f.write_text(
        "Jun  1 12:00:00 host kernel: old line\n"
        "Jun  5 12:00:00 host kernel: new line\n",
        encoding="utf-8",
    )
    runner.run(
        config={"sigwood": {"detect": "syslog", "default_window": "1d"}},
        syslog_dir=f,
    )
    s = capture_summary["summary"]
    assert s.record_counts.get("*.log*", 0) == 2, "bounded file loads full"
    assert "Default window" not in capsys.readouterr().err


def test_runner_flat_family_mixed_file_and_dir_trims_with_bucket(
    tmp_path, capture_summary, capsys
):
    """Mixed explicit-file + directory in one flat family (1E): the family is
    unbounded, the default window applies to the WHOLE load, and the named file's
    out-of-window rows are trimmed WITH the bucket. The floor anchors on DIRECTORY
    candidates only - the explicit file does not drive it (else its old row would
    survive)."""
    old_file = tmp_path / "old.log"
    old_file.write_text(
        "Jun  1 12:00:00 host kernel: explicit old line\n",  # trimmed with bucket
        encoding="utf-8",
    )
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "host.log").write_text(
        "Jun  5 12:00:00 host kernel: dir new line\n",  # anchor + in window
        encoding="utf-8",
    )
    runner.run(
        config={"sigwood": {"detect": "syslog", "default_window": "1d"}},
        syslog_dir=[old_file, syslog_dir],
    )
    s = capture_summary["summary"]
    assert "default window: last 1d" in capsys.readouterr().err
    assert s.record_counts.get("*.log*", 0) == 1, \
        "only the dir's in-window row survives; the explicit file's old row is trimmed"


def _ct_event(ts_iso: str, event_id: str) -> dict:
    return {
        "eventTime":       ts_iso,
        "eventSource":     "s3.amazonaws.com",
        "eventName":       "GetObject",
        "eventID":         event_id,
        "awsRegion":       "us-east-1",
        "sourceIPAddress": "192.0.2.10",
        "userIdentity": {
            "type":        "IAMUser",
            "userName":    "placeholder-user",
            "principalId": "AIDAEXAMPLE",
            "arn":         "arn:aws:iam::123456789012:user/placeholder-user",
        },
        "readOnly": True,
    }


def test_runner_cloudtrail_excluded_from_default_window_loads_full(
    tmp_path, capture_summary, capsys
):
    """CloudTrail opts OUT of the auto-default window (aws is baseline-relative):
    an UNQUALIFIED run loads the FULL archive (no trim), and - being the only
    family - emits NO "Default window" stderr line."""
    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    (ct_dir / "events.json").write_text(
        "\n".join(json.dumps(e) for e in [
            _ct_event("2026-06-01T12:00:00Z", "aaaa"),   # a month apart - both
            _ct_event("2026-06-05T12:00:00Z", "bbbb"),   # load (no default window)
        ]) + "\n",
        encoding="utf-8",
    )
    runner.run(
        config={"sigwood": {"detect": "aws", "default_window": "1d"}},
        cloudtrail_dir=ct_dir,
    )
    s = capture_summary["summary"]
    assert "Default window" not in capsys.readouterr().err, \
        "cloudtrail-only unqualified run engages no default window"
    assert s.record_counts.get("*.json*", 0) == 2, \
        "cloudtrail loads FULL - excluded from the auto-default window"


def test_runner_cloudtrail_explicit_window_narrows_and_riders(
    tmp_path, capture_summary
):
    """An explicit --since DOES window cloudtrail, and the aws window note then
    carries the --all rider (cloudtrail_narrowed)."""
    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    (ct_dir / "events.json").write_text(
        "\n".join(json.dumps(e) for e in [
            _ct_event("2026-06-01T12:00:00Z", "aaaa"),   # before since → excluded
            _ct_event("2026-06-05T12:00:00Z", "bbbb"),   # in window
        ]) + "\n",
        encoding="utf-8",
    )
    runner.run(
        config={"sigwood": {"detect": "aws", "default_window": "1d"}},
        cloudtrail_dir=ct_dir,
        since=datetime(2026, 6, 4, tzinfo=timezone.utc),
        until=datetime(2026, 6, 6, tzinfo=timezone.utc),
    )
    s = capture_summary["summary"]
    assert s.record_counts.get("*.json*", 0) == 1, "explicit window narrows cloudtrail"
    assert any("--all for a full-baseline" in n for n in s.notes), \
        "explicit narrowing → aws window note carries the --all rider"


def test_runner_mixed_unqualified_cloudtrail_full_no_aws_all_rider(
    tmp_path, capture_summary, capsys
):
    """Mixed unqualified run (aws + syslog): the default window fires for syslog
    (eligible) so the stderr line STILL prints, but cloudtrail loads FULL and the
    aws notes must NOT claim --all is needed (cloudtrail wasn't narrowed)."""
    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    (ct_dir / "events.json").write_text(
        "\n".join(json.dumps(e) for e in [
            _ct_event("2026-06-01T12:00:00Z", "aaaa"),
            _ct_event("2026-06-05T12:00:00Z", "bbbb"),
        ]) + "\n",
        encoding="utf-8",
    )
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "host.log").write_text(
        "Jun  1 12:00:00 host kernel: old line\n"
        "Jun  5 12:00:00 host kernel: new line\n",
        encoding="utf-8",
    )
    runner.run(
        config={"sigwood": {"detect": "aws,syslog", "default_window": "1d"}},
        cloudtrail_dir=ct_dir, syslog_dir=syslog_dir,
    )
    s = capture_summary["summary"]
    assert "default window: last 1d" in capsys.readouterr().err, \
        "syslog (eligible) still engages the default window"
    assert s.record_counts.get("*.json*", 0) == 2, "cloudtrail loaded FULL"
    # Positive guard so the negative below proves the --all rider was SUPPRESSED,
    # not that the whole aws note silently vanished (a vacuous pass otherwise).
    assert any(n.startswith("aws:") for n in s.notes), \
        "the aws first-seen note still fires"
    assert not any("--all" in n for n in s.notes), \
        "cloudtrail not narrowed → no --all rider on any aws note"


def test_apply_default_window_keep_null_and_metadata(tmp_path):
    """B/D unit: the post-load trim (relocated to loader.apply_default_window) retains
    NaN-ts rows under keep_null and preserves rotation_skips / warnings /
    data_size_bytes via dataclasses.replace (only logs / record_counts / data_window
    / coverage are rebuilt)."""
    import math
    import pandas as pd
    from sigwood.common.loader import LoadResult, RotationSkipInfo
    from sigwood.common.loader import apply_default_window

    base = datetime(2026, 6, 5, 12, 0, tzinfo=timezone.utc).timestamp()
    skips = {"*.log*": RotationSkipInfo(loaded=2, skipped=3, fallback=False)}

    def _mk() -> LoadResult:
        df = pd.DataFrame([
            {"ts": base, "message": "in-window"},
            {"ts": base - 5 * 86400, "message": "old"},      # outside 1d → trimmed
            {"ts": float("nan"), "message": "no-ts"},        # NaN → kept iff keep_null
        ])
        return LoadResult(
            logs={"*.log*": df},
            record_counts={"*.log*": 3},
            data_window=None,
            warnings=["a soft warning"],
            data_size_bytes=4242,
            rotation_skips=skips,
        )

    src = _mk()
    kept = apply_default_window(
        src, ["*.log*"], timedelta(days=1), keep_null=True
    )
    msgs = set(kept.logs["*.log*"]["message"])
    assert msgs == {"in-window", "no-ts"}, "keep_null retains the NaN-ts row"
    # #4: the passed-in LoadResult.logs must NOT be mutated in place (shallow copy).
    assert len(src.logs["*.log*"]) == 3, "input frame untouched by the trim"
    assert kept.logs["*.log*"] is not src.logs["*.log*"]
    assert kept.record_counts["*.log*"] == 2
    # Metadata preserved unchanged through replace().
    assert kept.warnings == ["a soft warning"]
    assert kept.data_size_bytes == 4242
    assert kept.rotation_skips is skips

    dropped = apply_default_window(
        _mk(), ["*.log*"], timedelta(days=1), keep_null=False
    )
    msgs2 = set(dropped.logs["*.log*"]["message"])
    assert msgs2 == {"in-window"}, "keep_null=False drops the NaN-ts row (drop policy)"
    assert not any(math.isnan(x) for x in dropped.logs["*.log*"]["ts"])


def test_runner_no_data_window_forces_requested_span_none(
    tmp_path, capture_summary, capsys
):
    """#2: a default window is active but the load has NO real data window (every
    row's ts is unparseable → kept by keep-policy but `_data_window` is None). The
    runner must force requested_span None so the underfill parenthetical can't render
    a confident comparison over data that doesn't exist.

    Uses pihole_dir: it KEEPs NaN-ts rows AND is discovered by filename (no content
    gate), so an all-unparseable-ts file still loads. The syslog content-sniff gate
    (Item E) rejects an all-unparseable-ts file at discovery - sniff requires a
    parseable ts - so this scenario is unreachable via syslog directory discovery,
    and a parseable line would itself give a non-None data window."""
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    # "Xxx" matches the outer \w{3} but strptime fails → NaN ts, kept by keep policy.
    (pihole_dir / "pihole.log").write_text(
        "Xxx  1 12:00:00 dnsmasq[1]: query[A] a.test from 192.0.2.1\n"
        "Xxx  2 12:00:00 dnsmasq[1]: query[A] b.test from 192.0.2.1\n",
        encoding="utf-8",
    )
    runner.run(
        config={"sigwood": {"detect": "dns", "default_window": "1d"}},
        pihole_dir=pihole_dir,
    )
    s = capture_summary["summary"]
    # Default window engaged (unbounded dir, no explicit window)...
    assert "default window: last 1d" in capsys.readouterr().err
    # ...but with no real data window, requested_span is forced None (the gate the
    # renderer can't see)...
    assert s.requested_span is None
    # ...and the summary carries no window at all - renderers answer
    # `data found: none` rather than an invented span.
    assert s.data_window is None


def test_runner_mixed_garbage_conn_real_dns_per_file_disclosure(
    tmp_path, capture_summary, capsys
):
    """One garbage file among good siblings: the conn.log no-records warning
    fires for THAT file while the dns rows load - the summary window comes from
    the real data, never None and never fabricated."""
    fresh_ts = datetime.now(timezone.utc).timestamp()
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text(
        "totally ordinary prose line one\n", encoding="utf-8"
    )
    _write_ndjson(zeek_dir / "dns.log", [
        {"ts": fresh_ts, "id.orig_h": "192.0.2.10",
         "query": "example.test", "qclass": 1},
        {"ts": fresh_ts + 60, "id.orig_h": "192.0.2.11",
         "query": "example.test", "qclass": 1},
    ])

    runner.run(
        config={"sigwood": {"detect": "beacon, dns", "default_window": "1d"}},
        zeek_dir=zeek_dir,
    )
    s = capture_summary["summary"]
    err = capsys.readouterr().err
    assert "conn.log: no Zeek records found - is this a Zeek log?" in err
    assert s.data_window is not None
    start, end = s.data_window
    assert start.timestamp() == pytest.approx(fresh_ts)
    assert end.timestamp() == pytest.approx(fresh_ts + 60)


def test_aws_window_note_cloudtrail_narrowed_rider() -> None:
    """The aws window note gains --all guidance ONLY when CloudTrail was actually
    narrowed (explicit window) - it rides the EXISTING note (no new note), and the
    base note is unchanged when CloudTrail loaded full."""
    plan = SimpleNamespace(will_run=["aws"])
    base = _aws_window_note(plan, cloudtrail_narrowed=False)
    assert base is not None
    assert "first-seen" in base
    assert "--all" not in base

    rider = _aws_window_note(plan, cloudtrail_narrowed=True)
    assert rider is not None
    assert rider.startswith(base)  # same note, guidance appended
    assert "--all" in rider

    # No aws → no note regardless of the flag.
    assert _aws_window_note(SimpleNamespace(will_run=["beacon"]),
                            cloudtrail_narrowed=True) is None


def _ct_service_event(ts_iso: str, event_id: str) -> dict:
    """A service-lane CloudTrail event (userIdentity.type=AWSService → service)."""
    return {
        "eventTime":       ts_iso,
        "eventSource":     "s3.amazonaws.com",
        "eventName":       "GetObject",
        "eventID":         event_id,
        "awsRegion":       "us-east-1",
        "sourceIPAddress": "ec2.amazonaws.com",
        "userIdentity":    {"type": "AWSService", "invokedBy": "ec2.amazonaws.com"},
        "readOnly":        True,
    }


def test_runner_aws_no_interactive_note_unqualified_end_to_end(
    tmp_path, capture_summary
):
    """#2 end-to-end: a real all-service-lane CloudTrail load (parser lane
    assignment → runner note assembly → detector empty return) on an UNQUALIFIED
    run discloses the neutral no-interactive note (NO --all) and aws emits no
    finding."""
    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    (ct_dir / "events.json").write_text(
        "\n".join(json.dumps(e) for e in [
            _ct_service_event("2026-06-01T12:00:00Z", "aaaa"),
            _ct_service_event("2026-06-05T12:00:00Z", "bbbb"),
        ]) + "\n",
        encoding="utf-8",
    )
    runner.run(
        config={"sigwood": {"detect": "aws", "default_window": "1d"}},
        cloudtrail_dir=ct_dir,
    )
    s = capture_summary["summary"]
    note = next((n for n in s.notes if "none are interactive-lane" in n), None)
    assert note is not None, "the no-interactive disclosure must be appended"
    assert "--all" not in note, "unqualified → CloudTrail loaded full, no --all"
    findings = capture_summary.get("findings", [])
    assert not any(f.detector == "aws" for f in findings), "aws scored nothing"


def test_runner_aws_no_interactive_note_narrowed_end_to_end(
    tmp_path, capture_summary
):
    """#2 end-to-end: with an explicit window (CloudTrail narrowed), the same
    no-interactive note carries the --all suffix."""
    ct_dir = tmp_path / "ct"
    ct_dir.mkdir()
    (ct_dir / "events.json").write_text(
        "\n".join(json.dumps(e) for e in [
            _ct_service_event("2026-06-05T12:00:00Z", "bbbb"),
        ]) + "\n",
        encoding="utf-8",
    )
    runner.run(
        config={"sigwood": {"detect": "aws", "default_window": "1d"}},
        cloudtrail_dir=ct_dir,
        since=datetime(2026, 6, 4, tzinfo=timezone.utc),
        until=datetime(2026, 6, 6, tzinfo=timezone.utc),
    )
    s = capture_summary["summary"]
    note = next((n for n in s.notes if "none are interactive-lane" in n), None)
    assert note is not None
    assert "- run with --all for full history" in note


def test_interactive_count_helper() -> None:
    """Supplementary unit: interactive_count counts interactive-lane rows; 0 on
    all-service / empty / missing-lane (== the silent-nothing condition)."""
    import pandas as pd
    from sigwood.detectors.aws import interactive_count

    assert interactive_count(None) == 0
    assert interactive_count(pd.DataFrame()) == 0
    assert interactive_count(pd.DataFrame({"x": [1, 2]})) == 0  # missing lane
    assert interactive_count(pd.DataFrame({"lane": ["service", "service"]})) == 0
    assert interactive_count(
        pd.DataFrame({"lane": ["interactive", "service", "interactive"]})
    ) == 2


# ── large-dataset prompt: skip_confirm wiring ────────────────────────────────


_TINY_WARN_CFG = {"sigwood": {"detect": "beacon", "warn_above": 1, "default_window": "all"}}


def test_runner_skip_confirm_skips_prompt_entirely(
    tmp_path: Path, capture_summary, monkeypatch
) -> None:
    """skip_confirm=True must short-circuit the prompt - input() is never called."""
    from sigwood.common.errors import ExportAborted  # noqa: F401  (import resolves post-move)

    zeek_dir = _make_flat_zeek(tmp_path, [_conn(_TS_JAN1), _conn(_TS_JAN5)])

    def _no_input(*_a, **_kw):
        raise AssertionError("input() must not be called when skip_confirm=True")

    monkeypatch.setattr("builtins.input", _no_input)
    runner.run(config=_TINY_WARN_CFG, zeek_dir=zeek_dir, skip_confirm=True)
    # If we got here, no input() was called and the run completed.
    assert capture_summary["summary"] is not None


def test_runner_decline_raises_export_aborted(
    tmp_path: Path, capture_summary, monkeypatch
) -> None:
    """Decline at the large-dataset prompt must raise ExportAborted (not bare return)."""
    from sigwood.common.errors import ExportAborted

    zeek_dir = _make_flat_zeek(tmp_path, [_conn(_TS_JAN1), _conn(_TS_JAN5)])
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    with pytest.raises(ExportAborted, match="aborted by user"):
        runner.run(config=_TINY_WARN_CFG, zeek_dir=zeek_dir)


def test_runner_accept_continues_normally(
    tmp_path: Path, capture_summary, monkeypatch
) -> None:
    """Default skip_confirm=False with 'y' answer preserves interactive behavior."""
    zeek_dir = _make_flat_zeek(tmp_path, [_conn(_TS_JAN1), _conn(_TS_JAN5)])
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    runner.run(config=_TINY_WARN_CFG, zeek_dir=zeek_dir)
    assert capture_summary["summary"] is not None


# ── _build_output_handler: output_file precedence and behavior ───────────────


from sigwood.runner import _build_output_handler  # noqa: E402
from sigwood.common.finding import RunSummary  # noqa: E402


def _drive_handler(handler, close_handler) -> None:
    """Drive a handler through one no-finding lifecycle so its file is created."""
    summary = RunSummary(
        data_window=(datetime(2026, 1, 1, tzinfo=timezone.utc),
                     datetime(2026, 1, 2, tzinfo=timezone.utc)),
        record_counts={},
        data_size_bytes=0,
        detectors_run=["beacon"],
        detectors_skipped={},
    )
    handler.begin(summary)
    handler.write([])
    handler.end()
    close_handler()


def test_build_output_handler_writes_to_exact_output_file(tmp_path: Path) -> None:
    """output_file writes to the EXACT path; no auto-named file appears."""
    target = tmp_path / "hunt.txt"
    handler, close_handler, written = _build_output_handler(
        output_format="text", output_dir=None, output_file=target, verbose_level=0,
    )
    assert written == target  # the EXACT path, never collision-suffixed
    _drive_handler(handler, close_handler)
    assert target.exists()
    # No auto-named *.txt sibling
    siblings = [p.name for p in tmp_path.iterdir()]
    assert siblings == ["hunt.txt"]


def test_build_output_handler_explicit_file_is_not_collision_suffixed(
    tmp_path: Path,
) -> None:
    """An EXISTING explicit FILE verdict is used as-is (overwrite), NEVER
    routed through unique_path - no new no-clobber behavior for explicit paths."""
    target = tmp_path / "existing.txt"
    target.write_text("stale", encoding="utf-8")
    handler, close_handler, written = _build_output_handler(
        output_format="text", output_dir=None, output_file=target, verbose_level=0,
    )
    assert written == target
    _drive_handler(handler, close_handler)
    # Same path, overwritten - no existing-1.txt sibling.
    assert {p.name for p in tmp_path.iterdir()} == {"existing.txt"}


def test_build_output_handler_creates_parent_directories(tmp_path: Path) -> None:
    """output_file parent directories are mkdir-p'd at handler-build time."""
    target = tmp_path / "deep" / "nested" / "hunt.txt"
    assert not target.parent.exists()
    handler, close_handler, _written = _build_output_handler(
        output_format="text", output_dir=None, output_file=target, verbose_level=0,
    )
    _drive_handler(handler, close_handler)
    assert target.exists()
    assert target.parent.is_dir()


def test_build_output_handler_output_file_takes_precedence_over_output_dir(
    tmp_path: Path,
) -> None:
    """When both are set, output_file wins and no findings file is created under output_dir."""
    explicit = tmp_path / "explicit.txt"
    some_dir = tmp_path / "some_dir"
    handler, close_handler, written = _build_output_handler(
        output_format="text", output_dir=some_dir, output_file=explicit, verbose_level=0,
    )
    assert written == explicit
    _drive_handler(handler, close_handler)
    assert explicit.exists()
    # output_dir may or may not have been created; key invariant is that no
    # auto-named findings file lives in it.
    if some_dir.exists():
        assert not any(p.is_file() for p in some_dir.iterdir())


def test_build_output_handler_auto_names_text_reports_with_txt_suffix(
    tmp_path: Path,
) -> None:
    """Directory targets auto-name text reports sigwood-report_<token>_<date>.txt."""
    date = datetime.now().strftime("%Y%m%d")
    handler, close_handler, written = _build_output_handler(
        output_format="text", output_dir=tmp_path, output_file=None, verbose_level=0,
        detectors_run=["beacon"],
    )
    _drive_handler(handler, close_handler)

    files = [p for p in tmp_path.iterdir() if p.is_file()]
    assert len(files) == 1
    report = files[0]
    assert report == written
    assert report.name == f"sigwood-report_beacon_{date}.txt"
    assert not list(tmp_path.glob("*.text"))


def test_build_output_handler_directory_target_collision_suffixes(
    tmp_path: Path,
) -> None:
    """A second auto-named report in the same dir gets a -1 collision suffix."""
    date = datetime.now().strftime("%Y%m%d")
    for _ in range(2):
        handler, close_handler, _written = _build_output_handler(
            output_format="text", output_dir=tmp_path, output_file=None, verbose_level=0,
            detectors_run=["dns"],
        )
        _drive_handler(handler, close_handler)
    names = {p.name for p in tmp_path.iterdir() if p.is_file()}
    assert names == {f"sigwood-report_dns_{date}.txt", f"sigwood-report_dns_{date}-1.txt"}


class _FakeStdout:
    """stdout stand-in: controllable isatty() + a binary .buffer."""

    def __init__(self, *, tty: bool) -> None:
        self._tty = tty
        self.buffer = io.BytesIO()

    def isatty(self) -> bool:
        return self._tty


def test_build_output_handler_pdf_no_target_tty_raises(monkeypatch) -> None:
    """No-target pdf to a TERMINAL → PDF_TTY_ERROR (the runner's defensive guard
    for programmatic callers; raises before constructing the handler)."""
    from sigwood.outputs.pdf import PDF_TTY_ERROR

    monkeypatch.setattr("sys.stdout", _FakeStdout(tty=True))
    with pytest.raises(ValueError) as exc:
        _build_output_handler("pdf", output_dir=None, output_file=None, verbose_level=0)
    assert str(exc.value) == PDF_TTY_ERROR


def test_build_output_handler_pdf_no_buffer_raises_tty_error(monkeypatch) -> None:
    """A non-tty stdout WITHOUT a binary `.buffer` (e.g. a programmatic StringIO)
    can't take pdf bytes → PDF_TTY_ERROR, never a raw AttributeError."""
    from sigwood.outputs.pdf import PDF_TTY_ERROR

    monkeypatch.setattr("sys.stdout", io.StringIO())  # isatty()=False, no .buffer
    with pytest.raises(ValueError) as exc:
        _build_output_handler("pdf", output_dir=None, output_file=None, verbose_level=0)
    assert str(exc.value) == PDF_TTY_ERROR


def test_build_output_handler_pdf_no_target_pipe_streams_bytes(monkeypatch) -> None:
    """No-target pdf to a PIPE → handler wired to sys.stdout.buffer; the rendered
    bytes land there and no file is written."""
    import sigwood.outputs.pdf as pdf_mod

    monkeypatch.setattr(pdf_mod, "_render_pdf_bytes", lambda html_str: b"%PDF-fake")
    fake = _FakeStdout(tty=False)
    monkeypatch.setattr("sys.stdout", fake)
    handler, close_handler, written = _build_output_handler(
        "pdf", output_dir=None, output_file=None, verbose_level=0,
    )
    assert written is None
    _drive_handler(handler, close_handler)
    assert fake.buffer.getvalue() == b"%PDF-fake"


# ── analyze "wrote report to <path>" narration (after a clean write) ─────────


def test_runner_reports_written_report_path_after_clean_write(tmp_path, capsys) -> None:
    zeek_dir = _make_flat_zeek(tmp_path, [_conn(_TS_JAN5)])
    out = tmp_path / "r.txt"
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir, output_file=out, load_all=True)
    assert out.exists()
    assert f"wrote report to {out}" in capsys.readouterr().err


def test_runner_quiet_suppresses_written_report_line(tmp_path, capsys) -> None:
    zeek_dir = _make_flat_zeek(tmp_path, [_conn(_TS_JAN5)])
    out = tmp_path / "r.txt"
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir, output_file=out, load_all=True, quiet=True)
    assert out.exists()
    assert "wrote report to" not in capsys.readouterr().err


def test_runner_stdout_run_reports_no_written_path(tmp_path, capsys) -> None:
    zeek_dir = _make_flat_zeek(tmp_path, [_conn(_TS_JAN5)])
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir, load_all=True)
    assert "wrote report to" not in capsys.readouterr().err


def test_runner_dry_run_reports_no_written_path(tmp_path, capsys) -> None:
    zeek_dir = _make_flat_zeek(tmp_path, [_conn(_TS_JAN5)])
    out = tmp_path / "r.txt"
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir, output_file=out, dry_run=True)
    assert not out.exists()
    assert "wrote report to" not in capsys.readouterr().err


# ── Deliverable 0: dry-run alignment of source-dir lines ─────────────────────

def test_dry_run_source_dir_lines_left_justified_share_value_column(
    tmp_path: Path, capsys,
) -> None:
    """All four ``*_dir:`` labels are flush-LEFT
    and their value-starts share one column. Colons intentionally do NOT
    align, so the source-dir block matches the window/detectors/skipped
    block."""
    zeek = tmp_path / "zeek"; zeek.mkdir()
    syslog = tmp_path / "syslog"; syslog.mkdir()
    pihole = tmp_path / "pihole"; pihole.mkdir()
    cloudtrail = tmp_path / "ct"; cloudtrail.mkdir()
    _print_dry_run(
        zeek_dir=zeek, syslog_dir=syslog, pihole_dir=pihole, cloudtrail_dir=cloudtrail,
        since=None, until=None, load_all=False, will_run=[], skipped={},
    )
    out = capsys.readouterr().out.splitlines()

    labels = ("zeek_dir:", "syslog_dir:", "pihole_dir:", "cloudtrail_dir:")
    dir_lines = [ln for ln in out if any(label in ln for label in labels)]
    assert len(dir_lines) == 4, f"expected 4 source-dir lines, got {len(dir_lines)}"

    # Labels flush-left: each line begins with its own label, no leading indent.
    for ln, label in zip(dir_lines, labels):
        assert ln.startswith(label), f"label not flush-left: {ln!r}"

    # Value start = first non-space char after the trailing gutter; all share one
    # column (col 17 = 15-char left-justified label + 2-space gutter).
    value_starts = []
    for ln in dir_lines:
        i = ln.index(":") + 1
        while i < len(ln) and ln[i] == " ":
            i += 1
        value_starts.append(i)
    assert len(set(value_starts)) == 1, (
        f"value starts misaligned: {value_starts} in lines {dir_lines}"
    )


# ── Deliverable 3: aws RunSummary notes - pure helper tests ──────────────────

def _fake_aws_mod(below_floor: int = 0):
    """Tiny fake of the aws detector exposing only what the runner reads."""
    return SimpleNamespace(
        DETECTOR_NAME="aws",
        STATUS="available",
        DEFAULT_CONFIG={"min_events": 50},
        below_floor_count=lambda df, n: below_floor,
    )


def _fake_plan(will_run: list[str], aws_mod=None) -> SimpleNamespace:
    detectors = {"aws": aws_mod} if aws_mod is not None else {}
    return SimpleNamespace(
        detectors=detectors,
        selected=will_run,
        will_run=will_run,
        skipped={},
        needed_logs={"*.json*": "cloudtrail_dir"},
    )


def test_aws_below_floor_note_returns_string_with_count() -> None:
    from sigwood.runner import _aws_below_floor_note
    plan = _fake_plan(["aws"], _fake_aws_mod(below_floor=5))
    df = pd.DataFrame([{"lane": "interactive", "principal": "x"}])
    note = _aws_below_floor_note(plan, {"*.json*": df}, config={})
    assert note is not None
    assert "5" in note
    assert "min_events" in note


def test_aws_below_floor_note_returns_none_when_aws_not_in_plan() -> None:
    from sigwood.runner import _aws_below_floor_note
    plan = _fake_plan(["beacon"], aws_mod=None)
    df = pd.DataFrame([{"lane": "interactive", "principal": "x"}])
    assert _aws_below_floor_note(plan, {"*.json*": df}, config={}) is None


def test_aws_below_floor_note_returns_none_when_count_is_zero() -> None:
    from sigwood.runner import _aws_below_floor_note
    plan = _fake_plan(["aws"], _fake_aws_mod(below_floor=0))
    df = pd.DataFrame([{"lane": "interactive", "principal": "x"}])
    assert _aws_below_floor_note(plan, {"*.json*": df}, config={}) is None


def test_aws_below_floor_note_returns_none_when_no_frame() -> None:
    from sigwood.runner import _aws_below_floor_note
    plan = _fake_plan(["aws"], _fake_aws_mod(below_floor=5))
    assert _aws_below_floor_note(plan, {}, config={}) is None


def test_aws_window_note_fires_when_aws_runs() -> None:
    from sigwood.runner import _aws_window_note
    plan = _fake_plan(["aws"], _fake_aws_mod())
    note = _aws_window_note(plan)
    assert note is not None
    assert "first-seen" in note


def test_aws_window_note_silent_when_aws_did_not_run() -> None:
    from sigwood.runner import _aws_window_note
    plan = _fake_plan(["beacon"], aws_mod=None)
    assert _aws_window_note(plan) is None


# ── Integration: real runner.run() emits the note via the loaded frame ───────

def test_aws_below_floor_note_in_runner_run_reflects_current_frame(
    tmp_path: Path, capture_summary, monkeypatch
) -> None:
    """The note must appear in the RunSummary.notes the user actually sees, not
    just in the helper. A helper-only test could pass while the
    runner's call ordering or wiring was broken; this asserts the wired path."""
    # Build a CloudTrail directory whose loaded frame has 3 below-floor
    # interactive principals.
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    events: list[dict] = []
    for name in ["alice", "bob", "carol"]:
        for i in range(5):
            events.append({
                "eventTime":       f"2026-06-01T12:0{i}:00Z",
                "eventSource":     "s3.amazonaws.com",
                "eventName":       "GetObject",
                "eventID":         f"e-{name}-{i}",
                "awsRegion":       "us-east-1",
                "sourceIPAddress": "192.0.2.10",
                "userIdentity":    {"type": "IAMUser", "userName": name,
                                     "arn": f"arn:aws:iam::123456789012:user/{name}"},
                "readOnly":        True,
            })
    (cloudtrail_dir / "events.json.log").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n",
        encoding="utf-8",
    )

    # Use the real aws detector so the wiring is exercised end to end.
    import sigwood.detectors.aws as aws_mod
    monkeypatch.setattr(runner, "discover_detectors", lambda **_: {"aws": aws_mod})

    runner.run(
        config={"sigwood": {"detect": "aws"}},
        cloudtrail_dir=cloudtrail_dir,
    )

    s = capture_summary["summary"]
    floor_notes = [n for n in s.notes if "below the min_events floor" in n]
    assert floor_notes, f"expected below-floor note in {s.notes}"
    assert "3" in floor_notes[0]


def test_aws_window_note_in_runner_run(
    tmp_path: Path, capture_summary, monkeypatch
) -> None:
    """The window-boundary disclosure must appear whenever aws runs."""
    cloudtrail_dir = tmp_path / "ct"
    cloudtrail_dir.mkdir()
    event = {
        "eventTime":       "2026-06-01T12:00:00Z",
        "eventSource":     "s3.amazonaws.com",
        "eventName":       "GetObject",
        "eventID":         "e-1",
        "awsRegion":       "us-east-1",
        "sourceIPAddress": "192.0.2.10",
        "userIdentity":    {"type": "IAMUser", "userName": "placeholder",
                             "arn": "arn:aws:iam::123456789012:user/placeholder"},
        "readOnly":        True,
    }
    (cloudtrail_dir / "events.json.log").write_text(
        json.dumps(event) + "\n", encoding="utf-8",
    )

    import sigwood.detectors.aws as aws_mod
    monkeypatch.setattr(runner, "discover_detectors", lambda **_: {"aws": aws_mod})

    runner.run(
        config={"sigwood": {"detect": "aws"}},
        cloudtrail_dir=cloudtrail_dir,
    )

    s = capture_summary["summary"]
    assert any("first-seen" in n for n in s.notes)


# ── _home_net_note - scan topology disclosure ────────────────────────────────
#
# Pure helper tests of the runner's home_net disclosure note. Provenance is
# carried by the ``__user_set__`` sidecar attached by the config loader; tests
# construct it explicitly to drive both default and declared paths.

_RFC1918_HOME_NET = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def _scan_plan(scan_in_plan: bool) -> SimpleNamespace:
    will_run = ["scan"] if scan_in_plan else ["beacon"]
    return SimpleNamespace(
        detectors={},
        selected=will_run,
        will_run=will_run,
        skipped={},
        needed_logs={},
    )


def test_home_net_note_default_includes_parenthetical() -> None:
    from sigwood.runner import _home_net_note
    config = {"sigwood": {"home_net": _RFC1918_HOME_NET}}
    note = _home_net_note(_scan_plan(scan_in_plan=True), config)
    assert note is not None
    assert "10.0.0.0/8" in note
    assert "172.16.0.0/12" in note
    assert "192.168.0.0/16" in note
    assert "RFC1918 default" in note
    assert "set home_net in config to override" in note


def test_home_net_note_declared_omits_parenthetical_with_custom_range() -> None:
    from sigwood.runner import _home_net_note
    config = {
        "sigwood": {"home_net": ["192.0.2.0/24"]},
        "__user_set__": {"sigwood": {"home_net"}},
    }
    note = _home_net_note(_scan_plan(scan_in_plan=True), config)
    assert note is not None
    assert "192.0.2.0/24" in note
    assert "RFC1918 default" not in note


def test_home_net_note_declared_omits_parenthetical_when_value_equals_default() -> None:
    """User explicitly types the RFC1918 list - must read as declared, not default.

    A value-only check would misclassify this. The ``__user_set__`` sidecar
    is the provenance source of truth.
    """
    from sigwood.runner import _home_net_note
    config = {
        "sigwood": {"home_net": list(_RFC1918_HOME_NET)},
        "__user_set__": {"sigwood": {"home_net"}},
    }
    note = _home_net_note(_scan_plan(scan_in_plan=True), config)
    assert note is not None
    assert "10.0.0.0/8" in note
    assert "RFC1918 default" not in note
    assert "override" not in note


def test_home_net_note_returns_none_when_scan_not_in_plan() -> None:
    from sigwood.runner import _home_net_note
    config = {"sigwood": {"home_net": _RFC1918_HOME_NET}}
    assert _home_net_note(_scan_plan(scan_in_plan=False), config) is None


# ── Stage 3: caller-owned TextIO seam for digest fan-out ─────────────────────


def test_build_output_handler_caller_stream_no_open_no_close(
    tmp_path: Path,
) -> None:
    """``_build_output_handler(..., stream=<TextIO>)`` returns a handler
    wrapping the caller's stream with a no-op close - the stream stays open
    after the close callback runs."""
    import io as _io
    from sigwood.runner import _build_output_handler

    buf = _io.StringIO()
    handler, close, written = _build_output_handler(
        "text", output_dir=None, output_file=None, verbose_level=0, stream=buf,
    )
    assert written is None  # caller owns the stream; the CLI reports digest paths
    close()
    assert not buf.closed
    # Handler must write to the caller's buffer, not stdout.
    handler._stream.write("probe\n")
    assert buf.getvalue() == "probe\n"


def test_run_digest_conn_writes_to_caller_stream(
    tmp_path: Path,
) -> None:
    """``run_digest(..., stream=<StringIO>)`` writes the conn card to the
    caller-owned stream - never touches output_dir / output_file."""
    import io as _io
    from sigwood import runner as _runner

    log_path = tmp_path / "conn.log"
    log_path.write_text(
        '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10", '
        '"id.resp_h": "198.51.100.20", "id.resp_p": 443, '
        '"proto": "tcp", "duration": 1.23}\n',
        encoding="utf-8",
    )
    buf = _io.StringIO()
    _runner.run_digest(
        config={"sigwood": {}},
        zeek_dir=log_path,
        stream=buf,
        skip_confirm=True,
        schema="conn",
    )
    rendered = buf.getvalue()
    # Flat-card identity block: source basename on line 1; "conn · …" on
    # line 3. No banner, no header rule under the new grammar.
    assert "conn.log" in rendered
    assert "conn ·" in rendered
    # No file was created next to the input log.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["conn.log"]


def test_run_digest_blob_writes_to_caller_stream(
    tmp_path: Path,
) -> None:
    """Stage 3 regression: ``run_digest(schema='blob', stream=<StringIO>)``
    writes the blob card to the caller-owned stream. Without the stream
    being threaded into ``_run_digest_blob``'s ``_build_output_handler``,
    blob cards would silently bypass the shared --out file and the fan-out
    contract would break the moment a positional sniffed to blob."""
    import io as _io
    from sigwood import runner as _runner

    blob = tmp_path / "weird.txt"
    blob.write_text(
        "unrecognized-app-banner xyzzy 42 frobnicate\n"
        "second line with no clear schema\n",
        encoding="utf-8",
    )
    buf = _io.StringIO()
    _runner.run_digest(
        config={"sigwood": {}},
        blob_path=blob,
        stream=buf,
        skip_confirm=True,
        schema="blob",
    )
    rendered = buf.getvalue()
    # Flat blob card: source basename on identity line 1; the labeled
    # best-guess headline names "Unrecognized source". No header rule.
    assert "weird.txt" in rendered
    assert "Unrecognized source" in rendered
    # No incidental files materialised in tmp_path beyond the input.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["weird.txt"]


# ── Liveness narration in the detector loop ───────────────────────────────────


def test_loading_detectors_liveness_wraps_plan_build_and_dry_run_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """Plan building is inside the detector-loading liveness phase; dry-run
    output stays stdout-only and does not contain the status label."""
    calls: list[tuple[str, bool]] = []

    @contextmanager
    def _fake_liveness(label: str, delay: float = 0.0, *, enabled: bool = True):
        calls.append((label, enabled))
        yield SimpleNamespace(seal=lambda _text: None)

    def _empty_plan(**_kw):
        return RunPlan(detectors={}, selected=[], will_run=[], skipped={}, needed_logs={})

    monkeypatch.setattr(runner, "liveness", _fake_liveness)
    monkeypatch.setattr(runner, "build_run_plan", _empty_plan)

    runner.run(config={"sigwood": {}}, dry_run=True)
    captured = capsys.readouterr()

    assert calls == [("loading detectors", True)]
    assert "loading detectors" not in captured.out
    assert "dry run" in captured.out

    calls.clear()
    runner.run(config={"sigwood": {}}, quiet=True)
    assert calls == [("loading detectors", False)]


def test_rendering_report_liveness_wraps_write_end_and_dry_run_skips_render(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The report write/end tail is one liveness phase; dry-run exits before
    output-handler construction or render narration."""
    calls: list[tuple[str, bool]] = []

    @contextmanager
    def _fake_liveness(label: str, delay: float = 0.0, *, enabled: bool = True):
        calls.append((label, enabled))
        yield SimpleNamespace(seal=lambda _text: None)

    class _CapHandler:
        def begin(self, _summary): pass
        def write(self, _findings): calls.append(("handler.write", True))
        def end(self): calls.append(("handler.end", True))

    def _fake_build(*_args, **_kw):
        return _CapHandler(), (lambda: None), None

    fake = _fake_detector("alpha", lambda _ctx: [])
    monkeypatch.setattr(runner, "liveness", _fake_liveness)
    monkeypatch.setattr(runner, "discover_detectors", lambda **_: {"alpha": fake})
    monkeypatch.setattr(runner, "_build_output_handler", _fake_build)

    runner.run(config={"sigwood": {"detect": "alpha"}})

    assert ("rendering report", True) in calls
    render_i = calls.index(("rendering report", True))
    assert calls[render_i + 1: render_i + 3] == [
        ("handler.write", True),
        ("handler.end", True),
    ]

    calls.clear()

    def _no_build(*_args, **_kw):
        raise AssertionError("dry-run must not build an output handler")

    monkeypatch.setattr(runner, "_build_output_handler", _no_build)
    runner.run(config={"sigwood": {"detect": "alpha"}}, dry_run=True)
    assert "dry run" in capsys.readouterr().out
    assert ("rendering report", True) not in calls

    calls.clear()
    monkeypatch.setattr(runner, "_build_output_handler", _fake_build)
    runner.run(config={"sigwood": {"detect": "alpha"}}, quiet=True)
    assert ("rendering report", False) in calls


def _fake_detector(name: str, run_impl):
    """Build a minimal fake detector module suitable for the runner loop."""
    return SimpleNamespace(
        DETECTOR_NAME=name,
        STATUS="available",
        REQUIRED_LOGS=[],
        OPTIONAL_LOGS=[],
        DEFAULT_CONFIG={},
        run=run_impl,
    )


def test_liveness_seals_one_record_per_non_syslog_detector(
    tmp_path: Path, capture_summary, monkeypatch, capsys
) -> None:
    """Two non-syslog detectors → two sealed lines (one per detector). The
    detector that returned findings gets the completion record 'done'; the
    empty one gets 'nothing'. The seal MUST NOT carry the finding count -
    the report header is the single authoritative count surface. Both
    records go to stderr only."""
    f1 = SimpleNamespace()  # opaque placeholder Findings - handler is patched
    f2 = SimpleNamespace()
    fakes = {
        "alpha": _fake_detector("alpha", lambda ctx: [f1, f2]),
        "beta":  _fake_detector("beta",  lambda ctx: []),
    }
    monkeypatch.setattr(runner, "discover_detectors", lambda **_: fakes)

    runner.run(config={"sigwood": {"detect": "alpha,beta"}})

    captured = capsys.readouterr()
    assert "alpha: done" in captured.err
    assert "beta: nothing" in captured.err
    # Seal MUST NOT contain the finding count - the header carries it.
    import re
    assert not re.search(r"alpha: \d+ findings", captured.err)
    # Records are stderr-only; stdout carries findings rendering (suppressed
    # here by the capture_summary fake handler).
    assert "alpha: done" not in captured.out
    assert "beta: nothing" not in captured.out
    # The captured findings via the patched handler include both detectors'
    # output (the patched handler is what the user pointed at - runner.run
    # returns None, so we assert against the captured findings list).
    assert capture_summary["findings"] == [f1, f2]


def test_liveness_suppresses_seal_on_detector_error(
    tmp_path: Path, capture_summary, monkeypatch, capsys
) -> None:
    """A detector that raises Exception leaves the existing 'detector error'
    line, and the liveness block emits NO sealed record (no false success)."""
    def _boom(ctx):
        raise RuntimeError("boom")

    fakes = {"gamma": _fake_detector("gamma", _boom)}
    monkeypatch.setattr(runner, "discover_detectors", lambda **_: fakes)

    runner.run(config={"sigwood": {"detect": "gamma"}})

    captured = capsys.readouterr()
    assert "gamma: detector error - boom" in captured.err
    # No seal of any shape for the errored detector.
    assert "gamma: nothing" not in captured.err
    assert "gamma: 0 findings" not in captured.err
    import re
    assert not re.search(r"gamma: \d+ findings", captured.err)
    # The patched handler still got called with an empty findings list
    # (run completes; the error did not abort the loop).
    assert capture_summary["findings"] == []


def test_liveness_skips_outer_spinner_for_syslog(
    tmp_path: Path, capture_summary, monkeypatch, capsys
) -> None:
    """syslog gets no outer liveness wrapper - its inner drain3 tqdm carries
    the narration for that phase. Verified as the absence of the outer
    'running syslog' label and the absence of a 'syslog: ...' seal."""
    fakes = {"syslog": _fake_detector("syslog", lambda ctx: [])}
    monkeypatch.setattr(runner, "discover_detectors", lambda **_: fakes)

    runner.run(config={"sigwood": {"detect": "syslog"}})

    captured = capsys.readouterr()
    assert "running syslog" not in captured.err
    assert "syslog: nothing" not in captured.err
    assert "syslog: 0 findings" not in captured.err


# ── _ts_confidence (item 4: timestamp-confidence floor) ──────────────────────


def _ts_frame(ts_values: list[float]) -> pd.DataFrame:
    """Build a minimal frame carrying only the ts column from a list of
    float values (use float("nan") for unparseable rows)."""
    return pd.DataFrame({"ts": ts_values})


def test_ts_confidence_full_parseable_with_span_is_confident() -> None:
    """All rows parseable + non-zero span → True."""
    assert _ts_confidence(_ts_frame([1000.0, 1100.0, 1200.0, 1300.0])) is True


def test_ts_confidence_at_floor_passes() -> None:
    """Parseable fraction equal to the floor (8/10 = 0.80) + non-zero span
    → True; the floor is inclusive."""
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0,
              float("nan"), float("nan")]
    assert _ts_confidence(_ts_frame(values)) is True
    assert _DIGEST_TS_CONFIDENCE_FLOOR == 0.80


def test_ts_confidence_just_below_floor_fails() -> None:
    """7/10 = 0.70 < 0.80 → False."""
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0,
              float("nan"), float("nan"), float("nan")]
    assert _ts_confidence(_ts_frame(values)) is False


def test_ts_confidence_all_nan_fails() -> None:
    """Every ts unparseable → False (coverage gate)."""
    assert _ts_confidence(_ts_frame([float("nan")] * 50)) is False


def test_ts_confidence_zero_span_fails() -> None:
    """All events at the same instant → False (span gate).

    The flat card renders the SAME bare "(timeline unavailable)" line
    for both the coverage gate and the span gate; there is no differentiated
    footer text and no sentinel reasons.
    """
    assert _ts_confidence(_ts_frame([42.0] * 80)) is False


def test_ts_confidence_no_ts_column_fails() -> None:
    """A frame with no ts column → False (structural coverage shape)."""
    frame = pd.DataFrame({"src": ["192.0.2.1", "192.0.2.2"]})
    assert _ts_confidence(frame) is False


def test_ts_confidence_empty_frame_fails() -> None:
    """Defensive: an empty frame returns False."""
    assert _ts_confidence(pd.DataFrame({"ts": []})) is False


# ── Both timeline-failure modes render the same bare line (no footer) ───────


def _zeek_conn_line(ts: float) -> str:
    return (
        '{"_path": "conn", "ts": ' + repr(ts) + ', "id.orig_h": "192.0.2.10",'
        ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp"}\n'
    )


def test_run_digest_zero_span_renders_bare_timeline_unavailable(
    tmp_path: Path, capsys,
) -> None:
    """Zero-span timestamps render the bare "(timeline unavailable)" line
    and NO footer block. The flat card grammar carries no differentiated
    footer text."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text(
        _zeek_conn_line(1779750000.0) * 5,
        encoding="utf-8",
    )

    runner.run_digest(
        config={"sigwood": {}},
        zeek_dir=zeek_dir, load_all=True, skip_confirm=True,
    )
    out = capsys.readouterr().out
    assert "(timeline unavailable)" in out
    # No footer / N.B. block anywhere in the flat grammar.
    assert "N.B." not in out
    assert "timeline collapsed" not in out
    assert "timestamp unparseable" not in out


def test_run_digest_low_coverage_renders_bare_timeline_unavailable(
    tmp_path: Path, capsys,
) -> None:
    """Low-coverage timestamps render the SAME bare line as zero-span -
    proves the _ts_confidence collapse to a boolean predicate, not just
    sentinel deletion."""
    syslog_dir = tmp_path / "syslog"
    syslog_dir.mkdir()
    (syslog_dir / "router.log").write_text(
        "<134>May 31 12:00:00 192.0.2.1 sshd[100]: real line\n"
        "garbage line 1\n"
        "garbage line 2\n"
        "garbage line 3\n"
        "garbage line 4\n",
        encoding="utf-8",
    )

    runner.run_digest(
        config={"sigwood": {}},
        syslog_dir=syslog_dir, load_all=True, skip_confirm=True,
        schema="syslog",
    )
    out = capsys.readouterr().out
    assert "(timeline unavailable)" in out
    assert "N.B." not in out
    assert "timestamp unparseable" not in out
    assert "floor 80%" not in out


def test_run_digest_summariser_raise_without_fallback_path_reraises(
    tmp_path: Path, monkeypatch,
) -> None:
    """When ``fallback_blob_path`` is None (the bare-config caller has no
    single-file fallback available), a summariser raise propagates out so
    the CLI's existing ValueError arm can format the message. The narrow
    wrap MUST NOT swallow exceptions silently when no fallback is
    available."""
    # Build a minimal Zeek conn file that loads fine.
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text(
        '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
        ' "id.resp_h": "198.51.100.20", "id.resp_p": 443, "proto": "tcp"}\n',
        encoding="utf-8",
    )

    def _exploding_summarizer(_schema_name: str):
        def _raise(*_a, **_kw):
            raise RuntimeError("induced summariser failure")
        return _raise

    monkeypatch.setattr(
        "sigwood.digest.get_summarizer", _exploding_summarizer,
    )

    # No fallback_blob_path → must re-raise.
    with pytest.raises(RuntimeError, match="induced summariser failure"):
        runner.run_digest(
            config={"sigwood": {}},
            zeek_dir=zeek_dir, load_all=True, skip_confirm=True,
            # fallback_blob_path is the default None.
        )


# ── _prepare_detector_context + prep-error vs detector-error labels ─────────
#
# Per-detector prep (filter_df + DetectorContext construction) lives
# INSIDE the per-detector liveness block, so the spinner appears as soon
# as the operator-visible work begins. A failure during prep must be
# labelled "prep error" - distinct from "detector error" - because the
# runner owns prep, not the detector (separation-of-powers).


def _zeek_conn_dir(tmp_path: Path) -> Path:
    """Build a minimal Zeek conn directory with one parseable record."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    _write_ndjson(zeek_dir / "conn.log", [
        _conn(_TS_JAN5),
        _conn(_TS_JAN5 + 60.0),
    ])
    return zeek_dir


def test_prep_error_renders_prep_error_label_not_detector_error(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """A failure inside _prepare_detector_context surfaces as
    'prep error', NOT 'detector error'. The detector module is not at
    fault - the runner's own prep raised."""
    zeek_dir = _zeek_conn_dir(tmp_path)

    def _exploding_prep(*_a, **_kw):
        raise RuntimeError("induced prep failure")

    monkeypatch.setattr(
        runner, "_prepare_detector_context", _exploding_prep,
    )

    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)

    err = capsys.readouterr().err
    assert "beacon: prep error - induced prep failure" in err
    # The detector-error label must NOT appear - that would mislead the
    # operator about WHERE the failure was. Separation-of-powers detail.
    assert "beacon: detector error" not in err


def test_detector_error_label_preserved_byte_identical(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    """A failure inside mod.run(ctx) keeps the existing
    'detector error - ...' shape exactly. Today's contract preserved."""
    zeek_dir = _zeek_conn_dir(tmp_path)

    import sigwood.detectors.beacon as beacon_mod

    def _exploding_run(_ctx):
        raise RuntimeError("induced detector failure")

    monkeypatch.setattr(beacon_mod, "run", _exploding_run)

    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)

    err = capsys.readouterr().err
    assert "beacon: detector error - induced detector failure" in err
    # The new prep-error label must NOT appear for a detector-side raise.
    assert "beacon: prep error" not in err


def test_liveness_seal_lands_once_for_successful_run(
    tmp_path: Path, monkeypatch, capsys, capture_summary,
) -> None:
    """A successful detector run produces exactly one sealed liveness
    record ('beacon: done' or 'beacon: nothing' - the seal carries no
    count; the report header is the single authoritative count surface).
    Guards against a double-seal regression - the prep block is INSIDE the
    liveness scope, so a stray extra seal would land if the body were
    wrapped twice."""
    zeek_dir = _zeek_conn_dir(tmp_path)

    # Patch beacon's run() to return nothing - sidesteps fixture
    # field-shape mismatches; this test is about seal accounting, not
    # detector logic.
    import sigwood.detectors.beacon as beacon_mod
    monkeypatch.setattr(beacon_mod, "run", lambda _ctx: [])

    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)
    err = capsys.readouterr().err
    # Either "beacon: N findings" or "beacon: nothing" - exactly one of
    # them, exactly once.
    seal_lines = [
        ln for ln in err.splitlines()
        if ln.strip().startswith("beacon:") and "error" not in ln
    ]
    assert len(seal_lines) == 1, (
        f"expected exactly one beacon seal line, got {seal_lines!r}"
    )


def test_prepare_detector_context_filters_per_pattern(tmp_path: Path) -> None:
    """Unit: _prepare_detector_context calls allowlist.filter_df once per
    pattern the detector declares (REQUIRED + OPTIONAL), and builds a
    DetectorContext with the filtered view. Verifies the pure extraction
    of the previously inline prep."""
    from sigwood.common.finding import DetectorContext as _DC

    mod = SimpleNamespace(
        REQUIRED_LOGS=[{"source": "zeek_dir", "pattern": "conn*.log*"}],
        OPTIONAL_LOGS=[{"source": "zeek_dir", "pattern": "dns*.log*"}],
    )

    conn_df = pd.DataFrame({"a": [1, 2]})
    dns_df = pd.DataFrame({"b": [3]})
    other_df = pd.DataFrame({"c": [4]})

    filter_calls: list[tuple[str, str]] = []

    class _RecordingAllowlist:
        def filter_df(self, df, name):
            filter_calls.append((name, "<df>"))
            # Identity filter for the test - we only care about being called.
            return df

    logs = {
        "conn*.log*": conn_df,
        "dns*.log*": dns_df,
        "other*.log*": other_df,
    }
    ctx = runner._prepare_detector_context(
        mod=mod, name="beacon", logs=logs,
        allowlist=_RecordingAllowlist(),
        det_cfg={"k": "v"},
        data_window=(_NOW := datetime(2026, 1, 5, tzinfo=timezone.utc),
                     _NOW),
        data_sources=["zeek_conn"],
        home_net=["10.0.0.0/8"],
    )

    # filter_df called for each declared pattern, in name=beacon.
    assert ("beacon", "<df>") in filter_calls
    assert filter_calls.count(("beacon", "<df>")) == 2  # conn + dns
    # other*.log* is NOT in the detector's declared patterns - passes
    # through unfiltered.
    assert "other*.log*" in ctx.logs
    assert ctx.logs["other*.log*"] is other_df

    # The returned context is shaped like the previously inline DetectorContext.
    assert isinstance(ctx, _DC)
    assert ctx.config == {"k": "v"}
    assert ctx.data_sources == ["zeek_conn"]
    assert ctx.home_net == ["10.0.0.0/8"]


# ── Rotation-peek disclosure notes (real runner.run, syslog_dir) ───────────────
#
# Drive runner.run end-to-end (NOT mocked) so the loader→RunSummary note seam is
# exercised. since/until are derived by parsing the fixture lines so the tests do
# not depend on the machine clock year. _rotation_skip_notes is the formatter.

from sigwood.parsers.syslog import parse_timestamp as _parse_ts

_SYSLOG_ONLY = {"sigwood": {"detect": "syslog"}}


def _sysrot_line(mon: str, day: int) -> str:
    return f"{mon} {day:>2} 12:00:00 host1 sshd[1]: session opened for user"


def _write_sysrot(d: Path, base: str, ts_by_ordinal: dict[int, tuple[str, int]]) -> None:
    d.mkdir(parents=True, exist_ok=True)
    for idx, (mon, day) in ts_by_ordinal.items():
        name = base if idx == 0 else f"{base}.{idx}"
        (d / name).write_text(_sysrot_line(mon, day) + "\n", encoding="utf-8")


def test_runner_rotation_skip_note_neutral_wording(tmp_path, capture_summary, capsys):
    """A bounded --since/--until run that skips BOTH a too-new leading file AND a
    too-old tail file under one count → the NEUTRAL 'outside' wording (truthful
    for both directions), counts off the post-window candidates. The normal prune
    is report-only: NO double-count clause and it does NOT print to stderr."""
    d = tmp_path / "syslog"
    _write_sysrot(d, "syslog.log", {
        0: ("Jun", 10),  # too-new (oldest row > until) → skipped
        1: ("Jun", 8),   # in window
        2: ("Jun", 6),   # in window
        3: ("Jun", 4),   # straddle since → kept
        4: ("Jun", 2),   # too-old → skipped
    })
    runner.run(
        config=_SYSLOG_ONLY,
        syslog_dir=d,
        since=_parse_ts(_sysrot_line("Jun", 5)),
        until=_parse_ts(_sysrot_line("Jun", 9)),
    )
    s = capture_summary["summary"]
    expected = (
        "syslog: loaded 3 of 5 rotation files; 2 skipped outside the selected "
        "window (by rotation order)"
    )
    assert expected in s.notes
    # the double-count clause is a CONTENT-overlap concern; the normal prune never
    # carries it, and the prune stays report-only (not surfaced to stderr).
    assert not any("counted twice" in n for n in s.notes)
    assert expected not in capsys.readouterr().err


def test_runner_rotation_fallback_note_wins(tmp_path, capture_summary, capsys):
    """One out-of-order rotation family → ONE fallback note for the pattern and
    NO skip-summary (fallback is data-true: the whole archive is read). Gross
    disorder reorders without duplicating → NO double-count clause; the fallback
    ALSO surfaces to stderr."""
    d = tmp_path / "syslog"
    _write_sysrot(d, "auth.log", {0: ("Jun", 6), 1: ("Jun", 5), 2: ("Jun", 4), 3: ("Jun", 3)})
    _write_sysrot(d, "kern.log", {0: ("Jun", 8), 1: ("Jun", 10)})  # first-ts RISE → disorder
    runner.run(
        config=_SYSLOG_ONLY,
        syslog_dir=d,
        since=_parse_ts(_sysrot_line("Jun", 5)),
    )
    s = capture_summary["summary"]
    expected = (
        "syslog: rotation order not monotonic - read the full archive "
        "(windowing skipped)"
    )
    assert expected in s.notes
    assert not any("skipped outside the selected window" in n for n in s.notes)
    assert not any("counted twice" in n for n in s.notes)
    assert expected in capsys.readouterr().err


def test_runner_rotation_no_note_when_unwindowed(tmp_path, capture_summary):
    """No explicit window → flat load reads all, no rotation note."""
    d = tmp_path / "syslog"
    _write_sysrot(d, "syslog.log", {0: ("Jun", 6), 1: ("Jun", 5), 2: ("Jun", 4)})
    runner.run(config=_SYSLOG_ONLY, syslog_dir=d, load_all=True)
    s = capture_summary["summary"]
    assert not any("rotation" in n.lower() for n in s.notes)


def test_runner_rotation_overlap_export_window_note(tmp_path, capture_summary, capsys):
    """Overlapping exporter-output windows in a flat dir → the overlap fallback
    wording WITH the double-count clause (whole-pattern full read), distinct from
    the monotonic note, and ALSO surfaced to stderr."""
    d = tmp_path / "syslog"
    d.mkdir(parents=True, exist_ok=True)
    (d / "splunk_20260601_7d.log").write_text(_sysrot_line("Jun", 1) + "\n", encoding="utf-8")
    (d / "splunk_20260605_1d.log").write_text(_sysrot_line("Jun", 5) + "\n", encoding="utf-8")
    runner.run(
        config=_SYSLOG_ONLY,
        syslog_dir=d,
        since=_parse_ts(_sysrot_line("Jun", 5)),
    )
    s = capture_summary["summary"]
    expected = (
        "syslog: overlapping export windows - read the full archive "
        "(windowing skipped; overlapping rows may be counted twice)"
    )
    assert expected in s.notes
    assert not any("not monotonic" in n for n in s.notes)
    assert expected in capsys.readouterr().err


def test_runner_rotation_duplicate_note(tmp_path, capture_summary, capsys):
    """A duplicate rotation slot (a file + its .gz sibling collapsing to one
    age_rank) → the 'duplicate rotation files' fallback wording WITH the
    double-count clause, distinct from the monotonic and overlap notes, and ALSO
    surfaced to stderr."""
    d = tmp_path / "syslog"
    d.mkdir(parents=True, exist_ok=True)
    (d / "auth.log").write_text(_sysrot_line("Jun", 6) + "\n", encoding="utf-8")
    with gzip.open(d / "auth.log.gz", "wt", encoding="utf-8") as fh:
        fh.write(_sysrot_line("Jun", 6) + "\n")
    runner.run(
        config=_SYSLOG_ONLY,
        syslog_dir=d,
        since=_parse_ts(_sysrot_line("Jun", 5)),
    )
    s = capture_summary["summary"]
    expected = (
        "syslog: duplicate rotation files - read the full archive "
        "(windowing skipped; duplicate rows may be counted twice)"
    )
    assert expected in s.notes
    assert not any(("not monotonic" in n or "overlapping" in n) for n in s.notes)
    assert expected in capsys.readouterr().err


def test_runner_rotation_fallback_quiet_suppresses_stderr_not_notes(
    tmp_path, capture_summary, capsys,
):
    """quiet gates the stderr fallback line ONLY - the RunSummary note (the report
    surface) still carries the disclosure."""
    d = tmp_path / "syslog"
    _write_sysrot(d, "auth.log", {0: ("Jun", 6), 1: ("Jun", 5), 2: ("Jun", 4), 3: ("Jun", 3)})
    _write_sysrot(d, "kern.log", {0: ("Jun", 8), 1: ("Jun", 10)})  # first-ts RISE → disorder
    runner.run(
        config=_SYSLOG_ONLY,
        syslog_dir=d,
        since=_parse_ts(_sysrot_line("Jun", 5)),
        quiet=True,
    )
    s = capture_summary["summary"]
    expected = (
        "syslog: rotation order not monotonic - read the full archive "
        "(windowing skipped)"
    )
    assert expected in s.notes                       # report unaffected by quiet
    assert expected not in capsys.readouterr().err   # stderr suppressed by -q


def test_runner_rotation_fallback_stderr_matches_note(tmp_path, capture_summary, capsys):
    """ONE formatter, two surfaces: the stderr fallback line is byte-identical to
    its RunSummary.notes entry (guards future drift between report and stderr)."""
    d = tmp_path / "syslog"
    d.mkdir(parents=True, exist_ok=True)
    (d / "splunk_20260601_7d.log").write_text(_sysrot_line("Jun", 1) + "\n", encoding="utf-8")
    (d / "splunk_20260605_1d.log").write_text(_sysrot_line("Jun", 5) + "\n", encoding="utf-8")
    runner.run(
        config=_SYSLOG_ONLY,
        syslog_dir=d,
        since=_parse_ts(_sysrot_line("Jun", 5)),
    )
    s = capture_summary["summary"]
    err_lines = [
        ln for ln in capsys.readouterr().err.splitlines()
        if "overlapping export windows" in ln
    ]
    note_lines = [n for n in s.notes if "overlapping export windows" in n]
    assert err_lines and note_lines
    assert err_lines == note_lines  # byte-identical → one shared formatter


# ── _source_overlap_notes - plan-time source-dir overlap disclosure ───────────


def _plan_with_needed(needed_logs: dict[str, str]) -> RunPlan:
    """Minimal RunPlan carrying only the needed_logs the overlap helper reads."""
    return RunPlan(
        detectors={}, selected=[], will_run=[],
        skipped={}, needed_logs=needed_logs,
    )


def test_source_overlap_two_families_same_dir(tmp_path) -> None:
    """Two IN-PLAN families resolved to the same directory → exactly one note
    naming both, in canonical key order."""
    shared = tmp_path / "shared"
    shared.mkdir()
    source_dirs = {"zeek_dir": [shared], "syslog_dir": [shared]}
    plan = _plan_with_needed(
        {"conn*.log*": "zeek_dir", "*.log*": "syslog_dir"}
    )
    notes = _source_overlap_notes(source_dirs, plan)
    assert len(notes) == 1, notes
    assert notes[0].startswith("zeek_dir, syslog_dir resolve to the same directory")
    assert str(shared.resolve()) in notes[0]
    # Customized-path-truthful tail (no hard-coded exports/<x>/).
    assert "global exports now auto-segment per source" in notes[0]


def test_source_overlap_three_families_same_dir(tmp_path) -> None:
    """≥3 families at one dir → one note listing all three, canonical order."""
    shared = tmp_path / "shared"
    shared.mkdir()
    source_dirs = {
        "zeek_dir": [shared], "syslog_dir": [shared], "pihole_dir": [shared],
    }
    plan = _plan_with_needed({
        "conn*.log*": "zeek_dir",
        "*.log*": "syslog_dir",
        "pihole*.log*": "pihole_dir",
    })
    notes = _source_overlap_notes(source_dirs, plan)
    assert len(notes) == 1, notes
    assert notes[0].startswith(
        "zeek_dir, syslog_dir, pihole_dir resolve to the same directory"
    )


def test_source_overlap_in_plan_negative(tmp_path) -> None:
    """Sharp case: two configured dirs resolve to the same directory but
    only ONE family is in the plan → NO note about the out-of-plan sibling."""
    shared = tmp_path / "shared"
    shared.mkdir()
    source_dirs = {"zeek_dir": [shared], "syslog_dir": [shared]}
    # Only zeek_dir is planned (e.g. detect=beacon); syslog_dir is configured
    # but unselected, so it cannot contaminate the run.
    plan = _plan_with_needed({"conn*.log*": "zeek_dir"})
    assert _source_overlap_notes(source_dirs, plan) == []


def test_source_overlap_nested_dirs_stay_silent(tmp_path) -> None:
    """Equal-dir ONLY: a NESTED pair (parent containing child) is NOT an
    overlap - flat discovery is non-recursive. Uses real existing dirs so the
    rail is proven by path inequality, not by a missing dir on the test box."""
    varlog = tmp_path / "varlog"
    zeek = varlog / "zeek"
    zeek.mkdir(parents=True)
    source_dirs = {"syslog_dir": [varlog], "zeek_dir": [zeek]}
    plan = _plan_with_needed(
        {"*.log*": "syslog_dir", "conn*.log*": "zeek_dir"}
    )
    assert _source_overlap_notes(source_dirs, plan) == []


def test_source_overlap_files_out_of_scope(tmp_path) -> None:
    """Explicit FILE inputs are out of scope - the vector is dir-glob overlap,
    not a shared named file."""
    f = tmp_path / "shared.log"
    f.write_text("x", encoding="utf-8")
    source_dirs = {"zeek_dir": [f], "syslog_dir": [f]}
    plan = _plan_with_needed(
        {"conn*.log*": "zeek_dir", "*.log*": "syslog_dir"}
    )
    assert _source_overlap_notes(source_dirs, plan) == []


def test_source_overlap_collapses_per_family_duplicates(tmp_path) -> None:
    """Two inputs in ONE family resolving to the same dir are not an overlap -
    overlap requires two DISTINCT families."""
    shared = tmp_path / "shared"
    shared.mkdir()
    source_dirs = {"zeek_dir": [shared, shared]}
    plan = _plan_with_needed({"conn*.log*": "zeek_dir"})
    assert _source_overlap_notes(source_dirs, plan) == []


# ── runner seam pin: the overlap note reaches RunSummary.notes ────────────────


def test_runner_emits_source_overlap_note(
    tmp_path, capture_summary, mock_load_required_logs,
) -> None:
    """Seam pin: the one-line notes.extend wiring lands the overlap note
    on the user-facing RunSummary.notes surface, not just in the pure helper.

    zeek_dir (beacon, REQUIRED conn*.log*) and cloudtrail_dir (aws, REQUIRED
    *.json*) both point at one shared directory holding both files → both
    families are in-plan at the same resolved dir → overlap note fires."""
    from sigwood.common.loader import LoadResult, SourceCoverage

    shared = tmp_path / "shared"
    shared.mkdir()
    _write_ndjson(shared / "conn.log", [_conn(_TS_JAN5)])
    (shared / "events.json.log").write_text("{}", encoding="utf-8")

    fake_lr = LoadResult(
        logs={
            "conn*.log*": pd.DataFrame(columns=["ts", "src", "dst"]),
            "*.json*": pd.DataFrame(columns=_CT_COLUMNS_FOR_MOCK),
        },
        record_counts={},
        data_window=None,
        warnings=[],
        data_size_bytes=0,
        coverage={},
    )
    mock_load_required_logs(fake_lr)

    runner.run(
        config={"sigwood": {"detect": "beacon,aws", "default_window": ""}},
        zeek_dir=shared,
        cloudtrail_dir=shared,
    )
    s = capture_summary["summary"]
    overlap = [n for n in s.notes if "resolve to the same directory" in n]
    assert len(overlap) == 1, s.notes
    assert "zeek_dir" in overlap[0] and "cloudtrail_dir" in overlap[0]


# ── BATCH 1: flat default-window floor over-prune (file-selection decouple) ──
#
# A flat family's default-window floor (f_max - span; f_max = max PEEKED first-ts)
# must drive FILE SELECTION only, never the load-time row filter - the precise
# post-load trim re-anchors on the family's real loaded max-ts. Synthetic RFC 5737
# fixtures; timestamps are now-relative so the yearless RFC 3164 year-guess yields
# true chronological order on any run date, and expected counts are computed via
# parse_timestamp exactly as the loader does (never hardcoded).


def _pihole_query_line(dt: datetime) -> str:
    """A dnsmasq/Pi-hole query line stamped at ``dt`` (yearless RFC 3164)."""
    return (
        f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S} "
        "dnsmasq[1]: query[A] example.test from 192.0.2.1"
    )


def _gz(text: str) -> bytes:
    return gzip.compress(text.encode("utf-8"))


def _gz_trailer_corrupt(text: str) -> bytes:
    # Drop the final trailer byte: the first line PEEKS fine, but a full read
    # raises at the missing end-of-stream marker → the read-corruption rail
    # discards the whole file (zero rows). Verified peek-OK / load-fail at every
    # payload size; mirrors test_loader's `_pihole_truncated_compressed`.
    return gzip.compress(text.encode("utf-8"))[:-1]


def test_runner_flat_default_corrupt_floor_does_not_overprune(
    tmp_path, capture_summary
):
    """Headline repro: a flat (pihole) default window whose PEEKED f_max comes from
    a corrupt rotation file that fails to load. The floor must drive FILE SELECTION
    only - the real straddler's rows survive and NO misdirecting widen note fires.
    Before the two-map fix the floor row-filtered at load: the real rows (all below
    f_max - span) were dropped, the family rendered empty, and a SPAN coverage note
    told the operator to widen - a silent under-report with a wrong hint."""
    from sigwood.parsers.syslog import parse_timestamp

    now = datetime.now(timezone.utc)
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()

    # Newer rotation file (rank 1): peeks to a high f_max (~now-2d) but its gzip
    # trailer is corrupt → discards at load (zero rows). Supplies f_max.
    corrupt_base = now - timedelta(days=2)
    corrupt = "".join(
        _pihole_query_line(corrupt_base + timedelta(minutes=m)) + "\n"
        for m in range(3)
    )
    (pihole_dir / "pihole.log.1.gz").write_bytes(_gz_trailer_corrupt(corrupt))

    # Older rotation file (rank 2): the lower-bound STRADDLER. 31 hourly rows over
    # >1d of REAL data, all BELOW the floor (f_max - 1d). Rotation-peek SELECTS and
    # loads it (file selection keeps the in-window rows); only the removed load-time
    # row floor would drop them - isolating the row-filter bug from the accepted
    # file-selection residual (the one selected real file holds 100% of real data).
    real_base = now - timedelta(days=8)
    real_dts = [real_base + timedelta(hours=h) for h in range(31)]
    real_body = "".join(_pihole_query_line(dt) + "\n" for dt in real_dts)
    (pihole_dir / "pihole.log.2.gz").write_bytes(_gz(real_body))

    runner.run(
        config={"sigwood": {"detect": "dns", "default_window": "1d"}},
        pihole_dir=pihole_dir,
    )
    s = capture_summary["summary"]

    # Expected = the last-1d of the REAL data, computed exactly as the loader does.
    real_ts = [parse_timestamp(_pihole_query_line(dt)) for dt in real_dts]
    real_max = max(real_ts)
    expected = sum(1 for t in real_ts if t >= real_max - timedelta(days=1))

    # (a) rows survive and equal the real last-span (NOT empty).
    assert expected > 0
    assert s.record_counts.get("pihole*.log*", 0) == expected
    # (b) NO misdirecting Pi-hole widening note. Tight match: the Pi-hole coverage
    # note specifically, so an unrelated future note can't mask a regression.
    assert not any(
        n.startswith("Pi-hole:") and "widen" in n for n in s.notes
    ), s.notes


def test_runner_flat_default_pihole_healthy_last_span(tmp_path, capture_summary):
    """Invariant #4: a HEALTHY flat (pihole) default window renders the last span
    and fires no widen note - the post-load trim subsumes the (removed) load-time
    floor when actual_max >= f_max (the normal case). Pins no behavior change."""
    from sigwood.parsers.syslog import parse_timestamp

    now = datetime.now(timezone.utc)
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    base = now - timedelta(days=2)
    dts = [base + timedelta(hours=h) for h in range(49)]  # ~2d hourly
    body = "".join(_pihole_query_line(dt) + "\n" for dt in dts)
    (pihole_dir / "pihole.log").write_text(body, encoding="utf-8")

    runner.run(
        config={"sigwood": {"detect": "dns", "default_window": "1d"}},
        pihole_dir=pihole_dir,
    )
    s = capture_summary["summary"]
    ts = [parse_timestamp(_pihole_query_line(dt)) for dt in dts]
    mx = max(ts)
    expected = sum(1 for t in ts if t >= mx - timedelta(days=1))
    assert expected > 0
    assert s.record_counts.get("pihole*.log*", 0) == expected
    assert not any(n.startswith("Pi-hole:") and "widen" in n for n in s.notes)


def test_runner_flat_default_pihole_keeps_nan_ts(tmp_path, capture_summary):
    """Invariant #5: keep-policy (pihole) NaN-ts rows survive the implicit default
    window (the post-load trim passes keep_null). The two-map change doesn't touch
    null handling."""
    now = datetime.now(timezone.utc)
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    base = now - timedelta(hours=12)
    lines = [
        _pihole_query_line(base + timedelta(minutes=m)) for m in range(0, 60, 10)
    ]  # 6 recent in-window rows
    # An unparseable-ts line (month "Xxx" → parse_timestamp None → NaN ts, KEPT).
    lines.append("Xxx  1 12:00:00 dnsmasq[1]: query[A] other.test from 192.0.2.2")
    (pihole_dir / "pihole.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    runner.run(
        config={"sigwood": {"detect": "dns", "default_window": "1d"}},
        pihole_dir=pihole_dir,
    )
    s = capture_summary["summary"]
    # 6 recent in-window rows + 1 NaN-ts row, all retained.
    assert s.record_counts.get("pihole*.log*", 0) == len(lines)


def test_runner_dated_zeek_default_routes_via_source_windows(tmp_path, monkeypatch):
    """Invariant #2: a dated-Zeek default window (trim_span None) routes through
    source_windows, NOT file_select_windows. Spies the loader kwargs to pin the
    runner's trim_span-discriminated split."""
    from sigwood.common import loader as loader_pkg

    captured: dict = {}
    real = loader_pkg.load_required_logs

    def spy(*a, **kw):
        captured["source_windows"] = kw.get("source_windows")
        captured["file_select_windows"] = kw.get("file_select_windows")
        return real(*a, **kw)

    monkeypatch.setattr(loader_pkg, "load_required_logs", spy)
    zeek_dir = _make_dated_zeek(tmp_path, {
        "2026-01-01": [_conn(_TS_JAN1)],
        "2026-01-05": [_conn(_TS_JAN5)],
    })
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)
    assert captured["source_windows"] and "zeek_dir" in captured["source_windows"]
    assert captured["file_select_windows"] is None


def test_runner_flat_default_routes_floor_via_file_select_windows(
    tmp_path, monkeypatch
):
    """Invariant: a flat (pihole) default-window floor (trim_span set) routes
    through file_select_windows as an open-ended (floor, None), NOT source_windows."""
    from sigwood.common import loader as loader_pkg

    captured: dict = {}
    real = loader_pkg.load_required_logs

    def spy(*a, **kw):
        captured["source_windows"] = kw.get("source_windows")
        captured["file_select_windows"] = kw.get("file_select_windows")
        return real(*a, **kw)

    monkeypatch.setattr(loader_pkg, "load_required_logs", spy)
    now = datetime.now(timezone.utc)
    pihole_dir = tmp_path / "pihole"
    pihole_dir.mkdir()
    body = "".join(
        _pihole_query_line(now - timedelta(hours=h)) + "\n" for h in (5, 4, 3, 2, 1, 0)
    )
    (pihole_dir / "pihole.log").write_text(body, encoding="utf-8")
    runner.run(
        config={"sigwood": {"detect": "dns", "default_window": "1d"}},
        pihole_dir=pihole_dir,
    )
    assert captured["source_windows"] is None
    fsw = captured["file_select_windows"]
    assert fsw is not None and "pihole_dir" in fsw
    assert fsw["pihole_dir"][1] is None  # conservative floor, open-ended upper bound


# ── display timezone switch: report auto-name date routes through the seam ───


def test_report_basename_date_routes_through_display_seam(pin_tz, restore_display_utc):
    """The auto-name date renders in the display timezone - the ROUTING pin:
    the name equals the display-seam date computed with the switch in the same
    state (``to_display_timezone`` itself is display.py's contract, not under
    test here). A ±12h zone is picked at runtime so the local and UTC dates
    DIFFER right now - the equality cannot pass by date coincidence."""
    from sigwood.common.display import set_display_utc, to_display_timezone

    if datetime.now(timezone.utc).hour < 12:
        pin_tz("Etc/GMT+12")   # POSIX sign inversion: UTC-12 → local date behind UTC
    else:
        pin_tz("Etc/GMT-12")   # UTC+12 → local date ahead of UTC

    dates: dict[bool, str] = {}
    for state in (False, True):
        set_display_utc(state)
        before = to_display_timezone(datetime.now(timezone.utc)).strftime("%Y%m%d")
        name = runner._report_basename("text", ["beacon"])
        after = to_display_timezone(datetime.now(timezone.utc)).strftime("%Y%m%d")
        assert name in {f"sigwood-report_beacon_{d}.txt" for d in (before, after)}
        dates[state] = before
    assert dates[False] != dates[True]  # the pinned zone guarantees a real split


# --- beacon non-established-share disclosure (real runner.run seam) ---

_NON_EST_NOTE_SUBSTR = "were not in an established state"


def _conn_full(ts, *, src="192.0.2.10", conn_state="SF", local_orig=True):
    """A Zeek-native conn record carrying conn_state / bytes / local_orig.

    ``_conn`` above omits conn_state deliberately (the missing-column fixture); this
    variant is the full conn shape the note-firing and gating arms need.
    """
    return {
        "ts": ts,
        "id.orig_h": src,
        "id.resp_h": "198.51.100.20",
        "id.resp_p": 443,
        "proto": "tcp",
        "orig_bytes": 512,
        "conn_state": conn_state,
        "local_orig": local_orig,
    }


def test_beacon_non_established_note_fires_with_counts(tmp_path, capture_summary):
    recs = [_conn_full(_TS_JAN5 + i, conn_state="S0") for i in range(1000)]
    zeek_dir = _make_flat_zeek(tmp_path, recs)
    assert runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir) == 0
    s = capture_summary["summary"]
    assert (
        "beacon: 1000 of 1000 connections (100%) were not in an established state "
        "and were not scored - a periodic retry pattern to a dead or blocked host is "
        "not detected"
    ) in s.notes


def test_beacon_non_established_note_defensive_on_missing_conn_state(
    tmp_path, capture_summary,
):
    # `_conn` omits conn_state, so the loaded frame lacks the column. The note helper
    # runs pre-loop, OUTSIDE the detector's error containment, so it must not raise; it
    # returns the (0, total) no-disclosure shape and no note is emitted. The detector's
    # own _filter_conn KeyError on the absent column is the contained, ledgered residual
    # - the run still completes cleanly (the note-path bug class is the uncontained one).
    recs = [_conn(_TS_JAN5 + i) for i in range(1000)]
    zeek_dir = _make_flat_zeek(tmp_path, recs)
    assert runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir) == 0
    s = capture_summary["summary"]
    assert not any(_NON_EST_NOTE_SUBSTR in n for n in s.notes)


def test_beacon_non_established_note_below_row_floor_is_silent(tmp_path, capture_summary):
    recs = [_conn_full(_TS_JAN5 + i, conn_state="S0") for i in range(50)]
    zeek_dir = _make_flat_zeek(tmp_path, recs)
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)
    s = capture_summary["summary"]
    assert not any(_NON_EST_NOTE_SUBSTR in n for n in s.notes)


def test_beacon_non_established_note_below_share_is_silent(tmp_path, capture_summary):
    # 100 non-established of 1000 (10%) is below the 0.5 share gate. Flows are kept tiny
    # (cycled src, ~10 conns each < min_connections) so beacon scoring is irrelevant;
    # only the RunSummary note surface is under test.
    recs = [
        _conn_full(
            _TS_JAN5 + i,
            src=f"192.0.2.{(i % 100) + 1}",
            conn_state="S0" if i < 100 else "SF",
        )
        for i in range(1000)
    ]
    zeek_dir = _make_flat_zeek(tmp_path, recs)
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir)
    s = capture_summary["summary"]
    assert not any(_NON_EST_NOTE_SUBSTR in n for n in s.notes)


# --- beacon span-adequacy disclosure (real runner.run seam) ---

_SPAN_NOTE_SUBSTR = "resolving a jittered beacon needs about"


def _span_rows(span_seconds: float, n: int) -> list[dict]:
    """n Zeek-native conn rows evenly spanning exactly ``span_seconds`` from _TS_JAN1."""
    if n == 1:
        return [_conn_full(_TS_JAN1)]
    step = span_seconds / (n - 1)
    return [_conn_full(_TS_JAN1 + i * step) for i in range(n)]


def test_beacon_span_note_narrowed_short_span(tmp_path, capture_summary):
    # 49 conn rows spanning exactly 2 days, beacon under a bounded lookback (explicit
    # since/until → requested_span set): the narrowed span note fires, suggesting a
    # wider window. since/until are timezone-aware datetimes (the window API); the rows
    # carry epoch seconds.
    recs = _span_rows(2 * 86400.0, 49)
    zeek_dir = _make_flat_zeek(tmp_path, recs)
    assert runner.run(
        config=_BEACON_ONLY,
        zeek_dir=zeek_dir,
        since=datetime(2025, 12, 31, tzinfo=timezone.utc),
        until=datetime(2026, 1, 4, tzinfo=timezone.utc),
    ) == 0
    s = capture_summary["summary"]
    note = (
        "beacon: analyzed 2d of data - resolving a jittered beacon needs about 7 days of span; "
        "widen with --all or a longer lookback"
    )
    assert note in s.notes
    # --all is the only reliable widen lever; the note never suggests a --days=
    # flag, which requires an N-M range and would not clear the floor under data-lag.
    assert not any("--days=" in n for n in s.notes)
    # Voice: STATUS note - no sigwood: prefix, lowercase-led.
    assert not note.startswith("sigwood")
    assert note[0].islower()


def test_beacon_span_note_unbounded_short_span_no_widen(tmp_path, capture_summary):
    # Same 2-day data under --all (load_all → requested_span None): the unbounded
    # wording fires with NO widen suggestion (a full load cannot be widened).
    recs = _span_rows(2 * 86400.0, 49)
    zeek_dir = _make_flat_zeek(tmp_path, recs)
    assert runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir, load_all=True) == 0
    s = capture_summary["summary"]
    assert (
        "beacon: only 2d of data available - resolving a jittered beacon needs about 7 days of span"
    ) in s.notes
    assert not any("widen" in n for n in s.notes)


def test_beacon_span_note_silent_at_or_above_floor(tmp_path, capture_summary):
    # 8 days of span is above the ~1-week floor: no span note.
    recs = _span_rows(8 * 86400.0, 9)
    zeek_dir = _make_flat_zeek(tmp_path, recs)
    runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir, load_all=True)
    s = capture_summary["summary"]
    assert not any(_SPAN_NOTE_SUBSTR in n for n in s.notes)


def test_beacon_span_note_silent_on_zero_measurement_sentinel(tmp_path, capture_summary):
    # A single conn row → analyzed_span_seconds is 0.0, the no-measurement sentinel
    # (distinct from a short span): no note, and the run completes without raising.
    recs = _span_rows(0.0, 1)
    zeek_dir = _make_flat_zeek(tmp_path, recs)
    assert runner.run(config=_BEACON_ONLY, zeek_dir=zeek_dir, load_all=True) == 0
    s = capture_summary["summary"]
    assert not any(_SPAN_NOTE_SUBSTR in n for n in s.notes)


def test_beacon_span_note_absent_when_beacon_not_selected(tmp_path, capture_summary):
    # Same short-span conn data, but beacon is not in the selection: no span note.
    recs = _span_rows(2 * 86400.0, 49)
    zeek_dir = _make_flat_zeek(tmp_path, recs)
    runner.run(config={"sigwood": {"detect": "scan"}}, zeek_dir=zeek_dir, load_all=True)
    s = capture_summary["summary"]
    assert not any(_SPAN_NOTE_SUBSTR in n for n in s.notes)


def test_conn_summary_only_dir_skips_conn_detectors_no_zero_yield_warning(
    tmp_path, capture_summary, capsys
):
    # A Corelight-style conn-summary is a plaintext connection SUMMARY, not a Zeek
    # conn log - its name shares the 'conn' prefix but the loader must never open
    # it. Discovery drops it: conn*.log* yields nothing, so beacon/scan/duration
    # skip cleanly, and the plaintext body (which would hit the zero-yield arm if
    # read) never produces the spurious "no Zeek records found" warning.
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn-summary.log").write_text(
        "ts\tsrc\tdst\n1704067200\t192.0.2.10\t198.51.100.10\n", encoding="utf-8"
    )
    runner.run(
        config={"sigwood": {"detect": "beacon, scan, duration", "default_window": "all"}},
        zeek_dir=zeek_dir,
    )
    err = capsys.readouterr().err
    for name in ("beacon", "scan", "duration"):
        assert f"skipping {name} detection" in err
    assert "no Zeek records found" not in err


def test_conn_summary_only_reaches_summary_surface_without_warning(
    tmp_path, capture_summary, capsys
):
    # Same conn-summary drop, but a valid dns.log rides along so a detector runs
    # and a RunSummary is produced (an all-skip run short-circuits before the
    # summary). beacon/scan/duration land in detectors_skipped with the standard
    # "not found" reason, and the zero-yield warning is absent from the operator
    # surfaces (stderr AND RunSummary.notes).
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn-summary.log").write_text(
        "ts\tsrc\tdst\n1704067200\t192.0.2.10\t198.51.100.10\n", encoding="utf-8"
    )
    _write_ndjson(zeek_dir / "dns.log", [
        {"ts": 1704067200.0, "id.orig_h": "192.0.2.10", "query": "example.test", "qclass": 1},
        {"ts": 1704067260.0, "id.orig_h": "192.0.2.11", "query": "example.test", "qclass": 1},
    ])
    assert runner.run(
        config={"sigwood": {"detect": "beacon, scan, duration, dns",
                              "default_window": "all"}},
        zeek_dir=zeek_dir,
    ) == 0
    s = capture_summary["summary"]
    err = capsys.readouterr().err
    for name in ("beacon", "scan", "duration"):
        assert name in s.detectors_skipped, s.detectors_skipped
        assert "not found" in s.detectors_skipped[name]
    assert "no Zeek records found" not in err
    assert not any("no Zeek records found" in n for n in s.notes)
