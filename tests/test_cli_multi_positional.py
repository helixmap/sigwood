"""Multi-positional source ingestion - CLI primary rail.

These tests exercise the REAL CLI ↔ runner path with ``--dry-run`` and
``runner.run`` UNMOCKED. They prove the CLI fan-in reads ALL of
``parsed["paths"]`` (a fan-in that read only ``parsed["path"]`` would silently
drop the rest): N positionals fan into per-family buckets, MERGE with explicit
``--<family>-dir`` flags (sanctioned rail supersession; both load), and the
union load runs across families.

Companion to:
- ``tests/test_source_resolution_seam.py`` (single-positional scope seam),
- ``tests/test_loader.py`` (loader-level union + dated-window guardrails),
- ``tests/test_sources.py`` (router + resolver primitives).

Privacy rail: RFC 5737 IPs (192.0.2.x / 198.51.100.x / 203.0.113.x) and
placeholder/example domains only.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from sigwood import cli, runner
from sigwood.common import config as cfg
from sigwood.common import loader, sources


# ── content fixtures (RFC 5737 + placeholder domains) ────────────────────────


_FLAT_SYSLOG_LINE = (
    "<134>Jun 11 12:00:00 examplehost sshd[1234]: Accepted publickey for placeholder\n"
)

_PIHOLE_LINE = (
    "Jun 11 12:00:00 piholehost dnsmasq[1234]: query[A] example.test from 192.0.2.10\n"
)

_ZEEK_NDJSON_CONN_LINE = (
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "id.resp_h": "198.51.100.20", "id.resp_p": 443,'
    ' "proto": "tcp", "duration": 1.23}\n'
)

_ZEEK_NDJSON_DNS_LINE = (
    '{"ts": 1779750000.0, "id.orig_h": "192.0.2.10",'
    ' "query": "example.test"}\n'
)

_CLOUDTRAIL_NDJSON_LINE = json.dumps({
    "eventVersion":    "1.08",
    "eventTime":       "2026-06-01T12:00:00Z",
    "userIdentity":    {"type": "IAMUser"},
    "eventName":       "GetObject",
    "eventSource":     "s3.amazonaws.com",
    "sourceIPAddress": "192.0.2.10",
}) + "\n"


def _write_cfg(tmp_path: Path, **keys: str) -> str:
    """Minimal TOML config under tmp_path; only named keys written."""
    lines = ["[sigwood]", 'root = ""']
    for k, v in keys.items():
        lines.append(f'{k} = "{v}"')
    cfg_path = tmp_path / "cfg.toml"
    cfg_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(cfg_path)


# ── PRIMARY RAIL: real cli._main + --dry-run, runner.run UNMOCKED ────────────


def test_dns_cross_source_positionals_both_families_load(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood dns zeek_dns.log events.log --dry-run``: the Zeek-shaped
    positional routes to zeek_dir, the Pi-hole-shaped positional routes to
    pihole_dir via content-sniff. Both appear in the dry-run block.

    The pihole fixture's filename is DELIBERATELY neutral (``events.log``, NOT
    ``pihole.log``) so the test proves CONTENT-SNIFF routes it - never fnmatch
    on the filename, which would let an old assumption pass accidentally.
    """
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_file = tmp_path / "zeek_dns.log"
    zeek_file.write_text(_ZEEK_NDJSON_DNS_LINE, encoding="utf-8")
    pihole_file = tmp_path / "events.log"  # neutral filename - sniff must classify by content
    pihole_file.write_text(_PIHOLE_LINE, encoding="utf-8")

    cfg_path = _write_cfg(tmp_path)
    cli._main([
        "dns", str(zeek_file), str(pihole_file),
        f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    assert str(zeek_file) in out
    assert str(pihole_file) in out
    # Sibling families NOT touched by any positional stay "not configured"
    # (verifies scope is the UNION of touched families).
    assert "syslog_dir:" in out
    assert "not configured" in out.split("syslog_dir:")[1].split("\n")[0]
    assert "cloudtrail_dir:" in out
    assert "not configured" in out.split("cloudtrail_dir:")[1].split("\n")[0]


def test_beacon_same_family_multi_positionals_both_files_listed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood beacon a.log b.log --dry-run``: both Zeek conn files land
    under zeek_dir's multi-input block. This is the natural multi-file command
    a sysadmin types after a shell glob; an old "first wins" rule would have
    silently dropped b.log."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    f1 = tmp_path / "conn.day1.log"
    f1.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    f2 = tmp_path / "conn.day2.log"
    f2.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    cfg_path = _write_cfg(tmp_path)
    cli._main([
        "beacon", str(f1), str(f2),
        f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    assert str(f1) in out
    assert str(f2) in out


def test_analyze_detect_all_heterogeneous_positionals_bucket_correctly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood conn.log dns.log syslog.log --dry-run`` (detect=all path):
    the Zeek-shaped positionals bucket into zeek_dir, the syslog-shaped
    positional buckets into syslog_dir. The detect=all router's None-mode
    content-sniff classifies each positional independently."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    conn = tmp_path / "conn.log"
    conn.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    dns = tmp_path / "dns.log"
    dns.write_text(_ZEEK_NDJSON_DNS_LINE, encoding="utf-8")
    syslog = tmp_path / "syslog.log"
    syslog.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")

    cfg_path = _write_cfg(tmp_path)
    cli._main([
        str(conn), str(dns), str(syslog),
        f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    # Both Zeek positionals under zeek_dir, syslog positional under syslog_dir.
    assert str(conn) in out
    assert str(dns) in out
    assert str(syslog) in out
    # The two zeek_dir entries must appear in the zeek_dir block, not syslog.
    zeek_block = out.split("zeek_dir:")[1].split("system logs:")[0]
    assert str(conn) in zeek_block
    assert str(dns) in zeek_block
    syslog_block = out.split("system logs:")[1].split("pihole_dir:")[0]
    assert str(syslog) in syslog_block


def test_flag_plus_positional_different_family_both_load(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood dns zeek.log --pihole-dir=pihole.log`` (different family):
    BOTH the positional and the explicit flag load. Mirrors the motivating
    user pattern from the BUGS entry - the operator wanted both files."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_file = tmp_path / "zeek_dns.log"
    zeek_file.write_text(_ZEEK_NDJSON_DNS_LINE, encoding="utf-8")
    pihole_file = tmp_path / "events.log"
    pihole_file.write_text(_PIHOLE_LINE, encoding="utf-8")

    cfg_path = _write_cfg(tmp_path)
    cli._main([
        "dns", str(zeek_file),
        f"--pihole-dir={pihole_file}",
        f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    assert str(zeek_file) in out
    assert str(pihole_file) in out


def test_same_family_flag_plus_positionals_all_merge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sigwood beacon a.log b.log --zeek-dir=c.log``: ALL THREE entries
    contribute to zeek_dir (MERGE - a flag adds to a same-family positional,
    it does not replace it). The order is positionals first, flag appended."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    f1 = tmp_path / "conn.a.log"
    f1.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    f2 = tmp_path / "conn.b.log"
    f2.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    f3 = tmp_path / "conn.c.log"
    f3.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    cfg_path = _write_cfg(tmp_path)
    cli._main([
        "beacon", str(f1), str(f2),
        f"--zeek-dir={f3}",
        f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    assert str(f1) in out
    assert str(f2) in out
    assert str(f3) in out


def test_multi_positional_scope_still_suppresses_unrelated_configured_sibling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Multi-positional run, all routing to syslog_dir, with a CONFIGURED
    zeek_dir in the config. Scope is the UNION of touched families
    (frozenset({"syslog_dir"}) here), so the configured zeek_dir stays out -
    the sibling-leak fix is preserved under the union shape."""
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [])
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    zeek_d = tmp_path / "configured_zeek"
    zeek_d.mkdir()
    f1 = tmp_path / "flat1.log"
    f1.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")
    f2 = tmp_path / "flat2.log"
    f2.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")

    cfg_path = _write_cfg(tmp_path, zeek_dir=str(zeek_d))
    cli._main([
        "syslog", str(f1), str(f2),
        f"--config={cfg_path}", "--dry-run",
    ])

    out = capsys.readouterr().out
    assert str(f1) in out
    assert str(f2) in out
    # The configured zeek_dir MUST NOT sneak through under union scoping.
    assert str(zeek_d) not in out
    assert "zeek_dir:" in out
    assert "not configured" in out.split("zeek_dir:")[1].split("\n")[0]


# ── SECONDARY: scalar-vs-list programmatic contract ──────────────────────────


def test_runner_run_scalar_and_list_produce_identical_dry_run_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``runner.run(zeek_dir="/x")`` and ``runner.run(zeek_dir=["/x"])`` MUST
    produce byte-identical dry-run output. The scalar caller is the
    degenerate one-element list under ``_normalize_overrides``; ~35
    programmatic scalar callers + the provenance rail
    (tests/test_root_provenance.py) depend on this."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    f = tmp_path / "conn.log"
    f.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")

    runner.run(config={"sigwood": {"root": ""}}, zeek_dir=str(f), dry_run=True)
    scalar_out = capsys.readouterr().out

    runner.run(config={"sigwood": {"root": ""}}, zeek_dir=[str(f)], dry_run=True)
    list_out = capsys.readouterr().out

    assert scalar_out == list_out


# ── SECONDARY: detect=all router fallback (None-mode) ────────────────────────


def test_route_positional_source_none_mode_dir_falls_back_to_zeek(
    tmp_path: Path,
) -> None:
    """detect=all / unknown selector with a directory positional → zeek_dir
    fallback. Preserves today's analyze default for unrecognized inputs."""
    d = tmp_path / "some_dir"
    d.mkdir()
    assert sources.route_positional_source(str(d), detector_module=None) == "zeek_dir"


def test_route_positional_source_none_mode_syslog_content_routes_syslog(
    tmp_path: Path,
) -> None:
    """detect=all + recognized flat syslog file → syslog_dir."""
    f = tmp_path / "flat.log"
    f.write_text(_FLAT_SYSLOG_LINE, encoding="utf-8")
    assert sources.route_positional_source(str(f), detector_module=None) == "syslog_dir"


def test_route_positional_source_none_mode_pihole_content_routes_pihole(
    tmp_path: Path,
) -> None:
    """detect=all + recognized Pi-hole dnsmasq content → pihole_dir, regardless
    of filename. Neutral filename ``events.log`` proves CONTENT-sniff."""
    f = tmp_path / "events.log"
    f.write_text(_PIHOLE_LINE, encoding="utf-8")
    assert sources.route_positional_source(str(f), detector_module=None) == "pihole_dir"


def test_route_positional_source_none_mode_cloudtrail_routes_cloudtrail(
    tmp_path: Path,
) -> None:
    """detect=all + recognized CloudTrail NDJSON → cloudtrail_dir."""
    f = tmp_path / "events.json.log"
    f.write_text(_CLOUDTRAIL_NDJSON_LINE, encoding="utf-8")
    assert sources.route_positional_source(
        str(f), detector_module=None,
    ) == "cloudtrail_dir"


def test_route_positional_source_none_mode_unrecognized_falls_back_to_zeek(
    tmp_path: Path,
) -> None:
    """detect=all + unrecognized content → zeek_dir fallback. Preserves
    today's analyze default for inputs the sniffer can't classify."""
    f = tmp_path / "garbage.log"
    f.write_text("not log content, just words\n" * 5, encoding="utf-8")
    assert sources.route_positional_source(str(f), detector_module=None) == "zeek_dir"


# ── SECONDARY: plan-time satisfiability lockstep ─────────────────────────────


def test_pihole_satisfiability_via_neutral_filename_lockstep_with_loader(
    tmp_path: Path,
) -> None:
    """Plan-time pihole satisfiability uses ``_syslog_files``
    (file-or-dir, ``*.log*``), NOT ``directory.glob(pattern)``. A Pi-hole
    file with a neutral name (``events.log``) MUST be plan-satisfiable,
    matching what the loader will actually ingest. A glob-on-pattern
    check would reject ``events.log`` (no ``pihole`` prefix) while the
    loader happily reads it - the plan/loader drift this guards against."""
    from types import SimpleNamespace

    from sigwood.runner import _is_optional_satisfiable

    f = tmp_path / "events.log"
    f.write_text(_PIHOLE_LINE, encoding="utf-8")

    req = {"source": "pihole_dir", "pattern": "pihole*.log*"}
    # Single-input shape (degenerate one-element list).
    assert _is_optional_satisfiable(req, {"pihole_dir": [f]}) is True


# ── SECONDARY: union dated-window (multi-input branch of the helper) ─────────


def test_zeek_dated_default_window_union_across_inputs(tmp_path: Path) -> None:
    """Multi dated-dir union: two inputs each carrying disjoint dates → the
    union spans the newest N=ceil(span_days). Generalizes the single-input
    selection (guardrail tests) across the union."""
    a = tmp_path / "siteA"
    a.mkdir()
    b = tmp_path / "siteB"
    b.mkdir()
    (a / "2026-01-01").mkdir()
    (a / "2026-01-03").mkdir()
    (b / "2026-01-05").mkdir()

    # span=2d → newest 2 distinct dates across the union (Jan 3 + Jan 5),
    # window Jan 3 → Jan 5.
    since, until = loader._zeek_dated_window([a, b], timedelta(days=2))
    assert since.date().isoformat() == "2026-01-03"
    assert until.date().isoformat() == "2026-01-05"


def test_zeek_dated_default_window_returns_none_when_file_alongside_dir(
    tmp_path: Path,
) -> None:
    """Mixed file + dated dir is NOT purely-dated → helper returns None →
    runner falls to the flat post-load path (max-ts over the combined
    loaded frame). Honesty rail: never silently trim unseen file rows."""
    f = tmp_path / "conn.log"
    f.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    d = tmp_path / "dated"
    d.mkdir()
    (d / "2026-01-05").mkdir()
    assert (
        loader._zeek_dated_window([f, d], timedelta(days=1))
        is None
    )


def test_zeek_dated_default_window_returns_none_when_flat_dir_alongside_dated(
    tmp_path: Path,
) -> None:
    """Mixed flat dir + dated dir is NOT purely-dated → helper returns None →
    runner falls to the flat post-load path."""
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "conn.log").write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    dated = tmp_path / "dated"
    dated.mkdir()
    (dated / "2026-01-05").mkdir()
    assert (
        loader._zeek_dated_window([flat, dated], timedelta(days=1))
        is None
    )


# ── SECONDARY: dedup accounting (duplicate input → no double-count) ─────────


def test_load_required_logs_dedupes_duplicate_inputs_no_double_count(
    tmp_path: Path,
) -> None:
    """A positional file that is ALSO inside a positional directory must
    contribute ONCE to byte total and record count. The loader's
    ``_union_dedupe`` (by ``.resolve()`` preserving first-seen order)
    enforces this; dedup runs BEFORE size/record accounting."""
    d = tmp_path / "zeek"
    d.mkdir()
    f = d / "conn.log"
    f.write_text(_ZEEK_NDJSON_CONN_LINE, encoding="utf-8")
    expected_size = f.stat().st_size

    # Pass BOTH the file (as a positional-style file input) AND the directory
    # containing it. The loader must dedupe by realpath, so conn.log is loaded
    # ONCE - total bytes match the single file's size, NOT 2x.
    result = loader.load_required_logs(
        {"conn*.log*": "zeek_dir"},
        {"zeek_dir": [f, d]},
    )
    assert result.record_counts == {"conn*.log*": 1}
    assert result.data_size_bytes == expected_size


def test_mixed_directory_positional_prints_vote_advisory(
    tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    """A mixed-family directory positional discloses the vote outcome on
    stderr - the losing family's files are not loaded as their own kind, and
    that must never be a silent omission. Status line: no sigwood: prefix."""
    log_dir = tmp_path / "mixed"
    log_dir.mkdir()
    for i in (1, 2):
        (log_dir / f"conn.{i}.log").write_text(
            '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
            '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
            '"id.resp_p":443,"proto":"tcp"}\n',
            encoding="utf-8",
        )
    (log_dir / "messages").write_text(
        "<134>Jun 11 12:00:00 host1 sshd[1234]: Accepted publickey for user\n",
        encoding="utf-8",
    )

    buckets = cli._build_positional_buckets([str(log_dir)], detector_module=None)

    err = capsys.readouterr().err
    assert buckets == {"zeek_dir": [str(log_dir)]}
    assert (
        f"{log_dir}: mixed log types sampled (zeek 2, syslog 1) - "
        "hunting it as zeek; pass the other files directly to include them"
    ) in err
    assert "sigwood:" not in err


def test_single_family_directory_positional_prints_no_advisory(
    tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "conn.log").write_text(
        '{"_path":"conn","ts":1779750000.0,"uid":"C1",'
        '"id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20",'
        '"id.resp_p":443,"proto":"tcp"}\n',
        encoding="utf-8",
    )

    cli._build_positional_buckets([str(log_dir)], detector_module=None)

    assert "mixed log types" not in capsys.readouterr().err
