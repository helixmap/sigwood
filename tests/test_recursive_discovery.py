"""Recursive discovery: one walk per supplied directory, one family per file.

A directory supplied with ``--recursive`` is walked once and stays one logical
input per family it supplies. These tests drive the real CLI with hermetic
configuration and pin the partition rule, Zeek's dated ownership across walks,
windows against equivalent explicit logical directories, the family-neutral
root facts and their owners, and every new disclosure on the saved surfaces.
"""

from __future__ import annotations

import gzip
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sigwood.cli as cli
import sigwood.common.loader as loader
import sigwood.runner as runner
from sigwood.common.errors import UsageError
from sigwood.common.loader import discovery as disc
from sigwood.common.loader import recursive as rec
from sigwood.common.loader.types import FileOutcomeKind
from sigwood.common.sources import prepare_analyze_discovery

_DAY = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
_ESC = "\x1b"
_CSI = "\x9b"


# ── fixture builders (RFC 5737 addresses, reserved names only) ───────────────


def _conn_rows(day: datetime, n: int = 6, host: str = "192.0.2.10") -> str:
    return "".join(json.dumps({
        "_path": "conn", "ts": (day + timedelta(minutes=i)).timestamp(),
        "uid": f"C{int(day.timestamp())}{i}", "id.orig_h": host,
        "id.orig_p": 40000 + i, "id.resp_h": "198.51.100.20", "id.resp_p": 443,
        "proto": "tcp", "conn_state": "SF", "duration": 1.5,
        "orig_bytes": 100, "resp_bytes": 900, "local_orig": True,
    }) + "\n" for i in range(n))


def _syslog_lines(day: int, host: str = "host1", n: int = 4) -> str:
    return "".join(
        f"Sep {day:2d} 1{i}:00:00 {host} sshd[{100 + i}]: Accepted publickey "
        f"for alice from 192.0.2.{i + 1} port 22 ssh2\n"
        for i in range(n)
    )


def _dnsmasq_lines(day: int, n: int = 4) -> str:
    return "".join(
        f"Sep {day:2d} 0{i}:00:00 dnsmasq[811]: query[A] h{i}.example.com "
        f"from 192.0.2.{10 + i}\n"
        for i in range(n)
    )


def _write(path: Path, text: str, *, gz: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def _dated(root: Path, days: int = 3, *, current: Path | None = None) -> Path:
    for d in range(days):
        day = _DAY + timedelta(days=d)
        _write(root / day.strftime("%Y-%m-%d") / "conn.log", _conn_rows(day))
    if current is not None:
        (root / "current").symlink_to(current, target_is_directory=True)
    return root


def _isolated_config(tmp_path: Path, **sigwood: str) -> Path:
    values = {
        "root": "", "zeek_dir": "", "syslog_dir": "", "pihole_dir": "",
        "cloudtrail_dir": "", "syslog_source": "files",
    }
    values.update(sigwood)
    lines = ["[sigwood]", *(f'{key} = "{value}"' for key, value in values.items())]
    path = tmp_path / "config.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _main(argv: list[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> int:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    return cli._main(argv)


class _Runner:
    """Run the real CLI and keep stderr and the saved JSON summary."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        self.tmp_path = tmp_path
        self.monkeypatch = monkeypatch
        self.capsys = capsys
        self.config = _isolated_config(tmp_path)
        self.n = 0

    def json(self, *argv: str, config: Path | None = None):
        self.n += 1
        out = self.tmp_path / f"run{self.n}.json"
        rc = _main([
            *argv, f"--config={config or self.config}", "-q", "--format=json",
            f"--out={out}",
        ], self.monkeypatch, self.tmp_path)
        err = self.capsys.readouterr().err
        summary = json.loads(out.read_text())["run_summary"] if out.exists() else None
        return rc, summary, err

    def dry(self, *argv: str, config: Path | None = None) -> tuple[int, str, str]:
        rc = _main([*argv, f"--config={config or self.config}", "--dry-run"],
                   self.monkeypatch, self.tmp_path)
        captured = self.capsys.readouterr()
        return rc, captured.out, captured.err


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> _Runner:
    return _Runner(tmp_path, monkeypatch, capsys)


def _notes(summary) -> list[str]:
    return list(summary["notes"]) if summary else []


# ── 1. the flag, its precedence and ordinary nested trees ───────────────────


@pytest.mark.parametrize("verb", [[], ["hunt"], ["syslog"]])
def test_nested_extensionless_logs_load_under_every_entry(
    run: _Runner, tmp_path: Path, verb: list[str],
) -> None:
    root = tmp_path / "logs"
    _write(root / "messages", _syslog_lines(20, host="top"))
    _write(root / "a" / "secure", _syslog_lines(20, host="hosta"))
    _write(root / "b" / "c" / "messages.1", _syslog_lines(19, host="hostc"))
    _write(root / "README", "notes about this archive\n")
    lead = verb or []
    rc, summary, err = run.json(*lead, "--recursive", str(root))
    assert rc == 0
    assert summary["record_counts"]["*.log*"] == 12
    expected = (
        f"discovery: 1 file under {root} is not recognized as any log this run "
        "reads (README)"
    )
    assert expected in err.splitlines()
    assert expected in _notes(summary)
    assert "this run did not search" not in err


def test_without_the_flag_nested_children_stay_unsearched(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    _write(root / "messages", _syslog_lines(20, host="top"))
    _write(root / "a" / "secure", _syslog_lines(20, host="hosta"))
    rc, summary, err = run.json("syslog", str(root))
    assert rc == 0
    assert summary["record_counts"]["*.log*"] == 4
    assert "1 subdirectory this run did not search (a)" in err


def test_a_supported_minority_beyond_the_routing_sample_is_found(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "mixed"
    for i in range(40):
        _write(root / f"svc{i:02d}.log", _syslog_lines(20, host=f"h{i}"))
    _write(root / "zz" / "deep" / "conn.log", _conn_rows(_DAY))
    rc, summary, _err = run.json("beacon", "--recursive", str(root))
    assert rc == 0
    assert summary["record_counts"]["conn*.log*"] == 6
    rc, summary, err = run.json("beacon", str(root))
    assert rc == 1 and summary is None
    assert "conn*.log* not found" in err


@pytest.mark.parametrize(("argv", "message"), [
    (["--recursive"], "nothing to hunt"),
    (["hunt", "--recursive", "{missing}"], "not found"),
    (["hunt", "--recursive", "{file}"], "--recursive needs a directory on this run"),
    (["hunt", "--recursive"], "--recursive needs a directory on this run"),
    (["beacon", "--recursive", "--zeek-dir={file}"], "--recursive needs a directory"),
])
def test_the_no_directory_error_keeps_the_specified_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str], message: str,
) -> None:
    file = _write(tmp_path / "conn.log", _conn_rows(_DAY))
    config = _isolated_config(tmp_path)
    filled = [
        part.format(missing=tmp_path / "missing", file=file) for part in argv
    ]
    with pytest.raises(ValueError) as caught:
        _main([*filled, f"--config={config}"], monkeypatch, tmp_path)
    assert message in str(caught.value)


def test_explicit_files_beside_one_explicit_directory_stay_valid(
    run: _Runner, tmp_path: Path,
) -> None:
    file = _write(tmp_path / "solo" / "conn.log", _conn_rows(_DAY))
    tree = _write(tmp_path / "tree" / "x" / "conn.log", _conn_rows(_DAY + timedelta(days=1)))
    rc, summary, _err = run.json("beacon", "--recursive", str(file), str(tree.parent.parent))
    assert rc == 0
    assert summary["record_counts"]["conn*.log*"] == 12


@pytest.mark.parametrize("verb", ["digest", "graph", "era"])
def test_non_analysis_verbs_reject_the_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verb: str,
) -> None:
    with pytest.raises(UsageError, match="--recursive is not valid for"):
        _main([verb, "--recursive", str(tmp_path)], monkeypatch, tmp_path)


def test_generated_help_and_allowed_sets_agree() -> None:
    for name, spec in cli._VERBS.items():
        analysis = name == "hunt" or name in cli._SINGLE_DETECTOR_COMMANDS
        assert ("recursive" in spec.allowed) is analysis, name
        if analysis:
            assert "--recursive" in cli._render_verb_help(name)


# ── 2. the partition: one family per file, in the accepted order ────────────


def _mixed(root: Path) -> Path:
    _write(root / "relay" / "all.log-20261015", _dnsmasq_lines(14))
    _write(root / "rsyslog" / "syslog.log", _syslog_lines(14, host="rfc"))
    _write(root / "pihole" / "pihole.log", _dnsmasq_lines(14))
    _write(root / "zeek" / "conn.log", _conn_rows(_DAY))
    return root


def test_hunt_partitions_a_mixed_tree_without_double_claims(
    run: _Runner, tmp_path: Path,
) -> None:
    root = _mixed(tmp_path / "mixed")
    rc, summary, err = run.json("hunt", "--recursive", str(root), "--detect=all")
    assert rc == 0
    counts = summary["record_counts"]
    assert counts["*.log*"] == 8               # forwarded dnsmasq + RFC syslog.log
    assert counts["pihole*.log*"] == 4         # the real pihole.log only
    assert counts["conn*.log*"] == 6
    assert "syslog*.log*" not in counts        # RFC syslog.log never reaches Zeek
    assert "no Zeek records found" not in err
    assert "shared files" not in err


def test_named_syslog_reads_a_real_pihole_log_through_its_content_gate(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "only-pihole"
    _write(root / "pihole.log", _dnsmasq_lines(14))
    rc, summary, _err = run.json("syslog", "--recursive", str(root))
    assert rc == 0
    assert summary["record_counts"]["*.log*"] == 4


def test_named_dns_keeps_pihole_and_rejects_forwarded_content_it_cannot_route(
    run: _Runner, tmp_path: Path,
) -> None:
    root = _mixed(tmp_path / "mixed")
    rc, summary, err = run.json("dns", "--recursive", str(root))
    assert rc == 0
    assert summary["record_counts"]["pihole*.log*"] == 4
    expected = (
        f"discovery: 1 file under {root} looks like Pi-hole logs, but its name "
        "does not match pihole*.log* (relay/all.log-20261015)"
    )
    assert expected in err.splitlines()


def test_named_beacon_is_silent_about_known_syslog_beside_zeek(
    run: _Runner, tmp_path: Path,
) -> None:
    root = _mixed(tmp_path / "mixed")
    rc, _summary, err = run.json("beacon", "--recursive", str(root))
    assert rc == 0
    assert "discovery:" not in err


def test_named_beacon_over_syslog_only_explains_the_root_before_skips(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    _write(root / "b" / "empty.log", "")
    rc, summary, err = run.json("beacon", "--recursive", str(root))
    assert rc == 1 and summary is None
    lines = err.splitlines()
    outcome = (
        f"discovery: nothing under {root} is read by this run - it holds 1 file "
        "of another log type and 1 empty file"
    )
    assert outcome in lines
    skip = next(i for i, line in enumerate(lines) if "skipping beacon" in line)
    assert lines.index(outcome) < skip
    assert "not recognized" not in err


def test_a_declared_override_walks_under_its_own_family_gate(
    run: _Runner, tmp_path: Path,
) -> None:
    declared = tmp_path / "declared"
    _write(declared / "x" / "messages", _syslog_lines(20))
    _write(declared / "y" / "conn.log", _conn_rows(_DAY))
    rc, summary, err = run.json("syslog", "--recursive", f"--syslog-dir={declared}")
    assert rc == 0
    assert summary["record_counts"]["*.log*"] == 4
    assert "discovery:" not in err


def test_a_scoped_empty_positional_never_refills_from_configuration(
    run: _Runner, tmp_path: Path,
) -> None:
    configured = _dated(tmp_path / "configured-zeek")
    config = _isolated_config(tmp_path, zeek_dir=str(configured))
    empty = tmp_path / "empty"
    empty.mkdir()
    rc, summary, err = run.json("beacon", "--recursive", str(empty), config=config)
    assert rc == 1 and summary is None
    assert f"discovery: {empty} holds no files - nothing to read there" in err
    assert "outside this run's positional scope" in err


def test_configured_roots_stay_shallow_beside_a_recursive_explicit_root(
    run: _Runner, tmp_path: Path,
) -> None:
    configured = tmp_path / "configured-syslog"
    _write(configured / "messages", _syslog_lines(20, host="top"))
    _write(configured / "nested" / "messages", _syslog_lines(20, host="kid"))
    zeek = tmp_path / "zeek"
    _write(zeek / "deep" / "conn.log", _conn_rows(_DAY))
    config = _isolated_config(tmp_path, syslog_dir=str(configured))
    rc, summary, err = run.json(
        "hunt", "--recursive", f"--zeek-dir={zeek}", "--detect=beacon,syslog",
        config=config,
    )
    assert rc == 0
    assert summary["record_counts"]["*.log*"] == 4
    assert summary["record_counts"]["conn*.log*"] == 6


@pytest.mark.parametrize("mode", ["off", "journal"])
def test_a_recursive_syslog_partition_conflicts_with_journal_and_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    config = _isolated_config(tmp_path)
    with pytest.raises(UsageError) as caught:
        _main(["syslog", "--recursive", str(root / "a"), str(root),
               f"--syslog-source={mode}", f"--config={config}"], monkeypatch, tmp_path)
    assert str(caught.value) == (
        f"--syslog-source={mode} cannot be combined with syslog files found by "
        f"--recursive ({root / 'a' / 'messages'})"
    )


def test_a_tree_without_syslog_files_keeps_off_legal(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "zeek-only"
    _write(root / "x" / "conn.log", _conn_rows(_DAY))
    rc, summary, _err = run.json(
        "hunt", "--recursive", str(root), "--syslog-source=off", "--detect=beacon,syslog",
    )
    assert rc == 0
    assert summary["record_counts"]["conn*.log*"] == 6


# ── 3. rows and windows against equivalent explicit logical directories ─────


def _two_hosts(root: Path) -> Path:
    for host, day in (("h1", 20), ("h2", 12)):
        _write(root / host / "messages", _syslog_lines(day, host=host))
        _write(root / host / "messages.1", _syslog_lines(day - 1, host=host))
    return root


@pytest.mark.parametrize("window", [[], ["--all"], ["--since=2026-09-18", "--until=2026-09-21"]])
def test_rows_and_windows_match_the_explicit_logical_directories(
    run: _Runner, tmp_path: Path, window: list[str],
) -> None:
    root = _two_hosts(tmp_path / "hosts")
    rc, recursive, _ = run.json("syslog", "--recursive", str(root), *window)
    rc2, explicit, _ = run.json("syslog", str(root / "h1"), str(root / "h2"), *window)
    assert rc == rc2 == 0
    assert recursive["record_counts"] == explicit["record_counts"]
    assert recursive["data_window"] == explicit["data_window"]
    assert recursive["data_size_bytes"] == explicit["data_size_bytes"]


def test_an_explicit_file_keeps_its_rotation_bypass_inside_a_recursive_root(
    run: _Runner, tmp_path: Path,
) -> None:
    root = _two_hosts(tmp_path / "hosts")
    _write(root / "h1" / "messages.2", _syslog_lines(17, host="h1"))   # straddles
    old = _write(root / "h1" / "messages.9", _syslog_lines(2, host="h1"))
    bounds = ["--since=2026-09-18", "--until=2026-09-21"]
    rc, with_file, _ = run.json("syslog", "--recursive", str(root), str(old), *bounds)
    rc2, without, _ = run.json("syslog", "--recursive", str(root), *bounds)
    assert rc == rc2 == 0
    assert with_file["data_size_bytes"] > without["data_size_bytes"]


def test_unrecognized_json_is_disclosed_while_a_declaration_admits_it(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "trail"
    _write(root / "AWSLogs" / "x.json", json.dumps({"not": "cloudtrail"}) + "\n")
    rc, _summary, err = run.json("aws", "--recursive", str(root))
    assert rc == 1
    assert (
        f"discovery: 1 file under {root} is not recognized as any log this run "
        "reads (AWSLogs/x.json)"
    ) in err
    rc, summary, err = run.json("aws", "--recursive", f"--cloudtrail-dir={root}")
    assert "discovery:" not in err
    assert summary is None or summary["record_counts"].get("*.json*", 0) == 0


# ── 4. Zeek's dated ownership across walks ──────────────────────────────────


@pytest.mark.parametrize("spool_name", ["aaa-spool", "zzz-spool"])
@pytest.mark.parametrize("window", [[], ["--all"]])
def test_a_dated_root_and_its_spool_stay_dated_in_either_walk_order(
    run: _Runner, tmp_path: Path, spool_name: str, window: list[str],
) -> None:
    root = tmp_path / "archive"
    spool = _write(root / spool_name / "conn.log", _conn_rows(_DAY + timedelta(days=3))).parent
    dated = _dated(root / "mmm-sensor", current=spool)
    _write(dated / "conn.log", _conn_rows(_DAY - timedelta(days=30)))    # mixed root
    _write(dated / "2026-09-10" / "deep" / "conn.log", _conn_rows(_DAY))  # deeper
    _write(root / "aaa-empty" / "conn.log.gz", "", gz=True)
    _write(root / "aaa-empty" / "syslog.log", "")
    rc, recursive, err = run.json("beacon", "--recursive", str(root), *window)
    rc2, explicit, _ = run.json("beacon", f"--zeek-dir={dated}", *window)
    assert rc == rc2 == 0
    assert recursive["record_counts"] == explicit["record_counts"]
    assert recursive["data_window"] == explicit["data_window"]
    assert recursive["data_size_bytes"] == explicit["data_size_bytes"]
    assert "flat directory" not in err
    assert "sits deeper than its dated layout reads" in err
    assert "at the top of dated directory" in err
    assert "did not follow" not in err


@pytest.mark.parametrize("inside", [False, True])
def test_a_current_only_dated_root_reads_its_spool(
    run: _Runner, tmp_path: Path, inside: bool,
) -> None:
    root = tmp_path / "archive"
    base = root if inside else tmp_path
    spool = _write(base / "spool" / "conn.log", _conn_rows(_DAY, n=12)).parent
    dated = root / "sensor"
    (dated / "2026-09-09").mkdir(parents=True)
    (dated / "2026-09-10").mkdir()
    (dated / "current").symlink_to(spool, target_is_directory=True)
    rc, recursive, _ = run.json("beacon", "--recursive", str(root))
    rc2, explicit, _ = run.json("beacon", f"--zeek-dir={dated}")
    assert rc == rc2 == 0
    assert recursive["record_counts"] == explicit["record_counts"] == {"conn*.log*": 12}


def test_a_pruned_date_alias_stays_pruned(run: _Runner, tmp_path: Path) -> None:
    root = tmp_path / "archive"
    dated = _dated(root / "sensor", days=10)
    (dated / "backup").symlink_to(dated / "2026-09-10", target_is_directory=True)
    rc, recursive, _ = run.json("beacon", "--recursive", str(root))
    rc2, explicit, _ = run.json("beacon", f"--zeek-dir={dated}")
    assert rc == rc2 == 0
    assert recursive["record_counts"] == explicit["record_counts"] == {"conn*.log*": 42}


def test_a_genuine_flat_root_is_named_in_preview_and_saved_notes(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "archive"
    _dated(root / "sensor")
    flat = _write(root / "flat" / "conn.log", _conn_rows(_DAY)).parent
    line = (
        f"Zeek: 1 flat directory sits beside dated directories ({flat}) - all "
        "Zeek logs load in full and only the newest 7d is kept after loading"
    )
    rc, summary, err = run.json("beacon", "--recursive", str(root))
    assert rc == 0
    assert line in err.splitlines() and line in _notes(summary)
    rc, _out, err = run.dry("beacon", "--recursive", str(root))
    assert rc == 0 and line in err.splitlines()
    rc, summary, err = run.json("beacon", "--recursive", str(root), "--all")
    assert "flat directory" not in err


def test_a_flat_alias_or_a_skipped_only_pattern_cannot_claim_the_full_read_policy(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "archive"
    dated = _dated(root / "sensor")
    alias = root / "alias"
    alias.mkdir()
    (alias / "conn.log").symlink_to(dated / "2026-09-10" / "conn.log")
    _write(root / "certs" / "x509.log", json.dumps({
        "ts": _DAY.timestamp(), "fingerprint": "ab" * 32,
    }) + "\n")
    rc, recursive, err = run.json(
        "hunt", "--recursive", str(root), "--detect=beacon,ssl",
    )
    rc2, explicit, _ = run.json("beacon", f"--zeek-dir={dated}")
    assert rc == rc2 == 0
    assert "flat director" not in err
    assert recursive["record_counts"]["conn*.log*"] == explicit["record_counts"]["conn*.log*"]
    assert recursive["data_window"] == explicit["data_window"]


def test_a_zero_contribution_dated_structure_cannot_change_the_window(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "archive"
    for d in (20, 21):
        _write(root / "daily" / f"2026-09-{d}" / "host.log", _syslog_lines(d))
    flat = _write(root / "zeek" / "conn.log", _conn_rows(_DAY)).parent
    rc, recursive, err = run.json("beacon", "--recursive", str(root))
    rc2, explicit, _ = run.json("beacon", str(flat))
    assert rc == rc2 == 0
    assert recursive["record_counts"] == explicit["record_counts"]
    assert recursive["data_window"] == explicit["data_window"]
    assert "flat director" not in err


def test_sparse_dates_across_two_dated_roots_select_their_union(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "archive"
    a, b = root / "a", root / "b"
    for sensor, offsets in ((a, (0, 9)), (b, (4, 12))):
        for off in offsets:
            day = _DAY + timedelta(days=off)
            _write(sensor / day.strftime("%Y-%m-%d") / "conn.log.gz", _conn_rows(day), gz=True)
    rc, recursive, _ = run.json("beacon", "--recursive", str(root))
    rc2, explicit, _ = run.json("beacon", str(a), str(b))
    assert rc == rc2 == 0
    assert recursive["record_counts"] == explicit["record_counts"]
    assert recursive["data_window"] == explicit["data_window"]


def test_the_link_exception_applies_the_partition_to_spool_files(
    run: _Runner, tmp_path: Path,
) -> None:
    """A file reached only through ``current`` meets the same partition rule."""
    root = tmp_path / "archive"
    spool = tmp_path / "spool"
    _write(spool / "conn.log", _conn_rows(_DAY))
    _write(spool / "conn.1.log.gz", "", gz=True)                    # empty compressed
    _write(spool / "dns.log", _syslog_lines(10, host="rfc"))        # RFC syslog, Zeek name
    _dated(root / "sensor", days=1, current=spool)
    rc, summary, err = run.json("hunt", "--recursive", str(root), "--detect=beacon,dns,syslog")
    assert rc == 0
    assert summary["record_counts"]["conn*.log*"] == 12
    assert "dns*.log*" not in summary["record_counts"]
    assert "*.log*" not in summary["record_counts"]                # never widened to syslog
    assert (
        f"discovery: 1 file in linked Zeek subdirectories under {root} is not a "
        "Zeek log this run reads and was not read (sensor/current/dns.log) - pass "
        "the linked directory directly to include it"
    ) in err.splitlines()
    # Visited directly as well: Zeek's identity is unchanged, and the generic
    # walk now gives the RFC file to syslog under its own rule.
    rc, both, err = run.json(
        "hunt", "--recursive", str(root), str(spool), "--detect=beacon,dns,syslog",
    )
    assert rc == 0
    assert both["record_counts"]["conn*.log*"] == 12
    assert both["record_counts"]["*.log*"] == 4
    assert "dns*.log*" not in both["record_counts"]
    assert "linked Zeek subdirectories" not in err


def test_a_spool_file_partition_matches_a_walked_file(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    _write(spool / "conn.log", _conn_rows(_DAY))
    _write(spool / "conn.1.log.gz", "", gz=True)
    _write(spool / "dns.log", _syslog_lines(10))
    root = _dated(tmp_path / "archive" / "sensor", days=1, current=spool).parent
    permitted = {"zeek_dir": ("conn*.log*", "dns*.log*"), "syslog_dir": ("*.log*",)}
    via_link = rec.RecursiveIndex(permitted)
    via_link.register(str(root), root, mode=rec.PARTITION)
    via_link.close()
    walked = rec.RecursiveIndex(permitted)
    walked.register(str(root), root, mode=rec.PARTITION)
    walked.register(str(spool), spool, mode=rec.PARTITION)
    walked.close()
    link = root / "sensor" / "current"
    for name in ("conn.log", "conn.1.log.gz"):
        linked, direct = via_link.outcome(link / name), walked.outcome(spool / name)
        assert (linked.kind, linked.family, linked.cause, linked.resolved) == (
            direct.kind, direct.family, direct.cause, direct.resolved,
        )
    assert via_link.outcome(link / "conn.1.log.gz").kind is FileOutcomeKind.EMPTY
    # RFC syslog content under a Zeek name: walked directly, syslog reads it and
    # Zeek's link spelling of the same file never becomes a Zeek candidate.
    assert walked.outcome(spool / "dns.log").family == "syslog_dir"
    assert not walked._admitted_as(link / "dns.log", "zeek_dir")
    # Reached only through the link, it is neither Zeek's nor widened to syslog.
    assert not via_link._admitted_as(link / "dns.log", "zeek_dir")
    assert link / "dns.log" not in via_link.partition_files("syslog_dir")
    assert via_link.partition_files("syslog_dir") == ()


# ── 5. name admission belongs to Zeek alone, and never overrides content ─────


def _ssl_rows(n: int = 3) -> str:
    return "".join(json.dumps({
        "ts": (_DAY + timedelta(minutes=i)).timestamp(), "uid": f"S{i}",
        "id.orig_h": "192.0.2.10", "id.orig_p": 50000 + i,
        "id.resp_h": "198.51.100.30", "id.resp_p": 443, "version": "TLSv12",
        "established": True, "resumed": False, "sni": None,
    }) + "\n" for i in range(n))


def test_directive_less_ssl_logs_load_by_their_primary_name(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "archive"
    flat = _write(root / "tls" / "ssl.log", _ssl_rows()).parent
    _write(flat / "x509.log", json.dumps({"ts": _DAY.timestamp(), "fingerprint": "cd" * 32}) + "\n")
    rc, recursive, _ = run.json("ssl", "--recursive", str(root))
    rc2, explicit, _ = run.json("ssl", f"--zeek-dir={flat}")
    assert rc == rc2 == 0
    assert recursive["record_counts"] == explicit["record_counts"]
    assert recursive["record_counts"]["ssl*.log*"] == 3


def test_unclassified_json_and_pihole_names_get_no_name_fallback(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "archive"
    _write(root / "pihole.log", json.dumps({"x": 1}) + "\n")
    _write(root / "events.json", json.dumps({"x": 1}) + "\n")
    rc, _summary, err = run.json("hunt", "--recursive", str(root), "--detect=dns,aws")
    assert rc == 1
    assert (
        f"discovery: nothing under {root} is read by this run - it holds 2 "
        "unrecognized files"
    ) in err


def test_empty_files_cannot_add_a_flat_root(run: _Runner, tmp_path: Path) -> None:
    root = tmp_path / "archive"
    dated = _dated(root / "sensor")
    _write(root / "sibling" / "conn.log.gz", "", gz=True)
    _write(root / "sibling" / "syslog.log", "")
    rc, recursive, err = run.json("beacon", "--recursive", str(root))
    rc2, explicit, _ = run.json("beacon", f"--zeek-dir={dated}")
    assert rc == rc2 == 0
    assert recursive["record_counts"] == explicit["record_counts"]
    assert recursive["data_window"] == explicit["data_window"]
    assert "flat director" not in err and "discovery:" not in err


# ── 6. overlaps, aliases, links and shared candidates ────────────────────────


def test_repeated_nested_and_aliased_roots_load_once(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20, host="a"))
    _write(root / "b" / "messages", _syslog_lines(20, host="b"))
    _write(root / "README", "notes\n")
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    rc, once, err1 = run.json("syslog", "--recursive", str(root))
    rc2, many, err2 = run.json(
        "syslog", "--recursive", str(root / "a"), str(root), str(root), str(alias),
    )
    assert rc == rc2 == 0
    assert once["record_counts"] == many["record_counts"] == {"*.log*": 8}
    assert once["data_size_bytes"] == many["data_size_bytes"]
    assert err2.count("discovery:") == err1.count("discovery:") == 1


def test_an_explicit_file_inside_a_recursive_root_loads_once(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    file = _write(root / "a" / "messages", _syslog_lines(20))
    rc, summary, _ = run.json("syslog", "--recursive", str(file), str(root))
    assert rc == 0
    assert summary["record_counts"]["*.log*"] == 4


def test_a_link_cycle_is_omitted_and_an_explicit_linked_root_is_walked(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    (root / "a" / "loop").symlink_to(root, target_is_directory=True)
    link = tmp_path / "linked"
    link.symlink_to(root, target_is_directory=True)
    rc, summary, err = run.json("syslog", "--recursive", str(root))
    assert rc == 0 and summary["record_counts"]["*.log*"] == 4
    assert (
        f"discovery: did not follow 1 linked subdirectory under {root} (a/loop) - "
        "pass a linked directory directly to include it"
    ) in err.splitlines()
    rc, summary, _ = run.json("syslog", "--recursive", str(link))
    assert rc == 0 and summary["record_counts"]["*.log*"] == 4


def test_shared_candidates_come_only_from_declarations(
    run: _Runner, tmp_path: Path,
) -> None:
    shared = tmp_path / "shared"
    _write(shared / "pihole.log", _dnsmasq_lines(14))
    rc, _summary, err = run.json(
        "hunt", "--recursive", f"--syslog-dir={shared}", f"--pihole-dir={shared}",
        "--detect=dns,syslog",
    )
    assert rc == 0
    assert (
        "shared files: 1 file is a candidate for both Pi-hole and syslog "
        f"({shared / 'pihole.log'})"
    ) in err.splitlines()
    rc, _summary, err = run.json("hunt", "--recursive", str(shared), "--detect=dns,syslog")
    assert rc == 0 and "shared files" not in err


def test_a_recursive_run_drops_the_equal_directory_overlap_note(
    run: _Runner, tmp_path: Path,
) -> None:
    shared = tmp_path / "shared"
    _write(shared / "pihole.log", _dnsmasq_lines(14))
    _write(shared / "messages", _syslog_lines(14))
    rc, summary, _ = run.json("hunt", "--recursive", str(shared), "--detect=dns,syslog")
    assert rc == 0
    assert not any("same directory" in note for note in _notes(summary))


# ── 7. failures keep their cause and owner ───────────────────────────────────


def test_a_readable_sibling_does_not_hide_a_later_denied_subtree(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    denied = _write(root / "z" / "messages", _syslog_lines(20)).parent
    denied.chmod(0)
    try:
        rc, summary, err = run.json("syslog", "--recursive", str(root))
    finally:
        denied.chmod(0o755)
    assert rc == 0
    line = (
        f"discovery: 1 subdirectory under {root} could not be listed (permission "
        "denied) - its contents are absent from this run (z)"
    )
    assert err.splitlines().count(line) == 1
    assert _notes(summary).count(line) == 1
    assert not any(note.startswith("syslog: directory could not be listed")
                   for note in _notes(summary))


def test_a_denied_positional_root_is_one_root_failure(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "locked"
    _write(root / "messages", _syslog_lines(20))
    root.chmod(0)
    try:
        rc, summary, err = run.json("syslog", "--recursive", str(root))
        rc_dry, _out, dry_err = run.dry("syslog", "--recursive", str(root))
    finally:
        root.chmod(0o755)
    assert rc == 1 and summary is None and rc_dry == 0
    line = (
        f"discovery: {root} could not be listed (permission denied) - nothing "
        "beneath it was searched"
    )
    for text in (err, dry_err):
        lines = text.splitlines()
        assert lines.count(line) == 1
        assert not any("nothing under" in other or "holds no files" in other
                       for other in lines)


def test_a_declared_denied_subtree_keeps_its_family_owner(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    denied = _write(root / "z" / "messages", _syslog_lines(20)).parent
    denied.chmod(0)
    try:
        rc, summary, err = run.json(
            "syslog", "--recursive", str(root), f"--syslog-dir={root}",
        )
        rc_dry, _out, dry_err = run.dry(
            "syslog", "--recursive", str(root), f"--syslog-dir={root}",
        )
    finally:
        denied.chmod(0o755)
    assert rc == 0 and rc_dry == 0
    owner = (
        f"syslog: directory could not be listed (permission denied) - its "
        f"contents are absent from this run ({denied})"
    )
    assert _notes(summary).count(owner) == 1
    assert dry_err.splitlines().count(owner) == 1
    for text in (err, dry_err, "\n".join(_notes(summary))):
        assert "subdirectory under" not in text


def test_read_failures_keep_their_cause_and_meet_a_permitted_gate(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    locked = _write(root / "b" / "secure", _syslog_lines(20))
    locked.chmod(0)
    try:
        rc, summary, err = run.json("syslog", "--recursive", str(root))
        rc_dry, _out, dry_err = run.dry("syslog", "--recursive", str(root))
        rc_b, _sb, beacon_err = run.json(
            "hunt", "--recursive", str(root), str(_write(tmp_path / "z" / "conn.log",
                                                       _conn_rows(_DAY)).parent),
            "--detect=beacon",
        )
    finally:
        locked.chmod(0o644)
    assert rc == 0 and rc_dry == 0 and rc_b == 0
    # Loaded: the load's own permission note states it; nothing is restated.
    assert "discovery:" not in err
    assert any("permission denied" in note for note in _notes(summary))
    assert (
        f"discovery: 1 file under {root} could not be read (EACCES) - kept as a "
        "possible syslog file for a full run to try (b/secure)"
    ) in dry_err.splitlines()
    assert (
        f"discovery: 1 file under {root} could not be read (EACCES) - its log type "
        "is unknown, so it was not loaded (b/secure)"
    ) in beacon_err.splitlines()
    for text in (err, dry_err, beacon_err):
        assert "not recognized" not in text


def test_a_corrupt_compressed_file_is_never_admitted(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    _write(root / "messages", _syslog_lines(20))
    raw = bytearray(gzip.compress(_syslog_lines(20).encode() * 50))
    for i in range(20, 60):
        raw[i] ^= 0xFF
    (root / "broken.log.gz").write_bytes(bytes(raw))
    rc, summary, err = run.json("syslog", "--recursive", str(root))
    assert rc == 0
    assert summary["record_counts"]["*.log*"] == 4
    assert (
        f"discovery: 1 file under {root} could not be read (zlib.error) - its log "
        "type is unknown, so it was not loaded (broken.log.gz)"
    ) in err.splitlines()


def test_listing_errors_group_by_cause_with_complete_counts(
    run: _Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    for i in range(5):
        _write(root / f"bad{i}" / "messages", _syslog_lines(20))
    for i in range(7):
        _write(root / "junk" / f"note{i}.txt", "plain notes\n")
    real = disc._scan_directory

    def flaky(directory: Path):
        if directory.name.startswith("bad"):
            return (), OSError(5, "Input/output error")
        return real(directory)

    monkeypatch.setattr(disc, "_scan_directory", flaky)
    rc, summary, err = run.json("syslog", "--recursive", str(root))
    assert rc == 0
    lines = err.splitlines()
    assert (
        f"discovery: 5 subdirectories under {root} could not be listed (EIO) - "
        "their contents are absent from this run (bad0, bad1, bad2 (+2 more))"
    ) in lines
    assert (
        f"discovery: 7 files under {root} are not recognized as any log this run "
        "reads (junk/note0.txt, junk/note1.txt, junk/note2.txt (+4 more))"
    ) in lines
    assert sum("discovery:" in line for line in lines) == 2


def test_an_incomplete_tree_never_claims_to_hold_no_files(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    (root / "open").mkdir(parents=True)
    denied = _write(root / "z" / "messages", _syslog_lines(20)).parent
    denied.chmod(0)
    try:
        rc, _summary, err = run.json("syslog", "--recursive", str(root))
    finally:
        denied.chmod(0o755)
    assert rc == 1
    assert (
        f"discovery: no files were found under {root} in the parts that could be "
        "searched - nothing to read there"
    ) in err.splitlines()
    assert "holds no files" not in err


def test_excluded_names_are_not_unrecognized_content(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "logs"
    _write(root / "btmp", "binary login records\x00\x01")
    _write(root / "._messages", "apple double")
    rc, _summary, err = run.json("syslog", "--recursive", str(root))
    assert rc == 1
    assert (
        f"discovery: nothing under {root} is read by this run - it holds 2 files "
        "excluded by name"
    ) in err.splitlines()


# ── 8. preview, quiet, surfaces and the sink audit ──────────────────────────


def test_preview_and_execution_select_the_same_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    root = tmp_path / "archive"
    spool = _write(tmp_path / "spool" / "conn.log", _conn_rows(_DAY + timedelta(days=2))).parent
    _dated(root / "sensor", current=spool)
    config = _isolated_config(tmp_path)
    previews: list = []
    real_preview = runner._dry_run_preview

    def spy_preview(*args, **kwargs):
        previews.append(real_preview(*args, **kwargs))
        return previews[-1]

    monkeypatch.setattr(runner, "_dry_run_preview", spy_preview)
    assert _main(["beacon", "--recursive", str(root), f"--config={config}", "--dry-run", "--all"],
                 monkeypatch, tmp_path) == 0
    previewed = list(previews[0].families["zeek_dir"].selected)
    loaded: list[Path] = []
    real_validate = loader.pipeline.validate_selected_files

    def spy_validate(files, *args, **kwargs):
        loaded.extend(files)
        return real_validate(files, *args, **kwargs)

    monkeypatch.setattr(loader.pipeline, "validate_selected_files", spy_validate)
    assert _main(["beacon", "--recursive", str(root), f"--config={config}", "-q", "--all",
                  "--format=json", f"--out={tmp_path / 'o.json'}"], monkeypatch, tmp_path) == 0
    capsys.readouterr()
    assert sorted(p.resolve() for p in previewed) == sorted(p.resolve() for p in loaded)
    assert len(loaded) == 4


def test_a_dry_run_walks_but_never_loads_runs_or_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    root = _mixed(tmp_path / "mixed")
    config = _isolated_config(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("a dry run loaded frames")

    monkeypatch.setattr(loader.pipeline, "run_load", forbidden)
    monkeypatch.setattr(loader, "load_required_logs", forbidden)
    before = set(tmp_path.rglob("*"))
    assert _main(["hunt", "--recursive", str(root), f"--config={config}", "--dry-run"],
                 monkeypatch, tmp_path) == 0
    out = capsys.readouterr().out
    assert "dry run - remove --dry-run to analyze" in out
    assert set(tmp_path.rglob("*")) - before <= {tmp_path / "home"}


@pytest.mark.parametrize("fmt", ["text", "json", "html"])
def test_quiet_saved_reports_keep_root_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, fmt: str,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    _write(root / "README", "notes\n")
    config = _isolated_config(tmp_path)
    out = tmp_path / f"report.{fmt}"
    assert _main(["syslog", "--recursive", str(root), f"--config={config}", "-q",
                  f"--format={fmt}", f"--out={out}"], monkeypatch, tmp_path) == 0
    assert "not recognized as any log this run reads" in capsys.readouterr().err
    assert "not recognized as any log this run reads" in out.read_text(encoding="utf-8")


def test_csv_stays_findings_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    _write(root / "README", "notes\n")
    config = _isolated_config(tmp_path)
    out = tmp_path / "report.csv"
    assert _main(["syslog", "--recursive", str(root), f"--config={config}", "-q",
                  "--format=csv", f"--out={out}"], monkeypatch, tmp_path) == 0
    capsys.readouterr()
    assert "not recognized" not in out.read_text(encoding="utf-8")


_HOSTILE = [
    "esc\x1b]0;owned\x07name", "csi\x9b31mname", "new\nline", 'quote"\'s',
    "<img src=x onerror=alert(1)>", "x" * 240,
]


@pytest.mark.parametrize("fmt", ["text", "json", "html"])
def test_hostile_names_are_inert_on_every_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, fmt: str,
) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    for name in _HOSTILE:
        _write(root / "junk" / name, "plain notes\n")
    flat_dir = root / ("flat" + _HOSTILE[0])
    _dated(root / "sensor")
    _write(flat_dir / "conn.log", _conn_rows(_DAY))
    (root / ("link" + _HOSTILE[4])).symlink_to(root / "a", target_is_directory=True)
    config = _isolated_config(tmp_path)
    out = tmp_path / f"report.{fmt}"
    assert _main(["hunt", "--recursive", str(root), "--detect=beacon,syslog",
                  f"--config={config}", "-q", f"--format={fmt}", f"--out={out}"],
                 monkeypatch, tmp_path) == 0
    err = capsys.readouterr().err
    saved = out.read_text(encoding="utf-8")
    for text in (err, saved):
        assert _ESC not in text and _CSI not in text and "\x07" not in text
    assert "discovery:" in err and "flat directory" in err
    if fmt == "html":
        assert "<img src=x" not in saved
        assert "&lt;img src=x onerror=alert(1)&gt;" in saved
    if fmt == "json":
        notes = json.loads(saved)["run_summary"]["notes"]
        assert any("not recognized" in note for note in notes)
        assert all("\n" not in note for note in notes)


# ── 9. retained limits: singleton rotation groups and the family anchor ─────


def test_date_partitioned_singletons_trade_rows_not_bytes(
    run: _Runner, tmp_path: Path,
) -> None:
    root = tmp_path / "hosts"
    for day in range(12, 22):
        _write(root / "new" / f"2026-09-{day}" / "messages", _syslog_lines(day, host="new"))
    _write(root / "old" / "2026-08-01" / "messages",
           "".join(f"Aug  1 1{i}:00:00 old sshd[{i}]: Accepted publickey for alice "
                   f"from 192.0.2.9 port 22 ssh2\n" for i in range(4)))
    rc, full, _ = run.json("syslog", "--recursive", str(root), "--all")
    rc2, bounded, _ = run.json(
        "syslog", "--recursive", str(root), "--since=2026-09-19", "--until=2026-09-22",
    )
    rc3, default, _ = run.json("syslog", "--recursive", str(root))
    assert rc == rc2 == rc3 == 0
    assert bounded["record_counts"]["*.log*"] < full["record_counts"]["*.log*"]
    assert bounded["data_size_bytes"] == full["data_size_bytes"]
    assert default["record_counts"]["*.log*"] < full["record_counts"]["*.log*"]
    assert default["data_window"][0] >= "2026-09-14"


# ── layering and the composer tripwire ──────────────────────────────────────


def test_new_runner_composers_name_no_source_family() -> None:
    import inspect

    composer = [
        runner._root_fact_lines,
        runner._layout_policy_lines,
        runner._shared_candidate_lines,
        runner._render_root_fact,
    ]
    for function in composer:
        source = inspect.getsource(function)
        for key in ("zeek_dir", "syslog_dir", "pihole_dir", "cloudtrail_dir", "journal"):
            assert f'"{key}"' not in source, (function.__name__, key)


def test_the_partition_names_no_source_family() -> None:
    import inspect

    source = inspect.getsource(rec.partition_file)
    for key in ("zeek_dir", "syslog_dir", "pihole_dir", "cloudtrail_dir"):
        assert f'"{key}"' not in source, key


def test_a_registered_strategy_without_recursive_fields_is_never_offered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "logs"
    file = _write(root / "messages", _syslog_lines(20))
    custom = loader.pipeline._SOURCE_LOADERS["syslog_dir"]
    from dataclasses import replace
    monkeypatch.setitem(loader.pipeline._SOURCE_LOADERS, "custom_dir", replace(
        custom, recursive_admit=None, recursive_excludes=None,
        claims_unclassified=False, content_fallthrough=False,
    ))
    outcome = rec.partition_file(file, {"custom_dir": ("*.log*",)})
    assert outcome.kind is FileOutcomeKind.OUTSIDE
    assert outcome.family == "syslog_dir"


def test_prepare_discovery_keeps_the_typed_order_of_buckets(tmp_path: Path) -> None:
    root = tmp_path / "logs"
    _write(root / "a" / "messages", _syslog_lines(20))
    file = _write(tmp_path / "solo" / "secure", _syslog_lines(20))
    buckets, _votes, discovery = prepare_analyze_discovery(
        [str(root), str(file)], detector_module=None, overrides={},
        recursive=True, declared_patterns={"syslog_dir": ["*.log*"]},
    )
    assert buckets == {"syslog_dir": [str(root), str(file)]}
    assert discovery.recursive
    assert discovery.provenance("syslog_dir", root) == "positional"


# ── one physical file, many names: admission per name, ownership after all ──


def _aliased(root: Path, content: str, original: str, alias: str) -> tuple[Path, Path]:
    first = _write(root / "a-original" / original, content)
    link = root / "z-alias" / alias
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(first)
    return root / "a-original", root / "z-alias"


@pytest.mark.parametrize("order", ["original-first", "alias-first", "ancestor", "alias-alone"])
def test_a_rejected_name_never_poisons_a_valid_alias(
    run: _Runner, tmp_path: Path, order: str,
) -> None:
    root = tmp_path / "aliases"
    original, alias = _aliased(root, _conn_rows(_DAY, n=12), "unnamed", "conn.log")
    roots = {
        "original-first": [original, alias], "alias-first": [alias, original],
        "ancestor": [root], "alias-alone": [alias],
    }[order]
    rc, summary, err = run.json("beacon", "--recursive", *map(str, roots), "--all")
    assert rc == 0
    assert summary["record_counts"] == {"conn*.log*": 12}
    assert "discovery:" not in err


@pytest.mark.parametrize("order", ["original-first", "alias-first"])
def test_a_rejected_pihole_name_never_poisons_a_valid_alias(
    run: _Runner, tmp_path: Path, order: str,
) -> None:
    root = tmp_path / "aliases"
    original, alias = _aliased(root, _dnsmasq_lines(14), "unnamed", "pihole.log")
    roots = [original, alias] if order == "original-first" else [alias, original]
    rc, summary, err = run.json("dns", "--recursive", *map(str, roots))
    assert rc == 0
    assert summary["record_counts"]["pihole*.log*"] == 4
    assert "discovery:" not in err


@pytest.mark.parametrize("real_name", ["pihole.log", "all.log-20261015"])
def test_two_names_for_one_file_never_feed_two_families(
    run: _Runner, tmp_path: Path, real_name: str,
) -> None:
    other = "all.log-20261015" if real_name == "pihole.log" else "pihole.log"
    root = tmp_path / "aliases"
    _aliased(root, _dnsmasq_lines(14), real_name, other)
    rc, summary, err = run.json("hunt", "--recursive", str(root), "--detect=dns,syslog")
    assert rc == 0
    assert summary["record_counts"] == {"pihole*.log*": 4}
    assert "discovery:" not in err and "shared files" not in err


def test_a_name_an_explicit_file_already_supplies_is_no_omission(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    target = _write(tmp_path / "solo" / "conn.log", _conn_rows(_DAY))
    (root / "x").mkdir(parents=True)
    (root / "x" / "unnamed").symlink_to(target)
    index = rec.RecursiveIndex({"zeek_dir": ("conn*.log*",)})
    index.register_supplied(target)
    index.register(str(root), root, mode=rec.PARTITION)
    index.close()
    assert index.outcome(root / "x" / "unnamed").kind is FileOutcomeKind.SUPPLIED
    assert index.root_facts() == []


def test_two_rejected_names_for_one_file_are_one_claim(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    target = _write(root / "a" / "unnamed", _conn_rows(_DAY))
    (root / "b").mkdir()
    (root / "b" / "also-unnamed").symlink_to(target)
    index = rec.RecursiveIndex({"zeek_dir": ("conn*.log*",)})
    index.register(str(root), root, mode=rec.PARTITION)
    index.close()
    (fact,) = [f for f in index.root_facts() if f.kind.value == "rejected_files"]
    assert fact.count == 1 and fact.paths == (root / "a" / "unnamed",)


# ── a kept-but-unreadable file the window does not select ───────────────────


def _rotations_with_bad_tail(root: Path, tail: str) -> Path:
    _write(root / "messages", _syslog_lines(20))
    _write(root / "messages.1", _syslog_lines(2))
    bad = root / tail
    if tail.endswith(".gz"):
        bad.write_bytes(b"not a gzip stream\n")
    else:
        _write(bad, _syslog_lines(1)).chmod(0)
    return bad


@pytest.mark.parametrize(("tail", "cause"), [("messages.2", "EACCES"), ("messages.2.gz", "BadGzipFile")])
def test_a_pruned_unreadable_tail_is_stated_after_the_load(
    run: _Runner, tmp_path: Path, tail: str, cause: str,
) -> None:
    root = tmp_path / "logs"
    bad = _rotations_with_bad_tail(root, tail)
    try:
        rc, summary, err = run.json("syslog", "--recursive", str(root))
        rc_dry, _out, dry_err = run.dry("syslog", "--recursive", str(root))
    finally:
        bad.chmod(0o644)
    assert rc == 0 and rc_dry == 0
    line = (
        f"discovery: 1 file under {root} could not be read ({cause}) - kept as a "
        f"possible syslog file, but this run's time window did not select it ({tail})"
    )
    assert err.splitlines().count(line) == 1
    assert _notes(summary).count(line) == 1
    assert any("skipped outside the selected window" in note for note in _notes(summary))
    assert (
        f"discovery: 1 file under {root} could not be read ({cause}) - kept as a "
        f"possible syslog file for a full run to try ({tail})"
    ) in dry_err.splitlines()


@pytest.mark.parametrize("tail", ["messages.1", "messages.1.gz"])
def test_a_selected_unreadable_file_is_left_to_the_load(
    run: _Runner, tmp_path: Path, tail: str,
) -> None:
    root = tmp_path / "logs"
    _write(root / "messages", _syslog_lines(20))
    bad = root / tail
    if tail.endswith(".gz"):
        bad.write_bytes(b"not a gzip stream\n")
    else:
        _write(bad, _syslog_lines(19)).chmod(0)
    try:
        rc, summary, err = run.json("syslog", "--recursive", str(root))
    finally:
        bad.chmod(0o644)
    assert rc == 0
    assert "discovery:" not in err
    assert not any("discovery:" in note for note in _notes(summary))
    if tail.endswith(".gz"):
        # The corruption rail states it, on stderr, as it does for any run.
        assert f"{tail} could not be read - compressed file is incomplete or corrupt" in err
    else:
        assert any("permission denied" in note for note in _notes(summary))
        assert f"{tail}: permission denied" in err


# ── an input that disappears after the walk keeps its observed kind ─────────


@pytest.mark.parametrize("removed", ["file", "root"])
@pytest.mark.parametrize("sibling", [True, False])
@pytest.mark.parametrize(("verb", "name", "rows"), [
    ("syslog", "messages", 4), ("beacon", "conn.log", 6),
])
def test_a_disappeared_input_is_reported_by_the_read_loop(
    run: _Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    removed: str, sibling: bool, verb: str, name: str, rows: int,
) -> None:
    content = _syslog_lines(20) if verb == "syslog" else _conn_rows(_DAY)
    root = tmp_path / "gone"
    target = _write(root / name, content)
    args = [verb, "--recursive", str(root)]
    if sibling:
        _write(tmp_path / "sibling" / name, content)
        args.append(str(tmp_path / "sibling"))
    real = runner._plan_and_load

    def vanish(*a, **kw):
        target.unlink()
        if removed == "root":
            root.rmdir()
        return real(*a, **kw)

    monkeypatch.setattr(runner, "_plan_and_load", vanish)
    rc, summary, err = run.json(*args)
    assert rc == 0
    pattern = "*.log*" if verb == "syslog" else "conn*.log*"
    assert summary["record_counts"].get(pattern, 0) == (rows if sibling else 0)
    assert f"{name} could not be read - unreadable (FileNotFoundError); skipping" in err


def test_a_disappeared_shallow_input_is_reported_too(
    run: _Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shallow run observes at planning; a directory gone by the load still reports."""
    root = tmp_path / "gone"
    target = _write(root / "messages", _syslog_lines(20))
    _write(tmp_path / "sibling" / "messages", _syslog_lines(20))
    real = loader.load_required_logs

    def vanish(*a, **kw):
        if target.exists():
            target.unlink()
            root.rmdir()
        return real(*a, **kw)

    monkeypatch.setattr(loader, "load_required_logs", vanish)
    rc, summary, err = run.json("syslog", str(root), str(tmp_path / "sibling"))
    assert rc == 0
    assert summary["record_counts"]["*.log*"] == 4
    assert "messages could not be read - unreadable (FileNotFoundError); skipping" in err


# ── an explicit input this run reads supplies its content to other names ────


def _explicit_alias(tmp_path: Path, explicit_name: str) -> tuple[Path, Path]:
    explicit = _write(tmp_path / "solo" / explicit_name, _conn_rows(_DAY, n=12))
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "unnamed").symlink_to(explicit)
    return explicit, tree


@pytest.mark.parametrize("order", ["file-first", "root-first", "override"])
def test_an_explicit_input_the_run_reads_supplies_another_name(
    run: _Runner, tmp_path: Path, order: str,
) -> None:
    explicit, tree = _explicit_alias(tmp_path, "conn.log")
    args = {
        "file-first": [str(explicit), str(tree)],
        "root-first": [str(tree), str(explicit)],
        "override": [f"--zeek-dir={explicit}", str(tree)],
    }[order]
    rc, summary, err = run.json("beacon", "--recursive", *args, "--all")
    assert rc == 0
    assert summary["record_counts"] == {"conn*.log*": 12}
    assert "discovery:" not in err
    assert not any("discovery:" in note for note in _notes(summary))


def test_an_explicit_input_the_run_does_not_read_hides_nothing(
    run: _Runner, tmp_path: Path,
) -> None:
    explicit, tree = _explicit_alias(tmp_path, "notes.txt")
    rc, _summary, err = run.json("beacon", "--recursive", str(explicit), str(tree), "--all")
    assert rc == 1
    lines = err.splitlines()
    assert (
        f"discovery: 1 file under {tree} looks like Zeek logs, but its name does not "
        "match conn*.log* (unnamed)"
    ) in lines
    assert (
        f"discovery: nothing under {tree} is read by this run - it holds 1 file "
        "named outside its family's patterns"
    ) in lines
