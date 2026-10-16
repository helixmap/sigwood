"""The analyze discovery inventory: observe once, select purely, disclose coverage.

The public discovery helpers are a selection over one observation, so the
inventory path and every other caller share one selection implementation. These
tests pin that equivalence, the legacy helpers' historical error behavior, the
source-checked loader seam, observation counts across a whole run, and every
coverage fact the run discloses on stderr and in saved reports.
"""

from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import sigwood.cli as cli
import sigwood.common.loader as loader
import sigwood.runner as runner
from sigwood.common.loader import (
    CandidatePopulation,
    DiscoveryInventory,
    EntryKind,
    discover_cloudtrail_files,
    discover_zeek_files,
    load_required_logs,
    resolve_load_windows,
)
from sigwood.common.loader import discovery as disc
from sigwood.common.loader import journal
from sigwood.common.loader.pipeline import _SOURCE_LOADERS
from sigwood.common.sources import prepare_analyze_discovery

_REPO = Path(__file__).resolve().parents[1]
_BASE = datetime(2026, 9, 1, 0, 30, tzinfo=timezone.utc)
_ESC = "\x1b"
_CSI = "\x9b"


# ── fixture builders (RFC 5737 addresses, reserved names only) ───────────────


def _conn_rows(day: datetime, n: int = 6) -> str:
    rows = []
    for i in range(n):
        ts = (day + timedelta(minutes=30 * i)).timestamp()
        rows.append(json.dumps({
            "_path": "conn", "ts": ts, "uid": f"C{int(ts)}{i}",
            "id.orig_h": "192.0.2.10", "id.orig_p": 40000 + i,
            "id.resp_h": "198.51.100.5", "id.resp_p": 443, "proto": "tcp",
            "orig_bytes": 100, "resp_bytes": 200, "conn_state": "SF",
        }))
    return "\n".join(rows) + "\n"


def _dns_rows(day: datetime, n: int = 4) -> str:
    rows = []
    for i in range(n):
        ts = (day + timedelta(minutes=45 * i)).timestamp()
        rows.append(json.dumps({
            "_path": "dns", "ts": ts, "uid": f"D{int(ts)}{i}",
            "id.orig_h": "192.0.2.20", "id.orig_p": 50000 + i,
            "id.resp_h": "198.51.100.53", "id.resp_p": 53, "proto": "udp",
            "query": f"q{i}.example.com", "qclass": 1, "qtype": 1, "rcode": 0,
        }))
    return "\n".join(rows) + "\n"


def _syslog_lines(day: int, host: str = "host1", n: int = 4) -> str:
    return "".join(
        f"Sep {day:2d} 1{i}:00:00 {host} sshd[{100 + i}]: Accepted publickey "
        f"for alice from 192.0.2.{i + 1} port 22 ssh2\n"
        for i in range(n)
    )


def _dnsmasq_lines(day: int, n: int = 4) -> str:
    return "".join(
        f"Oct {day:2d} 0{i}:00:00 dnsmasq[811]: query[A] h{i}.example.com "
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


def _dated_zeek(root: Path, days: int = 10) -> Path:
    for d in range(days):
        day = _BASE + timedelta(days=d)
        name = day.strftime("%Y-%m-%d")
        _write(root / name / "conn.log", _conn_rows(day))
        _write(root / name / "dns.log.gz", _dns_rows(day), gz=True)
    (root / "current").symlink_to(root / (_BASE + timedelta(days=days - 1)).strftime("%Y-%m-%d"))
    return root


def _ct_record(event_id: str, ts: str) -> dict:
    return {
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/alice",
                         "accountId": "123456789012", "userName": "alice"},
        "eventTime": ts, "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
        "awsRegion": "us-east-1", "sourceIPAddress": "192.0.2.50", "eventID": event_id,
        "readOnly": True, "eventType": "AwsApiCall", "recipientAccountId": "123456789012",
    }


def _cloudtrail_tree(root: Path) -> Path:
    day = root / "AWSLogs" / "123456789012" / "CloudTrail" / "us-east-1" / "2026" / "10" / "15"
    for i in range(2):
        _write(day / f"part{i}.json.gz",
               json.dumps({"Records": [_ct_record(f"e{i}", f"2026-10-15T1{i}:00:00Z")]}),
               gz=True)
    _write(day / ".hidden.json", json.dumps({"Records": [_ct_record("h", "2026-10-15T09:00:00Z")]}))
    _write(day / "Upper.JSON", json.dumps({"Records": [_ct_record("u", "2026-10-15T08:00:00Z")]}))
    _write(day / "._sidecar.json", "junk")
    _write(root / "AWSLogs" / "123456789012" / "CloudTrail-Digest" / "d.json.gz", "{}", gz=True)
    outside = root.parent / f"{root.name}-outside"
    _write(outside / "linked.json", json.dumps({"Records": [_ct_record("l", "2026-10-15T07:00:00Z")]}))
    (day / "linked-dir").symlink_to(outside, target_is_directory=True)
    (day / "file-link.json").symlink_to(day / ".hidden.json")
    return root


def _legacy_cloudtrail(path: Path) -> list[Path]:
    """The recursive-glob discovery the CloudTrail walk must reproduce."""
    out = []
    for candidate in sorted(path.rglob("*.json*")):
        if loader.is_reserved_provenance_path(candidate) or not candidate.is_file():
            continue
        if candidate.name.startswith("._") or "CloudTrail-Digest" in candidate.parts:
            continue
        out.append(candidate)
    return out


def _isolated_config(tmp_path: Path, **sigwood: str) -> Path:
    """A config file naming no real source; keyword values override."""
    values = {"root": "", "zeek_dir": "", "syslog_dir": "", "syslog_source": "files"}
    values.update(sigwood)
    lines = ["[sigwood]", *(f'{key} = "{value}"' for key, value in values.items())]
    path = tmp_path / "config.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# ── observe/select is the shipped discovery ─────────────────────────────────


@pytest.mark.parametrize("window", [
    (None, None),
    (_BASE + timedelta(days=6), None),
    (_BASE + timedelta(days=2), _BASE + timedelta(days=4)),
])
@pytest.mark.parametrize("pattern", ["conn*.log*", "dns*.log*", "ssl*.log*"])
def test_zeek_helper_is_a_selection_over_one_observation(
    tmp_path: Path, window, pattern: str,
) -> None:
    dated = _dated_zeek(tmp_path / "dated")
    flat = tmp_path / "flat"
    _write(flat / "conn.log", _conn_rows(_BASE))
    _write(flat / "conn-summary.log", "derived sibling\n")
    since, until = window
    for root in (dated, flat, flat / "conn.log"):
        obs = disc.observe_zeek_input(root)
        assert disc.select_zeek_files(obs, pattern, since, until) == discover_zeek_files(
            root, pattern, since, until,
        )


def test_flat_family_helpers_are_selections_over_one_observation(tmp_path: Path) -> None:
    syslog = tmp_path / "syslog"
    _write(syslog / "messages", _syslog_lines(20))
    _write(syslog / "messages.1", _syslog_lines(19))
    _write(syslog / "messages.2.gz", _syslog_lines(18), gz=True)
    _write(syslog / "dnf.log", "2026-09-20T12:00:00+0000 INFO --- not syslog\n")
    _write(syslog / "btmp", "binary-ish")
    pihole = tmp_path / "pihole"
    _write(pihole / "pihole.log", _dnsmasq_lines(14))
    _write(pihole / "pihole.log.1", _dnsmasq_lines(13))
    _write(pihole / "pihole-FTL.log", "ftl\n")
    _write(pihole / "._pihole.log", "junk")
    assert disc.select_syslog_files(disc.observe_syslog_input(syslog)) == (
        loader._discover_syslog_files(syslog)
    )
    assert [p.name for p in loader._discover_syslog_files(syslog)] == [
        "messages", "messages.1", "messages.2.gz",
    ]
    for pattern in ("pihole*.log*", "*.log*"):
        assert disc.select_pihole_files(disc.observe_pihole_input(pihole), pattern) == (
            loader._syslog_files(pihole, pattern)
        )


def test_cloudtrail_walk_matches_the_recursive_glob_grammar(tmp_path: Path) -> None:
    """Hidden names, case, digests, sidecars and links keep their old treatment."""
    root = _cloudtrail_tree(tmp_path / "ct")
    found = discover_cloudtrail_files(root)
    assert found == _legacy_cloudtrail(root)
    names = {p.name for p in found}
    assert {"part0.json.gz", "part1.json.gz", ".hidden.json", "file-link.json"} == names
    obs = disc.observe_cloudtrail_input(root)
    kinds = {fact.kind for fact in obs.facts}
    assert loader.DiscoveryFactKind.LINKED_DIRECTORY_OMITTED in kinds


def test_pihole_selection_never_admits_a_nonregular_name_match(tmp_path: Path) -> None:
    pihole = tmp_path / "pihole"
    _write(pihole / "pihole.log", _dnsmasq_lines(14))
    (pihole / "pihole.log.d").mkdir()
    os.mkfifo(pihole / "pihole.log.fifo")
    (pihole / "pihole.log.dangling").symlink_to(pihole / "absent")
    assert [p.name for p in loader._syslog_files(pihole, "pihole*.log*")] == ["pihole.log"]
    kinds = {e.path.name: e.kind for e in disc.observe_pihole_input(pihole).entries}
    assert kinds["pihole.log.d"] is EntryKind.DIRECTORY
    assert kinds["pihole.log.fifo"] is EntryKind.NONREGULAR
    assert kinds["pihole.log.dangling"] is EntryKind.BROKEN_LINK


def test_entry_inspection_failure_keeps_its_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed stat is ERROR with its errno, not a guessed broken link or FIFO."""
    target = _write(tmp_path / "d" / "pihole.log", _dnsmasq_lines(14))
    real_stat = os.stat

    def _stat(path, *args, **kwargs):
        if Path(path) == target:
            raise PermissionError(13, "synthetic")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(disc.os, "stat", _stat)
    entries = disc.observe_pihole_input(target.parent).entries
    assert [(e.kind, e.error) for e in entries] == [(EntryKind.ERROR, "EACCES")]


# ── legacy helpers keep their historical error behavior ──────────────────────


@pytest.mark.parametrize("helper, source_key, pattern", [
    (lambda p: discover_zeek_files(p, "conn*.log*"), "zeek_dir", "conn*.log*"),
    (lambda p: loader._discover_syslog_files(p), "syslog_dir", "*.log*"),
])
def test_iterdir_families_still_raise_a_nonpermission_listing_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, helper, source_key: str, pattern: str,
) -> None:
    root = tmp_path / source_key
    root.mkdir()
    real_iterdir = Path.iterdir

    def _fail(path: Path):
        if path == root:
            raise OSError(5, "synthetic I/O failure")
        return real_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", _fail)
    with pytest.raises(OSError):
        helper(root)
    inventory = DiscoveryInventory()
    skips: dict = {}
    assert inventory.candidates(source_key, root, pattern, _directory_skips=skips) == []
    obs = inventory.observation(source_key, root)
    assert obs is not None and obs.kind == "error"
    assert skips == {}


def test_inventory_records_a_denied_descendant_the_legacy_helper_does_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "cloudtrail"
    nested = root / "AWSLogs" / "000000000000" / "CloudTrail"
    nested.mkdir(parents=True)
    real_iterdir = Path.iterdir

    def _deny(path: Path):
        if path == nested:
            raise PermissionError(13, "synthetic nested denial")
        return real_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", _deny)
    legacy: dict = {}
    assert discover_cloudtrail_files(root, _directory_skips=legacy) == []
    assert legacy == {}
    observed: dict = {}
    assert DiscoveryInventory().candidates(
        "cloudtrail_dir", root, "*.json*", _directory_skips=observed,
    ) == []
    assert list(observed) == [("cloudtrail_dir", nested.resolve())]


# ── the loader seam (P1) ────────────────────────────────────────────────────


def _syslog_population(inventory: DiscoveryInventory, path: Path) -> dict:
    return inventory.populations({"*.log*": "syslog_dir"}, {"syslog_dir": [path]})


def test_population_for_another_source_is_refused(tmp_path: Path) -> None:
    flat = tmp_path / "flat"
    _write(flat / "messages", _syslog_lines(20))
    inventory = DiscoveryInventory()
    population = _syslog_population(inventory, flat)["*.log*"]
    with pytest.raises(ValueError, match="belong to 'syslog_dir', not 'journal'"):
        load_required_logs(
            {"*.log*": "journal"}, {"journal": [flat]},
            discovered_candidates={"*.log*": population},
        )
    empty = CandidatePopulation("pihole_dir", ())
    with pytest.raises(ValueError, match="belong to 'pihole_dir'"):
        load_required_logs(
            {"*.log*": "syslog_dir"}, {"syslog_dir": []},
            discovered_candidates={"*.log*": empty},
        )
    with pytest.raises(ValueError, match="do not match the run's syslog_dir inputs"):
        load_required_logs(
            {"*.log*": "syslog_dir"}, {"syslog_dir": [flat, tmp_path]},
            discovered_candidates={"*.log*": population},
        )
    with pytest.raises(ValueError, match="not observed by the inventory"):
        inventory.observe("journal", flat)


def test_a_supplied_empty_population_is_authoritative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    flat = tmp_path / "flat"
    flat.mkdir()
    inventory = DiscoveryInventory()
    populations = _syslog_population(inventory, flat)
    _write(flat / "messages", _syslog_lines(20))

    def _refuse(*_args, **_kwargs):
        raise AssertionError("an authoritative population must not be rediscovered")

    monkeypatch.setitem(
        _SOURCE_LOADERS, "syslog_dir",
        replace(_SOURCE_LOADERS["syslog_dir"], discover=_refuse),
    )
    result = load_required_logs(
        {"*.log*": "syslog_dir"}, {"syslog_dir": [flat]},
        show_progress=False, discovered_candidates=populations,
    )
    assert result.record_counts == {}


@pytest.mark.parametrize("layout", ["dated", "sparse", "flat", "mixed", "syslog"])
def test_window_resolution_reads_observations_with_unchanged_arithmetic(
    tmp_path: Path, layout: str,
) -> None:
    if layout in ("dated", "mixed"):
        dirs = [_dated_zeek(tmp_path / "dated", days=12)]
    elif layout == "sparse":
        dirs = [tmp_path / "sparse"]
        for d in (0, 9):
            day = _BASE + timedelta(days=d)
            _write(dirs[0] / day.strftime("%Y-%m-%d") / "conn.log", _conn_rows(day))
    else:
        dirs = []
    if layout in ("flat", "mixed"):
        flat = tmp_path / "flat"
        _write(flat / "conn.log", _conn_rows(_BASE + timedelta(days=11)))
        dirs.append(flat)
    needed = {"conn*.log*": "zeek_dir"}
    source = "zeek_dir"
    if layout == "syslog":
        syslog = tmp_path / "syslog"
        _write(syslog / "messages", _syslog_lines(20))
        _write(syslog / "messages.1", _syslog_lines(10))
        dirs = [syslog]
        needed = {"*.log*": "syslog_dir"}
        source = "syslog_dir"
    source_dirs = {source: dirs}
    legacy = resolve_load_windows(needed, source_dirs, "7d", since=None, until=None, load_all=False)
    inventory = DiscoveryInventory()
    observed = resolve_load_windows(
        needed, source_dirs, "7d", since=None, until=None, load_all=False,
        _discovery=inventory.populations(needed, source_dirs),
    )
    assert observed == legacy


# ── planning observes every selected input before reducing ──────────────────


def _module(name: str, required=(), optional=(), one_of: bool = False):
    return SimpleNamespace(
        DETECTOR_NAME=name, STATUS="available", REQUIRED_LOGS=list(required),
        OPTIONAL_LOGS=list(optional), REQUIRES_ONE_OF_OPTIONAL=one_of,
        DEFAULT_CONFIG={}, run=lambda _ctx: [],
    )


def _deny_iterdir(monkeypatch: pytest.MonkeyPatch, denied: Path) -> None:
    real_iterdir = Path.iterdir

    def _deny(path: Path):
        if path == denied:
            raise PermissionError(13, "synthetic denied")
        return real_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", _deny)


def test_a_later_denied_input_survives_an_earlier_failed_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    denied = tmp_path / "denied"
    denied.mkdir()
    _deny_iterdir(monkeypatch, denied)
    mod = _module("pair", required=[
        {"source": "zeek_dir", "pattern": "conn*.log*"},
        {"source": "syslog_dir", "pattern": "*.log*"},
    ])
    legacy = runner.build_run_plan(
        "pair", zeek_dir=zeek, syslog_dir=denied, detectors={"pair": mod},
    )
    assert legacy.directory_skips == {}
    plan = runner.build_run_plan(
        "pair", zeek_dir=zeek, syslog_dir=denied, detectors={"pair": mod},
        inventory=DiscoveryInventory(),
    )
    assert plan.skipped == legacy.skipped
    assert list(plan.directory_skips) == [("syslog_dir", denied.resolve())]


def test_an_optional_alternative_cannot_hide_a_later_omission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    flat = tmp_path / "flat"
    _write(flat / "messages", _syslog_lines(20))
    denied = tmp_path / "zeek-denied"
    denied.mkdir()
    _deny_iterdir(monkeypatch, denied)
    mod = _module("either", optional=[
        {"source": "syslog_dir", "pattern": "*.log*"},
        {"source": "zeek_dir", "pattern": "syslog*.log*"},
    ], one_of=True)
    plan = runner.build_run_plan(
        "either", zeek_dir=denied, syslog_dir=flat, detectors={"either": mod},
        inventory=DiscoveryInventory(),
    )
    assert plan.will_run == ["either"]
    assert list(plan.directory_skips) == [("zeek_dir", denied.resolve())]


# ── one observation per input across a whole run ────────────────────────────


def _count_observations(monkeypatch: pytest.MonkeyPatch, source: str) -> list[Path]:
    calls: list[Path] = []
    strategy = _SOURCE_LOADERS[source]
    real_observe = strategy.observe

    def _observe(path: Path):
        calls.append(path)
        return real_observe(path)

    def _refuse(*_args, **_kwargs):
        raise AssertionError("an inventory run must not rediscover")

    monkeypatch.setitem(
        _SOURCE_LOADERS, source, replace(strategy, observe=_observe, discover=_refuse),
    )
    return calls


def _run(argv: list[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> int:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    return cli._main(argv)


def test_each_input_is_observed_once_across_plan_windows_and_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    zeek = _dated_zeek(tmp_path / "zeek", days=10)
    calls = _count_observations(monkeypatch, "zeek_dir")
    config = _isolated_config(tmp_path)
    out = tmp_path / "out.json"
    assert _run([
        "hunt", str(zeek), f"--config={config}", "--detect=beacon,scan,exfil,dns,ssl",
        "-q", "--format=json", f"--out={out}",
    ], monkeypatch, tmp_path) == 0
    assert calls == [zeek]
    summary = json.loads(out.read_text(encoding="utf-8"))["run_summary"]
    assert summary["record_counts"]["conn*.log*"] > 0


def test_a_journal_win_never_observes_the_configured_flat_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    flat = tmp_path / "flat"
    _write(flat / "messages", "Jun  6 12:00:00 host.example sshd[2]: flat-only marker\n")
    script = tmp_path / "journalctl"
    record = {"__REALTIME_TIMESTAMP": "1760000000000000", "MESSAGE": "journal marker",
              "_HOSTNAME": "host.example", "SYSLOG_IDENTIFIER": "sshd", "_PID": "1"}
    script.write_text(
        f"#!{sys.executable}\nimport json\nprint(json.dumps({record!r}))\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: str(script))
    calls = _count_observations(monkeypatch, "syslog_dir")
    config = tmp_path / "config.toml"
    config.write_text(
        f'[sigwood]\nroot = ""\ndetect = "syslog"\nsyslog_dir = "{flat}"\n'
        'syslog_source = "auto"\nzeek_dir = ""\n',
        encoding="utf-8",
    )
    out = tmp_path / "out.json"
    assert _run(["syslog", f"--config={config}", "--all", "-q", "--format=json",
                 f"--out={out}"], monkeypatch, tmp_path) == 0
    assert calls == []
    summary = json.loads(out.read_text(encoding="utf-8"))["run_summary"]
    assert summary["data_sources"] == ["syslog_journal"]
    assert "flat-only marker" not in out.read_text(encoding="utf-8")


@pytest.mark.parametrize("case", ["dated", "flat_syslog", "pihole", "cloudtrail", "mixed"])
def test_inventory_run_matches_the_legacy_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str,
) -> None:
    """The inventory path and a context-free programmatic run agree exactly."""
    if case == "dated":
        family, paths, detect = "zeek_dir", [_dated_zeek(tmp_path / "z", days=10)], "beacon,dns"
    elif case == "flat_syslog":
        flat = tmp_path / "s"
        _write(flat / "messages", _syslog_lines(20))
        _write(flat / "messages.1", _syslog_lines(12))
        _write(flat / "messages.2.gz", _syslog_lines(3), gz=True)
        family, paths, detect = "syslog_dir", [flat], "syslog"
    elif case == "pihole":
        ph = tmp_path / "p"
        _write(ph / "pihole.log", _dnsmasq_lines(14))
        _write(ph / "pihole.log.1", _dnsmasq_lines(8))
        family, paths, detect = "pihole_dir", [ph], "dns"
    elif case == "cloudtrail":
        family, paths, detect = "cloudtrail_dir", [_cloudtrail_tree(tmp_path / "ct")], "aws"
    else:
        flat = tmp_path / "zf"
        _write(flat / "conn.log", _conn_rows(_BASE + timedelta(days=9)))
        family, paths = "zeek_dir", [_dated_zeek(tmp_path / "z", days=10), flat]
        detect = "beacon"
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    config = {"sigwood": {"root": "", "syslog_source": "files", "zeek_dir": "",
                          "syslog_dir": ""}}
    raw = [str(p) for p in paths]

    def _payload(with_discovery: bool) -> dict:
        _buckets, _votes, built = prepare_analyze_discovery(
            [], detector_module=None, overrides={family: raw},
        )
        out = tmp_path / f"run-{with_discovery}.json"
        assert runner.run(
            config=config, detect=detect, output_format="json", output_file=out,
            quiet=True, discovery=built if with_discovery else None,
            **{family: raw},
        ) == 0
        payload = json.loads(out.read_text(encoding="utf-8"))
        payload["run_summary"].pop("generated_at")
        for finding in payload["findings"]:
            finding.pop("ts_generated", None)
        return payload

    legacy = _payload(False)
    observed = _payload(True)
    legacy_notes = legacy["run_summary"].pop("notes")
    observed_notes = observed["run_summary"].pop("notes")
    assert observed == legacy
    assert legacy["run_summary"]["record_counts"]
    # Nothing is withdrawn; only coverage facts are added.
    assert [n for n in legacy_notes if n not in observed_notes] == []
    added = [n for n in observed_notes if n not in legacy_notes]
    if case == "cloudtrail":
        assert len(added) == 1 and "did not follow 1 linked subdirectory" in added[0]
    else:
        assert added == []


# ── coverage disclosure ─────────────────────────────────────────────────────


def _services(root: Path) -> Path:
    _write(root / "svcA" / "messages", _syslog_lines(20, host="svca"))
    _write(root / "svcB" / "messages", _syslog_lines(20, host="svcb"))
    return root


@pytest.mark.parametrize("verb", [[], ["hunt"], ["syslog"]])
def test_nested_services_name_the_unsearched_children_before_any_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, verb: list[str],
) -> None:
    parent = _services(tmp_path / "logs")
    config = _isolated_config(tmp_path)
    assert _run([*verb, str(parent), f"--config={config}", "-q"], monkeypatch, tmp_path) == 1
    err = capsys.readouterr().err.splitlines()
    coverage = [i for i, line in enumerate(err) if "this run did not search" in line]
    skips = [i for i, line in enumerate(err) if "skipping" in line]
    assert len(coverage) == 1 and skips and coverage[0] < min(skips)
    line = err[coverage[0]]
    assert "(svcA, svcB)" in line
    assert "pass a subdirectory or its files directly" in line
    assert "--recursive" not in line
    assert "contain" not in line.split("(")[0]


def test_a_successful_partial_run_saves_the_child_note_in_every_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    root = tmp_path / "root"
    _write(root / "messages", _syslog_lines(20, host="top"))
    _write(root / "child" / "messages", _syslog_lines(20, host="kid"))
    config = _isolated_config(tmp_path)
    expected = "1 subdirectory this run did not search (child)"
    for fmt in ("text", "json", "html"):
        out = tmp_path / f"report.{fmt}"
        assert _run(["syslog", str(root), f"--config={config}", "-q",
                     f"--format={fmt}", f"--out={out}"], monkeypatch, tmp_path) == 0
        assert expected in capsys.readouterr().err
        assert expected in out.read_text(encoding="utf-8")


def test_empty_unsupported_missing_and_unreadable_inputs_are_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    unsupported = tmp_path / "unsupported"
    _write(unsupported / "README.txt", "nothing here\n")
    good = tmp_path / "good"
    _write(good / "messages", _syslog_lines(20))
    config = _isolated_config(tmp_path)
    assert _run(["syslog", str(empty), f"--config={config}", "-q"], monkeypatch, tmp_path) == 1
    assert f"syslog: {empty} is empty - nothing to read there" in capsys.readouterr().err
    assert _run(["syslog", str(unsupported), f"--config={config}", "-q"],
                monkeypatch, tmp_path) == 1
    assert (f"syslog: {unsupported} holds 1 file, none recognized as syslog logs"
            in capsys.readouterr().err)
    missing = tmp_path / "missing"
    assert _run(["syslog", str(good), f"--syslog-dir={missing}", f"--config={config}",
                 "-q"], monkeypatch, tmp_path) == 0
    assert (f"syslog: {missing} was not found - its contents are absent from this run"
            in capsys.readouterr().err)


def test_a_healthy_configured_child_is_qualified_never_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    """Being another input proves nothing about the subtree beneath it.

    The configured Zeek child is healthy, so its own child note is suppressed;
    the parent's line must still list it rather than assume it was covered.
    """
    parent = tmp_path / "logs"
    _write(parent / "messages", _syslog_lines(20, host="top"))
    zeek = parent / "zeek"
    _write(zeek / "conn.log", _conn_rows(_BASE))
    _write(zeek / "old" / "conn.log", _conn_rows(_BASE))
    (parent / "other").mkdir()
    config = _isolated_config(tmp_path, zeek_dir=str(zeek), detect="syslog,beacon")
    assert _run(["hunt", f"--syslog-dir={parent}", f"--config={config}", "-q"],
                monkeypatch, tmp_path) == 0
    lines = [x for x in capsys.readouterr().err.splitlines() if "did not search" in x]
    assert lines == [
        f"syslog: {parent} has 2 subdirectories this run did not search "
        "(other, zeek; 1 is also an input of this run) - pass a subdirectory or "
        "its files directly to include them",
    ]


def test_a_selected_child_with_unread_grandchildren_stays_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    parent = tmp_path / "logs"
    child = parent / "child"
    _write(child / "messages", _syslog_lines(20))
    _write(child / "grand" / "messages", _syslog_lines(20))
    config = _isolated_config(tmp_path)
    assert _run(["syslog", str(parent), str(child), f"--config={config}", "-q"],
                monkeypatch, tmp_path) == 0
    err = capsys.readouterr().err
    assert (f"syslog: {parent} has 1 subdirectory this run did not search "
            "(child; 1 is also an input of this run)") in err
    assert f"syslog: {child} has 1 subdirectory this run did not search (grand)" in err


def test_a_healthy_configured_root_gets_no_routine_child_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    root = tmp_path / "var-log"
    _write(root / "messages", _syslog_lines(20))
    (root / "apt").mkdir()
    (root / "journal").mkdir()
    config = _isolated_config(tmp_path, syslog_dir=str(root), detect="syslog")
    assert _run(["hunt", f"--config={config}", "-q"], monkeypatch, tmp_path) == 0
    assert "did not search" not in capsys.readouterr().err
    (root / "messages").unlink()
    _write(root / "notes.txt", "not syslog\n")
    assert _run(["hunt", f"--config={config}", "-q"], monkeypatch, tmp_path) == 1
    assert (f"syslog: {root} has 2 subdirectories this run did not search (apt, journal)"
            in capsys.readouterr().err)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_existing_owners_keep_their_facts_without_a_second_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    good = tmp_path / "good"
    _write(good / "messages", _syslog_lines(20))
    denied_dir = tmp_path / "denied-dir"
    denied_dir.mkdir()
    denied_file_dir = tmp_path / "denied-file"
    locked = _write(denied_file_dir / "messages", _syslog_lines(20))
    nothing = tmp_path / "nothing"
    _write(nothing / "notes.txt", "not syslog\n")
    config = _isolated_config(tmp_path)
    os.chmod(denied_dir, 0o000)
    os.chmod(locked, 0o000)
    try:
        out = tmp_path / "out.json"
        assert _run(["syslog", str(good), str(denied_dir), str(denied_file_dir),
                     f"--config={config}", "-q", "--format=json", f"--out={out}"],
                    monkeypatch, tmp_path) == 0
    finally:
        os.chmod(denied_dir, 0o755)
        os.chmod(locked, 0o644)
    err = capsys.readouterr().err
    notes = json.loads(out.read_text(encoding="utf-8"))["run_summary"]["notes"]
    lines = [*err.splitlines(), *notes]
    # The directory denial: its own owner's note, exactly once, nowhere else.
    denial = [line for line in lines if str(denied_dir) in line and "system logs:" not in line]
    assert denial == [next(n for n in notes if "could not be listed" in n)]
    # The file denial: the loader's permission accounting, once in each surface.
    assert sum("permission denied - owned" in line for line in err.splitlines()) == 1
    assert sum("discovered files permission denied" in n for n in notes) == 1
    assert not any(str(denied_file_dir) in line and "did not search" in line for line in lines)
    # Nothing that looks like syslog, on a run that never loads: the new fact.
    assert _run(["syslog", str(nothing), f"--config={config}", "-q"],
                monkeypatch, tmp_path) == 1
    err = capsys.readouterr().err
    assert err.count("none recognized as syslog logs") == 1
    assert "looks like syslog" not in err


def test_a_loaded_flat_family_leaves_unsupported_content_to_the_loader_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    """When the pattern loads, the loader's silent-miss warning owns the fact."""
    nothing = tmp_path / "nothing"
    _write(nothing / "notes.txt", "not syslog\n")
    named = _write(tmp_path / "named" / "messages", _syslog_lines(20))
    config = _isolated_config(tmp_path)
    assert _run(["syslog", str(named), str(nothing), f"--config={config}", "-q"],
                monkeypatch, tmp_path) == 0
    err = capsys.readouterr().err
    assert f"syslog_dir: nothing in {nothing} looks like syslog" in err
    assert "none recognized as syslog logs" not in err


def test_coverage_lines_neutralize_hostile_child_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    parent = tmp_path / "logs"
    _write(parent / "messages", _syslog_lines(20))
    hostile = [f"a{_ESC}[31mred", f"b{_CSI}2J", "c\nforged: line", "<script>x<",
               "q'\"uote", "L" * 200]
    for name in hostile:
        (parent / name).mkdir()
    config = _isolated_config(tmp_path)
    outputs = {}
    for fmt in ("text", "json", "html"):
        out = tmp_path / f"r.{fmt}"
        assert _run(["syslog", str(parent), f"--config={config}", "-q",
                     f"--format={fmt}", f"--out={out}"], monkeypatch, tmp_path) == 0
        outputs[fmt] = out.read_text(encoding="utf-8")
        err = capsys.readouterr().err
        line = next(x for x in err.splitlines() if "did not search" in x)
        assert _ESC not in err and _CSI not in err
        assert "6 subdirectories" in line and "(+3 more)" in line
        assert len(line) < 1200
    assert _ESC not in outputs["text"] and _CSI not in outputs["text"]
    assert "forged: line" not in outputs["text"].split("did not search")[0][-200:]
    assert "<script>" not in outputs["html"]
    notes = json.loads(outputs["json"])["run_summary"]["notes"]
    assert any("did not search" in n for n in notes)


def test_a_positional_scope_is_never_widened_by_empty_routing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = {}
    real = cli._build_positional_buckets

    def _empty(paths, **kwargs):
        _buckets, discovery = real(paths, **kwargs)
        return {}, discovery

    def _capture(**kwargs):
        seen.update(kwargs)
        return 1

    monkeypatch.setattr(cli, "_build_positional_buckets", _empty)
    monkeypatch.setattr(runner, "run", _capture)
    target = tmp_path / "x"
    target.mkdir()
    config = _isolated_config(tmp_path)
    _run([str(target), f"--config={config}"], monkeypatch, tmp_path)
    assert seen["scope"] == frozenset()


# ── graph inherits the regular-file Pi-hole rule on its real route ──────────


def test_graph_pihole_route_skips_nonregular_matches_and_still_renders(tmp_path: Path) -> None:
    pihole = tmp_path / "pihole"
    _write(pihole / "pihole.log", _dnsmasq_lines(14, n=8))
    (pihole / "pihole.log.d").mkdir()
    os.mkfifo(pihole / "pihole.log.fifo")
    out = tmp_path / "graph.html"
    env = dict(os.environ, HOME=str(tmp_path / "home"), TZ="UTC")
    env.pop("SIGWOOD_ROOT", None)
    proc = subprocess.run(
        [sys.executable, "-m", "sigwood", "graph", f"--pihole-dir={pihole}",
         f"--out={out}", "-q"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.read_text(encoding="utf-8").startswith("<!")


def test_graph_keeps_a_zeek_listing_failure_operational(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    zeek = tmp_path / "zeek"
    _write(zeek / "conn.log", _conn_rows(_BASE))
    real_iterdir = Path.iterdir

    def _fail(path: Path):
        if path == zeek:
            raise OSError(5, "synthetic I/O failure")
        return real_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", _fail)
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["graph", f"--zeek-dir={zeek}", f"--out={tmp_path / 'g.html'}", "-q"])
    assert exit_info.value.code == 1
    assert "sigwood:" in capsys.readouterr().err
    assert not (tmp_path / "g.html").exists()


def test_a_dry_run_observes_but_never_loads_captures_or_runs_a_detector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    parent = _services(tmp_path / "logs")

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("a dry run must not load, capture or analyze")

    monkeypatch.setattr(loader, "load_required_logs", _forbidden)
    monkeypatch.setattr(loader, "prepare_journal_capture", _forbidden)
    monkeypatch.setattr(runner, "_prepare_detector_context", _forbidden)
    config = _isolated_config(tmp_path)
    assert _run(["syslog", str(parent), "--dry-run", f"--config={config}"],
                monkeypatch, tmp_path) == 0
    captured = capsys.readouterr()
    assert "this run did not search (svcA, svcB)" in captured.err
    assert "dry run" in captured.out


def test_a_missing_second_zeek_input_is_disclosed_not_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    """The inventory path discloses what the legacy loader raised on."""
    zeek = _dated_zeek(tmp_path / "zeek", days=3)
    missing = tmp_path / "missing"
    config = _isolated_config(tmp_path)
    with pytest.raises(FileNotFoundError):
        discover_zeek_files(missing, "conn*.log*")
    assert _run(["beacon", str(zeek), f"--zeek-dir={missing}", f"--config={config}",
                 "-q"], monkeypatch, tmp_path) == 0
    assert (f"Zeek: {missing} was not found - its contents are absent from this run"
            in capsys.readouterr().err)


def test_a_denied_zeek_date_child_reaches_the_listing_denial_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    zeek = _dated_zeek(tmp_path / "zeek", days=3)
    day = zeek / _BASE.strftime("%Y-%m-%d")
    _deny_iterdir(monkeypatch, day)
    out = tmp_path / "out.json"
    config = _isolated_config(tmp_path)
    assert _run(["beacon", str(zeek), f"--config={config}", "-q", "--all",
                 "--format=json", f"--out={out}"], monkeypatch, tmp_path) == 0
    notes = json.loads(out.read_text(encoding="utf-8"))["run_summary"]["notes"]
    denial = [n for n in notes if "could not be listed" in n]
    assert len(denial) == 1 and day.name in denial[0]


# ── entry inspection failures keep their cause ──────────────────────────────


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_a_link_to_an_uninspectable_target_is_an_entry_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    """EACCES on a link's target is not a dangling link, and it is disclosed."""
    protected = tmp_path / "protected"
    target = _write(protected / "auth.log", _syslog_lines(20))
    inputs = tmp_path / "input"
    _write(inputs / "messages", _syslog_lines(20))
    link = inputs / "auth.log"
    link.symlink_to(target)
    dangling = inputs / "gone.log"
    dangling.symlink_to(tmp_path / "absent")
    config = _isolated_config(tmp_path)
    out = tmp_path / "out.json"
    protected.chmod(0)
    try:
        assert disc._classify_entry(link).kind is EntryKind.ERROR
        assert disc._classify_entry(link).error == "EACCES"
        assert _run(["syslog", str(inputs), f"--config={config}", "-q", "--format=json",
                     f"--out={out}"], monkeypatch, tmp_path) == 0
    finally:
        protected.chmod(0o700)
    assert disc._classify_entry(dangling).kind is EntryKind.BROKEN_LINK
    expected = (f"syslog: 1 entry under {inputs} could not be inspected (EACCES) - "
                "not read (auth.log)")
    assert expected in capsys.readouterr().err
    notes = json.loads(out.read_text(encoding="utf-8"))["run_summary"]["notes"]
    assert expected in notes
    assert not any("gone.log" in n or "broken" in n for n in notes)


def _fail_stat(monkeypatch: pytest.MonkeyPatch, target: Path, code: int) -> None:
    real_stat = os.stat

    def _stat(path, *args, **kwargs):
        if Path(path) == target:
            raise OSError(code, "synthetic inspection failure")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(disc.os, "stat", _stat)


def test_an_unknown_type_cloudtrail_entry_is_counted_before_the_filename_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _cloudtrail_tree(tmp_path / "ct")
    account = root / "AWSLogs" / "account"
    account.mkdir()
    _fail_stat(monkeypatch, account, 5)
    obs = disc.observe_cloudtrail_input(root)
    errors = [f for f in obs.facts if f.kind is loader.DiscoveryFactKind.ENTRY_ERROR]
    assert [(f.paths, f.detail) for f in errors] == [((account,), "EIO")]
    assert discover_cloudtrail_files(root) == list(obs.accepted) and obs.accepted


def test_an_unknown_type_dated_zeek_root_entry_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    zeek = _dated_zeek(tmp_path / "zeek", days=3)
    odd = zeek / "2026-09-30"
    odd.mkdir()
    _fail_stat(monkeypatch, odd, 5)
    inventory = DiscoveryInventory()
    facts = inventory.input_facts("zeek_dir", zeek, ["conn*.log*"], invocation=True)
    assert [(f.kind, f.paths, f.detail) for f in facts] == [
        (loader.DiscoveryFactKind.ENTRY_ERROR, (odd,), "EIO"),
    ]


# ── denials reach the operator when no report renders ───────────────────────


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_a_denied_date_child_is_named_on_an_all_skipped_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    root = tmp_path / "zeek"
    day = root / "2026-10-15"
    _write(day / "conn.log", _conn_rows(_BASE))
    config = _isolated_config(tmp_path)
    day.chmod(0)
    try:
        assert _run(["beacon", f"--zeek-dir={root}", f"--config={config}", "-q",
                     "--format=json", "--out=-"], monkeypatch, tmp_path) == 1
        assert _run(["beacon", f"--zeek-dir={root}", f"--config={config}", "--dry-run"],
                    monkeypatch, tmp_path) == 0
    finally:
        day.chmod(0o755)
    captured = capsys.readouterr()
    lines = captured.err.splitlines()
    denial = (f"Zeek: directory could not be listed (permission denied) - its "
              f"contents are absent from this run ({day})")
    assert lines.count(denial) == 2
    assert lines.index(denial) < lines.index(
        "no detectors could run - check required log source paths in config or CLI overrides"
    )
    assert '"findings"' not in captured.out


def test_a_skip_reason_keeps_the_root_denial_it_already_states(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    root = tmp_path / "zeek"
    root.mkdir()
    _deny_iterdir(monkeypatch, root)
    config = _isolated_config(tmp_path)
    assert _run(["beacon", f"--zeek-dir={root}", f"--config={config}", "-q"],
                monkeypatch, tmp_path) == 1
    err = capsys.readouterr().err
    assert err.count(str(root)) == 1
    assert "zeek_dir directory could not be listed (permission denied)" in err


def test_a_later_denial_behind_an_earlier_failed_requirement_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    denied = tmp_path / "denied"
    denied.mkdir()
    _deny_iterdir(monkeypatch, denied)
    mod = _module("pair", required=[
        {"source": "zeek_dir", "pattern": "conn*.log*"},
        {"source": "syslog_dir", "pattern": "*.log*"},
    ])
    monkeypatch.setattr(
        runner, "select_detectors",
        lambda spec, detectors=None: runner.DetectorSelection(
            detectors={"pair": mod}, selected=["pair"], import_failures={},
        ),
    )
    config = _isolated_config(tmp_path, detect="pair")
    assert _run(["hunt", f"--zeek-dir={zeek}", f"--syslog-dir={denied}",
                 f"--config={config}", "-q"], monkeypatch, tmp_path) == 1
    lines = capsys.readouterr().err.splitlines()
    denial = (f"syslog: directory could not be listed (permission denied) - its "
              f"contents are absent from this run ({denied})")
    assert lines.count(denial) == 1
    assert any(line.startswith("conn*.log* not found") for line in lines)


# ── family policy stays with the loader ─────────────────────────────────────


def test_the_runner_composer_names_no_source_family() -> None:
    """Selection and its omissions are decided by the loader-owned strategies."""
    import inspect

    composer = [
        runner._discovery_coverage_lines,
        runner._qualify_unsearched,
        runner._render_coverage_fact,
        runner._merge_facts,
        runner._denial_owned_keys,
        runner._unowned_directory_skip_lines,
    ]
    for function in composer:
        source = inspect.getsource(function)
        for key in ("zeek_dir", "syslog_dir", "pihole_dir", "cloudtrail_dir", "journal"):
            assert f'"{key}"' not in source, (function.__name__, key)
    for name in ("_SHALLOW_SOURCES", "_name_gate_match", "_entry_facts"):
        assert not hasattr(runner, name)
