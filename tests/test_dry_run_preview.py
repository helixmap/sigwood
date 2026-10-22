"""The dry-run preview: the run's own selection, stated without loading.

A dry run selects each family's files with the load's own per-pattern selector
and the run's own window plan. These tests drive the real CLI against hermetic
fixtures and pin that the files a preview reports as selected are the files the
run reads, that each family states the policy the window resolver chose, and
that a preview never reaches parsing, content hashing, snapshot capture,
journal capture, detectors or reports.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sigwood.cli as cli
import sigwood.common.loader as loader
import sigwood.runner as runner
from sigwood.common.journal_probe import JournalProbeCode, JournalProbeResult
from sigwood.common.loader import PatternPreview, WindowPolicyReason

_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
_DAY = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


# ── fixture builders (RFC 5737 addresses, reserved names only) ───────────────


def _stamp(days_ago: float, minute: int = 0) -> str:
    """An RFC 3164 stamp from the runtime clock: the format has no year."""
    moment = datetime.now() - timedelta(days=days_ago) + timedelta(minutes=minute)
    return f"{_MONTHS[moment.month - 1]} {moment.day:2d} {moment:%H:%M:%S}"


def _syslog(days_ago: float, host: str = "host-a", n: int = 3) -> str:
    return "".join(
        f"{_stamp(days_ago, i)} {host} sshd[{100 + i}]: Accepted publickey for "
        f"alice from 192.0.2.{i + 1} port 22 ssh2\n"
        for i in range(n)
    )


def _dnsmasq(days_ago: float, n: int = 3) -> str:
    return "".join(
        f"{_stamp(days_ago, i)} dnsmasq[811]: query[A] h{i}.example.com "
        f"from 192.0.2.{10 + i}\n"
        for i in range(n)
    )


def _conn_rows(day: datetime, n: int = 4) -> str:
    return "".join(json.dumps({
        "_path": "conn", "ts": (day + timedelta(minutes=i)).timestamp(),
        "uid": f"C{int(day.timestamp())}{i}", "id.orig_h": "192.0.2.10",
        "id.orig_p": 40000 + i, "id.resp_h": "198.51.100.20", "id.resp_p": 443,
        "proto": "tcp", "conn_state": "SF", "duration": 1.5,
        "orig_bytes": 100, "resp_bytes": 900, "local_orig": True,
    }) + "\n" for i in range(n))


def _ct_record(event_id: str, ts: str) -> dict:
    return {
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/alice",
                         "accountId": "123456789012", "userName": "alice"},
        "eventTime": ts, "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
        "awsRegion": "us-east-1", "sourceIPAddress": "192.0.2.50", "eventID": event_id,
        "readOnly": True, "eventType": "AwsApiCall", "recipientAccountId": "123456789012",
    }


def _write(path: Path, text: str, *, gz: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def _rotations(root: Path, ages: tuple[float, ...] = (1, 9, 20, 40)) -> Path:
    """A flat syslog rotation set, newest first."""
    names = ["messages", "messages.1", "messages.2.gz", "messages.3.gz"]
    for name, age in zip(names, ages):
        _write(root / name, _syslog(age), gz=name.endswith(".gz"))
    return root


def _pihole(root: Path, count: int = 6, step: int = 8) -> Path:
    """A Pi-hole rotation set spanning ``count * step`` days."""
    for i in range(count):
        name = "pihole.log" if i == 0 else f"pihole.log.{i}"
        _write(root / (name + (".gz" if i > 1 else "")), _dnsmasq(1 + i * step), gz=i > 1)
    return root


def _dated(root: Path, days: int = 10, *, current: Path | None = None) -> Path:
    for d in range(days):
        day = _DAY + timedelta(days=d)
        _write(root / day.strftime("%Y-%m-%d") / "conn.log", _conn_rows(day))
    if current is not None:
        (root / "current").symlink_to(current, target_is_directory=True)
    return root


def _cloudtrail(root: Path) -> Path:
    day = root / "AWSLogs" / "123456789012" / "CloudTrail" / "us-east-1" / "2026" / "10" / "15"
    for i in range(2):
        _write(day / f"part{i}.json", json.dumps(
            {"Records": [_ct_record(f"e{i}", f"2026-10-15T1{i}:00:00Z")]},
        ))
    return root


def _config(tmp_path: Path, **sigwood: str) -> Path:
    values = {
        "root": "", "zeek_dir": "", "syslog_dir": "", "pihole_dir": "",
        "cloudtrail_dir": "", "syslog_source": "files",
    }
    values.update(sigwood)
    lines = ["[sigwood]", *(f'{key} = "{value}"' for key, value in values.items())]
    path = tmp_path / f"config-{len(list(tmp_path.glob('config-*.toml')))}.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class _Cli:
    """Run the real CLI, with the preview and the load's selection observed."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        self.tmp_path = tmp_path
        self.monkeypatch = monkeypatch
        self.capsys = capsys
        self.config = _config(tmp_path)
        self.previews: list = []
        self.windows: list = []
        self.loaded: list[list[Path]] = []
        real_preview = runner._dry_run_preview
        real_windows = runner._resolve_run_windows
        real_validate = loader.pipeline.validate_selected_files

        def spy_preview(*args, **kwargs):
            self.previews.append(real_preview(*args, **kwargs))
            return self.previews[-1]

        def spy_windows(*args, **kwargs):
            self.windows.append(real_windows(*args, **kwargs))
            return self.windows[-1]

        def spy_validate(files, *args, **kwargs):
            self.loaded.append(list(files))
            return real_validate(files, *args, **kwargs)

        monkeypatch.setattr(runner, "_dry_run_preview", spy_preview)
        monkeypatch.setattr(runner, "_resolve_run_windows", spy_windows)
        monkeypatch.setattr(loader.pipeline, "validate_selected_files", spy_validate)
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.delenv("SIGWOOD_ROOT", raising=False)

    def dry(self, *argv: str, config: Path | None = None) -> tuple[int, str, str]:
        rc = cli._main([*argv, f"--config={config or self.config}", "--dry-run"])
        captured = self.capsys.readouterr()
        return rc, captured.out, captured.err

    def run(self, *argv: str, config: Path | None = None) -> tuple[int, dict, str]:
        out = self.tmp_path / f"run{len(self.loaded)}-{len(self.previews)}.json"
        rc = cli._main([
            *argv, f"--config={config or self.config}", "-q", "--format=json",
            f"--out={out}",
        ])
        err = self.capsys.readouterr().err
        summary = json.loads(out.read_text())["run_summary"] if out.exists() else {}
        return rc, summary, err


@pytest.fixture
def sw(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> _Cli:
    return _Cli(tmp_path, monkeypatch, capsys)


def _rows(out: str, label: str) -> list[str]:
    """Every banner value under ``label``, family sub-rows included."""
    return [
        line.strip()[len(label):].strip()
        for line in out.splitlines()
        if line.strip().startswith(label)
    ]


def _reals(paths) -> list[Path]:
    return sorted(Path(p).resolve() for p in paths)


def _days_ago(days: int) -> str:
    return (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")


# ── the shipped label defect, and the per-family policy that replaces it ────


@pytest.mark.parametrize("recursive", [False, True])
def test_an_unqualified_dry_run_states_the_configured_default(sw, tmp_path, recursive):
    """A default-window run never says it reads all available data.

    The run itself applies the 7d default, so the window row says the default
    is configured and each family states what the resolver did with it.
    """
    logs = _rotations(tmp_path / "logs" / ("host-a" if recursive else ""))
    target = tmp_path / "logs"
    rc, out, _ = sw.dry("syslog", str(target), *(["--recursive"] if recursive else []))
    assert rc == 0
    assert "all available data" not in out
    assert _rows(out, "window:") == [
        "7d default configured; each source above states its own policy",
    ]
    assert _rows(out, "policy:") == [
        "default 7d: keeps the last 7d of this source's newest data after loading",
    ]
    assert logs.exists()


@pytest.mark.parametrize("spec", ["", "all"])
def test_a_disabled_default_reads_in_full_under_both_spellings(sw, tmp_path, spec):
    _rotations(tmp_path / "logs")
    config = _config(tmp_path, default_window=spec)
    rc, out, _ = sw.dry("syslog", str(tmp_path / "logs"), config=config)
    assert rc == 0
    assert _rows(out, "window:") == ["all available data (default window disabled)"]
    assert _rows(out, "policy:") == ["full input (default window disabled)"]
    assert sw.windows[-1].policies == {"syslog_dir": WindowPolicyReason.DEFAULT_DISABLED}
    assert sw.windows[-1].load_windows == []


def test_explicit_bounds_and_all_keep_their_own_policies(sw, tmp_path):
    _rotations(tmp_path / "logs")
    rc, out, _ = sw.dry("syslog", str(tmp_path / "logs"), "--all")
    assert rc == 0
    assert _rows(out, "policy:") == ["full input (--all)"]
    assert _rows(out, "window:") == ["all available data (--all)"]
    since, until = _days_ago(15), _days_ago(5)
    rc, out, _ = sw.dry("syslog", str(tmp_path / "logs"), f"--since={since}", f"--until={until}")
    assert rc == 0
    (policy,) = _rows(out, "policy:")
    assert policy.startswith("explicit window: ")
    assert policy.removeprefix("explicit window: ") == _rows(out, "window:")[0]
    assert sw.windows[-1].policies == {"syslog_dir": WindowPolicyReason.EXPLICIT}


def test_named_files_alone_read_in_full_without_claiming_the_default_applied(sw, tmp_path):
    logs = _rotations(tmp_path / "logs")
    rc, out, _ = sw.dry("syslog", str(logs / "messages"), str(logs / "messages.1"))
    assert rc == 0
    assert _rows(out, "policy:") == ["full input (named files only)"]
    # The run-level row says the default is configured, never that it applied.
    assert _rows(out, "window:") == [
        "7d default configured; each source above states its own policy",
    ]
    assert sw.windows[-1].policies == {"syslog_dir": WindowPolicyReason.NAMED_FILES}


def test_a_mixed_file_and_directory_family_takes_the_family_default(sw, tmp_path):
    logs = _rotations(tmp_path / "logs")
    extra = _write(tmp_path / "extra" / "auth.log", _syslog(2))
    rc, out, _ = sw.dry("syslog", str(logs), str(extra))
    assert rc == 0
    assert _rows(out, "policy:") == [
        "default 7d: keeps the last 7d of this source's newest data after loading",
    ]
    # The named file keeps its selection bypass while the family is trimmed.
    (family,) = sw.previews[-1].families.values()
    assert extra.resolve() in _reals(family.selected)


def test_a_named_file_beside_dated_zeek_moves_the_family_to_full_load_and_trim(sw, tmp_path):
    dated = _dated(tmp_path / "zeek")
    named = _write(tmp_path / "loose" / "conn.log", _conn_rows(_DAY + timedelta(days=12)))
    rc, out, _ = sw.dry("beacon", str(dated), str(named))
    assert rc == 0
    assert _rows(out, "policy:") == [
        "default 7d: loads in full, then keeps the last 7d of this source's newest data",
    ]
    (window,) = sw.windows[-1].load_windows
    assert window.select_window is None and window.trim_span == timedelta(days=7)


def test_a_dated_zeek_policy_names_the_resolvers_own_floor(sw, tmp_path):
    dated = _dated(tmp_path / "zeek")
    rc, out, _ = sw.dry("beacon", str(dated))
    assert rc == 0
    (window,) = sw.windows[-1].load_windows
    floor_date = window.select_window[0].astimezone(timezone.utc).date().isoformat()
    (policy,) = _rows(out, "policy:")
    assert policy.startswith(f"default 7d: date directories from {floor_date} onward")
    family = sw.previews[-1].families["zeek_dir"]
    selected_dates = {p.parent.name for p in family.selected}
    assert min(selected_dates) == floor_date
    assert all(p.parent.name < floor_date for p in family.not_selected)


def test_cloudtrail_reads_in_full_as_the_exempt_family(sw, tmp_path):
    _cloudtrail(tmp_path / "ct")
    rc, out, _ = sw.dry("aws", str(tmp_path / "ct"))
    assert rc == 0
    assert _rows(out, "policy:") == ["full input (this source takes no default window)"]
    family = sw.previews[-1].families["cloudtrail_dir"]
    assert family.selected == family.discovered and not family.not_selected


@pytest.mark.parametrize(("extra", "spec", "expected"), [
    ([], "7d", "default 7d: the 7d before the journal's newest entry, set when the journal is read"),
    (["--all"], "7d", "full input (--all)"),
    (["--since=2026-10-01", "--until=2026-10-10"], "7d", "explicit window: "),
    ([], "", "full input (default window disabled)"),
    ([], "all", "full input (default window disabled)"),
])
def test_a_journal_provider_states_its_policy_without_inventing_a_capture(
    sw, tmp_path, monkeypatch, extra, spec, expected,
):
    probes: list[dict] = []
    monkeypatch.setattr(
        runner, "probe_journal",
        lambda **kwargs: probes.append(kwargs) or JournalProbeResult(JournalProbeCode.READY),
    )

    def no_capture(*args, **kwargs):
        raise AssertionError("a dry run captured the journal")

    monkeypatch.setattr(loader, "prepare_journal_capture", no_capture)
    config = _config(tmp_path, syslog_source="journal", default_window=spec)
    rc, out, _ = sw.dry("syslog", *extra, config=config)
    assert rc == 0 and probes
    assert _rows(out, "system logs:") == ["journal (selected; accessible)"]
    (policy,) = _rows(out, "policy:")
    assert policy.startswith(expected)
    assert not _rows(out, "files:")


# ── preview and execution select the same files and bytes ───────────────────


def _parity_case(name: str, tmp_path: Path) -> tuple[list[str], str]:
    """One fixture and the detector arguments that read it."""
    if name == "syslog-rotations":
        return ["syslog", str(_rotations(tmp_path / "logs"))], "syslog_dir"
    if name == "rotation-groups":
        a = _rotations(tmp_path / "a")
        b = _rotations(tmp_path / "b", ages=(3, 12, 30, 50))
        return ["syslog", str(a), str(b)], "syslog_dir"
    if name == "explicit-overlap":
        logs = _rotations(tmp_path / "logs")
        return ["syslog", str(logs), str(logs / "messages.3.gz")], "syslog_dir"
    if name == "dated-zeek":
        return ["beacon", str(_dated(tmp_path / "zeek"))], "zeek_dir"
    if name == "sparse-dated":
        root = tmp_path / "zeek"
        for d in (0, 1, 9, 10, 30):
            day = _DAY + timedelta(days=d)
            _write(root / day.strftime("%Y-%m-%d") / "conn.log", _conn_rows(day))
        return ["beacon", str(root)], "zeek_dir"
    if name in ("spool-before-owner", "spool-after-owner"):
        parent = tmp_path / "archive"
        first, second = ("aa", "zz") if name == "spool-before-owner" else ("zz", "aa")
        spool = _write(
            parent / f"{first}-spool" / "conn.log", _conn_rows(_DAY + timedelta(days=11)),
        ).parent
        _dated(parent / f"{second}-sensor", current=spool)
        return ["beacon", "--recursive", str(parent)], "zeek_dir"
    if name == "flat-contributor":
        parent = tmp_path / "archive"
        _dated(parent / "sensor")
        _write(parent / "flat" / "conn.log", _conn_rows(_DAY + timedelta(days=12)))
        return ["beacon", "--recursive", str(parent)], "zeek_dir"
    if name == "cloudtrail":
        return ["aws", str(_cloudtrail(tmp_path / "ct"))], "cloudtrail_dir"
    if name == "pihole-history":
        return ["dnsblock", str(_pihole(tmp_path / "pihole"))], "pihole_dir"
    raise AssertionError(name)


_PARITY_CASES = [
    "syslog-rotations", "rotation-groups", "explicit-overlap", "dated-zeek",
    "sparse-dated", "spool-before-owner", "spool-after-owner", "flat-contributor",
    "cloudtrail", "pihole-history",
]


@pytest.mark.parametrize("window", ["default", "explicit", "all"])
@pytest.mark.parametrize("case", _PARITY_CASES)
def test_preview_selects_the_files_and_bytes_the_run_reads(sw, tmp_path, case, window):
    argv, source = _parity_case(case, tmp_path)
    flags = {
        "default": [],
        "explicit": [f"--since={_days_ago(60)}", f"--until={_days_ago(-1)}"],
        "all": ["--all"],
    }[window]
    if case.startswith(("dated", "sparse", "spool", "flat")) and window == "explicit":
        flags = ["--since=2026-09-14", "--until=2026-09-22"]
    rc, _, _ = sw.dry(*argv, *flags)
    assert rc == 0
    family = sw.previews[-1].families[source]
    rc, _, _ = sw.run(*argv, *flags)
    assert rc == 0
    executed = [path for batch in sw.loaded for path in batch]
    assert _reals(family.selected) == sorted(set(_reals(executed)))
    assert family.selected_bytes == sum(
        path.stat().st_size for path in {p.resolve() for p in executed}
    )
    assert not family.selected_unsized


def test_the_dnsblock_history_aperture_is_selected_and_stated(sw, tmp_path):
    pihole = _pihole(tmp_path / "pihole")
    rc, out, _ = sw.dry("dns", str(pihole))
    plain = sw.previews[-1].families["pihole_dir"]
    rc2, out2, _ = sw.dry("dnsblock", str(pihole))
    widened = sw.previews[-1].families["pihole_dir"]
    assert rc == rc2 == 0
    assert len(widened.selected) > len(plain.selected)
    (policy,) = _rows(out2, "policy:")
    assert "file selection reaches back to " in policy
    assert policy.endswith("for dnsblock's history")
    assert "reaches back" not in _rows(out, "policy:")[0]


def test_a_dated_tree_counts_only_primary_logs(sw, tmp_path):
    root = tmp_path / "zeek"
    _dated(root, days=2)
    _write(root / "2026-09-10" / "conn-summary.log", "summary\n")
    rc, out, _ = sw.dry("beacon", str(root), "--all")
    assert rc == 0
    family = sw.previews[-1].families["zeek_dir"]
    assert len(family.discovered) == 2
    assert all(p.name == "conn.log" for p in family.discovered)
    (files,) = _rows(out, "files:")
    assert files.startswith("2 discovered (")


# ── inspect-only: no load, hash, snapshot, capture, detector or report ──────


def _forbid(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Make every execution act raise if a preview reaches it."""
    reached: list[str] = []

    def forbidden(name: str):
        def fail(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"a dry run reached {name}")
        return fail

    targets = [
        (loader, "load_required_logs"),
        (loader.pipeline, "load_required_logs"),
        (loader.pipeline, "run_load"),
        (loader.pipeline, "run_folded_source"),
        (loader.pipeline, "validate_selected_files"),
        (loader.provenance, "validate_selected_files"),
        (loader.provenance, "hash_file"),
        (loader.pipeline, "build_source_snapshot"),
        (loader.fold, "build_source_snapshot"),
        (loader, "prepare_journal_capture"),
        (runner, "_prepare_detector_context"),
        (runner, "Reporter"),
    ]
    for module, name in targets:
        monkeypatch.setattr(module, name, forbidden(f"{module.__name__}.{name}"))
    return reached


def _manifest_export(parent: Path) -> Path:
    """A syslog export whose file is bound by a real provenance manifest."""
    from sigwood.common.paths import private_write_bytes
    from sigwood.exporters import (
        _commit_export_provenance,
        _new_stage_directory,
        _validate_staged_write,
    )

    parent.mkdir(parents=True, exist_ok=True)
    payload = _syslog(1).encode("utf-8")
    stage = _new_stage_directory(parent)
    staged_path = stage / "syslog_export.log"
    private_write_bytes(staged_path, payload)
    staged = _validate_staged_write(stage, {"bytes": len(payload), "paths": [staged_path]})
    _commit_export_provenance(
        staged,
        since=datetime.now(timezone.utc) - timedelta(days=2),
        until=datetime.now(timezone.utc),
        backend="splunk",
        request_zone="Etc/UTC",
        tzdata_version=None,
    )
    assert (parent / loader.PROVENANCE_MANIFEST_NAME).is_file()
    return parent


def test_a_dry_run_reaches_no_hash_snapshot_load_detector_or_report(sw, tmp_path, monkeypatch):
    export = _manifest_export(tmp_path / "exports" / "syslog")
    pihole = _pihole(tmp_path / "pihole")
    reached = _forbid(monkeypatch)
    # A manifest-bound export and a folded dnsblock population in one preview.
    rc, out, _ = sw.dry("hunt", "--detect=syslog,dnsblock", str(export), str(pihole))
    assert rc == 0
    assert "dry run - remove --dry-run to analyze" in out
    assert sw.previews[-1].families["pihole_dir"].selected
    assert sw.previews[-1].families["syslog_dir"].selected
    # The journal provider, under the same prohibitions: only the bounded
    # capability probe runs.
    probes: list[dict] = []
    monkeypatch.setattr(
        runner, "probe_journal",
        lambda **kwargs: probes.append(kwargs) or JournalProbeResult(JournalProbeCode.READY),
    )
    rc, out, _ = sw.dry("syslog", config=_config(tmp_path, syslog_source="auto"))
    assert rc == 0 and probes
    assert _rows(out, "system logs:")[0].startswith("journal (auto candidate")
    assert reached == []


@pytest.mark.parametrize(("seam", "argv"), [
    ("pipeline.validate_selected_files", ["syslog", "EXPORT"]),
    ("provenance.hash_file", ["syslog", "EXPORT"]),
    ("pipeline.build_source_snapshot", ["dnsblock", "PIHOLE"]),
])
def test_each_forbidden_seam_is_one_a_real_run_reaches(sw, tmp_path, monkeypatch, seam, argv):
    """The instrumentation sits on the real path: the actual run trips each seam."""
    paths = {
        "EXPORT": str(_manifest_export(tmp_path / "exports" / "syslog")),
        "PIHOLE": str(_pihole(tmp_path / "pihole")),
    }
    module_name, attr = seam.split(".")
    reached: list[str] = []

    def fail(*args, **kwargs):
        reached.append(seam)
        raise AssertionError(f"reached {seam}")

    monkeypatch.setattr(getattr(loader, module_name), attr, fail)
    command = [*(paths.get(a, a) for a in argv), f"--config={sw.config}", "-q",
               "--format=json", f"--out={tmp_path / 'o.json'}"]
    if seam == "pipeline.build_source_snapshot":
        # The nonrecoverable prepared detector contains this as a prep failure.
        assert cli._main(command) == 1
    else:
        with pytest.raises(AssertionError):
            cli._main(command)
    assert reached == [seam]


# ── unused sources, the union across patterns, fallback, unknown sizes ─────


def test_a_configured_source_no_runnable_detector_reads_is_labelled_unused(sw, tmp_path):
    zeek = _dated(tmp_path / "zeek", days=2)
    pihole = _pihole(tmp_path / "pihole", count=2)
    config = _config(tmp_path, zeek_dir=str(zeek), pihole_dir=str(pihole))
    rc, out, _ = sw.dry("beacon", config=config)
    assert rc == 0
    lines = out.splitlines()
    head = next(i for i, line in enumerate(lines) if line.startswith("pihole_dir:"))
    assert lines[head + 1].strip() == "not used by any detector that can run"
    assert "pihole_dir" not in sw.previews[-1].families


def test_nothing_runnable_and_an_empty_selection_keep_their_own_branches(sw, tmp_path):
    rc, out, _ = sw.dry("beacon", "--zeek-dir=" + str(tmp_path / "absent"))
    assert rc == 0
    assert _rows(out, "detectors:") == [
        "(none can run - required logs unavailable; a real run exits 1)",
    ]
    rc, _, err = sw.run("beacon", "--zeek-dir=" + str(tmp_path / "absent"))
    assert rc == 1 and "no detectors could run" in err
    rc, out, _ = sw.dry("hunt", "--detect= ")
    assert rc == 0
    assert _rows(out, "detectors:") == ["(none - detect spec selected none)"]
    rc, _, err = sw.run("hunt", "--detect= ")
    assert rc == 0 and "the detect spec selected none" in err


def test_a_file_another_pattern_selects_is_never_called_unselected(tmp_path, monkeypatch):
    shared = _write(tmp_path / "zeek" / "conn.log", "x\n")
    only = _write(tmp_path / "zeek" / "dns.log", "y\n")
    previews = {
        "conn*.log*": PatternPreview("zeek_dir", (shared, only), (only,)),
        "dns*.log*": PatternPreview("zeek_dir", (shared,), (shared,)),
    }
    monkeypatch.setattr(loader, "preview_required_files", lambda *a, **k: previews)
    plan = runner.RunPlan(
        detectors={}, selected=[], will_run=["beacon"], skipped={},
        needed_logs={"conn*.log*": "zeek_dir", "dns*.log*": "zeek_dir"},
    )
    preview = runner._dry_run_preview(
        plan, {"zeek_dir": [tmp_path / "zeek"]}, inventory=None, default_spec="7d",
        load_all=True, since=None, until=None, virtual_sources=(), verbose=False,
    )
    family = preview.families["zeek_dir"]
    assert _reals(family.selected) == _reals([shared, only])
    assert family.not_selected == ()


def test_a_rotation_fallback_keeps_its_reason_without_claiming_pruned_files(sw, tmp_path):
    # .1 starts after the head does, before selection could stop at the floor.
    _rotations(tmp_path / "logs", ages=(1, 0.5, 20, 40))
    rc, out, err = sw.dry("syslog", str(tmp_path / "logs"))
    assert rc == 0
    assert "rotation order not monotonic - read the full archive (windowing skipped)" in err
    family = sw.previews[-1].families["syslog_dir"]
    assert family.selected == family.discovered
    assert not _rows(out, "not selected:")
    rc, _, quiet_err = sw.dry("syslog", str(tmp_path / "logs"), "-q")
    assert "rotation order not monotonic" not in quiet_err


def test_a_selected_file_that_cannot_be_sized_is_never_counted_as_zero(sw, tmp_path, monkeypatch):
    logs = _rotations(tmp_path / "logs")
    real = loader.preview_required_files

    def vanish_after_selection(*args, **kwargs):
        previews = real(*args, **kwargs)
        (logs / "messages.1").unlink()
        return previews

    monkeypatch.setattr(loader, "preview_required_files", vanish_after_selection)
    rc, out, _ = sw.dry("syslog", str(logs))
    assert rc == 0
    (files,) = _rows(out, "files:")
    assert "selected (" in files and "plus 1 file of unknown size" in files
    family = sw.previews[-1].families["syslog_dir"]
    assert [p.name for p in family.selected_unsized] == ["messages.1"]


def test_on_disk_bytes_reports_what_it_could_not_size(tmp_path):
    real = _write(tmp_path / "a.log", "abc\n")
    missing = tmp_path / "gone.log"
    directory = tmp_path / "dir.log"
    directory.mkdir()
    assert loader.on_disk_bytes([real, missing, directory]) == (4, (missing, directory))


# ── the selection warnings a dry run used to drop ───────────────────────────


def test_a_dry_run_states_the_selection_warning_its_run_would_print(sw, tmp_path):
    """An explicit syslog file beside a directory with no syslog.

    The live run warns that nothing in the directory looks like syslog, and the
    coverage notice defers to that warning, so the dry run prints the same
    selection warning rather than saying nothing.
    """
    named = _write(tmp_path / "auth.log", _syslog(2))
    other = _write(tmp_path / "emptyish" / "notes.txt", "just notes\n").parent
    rc, _, err = sw.dry("syslog", str(named), str(other))
    assert rc == 0
    expected = f"syslog_dir: nothing in {other} looks like syslog"
    assert expected in err
    rc, _, live_err = sw.run("syslog", str(named), str(other))
    assert rc == 0 and expected in live_err


# ── loader seams: one selector, authoritative empties, source mismatch ──────


def test_the_preview_and_the_load_share_one_selector(tmp_path, monkeypatch):
    logs = _rotations(tmp_path / "logs")
    calls: list[str] = []
    real = loader.pipeline._select_pattern_files

    def spy(pattern, source, inputs, **kwargs):
        calls.append(pattern)
        return real(pattern, source, inputs, **kwargs)

    monkeypatch.setattr(loader.pipeline, "_select_pattern_files", spy)
    needed = {"*.log*": "syslog_dir"}
    dirs = {"syslog_dir": [logs]}
    floor = datetime.now(timezone.utc) - timedelta(days=8)
    previews = loader.preview_required_files(
        needed, dirs, file_select_windows={"syslog_dir": (floor, None)},
    )
    result = loader.load_required_logs(
        needed, dirs, file_select_windows={"syslog_dir": (floor, None)},
        show_progress=False,
    )
    assert calls == ["*.log*", "*.log*", "*.log*"]
    selected = previews["*.log*"].selected
    assert _reals(selected) == _reals(f.path for f in result.availability["*.log*"])
    assert len(previews["*.log*"].discovered) == 4 and len(selected) < 4


def test_a_supplied_empty_population_is_authoritative(tmp_path, monkeypatch):
    logs = tmp_path / "logs"
    logs.mkdir()
    inventory = loader.DiscoveryInventory()
    population = inventory.populations({"*.log*": "syslog_dir"}, {"syslog_dir": [logs]})
    _rotations(logs)  # files written after observation are not in the population

    def no_listing(*args, **kwargs):
        raise AssertionError("an authoritative population was listed again")

    monkeypatch.setattr(loader.pipeline.SourceLoader, "discover_paths", no_listing)
    previews = loader.preview_required_files(
        {"*.log*": "syslog_dir"}, {"syslog_dir": [logs]},
        discovered_candidates=population,
    )
    assert previews["*.log*"].discovered == () and previews["*.log*"].selected == ()


def test_a_population_for_another_source_is_refused_like_the_load_refuses_it(tmp_path):
    logs = _rotations(tmp_path / "logs")
    inventory = loader.DiscoveryInventory()
    population = inventory.populations({"*.log*": "syslog_dir"}, {"syslog_dir": [logs]})
    mismatched = {"*.log*": loader.CandidatePopulation("pihole_dir", population["*.log*"].inputs)}
    with pytest.raises(ValueError) as preview_error:
        loader.preview_required_files(
            {"*.log*": "syslog_dir"}, {"syslog_dir": [logs]},
            discovered_candidates=mismatched,
        )
    with pytest.raises(ValueError) as load_error:
        loader.load_required_logs(
            {"*.log*": "syslog_dir"}, {"syslog_dir": [logs]},
            discovered_candidates=mismatched, show_progress=False,
        )
    assert str(preview_error.value) == str(load_error.value)


def test_the_resolver_records_one_reason_per_planned_family(tmp_path):
    logs = _rotations(tmp_path / "logs")
    ct = _cloudtrail(tmp_path / "ct")
    named = _write(tmp_path / "solo" / "auth.log", _syslog(1))
    needed = {"*.log*": "syslog_dir", "*.json*": "cloudtrail_dir", "pihole*.log*": "pihole_dir"}
    policies: dict = {}
    windows = loader.resolve_load_windows(
        needed, {"syslog_dir": [logs], "cloudtrail_dir": [ct]}, "7d",
        since=None, until=None, load_all=False, _policies=policies,
    )
    assert policies == {
        "syslog_dir": WindowPolicyReason.RESOLVED,
        "cloudtrail_dir": WindowPolicyReason.EXEMPT,
        "pihole_dir": WindowPolicyReason.NOT_CONFIGURED,
    }
    assert [w.source for w in windows] == ["syslog_dir"]
    policies = {}
    loader.resolve_load_windows(
        {"*.log*": "syslog_dir"}, {"syslog_dir": [named]}, "7d",
        since=None, until=None, load_all=False, _policies=policies,
    )
    assert policies == {"syslog_dir": WindowPolicyReason.NAMED_FILES}
    assert loader.resolve_load_windows(
        {"*.log*": "syslog_dir"}, {"syslog_dir": [logs]}, "7d",
        since=None, until=None, load_all=False,
    ) == windows
