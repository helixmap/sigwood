"""Prepared population lifecycle through the real runner and report writers."""
from datetime import datetime, timezone
from types import SimpleNamespace
import json

import pytest

from sigwood import runner
from sigwood.common import loader
from sigwood.common.finding import Finding, Severity
from sigwood.common.loader import types as t

PATTERN = "*.log*"


@pytest.fixture(autouse=True)
def preparation_contract():
    # Resolve the capability at test setup so baseline absence is reported for
    # each case instead of preventing collection of the complete test matrix.
    from sigwood.common import finding
    globals().update({name: getattr(finding, name) for name in (
        "Declined", "DeclineReason", "Preparation", "PreparedPopulation",
    )})


def module(name="syslog", pattern=PATTERN, source="syslog_dir"):
    return SimpleNamespace(DETECTOR_NAME=name, STATUS="available", DEFAULT_CONFIG={},
                           REQUIRED_LOGS=[{"pattern": pattern, "source": source}],
                           OPTIONAL_LOGS=[], run=lambda ctx: [])


def inputs(tmp_path):
    local = tmp_path / "local"
    local.mkdir()
    path = local / "sample.log"
    path.write_text("2026-01-02T00:00:00Z fixture-host app: first\n"
                    "2026-01-02T00:00:10Z fixture-host app: last\n")
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    (zeek / "conn.log").write_text(json.dumps({"ts": 1767312000, "id.orig_h": "192.0.2.1",
        "id.resp_h": "198.51.100.1", "id.resp_p": 443, "proto": "tcp", "duration": 1}) + "\n")
    return local, path, zeek


def configure(monkeypatch, mode="ready", recoverable=True, keep=1, name="syslog"):
    mod = module(name)
    mod.REQUIRED_LOGS = []
    mod.OPTIONAL_LOGS = [{"pattern": PATTERN, "source": "syslog_dir"},
                         {"pattern": PATTERN, "source": "journal"}]
    mod.REQUIRES_ONE_OF_OPTIONAL = True
    sibling = module("witness", "conn*.log*", "zeek_dir")
    seen = {"dispatch": [], "sibling": [], "finish": [], "final_plans": []}
    def sibling_run(ctx):
        frame = ctx.logs["conn*.log*"].copy()
        seen["sibling"].append(frame)
        return [Finding("witness", Severity.INFO, "Ordinary source evidence", "Fixture evidence",
                        {"rows": len(frame)}, [], datetime(2026, 1, 2, tzinfo=timezone.utc),
                        (datetime(2026, 1, 2, tzinfo=timezone.utc),) * 2)]
    sibling.run = sibling_run
    original = loader.load_required_logs

    def load(needed, *args, **kwargs):
        if len(needed) > 1:
            seen["final_plans"].append(dict(kwargs.get("sink_plans", {})))
        return original(needed, *args, **kwargs)
    monkeypatch.setattr(loader, "load_required_logs", load)

    def prepare(host):
        seen["host"] = host
        if mode in {reason.value for reason in DeclineReason}:
            return Declined(DeclineReason(mode), "test cause\nsecond line")
        if mode == "before":
            raise ValueError("prepare failed\nsecond line")
        window, _ = host.window(datetime(2026, 1, 2, tzinfo=timezone.utc),
                                datetime(2026, 1, 2, 0, 0, 10, tzinfo=timezone.utc))
        # A real preliminary pass binds the same source the final pass reads.
        preliminary = host.fold(t.SinkPlan((t.FoldSink(
            "probe", lambda: t.FoldDelta(0, 0),
            lambda delta, chunk, mask: t.FoldDelta(delta.value + len(chunk.frame), 1),
            lambda: 0, lambda state, delta: state + delta.value, host.mask,
        ),), preserve_frame=False), window)
        snapshot = preliminary.snapshots[PATTERN]
        def admit(chunk):
            if mode == "admission":
                raise ValueError("admission failed")
            return chunk.frame.iloc[:keep]
        host.final(t.SinkPlan((), admit=t.AdmitSink("chosen", admit, tuple(t._SYSLOG_COLUMNS))),
                   window, prepared_snapshot=snapshot)
        if mode == "after":
            raise ValueError("after registration")
        def finish(ctx, final):
            seen["finish"].append(final)
            if mode == "finish":
                raise ValueError("finish failed")
            later = host.fold(t.SinkPlan((t.FoldSink(
                "post", lambda: t.FoldDelta(0, 0),
                lambda delta, chunk, mask: t.FoldDelta(delta.value + len(chunk.frame), 1),
                lambda: 0, lambda state, delta: state + delta.value, host.mask,
            ),), preserve_frame=False), window, prepared_snapshot=final.snapshot)
            assert later.fold_results[PATTERN]["post"] == 2
            return "prepared value"
        return Preparation(finish, frozenset({"fixture-host"}))
    mod.PREPARED_POPULATION = PreparedPopulation(PATTERN, prepare, recoverable)
    def run(ctx, **kwargs):
        seen["dispatch"].append((len(ctx.logs[PATTERN]), kwargs))
        return []
    mod.run = run
    monkeypatch.setattr(runner, "discover_detectors", lambda **kwargs: {name: mod, "witness": sibling})
    return seen


def run_reports(tmp_path, local, zeek, fmt="json", name="syslog", **kwargs):
    target = tmp_path / f"report.{fmt}"
    code = runner.run(config={"sigwood": {"detect": f"{name},witness"}},
                      syslog_dir=None if kwargs.get("syslog_source") == "journal" else local,
                      zeek_dir=zeek, load_all=True, no_allowlist=True,
                      output_format=fmt, output_file=target, quiet=True, skip_confirm=True,
                      **kwargs)
    text = target.read_text()
    return code, json.loads(text) if fmt == "json" else text


@pytest.mark.parametrize("fmt", ["json", "text"])
@pytest.mark.parametrize("mode", ["ready", "ineligible", "abstained", "failed", "before", "after", "admission", "finish"])
@pytest.mark.parametrize("recoverable", [True, False])
def test_lifecycle_reports(tmp_path, monkeypatch, capsys, fmt, mode, recoverable):
    local, _, zeek = inputs(tmp_path)
    seen = configure(monkeypatch, mode, recoverable)
    code, report = run_reports(tmp_path, local, zeek, fmt)
    failed = mode == "finish" or (not recoverable and mode != "ready")
    assert code == int(failed)
    assert len(seen["sibling"]) == 1
    assert len(seen["sibling"][0]) == 1
    assert bool(seen["dispatch"]) == (not failed)
    if not failed:
        expected = [(1, {"_prepared": "prepared value"})] if mode == "ready" else [(2, {})]
        assert seen["dispatch"] == expected, report
    if mode in {"after", "before", "ineligible", "abstained", "failed"}:
        assert PATTERN not in seen["final_plans"][0]
    if mode == "admission":
        assert not seen["finish"]
    err = capsys.readouterr().err
    if failed:
        assert "prep error" in err
    if fmt == "json":
        summary = report["run_summary"]
        assert bool(summary["detectors_failed"]) == failed
        note = [n for n in summary["notes"] if "prepared load" in n]
        assert len(note) == int(recoverable and mode not in {"ready", "ineligible", "finish"})
        assert all("second line" not in n for n in note)
        assert summary["record_counts"][PATTERN] == 2
    else:
        assert "records:" in report


@pytest.mark.parametrize("name", ["syslog", "sample"])
@pytest.mark.parametrize("keep", [0, 1])
def test_population_empty_or_subset_both_dispatch_branches(tmp_path, monkeypatch, name, keep):
    local, _, zeek = inputs(tmp_path)
    seen = configure(monkeypatch, keep=keep, name=name)
    code, report = run_reports(tmp_path, local, zeek, name=name)
    assert code == 0
    assert seen["dispatch"] == [(keep, {"_prepared": "prepared value"})]
    assert report["run_summary"]["record_counts"][PATTERN] == 2
    assert seen["finish"][0].population.rows == 2
    assert seen["finish"][0].population.window == (
        datetime(2026, 1, 2, tzinfo=timezone.utc), datetime(2026, 1, 2, 0, 0, 10, tzinfo=timezone.utc))


@pytest.mark.parametrize("mode", ["ready", "before", "after", "finish", "admission"])
@pytest.mark.parametrize("fmt", ["text", "json"])
def test_journal_capture_alive_through_finish_and_redacted(tmp_path, monkeypatch, capsys, mode, fmt):
    import sys
    from pathlib import Path
    from sigwood.common.loader import journal
    local, _, zeek = inputs(tmp_path)
    script = tmp_path / "journalctl"
    records = [{"__REALTIME_TIMESTAMP": str(1767312000000000 + i * 10000000),
                "MESSAGE": "event", "_HOSTNAME": "fixture-host", "SYSLOG_IDENTIFIER": "app"}
               for i in range(2)]
    script.write_text(f"#!{sys.executable}\nimport json\nfor r in {records!r}: print(json.dumps(r))\n")
    script.chmod(0o755)
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: str(script))
    seen = configure(monkeypatch)
    mod = runner.discover_detectors()["syslog"]
    original_prepare = mod.PREPARED_POPULATION.prepare
    captures = []
    def prepare(host):
        path = host._args["source_dirs"]["journal"][0]
        captures.append(path)
        assert path.exists()
        if mode == "before":
            raise ValueError(f"failure at {path} and {path.parent}\nsecret second line")
        prepared = original_prepare(host)
        if mode == "after":
            raise ValueError(f"failure at {path}")
        if mode == "admission":
            plan, window, snap = host.registration
            def bad(chunk):
                raise ValueError(f"failure at {path}")
            from dataclasses import replace
            host.registration = (replace(plan, admit=replace(plan.admit, admit=bad)), window, snap)
        def finish(ctx, final):
            assert path.exists()
            if mode == "finish":
                raise ValueError(f"failure at {path} and {path.parent}")
            return prepared.finish(ctx, final)
        return Preparation(finish, prepared.arbitration_hosts)
    mod.PREPARED_POPULATION = PreparedPopulation(PATTERN, prepare, True)
    original_run = mod.run
    def run(ctx, **kwargs):
        assert captures and all(not p.exists() for p in captures)
        return original_run(ctx, **kwargs)
    mod.run = run
    code, report = run_reports(tmp_path, local, zeek, fmt, syslog_source="journal")
    assert code == int(mode == "finish")
    assert captures and all(not path.exists() and not path.parent.exists() for path in captures)
    output = str(report) + capsys.readouterr().err
    assert all(str(path) not in output and str(path.parent) not in output for path in captures)
    if mode != "ready" and (fmt == "json" or mode != "admission"):
        assert "system journal capture" in output
    assert journal._ACTIVE_CAPTURES == set()


@pytest.mark.parametrize("answer", ["n", "eof", "interrupt"])
def test_journal_declined_confirmation_cleans_before_finish(tmp_path, monkeypatch, answer):
    import sys
    from sigwood.common.loader import journal
    local, _, zeek = inputs(tmp_path)
    script = tmp_path / "journalctl"
    script.write_text(f"#!{sys.executable}\nprint('" + json.dumps({"__REALTIME_TIMESTAMP": "1767312000000000",
                      "MESSAGE": "event", "_HOSTNAME": "fixture-host", "SYSLOG_IDENTIFIER": "app"}) + "')\n")
    script.chmod(0o755)
    monkeypatch.setattr(journal, "resolve_journalctl", lambda: str(script))
    seen = configure(monkeypatch, keep=0)
    captured_paths = []
    def decline(*args):
        captured_paths.extend(journal._ACTIVE_CAPTURES)
        if answer == "eof":
            raise EOFError
        if answer == "interrupt":
            raise KeyboardInterrupt
        return answer
    monkeypatch.setattr("builtins.input", decline)
    with pytest.raises(runner.ExportAborted):
        runner.run(config={"sigwood": {"detect": "syslog,witness", "warn_above": 1}},
                   zeek_dir=zeek, syslog_source="journal", load_all=True)
    assert not seen["finish"]
    assert "host" not in seen  # the pre-read prompt declines before preparation
    assert captured_paths
    assert all(not path.exists() and not path.parent.exists() for path in captured_paths)
    assert journal._ACTIVE_CAPTURES == set()


@pytest.mark.parametrize("with_dnsblock", [False, True])
def test_pattern_collision_refused_before_preparation_or_load(tmp_path, monkeypatch, with_dnsblock):
    local, _, zeek = inputs(tmp_path)
    pattern = "pihole*.log*" if with_dnsblock else PATTERN
    source = "pihole_dir" if with_dnsblock else "syslog_dir"
    first = module("dnsblock" if with_dnsblock else "one", pattern, source)
    second = module("two", pattern, source)
    def unexpected(*args, **kwargs):
        pytest.fail("collision reached preparation or loading")
    second.PREPARED_POPULATION = PreparedPopulation(pattern, unexpected, True)
    first.PREPARED_POPULATION = PreparedPopulation(pattern, unexpected,
                                                   recoverable=not with_dnsblock)
    monkeypatch.setattr(runner, "discover_detectors", lambda **kwargs: {first.DETECTOR_NAME: first, "two": second})
    monkeypatch.setattr(loader, "load_required_logs", unexpected)
    pihole = tmp_path / "pihole"
    pihole.mkdir()
    (pihole / "pihole.log").write_text("Jan  2 00:00:00 dnsmasq[1]: query[A] example.com from 192.0.2.1\n")
    with pytest.raises(ValueError, match=f"{first.DETECTOR_NAME} and two"):
        runner.run(config={"sigwood": {"detect": f"{first.DETECTOR_NAME},two"}},
                   syslog_dir=local, pihole_dir=pihole, load_all=True, quiet=True)


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_real_dnsblock_coexists_with_admission(tmp_path, monkeypatch, fmt):
    from sigwood.detectors import dnsblock
    local, _, zeek = inputs(tmp_path)
    pihole = tmp_path / "pihole"
    pihole.mkdir()
    (pihole / "pihole.log").write_text("Jan  2 00:00:00 dnsmasq[1]: query[A] example.com from 192.0.2.1\n")
    seen = configure(monkeypatch)
    modules = runner.discover_detectors()
    modules["dnsblock"] = dnsblock
    monkeypatch.setattr(runner, "discover_detectors", lambda **kwargs: modules)
    original = loader.load_required_logs
    calls = []
    def load(needed, *args, **kwargs):
        calls.append((dict(needed), set(kwargs.get("sink_plans", {}))))
        return original(needed, *args, **kwargs)
    monkeypatch.setattr(loader, "load_required_logs", load)
    reports = []
    for detect in ("syslog,witness,dnsblock", "witness,dnsblock"):
        target = tmp_path / f"{len(reports)}.{fmt}"
        assert runner.run(config={"sigwood": {"detect": detect}}, syslog_dir=local,
                          zeek_dir=zeek, pihole_dir=pihole, load_all=True, quiet=True,
                          no_allowlist=True, skip_confirm=True, output_file=target,
                          output_format=fmt) == 0
        reports.append(target.read_text())
    all_pattern = [plans for needed, plans in calls if PATTERN in needed and len(needed) == 3]
    assert all_pattern == [{PATTERN, "pihole*.log*"}]
    assert seen["dispatch"] == [(1, {"_prepared": "prepared value"})]
    for needed, plans in calls:
        if set(needed) == {"pihole*.log*"}:
            assert plans == {"pihole*.log*"}
    if fmt == "json":
        one, two = map(json.loads, reports)
        assert [f for f in one["findings"] if f["detector"] == "dnsblock"] == [f for f in two["findings"] if f["detector"] == "dnsblock"]
        assert [n for n in one["run_summary"]["notes"] if n.startswith("dnsblock:")] == [n for n in two["run_summary"]["notes"] if n.startswith("dnsblock:")]
    else:
        assert [line for line in reports[0].splitlines() if "dnsblock:" in line] == [line for line in reports[1].splitlines() if "dnsblock:" in line]


@pytest.mark.parametrize("reload_fails", [False, True])
def test_replaced_source_recovers_before_finish_and_preserves_sibling_bytes(tmp_path, monkeypatch, capsys, reload_fails):
    from dataclasses import replace
    local, path, zeek = inputs(tmp_path)
    seen = configure(monkeypatch)
    mod = runner.discover_detectors()["syslog"]
    prepare = mod.PREPARED_POPULATION.prepare
    def mutate(host):
        prepared = prepare(host)
        replacement = path.with_suffix(".new")
        replacement.write_text("2026-01-02T00:00:00Z other-host app: replacement longer than original record\n")
        replacement.replace(path)
        return prepared
    mod.PREPARED_POPULATION = PreparedPopulation(PATTERN, mutate, True)
    original = loader.load_required_logs
    captured = []
    def load(needed, *args, **kwargs):
        if set(needed) == {PATTERN} and not kwargs.get("sink_plans") and reload_fails:
            raise ValueError("reload refused")
        result = original(needed, *args, **kwargs)
        if len(needed) > 1:
            # Same text does not establish ownership: keep the ordinary source's
            # contribution even when the failed source has an identical warning.
            contributions = result.contributions.copy()
            for pattern, item in contributions.items():
                contributions[pattern] = replace(item, warnings=(*item.warnings, "same.log: warning"))
            result = replace(result, contributions=contributions,
                warnings=[w for c in contributions.values() for w in c.warnings])
            captured.append(result)
        return result
    monkeypatch.setattr(loader, "load_required_logs", load)
    if reload_fails:
        with pytest.raises(ValueError, match="reload refused"):
            run_reports(tmp_path, local, zeek)
    else:
        code, report = run_reports(tmp_path, local, zeek)
        assert code == 0
        assert seen["dispatch"] == [(1, {})]
        assert report["run_summary"]["data_size_bytes"] == path.stat().st_size + (zeek / "conn.log").stat().st_size
        assert len([n for n in report["run_summary"]["notes"] if "prepared load failed" in n]) == 1
        assert capsys.readouterr().err.count("same.log: warning") == 1
        assert len(captured) == 1
    assert not seen["finish"]


@pytest.mark.parametrize("recover", [False, True])
def test_arbitration_uses_committed_hosts_or_reloaded_hosts(tmp_path, monkeypatch, recover):
    local, path, zeek = inputs(tmp_path)
    (zeek / "syslog.log").write_text("\n".join(json.dumps({"ts": 1767312000,
        "host": host, "facility": "auth", "severity": "info",
        "message": f"2026-01-02T00:00:00Z {host} app: event"})
        for host in ("fixture-host", "other-host")) + "\n")
    seen = configure(monkeypatch, keep=0)
    modules = runner.discover_detectors()
    mod = modules["syslog"]
    mod.OPTIONAL_LOGS.append({"pattern": "syslog*.log*", "source": "zeek_dir"})
    original_prepare = mod.PREPARED_POPULATION.prepare
    def prepare(host):
        prepared = original_prepare(host)
        if recover:
            replacement = path.with_suffix(".new")
            replacement.write_text("2026-01-02T00:00:00Z other-host app: replacement\n")
            replacement.replace(path)
        return prepared
    mod.PREPARED_POPULATION = PreparedPopulation(PATTERN, prepare, True)
    rows = []
    def run(ctx, **kwargs):
        rows.extend(ctx.logs["syslog*.log*"]["host"].tolist())
        return []
    mod.run = run
    code, report = run_reports(tmp_path, local, zeek)
    assert code == 0
    assert rows == (["fixture-host"] if recover else ["other-host"])
    assert any("1 Zeek row set aside" in n for n in report["run_summary"]["notes"])


def test_population_without_finite_timestamps_reports_no_window(tmp_path, monkeypatch):
    directory = tmp_path / "pihole"
    directory.mkdir()
    (directory / "pihole.log").write_text("Xxx  2 00:00:00 dnsmasq[1]: query[A] example.com from 192.0.2.1\n")
    pattern = "pihole*.log*"
    mod = module("sample", pattern, "pihole_dir")
    def prepare(host):
        window, _ = host.window(None, None)
        sink = t.FoldSink("count", lambda: t.FoldDelta(0, 0),
            lambda delta, chunk, mask: t.FoldDelta(delta.value + len(chunk.frame), 1),
            lambda: 0, lambda state, delta: state + delta.value, host.mask)
        first = host.fold(t.SinkPlan((sink,), preserve_frame=False), window)
        host.final(t.SinkPlan((), admit=t.AdmitSink("empty", lambda c: c.frame.iloc[:0],
                   tuple(t._PIHOLE_COLUMNS))), window, prepared_snapshot=first.snapshots[pattern])
        def finish(ctx, final):
            assert final.population.rows == 1 and final.population.window is None
            assert ctx.logs[pattern].empty
            return True
        return Preparation(finish)
    mod.PREPARED_POPULATION = PreparedPopulation(pattern, prepare, True)
    mod.run = lambda ctx, **kwargs: []
    monkeypatch.setattr(runner, "discover_detectors", lambda **kwargs: {"sample": mod})
    output = tmp_path / "report.json"
    assert runner.run(config={"sigwood": {"detect": "sample"}}, pihole_dir=directory,
                      load_all=True, quiet=True, no_allowlist=True,
                      output_format="json", output_file=output) == 0
    summary = json.loads(output.read_text())["run_summary"]
    assert summary["record_counts"][pattern] == 1
    assert summary["data_window"] is None
    assert not any("no records" in note for note in summary["notes"])


def test_config_failure_is_unrecovered_before_prepare(tmp_path, monkeypatch):
    local, _, zeek = inputs(tmp_path)
    seen = configure(monkeypatch)
    mod = runner.discover_detectors()["syslog"]
    def invalid(config):
        raise ValueError("invalid config")
    mod.validate_config = invalid
    code, report = run_reports(tmp_path, local, zeek)
    assert code == 1 and "host" not in seen
    assert report["run_summary"]["detectors_failed"] == {"syslog": "prep error - invalid config"}
    assert not seen["dispatch"] and seen["sibling"]


def test_ordinary_sibling_findings_identical_with_and_without_preparation(tmp_path, monkeypatch):
    local, _, zeek = inputs(tmp_path)
    configure(monkeypatch)
    _, prepared = run_reports(tmp_path, local, zeek)
    output = tmp_path / "ordinary.json"
    assert runner.run(config={"sigwood": {"detect": "witness"}}, zeek_dir=zeek,
                      load_all=True, no_allowlist=True, quiet=True, output_format="json",
                      output_file=output) == 0
    ordinary = json.loads(output.read_text())
    assert [f for f in prepared["findings"] if f["detector"] == "witness"] == ordinary["findings"]


def test_optional_unavailable_pattern_can_decline_without_failing_run(tmp_path, monkeypatch):
    _, _, zeek = inputs(tmp_path)
    configure(monkeypatch)
    mod = runner.discover_detectors()["syslog"]
    mod.REQUIRES_ONE_OF_OPTIONAL = False
    mod.REQUIRED_LOGS = [{"pattern": "conn*.log*", "source": "zeek_dir"}]
    def prepare(host):
        assert host.local_files == 0
        return Declined(DeclineReason.INELIGIBLE)
    mod.PREPARED_POPULATION = PreparedPopulation(PATTERN, prepare, True)
    mod.run = lambda ctx: []
    output = tmp_path / "optional.json"
    assert runner.run(config={"sigwood": {"detect": "syslog,witness"}}, zeek_dir=zeek,
                      syslog_source="off", load_all=True, quiet=True, no_allowlist=True,
                      output_format="json", output_file=output) == 0
    summary = json.loads(output.read_text())["run_summary"]
    assert not summary["detectors_failed"]
    assert not any("prepared load" in note for note in summary["notes"])


def test_reload_failure_reaches_cli_error_boundary(tmp_path, monkeypatch, capsys):
    from sigwood import cli
    local, path, zeek = inputs(tmp_path)
    configure(monkeypatch, mode="admission")
    original = loader.load_required_logs
    def load(needed, *args, **kwargs):
        if set(needed) == {PATTERN} and not kwargs.get("sink_plans"):
            raise ValueError("ordinary reload unavailable")
        return original(needed, *args, **kwargs)
    monkeypatch.setattr(loader, "load_required_logs", load)
    config = tmp_path / "config.toml"
    config.write_text('[sigwood]\ndetect = "syslog,witness"\n' +
                      f'syslog_dir = "{local}"\nzeek_dir = "{zeek}"\n')
    with pytest.raises(SystemExit) as stopped:
        cli.main(["hunt", f"--config={config}", "--all", "--quiet", "--yes"])
    assert stopped.value.code == 1
    assert "sigwood: ordinary reload unavailable" in capsys.readouterr().err


def test_host_final_once_mask_timer_and_exact_eligibility(tmp_path, monkeypatch):
    local, _, zeek = inputs(tmp_path)
    seen = configure(monkeypatch)
    mod = runner.discover_detectors()["syslog"]
    original = mod.PREPARED_POPULATION.prepare
    def prepare(host):
        assert host.exact_window and host.local_files == 1
        assert not host.sibling_needs_frame
        with host.timer("prepare"):
            prepared = original(host)
        assert host.timings["prepare"] >= 0
        plan, window, snapshot = host.registration
        with pytest.raises(ValueError, match="only once"):
            host.final(plan, window, prepared_snapshot=snapshot)
        return prepared
    mod.PREPARED_POPULATION = PreparedPopulation(PATTERN, prepare, True)
    code, _ = run_reports(tmp_path, local, zeek)
    assert code == 0 and seen["finish"]


def test_corrupt_replacement_warning_is_rendered_once_after_reload(tmp_path, monkeypatch, capsys):
    import gzip
    local, path, zeek = inputs(tmp_path)
    compressed = path.with_suffix(".log.gz")
    with gzip.open(compressed, "wt") as stream:
        stream.write(path.read_text())
    path.unlink()
    seen = configure(monkeypatch)
    mod = runner.discover_detectors()["syslog"]
    prepare = mod.PREPARED_POPULATION.prepare
    def corrupt(host):
        prepared = prepare(host)
        replacement = compressed.with_suffix(".new")
        replacement.write_bytes(b"invalid compressed content")
        replacement.replace(compressed)
        return prepared
    mod.PREPARED_POPULATION = PreparedPopulation(PATTERN, corrupt, True)
    code, report = run_reports(tmp_path, local, zeek)
    assert code == 0
    assert not seen["finish"]
    err = capsys.readouterr().err
    assert err.count(compressed.name) == 1, err
    assert report["run_summary"]["record_counts"].get(PATTERN, 0) == 0
    assert any("prepared load failed" in n for n in report["run_summary"]["notes"])


@pytest.mark.parametrize("recoverable", [True, False])
def test_admitted_local_pattern_requires_population_hosts(tmp_path, monkeypatch, recoverable):
    from dataclasses import replace
    local, path, zeek = inputs(tmp_path)
    path.write_text(path.read_text().replace("fixture-host app: last", "other-host app: last"))
    (zeek / "syslog.log").write_text("\n".join(json.dumps({"ts": 1767312000,
        "message": f"2026-01-02T00:00:00Z {host} app: event"})
        for host in ("fixture-host", "other-host")) + "\n")
    seen = configure(monkeypatch, recoverable=recoverable, keep=1)
    mod = runner.discover_detectors()["syslog"]
    mod.OPTIONAL_LOGS.append({"pattern": "syslog*.log*", "source": "zeek_dir"})
    original_prepare = mod.PREPARED_POPULATION.prepare
    def prepare(host):
        return replace(original_prepare(host), arbitration_hosts=None)
    mod.PREPARED_POPULATION = PreparedPopulation(PATTERN, prepare, recoverable)
    remaining = []
    original_run = mod.run
    def run(ctx, **kwargs):
        remaining.append(ctx.logs["syslog*.log*"].copy())
        return original_run(ctx, **kwargs)
    mod.run = run
    code, report = run_reports(tmp_path, local, zeek)
    assert code == int(not recoverable)
    assert not seen["finish"]
    assert PATTERN not in seen["final_plans"][0]
    if recoverable:
        assert seen["dispatch"] == [(2, {})]
        assert remaining[0].empty
        notes = report["run_summary"]["notes"]
        assert any("prepared load failed" in note and "arbitration hosts" in note for note in notes)
        del mod.PREPARED_POPULATION
        _, ordinary = run_reports(tmp_path, local, zeek)
        assert remaining[-1].equals(remaining[0])
        assert [n for n in notes if "set aside" in n] == [n for n in ordinary["run_summary"]["notes"] if "set aside" in n]
    else:
        assert not seen["dispatch"]
        assert "arbitration hosts" in report["run_summary"]["detectors_failed"]["syslog"]


@pytest.mark.parametrize("stage", ["prepare", "finish", "validate"])
@pytest.mark.parametrize("fmt", ["json", "text"])
def test_empty_preparation_exception_retains_type(tmp_path, monkeypatch, capsys, stage, fmt):
    from dataclasses import replace
    local, _, zeek = inputs(tmp_path)
    seen = configure(monkeypatch, recoverable=False)
    mod = runner.discover_detectors()["syslog"]
    original_prepare = mod.PREPARED_POPULATION.prepare
    def fail(*args):
        raise RuntimeError()
    def prepare(host):
        if stage == "prepare":
            fail()
        return replace(original_prepare(host), finish=fail)
    mod.PREPARED_POPULATION = PreparedPopulation(PATTERN, prepare, False)
    if stage == "validate":
        mod.validate_config = fail
    code, report = run_reports(tmp_path, local, zeek, fmt)
    assert code == 1
    assert not seen["dispatch"]
    assert "syslog: prep error - RuntimeError" in capsys.readouterr().err
    if fmt == "json":
        assert report["run_summary"]["detectors_failed"]["syslog"] == "prep error - RuntimeError"
    else:
        assert "prep error - RuntimeError" in report
