"""Tests for the sequential detector-bench batch harness."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parent.parent
BATCH_PATH = ROOT / "tools" / "bench_batch.py"


def _load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bench_batch = _load_script("bench_batch_test", BATCH_PATH)


def _job(name: str = "repeat-job", **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": name,
        "config": "bench.toml",
        "dataset": "demo",
        "detect": "dns",
        "compare_to": "baseline.json",
        "expect": "repeat",
    }
    value.update(overrides)
    return value


def _write_manifest(
    tmp_path: Path,
    *,
    jobs: list[dict[str, Any]] | None = None,
    out_dir: str = "out",
    python: str | None = None,
    top_extra: dict[str, Any] | None = None,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "bench.toml").write_text("[sigwood]\nroot = \"\"\n", encoding="utf-8")
    (tmp_path / "baseline.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "corpus").mkdir(exist_ok=True)
    (tmp_path / "ledger.toml").write_text(
        "[dataset.demo]\nquestion = \"placeholder\"\n"
        "\n[dataset.other]\nquestion = \"placeholder\"\n",
        encoding="utf-8",
    )

    lines = [
        f"out_dir = {json.dumps(out_dir)}",
        'ledger = "ledger.toml"',
    ]
    if python is not None:
        lines.append(f"python = {json.dumps(python)}")
    for key, value in (top_extra or {}).items():
        lines.append(f"{key} = {_toml_value(value)}")
    for job in jobs if jobs is not None else [_job()]:
        lines.append("")
        lines.append("[[job]]")
        for key, value in job.items():
            lines.append(f"{key} = {_toml_value(value)}")
    manifest = tmp_path / "batch.toml"
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value)


class _FakeProcess:
    """Small Popen double that writes through the supplied child streams."""

    next_pid = 41000

    def __init__(self, behavior: dict[str, Any], kwargs: dict[str, Any]) -> None:
        self.behavior = behavior
        self.kwargs = kwargs
        self.pid = _FakeProcess.next_pid
        _FakeProcess.next_pid += 1
        self.returncode = None if behavior.get("interrupt") else behavior.get("code", 0)
        self.wait_calls: list[float | None] = []

    def communicate(self) -> tuple[str | None, str | None]:
        stdout = self.kwargs["stdout"]
        stderr = self.kwargs["stderr"]
        if stdout is not subprocess.PIPE:
            stdout.write(self.behavior.get("summary", "{}\n").encode())
            stdout.flush()
        if stderr is not subprocess.PIPE:
            stderr.write(self.behavior.get("err", "bench: measurement complete\n").encode())
            stderr.flush()
        if self.behavior.get("interrupt"):
            raise KeyboardInterrupt
        if stdout is subprocess.PIPE:
            return self.behavior.get("diff", "repeatable: 4 fields identical\n"), ""
        return None, None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls.append(timeout)
        if (
            timeout is not None
            and self.behavior.get("interrupt_wait_once")
            and sum(value is not None for value in self.wait_calls) == 1
        ):
            raise KeyboardInterrupt
        if timeout is not None and self.behavior.get("stubborn"):
            raise subprocess.TimeoutExpired("fake", timeout)
        if self.returncode is None:
            self.returncode = -signal.SIGKILL
        return self.returncode


def _install_children(
    monkeypatch: pytest.MonkeyPatch,
    behaviors: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[_FakeProcess]]:
    calls: list[dict[str, Any]] = []
    processes: list[_FakeProcess] = []
    selected = behaviors or {}

    def fake_popen(argv: list[str], **kwargs: Any) -> _FakeProcess:
        stage = Path(argv[1]).name
        if stage == "bench_summarize.py":
            bundle = Path(argv[argv.index("--bundle-dir") + 1])
            name = bundle.name.removesuffix("-bundle")
            kind = "summary"
        else:
            name = Path(argv[3]).stem
            kind = "diff"
        behavior = selected.get((name, kind), {})
        if behavior.get("spawn_error"):
            raise OSError("synthetic spawn failure")
        if behavior.get("on_start") is not None:
            behavior["on_start"]()
        call = {"argv": argv, **kwargs, "stage": kind, "name": name}
        calls.append(call)
        process = _FakeProcess(behavior, kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(bench_batch.subprocess, "Popen", fake_popen)
    return calls, processes


def _ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bench_batch, "_startup_guard", lambda: None)


def test_manifest_rejects_unknown_keys_at_both_levels(tmp_path: Path) -> None:
    top = _write_manifest(tmp_path / "top", top_extra={"mystery": True})
    with pytest.raises(bench_batch._ManifestError, match="root: unexpected key"):
        bench_batch._load_manifest(top.resolve())

    job_dir = tmp_path / "job"
    job = _job(mystery=True)
    nested = _write_manifest(job_dir, jobs=[job])
    with pytest.raises(bench_batch._ManifestError, match=r"job\[0\]: unexpected key"):
        bench_batch._load_manifest(nested.resolve())


@pytest.mark.parametrize(
    ("jobs", "match"),
    [
        ([_job("same"), _job("same")], "duplicate job name"),
        ([_job("UPPER")], "invalid job name"),
        ([_job(expect="maybe")], "expected diff or repeat"),
        ([_job(detect="   ")], "expected a non-empty string"),
        ([_job(all_window=1)], "expected a boolean"),
    ],
)
def test_manifest_rejects_invalid_job_contracts(
    tmp_path: Path, jobs: list[dict[str, Any]], match: str,
) -> None:
    manifest = _write_manifest(tmp_path, jobs=jobs)
    with pytest.raises(bench_batch._ManifestError, match=match):
        bench_batch._load_manifest(manifest.resolve())


def test_manifest_requires_at_least_one_job(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    manifest.write_text(
        'out_dir = "out"\nledger = "ledger.toml"\njob = []\n',
        encoding="utf-8",
    )
    with pytest.raises(bench_batch._ManifestError, match="expected at least one job"):
        bench_batch._load_manifest(manifest.resolve())


@pytest.mark.parametrize("missing", ["ledger.toml", "bench.toml", "baseline.json", "corpus"])
def test_manifest_validates_every_reference_before_running(
    tmp_path: Path, missing: str,
) -> None:
    job = _job(corpus="corpus")
    manifest = _write_manifest(tmp_path, jobs=[job])
    path = tmp_path / missing
    if path.is_dir():
        path.rmdir()
    else:
        path.unlink()
    with pytest.raises(bench_batch._ManifestError):
        bench_batch._load_manifest(manifest.resolve())


def test_manifest_rejects_unknown_dataset(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path, jobs=[_job(dataset="absent")])
    with pytest.raises(bench_batch._ManifestError, match="unknown dataset"):
        bench_batch._load_manifest(manifest.resolve())


def test_out_dir_must_be_empty_and_outside_repo(tmp_path: Path) -> None:
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "keep").write_text("x", encoding="utf-8")
    manifest = _write_manifest(tmp_path, out_dir="nonempty")
    with pytest.raises(bench_batch._ManifestError, match="absent or an empty directory"):
        bench_batch._load_manifest(manifest.resolve())

    outside = tmp_path / "outside"
    outside.mkdir()
    in_repo = bench_batch.REPO_ROOT / "batch-output-test"
    manifest = _write_manifest(outside, out_dir=str(in_repo))
    with pytest.raises(bench_batch._ManifestError, match="outside the repository"):
        bench_batch._load_manifest(manifest.resolve())
    assert not in_repo.exists()


@pytest.mark.parametrize("declared", ["bin/bench-python", "bench-python"])
def test_python_resolves_manifest_relative_or_through_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, declared: str,
) -> None:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    executable = binary_dir / "bench-python"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_dir))
    manifest = _write_manifest(tmp_path, python=declared)
    loaded = bench_batch._load_manifest(manifest.resolve())
    assert loaded["python"] == executable.resolve()


def test_python_resolution_preserves_virtualenv_symlink_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = Path(sys.executable).resolve()
    venv_python = tmp_path / "venvpy"
    venv_python.symlink_to(target)

    monkeypatch.setattr(bench_batch.sys, "executable", str(venv_python))
    default = bench_batch._resolve_python(None, tmp_path)
    explicit = bench_batch._resolve_python("./venvpy", tmp_path)

    assert default == explicit == venv_python
    assert default.is_symlink()
    assert default != target


def test_startup_guard_distinguishes_active_clear_and_probe_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[list[str]] = []

    def result(code: int):
        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            seen.append(argv)
            assert kwargs["stdout"] is subprocess.DEVNULL
            assert kwargs["stderr"] is subprocess.DEVNULL
            return subprocess.CompletedProcess(argv, code)
        return fake_run

    monkeypatch.setattr(bench_batch.subprocess, "run", result(1))
    bench_batch._startup_guard()
    assert seen[-1] == ["pgrep", "-f", bench_batch.ACTIVE_PATTERN]

    monkeypatch.setattr(bench_batch.subprocess, "run", result(0))
    with pytest.raises(bench_batch._ActiveBench):
        bench_batch._startup_guard()

    monkeypatch.setattr(bench_batch.subprocess, "run", result(2))
    with pytest.raises(bench_batch._StartupError):
        bench_batch._startup_guard()

    monkeypatch.setattr(
        bench_batch.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(OSError()),
    )
    with pytest.raises(bench_batch._StartupError):
        bench_batch._startup_guard()


def test_bad_manifest_runs_nothing_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = _write_manifest(tmp_path, top_extra={"mystery": True})
    monkeypatch.setattr(
        bench_batch, "_startup_guard", lambda: pytest.fail("startup guard must not run"),
    )
    assert bench_batch.main([str(manifest)]) == 1
    assert capsys.readouterr().err == "bench-batch: invalid manifest at root (unexpected key)\n"
    assert not (tmp_path / "out").exists()


def test_sequential_order_argv_environment_and_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs = [
        _job("first", corpus="corpus", all_window=True),
        _job("second", dataset="other", expect="diff", detect="dns,!scan"),
    ]
    manifest = _write_manifest(tmp_path, jobs=jobs)
    _ready(monkeypatch)
    monkeypatch.setenv("SIGWOOD_ROOT", "/should/not/cross")
    between_jobs: list[str] = []

    def inspect_partial_report() -> None:
        partial = (tmp_path / "out" / "report.txt").read_text(encoding="utf-8")
        assert "first: PASS" in partial
        assert "second:" not in partial
        between_jobs.append(partial)

    calls, _ = _install_children(monkeypatch, {
        ("first", "diff"): {"diff": "repeatable: 7 fields identical\n"},
        ("second", "summary"): {"on_start": inspect_partial_report},
        ("second", "diff"): {"diff": "diff: config changed\n  total_findings: 2 -> 1\n"},
    })

    assert bench_batch.main([str(manifest)]) == 0
    assert [(call["name"], call["stage"]) for call in calls] == [
        ("first", "summary"), ("first", "diff"),
        ("second", "summary"), ("second", "diff"),
    ]
    for call in calls:
        assert call["cwd"] == bench_batch.REPO_ROOT
        assert call["start_new_session"] is True
        assert "SIGWOOD_ROOT" not in call["env"]

    first_summary = calls[0]["argv"]
    assert first_summary[-2:] == [str((tmp_path / "corpus").resolve()), "--all"]
    assert first_summary[first_summary.index("--detect") + 1] == "dns"
    assert "--expect-diff" not in calls[1]["argv"]
    assert calls[2]["argv"][calls[2]["argv"].index("--detect") + 1] == "dns,!scan"
    assert calls[3]["argv"][-1] == "--expect-diff"
    assert len(between_jobs) == 1

    report = (tmp_path / "out" / "report.txt").read_text(encoding="utf-8")
    assert report.index("first: PASS") < report.index("second: PASS")
    assert "repeatable: 7 fields identical\n" in report
    assert "diff: config changed\n  total_findings: 2 -> 1\n" in report
    assert report.splitlines()[-1].startswith("2 of 2 passed · total wall ")


def test_repeat_cannot_pass_when_comparator_auto_selects_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _write_manifest(tmp_path)
    _ready(monkeypatch)
    _install_children(monkeypatch, {
        ("repeat-job", "diff"): {"diff": "diff: config changed\n", "code": 0},
    })
    assert bench_batch.main([str(manifest)]) == 1
    report = (tmp_path / "out" / "report.txt").read_text(encoding="utf-8")
    assert "repeat-job: FAIL" in report
    assert "diff: config changed\n" in report
    assert "failure: comparison did not confirm repeat\n" in report


def test_summary_failure_continues_and_reports_exact_five_line_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _write_manifest(tmp_path, jobs=[_job("broken"), _job("after")])
    _ready(monkeypatch)
    calls, _ = _install_children(monkeypatch, {
        ("broken", "summary"): {
            "code": 1,
            "err": "line1\nline2\nline3\nline4\nline5\nline6\nline7\n",
        },
    })
    assert bench_batch.main([str(manifest)]) == 1
    assert [(call["name"], call["stage"]) for call in calls] == [
        ("broken", "summary"), ("after", "summary"), ("after", "diff"),
    ]
    report = (tmp_path / "out" / "report.txt").read_text(encoding="utf-8")
    tail = report.split("stderr tail:\n", 1)[1].split("\n\nafter:", 1)[0]
    assert tail == "line3\nline4\nline5\nline6\nline7"
    assert "failure: measurement exited with status 1" in report
    assert "after: PASS" in report
    assert report.splitlines()[-1].startswith("1 of 2 passed · total wall ")


@pytest.mark.parametrize(
    ("behavior", "expected_failure"),
    [
        ({"err": "measurement ended\n"}, "measurement completion marker missing"),
        ({"diff_code": 1}, "comparison exited with status 1"),
        ({"spawn_error": True}, "could not launch measurement"),
    ],
)
def test_failure_verdict_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: dict[str, Any],
    expected_failure: str,
) -> None:
    manifest = _write_manifest(tmp_path)
    _ready(monkeypatch)
    selected: dict[tuple[str, str], dict[str, Any]] = {}
    if "diff_code" in behavior:
        selected[("repeat-job", "diff")] = {"code": behavior["diff_code"]}
    else:
        selected[("repeat-job", "summary")] = behavior
    _install_children(monkeypatch, selected)
    assert bench_batch.main([str(manifest)]) == 1
    report = (tmp_path / "out" / "report.txt").read_text(encoding="utf-8")
    assert f"failure: {expected_failure}" in report


def test_incremental_report_survives_mid_batch_exception_and_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs = [_job("one"), _job("two"), _job("three")]
    manifest = _write_manifest(tmp_path, jobs=jobs)
    _ready(monkeypatch)
    seen: list[str] = []

    def execute(_settings: dict[str, object], job: dict[str, object]):
        name = str(job["name"])
        seen.append(name)
        if name == "two":
            raise RuntimeError("synthetic mid-batch exception")
        return True, "repeatable: 3 fields identical\n", None, ""

    monkeypatch.setattr(bench_batch, "_execute_job", execute)
    assert bench_batch.main([str(manifest)]) == 1
    assert seen == ["one", "two", "three"]
    report = (tmp_path / "out" / "report.txt").read_text(encoding="utf-8")
    assert report.index("one: PASS") < report.index("two: FAIL") < report.index("three: PASS")
    assert "failure: unexpected job failure" in report
    assert report.splitlines()[-1].startswith("2 of 3 passed · total wall ")


def test_keyboard_interrupt_terminates_process_group_and_finalizes_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _write_manifest(tmp_path)
    _ready(monkeypatch)
    _, processes = _install_children(monkeypatch, {
        ("repeat-job", "summary"): {
            "interrupt": True,
            "stubborn": True,
            "err": "bench: job was running\n",
        },
    })
    killed: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr(
        bench_batch.os, "killpg", lambda pid, sig: killed.append((pid, sig)),
    )

    assert bench_batch.main([str(manifest)]) == 130
    proc = processes[0]
    assert killed == [(proc.pid, signal.SIGTERM), (proc.pid, signal.SIGKILL)]
    assert len(proc.wait_calls) == 2
    assert 0 < proc.wait_calls[0] <= bench_batch.TERMINATE_WAIT_SECONDS
    assert proc.wait_calls[1] is None
    report = (tmp_path / "out" / "report.txt").read_text(encoding="utf-8")
    assert "repeat-job: FAIL" in report
    assert "failure: interrupted" in report
    assert "bench: job was running" in report
    assert report.splitlines()[-1].startswith("0 of 1 passed · total wall ")


def test_repeated_keyboard_interrupt_cannot_skip_kill_and_reap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _write_manifest(tmp_path)
    _ready(monkeypatch)
    _, processes = _install_children(monkeypatch, {
        ("repeat-job", "summary"): {
            "interrupt": True,
            "interrupt_wait_once": True,
            "stubborn": True,
        },
    })
    killed: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr(
        bench_batch.os, "killpg", lambda pid, sig: killed.append((pid, sig)),
    )

    assert bench_batch.main([str(manifest)]) == 130
    proc = processes[0]
    assert killed == [(proc.pid, signal.SIGTERM), (proc.pid, signal.SIGKILL)]
    assert len([value for value in proc.wait_calls if value is not None]) == 2
    assert proc.wait_calls[-1] is None
    assert proc.returncode == -signal.SIGKILL


def test_active_guard_refuses_before_creating_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = _write_manifest(tmp_path)
    monkeypatch.setattr(
        bench_batch, "_startup_guard", lambda: (_ for _ in ()).throw(bench_batch._ActiveBench()),
    )
    assert bench_batch.main([str(manifest)]) == 1
    assert capsys.readouterr().err == "bench-batch: a bench process is already running\n"
    assert not (tmp_path / "out").exists()
