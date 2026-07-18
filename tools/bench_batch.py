#!/usr/bin/env python3
"""Run a sequential batch of detector bench jobs and write one morning report.

The manifest owns every input, comparison, and output path.  The batch validates
the complete manifest before it starts, runs ``bench_summarize.py`` and
``bench_diff.py`` as child processes one job at a time, and keeps all job
artifacts in an output directory outside the repository.  It is deliberately a
small foreground harness: no scheduling, parallelism, retries, notifications,
or keep-awake behavior.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SUMMARIZER = REPO_ROOT / "tools" / "bench_summarize.py"
DIFF = REPO_ROOT / "tools" / "bench_diff.py"

TOP_KEYS = frozenset({"out_dir", "ledger", "python", "job"})
TOP_REQUIRED = frozenset({"out_dir", "ledger", "job"})
JOB_KEYS = frozenset({
    "name", "config", "dataset", "detect", "corpus", "all_window",
    "compare_to", "expect",
})
JOB_REQUIRED = frozenset({
    "name", "config", "dataset", "detect", "compare_to", "expect",
})
NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
EXPECTATIONS = frozenset({"diff", "repeat"})
COMPLETE_MARKER = "bench: measurement complete"
ACTIVE_PATTERN = r"([b]ench_summarize\.py|[s]igwood[[:space:]]+hunt)"
TAIL_LINE_COUNT = 5
TERMINATE_WAIT_SECONDS = 1.0


class _ManifestError(ValueError):
    """A fail-closed manifest error with a safe structural location."""

    def __init__(self, location: str, reason: str) -> None:
        super().__init__(f"{location}: {reason}")
        self.location = location
        self.reason = reason


class _StartupError(RuntimeError):
    """The active-bench startup check could not prove a safe start."""


class _ActiveBench(RuntimeError):
    """Another bench or hunt process is already active."""


class _SpawnError(RuntimeError):
    """A job child could not be launched."""


def _safe_error(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def _exact_table(
    value: object,
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    location: str,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _ManifestError(location, "expected a table")
    actual = set(value)
    if actual - allowed:
        raise _ManifestError(location, "unexpected key")
    missing = required - actual
    if missing:
        field = sorted(missing)[0]
        raise _ManifestError(f"{location}.{field}", "missing key")
    return value


def _nonblank_string(value: object, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _ManifestError(location, "expected a non-empty string")
    return value


def _manifest_path(value: object, base: Path, location: str) -> Path:
    raw = _nonblank_string(value, location)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def _require_file(path: Path, location: str) -> Path:
    if not path.is_file():
        raise _ManifestError(location, "file not found")
    return path


def _require_source(path: Path, location: str) -> Path:
    if not path.exists() or not (path.is_file() or path.is_dir()):
        raise _ManifestError(location, "source not found")
    return path


def _resolve_python(value: object | None, base: Path) -> Path:
    if value is None:
        candidate = Path(sys.executable)
    else:
        raw = _nonblank_string(value, "root.python")
        expanded = Path(raw).expanduser()
        path_like = expanded.is_absolute() or os.sep in raw
        if os.altsep is not None:
            path_like = path_like or os.altsep in raw
        if path_like:
            candidate = expanded if expanded.is_absolute() else base / expanded
            candidate = Path(os.path.abspath(candidate))
        else:
            candidate = _find_executable(raw)
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise _ManifestError("root.python", "executable not found")
    return candidate


def _find_executable(name: str) -> Path:
    for raw_dir in os.environ.get("PATH", "").split(os.pathsep):
        directory = Path(raw_dir or os.curdir).expanduser()
        candidate = Path(os.path.abspath(directory / name))
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise _ManifestError("root.python", "executable not found")


def _validate_out_dir(path: Path) -> None:
    if path == REPO_ROOT or REPO_ROOT in path.parents:
        raise _ManifestError("root.out_dir", "must be outside the repository")
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise _ManifestError("root.out_dir", "must be absent or an empty directory")


def _load_ledger_datasets(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            ledger = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise _ManifestError("root.ledger", "could not read ledger") from exc
    datasets = ledger.get("dataset") if isinstance(ledger, dict) else None
    if not isinstance(datasets, dict):
        raise _ManifestError("root.ledger", "missing dataset table")
    return datasets


def _validate_job(
    raw: object,
    *,
    index: int,
    base: Path,
    datasets: dict[str, object],
    names: set[str],
) -> dict[str, object]:
    location = f"job[{index}]"
    table = _exact_table(
        raw, allowed=JOB_KEYS, required=JOB_REQUIRED, location=location,
    )

    name = _nonblank_string(table["name"], f"{location}.name")
    if not 1 <= len(name) <= 40 or any(char not in NAME_CHARS for char in name):
        raise _ManifestError(f"{location}.name", "invalid job name")
    if name in names:
        raise _ManifestError(f"{location}.name", "duplicate job name")
    names.add(name)

    dataset = _nonblank_string(table["dataset"], f"{location}.dataset")
    if dataset not in datasets:
        raise _ManifestError(f"{location}.dataset", "unknown dataset")
    detect = _nonblank_string(table["detect"], f"{location}.detect")
    expect = _nonblank_string(table["expect"], f"{location}.expect")
    if expect not in EXPECTATIONS:
        raise _ManifestError(f"{location}.expect", "expected diff or repeat")

    all_window = table.get("all_window", False)
    if type(all_window) is not bool:
        raise _ManifestError(f"{location}.all_window", "expected a boolean")

    config = _require_file(
        _manifest_path(table["config"], base, f"{location}.config"),
        f"{location}.config",
    )
    compare_to = _require_file(
        _manifest_path(table["compare_to"], base, f"{location}.compare_to"),
        f"{location}.compare_to",
    )
    corpus = None
    if "corpus" in table:
        corpus = _require_source(
            _manifest_path(table["corpus"], base, f"{location}.corpus"),
            f"{location}.corpus",
        )

    return {
        "name": name,
        "config": config,
        "dataset": dataset,
        "detect": detect,
        "corpus": corpus,
        "all_window": all_window,
        "compare_to": compare_to,
        "expect": expect,
    }


def _load_manifest(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise _ManifestError("root", "could not read manifest") from exc

    top = _exact_table(
        raw, allowed=TOP_KEYS, required=TOP_REQUIRED, location="root",
    )
    base = path.parent
    out_dir = _manifest_path(top["out_dir"], base, "root.out_dir")
    _validate_out_dir(out_dir)
    ledger = _require_file(
        _manifest_path(top["ledger"], base, "root.ledger"), "root.ledger",
    )
    datasets = _load_ledger_datasets(ledger)
    python = _resolve_python(top.get("python"), base)

    raw_jobs = top["job"]
    if not isinstance(raw_jobs, list) or not raw_jobs:
        raise _ManifestError("root.job", "expected at least one job")
    names: set[str] = set()
    jobs = [
        _validate_job(
            raw_job, index=index, base=base, datasets=datasets, names=names,
        )
        for index, raw_job in enumerate(raw_jobs)
    ]
    return {
        "manifest": path,
        "out_dir": out_dir,
        "ledger": ledger,
        "python": python,
        "jobs": jobs,
    }


def _startup_guard() -> None:
    try:
        result = subprocess.run(
            ["pgrep", "-f", ACTIVE_PATTERN],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as exc:
        raise _StartupError from exc
    if result.returncode == 0:
        raise _ActiveBench
    if result.returncode != 1:
        raise _StartupError


def _claim_out_dir(path: Path) -> None:
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise OSError("output directory changed after validation")
        return
    path.mkdir(parents=True, exist_ok=False)


class _Report:
    """Append and durably flush the private morning report."""

    def __init__(self, path: Path, manifest: Path, job_count: int, started: float) -> None:
        self._handle = path.open("x", encoding="utf-8", newline="\n")
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(started))
        self._write(
            f"manifest: {manifest}\n"
            f"jobs: {job_count}\n"
            f"started: {stamp}\n\n"
        )

    def _write(self, text: str) -> None:
        self._handle.write(text)
        self._handle.flush()
        os.fsync(self._handle.fileno())

    def job(
        self,
        *,
        name: str,
        passed: bool,
        elapsed: float,
        diff_output: str = "",
        failure: str | None = None,
        err_tail: str = "",
    ) -> None:
        status = "PASS" if passed else "FAIL"
        block = f"{name}: {status} · {elapsed:.1f}s\n"
        if diff_output:
            block += diff_output
            if not diff_output.endswith("\n"):
                block += "\n"
        if failure is not None:
            block += f"failure: {failure}\n"
        if err_tail:
            block += "stderr tail:\n" + err_tail
            if not err_tail.endswith("\n"):
                block += "\n"
        self._write(block + "\n")

    def footer(self, passed: int, total: int, elapsed: float) -> None:
        self._write(f"{passed} of {total} passed · total wall {elapsed:.1f}s\n")

    def close(self) -> None:
        self._handle.close()


def _terminate_process_group(proc: subprocess.Popen[object]) -> None:
    term_sent = False
    kill_sent = False
    deadline = 0.0
    while True:
        try:
            if proc.poll() is not None:
                proc.wait()
                return
            if not term_sent:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                term_sent = True
                deadline = time.monotonic() + TERMINATE_WAIT_SECONDS
            if not kill_sent:
                remaining = max(0.0, deadline - time.monotonic())
                if remaining:
                    try:
                        proc.wait(timeout=remaining)
                        return
                    except subprocess.TimeoutExpired:
                        pass
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                kill_sent = True
            proc.wait()
            return
        except KeyboardInterrupt:
            continue


def _run_process(
    argv: list[str],
    *,
    env: dict[str, str],
    stdout: object,
    stderr: object,
    text: bool = False,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.Popen(
            argv,
            cwd=REPO_ROOT,
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
            text=text,
        )
    except OSError as exc:
        raise _SpawnError from exc
    try:
        child_stdout, child_stderr = proc.communicate()
    except KeyboardInterrupt:
        _terminate_process_group(proc)
        raise
    return (
        proc.returncode,
        child_stdout if isinstance(child_stdout, str) else "",
        child_stderr if isinstance(child_stderr, str) else "",
    )


def _summary_argv(settings: dict[str, object], job: dict[str, object], bundle: Path) -> list[str]:
    argv = [
        str(settings["python"]),
        str(SUMMARIZER),
        "--config", str(job["config"]),
        "--bundle-dir", str(bundle),
        "--dataset-id", str(job["dataset"]),
        "--ledger", str(settings["ledger"]),
        "--detect", str(job["detect"]),
    ]
    if job["corpus"] is not None:
        argv.append(str(job["corpus"]))
    if job["all_window"]:
        argv.append("--all")
    return argv


def _diff_argv(settings: dict[str, object], job: dict[str, object], summary: Path) -> list[str]:
    argv = [
        str(settings["python"]),
        str(DIFF),
        str(job["compare_to"]),
        str(summary),
    ]
    if job["expect"] == "diff":
        argv.append("--expect-diff")
    return argv


def _stderr_tail(path: Path) -> tuple[str, bool]:
    lines: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                lines.append(line)
                if len(lines) > TAIL_LINE_COUNT:
                    del lines[0]
    except OSError:
        return "", False
    marker = any(line.rstrip("\r\n") == COMPLETE_MARKER for line in lines)
    return "".join(lines), marker


def _execute_job(
    settings: dict[str, object], job: dict[str, object],
) -> tuple[bool, str, str | None, str]:
    out_dir = settings["out_dir"]
    assert isinstance(out_dir, Path)
    name = str(job["name"])
    bundle = out_dir / f"{name}-bundle"
    summary = out_dir / f"{name}.json"
    err_path = out_dir / f"{name}.err"
    env = dict(os.environ)
    env.pop("SIGWOOD_ROOT", None)

    try:
        bundle.mkdir()
        with summary.open("xb") as summary_handle, err_path.open("xb") as err_handle:
            try:
                summary_code, _, _ = _run_process(
                    _summary_argv(settings, job, bundle),
                    env=env,
                    stdout=summary_handle,
                    stderr=err_handle,
                )
            except _SpawnError:
                tail, _ = _stderr_tail(err_path)
                return False, "", "could not launch measurement", tail
    except KeyboardInterrupt:
        raise
    except OSError:
        tail, _ = _stderr_tail(err_path)
        return False, "", "could not prepare job output", tail

    tail, marker = _stderr_tail(err_path)
    if summary_code != 0:
        return False, "", f"measurement exited with status {summary_code}", tail
    if not marker:
        return False, "", "measurement completion marker missing", tail

    try:
        diff_code, diff_stdout, _ = _run_process(
            _diff_argv(settings, job, summary),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except _SpawnError:
        return False, "", "could not launch comparison", tail
    if diff_code != 0:
        return False, diff_stdout, f"comparison exited with status {diff_code}", tail
    first_line = diff_stdout.splitlines()[0] if diff_stdout.splitlines() else ""
    if job["expect"] == "repeat" and not first_line.startswith("repeatable:"):
        return False, diff_stdout, "comparison did not confirm repeat", tail
    return True, diff_stdout, None, ""


def main(argv: list[str] | None = None) -> int:
    """Run the declared bench jobs and return 0, 1, or interrupt status 130."""
    tokens = list(sys.argv[1:] if argv is None else argv)
    if len(tokens) != 1:
        return _safe_error("bench-batch: invalid arguments")
    manifest = Path(tokens[0]).expanduser().resolve()
    try:
        settings = _load_manifest(manifest)
    except _ManifestError as exc:
        return _safe_error(
            f"bench-batch: invalid manifest at {exc.location} ({exc.reason})"
        )
    except (OSError, ValueError, TypeError):
        return _safe_error("bench-batch: invalid manifest")

    try:
        _startup_guard()
    except _ActiveBench:
        return _safe_error("bench-batch: a bench process is already running")
    except _StartupError:
        return _safe_error("bench-batch: could not check for active bench processes")
    except KeyboardInterrupt:
        return 130

    out_dir = settings["out_dir"]
    jobs = settings["jobs"]
    assert isinstance(out_dir, Path)
    assert isinstance(jobs, list)
    try:
        _claim_out_dir(out_dir)
        started_wall = time.time()
        started_mono = time.monotonic()
        report = _Report(out_dir / "report.txt", manifest, len(jobs), started_wall)
    except (OSError, ValueError):
        return _safe_error("bench-batch: could not prepare output directory")

    passed = 0
    try:
        for raw_job in jobs:
            assert isinstance(raw_job, dict)
            job_started = time.monotonic()
            try:
                ok, diff_output, failure, err_tail = _execute_job(settings, raw_job)
            except KeyboardInterrupt:
                err_path = out_dir / f"{raw_job['name']}.err"
                err_tail, _ = _stderr_tail(err_path)
                report.job(
                    name=str(raw_job["name"]),
                    passed=False,
                    elapsed=time.monotonic() - job_started,
                    failure="interrupted",
                    err_tail=err_tail,
                )
                report.footer(passed, len(jobs), time.monotonic() - started_mono)
                return 130
            except Exception:
                err_path = out_dir / f"{raw_job['name']}.err"
                err_tail, _ = _stderr_tail(err_path)
                ok = False
                diff_output = ""
                failure = "unexpected job failure"

            if ok:
                passed += 1
            report.job(
                name=str(raw_job["name"]),
                passed=ok,
                elapsed=time.monotonic() - job_started,
                diff_output=diff_output,
                failure=failure,
                err_tail=err_tail,
            )
        report.footer(passed, len(jobs), time.monotonic() - started_mono)
        return 0 if passed == len(jobs) else 1
    except KeyboardInterrupt:
        try:
            report.footer(passed, len(jobs), time.monotonic() - started_mono)
        except OSError:
            pass
        return 130
    except OSError:
        return _safe_error("bench-batch: could not update report")
    finally:
        try:
            report.close()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
