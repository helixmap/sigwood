"""Tests for the privacy-safe detector measurement bench."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parent.parent
SUMMARIZER_PATH = ROOT / "tools" / "bench_summarize.py"
DIFF_PATH = ROOT / "tools" / "bench_diff.py"
GENERATOR_PATH = ROOT / "demo" / "gen_corpus.py"
TEXT_RULE = "─" * 80


def _load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bench_summarize = _load_script("bench_summarize_test", SUMMARIZER_PATH)
bench_diff = _load_script("bench_diff_test", DIFF_PATH)
gen_corpus = _load_script("bench_gen_corpus_test", GENERATOR_PATH)


def _config_text(zeek_dir: Path | None = None, *, beacon_threshold: float | None = None) -> str:
    zeek_value = "" if zeek_dir is None else str(zeek_dir)
    text = (
        "[sigwood]\n"
        'root = ""\n'
        f"zeek_dir = {json.dumps(zeek_value)}\n"
        'syslog_dir = ""\n'
        'syslog_source = "off"\n'
        'pihole_dir = ""\n'
        'cloudtrail_dir = ""\n'
        'detect = "all"\n'
        "\n[allowlist]\n"
        'allowlist_dir = ""\n'
    )
    if beacon_threshold is not None:
        text += f"\n[detectors.beacon]\nthreshold = {beacon_threshold}\n"
    return text


def _write_config(path: Path, zeek_dir: Path | None = None, *, threshold: float | None = None) -> None:
    path.write_text(_config_text(zeek_dir, beacon_threshold=threshold), encoding="utf-8")


def _ledger_text(salt: str = "0123456789abcdef0123456789abcdef") -> str:
    return (
        f"salt = {json.dumps(salt)}\n\n"
        "[dataset.demo]\n"
        'path = "synthetic corpus"\n'
        'version = "test"\n'
        'download_sha256 = "not-applicable"\n'
        'license = "test fixture"\n'
        'label_source = "generator"\n'
        'question = "does the mechanism repeat?"\n'
        'approval = "synthetic"\n'
        'revisit = "when the fixture changes"\n'
    )


def _write_ledger(path: Path, salt: str = "0123456789abcdef0123456789abcdef") -> None:
    path.write_text(_ledger_text(salt), encoding="utf-8")


def _selectors() -> list[dict[str, str]]:
    beacon_title = (
        f"{gen_corpus.BENCH_BEACON[0]} → {gen_corpus.BENCH_BEACON[1]}:"
        f"{gen_corpus.BENCH_BEACON[2]}/{gen_corpus.BENCH_BEACON[3]}"
    )
    duration_title = (
        f"{gen_corpus.BENCH_DURATION[0]} → {gen_corpus.BENCH_DURATION[1]}:"
        f"{gen_corpus.BENCH_DURATION[2]}/{gen_corpus.BENCH_DURATION[3]}"
    )
    return [
        {
            "example_id": "beacon_c2",
            "detector": "beacon",
            "field": "title",
            "op": "eq",
            "value": beacon_title,
        },
        {
            "example_id": "duration_c2",
            "detector": "duration",
            "field": "title",
            "op": "eq",
            "value": duration_title,
        },
    ]


def _write_selectors(path: Path, selectors: list[dict[str, str]] | None = None) -> None:
    path.write_text(json.dumps(selectors or _selectors()), encoding="utf-8")


def _clean_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("SIGWOOD_ROOT", None)
    return env


def _summary_command(
    config: Path,
    bundle: Path,
    ledger: Path,
    *,
    selectors: Path | None = None,
    python: Path | None = None,
    extra: list[str] | None = None,
) -> list[str]:
    command = [
        sys.executable,
        str(SUMMARIZER_PATH),
        "--config",
        str(config),
        "--bundle-dir",
        str(bundle),
        "--dataset-id",
        "demo",
        "--ledger",
        str(ledger),
        "--python",
        str(python or Path(sys.executable)),
        "--all",
    ]
    if selectors is not None:
        command.extend(["--selectors", str(selectors)])
    if extra:
        command.extend(extra)
    return command


def _run_summary(
    config: Path,
    bundle: Path,
    ledger: Path,
    *,
    selectors: Path | None = None,
    python: Path | None = None,
    env: dict[str, str] | None = None,
    extra: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _summary_command(
            config,
            bundle,
            ledger,
            selectors=selectors,
            python=python,
            extra=extra,
        ),
        capture_output=True,
        text=True,
        env=env or _clean_env(),
        cwd=ROOT,
        check=False,
    )


def _generate(out_dir: Path, *, scenario: str = "bench") -> None:
    subprocess.run(
        [sys.executable, str(GENERATOR_PATH), str(out_dir), "--scenario", scenario],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _payload(
    findings: list[dict[str, Any]] | None = None,
    *,
    requested_span: float | None = None,
    detectors_run: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "sigwood_version": "0.2.3",
        "schema_version": 1,
        "run_summary": {
            "data_window": None,
            "record_counts": {},
            "data_size_bytes": 0,
            "detectors_run": detectors_run or [],
            "detectors_skipped": {},
            "detectors_failed": {},
            "notes": [],
            "data_sources": [],
            "detector_methods": {
                name: None for name in (detectors_run or [])
            },
            "requested_span": requested_span,
            "suppression": None,
        },
        "findings": findings or [],
    }


def _finding(
    detector: str = "duration",
    severity: str = "low",
    *,
    title: str = "reserved flow",
) -> dict[str, Any]:
    return {
        "detector": detector,
        "severity": severity,
        "title": title,
        "description": "Synthetic description.",
        "next_steps": [],
        "evidence": {},
        "ts_generated": "2026-06-01T00:00:00+00:00",
        "data_window": [
            "2026-06-01T00:00:00+00:00",
            "2026-06-02T00:00:00+00:00",
        ],
    }


def _projection_config() -> dict[str, Any]:
    return {
        "sigwood": {"root": ""},
        "detectors": {},
        "allowlist": {
            "enabled": True,
            "allowlist_dir": "",
            "domain_patterns": [],
            "connection_rules": [],
        },
    }


def test_demo_default_and_explicit_scenario_are_byte_identical(tmp_path: Path) -> None:
    default_dir = tmp_path / "default"
    explicit_dir = tmp_path / "explicit"
    subprocess.run(
        [sys.executable, str(GENERATOR_PATH), str(default_dir)],
        capture_output=True,
        cwd=ROOT,
        check=True,
    )
    _generate(explicit_dir, scenario="demo")
    assert _tree_bytes(default_dir) == _tree_bytes(explicit_dir)


def test_bench_end_to_end_repeats_ranks_and_detects_threshold_change(tmp_path: Path) -> None:
    corpus_a = tmp_path / "corpus-a"
    corpus_b = tmp_path / "corpus-b"
    _generate(corpus_a)
    _generate(corpus_b)
    assert _tree_bytes(corpus_a) == _tree_bytes(corpus_b)
    assert set(_tree_bytes(corpus_a)) == {"zeek/conn.log"}

    config = tmp_path / "bench.toml"
    changed_config = tmp_path / "bench-changed.toml"
    ledger = tmp_path / "ledger.toml"
    selectors = tmp_path / "selectors.json"
    _write_config(config, corpus_a / "zeek")
    _write_config(changed_config, corpus_a / "zeek", threshold=0.9)
    _write_ledger(ledger)
    _write_selectors(selectors)

    first = _run_summary(config, tmp_path / "bundle-1", ledger, selectors=selectors)
    second = _run_summary(config, tmp_path / "bundle-2", ledger, selectors=selectors)
    assert first.returncode == second.returncode == 0, (first.stderr, second.stderr)
    assert "bench: measurement complete" in first.stderr
    summary_a = json.loads(first.stdout)
    summary_b = json.loads(second.stdout)
    runtime_a = summary_a.pop("runtime_seconds")
    runtime_b = summary_b.pop("runtime_seconds")
    assert type(runtime_a) is type(runtime_b) is float
    assert summary_a == summary_b

    assert summary_a["total_findings"] == 2
    assert summary_a["findings_by_detector_severity"]["beacon"]["medium"] == 1
    assert summary_a["findings_by_detector_severity"]["duration"]["high"] == 1
    assert summary_a["findings_by_detector_severity"]["scan"] == {
        "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    assert summary_a["known_example_ranks"]["beacon_c2"]["rank"] == 1
    assert summary_a["known_example_ranks"]["duration_c2"]["rank"] == 1
    assert summary_a["requested_span_seconds"] is None

    expected_bundle = {
        "hunt.json",
        "hunt.text",
        "hunt.json.stderr",
        "hunt.text.stderr",
        "merged-config.json",
    }
    assert {path.name for path in (tmp_path / "bundle-1").iterdir()} == expected_bundle

    changed = _run_summary(
        changed_config, tmp_path / "bundle-changed", ledger, selectors=selectors
    )
    assert changed.returncode == 0, changed.stderr
    summary_changed = json.loads(changed.stdout)
    assert summary_changed["config_hash"] != summary_a["config_hash"]
    assert summary_changed["findings_by_detector_severity"]["beacon"]["medium"] == 0
    assert summary_changed["total_findings"] == 1

    left_path = tmp_path / "summary-a.json"
    right_path = tmp_path / "summary-changed.json"
    summary_a["runtime_seconds"] = runtime_a
    left_path.write_text(json.dumps(summary_a), encoding="utf-8")
    right_path.write_text(json.dumps(summary_changed), encoding="utf-8")
    diff = subprocess.run(
        [
            sys.executable,
            str(DIFF_PATH),
            str(left_path),
            str(right_path),
            "--expect-diff",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert diff.returncode == 0, diff.stderr
    assert "findings_by_detector_severity.beacon.medium" in diff.stdout


def test_projection_handles_nullable_shapes_span_and_absent_header() -> None:
    raw = _payload([_finding()], requested_span=604800.0, detectors_run=["duration"])
    payload = bench_summarize._validate_payload(raw)
    summary = bench_summarize._project_summary(
        payload,
        "",
        exit_code=0,
        runtime_seconds=1.25,
        config_hash="abc123abc123",
        dataset_id="demo",
        config=_projection_config(),
        selectors=[],
    )
    assert summary["requested_span_seconds"] == 604800
    assert type(summary["requested_span_seconds"]) is int
    assert summary["default_visible"] == {"duration": 0}
    assert summary["cap_hidden"] == {"duration": 0}
    assert summary["level_hidden"] == {"duration": 1}


def test_config_hash_is_salted_path_redacted_and_behavior_sensitive() -> None:
    salt = "0123456789abcdef0123456789abcdef"
    config = _projection_config()
    config["sigwood"]["root"] = "/private/synthetic-a"
    baseline = bench_summarize._config_hash(config, salt)

    moved = copy.deepcopy(config)
    moved["sigwood"]["root"] = "/private/synthetic-b"
    moved["export"] = {"destination": "/private/synthetic-export"}
    moved["graph"] = {"title": "synthetic graph"}
    assert bench_summarize._config_hash(moved, salt) == baseline

    changed = copy.deepcopy(config)
    changed["detectors"] = {"beacon": {"threshold": 0.9}}
    assert bench_summarize._config_hash(changed, salt) != baseline
    assert bench_summarize._config_hash(config, "fedcba9876543210fedcba9876543210") != baseline


def test_payload_refuses_schema_bump_and_structural_key_drift() -> None:
    bumped = _payload()
    bumped["schema_version"] = 2
    with pytest.raises(bench_summarize.SummaryRefusal):
        bench_summarize._validate_payload(bumped)

    drifted = _payload()
    drifted["run_summary"]["new_field"] = "raw"
    with pytest.raises(bench_summarize.SummaryRefusal):
        bench_summarize._validate_payload(drifted)


def test_text_count_contract_handles_singular_and_comma_cap() -> None:
    report = (
        "duration - 1 finding · 1 H\n"
        f"{TEXT_RULE}\n"
        "[H] reserved flow\n"
    )
    visible, capped, level = bench_summarize._parse_text_counts(report, {"duration": 1})
    assert visible == {"duration": 1}
    assert capped == {"duration": 0}
    assert level == {"duration": 0}

    capped_report = (
        "duration - 1100 findings · 1100 H\n"
        f"{TEXT_RULE}\n"
        "… 1,000 more not shown (showing first 100). Unusually high - narrow with "
        "the allowlist, or this detector may be misbehaving.\n"
    )
    visible, capped, level = bench_summarize._parse_text_counts(
        capped_report, {"duration": 1100}
    )
    assert visible == {"duration": 100}
    assert capped == {"duration": 1000}
    assert level == {"duration": 0}


def _diff_summary(**overrides: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "config_hash": "aaaaaaaaaaaa",
        "runtime_seconds": 1.0,
        "sigwood_version": "0.2.3",
        "schema_version": 1,
        "dataset_id": "demo",
        "record_counts": {},
        "data_size_bytes": 10,
        "requested_span_seconds": None,
        "total_findings": 2,
        "detectors_failed": [],
    }
    summary.update(overrides)
    return summary


def test_diff_repeat_is_type_and_container_exact() -> None:
    same = _diff_summary()
    code, lines = bench_diff._compare(
        same, copy.deepcopy(same), expect_diff=False, strict_runtime=False
    )
    assert code == 0
    assert lines[0].startswith("repeatable:")

    bool_value = _diff_summary(total_findings=True)
    code, _ = bench_diff._compare(
        same, bool_value, expect_diff=False, strict_runtime=False
    )
    assert code == 1

    missing_container = _diff_summary()
    missing_container.pop("detectors_failed")
    code, _ = bench_diff._compare(
        same, missing_container, expect_diff=False, strict_runtime=False
    )
    assert code == 1

    dict_container = _diff_summary(detectors_failed={})
    code, _ = bench_diff._compare(
        same, dict_container, expect_diff=False, strict_runtime=False
    )
    assert code == 1


def test_diff_expect_diff_requires_detector_behavior() -> None:
    base = _diff_summary()
    for context_change in (
        {"config_hash": "bbbbbbbbbbbb"},
        {"sigwood_version": "0.2.4"},
        {"dataset_id": "demo-next"},
        {"record_counts": {"conn*.log*": 11}},
    ):
        changed = copy.deepcopy(base)
        changed.update(context_change)
        code, lines = bench_diff._compare(
            base, changed, expect_diff=True, strict_runtime=False
        )
        assert code == 1
        assert lines[-1] == "change produced no observable BEHAVIORAL change"

    changed = _diff_summary(total_findings=1)
    code, lines = bench_diff._compare(
        base, changed, expect_diff=True, strict_runtime=False
    )
    assert code == 0
    assert any("total_findings" in line for line in lines)


def test_diff_runtime_tolerance_and_unknown_float_guard() -> None:
    base = _diff_summary(runtime_seconds=1.0)
    slower = _diff_summary(runtime_seconds=3.0)
    code, _ = bench_diff._compare(
        base, slower, expect_diff=False, strict_runtime=False
    )
    assert code == 0
    code, _ = bench_diff._compare(
        base, slower, expect_diff=False, strict_runtime=True
    )
    assert code == 1

    unexpected = _diff_summary(score=0.5)
    with pytest.raises(bench_diff.DiffError, match="unexpected float field score"):
        bench_diff._compare(base, unexpected, expect_diff=False, strict_runtime=False)


def test_diff_cli_errors_do_not_echo_path_bearing_tokens(tmp_path: Path) -> None:
    secret = "/private/synthetic-summary-name.json"
    invalid = subprocess.run(
        [sys.executable, str(DIFF_PATH), f"--unknown={secret}"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert invalid.returncode == 2
    assert invalid.stdout == ""
    assert invalid.stderr == "bench-diff: invalid arguments\n"
    assert secret not in invalid.stderr

    missing = subprocess.run(
        [sys.executable, str(DIFF_PATH), secret, str(tmp_path / "also-missing.json")],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert missing.returncode == 1
    assert missing.stdout == ""
    assert missing.stderr == "bench-diff: could not read summaries\n"
    assert secret not in missing.stderr


def _fake_python(path: Path, payload: dict[str, Any], *, mismatch: bool = False) -> None:
    encoded = json.dumps(payload)
    script = f'''#!/usr/bin/env python3
import sys
is_json = any(arg == "--format=json" for arg in sys.argv)
sys.stderr.write("/private/synthetic-secret/conn.log\\n")
if is_json:
    sys.stdout.write({encoded!r})
    sys.stdout.write("\\n")
    raise SystemExit(0)
sys.stdout.write("")
raise SystemExit({1 if mismatch else 0})
'''
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _minimal_inputs(tmp_path: Path) -> tuple[Path, Path]:
    config = tmp_path / "bench.toml"
    ledger = tmp_path / "ledger.toml"
    _write_config(config)
    _write_ledger(ledger)
    return config, ledger


def test_child_stderr_is_quarantined_byte_for_byte(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    fake = tmp_path / "fake-python"
    _fake_python(fake, _payload())
    bundle = tmp_path / "bundle"
    result = _run_summary(config, bundle, ledger, python=fake)
    assert result.returncode == 0, result.stderr
    secret = "/private/synthetic-secret/conn.log"
    assert secret not in result.stdout
    assert secret not in result.stderr
    assert (bundle / "hunt.json.stderr").read_bytes() == (secret + "\n").encode()
    assert (bundle / "hunt.text.stderr").read_bytes() == (secret + "\n").encode()


def test_selector_match_value_never_crosses_parent_surfaces(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    selectors = tmp_path / "selectors.json"
    selector_secret = "/private/selector-secret/value.log"
    _write_selectors(
        selectors,
        [{
            "example_id": "duration_example",
            "detector": "duration",
            "field": "title",
            "op": "contains",
            "value": selector_secret,
        }],
    )
    payload = _payload(detectors_run=["duration"])
    fake = tmp_path / "fake-python"
    _fake_python(fake, payload)
    result = _run_summary(
        config, tmp_path / "bundle", ledger, selectors=selectors, python=fake
    )
    assert result.returncode == 0, result.stderr
    assert selector_secret not in result.stdout
    assert selector_secret not in result.stderr
    rank = json.loads(result.stdout)["known_example_ranks"]["duration_example"]
    assert rank == {
        "detector": "duration",
        "example_id": "duration_example",
        "found": False,
        "pool_size": 0,
        "rank": None,
    }


def test_selector_detector_must_be_in_run_status_without_echo(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    selectors = tmp_path / "selectors.json"
    detector_secret = "/private/synthetic-selector-detector"
    _write_selectors(
        selectors,
        [{
            "example_id": "duration_example",
            "detector": detector_secret,
            "field": "title",
            "op": "contains",
            "value": "synthetic value",
        }],
    )
    fake = tmp_path / "fake-python"
    _fake_python(fake, _payload(detectors_run=["duration"]))
    bundle = tmp_path / "bundle"
    result = _run_summary(config, bundle, ledger, selectors=selectors, python=fake)
    assert result.returncode == 1
    assert result.stdout == ""
    assert detector_secret not in result.stderr
    assert result.stderr == "bench: summary refused at selectors.detector\n"
    assert detector_secret not in (bundle / "bench.error.txt").read_text(encoding="utf-8")


def test_sigwood_root_refuses_before_launch_without_echo(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    marker = tmp_path / "never-launched"
    env = _clean_env()
    env["SIGWOOD_ROOT"] = "/private/synthetic-secret/root"
    result = _run_summary(config, tmp_path / "bundle", ledger, python=marker, env=env)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "SIGWOOD_ROOT is set" in result.stderr
    assert env["SIGWOOD_ROOT"] not in result.stderr
    assert not (tmp_path / "bundle").exists()


def test_config_error_path_does_not_echo(tmp_path: Path) -> None:
    config = tmp_path / "private-config-name.toml"
    ledger = tmp_path / "ledger.toml"
    _write_ledger(ledger)
    result = _run_summary(config, tmp_path / "bundle", ledger)
    assert result.returncode == 1
    assert result.stdout == ""
    assert str(config) not in result.stderr
    assert result.stderr == "bench: could not read --config\n"
    assert not (tmp_path / "bundle").exists()


def test_nonempty_bundle_refuses_without_modifying_contents(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    bundle = tmp_path / "bundle-private-name"
    bundle.mkdir()
    sentinel = bundle / "sentinel"
    sentinel.write_bytes(b"keep")
    result = _run_summary(config, bundle, ledger)
    assert result.returncode == 1
    assert result.stdout == ""
    assert str(bundle) not in result.stderr
    assert sentinel.read_bytes() == b"keep"
    assert set(bundle.iterdir()) == {sentinel}


def test_parent_failure_retains_raw_diagnostic_without_echo(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    fake = tmp_path / "fake-python"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stderr.write('/private/synthetic-secret/child.log\\n')\n"
        "sys.stdout.write('not-json\\n')\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    bundle = tmp_path / "bundle"
    result = _run_summary(config, bundle, ledger, python=fake)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "/private/synthetic-secret" not in result.stderr
    assert "details in the bundle" in result.stderr
    diagnostic = bundle / "bench.error.txt"
    assert diagnostic.exists()
    assert "JSONDecodeError" in diagnostic.read_text(encoding="utf-8")


def test_launch_error_path_is_confined_to_parent_diagnostic(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    missing_python = tmp_path / "private-python-name"
    bundle = tmp_path / "bundle"
    result = _run_summary(config, bundle, ledger, python=missing_python)
    assert result.returncode == 1
    assert result.stdout == ""
    assert str(missing_python) not in result.stderr
    assert "details in the bundle" in result.stderr
    diagnostic = (bundle / "bench.error.txt").read_text(encoding="utf-8")
    assert str(missing_python) in diagnostic


@pytest.mark.parametrize("salt", [None, "", "not-hex", "abcd"])
def test_missing_or_weak_ledger_salt_refuses_without_echo(tmp_path: Path, salt: str | None) -> None:
    config = tmp_path / "bench.toml"
    ledger = tmp_path / "private-ledger-name.toml"
    _write_config(config)
    if salt is None:
        text = _ledger_text().split("\n", 1)[1]
        ledger.write_text(text, encoding="utf-8")
    else:
        _write_ledger(ledger, salt)
    result = _run_summary(config, tmp_path / "bundle", ledger)
    assert result.returncode == 1
    assert result.stdout == ""
    assert str(ledger) not in result.stderr
    if salt:
        assert salt not in result.stderr
    assert not (tmp_path / "bundle").exists()


def test_argparse_error_does_not_echo_path_bearing_token(tmp_path: Path) -> None:
    secret = "--unknown=/private/synthetic-secret/conn.log"
    result = subprocess.run(
        [sys.executable, str(SUMMARIZER_PATH), secret],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "bench: invalid arguments\n"
    assert secret not in result.stderr


def test_bundle_inside_repository_refuses_without_echo(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    inside = ROOT / "synthetic-private-bundle"
    result = _run_summary(config, inside, ledger)
    assert result.returncode == 1
    assert result.stdout == ""
    assert str(inside) not in result.stderr
    assert not inside.exists()


def test_selector_normalization_collision_refuses_before_bundle(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    selectors = tmp_path / "private-selectors-name.json"
    entries = _selectors()
    entries[0]["example_id"] = "same\u0001"
    entries[1]["example_id"] = "same"
    _write_selectors(selectors, entries)
    result = _run_summary(config, tmp_path / "bundle", ledger, selectors=selectors)
    assert result.returncode == 1
    assert result.stdout == ""
    assert str(selectors) not in result.stderr
    assert not (tmp_path / "bundle").exists()


def test_two_run_exit_mismatch_emits_no_summary(tmp_path: Path) -> None:
    config, ledger = _minimal_inputs(tmp_path)
    fake = tmp_path / "fake-python"
    _fake_python(fake, _payload(), mismatch=True)
    bundle = tmp_path / "bundle"
    result = _run_summary(config, bundle, ledger, python=fake)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "runs disagreed" in result.stderr
    assert (bundle / "bench.error.txt").exists()
