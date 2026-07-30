"""Tests for the standalone privacy-bounded field-validation kit."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import stat
import sys
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import pytest

from sigwood import runner
from sigwood.common.finding import DetectorContext
from sigwood.common.loader import load_logs
from sigwood.detectors import aws, beacon, dns, duration, scan, syslog


ROOT = Path(__file__).resolve().parent.parent
FIELDKIT_PATH = ROOT / "tools" / "fieldkit.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("fieldkit_test", FIELDKIT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fieldkit = _load_script()


def _payload(marker: str = "HOSTILE_MARKER") -> dict[str, object]:
    return {
        "sigwood_version": "0.2.8",
        "schema_version": 1,
        "run_summary": {
            "data_window": [
                "2026-07-29T12:00:00+00:00",
                "2026-07-29T12:02:03+00:00",
            ],
            "record_counts": {
                "conn*.log*": 60,
                marker + "_pattern": 7,
            },
            "record_labels": {"conn*.log*": marker + "_label"},
            "data_size_bytes": 4096,
            "detectors_run": ["beacon", marker + "_run"],
            "detectors_skipped": {
                "duration": "conn logs not found",
                marker + "_skip_key": marker + "_skip_reason",
            },
            "detectors_failed": {
                "dns": "detector error - " + marker + "_failure",
                marker + "_fail_key": marker + "_failure",
            },
            "notes": [
                "beacon - " + marker + "_note",
                marker + "_unmatched_note",
            ],
            "data_sources": ["zeek_conn", marker + "_source"],
            "detector_methods": {"beacon": {"label": marker, "named": True}},
            "requested_span": 3600.0,
            "invocation": marker + "_invocation",
            "generated_at": "2026-07-29T12:00:00+00:00",
            "suppression": {
                "enabled": True,
                "connections": 1,
                "domains": 2,
                "connection_total": 60,
                "domain_total": 20,
                "host_rows": 3,
                "host_total": 4,
                "hosts_matched": 2,
            },
        },
        "findings": [
            {
                "detector": "beacon",
                "severity": "medium",
                "title": marker + "\u001b[31m\u0085_title",
                "description": marker + "_description",
                "next_steps": [marker + "_step"],
                "evidence": {
                    "beacon_score": 0.75,
                    "conn_count": 60,
                    "dominant_period": 175.0,
                    "span_seconds": 10325.0,
                    "cycles": 59.0,
                    "unknown_" + marker: 99,
                    "period_str": marker + "_evidence",
                    "first_seen": marker + "_first_seen",
                    "last_seen": marker + "_last_seen",
                    "registrable_domain": marker + "_domain",
                    "host": marker + "_host",
                    "program": marker + "_program",
                    "sample_raw": [marker + "_raw"],
                    "members": [{"title": marker + "_member"}],
                },
                "ts_generated": marker + "_generated",
                "data_window": [
                    marker + "_finding_start",
                    marker + "_finding_end",
                ],
            },
            {
                "detector": marker + "_detector",
                "severity": marker + "_severity",
                "title": marker + "_other_title",
                "description": marker,
                "next_steps": [marker],
                "evidence": {
                    marker + "_key": marker + "_value",
                    "direction": marker + "_enum",
                },
            },
        ],
    }


def _stub_sigwood(directory: Path, payload: object, *, version: str) -> Path:
    directory.mkdir()
    payload_path = directory / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    script = directory / "sigwood"
    script.write_text(
        "#!%s\n"
        "import json, pathlib, sys\n"
        "payload = pathlib.Path(%r)\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print(%r)\n"
        "    raise SystemExit(0)\n"
        "out = next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--out='))\n"
        "pathlib.Path(out).write_text(payload.read_text(encoding='utf-8'), encoding='utf-8')\n"
        "raise SystemExit(0)\n"
        % (sys.executable, str(payload_path), version),
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _machine_data(bundle: str) -> dict[str, object]:
    marker = "## machine data\n\n"
    tail = bundle.split(marker, 1)[1]
    lines = tail.splitlines()
    return json.loads("\n".join(lines[1:-1]))


def test_standalone_script_is_python39_syntax_and_has_no_product_or_network_imports() -> None:
    source = FIELDKIT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(FIELDKIT_PATH), feature_version=(3, 9))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not {name for name in imported if name == "sigwood" or name.startswith("sigwood.")}
    assert not imported.intersection(
        {"http", "http.client", "requests", "socket", "urllib", "urllib.request"}
    )


def test_literal_vocabulary_tables_match_live_available_detectors() -> None:
    modules = (aws, beacon, dns, duration, scan, syslog)
    assert fieldkit.DETECTOR_TOKENS == frozenset(
        module.DETECTOR_NAME for module in modules
    )
    patterns = {
        spec["pattern"]
        for module in modules
        for spec in [*module.REQUIRED_LOGS, *module.OPTIONAL_LOGS]
    }
    assert fieldkit.RECORD_PATTERN_TOKENS == frozenset(patterns)

    needed_logs = {
        "*.json*": "cloudtrail_dir",
        "*.log*": "journal",
        "conn*.log*": "zeek_dir",
        "dns*.log*": "zeek_dir",
        "pihole*.log*": "pihole_dir",
        "syslog*.log*": "zeek_dir",
    }
    expected_sources = set(
        runner._derive_data_sources(
            needed_logs,
            {pattern: 1 for pattern in needed_logs},
        )
    )
    expected_sources.update({"syslog_raw"})
    assert fieldkit.DATA_SOURCE_TOKENS == frozenset(expected_sources)


def test_real_protocol_adversarial_bundle_copies_no_hostile_report_string(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "HOSTILE_MARKER"
    bin_dir = tmp_path / "bin"
    _stub_sigwood(bin_dir, _payload(marker), version=marker + "\u001b[31m")
    monkeypatch.setenv("PATH", str(bin_dir))

    rc = fieldkit.main(
        ["--out=%s" % tmp_path, "--skip-smoke", "--no-triage"]
    )

    assert rc == 0
    bundles = list(tmp_path.glob("sigwood-field-report_*.md"))
    assert len(bundles) == 1
    raw = bundles[0].read_bytes()
    assert marker.encode() not in raw
    projection = _machine_data(raw.decode("utf-8"))
    assert projection["kit"]["sigwood_version"] is None
    assert projection["kit"]["version_unparsed"] is True
    assert projection["run_summary"]["record_counts"]["other"] == 7
    assert "other" in projection["findings"]["counts"]


def test_whitelist_types_and_identifier_buckets_are_fail_closed() -> None:
    raw = _payload()
    findings = raw["findings"]
    assert isinstance(findings, list)
    evidence = findings[0]["evidence"]
    assert isinstance(evidence, dict)
    evidence["conn_count"] = True
    evidence["cycles"] = "59"
    evidence["dominant_period"] = float("inf")

    projected, _ = fieldkit._project_findings(findings)

    numeric = projected["evidence"]["beacon"]["numeric"]
    assert "conn_count" not in numeric
    assert "cycles" not in numeric
    assert "dominant_period" not in numeric
    assert numeric["beacon_score"] == {
        "n": 1,
        "min": 0.75,
        "median": 0.75,
        "max": 0.75,
    }
    assert projected["counts"]["other"]["other"] == 1


def test_json_reader_rejects_nonfinite_constants(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"schema_version": 1, "value": NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite"):
        fieldkit._load_json(path)


@pytest.mark.parametrize("value", [True, 2, "1", None])
def test_schema_version_refusal_is_exact_and_non_bool(value: object) -> None:
    with pytest.raises(fieldkit.SchemaMismatch):
        fieldkit._validate_payload({"schema_version": value})


def test_schema_mismatch_refuses_without_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _payload()
    payload["schema_version"] = 2
    bin_dir = tmp_path / "bin"
    _stub_sigwood(bin_dir, payload, version="sigwood 0.2.8")
    monkeypatch.setenv("PATH", str(bin_dir))

    rc = fieldkit.main(
        ["--out=%s" % tmp_path, "--skip-smoke", "--no-triage"]
    )

    assert rc == 1
    assert list(tmp_path.glob("sigwood-field-report_*.md")) == []
    assert capsys.readouterr().err == (
        "this kit understands sigwood report schema 1 "
        + chr(0x2014)
        + " "
        "download the current kit from the repo\n"
    )


def test_data_window_span_accepts_real_feed_shape_and_python39_z_form() -> None:
    assert fieldkit._data_window_span(
        ["2026-07-29T12:00:00+00:00", "2026-07-29T12:02:03+00:00"]
    ) == 123.0
    assert fieldkit._data_window_span(
        ["2026-07-29T12:00:00Z", "2026-07-29T12:02:03Z"]
    ) == 123.0
    assert fieldkit._data_window_span(
        ["2026-07-29T12:00:00Z", "not-a-time"]
    ) is None


def test_classifier_buckets_never_copy_source_text() -> None:
    marker = "private-marker"
    assert fieldkit._classify_skip("zeek_dir not configured") == "not_configured"
    assert fieldkit._classify_skip("conn*.log* not found") == "not_found"
    assert fieldkit._classify_skip("out of scope") == "scope"
    assert fieldkit._classify_skip("import failed - dependency") == "import_failed"
    assert fieldkit._classify_skip(marker) == "other"
    assert fieldkit._classify_failure("prep error - " + marker) == "prep"
    assert fieldkit._classify_failure("detector error - " + marker) == "detector"
    assert fieldkit._classify_failure(marker) == "other"
    assert fieldkit._classify_note("beacon - " + marker) == "beacon"
    assert fieldkit._classify_note(marker) == "other"


def test_smoke_corpus_is_deterministic_and_fires_real_beacon(tmp_path: Path) -> None:
    first = fieldkit.generate_smoke_corpus()
    second = fieldkit.generate_smoke_corpus()
    assert first == second
    source = tmp_path / "conn.log"
    source.write_bytes(first)

    frame = load_logs(tmp_path, "conn*.log*")
    window = (
        datetime.fromtimestamp(float(frame["ts"].min()), tz=timezone.utc),
        datetime.fromtimestamp(float(frame["ts"].max()), tz=timezone.utc),
    )
    findings = beacon.run(
        DetectorContext(
            logs={"conn*.log*": frame},
            config=dict(beacon.DEFAULT_CONFIG),
            allowlist=None,
            data_window=window,
        )
    )
    assert any(finding.detector == "beacon" for finding in findings)


class _NonTTY:
    def isatty(self) -> bool:
        return False


class _TTY:
    def isatty(self) -> bool:
        return True


def test_non_tty_skips_triage_and_questions_without_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_input(prompt: str = "") -> str:
        raise AssertionError(prompt)

    monkeypatch.setattr("builtins.input", forbidden_input)
    findings = [{"detector": "beacon", "severity": "medium", "title": "private"}]

    triage, answers = fieldkit._triage(findings, no_triage=False, stdin=_NonTTY())

    assert triage == {
        "ran": False,
        "skip_reason": "non_tty",
        "reviewed": 0,
        "items": [],
        "untriaged": {"medium": 1},
    }
    assert answers == {"missed": "", "confusing": "", "monthly": ""}


def test_eof_at_triage_stops_and_still_writes_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bin_dir = tmp_path / "bin"
    _stub_sigwood(bin_dir, _payload("DROP_EOF"), version="sigwood 0.2.8")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setattr(fieldkit.sys, "stdin", _TTY())
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt="": (_ for _ in ()).throw(EOFError(prompt)),
    )

    assert fieldkit.main(["--out=%s" % tmp_path, "--skip-smoke"]) == 0

    bundle = next(tmp_path.glob("sigwood-field-report_*.md")).read_text(
        encoding="utf-8"
    )
    projection = _machine_data(bundle)
    assert projection["triage"]["stopped_early"] is True
    assert projection["triage"]["reviewed"] == 0
    assert projection["triage"]["untriaged"] == {"medium": 1, "other": 1}
    assert projection["answers"] == {"missed": "", "confusing": "", "monthly": ""}
    assert "Traceback" not in capsys.readouterr().err


def test_eof_at_answers_uses_empty_answers_and_still_writes_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _payload("DROP_ANSWERS")
    findings = payload["findings"]
    assert isinstance(findings, list)
    payload["findings"] = findings[:1]
    bin_dir = tmp_path / "bin"
    _stub_sigwood(bin_dir, payload, version="sigwood 0.2.8")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setattr(fieldkit.sys, "stdin", _TTY())
    responses = iter(["k"])

    def answer_or_eof(prompt: str = "") -> str:
        try:
            return next(responses)
        except StopIteration as exc:
            raise EOFError(prompt) from exc

    monkeypatch.setattr("builtins.input", answer_or_eof)

    assert fieldkit.main(["--out=%s" % tmp_path, "--skip-smoke"]) == 0

    bundle = next(tmp_path.glob("sigwood-field-report_*.md")).read_text(
        encoding="utf-8"
    )
    projection = _machine_data(bundle)
    assert projection["triage"]["reviewed"] == 1
    assert projection["triage"]["items"][0]["verdict"] == "known_benign"
    assert projection["answers"] == {"missed": "", "confusing": "", "monthly": ""}
    assert "Traceback" not in capsys.readouterr().err


def test_skip_verdict_is_reviewed_and_not_untriaged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(["s", "", "", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(responses))
    findings = [{"detector": "beacon", "severity": "medium", "title": "private"}]

    triage, _answers = fieldkit._triage(
        findings,
        no_triage=False,
        stdin=_TTY(),
    )

    assert triage["reviewed"] == 1
    assert triage["items"] == [
        {
            "index": 1,
            "detector": "beacon",
            "severity": "medium",
            "verdict": "skip",
        }
    ]
    assert triage["untriaged"] == {}


def test_title_sanitizer_removes_full_control_class_and_truncates() -> None:
    hostile = "a\u0000b\u001bc\u007fd\u0085e\udc80f" + ("z" * 200)
    rendered = fieldkit._render_title(hostile)
    assert all(
        not (ord(char) < 0x20 or ord(char) == 0x7F or 0x80 <= ord(char) <= 0x9F)
        for char in rendered
    )
    assert not any(0xDC80 <= ord(char) <= 0xDCFF for char in rendered)
    assert len(rendered) == 160


def _projection() -> dict[str, object]:
    payload = fieldkit._validate_payload(_payload("DROP_ME"))
    findings, local = fieldkit._project_findings(payload["findings"])
    assert findings is not None and local
    return fieldkit._projection(
        generated_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
        version="0.2.8",
        version_unparsed=False,
        smoke={"ran": True, "passed": True},
        hunt_exit_code=0,
        hunt_wall_seconds=1.25,
        peak_child_rss_mb=12.5,
        payload=payload,
        triage={
            "ran": False,
            "skip_reason": "non_tty",
            "reviewed": 0,
            "items": [],
            "untriaged": {"medium": 1},
        },
        answers={"missed": "", "confusing": "", "monthly": ""},
    )


def test_bundle_is_0600_and_collision_uses_exclusive_suffix(tmp_path: Path) -> None:
    projection = _projection()
    first_state = fieldkit.ProtocolState()
    second_state = fieldkit.ProtocolState()

    first = fieldkit.write_bundle(projection, tmp_path, first_state)
    second = fieldkit.write_bundle(projection, tmp_path, second_state)

    assert first.name == "sigwood-field-report_20260730.md"
    assert second.name == "sigwood-field-report_20260730-1.md"
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert stat.S_IMODE(second.stat().st_mode) == 0o600


def test_injected_write_failure_removes_reserved_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fdopen = os.fdopen

    class BrokenWriter:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def write(self, value: str) -> None:
            del value
            raise OSError("injected")

    def broken_fdopen(*args, **kwargs):
        descriptor = args[0]
        os.close(descriptor)
        return BrokenWriter()

    monkeypatch.setattr(fieldkit.os, "fdopen", broken_fdopen)
    state = fieldkit.ProtocolState()

    with pytest.raises(OSError, match="injected"):
        fieldkit.write_bundle(_projection(), tmp_path, state)

    assert list(tmp_path.glob("sigwood-field-report_*.md")) == []
    assert state.bundle_path is None
    monkeypatch.setattr(fieldkit.os, "fdopen", real_fdopen)


def test_missing_hunt_report_continues_with_null_report_sections(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "sigwood"
    script.write_text(
        "#!%s\n"
        "import sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('sigwood 0.2.8')\n"
        "raise SystemExit(0)\n" % sys.executable,
        encoding="utf-8",
    )
    script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))

    assert fieldkit.main(
        ["--out=%s" % tmp_path, "--skip-smoke", "--no-triage"]
    ) == 0
    bundle = next(tmp_path.glob("sigwood-field-report_*.md")).read_text(
        encoding="utf-8"
    )
    projection = _machine_data(bundle)
    assert projection["run_summary"] is None
    assert projection["findings"] is None


def test_non_mapping_hunt_report_continues_with_null_report_sections(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    _stub_sigwood(bin_dir, ["parseable", "but", "not", "a", "report"], version="sigwood 0.2.8")
    monkeypatch.setenv("PATH", str(bin_dir))

    assert fieldkit.main(
        ["--out=%s" % tmp_path, "--skip-smoke", "--no-triage"]
    ) == 0
    bundle = next(tmp_path.glob("sigwood-field-report_*.md")).read_text(
        encoding="utf-8"
    )
    projection = _machine_data(bundle)
    assert projection["run_summary"] is None
    assert projection["findings"] is None


def test_undecodable_version_output_records_unparsed_and_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    payload_path = bin_dir / "payload.json"
    payload_path.write_text(json.dumps(_payload("DROP_VERSION")), encoding="utf-8")
    script = bin_dir / "sigwood"
    script.write_text(
        "#!%s\n"
        "import pathlib, sys\n"
        "payload = pathlib.Path(%r)\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    sys.stdout.buffer.write(b'sigwood \\xff\\n')\n"
        "    raise SystemExit(0)\n"
        "out = next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--out='))\n"
        "pathlib.Path(out).write_text(payload.read_text(encoding='utf-8'), encoding='utf-8')\n"
        "raise SystemExit(0)\n"
        % (sys.executable, str(payload_path)),
        encoding="utf-8",
    )
    script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))

    assert fieldkit.main(
        ["--out=%s" % tmp_path, "--skip-smoke", "--no-triage"]
    ) == 0
    bundle = next(tmp_path.glob("sigwood-field-report_*.md")).read_text(
        encoding="utf-8"
    )
    projection = _machine_data(bundle)
    assert projection["kit"]["sigwood_version"] is None
    assert projection["kit"]["version_unparsed"] is True


def test_rendered_prose_and_machine_data_share_one_count() -> None:
    rendered = fieldkit.render_bundle(_projection())
    projection = _machine_data(rendered)
    count = projection["run_summary"]["record_counts"]["conn*.log*"]
    assert "| records: conn*.log* | %d |" % count in rendered


def test_machine_data_fence_outgrows_answer_backticks() -> None:
    projection = _projection()
    projection["answers"]["missed"] = "``````"
    rendered = fieldkit.render_bundle(projection)
    tail = rendered.split("## machine data\n\n", 1)[1]
    fence = tail.splitlines()[0]
    assert fence == "```````json"
