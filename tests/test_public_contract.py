"""Executable inventory for the public sigwood 1.x contract."""

from __future__ import annotations

import copy
import csv
import inspect
import io
import json
import re
import subprocess
import sys
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

import sigwood
import sigwood.cli as cli
import sigwood.common.allowlist as allowlist
import sigwood.common.config as config
import sigwood.common.output as output
import sigwood.runner as runner
from sigwood import DetectorContext, Finding, Severity
from sigwood.common.errors import ExportAborted
from sigwood.common.finding import MethodTag, RunSummary, SuppressionSummary
from sigwood.outputs.csv import CsvHandler, _FIELDNAMES
from sigwood.outputs.json import JsonHandler, _SCHEMA_VERSION
from sigwood.outputs._sanitize import strip_control_keep_newlines


_NOW = datetime(2026, 8, 1, 6, 0, 1, tzinfo=timezone.utc)
_WINDOW = (
    datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc),
    datetime(2026, 8, 1, 6, 0, tzinfo=timezone.utc),
)

_VERBS = {
    "allowlist", "auth", "aws", "beacon", "digest", "dns", "exfil",
    "export", "graph", "hunt", "init", "scan", "syslog",
}
_FORMATS = {"csv", "html", "json", "pdf", "text"}
_FLAGS = (
    ("--help", "-h", False, ""),
    ("--version", "-V", False, ""),
    ("--verbose", "-v", False, ""),
    ("--yes", "-y", False, ""),
    ("--all", "-a", False, ""),
    ("--quiet", "-q", False, ""),
    ("--out", "-o", True, "PATH"),
    ("--config", "-c", True, "FILE"),
    ("--since", "-s", True, "DURATION|DATE"),
    ("--detect", "-d", True, "LIST"),
    ("--dry-run", None, False, ""),
    ("--no-allowlist", None, False, ""),
    ("--format", "-f", True, "FORMAT"),
    ("--until", None, True, "DATE"),
    ("--days", None, True, "N-M"),
    ("--hours", None, True, "N-M"),
    ("--utc", None, False, ""),
    ("--zeek-dir", None, True, "PATH"),
    ("--pihole-dir", None, True, "PATH"),
    ("--syslog-dir", None, True, "PATH"),
    ("--syslog-source", None, True, "MODE"),
    ("--cloudtrail-dir", None, True, "PATH"),
)
_CSV_HEADER = [
    "severity", "detector", "finding", "next_steps", "description",
    "signals", "data_window_start", "data_window_end", "status", "notes",
]
_RUN_SUMMARY_KEYS = {
    "data_window", "record_counts", "record_labels", "data_size_bytes",
    "detectors_run", "detectors_skipped", "detectors_failed", "notes",
    "data_sources", "detector_methods", "requested_span", "suppression",
    "invocation", "generated_at",
}
_FINDING_JSON_KEYS = {
    "detector", "severity", "title", "description", "next_steps",
    "evidence", "ts_generated", "data_window",
}
_SUPPRESSION_KEYS = {
    "enabled", "connections", "domains", "connection_total", "domain_total",
    "host_rows", "host_total", "hosts_matched",
}


def _finding(*, title: str = "192.0.2.10 → 198.51.100.20:443/tcp") -> Finding:
    return Finding(
        detector="beacon",
        severity=Severity.MEDIUM,
        title=title,
        description="The regular cadence of an automated check-in.",
        evidence={"first_seen": _WINDOW[0].isoformat(), "conn_count": 480},
        next_steps=["Check expected.example", "Review the connection history"],
        ts_generated=_NOW,
        data_window=_WINDOW,
    )


def _summary(*, nullable: bool = False) -> RunSummary:
    return RunSummary(
        data_window=None if nullable else _WINDOW,
        record_counts={"conn*.log*": 12_345},
        record_labels={"conn*.log*": "connections"},
        data_size_bytes=480_000,
        detectors_run=["beacon", "dns"],
        detectors_skipped={},
        detectors_failed={},
        notes=[],
        data_sources=["zeek_conn"],
        detector_methods={
            "beacon": MethodTag("FFT", True),
            "dns": None,
        },
        requested_span=None if nullable else timedelta(days=7),
        suppression=(
            None
            if nullable
            else SuppressionSummary(
                enabled=True,
                connections=0,
                domains=0,
                connection_total=12_345,
                domain_total=0,
                host_rows=0,
                host_total=0,
                hosts_matched=0,
            )
        ),
        invocation=None if nullable else "sigwood hunt --format=json",
        generated_at=None if nullable else _NOW,
    )


def _json_payload(*, nullable: bool = False) -> dict[str, object]:
    stream = io.StringIO()
    handler = JsonHandler(stream=stream)
    handler.begin(_summary(nullable=nullable))
    handler.write([_finding()])
    handler.end()
    payload = json.loads(stream.getvalue())
    assert isinstance(payload, dict)
    return payload


def test_root_exports_and_unsuppressed_signature() -> None:
    assert sigwood.DetectorContext is DetectorContext
    assert sigwood.Finding is Finding
    assert sigwood.Severity is Severity

    signature = inspect.signature(DetectorContext.unsuppressed)
    assert list(signature.parameters) == [
        "logs", "data_window", "config", "data_sources", "home_net",
    ]
    assert signature.parameters["logs"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert signature.parameters["data_window"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["data_window"].default is inspect.Parameter.empty
    assert signature.parameters["config"].default is None
    assert signature.parameters["data_sources"].default == ()
    assert signature.parameters["home_net"].default == ()


def test_unsuppressed_context_uses_fresh_defaults_and_a_real_empty_matcher() -> None:
    frames = {
        "conn*.log*": pd.DataFrame({
            "src": ["192.0.2.10"],
            "dst": ["198.51.100.20"],
            "port": [443],
            "proto": ["tcp"],
        }),
        "dns*.log*": pd.DataFrame({
            "query": ["telemetry.example"],
            "src": ["192.0.2.10"],
        }),
        "*.log*": pd.DataFrame({
            "host": ["host.example"],
            "message": ["example service started"],
        }),
    }
    first = DetectorContext.unsuppressed(frames, data_window=_WINDOW)
    second = DetectorContext.unsuppressed(frames, data_window=_WINDOW)

    assert isinstance(first.allowlist, allowlist.AllowlistMatcher)
    assert first.logs is frames
    assert first.config == {} and first.config is not second.config
    assert first.data_sources == [] and first.data_sources is not second.data_sources
    assert first.home_net == [] and first.home_net is not second.home_net
    for frame in frames.values():
        pd.testing.assert_frame_equal(first.allowlist.filter_df(frame, "beacon"), frame)


def test_all_available_detectors_run_on_an_empty_unsuppressed_context() -> None:
    context = DetectorContext.unsuppressed({}, data_window=_WINDOW)
    for name in sorted({
        "auth", "aws", "beacon", "dns", "exfil", "scan", "syslog",
    }):
        run = import_module(f"sigwood.detectors.{name}").run
        result = run(context)
        assert isinstance(result, list), name
        assert all(isinstance(item, Finding) for item in result), name


def test_bare_root_import_does_not_load_pandas(tmp_path: Path) -> None:
    script = (
        "import sys, sigwood; "
        "from sigwood import DetectorContext, Finding, Severity; "
        "assert pandas not in sys.modules"
    ).replace("pandas", repr("pandas"))
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_finding_and_severity_inventory() -> None:
    assert [item.name for item in fields(Finding)] == [
        "detector", "severity", "title", "description", "evidence",
        "next_steps", "ts_generated", "data_window",
    ]
    assert [(member.name, member.value) for member in Severity] == [
        ("HIGH", "H"), ("MEDIUM", "M"), ("LOW", "L"), ("INFO", "I"),
    ]


def test_cli_inventory_is_derived_from_the_owning_specs() -> None:
    assert set(cli._VERBS) == _VERBS
    observed = tuple(
        (
            spec.long,
            None if spec.short is None else f"-{spec.short}",
            spec.takes_value,
            spec.metavar,
        )
        for spec in cli._FLAG_LIST
    )
    assert observed == _FLAGS
    assert [short for _long, short, _takes, _meta in observed if short] == [
        "-h", "-V", "-v", "-y", "-a", "-q", "-o", "-c", "-s", "-d", "-f",
    ]


def test_syslog_source_is_allowed_for_both_local_lane_detector_verbs() -> None:
    assert {
        name
        for name in cli._SINGLE_DETECTOR_COMMANDS
        if "syslog_source" in cli._VERBS[name].allowed
    } == {"auth", "syslog"}


def test_contract_page_tracks_the_atomic_auth_surface_inventory() -> None:
    contract = (
        Path(__file__).resolve().parents[1] / "docs" / "CONTRACT.md"
    ).read_text(encoding="utf-8")

    assert "Thirteen, all of which stay recognized:" in contract
    assert "`hunt` · `auth` · `beacon`" in contract
    assert "The seven callable detectors are `auth`, `aws`, `beacon`" in contract
    assert "exactly `auth` and `syslog` own the local system-log lane" in contract
    assert "## Exfil measured evidence" in contract
    assert "They are not a claim about\nunmeasured rows for the same pair." in contract


def test_cli_value_grammar_and_duplicate_semantics() -> None:
    assert cli._parse_args(["--out=first", "--out=second"], "hunt")["out"] == "second"
    assert cli._parse_args(["-o=report.txt"], "hunt")["out"] == "report.txt"
    for args in (["--out", "report.txt"], ["-oreport.txt"], ["-vy"]):
        with pytest.raises(cli.UsageError):
            cli._parse_args(list(args), "hunt")
    with pytest.raises(cli.UsageError):
        cli._parse_args(["--quiet=true"], "hunt")
    assert cli._resolve_verbose_level(cli._parse_args(["-v", "-vv"], "hunt")) == 2
    assert cli._resolve_verbose_level(cli._parse_args(["-vv", "-v"], "hunt")) == 2


def test_output_format_inventory_comes_from_lazy_registration(monkeypatch: pytest.MonkeyPatch) -> None:
    imported: list[str] = []
    monkeypatch.setattr(output.importlib, "import_module", imported.append)
    output.register_builtin_handlers()
    assert {name.rsplit(".", 1)[-1] for name in imported} == _FORMATS


def test_pdf_is_a_registered_token_without_preflighting_the_native_stack() -> None:
    handler = output.get_handler("pdf")
    assert issubclass(handler, output.OutputHandler)
    assert handler.__module__ == "sigwood.outputs.pdf"


def test_json_producer_inventory_and_nested_types_are_exact() -> None:
    payload = _json_payload()
    assert set(payload) == {"sigwood_version", "schema_version", "run_summary", "findings"}
    assert payload["schema_version"] == _SCHEMA_VERSION == 1

    summary = payload["run_summary"]
    assert isinstance(summary, dict)
    assert set(summary) == _RUN_SUMMARY_KEYS
    assert type(summary["data_window"]) is list
    assert type(summary["record_counts"]) is dict
    assert type(summary["record_labels"]) is dict
    assert type(summary["data_size_bytes"]) is int
    assert type(summary["detectors_run"]) is list
    assert type(summary["detectors_skipped"]) is dict
    assert type(summary["detectors_failed"]) is dict
    assert type(summary["notes"]) is list
    assert type(summary["data_sources"]) is list
    assert type(summary["detector_methods"]) is dict
    assert type(summary["requested_span"]) is float
    assert type(summary["invocation"]) is str
    assert type(summary["generated_at"]) is str
    assert type(summary["suppression"]) is dict

    methods = summary["detector_methods"]
    assert methods["dns"] is None
    assert set(methods["beacon"]) == {"label", "named"}
    assert type(methods["beacon"]["label"]) is str
    assert type(methods["beacon"]["named"]) is bool
    suppression = summary["suppression"]
    assert set(suppression) == _SUPPRESSION_KEYS
    assert type(suppression["enabled"]) is bool
    assert all(type(suppression[key]) is int for key in _SUPPRESSION_KEYS - {"enabled"})

    finding = payload["findings"][0]
    assert set(finding) == _FINDING_JSON_KEYS
    assert finding["severity"] == "medium"
    assert type(finding["detector"]) is str
    assert type(finding["title"]) is str
    assert type(finding["description"]) is str
    assert type(finding["next_steps"]) is list
    assert type(finding["evidence"]) is dict
    assert type(finding["ts_generated"]) is str
    assert type(finding["data_window"]) is list
    for value in [finding["ts_generated"], *finding["data_window"], *summary["data_window"]]:
        parsed = datetime.fromisoformat(value)
        assert parsed.utcoffset() == timedelta(0)


def test_json_nullable_arms_are_explicit() -> None:
    summary = _json_payload(nullable=True)["run_summary"]
    assert isinstance(summary, dict)
    assert {
        key for key, value in summary.items() if value is None
    } == {"data_window", "requested_span", "suppression", "invocation", "generated_at"}
    assert summary["detector_methods"] == {
        "beacon": {"label": "FFT", "named": True},
        "dns": None,
    }


def test_json_consumer_shape_tolerates_additive_fields() -> None:
    payload = copy.deepcopy(_json_payload())
    payload["future_top_level"] = {"version": 2}
    payload["run_summary"]["future_summary_field"] = [1, 2, 3]
    payload["findings"][0]["future_finding_field"] = True
    payload["findings"][0]["evidence"]["future_evidence_field"] = "open"

    assert {"sigwood_version", "schema_version", "run_summary", "findings"} <= payload.keys()
    assert _RUN_SUMMARY_KEYS <= payload["run_summary"].keys()
    assert _FINDING_JSON_KEYS <= payload["findings"][0].keys()
    assert payload["findings"][0]["evidence"]["first_seen"] == _WINDOW[0].isoformat()


def test_csv_producer_header_control_and_formula_contract() -> None:
    assert _FIELDNAMES == _CSV_HEADER
    stream = io.StringIO()
    handler = CsvHandler(stream=stream)
    finding = _finding(title="\x1b=SUM(1,1)\x7f\x85")
    finding.next_steps = ["first line", "second line"]
    handler.begin(_summary())
    handler.write([finding])
    handler.end()

    rows = list(csv.DictReader(io.StringIO(stream.getvalue())))
    assert list(rows[0]) == _CSV_HEADER
    assert rows[0]["finding"] == "'=SUM(1,1)"
    assert rows[0]["next_steps"] == "first line\nsecond line"
    assert strip_control_keep_newlines("a\n\x00\x1f\x7f\x80\x9fb") == "a\nb"


def test_documented_config_key_inventory_is_not_defaults_only() -> None:
    # The contract boundary is DOCUMENTED, not merely DEFAULTED. report_dir and
    # the export_dir/query leaves intentionally live only in the shipped example.
    sigwood_keys = set(config._DEFAULTS["sigwood"]) | {"report_dir"}
    assert sigwood_keys == {
        "root", "detect", "zeek_dir", "syslog_dir", "syslog_source",
        "pihole_dir", "cloudtrail_dir", "home_net", "export_dir", "report_dir",
        "output_format", "warn_above", "default_window", "quiet", "use_utc",
        "max_findings_per_detector",
    }

    expected_detectors = {
        "aws": {
            "min_events", "min_scorable_principals", "burst_gap_seconds",
            "burst_window_edge_margin_seconds", "burst_min_firsts",
            "burst_high_error_rate", "burst_high_service_count",
            "composite_medium_threshold", "composite_low_threshold",
        },
        "beacon": {"bin_seconds", "min_connections", "threshold"},
        "dns": {
            "min_cluster_size", "min_samples", "threshold", "thresh_high_entropy",
            "scan_dense_clusters", "scan_min_high_entropy_fraction",
            "scan_min_cluster_members", "scan_min_regdomain_share",
            "scan_max_members_per_cluster", "promote_below_gate",
            "promote_min_subdomains", "promote_min_nxdomain_fraction",
        },
        "exfil": {"min_outbound_bytes", "min_orig_share"},
        "scan": {
            "window_secs", "horizontal_threshold", "vertical_threshold",
            "block_host_threshold", "block_port_threshold", "block_state_min",
            "slow_min_ports", "slow_min_buckets", "slow_state_min",
        },
        "syslog": {
            "rarity_pct", "max_count", "depth", "sim_thresh", "parametrize_numeric",
            "line_trim_limit", "burst_gap_seconds", "burst_min_size",
            "family_min_size", "reboot_cluster_seconds", "recognize_transactions",
            "privileged_programs",
        },
    }
    for name, expected in expected_detectors.items():
        defaults = copy.deepcopy(import_module(f"sigwood.detectors.{name}").DEFAULT_CONFIG)
        if name == "dns":
            assert set(defaults.pop("pihole")) == {"min_cluster_size", "min_samples"}
        assert set(defaults) == expected, name

    assert set(config._DEFAULTS["allowlist"]) == {
        "enabled", "allowlist_dir", "domain_patterns", "connection_rules",
    }
    assert {"common", "devices", "homelab"} <= {
        spec.name for spec in allowlist._SHIPPED_LISTS
    }
    assert set(config._DEFAULTS["graph"]) == {
        "target_bins", "top_hosts", "top_services", "domain_level",
    }
    assert set(config._DEFAULTS["export"]["splunk"]) | {"export_dir"} == {
        "host", "port", "username", "password", "verify_tls", "export_dir",
    }
    assert set(config._DEFAULTS["export"]["cloudtrail"]) | {"export_dir"} == {
        "path", "egress_warn_gb", "export_dir",
    }
    example = (
        Path(config.__file__).resolve().parents[1] / "data" / "config_example.toml"
    ).read_text(encoding="utf-8")
    for key in {"spl", "output_basename", "export_dir"}:
        assert re.search(rf"^# {key}\s*=", example, flags=re.MULTILINE), key
    assert "[export.cloudtrail.query." not in example


def test_allowlist_entry_base_keys_and_behavior_bearing_match_kinds() -> None:
    pair = allowlist._entry_from_raw(
        {
            "match": "ip_pair",
            "comment": "example pair",
            "detectors": ["beacon"],
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "dst_port": 443,
            "future_metadata": "preserved",
        },
        where="contract fixture",
    )
    pair_rule = allowlist._stanza_to_numeric_rule(pair)
    assert pair.match == "ip_pair"
    assert pair.comment == "example pair"
    assert pair.detectors == ["beacon"]
    assert pair.extra["future_metadata"] == "preserved"
    assert (pair_rule.ip1, pair_rule.ip2, pair_rule.port) == (
        "192.0.2.10", "198.51.100.20", 443,
    )

    port = allowlist._entry_from_raw(
        {"match": "dst_port", "value": 53},
        where="contract fixture",
    )
    port_rule = allowlist._stanza_to_numeric_rule(port)
    assert port.match == "dst_port"
    assert port_rule.port == 53


def test_exit_code_inventory_and_confirmation_decline_is_zero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli._SIGINT_EXIT_CODE == 130
    assert cli._SIGPIPE_EXIT_CODE == 141

    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    def decline(_argv: list[str] | None) -> int:
        runner._confirm_large_dataset(2, {"warn_above": 1}, skip_confirm=False)
        return 1  # pragma: no cover - the real gate raises before this point

    monkeypatch.setattr(cli, "_main", decline)
    with pytest.raises(SystemExit) as caught:
        cli.main([])
    assert caught.value.code == 0
    assert capsys.readouterr().out == "sigwood: aborted by user\n"

    monkeypatch.setattr(cli, "_main", lambda _argv: (_ for _ in ()).throw(ValueError("bad")))
    with pytest.raises(SystemExit) as caught:
        cli.main([])
    assert caught.value.code == 1


def _assert_aware_iso(value: object) -> None:
    assert isinstance(value, str)
    assert datetime.fromisoformat(value).utcoffset() is not None


def test_event_time_contract_uses_current_finding_producers() -> None:
    beacon = import_module("sigwood.detectors.beacon")
    dns = import_module("sigwood.detectors.dns")
    exfil = import_module("sigwood.detectors.exfil")
    aws = import_module("sigwood.detectors.aws")
    scan = import_module("sigwood.detectors.scan")
    syslog_detector = import_module("sigwood.detectors.syslog")

    beacon_finding = beacon._make_finding(
        "192.0.2.10",
        "198.51.100.20",
        443,
        "tcp",
        {
            "beacon_score": 0.5,
            "dominant_period": 60.0,
            "dominant_period_m": 1.0,
            "conn_count": 20,
        },
        pd.DataFrame({"bytes": [100]}),
        _WINDOW,
        beacon._event_time_evidence(60.0, 120.0),
    )
    assert {"first_seen", "last_seen", "span_seconds", "cycles"} <= beacon_finding.evidence.keys()
    _assert_aware_iso(beacon_finding.evidence["first_seen"])
    _assert_aware_iso(beacon_finding.evidence["last_seen"])

    group_finding = dns._make_group_finding(
        "example.com",
        pd.DataFrame({
            "source": ["zeek", "zeek"],
            "label_entropy": [2.0, 1.9],
            "query_count": [1, 1],
            "querier_ips": [["192.0.2.10"], ["192.0.2.11"]],
            "query": ["a.example.com", "b.example.com"],
            "first_ts": [60.0, 90.0],
            "last_ts": [70.0, 120.0],
            "has_public_suffix": [True, True],
        }),
        _NOW,
        _WINDOW,
    )
    singleton_finding = dns._make_singleton_finding(
        pd.Series({
            "source": "zeek",
            "query": "one.example.com",
            "label_entropy": 2.0,
            "query_count": 1,
            "unique_sources": 1,
            "querier_ips": ["192.0.2.10"],
            "rcode_distribution": {},
            "has_public_suffix": True,
            "first_ts": 60.0,
            "last_ts": 60.0,
        }),
        "example.com",
        _NOW,
        _WINDOW,
    )
    for finding in (group_finding, singleton_finding):
        assert {"first_seen", "last_seen", "span_seconds"} <= finding.evidence.keys()
        _assert_aware_iso(finding.evidence["first_seen"])

    exfil_context = DetectorContext.unsuppressed(
        {"conn*.log*": pd.DataFrame({
            "src": ["10.0.0.10"],
            "dst": ["198.51.100.20"],
            "port": [443],
            "proto": ["tcp"],
            "duration": [3600.0],
            "ts": [60.0],
            "bytes": [1 << 30],
            "resp_bytes": [1],
            "local_orig": [True],
        })},
        data_window=_WINDOW,
    )
    exfil_finding = exfil.run(exfil_context)[0]
    assert {"first_seen", "last_seen", "span_seconds"} <= exfil_finding.evidence.keys()
    _assert_aware_iso(exfil_finding.evidence["first_seen"])
    _assert_aware_iso(exfil_finding.evidence["last_seen"])

    rows = [
        SimpleNamespace(
            ts=60.0 + offset,
            raw=f"example service event {offset}",
            program="exampled",
            template_id=offset,
            message=f"example service event {offset}",
        )
        for offset in range(2)
    ]
    burst_pair = syslog_detector._burst_finding("host.example", rows, _NOW, _WINDOW)
    syslog_detector._decorate_burst_first_seen([burst_pair])
    burst_finding = burst_pair[1]
    family_finding = syslog_detector._collapse_families(
        pd.DataFrame({
            "host": ["host.example", "host.example"],
            "program": ["exampled", "exampled"],
            "ts": [60.0, 61.0],
            "raw": ["example one", "example two"],
            "message": ["example one", "example two"],
            "template_id": [1, 2],
        }),
        {1: 1, 2: 1},
        1,
        min_size=2,
        now=_NOW,
        data_window=_WINDOW,
        severity=Severity.LOW,
        privileged=False,
        program_totals={("host.example", "exampled"): 2},
    )[0][1]
    single_finding = syslog_detector._isolated_finding(
        "host.example",
        SimpleNamespace(
            ts=60.0,
            raw="example isolated line",
            program="exampled",
            template_id=1,
            template_str="example <*> line",
        ),
        {1: 1},
        1,
        _NOW,
        _WINDOW,
        severity=Severity.LOW,
        privileged=False,
        program_total=1,
    )[1]
    reboot_finding = syslog_detector._reboot_finding(
        syslog_detector._BootEvent("host.example", 60.0, 61.0, 2),
        _NOW,
        _WINDOW,
    )[1]
    transaction_finding = syslog_detector._transaction_finding(
        syslog_detector._TransactionEvent(
            "admin session", "host.example", 60.0, 120.0, 30.0, 150.0, (60.0, 120.0),
        ),
        [family_finding, single_finding],
        _NOW,
        _WINDOW,
    )[1]
    for finding in (family_finding, burst_finding, single_finding, transaction_finding):
        assert "first_seen" in finding.evidence
        _assert_aware_iso(finding.evidence["first_seen"])
    assert "reboot_ts" in reboot_finding.evidence
    _assert_aware_iso(reboot_finding.evidence["reboot_ts"])

    aws_burst = aws._make_burst_finding(
        {
            "principal": "analyst@example.test",
            "start_time": "1970-01-01T00:01:00+00:00",
            "start_ts": 60.0,
            "span_seconds": 30.0,
            "new_action_count": 3,
            "new_service_count": 1,
            "error_rate": 0.0,
            "mean_rarity": 1.0,
            "new_actions": ["A", "B", "C"],
            "new_services": ["service.example"],
            "source_ips": ["192.0.2.10"],
            "aws_regions": ["us-east-1"],
            "sample_event_ids": ["example-event"],
        },
        0.5,
        3,
        300,
        _NOW,
        _WINDOW,
    )
    assert "start_time" in aws_burst.evidence
    assert "start_ts" not in aws_burst.evidence
    _assert_aware_iso(aws_burst.evidence["start_time"])

    scan_finding = scan._make_finding(
        {
            "scan_type": "vertical",
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "port": None,
            "distinct_ports": 20,
            "distinct_hosts": 1,
            "total_conns": 20,
            "scan_state_ratio": 0.7,
            "top_states": "S0",
            "direction": "internal→external",
            "pattern_tag": "confirmed_scan",
            "window_start": "2026-08-01 00:00:00",
            "window_secs": 3600,
            "_severity": Severity.HIGH,
        },
        _WINDOW,
    )
    assert scan_finding.evidence["window_start"] == "2026-08-01 00:00:00"
    assert datetime.fromisoformat(scan_finding.evidence["window_start"]).tzinfo is None

    aws_summary = aws._make_ranked_summary_finding(
        pd.DataFrame(), _NOW, _WINDOW, population_floor=5,
    )
    dns_summary = dns._make_scan_summary_finding(
        pd.DataFrame({
            "dense_cluster_id": [1],
            "label_entropy": [2.0],
            "cluster_true_member_count": [100],
            "registrable_domain": ["example.com"],
        }),
        1.8,
        _NOW,
        _WINDOW,
    )
    assert dns_summary is not None
    time_keys = {"first_seen", "last_seen", "reboot_ts", "start_time", "window_start"}
    assert time_keys.isdisjoint(aws_summary.evidence)
    assert time_keys.isdisjoint(dns_summary.evidence)
