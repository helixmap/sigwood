#!/usr/bin/env python3
"""Run the detector measurement bench and emit one privacy-safe summary."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import traceback
from pathlib import Path
from typing import Any, NoReturn

from sigwood.common import config as cfg
from sigwood.common.allowlist import resolve_allowlist_plan
from sigwood.common.sanitize import strip_control


EXPECTED_SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = Path(__file__).with_name("bench_ledger.demo.toml")

TOP_KEYS = frozenset({"sigwood_version", "schema_version", "run_summary", "findings"})
RUN_SUMMARY_KEYS = frozenset({
    "data_window",
    "record_counts",
    "data_size_bytes",
    "detectors_run",
    "detectors_skipped",
    "detectors_failed",
    "notes",
    "data_sources",
    "detector_methods",
    "requested_span",
    "suppression",
})
FINDING_KEYS = frozenset({
    "detector",
    "severity",
    "title",
    "description",
    "next_steps",
    "evidence",
    "ts_generated",
    "data_window",
})
SUPPRESSION_KEYS = frozenset({
    "enabled", "connections", "domains", "connection_total", "domain_total",
})
METHOD_KEYS = frozenset({"label", "named"})
SEVERITIES = ("high", "medium", "low", "info")
SYNTHETIC_TIERS = frozenset({
    "ranked_summary", "scan_summary", "burst", "family", "reboot", "transaction",
})
TRANSACTION_LABELS = ("admin session", "update run")

LEDGER_FIELDS = frozenset({
    "path",
    "version",
    "download_sha256",
    "license",
    "label_source",
    "question",
    "approval",
    "revisit",
})
SELECTOR_KEYS = frozenset({"example_id", "detector", "field", "op", "value"})
SELECTOR_OPS = frozenset({"eq", "endswith", "contains"})
DATASET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
SALT_RE = re.compile(r"^[0-9a-f]{32}$")

TEXT_RULE = "─" * 80
HEADER_RE = re.compile(r"^(?P<det>\S+) - (?P<n>\d+) findings?\b")
CAP_RE = re.compile(
    r"(?P<hidden>[\d,]+) more not shown \(showing first (?P<shown>[\d,]+)\)"
)
CAP_MARKER = "more not shown"

PINNED_ENV = {
    "NUMBA_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "PYTHONHASHSEED": "0",
}
BUNDLE_FILES = {
    "json_stdout": "hunt.json",
    "text_stdout": "hunt.text",
    "json_stderr": "hunt.json.stderr",
    "text_stderr": "hunt.text.stderr",
    "config": "merged-config.json",
    "error": "bench.error.txt",
}

HASH_DOMAIN = b"sigwood-bench-config-v1"
SIGWOOD_REDACT_KEYS = frozenset({
    "root",
    "zeek_dir",
    "syslog_dir",
    "pihole_dir",
    "cloudtrail_dir",
    "export_dir",
    "report_dir",
    "home_net",
})
ALLOWLIST_REDACT_KEYS = frozenset({
    "domain_patterns", "connection_rules", "allowlist_dir",
})
SHIPPED_LIST_NAMES = frozenset({"common", "devices", "homelab"})


class SummaryRefusal(ValueError):
    """A fail-closed refusal carrying a safe structural location."""

    def __init__(self, path: str, detail: str) -> None:
        super().__init__(f"{path}: {detail}")
        self.path = path


class BenchFailure(RuntimeError):
    """An operational failure with a bounded parent-facing message."""

    def __init__(self, safe_message: str, cause: BaseException | None = None) -> None:
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.cause = cause


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser whose failures never echo path-bearing tokens."""

    def error(self, message: str) -> NoReturn:
        del message
        self.exit(2, "bench: invalid arguments\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--expected-record-counts", required=True)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--detect", default="all")
    parser.add_argument("--all", action="store_true", dest="load_all")
    parser.add_argument("--selectors", type=Path)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("corpus", nargs="?", type=Path)
    return parser


def _safe_error(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def _load_expected_record_counts(raw: str) -> dict[str, int]:
    """Parse one explicit run-contract pin without accepting duplicate keys."""
    duplicates: set[str] = set()

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicates.add(key)
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=object_pairs)
    if duplicates or not isinstance(value, dict):
        raise ValueError("expected a unique-key object")
    for pattern, count in value.items():
        if (
            not isinstance(pattern, str)
            or not pattern
            or strip_control(pattern) != pattern
        ):
            raise ValueError("invalid record-count pattern")
        if type(count) is not int or count < 0:
            raise ValueError("invalid record count")
    return value


def _assert_record_counts(
    dataset_id: str,
    expected: dict[str, int],
    actual: dict[str, int],
) -> None:
    """Fail closed when the observed loader map differs from the run pin."""
    missing = object()
    for pattern in sorted(set(expected) | set(actual)):
        expected_value = expected.get(pattern, missing)
        actual_value = actual.get(pattern, missing)
        if expected_value == actual_value:
            continue
        safe_pattern = strip_control(pattern) or "<control-only>"
        expected_label = "<unpinned>" if expected_value is missing else str(expected_value)
        actual_label = "<missing>" if actual_value is missing else str(actual_value)
        raise BenchFailure(
            "bench: dataset "
            f"{dataset_id} record count mismatch for pattern "
            f"{json.dumps(safe_pattern, ensure_ascii=True)}: "
            f"expected {expected_label}, actual {actual_label}"
        )


def _require_exact_keys(value: object, expected: frozenset[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SummaryRefusal(path, "expected an object")
    actual = set(value)
    extra = sorted(actual - expected)
    missing = sorted(expected - actual)
    if extra:
        raise SummaryRefusal(path, f"unexpected key {extra[0]!r}")
    if missing:
        raise SummaryRefusal(path, f"missing key {missing[0]!r}")
    return value


def _require_list(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise SummaryRefusal(path, "expected a list")
    return value


def _require_str(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise SummaryRefusal(path, "expected a string")
    return value


def _require_int(value: object, path: str) -> int:
    if type(value) is not int:
        raise SummaryRefusal(path, "expected an integer")
    return value


def _require_bool(value: object, path: str) -> bool:
    if type(value) is not bool:
        raise SummaryRefusal(path, "expected a boolean")
    return value


def _validate_payload(payload: object) -> dict[str, Any]:
    top = _require_exact_keys(payload, TOP_KEYS, "root")
    version = _require_int(top["schema_version"], "schema_version")
    if version != EXPECTED_SCHEMA_VERSION:
        raise SummaryRefusal("schema_version", "unsupported value")
    _require_str(top["sigwood_version"], "sigwood_version")

    run = _require_exact_keys(top["run_summary"], RUN_SUMMARY_KEYS, "run_summary")
    record_counts = _require_exact_keys_dynamic(run["record_counts"], "run_summary.record_counts")
    for key, value in record_counts.items():
        _require_str(key, "run_summary.record_counts key")
        if _require_int(value, f"run_summary.record_counts.{key}") < 0:
            raise SummaryRefusal(f"run_summary.record_counts.{key}", "expected non-negative")
    _require_int(run["data_size_bytes"], "run_summary.data_size_bytes")
    for field in ("detectors_run", "data_sources"):
        for index, value in enumerate(_require_list(run[field], f"run_summary.{field}")):
            _require_str(value, f"run_summary.{field}[{index}]")
    for field in ("detectors_skipped", "detectors_failed"):
        mapping = _require_exact_keys_dynamic(run[field], f"run_summary.{field}")
        for key in mapping:
            _require_str(key, f"run_summary.{field} key")

    methods = _require_exact_keys_dynamic(run["detector_methods"], "run_summary.detector_methods")
    for name, raw in methods.items():
        _require_str(name, "run_summary.detector_methods key")
        if raw is None:
            continue
        method = _require_exact_keys(raw, METHOD_KEYS, f"run_summary.detector_methods.{name}")
        _require_str(method["label"], f"run_summary.detector_methods.{name}.label")
        _require_bool(method["named"], f"run_summary.detector_methods.{name}.named")

    suppression = run["suppression"]
    if suppression is not None:
        suppression_map = _require_exact_keys(
            suppression, SUPPRESSION_KEYS, "run_summary.suppression"
        )
        _require_bool(suppression_map["enabled"], "run_summary.suppression.enabled")
        for field in ("connections", "domains", "connection_total", "domain_total"):
            _require_int(suppression_map[field], f"run_summary.suppression.{field}")

    requested = run["requested_span"]
    if requested is not None and type(requested) not in (int, float):
        raise SummaryRefusal("run_summary.requested_span", "expected a number or null")

    findings = _require_list(top["findings"], "findings")
    for index, raw in enumerate(findings):
        finding = _require_exact_keys(raw, FINDING_KEYS, f"findings[{index}]")
        _require_str(finding["detector"], f"findings[{index}].detector")
        severity = _require_str(finding["severity"], f"findings[{index}].severity")
        if severity not in SEVERITIES:
            raise SummaryRefusal(f"findings[{index}].severity", "unexpected value")
        _require_str(finding["title"], f"findings[{index}].title")
        if not isinstance(finding["evidence"], dict):
            raise SummaryRefusal(f"findings[{index}].evidence", "expected an object")

    return top


def _require_exact_keys_dynamic(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SummaryRefusal(path, "expected an object")
    return value


def _parse_int_with_commas(value: str, path: str) -> int:
    try:
        return int(value.replace(",", ""))
    except ValueError as exc:
        raise SummaryRefusal(path, "invalid count") from exc


def _parse_text_counts(
    report: str,
    totals: dict[str, int],
) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    """Read renderer-disclosed group/cap counts without reimplementing policy."""
    lines = report.splitlines()
    headers: dict[str, int] = {}
    cap_hidden: dict[str, int] = {}
    current: str | None = None

    for index, line in enumerate(lines):
        if line == TEXT_RULE:
            if index == 0:
                raise SummaryRefusal("text.header", "rule has no header")
            header_line = lines[index - 1]
            match = HEADER_RE.match(header_line)
            if match is None:
                raise SummaryRefusal("text.header", "format changed")
            detector = match.group("det")
            if detector in headers:
                raise SummaryRefusal("text.header", "duplicate detector")
            headers[detector] = int(match.group("n"))
            current = detector
            continue

        if CAP_MARKER in line:
            match = CAP_RE.search(line)
            if match is None:
                raise SummaryRefusal("text.cap", "format changed")
            if current is None:
                raise SummaryRefusal("text.cap", "has no detector header")
            if current in cap_hidden:
                raise SummaryRefusal("text.cap", "duplicate detector")
            hidden = _parse_int_with_commas(match.group("hidden"), "text.cap.hidden")
            shown = _parse_int_with_commas(match.group("shown"), "text.cap.shown")
            cap_hidden[current] = hidden
            if headers[current] - hidden != shown:
                raise SummaryRefusal("text.cap", "counts are inconsistent")

    unknown = sorted(set(headers) - set(totals))
    if unknown:
        raise SummaryRefusal("text.header", "detector is absent from json")

    default_visible: dict[str, int] = {}
    level_hidden: dict[str, int] = {}
    normalized_cap: dict[str, int] = {}
    for detector, total in totals.items():
        visible_pre_cap = headers.get(detector, 0)
        hidden_by_cap = cap_hidden.get(detector, 0)
        visible = visible_pre_cap - hidden_by_cap
        hidden_by_level = total - visible_pre_cap
        if min(total, visible_pre_cap, hidden_by_cap, visible, hidden_by_level) < 0:
            raise SummaryRefusal("text.counts", "negative or inconsistent count")
        default_visible[detector] = visible
        normalized_cap[detector] = hidden_by_cap
        level_hidden[detector] = hidden_by_level

    return default_visible, normalized_cap, level_hidden


def _normalize_example_id(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("example_id must be a string")
    normalized = strip_control(value)[:40]
    if not normalized:
        raise ValueError("example_id must not be empty")
    return normalized


def _load_selectors(path: Path | None) -> list[dict[str, str]]:
    if path is None:
        return []
    with path.open("rb") as handle:
        raw = json.load(handle)
    if not isinstance(raw, list):
        raise ValueError("selectors must be a list")

    selectors: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != SELECTOR_KEYS:
            raise ValueError("selector shape is invalid")
        normalized = _normalize_example_id(entry["example_id"])
        if normalized in seen_ids:
            raise ValueError("selector example_id collision")
        seen_ids.add(normalized)
        detector = entry["detector"]
        field = entry["field"]
        op = entry["op"]
        value = entry["value"]
        if not all(isinstance(item, str) for item in (detector, field, op, value)):
            raise ValueError("selector values must be strings")
        if field != "title" and not re.fullmatch(r"evidence\.[^.]+", field):
            raise ValueError("selector field is invalid")
        if op not in SELECTOR_OPS:
            raise ValueError("selector operation is invalid")
        selectors.append({
            "example_id": normalized,
            "detector": detector,
            "field": field,
            "op": op,
            "value": value,
        })
    return selectors


def _known_example_ranks(
    findings: list[dict[str, Any]],
    selectors: list[dict[str, str]],
    detector_names: set[str],
) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for selector in selectors:
        detector = selector["detector"]
        if detector not in detector_names:
            raise SummaryRefusal("selectors.detector", "detector is absent from run status")
        pool = [
            finding
            for finding in findings
            if finding["detector"] == detector
            and finding["evidence"].get("tier") not in SYNTHETIC_TIERS
        ]
        rank: int | None = None
        for index, finding in enumerate(pool, start=1):
            if selector["field"] == "title":
                candidate = finding["title"]
            else:
                key = selector["field"].split(".", 1)[1]
                candidate = finding["evidence"].get(key)
            if not isinstance(candidate, str):
                continue
            op = selector["op"]
            needle = selector["value"]
            matched = (
                candidate == needle if op == "eq"
                else candidate.endswith(needle) if op == "endswith"
                else needle in candidate
            )
            if matched:
                rank = index
                break
        example_id = selector["example_id"]
        output[example_id] = {
            "example_id": example_id,
            "detector": strip_control(detector),
            "found": rank is not None,
            "rank": rank,
            "pool_size": len(pool),
        }
    return output


def _json_default(value: object) -> object:
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"unsupported config value type: {type(value).__name__}")


def _load_ledger(path: Path, dataset_id: str) -> tuple[dict[str, Any], str]:
    if DATASET_ID_RE.fullmatch(dataset_id) is None:
        raise ValueError("invalid dataset id")
    with path.open("rb") as handle:
        ledger = tomllib.load(handle)
    salt = ledger.get("salt")
    if not isinstance(salt, str) or SALT_RE.fullmatch(salt) is None:
        raise ValueError("invalid ledger salt")
    datasets = ledger.get("dataset")
    if not isinstance(datasets, dict):
        raise ValueError("missing dataset table")
    entry = datasets.get(dataset_id)
    if not isinstance(entry, dict) or set(entry) != LEDGER_FIELDS:
        raise ValueError("dataset entry is missing or invalid")
    if not all(isinstance(value, str) for value in entry.values()):
        raise ValueError("dataset metadata must be strings")
    return ledger, salt


def _redacted_hash_input(config: dict[str, Any]) -> dict[str, Any]:
    sigwood = copy.deepcopy(config.get("sigwood", {}))
    detectors = copy.deepcopy(config.get("detectors", {}))
    allowlist = copy.deepcopy(config.get("allowlist", {}))
    for key in SIGWOOD_REDACT_KEYS:
        if key in sigwood:
            sigwood[key] = "<redacted>"
    for key in ALLOWLIST_REDACT_KEYS:
        if key in allowlist:
            allowlist[key] = "<redacted>"
    return {"sigwood": sigwood, "detectors": detectors, "allowlist": allowlist}


def _config_hash(config: dict[str, Any], salt: str) -> str:
    canonical = json.dumps(
        _redacted_hash_input(config),
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")
    digest = hashlib.sha256(HASH_DOMAIN + b"\0" + bytes.fromhex(salt) + canonical)
    return digest.hexdigest()[:12]


def _prepare_bundle(raw_path: Path) -> Path:
    path = raw_path.expanduser().resolve()
    if path == REPO_ROOT or REPO_ROOT in path.parents:
        raise ValueError("bundle is inside repository")
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise ValueError("bundle is not a new empty directory")
    else:
        path.mkdir(parents=True, exist_ok=False)
    return path


def _write_parent_error(bundle: Path, exc: BaseException) -> None:
    try:
        detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        (bundle / BUNDLE_FILES["error"]).write_text(
            detail, encoding="utf-8", errors="backslashreplace"
        )
    except OSError:
        pass


def _child_command(args: argparse.Namespace, output_format: str) -> list[str]:
    command = [
        str(args.python),
        "-m",
        "sigwood",
        "hunt",
        f"--config={args.config}",
        f"--format={output_format}",
        "--out=-",
        "--yes",
        f"--detect={args.detect}",
    ]
    if args.load_all:
        command.append("--all")
    if args.corpus is not None:
        command.append(str(args.corpus))
    return command


def _transaction_rollup(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Project only aggregate transaction accounting; reject data-shaped labels."""
    units = {
        label: {severity: 0 for severity in SEVERITIES}
        for label in TRANSACTION_LABELS
    }
    claimed = {label: 0 for label in TRANSACTION_LABELS}
    represented = {label: 0 for label in TRANSACTION_LABELS}
    unit_members: dict[str, list[int]] = {label: [] for label in TRANSACTION_LABELS}
    unit_lines: dict[str, list[int]] = {label: [] for label in TRANSACTION_LABELS}
    remainder = {severity: 0 for severity in SEVERITIES}
    for index, finding in enumerate(findings):
        if finding["detector"] != "syslog":
            continue
        evidence = finding["evidence"]
        if evidence.get("tier") != "transaction":
            remainder[finding["severity"]] += 1
            continue
        label = evidence.get("label")
        if label not in units:
            raise SummaryRefusal(
                f"findings[{index}].evidence.label", "unexpected transaction label"
            )
        member_count = evidence.get("member_count")
        represented_count = evidence.get("represented_line_count")
        if type(member_count) is not int or member_count < 0:
            raise SummaryRefusal(
                f"findings[{index}].evidence.member_count", "expected non-negative integer"
            )
        if type(represented_count) is not int or represented_count < 0:
            raise SummaryRefusal(
                f"findings[{index}].evidence.represented_line_count",
                "expected non-negative integer",
            )
        units[label][finding["severity"]] += 1
        claimed[label] += member_count
        represented[label] += represented_count
        unit_members[label].append(member_count)
        unit_lines[label].append(represented_count)
    for values in (*unit_members.values(), *unit_lines.values()):
        values.sort(reverse=True)
    return {
        "units_by_label_severity": units,
        "claimed_member_findings": claimed,
        "represented_rare_lines": represented,
        "unit_member_counts": unit_members,
        "unit_represented_line_counts": unit_lines,
        "remaining_findings_by_severity": remainder,
    }


def _run_child(
    args: argparse.Namespace,
    output_format: str,
    env: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            _child_command(args, output_format),
            capture_output=True,
            check=False,
            env=env,
        )
    except OSError as exc:
        raise BenchFailure("bench: could not launch sigwood — details in the bundle", exc) from exc


def _allowlist_state(
    run_summary: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    plan = resolve_allowlist_plan(config)
    shipped = sorted(
        item.name for item in plan.lists if item.origin == "shipped" and item.enabled
    )
    if not set(shipped) <= SHIPPED_LIST_NAMES:
        raise SummaryRefusal("allowlist_state.shipped_lists_on", "unknown shipped list")
    user_count = sum(
        1
        for item in plan.lists
        if item.enabled and item.origin in {"dropin", "config-path"}
    )
    suppression = run_summary["suppression"]
    if suppression is None:
        return {
            "enabled": plan.master_enabled,
            "connections": 0,
            "domains": 0,
            "connection_total": 0,
            "domain_total": 0,
            "shipped_lists_on": shipped,
            "user_lists_on": user_count,
        }
    return {
        "enabled": suppression["enabled"],
        "connections": suppression["connections"],
        "domains": suppression["domains"],
        "connection_total": suppression["connection_total"],
        "domain_total": suppression["domain_total"],
        "shipped_lists_on": shipped,
        "user_lists_on": user_count,
    }


def _safe_name_list(values: list[Any]) -> list[str]:
    return sorted(strip_control(_require_str(value, "summary name")) for value in values)


def _project_summary(
    payload: dict[str, Any],
    report: str,
    *,
    exit_code: int,
    runtime_seconds: float,
    config_hash: str,
    dataset_id: str,
    config: dict[str, Any],
    selectors: list[dict[str, str]],
    include_known_examples: bool = False,
) -> dict[str, Any]:
    run = payload["run_summary"]
    findings = payload["findings"]

    run_detector_names = [strip_control(name) for name in run["detectors_run"]]
    if len(set(run_detector_names)) != len(run_detector_names):
        raise SummaryRefusal("run_summary.detectors_run", "normalized names collide")
    grouped: dict[str, dict[str, int]] = {
        detector: {severity: 0 for severity in SEVERITIES}
        for detector in run_detector_names
    }
    totals: dict[str, int] = {detector: 0 for detector in run_detector_names}
    for finding in findings:
        detector = strip_control(finding["detector"])
        if detector not in grouped:
            raise SummaryRefusal("findings.detector", "detector is absent from detectors_run")
        grouped[detector][finding["severity"]] += 1
        totals[detector] += 1

    default_visible, cap_hidden, level_hidden = _parse_text_counts(report, totals)
    methods: dict[str, str | None] = {}
    for name, method in run["detector_methods"].items():
        safe_name = strip_control(name)
        methods[safe_name] = None if method is None else strip_control(method["label"])
    dns_method = run["detector_methods"].get("dns")
    backend = None if dns_method is None else strip_control(dns_method["label"])

    requested = run["requested_span"]
    requested_seconds = None if requested is None else int(requested)
    summary: dict[str, Any] = {
        "sigwood_version": strip_control(payload["sigwood_version"]),
        "schema_version": payload["schema_version"],
        "findings_by_detector_severity": grouped,
        "total_findings": len(findings),
        "detectors_run": _safe_name_list(run["detectors_run"]),
        "detectors_skipped": _safe_name_list(list(run["detectors_skipped"])),
        "detectors_failed": _safe_name_list(list(run["detectors_failed"])),
        "backend": backend,
        "detector_methods": methods,
        "data_sources": _safe_name_list(run["data_sources"]),
        "allowlist_state": _allowlist_state(run, config),
        "record_counts": {
            strip_control(key): value for key, value in sorted(run["record_counts"].items())
        },
        "data_size_bytes": run["data_size_bytes"],
        "requested_span_seconds": requested_seconds,
        "default_visible": default_visible,
        "cap_hidden": cap_hidden,
        "level_hidden": level_hidden,
        "runtime_seconds": round(runtime_seconds, 6),
        "config_hash": config_hash,
        "dataset_id": dataset_id,
        "exit_code": exit_code,
        "transaction_rollup": _transaction_rollup(findings),
    }
    if include_known_examples:
        detector_names = (
            set(run["detectors_run"])
            | set(run["detectors_skipped"])
            | set(run["detectors_failed"])
        )
        summary["known_example_ranks"] = _known_example_ranks(
            findings, selectors, detector_names
        )
    return summary


def _measurement(
    args: argparse.Namespace,
    bundle: Path,
    config: dict[str, Any],
    salt: str,
    selectors: list[dict[str, str]],
    expected_record_counts: dict[str, int],
) -> int:
    config_bytes = json.dumps(
        config, indent=2, sort_keys=True, default=_json_default,
    ).encode("utf-8") + b"\n"
    (bundle / BUNDLE_FILES["config"]).write_bytes(config_bytes)

    child_env = dict(os.environ)
    child_env.pop("SIGWOOD_ROOT", None)
    child_env.update(PINNED_ENV)

    started = time.monotonic()
    json_run = _run_child(args, "json", child_env)
    runtime_seconds = time.monotonic() - started
    (bundle / BUNDLE_FILES["json_stdout"]).write_bytes(json_run.stdout)
    (bundle / BUNDLE_FILES["json_stderr"]).write_bytes(json_run.stderr)

    text_run = _run_child(args, "text", child_env)
    (bundle / BUNDLE_FILES["text_stdout"]).write_bytes(text_run.stdout)
    (bundle / BUNDLE_FILES["text_stderr"]).write_bytes(text_run.stderr)

    if json_run.returncode != text_run.returncode:
        raise BenchFailure("bench: sigwood runs disagreed — details in the bundle")
    try:
        json_text = json_run.stdout.decode("utf-8")
        report = text_run.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BenchFailure("bench: could not decode sigwood output — details in the bundle", exc) from exc
    try:
        raw_payload = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise BenchFailure("bench: sigwood run failed — details in the bundle", exc) from exc

    payload = _validate_payload(raw_payload)
    _assert_record_counts(
        args.dataset_id,
        expected_record_counts,
        payload["run_summary"]["record_counts"],
    )
    summary = _project_summary(
        payload,
        report,
        exit_code=json_run.returncode,
        runtime_seconds=runtime_seconds,
        config_hash=_config_hash(config, salt),
        dataset_id=args.dataset_id,
        config=config,
        selectors=selectors,
        include_known_examples=args.selectors is not None,
    )
    json.dump(summary, sys.stdout, indent=2, sort_keys=True, allow_nan=False)
    print()
    print("bench: measurement complete", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run one two-format measurement and emit its approved summary fields."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if "SIGWOOD_ROOT" in os.environ:
        return _safe_error(
            "bench: SIGWOOD_ROOT is set — unset it (the bench resolves paths from --config)"
        )
    try:
        config = cfg.load(args.config)
    except (OSError, ValueError, cfg.ConfigError):
        return _safe_error("bench: could not read --config")
    try:
        expected_record_counts = _load_expected_record_counts(
            args.expected_record_counts
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        return _safe_error("bench: could not validate --expected-record-counts")
    try:
        _, salt = _load_ledger(args.ledger, args.dataset_id)
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return _safe_error("bench: could not read or validate --ledger")
    try:
        selectors = _load_selectors(args.selectors)
    except (OSError, ValueError, json.JSONDecodeError):
        return _safe_error("bench: could not read or validate --selectors")
    try:
        bundle = _prepare_bundle(args.bundle_dir)
    except (OSError, ValueError):
        return _safe_error("bench: --bundle-dir must be a new empty directory outside the repo")

    try:
        return _measurement(
            args, bundle, config, salt, selectors, expected_record_counts
        )
    except SummaryRefusal as exc:
        _write_parent_error(bundle, exc)
        return _safe_error(f"bench: summary refused at {strip_control(exc.path)}")
    except BenchFailure as exc:
        _write_parent_error(bundle, exc.cause or exc)
        return _safe_error(exc.safe_message)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        _write_parent_error(bundle, exc)
        return _safe_error("bench: measurement failed — details in the bundle")


if __name__ == "__main__":
    raise SystemExit(main())
