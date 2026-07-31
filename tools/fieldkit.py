#!/usr/bin/env python3
"""Collect a privacy-bounded sigwood field-validation report.

This file is deliberately standalone: collaborators may download it without the
repository and run it with any Python 3.9+ interpreter while the ``sigwood``
command is available on PATH.
"""

from __future__ import annotations

import argparse
import builtins
import json
import math
import os
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, TextIO, Tuple

try:
    import resource
except ImportError:  # pragma: no cover - exercised on non-POSIX Python
    resource = None  # type: ignore[assignment]


KIT_VERSION = "1"
REPORT_SCHEMA_VERSION = 1
RETURN_ADDRESS = "fieldkit@augros.org"

DETECTOR_TOKENS = frozenset({"aws", "beacon", "dns", "duration", "scan", "syslog"})
SEVERITY_TOKENS = frozenset({"high", "medium", "low", "info"})
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "other": 4}
VERDICT_TOKENS = frozenset(
    {"known_benign", "unexplained_plausible", "nonsense", "interesting", "skip"}
)
RECORD_PATTERN_TOKENS = frozenset(
    {"*.json*", "*.log*", "conn*.log*", "dns*.log*", "pihole*.log*", "syslog*.log*"}
)
DATA_SOURCE_TOKENS = frozenset(
    {
        "cloudtrail_raw",
        "dnsmasq_dns",
        "syslog_journal",
        "syslog_raw",
        "zeek_conn",
        "zeek_dns",
        "zeek_syslog",
    }
)

NUMERIC_EVIDENCE = {
    "aws": frozenset(
        {
            "action_entropy",
            "composite_z",
            "distinct_aws_region",
            "distinct_event_name",
            "distinct_event_source",
            "distinct_hours_active",
            "distinct_source_ip",
            "error_rate",
            "event_count",
            "mean_rarity",
            "new_action_count",
            "new_service_count",
            "population_floor",
            "read_ratio",
            "scorable_count",
            "span_seconds",
            "top_composite_z",
            "z_action_entropy",
            "z_distinct_event_name",
            "z_distinct_source_ip",
            "z_error_rate",
        }
    ),
    "beacon": frozenset(
        {"beacon_score", "conn_count", "cycles", "dominant_period", "span_seconds"}
    ),
    "dns": frozenset(
        {
            "label_score",
            "max_label_score",
            "min_label_score",
            "nxdomain_count",
            "nxdomain_fraction",
            "subdomain_count",
            "total_queries",
            "unique_sources",
        }
    ),
    "duration": frozenset({"max_duration_seconds"}),
    "scan": frozenset(
        {
            "active_buckets",
            "distinct_hosts",
            "distinct_ports",
            "max_ports_in_bucket",
            "scan_state_ratio",
            "temporal_spread_score",
            "total_conns",
            "window_secs",
        }
    ),
    "syslog": frozenset(
        {
            "host_total",
            "line_count",
            "member_count",
            "program_total",
            "represented_line_count",
            "signal_count",
            "span_seconds",
        }
    ),
}

ENUM_EVIDENCE = {
    "aws": {"tier": frozenset({"burst", "ranked", "ranked_summary"})},
    "dns": {
        "tier": frozenset({"standard", "below_gate_group", "scan_summary"}),
        "severity_basis": frozenset({"resolution-outcome", "volume-concentration"}),
    },
    "scan": {
        "direction": frozenset(
            {
                "internal→internal",
                "internal→external",
                "external→internal",
                "external→external",
            }
        )
    },
    "syslog": {
        "shape": frozenset(
            {"plain_rare_line", "family", "burst", "reboot", "transaction"}
        )
    },
}

SUPPRESSION_NUMERIC_FIELDS = frozenset(
    {
        "connections",
        "domains",
        "connection_total",
        "domain_total",
        "host_rows",
        "host_total",
        "hosts_matched",
    }
)

_VERSION_RE = re.compile(r"^sigwood ([0-9A-Za-z.+-]{1,32})$")
_CONTROL_DELETE = dict.fromkeys(
    list(range(0x00, 0x20))
    + [0x7F]
    + list(range(0x80, 0xA0))
    + list(range(0xDC80, 0xDD00))
)
_BUNDLE_PREFIX = "sigwood-field-report"


class FieldkitError(RuntimeError):
    """An expected collaborator-facing failure."""


class SchemaMismatch(FieldkitError):
    """The installed report schema is not understood by this kit."""


class SafeArgumentParser(argparse.ArgumentParser):
    """Keep argparse failures short and free of caller-supplied path text."""

    def error(self, message: str) -> None:
        del message
        self.exit(2, "fieldkit: invalid arguments\n")


@dataclass
class ProtocolState:
    """Paths whose cleanup must survive exceptions and interrupts."""

    workdir: Optional[Path] = None
    bundle_path: Optional[Path] = None


def _build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path.cwd())
    parser.add_argument("--skip-smoke", action="store_true")
    parser.add_argument("--no-triage", action="store_true")
    return parser


def _reject_nonfinite(token: str) -> None:
    raise ValueError("non-finite json number")


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle, parse_constant=_reject_nonfinite)


def _try_load_json(path: Path) -> Optional[Any]:
    try:
        return _load_json(path)
    except (OSError, UnicodeError, ValueError, TypeError):
        return None


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _number(value: Any) -> Optional[float]:
    return float(value) if _is_number(value) else None


def _integer(value: Any) -> Optional[int]:
    if not _is_number(value):
        return None
    numeric = float(value)
    return int(numeric) if numeric.is_integer() else None


def _token(value: Any, allowed: Iterable[str]) -> str:
    allowed_set = allowed if isinstance(allowed, (set, frozenset)) else frozenset(allowed)
    return value if isinstance(value, str) and value in allowed_set else "other"


def _safe_platform_string(value: Any, *, maximum: int = 120) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.translate(_CONTROL_DELETE).strip()
    return cleaned[:maximum] if cleaned else None


def _parse_iso(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _data_window_span(value: Any) -> Optional[float]:
    if not isinstance(value, list) or len(value) != 2:
        return None
    start = _parse_iso(value[0])
    end = _parse_iso(value[1])
    if start is None or end is None or end < start:
        return None
    return (end - start).total_seconds()


def _classify_skip(value: Any) -> str:
    if not isinstance(value, str):
        return "other"
    lowered = value.lower()
    if "import failed" in lowered:
        return "import_failed"
    if "not configured" in lowered:
        return "not_configured"
    if "not found" in lowered or "no dns source found" in lowered or "no syslog source found" in lowered:
        return "not_found"
    if "scope" in lowered or "out of scope" in lowered:
        return "scope"
    return "other"


def _classify_failure(value: Any) -> str:
    if not isinstance(value, str):
        return "other"
    if value.startswith("prep error - "):
        return "prep"
    if value.startswith("detector error - "):
        return "detector"
    return "other"


def _classify_note(value: Any) -> str:
    if not isinstance(value, str):
        return "other"
    lowered = value.lower()
    rules = (
        ("default window", "default_window"),
        ("coverage", "coverage"),
        ("rotation", "rotation"),
        ("carried by both", "arbitration"),
        ("system logs", "provider"),
        ("journal", "provider"),
        ("provider", "provider"),
        ("arbitration", "arbitration"),
        ("allowlist", "allowlist"),
        ("home_net", "home_net"),
        ("home net", "home_net"),
        ("cloudtrail", "aws"),
        ("aws", "aws"),
        ("beacon", "beacon"),
        ("opt-in", "opt_in"),
        ("default hunt - not run", "opt_in"),
        ("overlap", "overlap"),
    )
    for needle, category in rules:
        if needle in lowered:
            return category
    return "other"


def _merge_reason(target: MutableMapping[str, str], name: str, reason: str) -> None:
    current = target.get(name)
    if current is None:
        target[name] = reason
    elif current != reason:
        target[name] = "other"


def _project_run_summary(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None

    record_counts: Dict[str, int] = {}
    unknown_count = 0
    raw_counts = raw.get("record_counts")
    if isinstance(raw_counts, Mapping):
        for pattern, value in raw_counts.items():
            count = _integer(value)
            if count is None or count < 0:
                continue
            if isinstance(pattern, str) and pattern in RECORD_PATTERN_TOKENS:
                record_counts[pattern] = record_counts.get(pattern, 0) + count
            else:
                unknown_count += count
    if unknown_count:
        record_counts["other"] = unknown_count

    detectors_run: List[str] = []
    raw_run = raw.get("detectors_run")
    if isinstance(raw_run, list):
        for value in raw_run:
            normalized = _token(value, DETECTOR_TOKENS)
            if normalized not in detectors_run:
                detectors_run.append(normalized)

    skipped: Dict[str, str] = {}
    raw_skipped = raw.get("detectors_skipped")
    if isinstance(raw_skipped, Mapping):
        for detector, reason in raw_skipped.items():
            _merge_reason(
                skipped,
                _token(detector, DETECTOR_TOKENS),
                _classify_skip(reason),
            )

    failed: Dict[str, str] = {}
    raw_failed = raw.get("detectors_failed")
    if isinstance(raw_failed, Mapping):
        for detector, reason in raw_failed.items():
            _merge_reason(
                failed,
                _token(detector, DETECTOR_TOKENS),
                _classify_failure(reason),
            )

    data_sources: List[str] = []
    raw_sources = raw.get("data_sources")
    if isinstance(raw_sources, list):
        for value in raw_sources:
            normalized = _token(value, DATA_SOURCE_TOKENS)
            if normalized not in data_sources:
                data_sources.append(normalized)

    notes: Counter[str] = Counter()
    raw_notes = raw.get("notes")
    if isinstance(raw_notes, list):
        notes.update(_classify_note(value) for value in raw_notes)

    suppression: Optional[Dict[str, Any]] = None
    raw_suppression = raw.get("suppression")
    if isinstance(raw_suppression, Mapping):
        suppression = {}
        if isinstance(raw_suppression.get("enabled"), bool):
            suppression["enabled"] = raw_suppression["enabled"]
        for key in sorted(SUPPRESSION_NUMERIC_FIELDS):
            value = _integer(raw_suppression.get(key))
            if value is not None and value >= 0:
                suppression[key] = value

    requested_span = _number(raw.get("requested_span"))
    data_size = _integer(raw.get("data_size_bytes"))
    return {
        "record_counts": record_counts,
        "data_window_span_seconds": _data_window_span(raw.get("data_window")),
        "requested_span": requested_span if requested_span is None or requested_span >= 0 else None,
        "data_size_bytes": data_size if data_size is None or data_size >= 0 else None,
        "data_sources": data_sources,
        "detectors_run": detectors_run,
        "detectors_skipped": skipped,
        "detectors_failed": failed,
        "suppression": suppression,
        "notes": dict(sorted(notes.items())),
    }


def _distribution(values: Sequence[float]) -> Dict[str, Any]:
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "min": ordered[0],
        "median": statistics.median(ordered),
        "max": ordered[-1],
    }


def _enum_values(detector: str, key: str, evidence: Mapping[str, Any]) -> List[str]:
    if detector == "syslog" and key == "shape":
        tier = evidence.get("tier")
        return [tier if isinstance(tier, str) else "plain_rare_line"]
    if detector == "dns" and key == "tier":
        tier = evidence.get("tier")
        return [tier if isinstance(tier, str) else "standard"]
    value = evidence.get(key)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return [value] if isinstance(value, str) else []


def _project_findings(raw: Any) -> Tuple[Optional[Dict[str, Any]], List[Mapping[str, Any]]]:
    if not isinstance(raw, list):
        return None, []

    counts: Dict[str, Counter[str]] = defaultdict(Counter)
    numeric: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    enums: Dict[str, Dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    privileged: Counter[str] = Counter()
    local_findings: List[Mapping[str, Any]] = []

    for item in raw:
        if not isinstance(item, Mapping):
            continue
        detector = _token(item.get("detector"), DETECTOR_TOKENS)
        severity = _token(item.get("severity"), SEVERITY_TOKENS)
        counts[detector][severity] += 1
        local_findings.append(item)

        evidence = item.get("evidence")
        if not isinstance(evidence, Mapping) or detector == "other":
            continue
        for key in NUMERIC_EVIDENCE.get(detector, frozenset()):
            value = _number(evidence.get(key))
            if value is not None:
                numeric[detector][key].append(value)
        if detector == "syslog" and evidence.get("privileged") is True:
            privileged[detector] += 1
        for key, allowed in ENUM_EVIDENCE.get(detector, {}).items():
            values = _enum_values(detector, key, evidence)
            if not values:
                continue
            for value in values:
                enums[detector][key][_token(value, allowed)] += 1

    aggregate_counts = {
        detector: dict(sorted(by_severity.items()))
        for detector, by_severity in sorted(counts.items())
    }
    evidence_summary: Dict[str, Any] = {}
    for detector in sorted(DETECTOR_TOKENS):
        detector_summary: Dict[str, Any] = {}
        if numeric.get(detector):
            detector_summary["numeric"] = {
                key: _distribution(values)
                for key, values in sorted(numeric[detector].items())
                if values
            }
        if enums.get(detector):
            detector_summary["enums"] = {
                key: dict(sorted(histogram.items()))
                for key, histogram in sorted(enums[detector].items())
            }
        if detector == "syslog":
            detector_summary["privileged_count"] = privileged.get(detector, 0)
        if detector_summary:
            evidence_summary[detector] = detector_summary

    return {
        "counts": aggregate_counts,
        "evidence": evidence_summary,
    }, local_findings


def _validate_payload(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise FieldkitError("fieldkit: sigwood wrote an unreadable report")
    version = payload.get("schema_version")
    if type(version) is not int or version != REPORT_SCHEMA_VERSION:
        raise SchemaMismatch(
            "this kit understands sigwood report schema 1 — "
            "download the current kit from the repo"
        )
    return payload


def _canonical_version(stdout: str) -> Tuple[Optional[str], bool]:
    candidate = stdout.rstrip("\r\n")
    match = _VERSION_RE.fullmatch(candidate)
    return (match.group(1), False) if match else (None, True)


def _platform_facts() -> Dict[str, Any]:
    system = platform.system().lower()
    os_token = system if system in {"darwin", "linux", "windows"} else "other"
    total_mb: Optional[int] = None
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        page_count = int(os.sysconf("SC_PHYS_PAGES"))
        if page_size > 0 and page_count > 0:
            total_mb = int((page_size * page_count) / (1024 * 1024))
    except (AttributeError, OSError, TypeError, ValueError):
        total_mb = None
    return {
        "os": os_token,
        "release": _safe_platform_string(platform.release()),
        "machine": _safe_platform_string(platform.machine()),
        "python": _safe_platform_string(platform.python_version()),
        "cpu_count": os.cpu_count(),
        "mem_total_mb": total_mb,
    }


def generate_smoke_corpus() -> bytes:
    """Return the deterministic Zeek NDJSON connection canary."""
    rng = random.Random(1764)
    base_timestamp = 1_767_225_600.0
    records: List[str] = []
    for index in range(72):
        timestamp = base_timestamp + index * 175 + rng.uniform(-4, 4)
        record = {
            "_path": "conn",
            "ts": round(timestamp, 6),
            "uid": "SMOKE%03d" % index,
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 49152,
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 1.0,
            "orig_bytes": 128,
            "resp_bytes": 64,
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 2,
            "orig_ip_bytes": 232,
            "resp_pkts": 2,
            "resp_ip_bytes": 168,
        }
        records.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return ("\n".join(records) + "\n").encode("ascii")


def _smoke_passed(payload: Any) -> bool:
    if not isinstance(payload, Mapping):
        return False
    findings = payload.get("findings")
    return isinstance(findings, list) and any(
        isinstance(item, Mapping) and item.get("detector") == "beacon"
        for item in findings
    )


def _peak_child_rss_mb() -> Optional[float]:
    if resource is None:
        return None
    try:
        raw = float(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if not math.isfinite(raw) or raw < 0:
        return None
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    return round(raw / divisor, 2)


def _render_title(value: Any, *, limit: int = 160) -> str:
    text = value if isinstance(value, str) else ""
    return text.translate(_CONTROL_DELETE)[:limit]


def _severity_counts(findings: Sequence[Mapping[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for item in findings:
        counts[_token(item.get("severity"), SEVERITY_TOKENS)] += 1
    return counts


def _read_line(prompt: str) -> Optional[str]:
    """Read one terminal line, returning no value when the input stream closes."""
    try:
        return builtins.input(prompt)
    except EOFError:
        return None


def _triage(
    findings: Sequence[Mapping[str, Any]],
    *,
    no_triage: bool,
    stdin: TextIO,
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    skip_reason: Optional[str] = None
    if no_triage:
        skip_reason = "disabled"
    else:
        try:
            interactive = bool(stdin.isatty())
        except (AttributeError, OSError):
            interactive = False
        if not interactive:
            skip_reason = "non_tty"

    if skip_reason is not None:
        return {
            "ran": False,
            "skip_reason": skip_reason,
            "reviewed": 0,
            "items": [],
            "untriaged": dict(sorted(_severity_counts(findings).items())),
        }, {"missed": "", "confusing": "", "monthly": ""}

    ordered = sorted(
        enumerate(findings),
        key=lambda pair: SEVERITY_ORDER[
            _token(pair[1].get("severity"), SEVERITY_TOKENS)
        ],
    )
    review = ordered[:20]
    remainder = ordered[20:]
    untriaged = _severity_counts([item for _, item in remainder])
    items: List[Dict[str, Any]] = []
    choices = {
        "k": "known_benign",
        "u": "unexplained_plausible",
        "n": "nonsense",
        "i": "interesting",
        "s": "skip",
    }
    stopped = False
    for position, (_, item) in enumerate(review):
        detector = _token(item.get("detector"), DETECTOR_TOKENS)
        severity = _token(item.get("severity"), SEVERITY_TOKENS)
        title = _render_title(item.get("title"))
        prompt = "[%s] %s  %s\n[k/u/n/i/s, q to stop] " % (
            severity[:1].upper() if severity != "other" else "?",
            detector,
            title,
        )
        answer: Optional[str] = ""
        for attempt in range(2):
            answer = _read_line(
                prompt if attempt == 0 else "choose k/u/n/i/s/q: "
            )
            if answer is None:
                break
            choice = answer.strip().lower()[:1]
            if choice in choices or choice == "q":
                break
        choice = "q" if answer is None else answer.strip().lower()[:1]
        if choice == "q":
            untriaged.update(
                _severity_counts([remaining for _, remaining in review[position:]])
            )
            stopped = True
            break
        verdict = choices.get(choice, "skip")
        items.append(
            {
                "index": position + 1,
                "detector": detector,
                "severity": severity,
                "verdict": verdict,
            }
        )

    print("please don't paste log lines from your systems")
    answers = {
        "missed": _read_line("anything real it missed? ") or "",
        "confusing": _read_line("anything confusing in the report? ") or "",
        "monthly": _read_line("would you run this monthly? ") or "",
    }
    return {
        "ran": True,
        "skip_reason": None,
        "reviewed": len(items),
        "stopped_early": stopped,
        "items": items,
        "untriaged": dict(sorted(untriaged.items())),
    }, answers


def _markdown_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")
    return "\n".join(lines)


def _answer_block(value: Any) -> str:
    text = value if isinstance(value, str) else ""
    return "\n".join("    " + line for line in (text.splitlines() or [""]))


def _json_fence(encoded: str) -> str:
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", encoded)), default=0)
    return "`" * max(3, longest + 1)


def render_bundle(projection: Mapping[str, Any]) -> str:
    """Render prose and machine data from the same projection object."""
    kit = projection["kit"]
    run_summary = projection.get("run_summary")
    findings = projection.get("findings")
    triage = projection["triage"]
    answers = projection["answers"]

    platform_rows = [
        (key, kit["platform"].get(key))
        for key in ("os", "release", "machine", "python", "cpu_count", "mem_total_mb")
    ]
    corpus_rows: List[Tuple[Any, Any]] = []
    if isinstance(run_summary, Mapping):
        corpus_rows.extend(
            [
                ("data window span (seconds)", run_summary.get("data_window_span_seconds")),
                ("requested span (seconds)", run_summary.get("requested_span")),
                ("data size (bytes)", run_summary.get("data_size_bytes")),
                ("data sources", ", ".join(run_summary.get("data_sources", [])) or "none"),
            ]
        )
        for pattern, count in run_summary.get("record_counts", {}).items():
            corpus_rows.append(("records: " + pattern, count))
    else:
        corpus_rows.append(("report", "unavailable"))

    finding_rows: List[Tuple[Any, ...]] = []
    if isinstance(findings, Mapping):
        for detector, severity_counts in findings.get("counts", {}).items():
            finding_rows.append(
                (
                    detector,
                    severity_counts.get("high", 0),
                    severity_counts.get("medium", 0),
                    severity_counts.get("low", 0),
                    severity_counts.get("info", 0),
                    severity_counts.get("other", 0),
                )
            )

    if not isinstance(findings, Mapping):
        findings_output = (
            "sigwood produced no readable report, so no finding summary is available."
        )
    elif not findings.get("counts"):
        findings_output = "sigwood ran the hunt and reported no findings."
    else:
        findings_output = _markdown_table(
            ("detector", "high", "medium", "low", "info", "other"),
            finding_rows,
        )

    machine_json = json.dumps(projection, indent=2, ensure_ascii=True, sort_keys=True)
    fence = _json_fence(machine_json)
    lines = [
        "# sigwood field report",
        "",
        "This report was created for independent field validation. The automated "
        "projection never copies log-derived strings. The three answers below are "
        "the sole collaborator-authored free-text exception.",
        "",
        "Read the whole file before sending it to %s." % RETURN_ADDRESS,
        "",
        "## platform",
        "",
        _markdown_table(("field", "value"), platform_rows),
        "",
        "## corpus shape",
        "",
        _markdown_table(("field", "value"), corpus_rows),
        "",
        "Log-derived data-window endpoints are excluded; only the calculated span "
        "is retained. `generated_at` and the filename date describe this kit run.",
        "",
        "## runtime",
        "",
        _markdown_table(
            ("field", "value"),
            (
                ("hunt arm", projection["hunt"]["arm"]),
                ("hunt exit code", projection["hunt"]["exit_code"]),
                ("hunt wall seconds", projection["hunt"]["wall_seconds"]),
                (
                    "peak child RSS (MiB)",
                    projection.get("peak_child_rss_mb"),
                ),
                ("smoke ran", projection["smoke"]["ran"]),
                ("smoke passed", projection["smoke"]["passed"]),
            ),
        ),
        "",
        "Peak child RSS is the maximum across all completed child processes: the "
        "version probe, smoke canary when enabled, and hunt.",
        "",
        "## findings",
        "",
        findings_output,
        "",
        "## triage",
        "",
        _markdown_table(
            ("field", "value"),
            (
                ("ran", triage["ran"]),
                ("skip reason", triage.get("skip_reason")),
                ("reviewed", triage["reviewed"]),
                (
                    "untriaged",
                    ", ".join(
                        "%s=%s" % (key, value)
                        for key, value in triage.get("untriaged", {}).items()
                    )
                    or "none",
                ),
            ),
        ),
        "",
        "## your answers",
        "",
        "### anything real it missed",
        "",
        _answer_block(answers.get("missed")),
        "",
        "### anything confusing in the report",
        "",
        _answer_block(answers.get("confusing")),
        "",
        "### would you run this monthly",
        "",
        _answer_block(answers.get("monthly")),
        "",
        "## machine data",
        "",
        fence + "json",
        machine_json,
        fence,
        "",
    ]
    return "\n".join(lines)


def _reserve_bundle(out_dir: Path, generated_at: datetime) -> Tuple[Path, int]:
    date_part = generated_at.astimezone(timezone.utc).strftime("%Y%m%d")
    suffix = 0
    while True:
        name = "%s_%s%s.md" % (
            _BUNDLE_PREFIX,
            date_part,
            "" if suffix == 0 else "-%d" % suffix,
        )
        path = out_dir / name
        try:
            descriptor = os.open(
                str(path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            return path, descriptor
        except FileExistsError:
            suffix += 1


def write_bundle(
    projection: Mapping[str, Any],
    out_dir: Path,
    state: ProtocolState,
) -> Path:
    content = render_bundle(projection)
    generated_at = _parse_iso(projection["kit"]["generated_at"]) or datetime.now(timezone.utc)
    path, descriptor = _reserve_bundle(out_dir, generated_at)
    state.bundle_path = path
    handle = None
    try:
        handle = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if handle is None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        state.bundle_path = None
        raise
    return path


def _resolve_out_dir(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise FieldkitError("fieldkit: output directory is not available") from exc
    if not resolved.is_dir():
        raise FieldkitError("fieldkit: --out must name an existing directory")
    return resolved


def _projection(
    *,
    generated_at: datetime,
    version: Optional[str],
    version_unparsed: bool,
    smoke: Mapping[str, bool],
    hunt_exit_code: int,
    hunt_wall_seconds: float,
    peak_child_rss_mb: Optional[float],
    payload: Optional[Mapping[str, Any]],
    triage: Mapping[str, Any],
    answers: Mapping[str, str],
) -> Dict[str, Any]:
    run_summary = None
    findings = None
    if payload is not None:
        run_summary = _project_run_summary(payload.get("run_summary"))
        findings, _ = _project_findings(payload.get("findings"))
    kit: Dict[str, Any] = {
        "kit_version": KIT_VERSION,
        "generated_at": generated_at.isoformat(),
        "platform": _platform_facts(),
        "sigwood_version": version,
        "schema_version": REPORT_SCHEMA_VERSION,
    }
    if version_unparsed:
        kit["version_unparsed"] = True
    return {
        "kit": kit,
        "smoke": dict(smoke),
        "hunt": {
            "arm": "default_hunt",
            "exit_code": hunt_exit_code,
            "wall_seconds": round(hunt_wall_seconds, 3),
        },
        "peak_child_rss_mb": peak_child_rss_mb,
        "run_summary": run_summary,
        "findings": findings,
        "triage": dict(triage),
        "answers": dict(answers),
    }


def run_protocol(
    args: argparse.Namespace,
    state: ProtocolState,
    *,
    stdin: Optional[TextIO] = None,
) -> Path:
    out_dir = _resolve_out_dir(args.out)
    executable = shutil.which("sigwood")
    if executable is None:
        raise FieldkitError("fieldkit: sigwood was not found on PATH")

    try:
        workdir = Path(tempfile.mkdtemp(prefix="sigwood-fieldkit-"))
    except OSError as exc:
        raise FieldkitError("fieldkit: could not create a private work directory") from exc
    state.workdir = workdir

    try:
        version_run = subprocess.run(
            [executable, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
            check=False,
        )
        version, version_unparsed = _canonical_version(version_run.stdout or "")

        smoke = {"ran": not args.skip_smoke, "passed": False}
        if not args.skip_smoke:
            smoke_source = workdir / "conn.log"
            smoke_report = workdir / "smoke.json"
            smoke_source.write_bytes(generate_smoke_corpus())
            smoke_run = subprocess.run(
                [
                    executable,
                    "beacon",
                    str(smoke_source),
                    "--format=json",
                    "--out=%s" % smoke_report,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            smoke["passed"] = (
                smoke_run.returncode == 0
                and _smoke_passed(_try_load_json(smoke_report))
            )
            if not smoke["passed"]:
                print("fieldkit: smoke canary failed; continuing", file=sys.stderr)

        hunt_report = workdir / "hunt.json"
        started = time.monotonic()
        hunt_run = subprocess.run(
            [
                executable,
                "hunt",
                "--format=json",
                "--out=%s" % hunt_report,
            ],
            check=False,
        )
        wall_seconds = time.monotonic() - started
        peak_rss = _peak_child_rss_mb()

        raw_payload = _try_load_json(hunt_report)
        payload: Optional[Mapping[str, Any]] = None
        local_findings: List[Mapping[str, Any]] = []
        if isinstance(raw_payload, Mapping):
            payload = _validate_payload(raw_payload)
            _, local_findings = _project_findings(payload.get("findings"))

        triage, answers = _triage(
            local_findings,
            no_triage=args.no_triage,
            stdin=sys.stdin if stdin is None else stdin,
        )
        generated_at = datetime.now(timezone.utc)
        projection = _projection(
            generated_at=generated_at,
            version=version,
            version_unparsed=version_unparsed,
            smoke=smoke,
            hunt_exit_code=hunt_run.returncode,
            hunt_wall_seconds=wall_seconds,
            peak_child_rss_mb=peak_rss,
            payload=payload,
            triage=triage,
            answers=answers,
        )
        return write_bundle(projection, out_dir, state)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        state.workdir = None


def _cleanup_bundle(state: ProtocolState) -> None:
    if state.bundle_path is None:
        return
    try:
        state.bundle_path.unlink()
    except FileNotFoundError:
        pass
    state.bundle_path = None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    state = ProtocolState()
    try:
        bundle = run_protocol(args, state)
        print(str(bundle))
        print("read the whole file, then email it to %s" % RETURN_ADDRESS)
        return 0
    except KeyboardInterrupt:
        _cleanup_bundle(state)
        print("interrupted — nothing written", file=sys.stderr)
        return 130
    except SchemaMismatch as exc:
        _cleanup_bundle(state)
        print(str(exc), file=sys.stderr)
        return 1
    except (FieldkitError, OSError, subprocess.SubprocessError, ValueError) as exc:
        _cleanup_bundle(state)
        message = str(exc) if isinstance(exc, FieldkitError) else "fieldkit: protocol failed"
        print(message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
