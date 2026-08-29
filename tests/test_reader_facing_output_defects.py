"""Regressions for the U-2026-08-29-05 reader-facing output fixes."""

from __future__ import annotations

import io
from copy import deepcopy
from datetime import datetime, timezone

import pandas as pd

from sigwood.common.finding import DetectorContext, Finding, RunSummary, Severity
from sigwood.detectors import exfil
from sigwood.outputs._evidence import format_evidence_for_reading
from sigwood.outputs._render_model import _project_exfil
from sigwood.outputs.csv import CsvHandler
from sigwood.outputs.json import JsonHandler


WINDOW = (
    datetime(2026, 8, 1, tzinfo=timezone.utc),
    datetime(2026, 8, 2, tzinfo=timezone.utc),
)

PAIR_KEYS = {
    "src",
    "dst",
    "orig_bytes_total",
    "resp_bytes_total",
    "orig_share",
    "connection_count",
    "port_mix",
    "span_seconds",
    "first_seen",
    "last_seen",
    "max_duration_seconds",
}
ROLLUP_KEYS = {
    "tier",
    "src",
    "destination_network",
    "destination_count",
    "orig_bytes_total",
    "resp_bytes_total",
    "orig_share",
    "connection_count",
    "port_mix",
    "span_seconds",
    "first_seen",
    "last_seen",
    "max_duration_seconds",
    "members",
}
MEMBER_KEYS = {
    "dst",
    "orig_bytes",
    "resp_bytes",
    "orig_share",
    "connection_count",
    "port_mix",
    "span_seconds",
    "first_seen",
    "last_seen",
    "max_duration_seconds",
}


def _row(dst: str, port: int, outbound: int, ts: float) -> dict[str, object]:
    return {
        "src": "10.0.0.10",
        "dst": dst,
        "port": port,
        "proto": "tcp",
        "bytes": outbound,
        "resp_bytes": 100,
        "ts": ts,
        "duration": 3.5,
        "local_orig": True,
    }


def _findings(rows: list[dict[str, object]]) -> list[Finding]:
    return exfil.run(DetectorContext.unsuppressed(
        {"conn*.log*": pd.DataFrame(rows)},
        config={"min_outbound_bytes": 1_000, "min_orig_share": 0.6},
        data_window=WINDOW,
    ))


def _labels(port_mix: str) -> list[str]:
    return [entry.rsplit(" (", 1)[0] for entry in port_mix.split(", ")]


def _transport(finding: Finding) -> str:
    return next(cell.value for cell in _project_exfil(finding) if cell.key == "transport")


def test_exfil_promotes_the_same_ranked_services_at_all_three_structural_levels() -> None:
    pair = _findings([
        _row("203.0.113.30", 443, 1_200, 60.0),
        _row("203.0.113.30", 8443, 500, 120.0),
    ])[0]

    assert set(pair.evidence) == PAIR_KEYS | {"services"}
    assert pair.evidence["services"] == _labels(pair.evidence["port_mix"])
    assert _transport(pair) == ", ".join(pair.evidence["services"])

    rollup_rows = [
        row
        for index, dst in enumerate(
            ("198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23")
        )
        for row in (
            _row(dst, 443, 1_200 + index, 60.0 + index),
            _row(dst, 8443, 500 + index, 120.0 + index),
        )
    ]
    rollup = _findings(rollup_rows)[0]

    assert rollup.evidence["tier"] == "destination_pool"
    assert set(rollup.evidence) == ROLLUP_KEYS | {"services"}
    assert rollup.evidence["services"] == _labels(rollup.evidence["port_mix"])
    assert _transport(rollup) == ", ".join(rollup.evidence["services"])
    for member in rollup.evidence["members"]:
        assert set(member) == MEMBER_KEYS | {"services"}
        assert member["services"] == _labels(member["port_mix"])

    legacy = Finding(
        detector="exfil",
        severity=Severity.MEDIUM,
        title="legacy",
        description="legacy",
        evidence={
            "src": "10.0.0.10",
            "dst": "203.0.113.30",
            "orig_bytes_total": 1_200,
            "orig_share": 0.9,
            "connection_count": 1,
            "port_mix": "443/tcp (1.2 KB)",
        },
        next_steps=[],
        ts_generated=WINDOW[1],
        data_window=WINDOW,
    )
    assert _transport(legacy) == "443/tcp (1.2 KB)"


def _summary() -> RunSummary:
    return RunSummary(
        data_window=WINDOW,
        record_counts={"ssl*.log*": 1},
        data_size_bytes=0,
        detectors_run=["ssl"],
        detectors_skipped={},
        detector_missions={"ssl": "Mission for ssl."},
    )


def _machine_bytes(handler_type: type[CsvHandler] | type[JsonHandler], finding: Finding) -> str:
    stream = io.StringIO()
    handler = handler_type(stream=stream, verbose_level=2)
    handler.begin(_summary())
    handler.write([finding])
    handler.end()
    return stream.getvalue()


def test_ssl_leaf_name_is_confined_to_a_detached_reader_view() -> None:
    finding = Finding(
        detector="ssl",
        severity=Severity.LOW,
        title="192.0.2.10 → 198.51.100.20",
        description="A certificate chain did not validate.",
        evidence={
            "severity_basis": ["validation"],
            "validation_status": "self-signed certificate in certificate chain",
            "cert_self_signed": False,
        },
        next_steps=[],
        ts_generated=WINDOW[1],
        data_window=WINDOW,
    )
    original = deepcopy(finding.evidence)
    json_before = _machine_bytes(JsonHandler, finding)
    csv_before = _machine_bytes(CsvHandler, finding)

    view = format_evidence_for_reading(finding, finding.evidence)

    assert view["cert_leaf_self_signed"] is False
    assert "cert_self_signed" not in view
    assert finding.evidence == original
    assert finding.evidence["cert_self_signed"] is False
    assert _machine_bytes(JsonHandler, finding) == json_before
    assert _machine_bytes(CsvHandler, finding) == csv_before
